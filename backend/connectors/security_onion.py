"""Security Onion connector.

Security Onion stores every log it collects (Zeek, Suricata, Wazuh, osquery,
Elastic Agent, ...) in Elasticsearch. This module pulls a time-bounded slice
of those events out of Elasticsearch and hands it back as a pandas DataFrame
shaped exactly like the DataFrame produced by a CSV upload:

  * one row per event
  * one column per flattened field ("id.orig_h", "source.ip", ...)
  * every value a string, missing values as ""
  * the event timestamp in a column named EventTime

so the rest of the DimSense pipeline (field scoring, windowing, anomaly
detection) runs on it without modification.

Security Onion specifics handled here:
  * HTTPS with a self-signed certificate  -> verify_ssl=False by default,
    SSL warnings suppressed
  * Basic auth only                        -> username/password, no API keys
  * 30 second request timeout
  * Data streams (SO 2.4+) whose backing indices are hidden ".ds-*" indices
    -> data stream names are listed alongside plain indices
"""
from __future__ import annotations

import json
import logging
from typing import Any

import pandas as pd

try:
    from elasticsearch import (
        ApiError,
        AuthenticationException,
        AuthorizationException,
        ConnectionError as ESConnectionError,
        ConnectionTimeout,
        Elasticsearch,
        NotFoundError,
        UnsupportedProductError,
    )
except ImportError as exc:  # pragma: no cover - import guard
    raise ImportError(
        "The Security Onion connector requires the 'elasticsearch' package. "
        "Install it with: pip install 'elasticsearch>=8.0.0'"
    ) from exc

logger = logging.getLogger("dimsense.connectors.security_onion")

DEFAULT_PORT = 9200
REQUEST_TIMEOUT = 30           # seconds, per request
SCROLL_BATCH_SIZE = 1000       # documents per scroll page
SCROLL_KEEPALIVE = "2m"        # how long Elasticsearch keeps the scroll context alive
MAX_SAMPLE_SIZE = 10_000       # Elasticsearch default max result window for a single search
TIME_COLUMN = "EventTime"      # column name the windowing engine expects


class SecurityOnionError(Exception):
    """A connection, authentication, or query failure against Security Onion.

    ``status_code`` is the HTTP status the API layer should surface. It is
    502 for connectivity problems, 504 for timeouts, 401/403 for credential
    problems, and 404 for a missing index.
    """

    def __init__(self, message: str, status_code: int = 502):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #

def _stringify(value: Any) -> str:
    """Render a single Elasticsearch field value as a string.

    None becomes "" so the analysis engine's ``value != ""`` non-empty test
    keeps one unambiguous meaning across CSV and Security Onion sources.
    """
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple)):
        if all(not isinstance(v, (dict, list, tuple)) for v in value):
            return ", ".join(_stringify(v) for v in value)
        return json.dumps(value, default=str)
    return str(value)


def flatten_document(doc: dict, parent_key: str = "", sep: str = ".") -> dict[str, str]:
    """Flatten a nested document into dot-notation keys with string values.

    {"id": {"orig_h": "1.2.3.4"}} -> {"id.orig_h": "1.2.3.4"}
    """
    flat: dict[str, str] = {}
    for key, value in doc.items():
        full_key = f"{parent_key}{sep}{key}" if parent_key else str(key)
        if isinstance(value, dict):
            if value:
                flat.update(flatten_document(value, full_key, sep))
            else:
                flat[full_key] = ""
        else:
            flat[full_key] = _stringify(value)
    return flat


def _body(response: Any) -> Any:
    """Unwrap an elasticsearch-py ApiResponse into its plain dict body."""
    return getattr(response, "body", response)


def _build_url(host: str, port: int) -> str:
    """Build the Elasticsearch base URL.

    Security Onion serves Elasticsearch over HTTPS, so that is the default
    scheme. A host given as a full URL ("http://so-manager:9200") is used
    as-is, which allows plain-HTTP test clusters.
    """
    host = host.strip()
    if "://" in host:
        scheme, _, rest = host.partition("://")
    else:
        scheme, rest = "https", host
    rest = rest.rstrip("/")
    netloc = rest.split("/", 1)[0]
    has_port = ":" in netloc and netloc.rsplit(":", 1)[-1].isdigit()
    if has_port:
        return f"{scheme}://{rest}"
    return f"{scheme}://{rest}:{port}"


def _suppress_insecure_warnings() -> None:
    try:
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:  # pragma: no cover - best effort only
        pass


_PLAINTEXT_MARKERS = ("WRONG_VERSION_NUMBER", "RECORD_LAYER_FAILURE", "UNKNOWN_PROTOCOL", "HTTP_REQUEST")


def _looks_like_plaintext_server(exc: Exception) -> bool:
    """True when a TLS handshake failed because the peer spoke plain HTTP."""
    text = str(getattr(exc, "message", None) or exc).upper()
    return any(marker in text for marker in _PLAINTEXT_MARKERS)


# --------------------------------------------------------------------------- #
# Connector                                                                   #
# --------------------------------------------------------------------------- #

class SecurityOnionConnector:
    def __init__(self, host: str, port: int, username: str, password: str, verify_ssl: bool = False):
        """
        host: Security Onion Elasticsearch host
              e.g. "192.168.1.100" or "so-manager"
        port: Elasticsearch port, default 9200
        username: Elasticsearch username
        password: Elasticsearch password
        verify_ssl: False by default since Security
                    Onion uses self-signed certs
        """
        self.host = host
        self.port = int(port) if port else DEFAULT_PORT
        self.username = username
        self._password = password
        self.verify_ssl = bool(verify_ssl)
        self.url = _build_url(host, self.port)
        # A host given without a scheme defaults to HTTPS, which is what a
        # real Security Onion speaks. The first request probes once whether
        # the server really does TLS; see _ensure_scheme().
        self._scheme_checked = "://" in host.strip()
        self._info: dict | None = None

        if not self.verify_ssl:
            _suppress_insecure_warnings()

        self.client = self._make_client(self.url)

    def _make_client(self, url: str) -> Elasticsearch:
        has_credentials = bool(self.username or self._password)
        return Elasticsearch(
            url,
            basic_auth=(self.username, self._password) if has_credentials else None,
            verify_certs=self.verify_ssl,
            ssl_show_warn=False,
            request_timeout=REQUEST_TIMEOUT,
            max_retries=1,
            retry_on_timeout=False,
        )

    def _ensure_scheme(self) -> None:
        """Probe once whether an HTTPS-by-default host really speaks TLS.

        Real Security Onion always does. A local test cluster started with
        xpack.security.enabled=false answers plain HTTP on the same port and
        the TLS handshake fails with WRONG_VERSION_NUMBER. In that case we
        fall back to http:// only when no credentials were supplied, so a
        username/password is never sent unencrypted by accident. With
        credentials the caller must opt in by giving an explicit http:// host.
        """
        if self._scheme_checked:
            return
        self._scheme_checked = True
        try:
            self._info = _body(self.client.info())
            return
        except ESConnectionError as exc:
            if not _looks_like_plaintext_server(exc):
                return  # a real connectivity problem; the caller's own request reports it
        except Exception:
            return

        http_url = "http://" + self.url[len("https://"):]
        if self.username or self._password:
            raise SecurityOnionError(
                f"{self.url} answered with plain HTTP instead of TLS. Refusing to send credentials "
                f"unencrypted; if this is a test cluster without TLS, set host to '{http_url}' explicitly.",
                status_code=502,
            )
        logger.warning("%s does not speak TLS; falling back to %s (no credentials configured)", self.url, http_url)
        self.close()
        self.url = http_url
        self.client = self._make_client(http_url)

    # -- lifecycle --------------------------------------------------------- #

    def close(self) -> None:
        try:
            self.client.close()
        except Exception:  # pragma: no cover - best effort only
            pass

    def __enter__(self) -> "SecurityOnionConnector":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    # -- error translation ------------------------------------------------- #

    def _translate(self, exc: Exception) -> SecurityOnionError:
        """Turn an elasticsearch-py exception into a SecurityOnionError with a
        message an analyst can act on. Never includes the password."""
        if isinstance(exc, SecurityOnionError):
            return exc
        if isinstance(exc, AuthenticationException):
            return SecurityOnionError(
                f"Authentication failed for user '{self.username}' at {self.url}. "
                "Check the Elasticsearch username and password.",
                status_code=401,
            )
        if isinstance(exc, AuthorizationException):
            return SecurityOnionError(
                f"User '{self.username}' is not authorized to perform this operation on {self.url}.",
                status_code=403,
            )
        if isinstance(exc, ConnectionTimeout):
            return SecurityOnionError(
                f"Timed out after {REQUEST_TIMEOUT}s waiting for Security Onion at {self.url}.",
                status_code=504,
            )
        if isinstance(exc, ESConnectionError):
            detail = str(getattr(exc, "message", None) or exc)
            hint = ""
            upper = detail.upper()
            if "CERTIFICATE" in upper or "SSL" in upper:
                hint = (
                    " (TLS problem: Security Onion uses a self-signed certificate, "
                    "so verify_ssl should usually be false)"
                )
            return SecurityOnionError(
                f"Could not connect to Security Onion at {self.url}: {detail}{hint}",
                status_code=502,
            )
        if isinstance(exc, UnsupportedProductError):
            return SecurityOnionError(
                f"The server at {self.url} did not identify itself as Elasticsearch. "
                "Check that the host and port point at the Elasticsearch API (usually port 9200), "
                "not the Security Onion web interface or Kibana.",
                status_code=502,
            )
        if isinstance(exc, NotFoundError):
            return SecurityOnionError(
                f"Not found on {self.url}: {getattr(exc, 'message', exc)}",
                status_code=404,
            )
        if isinstance(exc, ApiError):
            return SecurityOnionError(
                f"Elasticsearch at {self.url} returned an error: {getattr(exc, 'message', exc)}",
                status_code=502,
            )
        return SecurityOnionError(
            f"Unexpected error talking to Security Onion at {self.url}: {type(exc).__name__}: {exc}",
            status_code=502,
        )

    # -- public API -------------------------------------------------------- #

    def test_connection(self) -> dict:
        """
        Test that the connection works. Never raises.
        Returns: {
            "success": bool,
            "version": str or None,
            "indices": list of available indices,
            "error": str or None
        }
        If the cluster is reachable but indices cannot be listed (usually a
        privilege problem) ``success`` is still True and ``error`` explains
        why ``indices`` is empty.
        """
        result: dict[str, Any] = {"success": False, "version": None, "indices": [], "error": None}
        try:
            self._ensure_scheme()
            info = self._info if self._info is not None else _body(self.client.info())
            result["version"] = (info.get("version") or {}).get("number")
            result["success"] = True
        except Exception as exc:
            result["error"] = self._translate(exc).message
            logger.warning("Security Onion connection test failed for %s: %s", self.url, result["error"])
            return result

        try:
            result["indices"] = self.list_indices()
        except SecurityOnionError as exc:
            result["error"] = f"Connected, but could not list indices: {exc.message}"
            logger.warning(result["error"])
        return result

    def list_indices(self) -> list:
        """
        Return list of available index names, sorted.
        System indices starting with "." are filtered out.
        Security Onion 2.4+ writes to data streams (logs-zeek.conn-so,
        logs-suricata.alert-so, ...) whose backing indices are hidden
        ".ds-*" indices, so data stream names are included as well.
        """
        names: set[str] = set()
        try:
            self._ensure_scheme()
            rows = _body(self.client.cat.indices(index="*", h="index", format="json", expand_wildcards="open"))
        except Exception as exc:
            raise self._translate(exc) from exc
        for row in rows or []:
            name = row.get("index") if isinstance(row, dict) else None
            if name and not name.startswith("."):
                names.add(name)

        try:
            streams = _body(self.client.indices.get_data_stream(name="*"))
            for stream in streams.get("data_streams", []) or []:
                name = stream.get("name")
                if name and not name.startswith("."):
                    names.add(name)
        except Exception as exc:
            # Older Elasticsearch (pre 7.9) has no data streams, and some
            # roles cannot read them. Plain indices are still returned.
            logger.debug("Could not list data streams on %s: %s", self.url, exc)

        return sorted(names)

    def query_events(
        self,
        index_pattern: str,
        start_time: str,
        end_time: str,
        max_rows: int = 100000,
        time_field: str = "@timestamp",
    ) -> pd.DataFrame:
        """
        Query Elasticsearch for events in time range.

        start_time, end_time: ISO format strings, e.g. "2024-01-01T00:00:00".
        Timestamps without a timezone are interpreted as UTC by Elasticsearch.

        Uses the scroll API in batches of SCROLL_BATCH_SIZE documents,
        ordered by ``time_field`` ascending, so a truncated result is the
        earliest ``max_rows`` events in the range rather than an arbitrary
        subset.

        Returns a DataFrame where each row is one event, each column is a
        flattened field (dot notation), every value is a string, and
        ``time_field`` has been renamed to EventTime. Elasticsearch metadata
        is kept as the _index and _id columns.

        An empty DataFrame is returned (never an exception) when the index
        pattern does not exist or the range holds no events. In both cases
        ``df.attrs["message"]`` carries a human-readable explanation and
        ``df.attrs["not_found"]`` is True for the missing-index case.
        Connection and authentication failures raise SecurityOnionError.

        ``df.attrs["total_available"]`` is the total hit count and
        ``df.attrs["truncated"]`` is True when it exceeded ``max_rows``.
        """
        max_rows = int(max_rows)
        if max_rows <= 0:
            return self._empty_frame("max_rows must be a positive integer")

        self._ensure_scheme()
        if not self._index_exists(index_pattern):
            message = (
                f"Index pattern '{index_pattern}' does not match any index or data stream on {self.url}"
            )
            logger.warning(message)
            return self._empty_frame(message, not_found=True)

        query = {
            "range": {
                time_field: {
                    "gte": start_time,
                    "lte": end_time,
                    "format": "strict_date_optional_time",
                }
            }
        }
        sort = [{time_field: {"order": "asc", "unmapped_type": "date"}}]

        rows: list[dict[str, str]] = []
        total_available = 0
        scroll_id = None
        try:
            response = _body(
                self.client.search(
                    index=index_pattern,
                    query=query,
                    sort=sort,
                    size=min(SCROLL_BATCH_SIZE, max_rows),
                    scroll=SCROLL_KEEPALIVE,
                    track_total_hits=True,
                    ignore_unavailable=True,
                )
            )
            scroll_id = response.get("_scroll_id")
            total = response["hits"].get("total") or {}
            total_available = int(total.get("value", 0) if isinstance(total, dict) else total)
            hits = response["hits"]["hits"]

            while hits:
                for hit in hits:
                    rows.append(self._hit_to_row(hit))
                    if len(rows) >= max_rows:
                        break
                if len(rows) >= max_rows or not scroll_id:
                    break
                response = _body(self.client.scroll(scroll_id=scroll_id, scroll=SCROLL_KEEPALIVE))
                scroll_id = response.get("_scroll_id", scroll_id)
                hits = response["hits"]["hits"]
        except NotFoundError as exc:
            message = (
                f"Index pattern '{index_pattern}' was not found on {self.url}: {getattr(exc, 'message', exc)}"
            )
            logger.warning(message)
            return self._empty_frame(message, not_found=True)
        except Exception as exc:
            raise self._translate(exc) from exc
        finally:
            if scroll_id:
                try:
                    self.client.clear_scroll(scroll_id=scroll_id)
                except Exception:
                    pass

        if not rows:
            message = f"No events found in '{index_pattern}' between {start_time} and {end_time}"
            logger.info(message)
            return self._empty_frame(message)

        truncated = total_available > len(rows)
        if truncated:
            logger.warning(
                "Query on '%s' between %s and %s matched %d events; returning the first %d (max_rows=%d)",
                index_pattern, start_time, end_time, total_available, len(rows), max_rows,
            )

        df = self._rows_to_frame(rows, time_field)
        df.attrs.update({
            "message": None,
            "not_found": False,
            "total_available": total_available,
            "truncated": truncated,
        })
        return df

    def get_field_sample(self, index_pattern: str, sample_size: int = 1000) -> list:
        """
        Return a sorted list of all field names present in a sample of the
        most recent documents from this index. Field names are flattened the
        same way query_events flattens them, so the list previews the columns
        a query would produce (the timestamp field is shown under its
        original name, e.g. "@timestamp").
        Raises SecurityOnionError (404) if the index pattern matches nothing.
        """
        size = max(1, min(int(sample_size), MAX_SAMPLE_SIZE))

        self._ensure_scheme()
        if not self._index_exists(index_pattern):
            raise SecurityOnionError(
                f"Index pattern '{index_pattern}' does not match any index or data stream on {self.url}",
                status_code=404,
            )

        try:
            response = _body(
                self.client.search(
                    index=index_pattern,
                    query={"match_all": {}},
                    sort=[{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
                    size=size,
                    ignore_unavailable=True,
                )
            )
        except NotFoundError as exc:
            raise SecurityOnionError(
                f"Index pattern '{index_pattern}' was not found on {self.url}: {getattr(exc, 'message', exc)}",
                status_code=404,
            ) from exc
        except Exception as exc:
            raise self._translate(exc) from exc

        fields: set[str] = set()
        for hit in response["hits"]["hits"]:
            fields.update(self._hit_to_row(hit).keys())
        return sorted(fields)

    # -- internals --------------------------------------------------------- #

    def _index_exists(self, index_pattern: str) -> bool:
        """True if the pattern resolves to at least one index, alias, or data
        stream. If Elasticsearch cannot answer (old version, privileges) we
        assume it exists and let the search itself report any problem."""
        try:
            resolved = _body(self.client.indices.resolve_index(name=index_pattern, expand_wildcards="open"))
        except NotFoundError:
            return False
        except Exception as exc:
            logger.debug("resolve_index unavailable on %s, skipping existence check: %s", self.url, exc)
            return True
        return any(resolved.get(key) for key in ("indices", "aliases", "data_streams"))

    @staticmethod
    def _hit_to_row(hit: dict) -> dict[str, str]:
        row = flatten_document(hit.get("_source") or {})
        row["_index"] = _stringify(hit.get("_index"))
        row["_id"] = _stringify(hit.get("_id"))
        return row

    @staticmethod
    def _rows_to_frame(rows: list[dict[str, str]], time_field: str) -> pd.DataFrame:
        df = pd.DataFrame(rows)
        # Documents that lack a field produce NaN for that column; the CSV
        # path represents missing values as "", so match it before casting.
        df = df.fillna("").astype(str)

        if time_field in df.columns and time_field != TIME_COLUMN:
            if TIME_COLUMN in df.columns:
                logger.warning(
                    "Documents already contain an %s field; keeping it as %s.original",
                    TIME_COLUMN, TIME_COLUMN,
                )
                df = df.rename(columns={TIME_COLUMN: f"{TIME_COLUMN}.original"})
            df = df.rename(columns={time_field: TIME_COLUMN})

        if TIME_COLUMN in df.columns:
            ordered = [TIME_COLUMN] + [c for c in df.columns if c != TIME_COLUMN]
            df = df[ordered]
        return df.reset_index(drop=True)

    @staticmethod
    def _empty_frame(message: str, not_found: bool = False) -> pd.DataFrame:
        df = pd.DataFrame()
        df.attrs.update({
            "message": message,
            "not_found": not_found,
            "total_available": 0,
            "truncated": False,
        })
        return df
