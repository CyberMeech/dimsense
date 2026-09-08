"""Generate synthetic Zeek conn.log events that look like a Security Onion
``logs-zeek.conn-*`` index and bulk-load them into a local Elasticsearch.

Timeline (event indices):

    0      - 32,000   baseline: 50 workstations doing normal DNS, web and
                      occasional admin traffic
    32,000 - 38,000   anomaly:  event rate ~3x, 78% of connections go to one
                      C2 address (185.220.101.50, the rest to other hosts in
                      the same Tor-exit /24), 30 new hosts (10.0.1.x) appear,
                      ports collapse to 443/4444, short uniform beacon
                      durations and near-fixed payload sizes
    38,000 - 50,000   baseline again

Timestamps start at 2026-01-01T00:00:00Z. Inter-event gaps are drawn from
8-15 s (baseline) and 2-4 s (anomaly). Drawn as-is those gaps add up to about
6 days, so the whole timeline is compressed uniformly (factor printed at run
time) to fit inside the five-day window ending 2026-01-06T00:00:00Z, which is
the range the DimSense verification query uses. Relative rates are preserved.

With DimSense's 8,192-event windows the anomaly lands in window 4
(events 32,768-40,959, about 64% anomalous), which is also the first window
that has enough history to be scored.

Usage:
    python backend/tests/generate_zeek_data.py                       # load into http://localhost:9200
    python backend/tests/generate_zeek_data.py --es-url http://h:9200
    python backend/tests/generate_zeek_data.py --dry-run --csv out.csv   # generate only, no Elasticsearch
"""
from __future__ import annotations

import argparse
import csv
import math
import random
import string
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

ES_URL = "http://localhost:9200"
INDEX_NAME = "logs-zeek.conn-default"
# Elasticsearch 8 ships a built-in template that turns every logs-*-* name into
# a data stream, and Security Onion 2.4 stores Zeek logs in data streams too.
# So the "index" is really a data stream backed by hidden .ds-* indices, with
# our own higher-priority template supplying the mapping.
INDEX_TEMPLATE_NAME = "dimsense-logs-zeek-conn"
INDEX_TEMPLATE_PATTERN = "logs-zeek.conn-*"
TOTAL_EVENTS = 50_000
ANOMALY_START = 32_000
ANOMALY_END = 38_000
START_TIME = datetime(2026, 1, 1, tzinfo=timezone.utc)
MAX_SPAN_SECONDS = int(4.95 * 86_400)   # keep every event before 2026-01-06T00:00:00Z
BULK_BATCH_SIZE = 1000
PROGRESS_EVERY = 5000
DEFAULT_SEED = 20260101

# --- network population ------------------------------------------------------
BASELINE_HOSTS = [f"10.0.0.{i}" for i in range(1, 51)]
REGULAR_HOSTS = BASELINE_HOSTS[:42]
OCCASIONAL_HOSTS = BASELINE_HOSTS[42:]          # only active now and then
ANOMALY_HOSTS = [f"10.0.1.{i}" for i in range(1, 31)]
HEAVY_BEACONERS = ANOMALY_HOSTS[:3]             # a few infected hosts beacon far more

GATEWAY = "10.0.0.1"
INTERNAL_SERVER = "192.168.1.100"
DNS_RESOLVERS = [("8.8.8.8", 0.5), ("8.8.4.4", 0.2), ("1.1.1.1", 0.2), (GATEWAY, 0.1)]
KNOWN_EXTERNAL = ["52.94.236.248", "142.250.72.14", "104.16.132.229", "151.101.1.140", "13.107.42.14"]
C2_IP = "185.220.101.50"
C2_FALLBACK_IPS = [f"185.220.101.{i}" for i in range(1, 101) if i != 50]

COMMON_PORTS = [(443, 0.52), (80, 0.20), (53, 0.18), (22, 0.02), (3389, 0.015), (445, 0.015)]
RARE_PORTS = [8080, 8443, 5900, 1433, 25, 110, 143, 993, 995, 5432, 3306, 6379, 27017, 8000, 8888,
              9090, 5060, 123, 161, 389, 636, 1521, 2049, 5985, 5986, 8009, 9200, 9300, 111, 2375]
SERVICE_BY_PORT = {
    443: "ssl", 80: "http", 53: "dns", 22: "ssh", 445: "smb", 3389: "",
    8080: "http", 8443: "ssl", 8000: "http", 8888: "http", 25: "smtp",
    993: "ssl", 995: "ssl", 143: "imap", 110: "pop3", 636: "ssl", 5986: "ssl",
}

CONN_STATES = [
    ("SF", 0.70), ("S0", 0.10), ("REJ", 0.05), ("RSTO", 0.04), ("RSTR", 0.03),
    ("S1", 0.03), ("SH", 0.02), ("OTH", 0.0293),
    ("RSTOS0", 0.0004), ("RSTRH", 0.0002), ("SHR", 0.0001),   # rare, so per-window diversity varies
]
ANOMALY_CONN_STATES = [("SF", 0.88), ("S0", 0.06), ("REJ", 0.03), ("RSTO", 0.02), ("RSTRH", 0.005), ("SHR", 0.005)]

# (orig_lo, orig_hi, resp_lo, resp_hi) - log-uniform byte ranges per service
BYTES_BY_SERVICE = {
    "dns": (40, 120, 60, 600),
    "http": (200, 3_000, 500, 200_000),
    "ssl": (300, 8_000, 1_000, 500_000),
    "ssh": (1_000, 50_000, 1_000, 80_000),
    "smb": (500, 20_000, 500, 50_000),
    "smtp": (500, 20_000, 200, 2_000),
    "imap": (200, 5_000, 500, 100_000),
    "pop3": (200, 5_000, 500, 100_000),
    "": (60, 5_000, 1, 20_000),
}

MAPPING = {
    "properties": {
        "@timestamp": {"type": "date"},
        "uid": {"type": "keyword"},
        "id": {
            "properties": {
                "orig_h": {"type": "keyword"},
                "orig_p": {"type": "integer"},
                "resp_h": {"type": "keyword"},
                "resp_p": {"type": "integer"},
            }
        },
        "proto": {"type": "keyword"},
        "service": {"type": "keyword"},
        "duration": {"type": "float"},
        "orig_bytes": {"type": "long"},
        "resp_bytes": {"type": "long"},
        "conn_state": {"type": "keyword"},
        "missed_bytes": {"type": "long"},
        "orig_pkts": {"type": "long"},
        "resp_pkts": {"type": "long"},
    }
}


# --- helpers -----------------------------------------------------------------

def _pick(rng: random.Random, weighted: list[tuple]) -> object:
    population, weights = zip(*weighted)
    return rng.choices(population, weights=weights, k=1)[0]


def _log_uniform_int(rng: random.Random, lo: int, hi: int) -> int:
    lo = max(lo, 1)
    return int(round(math.exp(rng.uniform(math.log(lo), math.log(hi)))))


def _uid(rng: random.Random) -> str:
    alphabet = string.ascii_letters + string.digits
    return "C" + "".join(rng.choice(alphabet) for _ in range(17))


def _random_public_ip(rng: random.Random) -> str:
    first = rng.choice([23, 34, 35, 44, 52, 54, 64, 66, 72, 74, 99, 104, 107, 130, 142, 151, 157, 162, 184, 199, 204, 208, 216])
    return f"{first}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _baseline_source(rng: random.Random) -> str:
    # Regular hosts weight 1.0, occasional hosts 0.004 -> each occasional host
    # shows up in roughly half of the 8,192-event windows, so the number of
    # distinct sources per window drifts between ~44 and ~50 instead of being
    # a constant the anomaly scorer would have to skip.
    return rng.choices(
        REGULAR_HOSTS + OCCASIONAL_HOSTS,
        weights=[1.0] * len(REGULAR_HOSTS) + [0.004] * len(OCCASIONAL_HOSTS),
        k=1,
    )[0]


def _fmt_ts(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"


# --- event builders ----------------------------------------------------------

def _baseline_event(rng: random.Random, occasional_pool: list[str]) -> dict:
    r = rng.random()
    if r < 0.003:                                             # a little ICMP
        proto, port, service = "icmp", 8, ""
        dst = GATEWAY if rng.random() < 0.5 else _pick(rng, DNS_RESOLVERS)
    elif r < 0.033:                                           # rare ports
        proto = "tcp"
        port = rng.choice(RARE_PORTS)
        service = SERVICE_BY_PORT.get(port, "")
        dst = rng.choice(KNOWN_EXTERNAL + [INTERNAL_SERVER]) if rng.random() < 0.7 else rng.choice(occasional_pool)
    else:
        port = _pick(rng, COMMON_PORTS)
        service = SERVICE_BY_PORT[port]
        if port == 53:
            proto = "udp" if rng.random() < 0.92 else "tcp"
            dst = _pick(rng, DNS_RESOLVERS)
        elif port in (443, 80):
            proto = "tcp"
            q = rng.random()
            if q < 0.30:
                dst = INTERNAL_SERVER
            elif q < 0.85:
                dst = rng.choice(KNOWN_EXTERNAL)
            else:
                dst = rng.choice(occasional_pool)
        else:                                                 # 22 / 3389 / 445 admin traffic
            proto = "tcp"
            q = rng.random()
            dst = INTERNAL_SERVER if q < 0.6 else (GATEWAY if q < 0.8 else rng.choice(BASELINE_HOSTS))

    if proto == "icmp":
        orig_bytes = rng.randint(56, 84)
        resp_bytes = rng.randint(56, 84)
    else:
        o_lo, o_hi, r_lo, r_hi = BYTES_BY_SERVICE.get(service, BYTES_BY_SERVICE[""])
        orig_bytes = _log_uniform_int(rng, o_lo, o_hi)
        resp_bytes = 0 if (service == "" and rng.random() < 0.2) else _log_uniform_int(rng, r_lo, r_hi)

    return {
        "src": _baseline_source(rng),
        "dst": dst,
        "port": port,
        "proto": proto,
        "service": service,
        "duration": round(rng.uniform(0.1, 30.0), 3),
        "orig_bytes": orig_bytes,
        "resp_bytes": resp_bytes,
        "conn_state": _pick(rng, CONN_STATES),
        "missed_bytes": 0 if rng.random() < 0.99 else rng.randint(1, 5000),
        "orig_pkts": max(1, orig_bytes // rng.randint(400, 1400) + rng.randint(1, 4)),
        "resp_pkts": max(0, resp_bytes // rng.randint(400, 1400) + rng.randint(0, 4)),
    }


def _anomaly_event(rng: random.Random) -> dict:
    src = rng.choice(HEAVY_BEACONERS) if rng.random() < 0.20 else rng.choice(BASELINE_HOSTS + ANOMALY_HOSTS)
    dst = C2_IP if rng.random() < 0.78 else rng.choice(C2_FALLBACK_IPS)
    port = 443 if rng.random() < 0.70 else 4444
    service = ("ssl" if rng.random() < 0.85 else "") if port == 443 else ""
    orig_bytes = rng.choice((312, 328, 344)) + rng.randint(0, 3)      # near-fixed beacon payload
    resp_bytes = rng.choice((1024, 1088, 1152)) + rng.randint(0, 7)
    return {
        "src": src,
        "dst": dst,
        "port": port,
        "proto": "tcp",
        "service": service,
        "duration": round(rng.uniform(0.08, 0.20), 3),               # short and uniform
        "orig_bytes": orig_bytes,
        "resp_bytes": resp_bytes,
        "conn_state": _pick(rng, ANOMALY_CONN_STATES),
        "missed_bytes": 0,
        "orig_pkts": rng.randint(4, 6),
        "resp_pkts": rng.randint(4, 8),
    }


def generate_events(seed: int = DEFAULT_SEED) -> tuple[list[dict], dict]:
    """Return (documents, summary). Documents are ready for the bulk API."""
    rng = random.Random(seed)
    occasional_pool = [_random_public_ip(rng) for _ in range(60)]

    # Pass 1: inter-event gaps, so the timeline can be compressed to fit 5 days.
    gaps = []
    for i in range(TOTAL_EVENTS):
        anomalous = ANOMALY_START <= i < ANOMALY_END
        gaps.append(rng.uniform(2, 4) if anomalous else rng.uniform(8, 15))
    raw_span = sum(gaps)
    factor = min(1.0, MAX_SPAN_SECONDS / raw_span)

    # Pass 2: events.
    docs = []
    elapsed = 0.0
    anomaly_first = anomaly_last = None
    for i in range(TOTAL_EVENTS):
        anomalous = ANOMALY_START <= i < ANOMALY_END
        elapsed += gaps[i] * factor
        ts = START_TIME + timedelta(seconds=elapsed)
        ev = _anomaly_event(rng) if anomalous else _baseline_event(rng, occasional_pool)
        if anomalous:
            anomaly_first = anomaly_first or ts
            anomaly_last = ts
        doc = {
            "@timestamp": _fmt_ts(ts),
            "uid": _uid(rng),
            "id": {
                "orig_h": ev["src"],
                "orig_p": rng.randint(49152, 65535),
                "resp_h": ev["dst"],
                "resp_p": ev["port"],
            },
            "proto": ev["proto"],
            "duration": ev["duration"],
            "orig_bytes": ev["orig_bytes"],
            "resp_bytes": ev["resp_bytes"],
            "conn_state": ev["conn_state"],
            "missed_bytes": ev["missed_bytes"],
            "orig_pkts": ev["orig_pkts"],
            "resp_pkts": ev["resp_pkts"],
        }
        if ev["service"]:                       # Zeek omits the field when unknown
            doc["service"] = ev["service"]
        docs.append(doc)

    summary = {
        "seed": seed,
        "total_events": len(docs),
        "first_event": docs[0]["@timestamp"],
        "last_event": docs[-1]["@timestamp"],
        "span_days": round(elapsed / 86_400, 2),
        "compression_factor": round(factor, 4),
        "anomaly_events": f"{ANOMALY_START:,}-{ANOMALY_END:,}",
        "anomaly_start": _fmt_ts(anomaly_first),
        "anomaly_end": _fmt_ts(anomaly_last),
        "baseline_gap_seconds": f"{8 * factor:.1f}-{15 * factor:.1f}",
        "anomaly_gap_seconds": f"{2 * factor:.1f}-{4 * factor:.1f}",
    }
    return docs, summary


# --- CSV export (mirrors what the Security Onion connector produces) ---------

def write_csv(docs: list[dict], path: Path) -> None:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from connectors.security_onion import flatten_document  # same flattening as the live path

    rows = [flatten_document(d) for d in docs]
    for row in rows:
        row["EventTime"] = row.pop("@timestamp")
    columns = ["EventTime"] + sorted({k for r in rows for k in r} - {"EventTime"})
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=columns, restval="")
        writer.writeheader()
        writer.writerows(rows)
    print(f"CSV written to {path} ({len(rows):,} rows, {len(columns)} columns)")


# --- Elasticsearch loading ---------------------------------------------------

def _wait_for_cluster(client, wait_seconds: int) -> None:
    deadline = time.time() + wait_seconds
    last_error = None
    while time.time() < deadline:
        try:
            health = client.cluster.health(wait_for_status="yellow", timeout="10s")
            status = getattr(health, "body", health)["status"]
            print(f"Elasticsearch cluster status: {status}")
            return
        except Exception as exc:  # not up yet
            last_error = exc
            time.sleep(3)
    sys.exit(f"Elasticsearch did not become ready within {wait_seconds}s: {last_error}")


def load_into_elasticsearch(docs: list[dict], es_url: str, recreate: bool, wait_seconds: int) -> int:
    from elasticsearch import Elasticsearch, NotFoundError

    client = Elasticsearch(es_url, request_timeout=60)
    _wait_for_cluster(client, wait_seconds)
    info = getattr(client.info(), "body", None) or client.info()
    print(f"Connected to Elasticsearch {info['version']['number']} at {es_url}")

    try:
        existing = getattr(client.indices.get_data_stream(name=INDEX_NAME), "body", {})
    except NotFoundError:
        existing = {}
    if existing.get("data_streams"):
        if not recreate:
            sys.exit(f"Data stream {INDEX_NAME} already exists; rerun without --keep-index to recreate it")
        print(f"Deleting existing data stream {INDEX_NAME}")
        client.indices.delete_data_stream(name=INDEX_NAME)
    elif client.indices.exists(index=INDEX_NAME):
        if not recreate:
            sys.exit(f"Index {INDEX_NAME} already exists; rerun without --keep-index to recreate it")
        print(f"Deleting existing index {INDEX_NAME}")
        client.indices.delete(index=INDEX_NAME)

    client.indices.put_index_template(
        name=INDEX_TEMPLATE_NAME,
        index_patterns=[INDEX_TEMPLATE_PATTERN],
        data_stream={},
        priority=500,   # above the built-in "logs" template (100)
        template={
            "settings": {"number_of_shards": 1, "number_of_replicas": 0},
            "mappings": MAPPING,
        },
    )
    client.indices.create_data_stream(name=INDEX_NAME)
    print(f"Created data stream {INDEX_NAME} (template {INDEX_TEMPLATE_NAME}, pattern {INDEX_TEMPLATE_PATTERN})")

    loaded = failed = 0
    next_progress = PROGRESS_EVERY
    for start in range(0, len(docs), BULK_BATCH_SIZE):
        batch = docs[start:start + BULK_BATCH_SIZE]
        operations = []
        for doc in batch:
            operations.append({"create": {"_index": INDEX_NAME, "_id": doc["uid"]}})   # data streams only accept create
            operations.append(doc)
        response = getattr(client.bulk(operations=operations, refresh=False), "body", None)
        if response and response.get("errors"):
            errors = [item["create"]["error"] for item in response["items"] if item["create"].get("error")]
            failed += len(errors)
            if errors:
                print(f"  bulk errors in batch starting at {start}: {errors[0]}")
        loaded += len(batch)
        if loaded >= next_progress:
            print(f"  loaded {loaded:,}/{len(docs):,} events")
            next_progress += PROGRESS_EVERY

    client.indices.refresh(index=INDEX_NAME)
    count = int(client.count(index=INDEX_NAME)["count"])
    if failed:
        print(f"WARNING: {failed} documents failed to index")
    print(f"Done: {count:,} documents in {INDEX_NAME}")
    return count


# --- main --------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic Zeek conn logs and load them into Elasticsearch.")
    parser.add_argument("--es-url", default=ES_URL, help=f"Elasticsearch URL (default {ES_URL})")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED, help="random seed (default %(default)s)")
    parser.add_argument("--dry-run", action="store_true", help="generate and summarise only; do not touch Elasticsearch")
    parser.add_argument("--csv", type=Path, help="also write the generated events to this CSV (flattened like the connector output)")
    parser.add_argument("--keep-index", action="store_true", help="fail instead of deleting an existing data stream")
    parser.add_argument("--wait", type=int, default=120, help="seconds to wait for Elasticsearch to become ready")
    args = parser.parse_args()

    print(f"Generating {TOTAL_EVENTS:,} Zeek conn events (seed {args.seed})...")
    docs, summary = generate_events(args.seed)
    for key, value in summary.items():
        print(f"  {key:22s} {value}")

    if args.csv:
        write_csv(docs, args.csv)
    if args.dry_run:
        print("Dry run: skipping Elasticsearch load")
        return

    count = load_into_elasticsearch(docs, args.es_url, recreate=not args.keep_index, wait_seconds=args.wait)
    if count != TOTAL_EVENTS:
        sys.exit(f"Expected {TOTAL_EVENTS:,} documents but the index holds {count:,}")
    print(f"All {TOTAL_EVENTS:,} events loaded into {INDEX_NAME} at {args.es_url}")


if __name__ == "__main__":
    main()
