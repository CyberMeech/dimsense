import statistics
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from starlette.exceptions import HTTPException as StarletteHTTPException

try:
    from analyze import analyze_field, classify_reason, passes_filter  # Railway: backend/ is root
except ImportError:
    from backend.analyze import analyze_field, classify_reason, passes_filter  # local: run from project root

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"

SESSION_TTL_SECONDS = 60 * 60
WINDOW_SIZE = 8192
ROLLING_WINDOW = 20
ROLLING_MIN_PERIODS = 5
ZSCORE_THRESHOLD = 3.0
ANOMALY_SCORE_THRESHOLD = 3

sessions: dict[str, dict] = {}


def _purge_expired_sessions() -> None:
    now = time.time()
    expired = [sid for sid, s in sessions.items() if now - s["created_at"] > SESSION_TTL_SECONDS]
    for sid in expired:
        session = sessions.pop(sid)
        csv_path = session.get("csv_path")
        if csv_path and Path(csv_path).exists():
            Path(csv_path).unlink(missing_ok=True)


def _get_session(session_id: str) -> dict:
    _purge_expired_sessions()
    session = sessions.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found or has expired")
    return session


@asynccontextmanager
async def lifespan(app: FastAPI):
    UPLOAD_DIR.mkdir(exist_ok=True)
    yield


app = FastAPI(title="DimSense API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    duration_ms = (time.perf_counter() - start) * 1000
    timestamp = datetime.now(timezone.utc).isoformat()
    print(f"[{timestamp}] {request.method} {request.url.path} -> {response.status_code} ({duration_ms:.1f}ms)")
    return response


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    return JSONResponse(status_code=exc.status_code, content={"error": exc.detail})


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    messages = "; ".join(
        f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()
    )
    return JSONResponse(status_code=422, content={"error": f"Invalid request: {messages}"})


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    return JSONResponse(status_code=500, content={"error": f"Internal server error: {exc}"})


class ConfirmFieldsRequest(BaseModel):
    selected_fields: list[str]


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/upload-csv")
async def upload_csv(file: UploadFile = File(...)):
    _purge_expired_sessions()

    contents = await file.read()
    if not contents:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    session_id = str(uuid.uuid4())
    csv_path = UPLOAD_DIR / f"{session_id}.csv"
    csv_path.write_bytes(contents)

    try:
        df = pd.read_csv(csv_path, dtype=str, na_filter=False)
    except Exception as exc:
        csv_path.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail=f"Could not parse CSV: {exc}")

    if len(df.columns) == 0:
        csv_path.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail="CSV has no columns")

    sessions[session_id] = {
        "created_at": time.time(),
        "csv_path": str(csv_path),
        "df": df,
        "analysis": None,
        "confirmed_fields": None,
    }

    return {
        "session_id": session_id,
        "row_count": len(df),
        "field_count": len(df.columns),
        "preview": df.head(5).to_dict(orient="records"),
    }


@app.post("/analyze/{session_id}")
async def analyze(session_id: str):
    session = _get_session(session_id)
    df = session["df"]
    total_records = len(df)

    fields = []
    for field_name in df.columns:
        n_nonempty, n_unique, n_max = analyze_field(df[field_name])
        passed = passes_filter(n_nonempty, n_unique, n_max, total_records)
        reason = classify_reason(n_nonempty, n_unique, n_max, total_records, passed)
        fields.append({
            "field_name": field_name,
            "n_nonempty": n_nonempty,
            "n_unique": n_unique,
            "n_max": n_max,
            "total_records": total_records,
            "passed_filter": passed,
            "algorithm_recommended": passed,
            "plain_english_reason": reason,
        })

    session["analysis"] = fields

    csv_path = session.get("csv_path")
    if csv_path and Path(csv_path).exists():
        Path(csv_path).unlink(missing_ok=True)
    session["csv_path"] = None

    return {
        "session_id": session_id,
        "total_records": total_records,
        "total_fields": len(df.columns),
        "fields": fields,
    }


def _zscore_series(values: pd.Series) -> pd.Series:
    # Baseline is built from prior windows only (current window excluded) so a
    # spike can't inflate its own median/std and dampen its z-score. Scoring
    # starts once 5 windows total have been observed, i.e. 4 prior windows.
    prior = values.shift(1)
    rolling = prior.rolling(window=ROLLING_WINDOW, min_periods=ROLLING_MIN_PERIODS - 1)
    median = rolling.median()
    std = rolling.std()
    zscore = (values - median) / std
    return zscore.replace([np.inf, -np.inf], np.nan)


def _top_value(series: pd.Series) -> tuple[str | None, int]:
    nonempty = series[series != ""]
    if len(nonempty) == 0:
        return None, 0
    counts = nonempty.value_counts()
    return str(counts.idxmax()), int(counts.max())


FIELD_LABELS = {
    "SrcIP": "source IP",
    "DstIP": "destination IP",
    "DstPort": "destination port",
    "SrcPort": "source port",
    "EventType": "event type",
    "BytesSent": "bytes sent",
    "BytesReceived": "bytes received",
    "SrcProcName": "source process name",
    "SrcProcCmdLine": "source process command line",
    "SrcProcUser": "source process user",
    "TgtProcName": "target process name",
    "TgtProcPID": "target process PID",
    "AgentName": "agent",
    "AgentID": "agent ID",
    "SiteName": "site",
    "GroupName": "group",
    "OSType": "OS type",
    "OSVersion": "OS version",
    "UserName": "user",
    "UserSID": "user SID",
    "LogonType": "logon type",
    "DNSDomain": "DNS domain",
    "DNSResponseIP": "DNS response IP",
    "FilePath": "file path",
    "FileExtension": "file extension",
    "RegistryKeyPath": "registry key path",
    "ThreatName": "threat name",
    "IndicatorCategory": "indicator category",
}


def _field_label(field_name: str) -> str:
    return FIELD_LABELS.get(field_name, field_name)


def _human_time_range(start: pd.Timestamp, end: pd.Timestamp) -> str:
    if start.date() == end.date():
        return f"{start.strftime('%B %d, %Y')} between {start.strftime('%H:%M')} and {end.strftime('%H:%M')} UTC"
    return f"{start.strftime('%B %d, %Y %H:%M')} UTC to {end.strftime('%B %d, %Y %H:%M')} UTC"


def _field_observation(
    field_name: str,
    top_value: str | None,
    top_value_pct: float,
    baseline_pct: float,
    n_unique: int,
    baseline_n_unique: float,
    n_max_anomalous: bool,
) -> str:
    label = _field_label(field_name)
    if top_value is None:
        return f"{label} had no populated values in this window"
    if n_max_anomalous:
        return (
            f"{label} {top_value} accounted for {top_value_pct}% of observed events in this window, "
            f"compared to a typical baseline of {round(baseline_pct, 1)}%"
        )
    return (
        f"{label} broadened to {n_unique} distinct values in this window (typical baseline ~"
        f"{baseline_n_unique:.0f}), though the most common value {top_value} still only accounted for "
        f"{top_value_pct}% of events"
    )


def _pattern_clause(event_rate_spiked: bool, n_max_spiked: bool, n_unique_spiked: bool, rate_multiplier: float) -> str:
    if event_rate_spiked and n_max_spiked and n_unique_spiked:
        return (
            f"this pattern is consistent with coordinated activity across multiple dimensions "
            f"simultaneously — event volume rose to {rate_multiplier}x the typical rate while activity "
            f"both concentrated around dominant entities and broadened across more sources, consistent "
            f"with command-and-control callbacks or coordinated lateral movement"
        )
    if n_max_spiked and not n_unique_spiked:
        return (
            "this pattern is consistent with concentrated activity, where a small number of entities "
            "account for a disproportionate share of activity while overall participation stayed normal "
            "— potentially beaconing, focused reconnaissance, or abuse of a specific account or host"
        )
    if n_unique_spiked and not n_max_spiked:
        return (
            "this pattern is consistent with broad participation across more distinct entities than "
            "normal without a single dominant entity — potentially scanning activity, worm-like spread, "
            "or a coordinated callback from multiple infected hosts"
        )
    if event_rate_spiked and not n_max_spiked and not n_unique_spiked:
        return (
            f"this pattern is consistent with a volume spike without a distributional shift — event "
            f"volume rose to {rate_multiplier}x the typical rate but concentration and diversity stayed "
            f"normal, potentially a scheduled batch job, backup process, or benign workload spike"
        )
    if n_max_spiked and not event_rate_spiked:
        return (
            "this pattern is consistent with quiet, low-and-slow concentration designed to avoid "
            "volume-based detection"
        )
    return "this pattern combines multiple anomalous dimensional metrics that don't fit a single category"


def _build_interpretation(
    window_start_ts: pd.Timestamp,
    window_end_ts: pd.Timestamp,
    window_start_iso: str,
    window_end_iso: str,
    contributing_field_stats: list[dict],
    baseline_pct_by_field: dict[str, float],
    baseline_nunique_by_field: dict[str, float],
    event_rate_spiked: bool,
    n_max_spiked: bool,
    n_unique_spiked: bool,
    rate_multiplier: float,
) -> str:
    time_range = _human_time_range(window_start_ts, window_end_ts)

    def _severity(fs: dict) -> float:
        zs = [abs(z) for z in (fs.get("n_unique_zscore"), fs.get("n_max_zscore")) if z is not None]
        return max(zs) if zs else 0.0

    ranked = sorted(contributing_field_stats, key=_severity, reverse=True)
    sentences = []
    for fs in ranked[:2]:
        field_name = fs["field_name"]
        sentence = _field_observation(
            field_name,
            fs.get("top_value"),
            fs.get("top_value_pct"),
            baseline_pct_by_field.get(field_name, 0.0),
            fs["n_unique"],
            baseline_nunique_by_field.get(field_name, 0),
            fs["n_max_anomalous"],
        )
        sentences.append(sentence[0].upper() + sentence[1:] + ".")
    observation_text = " ".join(sentences)

    pattern_clause = _pattern_clause(event_rate_spiked, n_max_spiked, n_unique_spiked, rate_multiplier)

    return (
        f"During {time_range}, {observation_text} {pattern_clause[0].upper()}{pattern_clause[1:]}. "
        f"Verify with your team whether any scheduled task, software deployment, or authorized "
        f"maintenance explains this activity between {window_start_iso} and {window_end_iso}. If no "
        f"expected activity accounts for this pattern, treat as a potential incident and initiate your "
        f"IR process per your organization's SOPs."
    )


@app.post("/confirm-fields/{session_id}")
async def confirm_fields(session_id: str, body: ConfirmFieldsRequest):
    session = _get_session(session_id)
    if session.get("analysis") is None:
        raise HTTPException(status_code=400, detail="Run /analyze on this session before confirming fields")

    selected_fields = body.selected_fields
    if not selected_fields:
        raise HTTPException(status_code=400, detail="selected_fields must not be empty")

    df = session["df"]
    unknown = [f for f in selected_fields if f not in df.columns]
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unknown field(s): {', '.join(unknown)}")
    if "EventTime" not in df.columns:
        raise HTTPException(status_code=400, detail="CSV has no EventTime column required for windowing")

    try:
        event_time = pd.to_datetime(df["EventTime"])
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Could not parse EventTime column: {exc}")

    ordered = df.assign(_event_time=event_time).sort_values("_event_time").reset_index(drop=True)
    total_records = len(ordered)
    total_windows = total_records // WINDOW_SIZE

    if total_windows == 0:
        raise HTTPException(
            status_code=400,
            detail=f"Not enough records ({total_records}) to form a single window of {WINDOW_SIZE}",
        )

    window_meta = []
    field_unique_series: dict[str, list[int]] = {f: [] for f in selected_fields}
    field_max_series: dict[str, list[int]] = {f: [] for f in selected_fields}
    event_rate_values = []

    for w in range(total_windows):
        start = w * WINDOW_SIZE
        end = start + WINDOW_SIZE
        chunk = ordered.iloc[start:end]
        window_start = chunk["_event_time"].iloc[0]
        window_end = chunk["_event_time"].iloc[-1]

        duration_hours = max((window_end - window_start).total_seconds() / 3600, 1e-9)
        event_rate = WINDOW_SIZE / duration_hours

        window_meta.append({
            "window_index": w,
            "window_start_ts": window_start,
            "window_end_ts": window_end,
            "window_start": window_start.isoformat(),
            "window_end": window_end.isoformat(),
            "event_rate_per_hour": event_rate,
        })
        event_rate_values.append(event_rate)

        for field_name in selected_fields:
            _, n_unique, n_max = analyze_field(chunk[field_name])
            field_unique_series[field_name].append(n_unique)
            field_max_series[field_name].append(n_max)

    event_rate_z = _zscore_series(pd.Series(event_rate_values))
    event_rate_anomalous = (event_rate_z.abs() > ZSCORE_THRESHOLD).fillna(False)

    field_unique_z = {}
    field_unique_anomalous = {}
    field_max_z = {}
    field_max_anomalous = {}
    for field_name in selected_fields:
        z_u = _zscore_series(pd.Series(field_unique_series[field_name]))
        field_unique_z[field_name] = z_u
        field_unique_anomalous[field_name] = (z_u.abs() > ZSCORE_THRESHOLD).fillna(False)

        z_m = _zscore_series(pd.Series(field_max_series[field_name]))
        field_max_z[field_name] = z_m
        field_max_anomalous[field_name] = (z_m.abs() > ZSCORE_THRESHOLD).fillna(False)

    windows = []
    flagged_indices = []
    window_spike_flags = {}
    for w in range(total_windows):
        field_stats = []
        n_max_spiked = False
        n_unique_spiked = False
        anomaly_score = int(bool(event_rate_anomalous.iloc[w]))

        for field_name in selected_fields:
            u_anom = bool(field_unique_anomalous[field_name].iloc[w])
            m_anom = bool(field_max_anomalous[field_name].iloc[w])
            anomaly_score += int(u_anom) + int(m_anom)
            n_unique_spiked = n_unique_spiked or u_anom
            n_max_spiked = n_max_spiked or m_anom

            u_z = field_unique_z[field_name].iloc[w]
            m_z = field_max_z[field_name].iloc[w]
            field_stats.append({
                "field_name": field_name,
                "n_unique": field_unique_series[field_name][w],
                "n_max": field_max_series[field_name][w],
                "n_unique_zscore": None if pd.isna(u_z) else float(u_z),
                "n_max_zscore": None if pd.isna(m_z) else float(m_z),
                "n_unique_anomalous": u_anom,
                "n_max_anomalous": m_anom,
            })

        is_flagged = anomaly_score >= ANOMALY_SCORE_THRESHOLD
        window = {
            "window_index": w,
            "window_start": window_meta[w]["window_start"],
            "window_end": window_meta[w]["window_end"],
            "event_rate_per_hour": window_meta[w]["event_rate_per_hour"],
            "anomaly_score": anomaly_score,
            "is_flagged": is_flagged,
            "field_stats": field_stats,
        }
        windows.append(window)

        if is_flagged:
            flagged_indices.append(w)
            window_spike_flags[w] = (bool(event_rate_anomalous.iloc[w]), n_max_spiked, n_unique_spiked)

    non_flagged = [w for w in range(total_windows) if w not in flagged_indices] or list(range(total_windows))
    baseline_event_rate = statistics.median(event_rate_values[w] for w in non_flagged)
    baseline_pct_by_field = {
        f: statistics.median(field_max_series[f][w] for w in non_flagged) / WINDOW_SIZE * 100
        for f in selected_fields
    }
    baseline_nunique_by_field = {
        f: statistics.median(field_unique_series[f][w] for w in non_flagged)
        for f in selected_fields
    }

    flagged_windows = []
    for window in windows:
        if not window["is_flagged"]:
            continue
        w = window["window_index"]
        chunk = ordered.iloc[w * WINDOW_SIZE:w * WINDOW_SIZE + WINDOW_SIZE]
        event_rate_spiked, n_max_spiked, n_unique_spiked = window_spike_flags[w]

        flagged_event_rate = window["event_rate_per_hour"]
        rate_multiplier = round(flagged_event_rate / baseline_event_rate, 1)

        enriched_field_stats = []
        contributing = []
        for fs in window["field_stats"]:
            fs_copy = dict(fs)
            if fs["n_max_anomalous"] or fs["n_unique_anomalous"]:
                top_value, top_value_count = _top_value(chunk[fs["field_name"]])
                fs_copy["top_value"] = top_value
                fs_copy["top_value_count"] = top_value_count
                fs_copy["top_value_pct"] = round(top_value_count / WINDOW_SIZE * 100, 1)
                contributing.append(fs_copy)
            enriched_field_stats.append(fs_copy)

        interpretation = _build_interpretation(
            window_meta[w]["window_start_ts"],
            window_meta[w]["window_end_ts"],
            window_meta[w]["window_start"],
            window_meta[w]["window_end"],
            contributing,
            baseline_pct_by_field,
            baseline_nunique_by_field,
            event_rate_spiked,
            n_max_spiked,
            n_unique_spiked,
            rate_multiplier,
        )

        flagged_windows.append({
            **window,
            "field_stats": enriched_field_stats,
            "baseline_event_rate": baseline_event_rate,
            "flagged_event_rate": flagged_event_rate,
            "rate_multiplier": rate_multiplier,
            "interpretation": interpretation,
        })

    session["confirmed_fields"] = selected_fields

    return {
        "session_id": session_id,
        "window_size": WINDOW_SIZE,
        "total_windows": total_windows,
        "windows": windows,
        "flagged_windows": flagged_windows,
    }
