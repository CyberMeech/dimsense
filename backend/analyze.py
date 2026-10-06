import argparse
import os
import re
import sys
import warnings
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

# NOTE: python-dotenv and supabase are imported lazily inside
# get_supabase_client() so that importing the pure analysis functions
# from the API does not require those packages to be installed.

# Heuristic bounds from the paper's Big Data Dimensional Analysis
# (MIT revised formula): Nnonempty ~ N, 1 << Nunique << N, 1 << Nmax << N.
# Thresholds are dataset-dependent -- tune these for your own log source.
MIN_COVERAGE_RATIO = 0.70
MIN_UNIQUE_VALUES = 5
MAX_UNIQUE_RATIO = 0.5
MIN_MAX_FREQUENCY = 2
MAX_MAX_RATIO = 0.95

# Step 5: a field is a timestamp when more than this share of its non-empty
# values parse as datetimes.
TIMESTAMP_PARSE_RATIO = 0.90
# Preferred names for the primary timestamp, in priority order.
PREFERRED_TIMESTAMP_FIELDS = ("EventTime", "@timestamp")
# Cheap pre-check before attempting datetime parsing: the value must look like
# a date (digits separated by - or /) or carry a clock time (hh:mm). This keeps
# numeric columns such as ports, PIDs, and counters out of the parser.
_DATETIME_HINT = re.compile(r"\d{1,4}[-/]\d{1,2}[-/]\d{1,4}|\d{1,2}:\d{2}")
_TIMESTAMP_SAMPLE_SIZE = 2000

REASON_PASSED = "Well populated, diverse values, moderate concentration — good signal field"
REASON_PRIMARY_KEY = "Unique identifier field — excluded as primary key, not useful for pattern analysis"
REASON_REDUNDANT_TIMESTAMP = "Redundant timestamp field — primary timestamp already selected"
REASON_PRIMARY_TIMESTAMP = "Primary timestamp field — used for time windowing, not analyzed as a dimension"

# Test tenant/connector seeded in the DimSense Supabase schema.
TENANT_ID = "11111111-1111-1111-1111-111111111111"
CONNECTOR_ID = "22222222-2222-2222-2222-222222222222"


# --------------------------------------------------------------------------- #
# Per-field statistics                                                        #
# --------------------------------------------------------------------------- #

def field_stats(series):
    """Compute the per-field dimensional statistics.

    Returns a dict with:
      n_nonempty  count of non-empty values            (Nnonempty)
      n_unique    count of distinct non-empty values   (Nunique)
      n_max       frequency of the most common value   (Nmax)
      n1          count of values that occur exactly once (N1, singletons)
      max_val     the most common value itself, or None when the field is empty
    """
    nonempty = series[series != ""]
    n_nonempty = int(len(nonempty))
    if n_nonempty == 0:
        return {"n_nonempty": 0, "n_unique": 0, "n_max": 0, "n1": 0, "max_val": None}
    counts = nonempty.value_counts()
    return {
        "n_nonempty": n_nonempty,
        "n_unique": int(len(counts)),
        "n_max": int(counts.iloc[0]),
        "n1": int((counts == 1).sum()),
        "max_val": str(counts.index[0]),
    }


def analyze_field(series):
    """Lightweight (Nnonempty, Nunique, Nmax) tuple. Kept for the windowing
    engine, which calls this once per field per window and does not need N1
    or MaxVal."""
    nonempty = series[series != ""]
    n_nonempty = len(nonempty)
    n_unique = nonempty.nunique()
    n_max = int(nonempty.value_counts().max()) if n_nonempty else 0
    return n_nonempty, n_unique, n_max


def passes_filter(n_nonempty, n_unique, n_max, total_records):
    if total_records == 0:
        return False
    coverage_ok = (n_nonempty / total_records) >= MIN_COVERAGE_RATIO
    diversity_ok = MIN_UNIQUE_VALUES <= n_unique <= MAX_UNIQUE_RATIO * total_records
    dominance_ok = MIN_MAX_FREQUENCY <= n_max <= MAX_MAX_RATIO * total_records
    return coverage_ok and diversity_ok and dominance_ok


def classify_reason(n_nonempty, n_unique, n_max, total_records, passed):
    if passed:
        return REASON_PASSED

    # Checked in the same priority order as the paper's three criteria:
    # coverage, then dominance/diversity edge cases.
    coverage_ratio = (n_nonempty / total_records) if total_records else 0
    if coverage_ratio < MIN_COVERAGE_RATIO:
        return (
            f"Present in fewer than {MIN_COVERAGE_RATIO:.0%} of records — too sparse for reliable "
            "analysis. May still be operationally valuable — consider manual override"
        )
    if n_max < MIN_MAX_FREQUENCY:
        return "All or nearly all values unique — likely an ID or hash field, no pattern to analyze at scale"
    if n_unique < MIN_UNIQUE_VALUES:
        return (
            f"Fewer than {MIN_UNIQUE_VALUES} distinct values — near-constant field, "
            "not enough variance to detect"
        )
    if n_unique > MAX_UNIQUE_RATIO * total_records:
        return "Too many distinct values — likely a counter or port number with no repeating pattern"
    return "Single value dominates — constant field, no variance to detect"


# --------------------------------------------------------------------------- #
# Step 5 helper: timestamp detection                                          #
# --------------------------------------------------------------------------- #

def is_timestamp_series(series):
    """True when more than TIMESTAMP_PARSE_RATIO of the non-empty values parse
    as datetimes. A regex pre-check on a sample rejects purely numeric columns
    (ports, PIDs, counters, epoch integers) before the parser runs, so those
    are never mistaken for timestamps."""
    nonempty = series[series != ""]
    if len(nonempty) == 0:
        return False
    sample = nonempty.head(_TIMESTAMP_SAMPLE_SIZE)
    if sample.str.contains(_DATETIME_HINT, regex=True).mean() <= 0.5:
        return False
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        parsed = pd.to_datetime(nonempty, errors="coerce", format="mixed", utc=True)
    return bool(parsed.notna().mean() > TIMESTAMP_PARSE_RATIO)


# --------------------------------------------------------------------------- #
# Full per-dataset analysis (steps 1-5)                                       #
# --------------------------------------------------------------------------- #

def analyze_dataframe(df):
    """Run the revised dimensional analysis over every column of ``df``.

    Steps 1-3: per-field statistics and the three retention filters.
    Step 4:    primary key detection. The primary key is the field with the
               highest Nunique where Nunique >= N (every record distinct). When
               several fields tie, timestamp-like fields are passed over and
               the earliest column wins. Exactly one field, or none, is marked.
    Step 5:    timestamp selection. Every field whose values parse as
               datetimes is marked is_timestamp. The primary timestamp is
               EventTime or @timestamp when present, otherwise the timestamp
               field with the highest Nnonempty; every other timestamp field
               is excluded as redundant.

    Returns one dict per column, in column order, with the keys
    field_name, n_nonempty, n_unique, n_max, n1, max_val, total_records,
    passed_filter, algorithm_recommended, is_primary_key, is_timestamp,
    plain_english_reason.
    """
    total_records = len(df)
    rows = []
    for field_name in df.columns:
        stats = field_stats(df[field_name])
        passed = passes_filter(stats["n_nonempty"], stats["n_unique"], stats["n_max"], total_records)
        rows.append({
            "field_name": field_name,
            **stats,
            "total_records": total_records,
            "passed_filter": passed,
            "algorithm_recommended": passed,
            "is_primary_key": False,
            "is_timestamp": is_timestamp_series(df[field_name]),
            "plain_english_reason": classify_reason(
                stats["n_nonempty"], stats["n_unique"], stats["n_max"], total_records, passed
            ),
        })

    # Step 4: primary key.
    if total_records > 0:
        candidates = [r for r in rows if r["n_unique"] >= total_records]
        if candidates:
            # Highest Nunique first; among ties prefer non-timestamps, then column order.
            best = min(candidates, key=lambda r: (-r["n_unique"], r["is_timestamp"], rows.index(r)))
            best["is_primary_key"] = True
            best["passed_filter"] = False
            best["algorithm_recommended"] = False
            best["plain_english_reason"] = REASON_PRIMARY_KEY

    # Step 5: timestamps.
    timestamps = [r for r in rows if r["is_timestamp"] and not r["is_primary_key"]]
    if timestamps:
        selected = next(
            (r for name in PREFERRED_TIMESTAMP_FIELDS for r in timestamps if r["field_name"] == name),
            None,
        ) or max(timestamps, key=lambda r: (r["n_nonempty"], -rows.index(r)))
        for r in timestamps:
            if r is selected:
                # The primary timestamp keeps its filter verdict; when it fails
                # the three criteria, say why in timestamp terms rather than
                # calling it a counter or port number.
                if not r["passed_filter"]:
                    r["plain_english_reason"] = REASON_PRIMARY_TIMESTAMP
                continue
            r["passed_filter"] = False
            r["algorithm_recommended"] = False
            r["plain_english_reason"] = REASON_REDUNDANT_TIMESTAMP

    return rows


# --------------------------------------------------------------------------- #
# Supabase (CLI only)                                                         #
# --------------------------------------------------------------------------- #

def get_supabase_client():
    from dotenv import load_dotenv
    from supabase import create_client

    load_dotenv()
    url = os.environ.get("SUPABASE_URL")
    key = os.environ.get("SUPABASE_SERVICE_KEY")
    if not url or not key:
        sys.exit("SUPABASE_URL and SUPABASE_SERVICE_KEY must be set in .env")
    return create_client(url, key)


def write_to_supabase(rows):
    client = get_supabase_client()
    table = client.table("retained_fields")

    table.delete().eq("tenant_id", TENANT_ID).eq("connector_id", CONNECTOR_ID).execute()

    computed_at = datetime.now(timezone.utc).isoformat()
    written = 0
    print(f"\nWriting {len(rows)} fields to Supabase retained_fields table...")
    for row in rows:
        record = {
            "tenant_id": TENANT_ID,
            "connector_id": CONNECTOR_ID,
            "field_name": row["field_name"],
            "n_nonempty": int(row["n_nonempty"]),
            "n_unique": int(row["n_unique"]),
            "n_max": int(row["n_max"]),
            "total_records": int(row["total_records"]),
            "passed_filter": bool(row["passed_filter"]),
            "algorithm_recommended": bool(row["algorithm_recommended"]),
            "user_selected": None,
            "confirmed_at": None,
            "computed_at": computed_at,
            "plain_english_reason": row["plain_english_reason"],
        }
        try:
            table.insert(record).execute()
            written += 1
            print(f"  wrote {row['field_name']}")
        except Exception as exc:
            print(f"  FAILED to write {row['field_name']}: {exc}")

    print(f"\n{written}/{len(rows)} rows written to Supabase retained_fields table")


# --------------------------------------------------------------------------- #
# CLI                                                                         #
# --------------------------------------------------------------------------- #

def main():
    parser = argparse.ArgumentParser(
        description="Big Data Dimensional Analysis over a host-based EDR log export."
    )
    parser.add_argument("--csv", required=True, help="Path to the log CSV file")
    parser.add_argument("--sep", default=",", help="Field delimiter (default ',')")
    parser.add_argument("--output", help="Optional path to write the per-field report as CSV")
    parser.add_argument("--no-supabase", action="store_true", help="Skip writing results to Supabase")
    args = parser.parse_args()

    csv_path = Path(args.csv)
    if not csv_path.exists():
        sys.exit(f"File not found: {csv_path}")

    # na_filter=False keeps empty cells as "" instead of NaN, so
    # "nonempty" has one unambiguous definition: value != "".
    df = pd.read_csv(csv_path, sep=args.sep, dtype=str, na_filter=False)
    total_records = len(df)

    rows = analyze_dataframe(df)

    report = pd.DataFrame(rows).sort_values("n_unique", ascending=False).reset_index(drop=True)
    report.insert(0, "rank", report.index + 1)

    display = report[[
        "rank", "field_name", "n_nonempty", "n_unique", "n_max", "n1", "max_val",
        "passed_filter", "is_primary_key", "is_timestamp",
    ]].copy()
    display["max_val"] = display["max_val"].map(
        lambda v: "" if v is None else (v if len(v) <= 30 else v[:27] + "...")
    )

    print(f"\nAnalyzed {total_records} records across {len(df.columns)} fields\n")
    print(display.to_string(index=False))

    kept = int(report["passed_filter"].sum())
    print(f"\n{kept}/{len(df.columns)} fields passed all filters "
          f"({(1 - kept / len(df.columns)) * 100:.1f}% eliminated)")
    pk = [r["field_name"] for r in rows if r["is_primary_key"]]
    ts = [r["field_name"] for r in rows if r["is_timestamp"]]
    print(f"Primary key: {pk[0] if pk else '(none detected)'}")
    print(f"Timestamp fields: {', '.join(ts) if ts else '(none detected)'}")

    if args.output:
        report.to_csv(args.output, index=False)
        print(f"\nReport written to {args.output}")

    if not args.no_supabase:
        write_to_supabase(rows)


if __name__ == "__main__":
    main()
