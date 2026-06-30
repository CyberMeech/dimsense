import argparse
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
from dotenv import load_dotenv
from supabase import create_client

# Heuristic bounds from the paper's Big Data Dimensional Analysis:
# Nnonempty ~ N, 1 << Nunique << N, 1 << Nmax << N. Thresholds are
# dataset-dependent -- tune these for your own log source.
MIN_COVERAGE_RATIO = 0.95
MIN_UNIQUE_VALUES = 5
MAX_UNIQUE_RATIO = 0.5
MIN_MAX_FREQUENCY = 2
MAX_MAX_RATIO = 0.95

# Test tenant/connector seeded in the DimSense Supabase schema.
TENANT_ID = "11111111-1111-1111-1111-111111111111"
CONNECTOR_ID = "22222222-2222-2222-2222-222222222222"


def analyze_field(series):
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
        return "Well populated, diverse values, moderate concentration — good signal field"

    # Checked in the same priority order as the paper's three criteria:
    # coverage, then dominance/diversity edge cases.
    coverage_ratio = (n_nonempty / total_records) if total_records else 0
    if coverage_ratio < MIN_COVERAGE_RATIO:
        return (
            "Present in fewer than 80% of records — too sparse for reliable "
            "analysis. May still be operationally valuable — consider manual override"
        )
    if n_max < MIN_MAX_FREQUENCY:
        return "All or nearly all values unique — likely an ID or hash field, no pattern to analyze at scale"
    if n_unique < MIN_UNIQUE_VALUES:
        return "Single value dominates — constant field, no variance to detect"
    if n_unique > MAX_UNIQUE_RATIO * total_records:
        return "Too many distinct values — likely a counter or port number with no repeating pattern"
    return "Single value dominates — constant field, no variance to detect"


def get_supabase_client():
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
            "plain_english_reason": classify_reason(
                row["n_nonempty"], row["n_unique"], row["n_max"],
                row["total_records"], row["passed_filter"],
            ),
        }
        try:
            table.insert(record).execute()
            written += 1
            print(f"  wrote {row['field_name']}")
        except Exception as exc:
            print(f"  FAILED to write {row['field_name']}: {exc}")

    print(f"\n{written}/{len(rows)} rows written to Supabase retained_fields table")


def main():
    parser = argparse.ArgumentParser(
        description="Big Data Dimensional Analysis over a host-based EDR log export."
    )
    parser.add_argument("--csv", required=True, help="Path to the log CSV file")
    parser.add_argument("--sep", default=",", help="Field delimiter (default ',')")
    parser.add_argument("--output", help="Optional path to write the per-field report as CSV")
    args = parser.parse_args()

    csv_path = Path(args.csv)
    if not csv_path.exists():
        sys.exit(f"File not found: {csv_path}")

    # na_filter=False keeps empty cells as "" instead of NaN, so
    # "nonempty" has one unambiguous definition: value != "".
    df = pd.read_csv(csv_path, sep=args.sep, dtype=str, na_filter=False)
    total_records = len(df)

    rows = []
    for field_name in df.columns:
        n_nonempty, n_unique, n_max = analyze_field(df[field_name])
        passed = passes_filter(n_nonempty, n_unique, n_max, total_records)
        rows.append({
            "field_name": field_name,
            "n_nonempty": n_nonempty,
            "n_unique": n_unique,
            "n_max": n_max,
            "total_records": total_records,
            "passed_filter": passed,
            "algorithm_recommended": passed,
        })

    report = pd.DataFrame(rows).sort_values("n_unique", ascending=False).reset_index(drop=True)
    report.insert(0, "rank", report.index + 1)

    print(f"\nAnalyzed {total_records} records across {len(df.columns)} fields\n")
    print(report.to_string(index=False))

    kept = int(report["passed_filter"].sum())
    print(f"\n{kept}/{len(df.columns)} fields passed all three filters "
          f"({(1 - kept / len(df.columns)) * 100:.1f}% eliminated)")

    if args.output:
        report.to_csv(args.output, index=False)
        print(f"\nReport written to {args.output}")

    write_to_supabase(rows)


if __name__ == "__main__":
    main()
