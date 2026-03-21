"""
cli.py
------
Command-line interface for the Log Analyzer.

Why a CLI?
  - Real DevOps/DE environments run log analysis as cron jobs, not GUIs
  - Must integrate into CI/CD pipelines and shell scripts
  - Streamlit-only tools CANNOT be used in production automation

Usage:
  python cli.py --input data/raw/access.log --report
  python cli.py --input data/raw/ --batch "*.log.gz" --anomaly
  python cli.py --input data/raw/access.log --brute-force --threshold 10 --window 5
"""

import sys
import argparse
import logging
from pathlib import Path

import pandas as pd

# ─── Dependency check ─────────────────────────────────────────────────────────

def _check_deps():
    missing = []
    for pkg in ['pandas', 'plotly']:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
    if missing:
        print(f"[ERROR] Missing packages: {', '.join(missing)}")
        print("Install with: pip install -r requirements.txt")
        sys.exit(1)

_check_deps()

from src.parser   import parse_log_file, batch_parse, save_parquet
from src.analyzer import add_features, get_summary_stats, detect_traffic_anomalies, detect_brute_force, get_top_ips, get_top_404_paths

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("log_analyzer.cli")


# ─── CLI Definition ───────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="log_analyzer",
        description="Apache Log Intelligence CLI — Parse, Analyze, and Report",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Parse a single log file and print summary
  python cli.py --input data/raw/access.log --report

  # Batch parse a directory of gzipped logs
  python cli.py --input data/raw/ --batch "*.log.gz" --report

  # Run anomaly detection with custom Z-score threshold
  python cli.py --input data/raw/access.log --anomaly --z-score 2.5

  # Detect brute-force: >20 failures in 5 min window
  python cli.py --input data/raw/access.log --brute-force --threshold 20 --window 5

  # Export Parquet for fast future reloads
  python cli.py --input data/raw/access.log --save-parquet data/processed/logs.parquet
        """,
    )

    # Input
    p.add_argument('--input', '-i', required=True,
                   help='Path to a .log file or directory (use with --batch)')
    p.add_argument('--batch', '-b', default=None, metavar='PATTERN',
                   help='Glob pattern for batch parsing (e.g. "*.log.gz")')

    # Actions
    p.add_argument('--report', action='store_true',
                   help='Print summary statistics report')
    p.add_argument('--anomaly', action='store_true',
                   help='Run Z-score traffic anomaly detection')
    p.add_argument('--z-score', type=float, default=3.0, metavar='FLOAT',
                   help='Z-score threshold for anomaly detection (default: 3.0)')
    p.add_argument('--brute-force', action='store_true',
                   help='Detect brute-force login attempts')
    p.add_argument('--threshold', type=int, default=20, metavar='INT',
                   help='Failures in window to flag as brute-force (default: 20)')
    p.add_argument('--window', type=int, default=5, metavar='MINUTES',
                   help='Rolling window in minutes for brute-force (default: 5)')
    p.add_argument('--top-ips', type=int, default=0, metavar='N',
                   help='Print top N IPs by request volume')
    p.add_argument('--top-404', type=int, default=0, metavar='N',
                   help='Print top N paths returning 404')

    # Output
    p.add_argument('--save-parquet', metavar='PATH',
                   help='Save parsed DataFrame to Parquet for fast reloads')
    p.add_argument('--output-csv', metavar='PATH',
                   help='Export analysis results to CSV')
    p.add_argument('--verbose', '-v', action='store_true',
                   help='Enable verbose logging')

    return p


# ─── Ingestion ────────────────────────────────────────────────────────────────

def ingest(args: argparse.Namespace) -> pd.DataFrame:
    """Load and parse log file(s) based on CLI args."""
    input_path = Path(args.input)

    if args.batch:
        if not input_path.is_dir():
            logger.error("--batch requires --input to be a directory. Got: %s", input_path)
            sys.exit(1)
        logger.info("Batch parsing: %s [pattern=%s]", input_path, args.batch)
        df = batch_parse(input_path, pattern=args.batch)
    else:
        if not input_path.is_file():
            logger.error("File not found: %s", input_path)
            sys.exit(1)
        logger.info("Parsing: %s", input_path)
        df = parse_log_file(input_path)

    return df


# ─── Report Printer ───────────────────────────────────────────────────────────

def print_summary(df: pd.DataFrame):
    stats = get_summary_stats(df)
    print("\n" + "═" * 55)
    print("  📊  LOG ANALYSIS SUMMARY REPORT")
    print("═" * 55)
    for key, value in stats.items():
        label = key.replace('_', ' ').title()
        print(f"  {label:<28} {value}")
    print("═" * 55)


def print_df(title: str, df: pd.DataFrame, max_rows: int = 20):
    print(f"\n{'─' * 55}")
    print(f"  {title}")
    print("─" * 55)
    if df.empty:
        print("  (No results)")
    else:
        print(df.head(max_rows).to_string(index=False))
    print()


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = build_parser()
    args   = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # ── Ingest ──
    df = ingest(args)
    df = add_features(df)

    logger.info("Loaded %d log entries | %d unique IPs", len(df), df['ip'].nunique())

    # ── Save Parquet ──
    if args.save_parquet:
        save_parquet(df, args.save_parquet)
        print(f"✅ Saved to: {args.save_parquet}")

    # ── Summary Report ──
    if args.report:
        print_summary(df)

    # ── Top IPs ──
    if args.top_ips > 0:
        top_ips_df = get_top_ips(df, n=args.top_ips)
        print_df(f"TOP {args.top_ips} IPs BY REQUEST VOLUME", top_ips_df)
        if args.output_csv:
            out = Path(args.output_csv)
            top_ips_df.to_csv(out.with_stem(out.stem + '_top_ips'), index=False)

    # ── Top 404 Paths ──
    if args.top_404 > 0:
        paths_df = get_top_404_paths(df, n=args.top_404)
        print_df(f"TOP {args.top_404} PATHS RETURNING 404", paths_df)

    # ── Traffic Anomaly Detection ──
    if args.anomaly:
        anomalies = detect_traffic_anomalies(df, z_threshold=args.z_score)
        print_df(
            f"TRAFFIC ANOMALIES  (Z-Score ≥ {args.z_score})",
            anomalies[['ip', 'date', 'hour', 'request_count', 'z_score']]
        )
        if args.output_csv and not anomalies.empty:
            out = Path(args.output_csv)
            anomalies.to_csv(out.with_stem(out.stem + '_anomalies'), index=False)
            print(f"✅ Anomaly report saved: {out.with_stem(out.stem + '_anomalies')}")

    # ── Brute-Force Detection ──
    if args.brute_force:
        bf = detect_brute_force(df, window_minutes=args.window, threshold=args.threshold)
        print_df(
            f"BRUTE-FORCE SUSPECTS  (≥{args.threshold} failures in {args.window}min)",
            bf
        )
        if args.output_csv and not bf.empty:
            out = Path(args.output_csv)
            bf.to_csv(out.with_stem(out.stem + '_bruteforce'), index=False)
            print(f"✅ Brute-force report saved.")

    # ── Default: at least show summary if nothing else requested ──
    if not any([args.report, args.anomaly, args.brute_force,
                args.top_ips > 0, args.top_404 > 0]):
        print_summary(df)


if __name__ == '__main__':
    main()
