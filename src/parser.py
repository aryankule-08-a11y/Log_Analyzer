"""
parser.py
---------
Parses raw Apache Combined Log Format files into structured Pandas DataFrames.

Supports:
  - Plain .log files
  - Gzip-compressed .log.gz files
  - Batch parsing of entire directories

Apache Combined Log Format example:
  192.168.1.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://ref.com/" "Mozilla/5.0"
"""

import re
import gzip
import logging
from pathlib import Path
from typing import Generator
import pandas as pd

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)

# ─── Regex Pattern ────────────────────────────────────────────────────────────
# Matches Apache Combined Log Format (CLF + referrer + user-agent)
APACHE_LOG_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+'                        # IP address
    r'\S+\s+'                                # ident (ignored, usually -)
    r'(?P<user>\S+)\s+'                      # auth user (usually -)
    r'\[(?P<timestamp>[^\]]+)\]\s+'          # [timestamp]
    r'"(?P<method>[A-Z]+|-)?\s*'             # HTTP method (GET/POST/etc or -)
    r'(?P<path>\S+)?\s*'                     # Request path
    r'(?P<protocol>HTTP/[\d.]+)?"\s*'        # HTTP version
    r'(?P<status>\d{3})\s+'                  # Status code (3 digits)
    r'(?P<bytes>\S+)'                        # Bytes transferred (or -)
    r'(?:\s+"(?P<referrer>[^"]*)")?'         # Optional referrer
    r'(?:\s+"(?P<user_agent>[^"]*)")?'       # Optional user-agent
)

TIMESTAMP_FMT = "%d/%b/%Y:%H:%M:%S %z"


# ─── File Opener ──────────────────────────────────────────────────────────────

def _open_log_file(path: Path) -> Generator[str, None, None]:
    """Opens a plain or gzip-compressed log file and yields raw lines."""
    if path.suffix == '.gz':
        with gzip.open(path, 'rt', encoding='utf-8', errors='replace') as f:
            yield from f
    else:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            yield from f


# ─── Core Parser ──────────────────────────────────────────────────────────────

def parse_log_file(file_path: str | Path) -> pd.DataFrame:
    """
    Parse a raw Apache Combined Log Format file into a typed DataFrame.

    Parameters
    ----------
    file_path : str or Path
        Path to a .log or .log.gz file.

    Returns
    -------
    pd.DataFrame
        Columns: ip, user, timestamp, method, path, protocol,
                 status, bytes, referrer, user_agent

    Raises
    ------
    FileNotFoundError
        If the log file does not exist.
    ValueError
        If no valid log lines are found.
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")

    records = []
    total_lines = 0
    failed_lines = 0

    for line in _open_log_file(path):
        total_lines += 1
        line = line.strip()
        if not line:
            continue

        match = APACHE_LOG_PATTERN.match(line)
        if not match:
            failed_lines += 1
            logger.debug("Unparseable line %d: %s", total_lines, line[:120])
            continue

        records.append(match.groupdict())

    parse_pct = (len(records) / total_lines * 100) if total_lines else 0.0
    logger.info(
        "Parsed %d / %d lines (%.1f%%) | Failed: %d | File: %s",
        len(records), total_lines, parse_pct, failed_lines, path.name
    )

    if not records:
        raise ValueError(
            f"No valid Apache log lines found in '{path}'. "
            "Check the file format — expected Apache Combined Log Format."
        )

    df = pd.DataFrame(records)
    df = _cast_columns(df)
    return df


# ─── Type Casting ─────────────────────────────────────────────────────────────

def _cast_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Cast parsed string columns to correct Python/Pandas types."""

    # Status code → Int16 (fits 100–599, saves memory)
    df['status'] = pd.to_numeric(df['status'], errors='coerce').astype('Int16')

    # Bytes → int64 (handle '-' which Apache writes when bytes = 0)
    df['bytes'] = df['bytes'].replace('-', '0')
    df['bytes'] = pd.to_numeric(df['bytes'], errors='coerce').fillna(0).astype('int64')

    # Timestamp → UTC-aware datetime
    df['timestamp'] = pd.to_datetime(
        df['timestamp'],
        format=TIMESTAMP_FMT,
        errors='coerce',
        utc=True
    )

    # Drop rows where timestamp failed to parse
    bad_ts = df['timestamp'].isna().sum()
    if bad_ts > 0:
        logger.warning("Dropped %d rows with unparseable timestamps.", bad_ts)
        df = df.dropna(subset=['timestamp'])

    # Normalize missing string fields
    for col in ['user', 'method', 'referrer', 'user_agent']:
        if col in df.columns:
            df[col] = df[col].replace('-', None)

    return df.reset_index(drop=True)


# ─── Batch Parser ─────────────────────────────────────────────────────────────

def batch_parse(log_dir: str | Path, pattern: str = "*.log") -> pd.DataFrame:
    """
    Parse all log files matching a glob pattern in a directory.

    Parameters
    ----------
    log_dir : str or Path
        Directory containing log files.
    pattern : str
        Glob pattern to match, e.g. '*.log', '*.log.gz', 'access_*.log'

    Returns
    -------
    pd.DataFrame
        Combined DataFrame from all matched files.
    """
    log_dir = Path(log_dir)
    files = sorted(log_dir.glob(pattern))

    if not files:
        raise FileNotFoundError(
            f"No files matching '{pattern}' found in: {log_dir}"
        )

    logger.info("Batch parsing %d files from: %s", len(files), log_dir)
    dfs = []
    for f in files:
        try:
            dfs.append(parse_log_file(f))
        except (ValueError, FileNotFoundError, OSError) as exc:
            logger.error("Skipped '%s': %s", f.name, exc)

    if not dfs:
        raise ValueError("No files were successfully parsed.")

    combined = pd.concat(dfs, ignore_index=True)
    logger.info(
        "Batch parse complete — total rows: %d | unique IPs: %d",
        len(combined),
        combined['ip'].nunique()
    )
    return combined


# ─── Save / Load ──────────────────────────────────────────────────────────────

def save_parquet(df: pd.DataFrame, output_path: str | Path) -> None:
    """Save parsed DataFrame to Parquet for fast reloading (~10x faster than CSV re-parse)."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(output_path, index=False, compression='snappy')
    logger.info("Saved %d rows to: %s", len(df), output_path)


def load_parquet(path: str | Path) -> pd.DataFrame:
    """Load previously saved parsed log Parquet file."""
    return pd.read_parquet(path)
