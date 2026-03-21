"""
analyzer.py
-----------
Core analysis functions for Apache log DataFrames.

All functions:
  - Accept a parsed, feature-engineered DataFrame
  - Return structured DataFrames or Series
  - Are stateless (no global state, safe for concurrent use)
  - Log their outputs for traceability
"""

import logging
import pandas as pd
import numpy as np

logger = logging.getLogger(__name__)


# ─── Feature Engineering ──────────────────────────────────────────────────────

BOT_UA_PATTERN = (
    r'(bot|crawler|spider|scraper|python-requests|curl|wget|'
    r'Go-http|libwww|Scrapy|Googlebot|Bingbot|DotBot|AhrefsBot|'
    r'SemrushBot|MJ12bot|facebookexternalhit)'
)


def add_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Feature engineering: adds derived columns used across all analyses.
    Always call this once after parsing, before any other analysis function.

    Adds:
      hour, day_of_week, date         ← time decomposition
      is_error, is_client_error,
      is_server_error, is_success      ← HTTP status buckets
      is_bot                           ← automated traffic flag
    """
    df = df.copy()

    # ── Time features ──
    df['hour']        = df['timestamp'].dt.hour
    df['day_of_week'] = df['timestamp'].dt.day_name()
    df['date']        = df['timestamp'].dt.date

    # ── HTTP status categories ──
    df['is_success']       = df['status'].between(200, 299)
    df['is_redirect']      = df['status'].between(300, 399)
    df['is_client_error']  = df['status'].between(400, 499)
    df['is_server_error']  = df['status'] >= 500
    df['is_error']         = df['status'] >= 400

    # ── Bot detection via user-agent signature matching ──
    df['is_bot'] = df['user_agent'].str.contains(
        BOT_UA_PATTERN, case=False, na=False, regex=True
    )

    logger.info(
        "Features added | rows=%d | errors=%.1f%% | bots=%.1f%%",
        len(df),
        df['is_error'].mean() * 100,
        df['is_bot'].mean() * 100
    )
    return df


# ─── Status Code Analysis ─────────────────────────────────────────────────────

def get_status_distribution(df: pd.DataFrame) -> pd.DataFrame:
    """
    Count of requests per HTTP status code, with human-readable category labels.
    """
    counts = df['status'].value_counts().reset_index()
    counts.columns = ['status_code', 'count']
    counts['category'] = counts['status_code'].apply(_status_category)
    return counts.sort_values('status_code')


def _status_category(code: int) -> str:
    if code < 300:   return 'Success (2xx)'
    if code < 400:   return 'Redirect (3xx)'
    if code < 500:   return 'Client Error (4xx)'
    return 'Server Error (5xx)'


# ─── Error Analysis ───────────────────────────────────────────────────────────

def get_error_summary(df: pd.DataFrame) -> pd.DataFrame:
    """
    All 4xx/5xx responses grouped by (status, path).
    Identifies broken endpoints and scanner probe targets.
    """
    errors = df[df['is_error']].copy()
    if errors.empty:
        logger.warning("No error responses found in dataset.")
        return pd.DataFrame(columns=['status', 'path', 'count'])

    summary = (
        errors.groupby(['status', 'path'])
        .size()
        .reset_index(name='count')
        .sort_values('count', ascending=False)
    )
    return summary


def get_top_404_paths(df: pd.DataFrame, n: int = 10) -> pd.DataFrame:
    """
    Top N paths returning 404.
    High-frequency 404s on non-existent paths = directory enumeration / scanning.
    """
    paths_404 = (
        df[df['status'] == 404]
        .groupby('path')
        .size()
        .reset_index(name='count')
        .sort_values('count', ascending=False)
        .head(n)
    )
    return paths_404


# ─── Traffic Analysis ─────────────────────────────────────────────────────────

def get_hourly_traffic(df: pd.DataFrame) -> pd.DataFrame:
    """
    Request counts grouped by hour bucket.
    Used for traffic trend line charts and anomaly detection baseline.
    """
    hourly = (
        df.groupby(df['timestamp'].dt.floor('h'))
        .size()
        .reset_index(name='request_count')
    )
    hourly.columns = ['hour_bucket', 'request_count']
    return hourly.sort_values('hour_bucket')


def get_daily_traffic(df: pd.DataFrame) -> pd.DataFrame:
    """Request counts grouped by calendar day."""
    return (
        df.groupby('date')
        .size()
        .reset_index(name='request_count')
    )


def get_peak_hours(df: pd.DataFrame) -> pd.DataFrame:
    """
    Average request rate by hour of day across all dates.
    Useful for capacity planning and identifying attack windows.
    """
    return (
        df.groupby('hour')
        .size()
        .reset_index(name='avg_requests')
        .sort_values('avg_requests', ascending=False)
    )


# ─── IP Analysis ──────────────────────────────────────────────────────────────

def get_top_ips(df: pd.DataFrame, n: int = 15) -> pd.DataFrame:
    """
    Top N IPs by request volume with request composition breakdown.

    Columns:
      ip, total_requests, error_requests, bot_requests, error_rate
    """
    ip_stats = df.groupby('ip').agg(
        total_requests  = ('ip',       'count'),
        error_requests  = ('is_error', 'sum'),
        bot_requests    = ('is_bot',   'sum'),
    ).reset_index()

    ip_stats['error_rate'] = (
        ip_stats['error_requests'] / ip_stats['total_requests']
    ).round(4)

    return (
        ip_stats
        .sort_values('total_requests', ascending=False)
        .head(n)
        .reset_index(drop=True)
    )


# ─── Anomaly Detection ────────────────────────────────────────────────────────

def detect_traffic_anomalies(
    df: pd.DataFrame,
    z_threshold: float = 3.0
) -> pd.DataFrame:
    """
    Detect IPs with statistically anomalous request volumes using Z-score.

    Method:
      For each (date, hour) window, compute mean and std of per-IP request counts.
      Flag any IP whose count exceeds mean + z_threshold * std.

    Parameters
    ----------
    z_threshold : float
        Default 3.0 → flags IPs beyond 99.7th percentile of the distribution.

    Returns
    -------
    pd.DataFrame
        Suspicious IP-hour windows with z-score, sorted descending.
    """
    if df.empty:
        return pd.DataFrame()

    hourly_ip = (
        df.groupby(['date', 'hour', 'ip'])
        .size()
        .reset_index(name='request_count')
    )

    # Per-window baseline statistics
    window_stats = (
        hourly_ip.groupby(['date', 'hour'])['request_count']
        .agg(window_mean='mean', window_std='std')
        .reset_index()
    )
    # Avoid division by zero in uniform-traffic windows
    window_stats['window_std'] = window_stats['window_std'].fillna(1.0).clip(lower=1.0)

    merged = hourly_ip.merge(window_stats, on=['date', 'hour'])
    merged['z_score'] = (
        (merged['request_count'] - merged['window_mean']) / merged['window_std']
    ).round(3)

    anomalies = (
        merged[merged['z_score'] >= z_threshold]
        .sort_values('z_score', ascending=False)
        .reset_index(drop=True)
    )

    logger.info(
        "Traffic anomaly detection (z≥%.1f): flagged %d IP-window pairs",
        z_threshold, len(anomalies)
    )
    return anomalies


def detect_brute_force(
    df: pd.DataFrame,
    window_minutes: int = 5,
    threshold: int = 20
) -> pd.DataFrame:
    """
    Detect brute-force login attacks: IPs with ≥threshold failed auth
    requests (401/403) within a rolling [window_minutes]-minute window.

    Parameters
    ----------
    window_minutes : int
        Sliding window size in minutes. Default 5 min is industry-standard
        for brute-force detection rate limiting.
    threshold : int
        Minimum failures in the window to raise an alert. Default 20.

    Returns
    -------
    pd.DataFrame
        One row per offending IP: ip, window_end, failures_in_window, path.
    """
    auth_failures = df[df['status'].isin([401, 403])].copy()
    if auth_failures.empty:
        logger.info("No 401/403 responses found — no brute-force candidates.")
        return pd.DataFrame()

    auth_failures = auth_failures.sort_values('timestamp')
    auth_failures['ts_epoch'] = (
        auth_failures['timestamp'].astype('int64') // 10**9
    )
    window_sec = window_minutes * 60

    results = []
    for ip, group in auth_failures.groupby('ip'):
        group_sorted = group.sort_values('ts_epoch')
        ts_arr = group_sorted['ts_epoch'].values

        for i, ts in enumerate(ts_arr):
            # Count failures in [ts - window, ts]
            count = int(((ts_arr >= ts - window_sec) & (ts_arr <= ts)).sum())
            if count >= threshold:
                results.append({
                    'ip':                 ip,
                    'window_end':         group_sorted.iloc[i]['timestamp'],
                    'failures_in_window': count,
                    'example_path':       group_sorted.iloc[i]['path'],
                    'window_minutes':     window_minutes,
                })
                break  # One alert per IP — avoid duplicate rows

    result_df = pd.DataFrame(results)
    if not result_df.empty:
        result_df = result_df.sort_values('failures_in_window', ascending=False)

    logger.info(
        "Brute-force detection (window=%dmin, threshold=%d): flagged %d IPs",
        window_minutes, threshold, len(result_df)
    )
    return result_df.reset_index(drop=True)


# ─── Bandwidth Analysis ───────────────────────────────────────────────────────

def get_bandwidth_usage(df: pd.DataFrame, n: int = 15) -> pd.DataFrame:
    """
    Total bytes served per endpoint, sorted descending.
    Heavy traffic on unexpected paths = potential data exfiltration risk.
    """
    return (
        df.groupby('path')['bytes']
        .agg(total_bytes='sum', avg_bytes='mean', request_count='count')
        .reset_index()
        .sort_values('total_bytes', ascending=False)
        .head(n)
        .assign(total_mb=lambda x: (x['total_bytes'] / 1_048_576).round(2))
    )


# ─── User-Agent Analysis ──────────────────────────────────────────────────────

def get_user_agent_summary(df: pd.DataFrame) -> pd.DataFrame:
    """Bot vs Human traffic split and top user agents."""
    traffic_split = df['is_bot'].value_counts().rename({True: 'Bot', False: 'Human'})

    top_ua = (
        df.groupby('user_agent')
        .size()
        .reset_index(name='count')
        .sort_values('count', ascending=False)
        .head(10)
    )
    return {
        'traffic_split': traffic_split,
        'top_user_agents': top_ua
    }


# ─── Endpoint Popularity ──────────────────────────────────────────────────────

def get_top_endpoints(df: pd.DataFrame, n: int = 10) -> pd.DataFrame:
    """Most frequently accessed URL paths (2xx only — valid hits)."""
    return (
        df[df['is_success']]
        .groupby('path')
        .size()
        .reset_index(name='hit_count')
        .sort_values('hit_count', ascending=False)
        .head(n)
    )


# ─── Quick Summary ────────────────────────────────────────────────────────────

def get_summary_stats(df: pd.DataFrame) -> dict:
    """
    Return a flat dict of high-level KPIs for dashboard summary cards.
    """
    return {
        'total_requests':   len(df),
        'unique_ips':       df['ip'].nunique(),
        'date_range_days': (df['timestamp'].max() - df['timestamp'].min()).days,
        'error_rate':       f"{df['is_error'].mean() * 100:.2f}%",
        'bot_traffic_pct':  f"{df['is_bot'].mean() * 100:.2f}%",
        'top_status':       int(df['status'].mode().iloc[0]),
        'total_bytes_gb':   f"{df['bytes'].sum() / 1_073_741_824:.3f} GB",
        'server_errors':    int(df['is_server_error'].sum()),
    }
