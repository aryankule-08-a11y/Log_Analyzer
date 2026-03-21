"""
app.py — Streamlit Dashboard (Thin UI Layer)
--------------------------------------------
Supports BOTH:
  1. Raw Apache Combined Log Format (.log, .txt, .log.gz)
  2. Structured CSV log files (.csv)  ← auto-detected & mapped

All business logic lives in src/ modules.
"""

import logging
import io
import streamlit as st
import pandas as pd
import numpy as np
from pathlib import Path
import tempfile, os

from src.parser    import parse_log_file, save_parquet
from src.analyzer  import (
    add_features, get_summary_stats, get_status_distribution,
    get_hourly_traffic, get_top_ips, detect_traffic_anomalies,
    detect_brute_force, get_top_404_paths, get_bandwidth_usage,
    get_error_summary
)
from src.anomaly   import run_isolation_forest, detect_iqr_outliers
from src.visualizer import (
    plot_status_distribution, plot_hourly_traffic, plot_top_ips,
    plot_error_heatmap, plot_anomalies, plot_top_404_paths,
    plot_bot_vs_human, plot_brute_force_timeline
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("log_analyzer.app")


# ─── Page Config ──────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="Log Analyzer | Intelligence Platform",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── CSS ──────────────────────────────────────────────────────────────────────

st.markdown("""
<style>
  .stApp { background-color: #0d1117; }
  [data-testid="metric-container"] {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 8px;
      padding: 16px;
  }
  [data-testid="stSidebar"] { background-color: #161b22; }
  h2, h3 { color: #58a6ff !important; }
  .alert-box {
      background: #1f1f2e;
      border-left: 4px solid #e74c3c;
      padding: 12px 16px;
      border-radius: 4px;
      margin: 8px 0;
  }
  .info-box {
      background: #1a2332;
      border-left: 4px solid #58a6ff;
      padding: 12px 16px;
      border-radius: 4px;
      margin: 8px 0;
  }
</style>
""", unsafe_allow_html=True)


# ─── CSV Column Mapping ───────────────────────────────────────────────────────
# Maps many possible CSV column names → our standard internal names.
# This makes the app work with any CSV log format, not just one specific schema.

COLUMN_ALIASES = {
    # IP address variants
    'ip':          ['ip', 'ip_address', 'client_ip', 'source_ip', 'remote_addr',
                    'host', 'clientip', 'remote_host', 'src_ip', 'c-ip'],
    # Timestamp variants
    'timestamp':   ['timestamp', 'time', 'datetime', 'date_time', 'log_time',
                    'request_time', 'date', '@timestamp', 'time_stamp', 'ts'],
    # HTTP method
    'method':      ['method', 'http_method', 'request_method', 'verb', 'cs-method'],
    # Request path / URL
    'path':        ['path', 'url', 'request', 'uri', 'endpoint', 'cs-uri-stem',
                    'request_uri', 'resource', 'page', 'cs-uri', 'service'],
    # HTTP status code
    'status':      ['status', 'status_code', 'response_code', 'http_status',
                    'code', 'sc-status', 'response', 'http_code', 'statuscode'],
    # Response bytes
    'bytes':       ['bytes', 'size', 'response_size', 'content_length', 'bytes_sent',
                    'sc-bytes', 'body_bytes_sent', 'byte_count'],
    # Referrer
    'referrer':    ['referrer', 'referer', 'http_referer', 'cs-referer'],
    # User agent
    'user_agent':  ['user_agent', 'useragent', 'browser', 'agent',
                    'cs-user-agent', 'http_user_agent', 'ua'],
    # Auth user
    'user':        ['user', 'username', 'user_name', 'auth_user', 'cs-username',
                    'remote_user', 'login'],
}

# Minimum columns needed to run meaningful analysis
REQUIRED_COLS = {'timestamp', 'status'}


def _map_csv_columns(df: pd.DataFrame) -> pd.DataFrame:
    """
    Remap CSV columns to our internal standard names using COLUMN_ALIASES.
    Case-insensitive. Returns a renamed DataFrame with only mapped columns.
    """
    raw_cols_lower = {c.lower().strip(): c for c in df.columns}
    rename_map = {}

    for standard_name, aliases in COLUMN_ALIASES.items():
        if standard_name in df.columns:
            continue  # Already correct name
        for alias in aliases:
            if alias.lower() in raw_cols_lower:
                original = raw_cols_lower[alias.lower()]
                if original not in rename_map.values():
                    rename_map[original] = standard_name
                    break

    df = df.rename(columns=rename_map)
    return df


def _cast_csv_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Cast CSV columns to correct types after column mapping."""

    # ── Timestamp ──
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce', utc=True)
        if df['timestamp'].dt.tz is None:
            df['timestamp'] = df['timestamp'].dt.tz_localize('UTC')
        bad = df['timestamp'].isna().sum()
        if bad > 0:
            df = df.dropna(subset=['timestamp'])

    # ── Status code ──
    if 'status' in df.columns:
        df['status'] = pd.to_numeric(df['status'], errors='coerce').astype('Int16')
        df = df.dropna(subset=['status'])

    # ── Bytes ──
    if 'bytes' in df.columns:
        df['bytes'] = df['bytes'].replace(['-', '', 'None', 'null'], '0')
        df['bytes'] = pd.to_numeric(df['bytes'], errors='coerce').fillna(0).astype('int64')
    else:
        df['bytes'] = 0  # Default to 0 if not present

    # ── Fill missing optional columns with defaults ──
    defaults = {
        'ip':         'unknown',
        'method':     'GET',
        'path':       '/',
        'user_agent': 'unknown',
        'referrer':   None,
        'user':       None,
        'protocol':   'HTTP/1.1',
    }
    for col, default in defaults.items():
        if col not in df.columns:
            df[col] = default

    return df.reset_index(drop=True)


# ─── Smart Loader ─────────────────────────────────────────────────────────────

@st.cache_data(show_spinner="Loading and processing log data...")
def load_and_parse(file_bytes: bytes, filename: str) -> tuple[pd.DataFrame, str]:
    """
    Smart loader: detects CSV vs raw log format automatically.
    Returns (DataFrame, format_detected) where format_detected is 'csv' or 'log'.
    """
    suffix = Path(filename).suffix.lower()

    # ── CSV path ──
    if suffix == '.csv':
        df = pd.read_csv(io.BytesIO(file_bytes), low_memory=False)
        df = _map_csv_columns(df)
        df = _cast_csv_columns(df)

        missing = REQUIRED_COLS - set(df.columns)
        if missing:
            raise ValueError(
                f"CSV is missing required columns after mapping: {missing}. "
                f"Found columns: {list(df.columns)}"
            )
        df = add_features(df)
        return df, 'csv'

    # ── Raw log path (.log, .txt, .gz) ──
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(file_bytes)
        tmp_path = tmp.name

    try:
        df = parse_log_file(tmp_path)
        df = add_features(df)
    finally:
        os.unlink(tmp_path)

    return df, 'log'


# ─── Sidebar ──────────────────────────────────────────────────────────────────

with st.sidebar:
    st.title("🔍 Log Analyzer")
    st.caption("Web Log Intelligence Platform v2.1")
    st.divider()

    uploaded_file = st.file_uploader(
        "Upload Log File",
        type=['log', 'txt', 'gz', 'csv'],   # ← CSV now supported
        help=(
            "Supports:\n"
            "• CSV log files (.csv) — any column schema\n"
            "• Apache Combined Log Format (.log, .txt, .log.gz)"
        )
    )

    st.divider()
    st.subheader("⚙️ Detection Settings")
    z_threshold  = st.slider("Z-Score Threshold (Anomaly)", 1.0, 5.0, 3.0, 0.5)
    bf_window    = st.slider("Brute-Force Window (min)", 1, 30, 5)
    bf_threshold = st.slider("Brute-Force Threshold (failures)", 1, 100, 5)

    st.divider()
    st.caption(
        "💡 Try the [NASA HTTP dataset](https://www.kaggle.com/datasets/shawon10/web-log-dataset) "
        "or any Apache / Nginx access log."
    )


# ─── Main Content ─────────────────────────────────────────────────────────────

st.title("🔍 Web Log Intelligence Platform")
st.markdown("**Upload any CSV log file or raw Apache `.log` file — full analysis runs automatically.**")

if uploaded_file is None:
    st.info("👈 Upload a log file from the sidebar to begin analysis.")

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("""
        #### ✅ Accepted: CSV Files
        Any `.csv` with at least a **timestamp** and **status code** column.
        Common column names are auto-detected:
        - `ip`, `ip_address`, `client_ip`
        - `timestamp`, `time`, `datetime`
        - `status`, `status_code`, `response_code`
        - `path`, `url`, `request`, `uri`
        - `bytes`, `size`, `response_size`
        """)
    with col2:
        st.markdown("""
        #### ✅ Accepted: Raw Apache Logs
        Standard Apache Combined Log Format:
        ```
        192.168.1.1 - - [10/Oct/2000:13:55:36 -0700]
        "GET /index.html HTTP/1.0" 200 2326
        ```
        Supports `.log`, `.txt`, `.log.gz`
        """)
    st.stop()


# ─── Load Data ────────────────────────────────────────────────────────────────

try:
    df, fmt = load_and_parse(uploaded_file.read(), uploaded_file.name)
except Exception as e:
    st.error(f"❌ Failed to load file: **{e}**")
    with st.expander("🔍 Troubleshooting Help"):
        st.markdown(f"""
        **File uploaded**: `{uploaded_file.name}`

        **For CSV files**, make sure your file has at least:
        - A column with timestamps (e.g. `timestamp`, `time`, `date`)
        - A column with HTTP status codes (e.g. `status`, `status_code`, `response_code`)

        **Column auto-detection** supports many naming variations. If your
        columns are different, rename them in Excel/Notepad before uploading.

        **Error details**: `{e}`
        """)
    st.stop()

# ─── Format Badge ─────────────────────────────────────────────────────────────

fmt_label = "📄 CSV Format" if fmt == 'csv' else "📋 Apache Log Format"
fmt_color = "#2ecc71" if fmt == 'csv' else "#3498db"
st.markdown(
    f'<div class="info-box">✅ File loaded successfully — '
    f'<b style="color:{fmt_color}">{fmt_label}</b> | '
    f'<b>{len(df):,}</b> rows | '
    f'<b>{df["ip"].nunique():,}</b> unique IPs | '
    f'Columns detected: {", ".join(f"`{c}`" for c in df.columns[:8])}{"..." if len(df.columns) > 8 else ""}'
    f'</div>',
    unsafe_allow_html=True
)

# ─── Column mapping info (CSV only) ───────────────────────────────────────────
if fmt == 'csv':
    with st.expander("🗂️ Column Mapping Details (click to expand)"):
        mapping_info = []
        for std_col in COLUMN_ALIASES.keys():
            if std_col in df.columns:
                mapping_info.append({"Standard Name": std_col, "Status": "✅ Detected", "Values Sample": str(df[std_col].iloc[0]) if len(df) > 0 else "N/A"})
            else:
                mapping_info.append({"Standard Name": std_col, "Status": "⬜ Not found (using default)", "Values Sample": "—"})
        st.dataframe(pd.DataFrame(mapping_info), use_container_width=True, hide_index=True)


# ─── KPI Summary Cards ────────────────────────────────────────────────────────

st.subheader("📊 Summary")

try:
    stats = get_summary_stats(df)

    cols = st.columns(4)
    kpi_map = [
        ("Total Requests",  f"{stats['total_requests']:,}",     "📥"),
        ("Unique IPs",      f"{stats['unique_ips']:,}",         "🌐"),
        ("Error Rate",      stats['error_rate'],                 "❌"),
        ("Bot Traffic",     stats['bot_traffic_pct'],            "🤖"),
    ]
    for col, (label, value, icon) in zip(cols, kpi_map):
        col.metric(f"{icon} {label}", value)

    cols2 = st.columns(4)
    kpi_map2 = [
        ("Date Range",      f"{stats['date_range_days']} days", "📅"),
        ("Server Errors",   f"{stats['server_errors']:,}",      "🔥"),
        ("Total Bandwidth", stats['total_bytes_gb'],             "💾"),
        ("Top Status",      f"HTTP {stats['top_status']}",      "✅"),
    ]
    for col, (label, value, icon) in zip(cols2, kpi_map2):
        col.metric(f"{icon} {label}", value)

except Exception as e:
    st.warning(f"Could not compute some summary stats: {e}")


# ─── Navigation Tabs ──────────────────────────────────────────────────────────

tab_traffic, tab_errors, tab_security, tab_anomaly, tab_raw = st.tabs([
    "📈 Traffic", "🚨 Errors", "🔐 Security", "🧠 Anomaly Detection", "🗂️ Raw Data"
])


# ────────────────────────── TAB 1: TRAFFIC ────────────────────────────────────
with tab_traffic:
    try:
        st.subheader("Request Volume Over Time")
        hourly = get_hourly_traffic(df)
        if hourly.empty:
            st.info("No time-series data available.")
        else:
            st.plotly_chart(plot_hourly_traffic(hourly), use_container_width=True)

        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Top IP Addresses")
            top_ips_df = get_top_ips(df, n=15)
            if not top_ips_df.empty and top_ips_df['ip'].iloc[0] != 'unknown':
                st.plotly_chart(plot_top_ips(top_ips_df), use_container_width=True)
            else:
                st.dataframe(top_ips_df, use_container_width=True, hide_index=True)

        with col2:
            st.subheader("Bot vs Human Traffic")
            st.plotly_chart(plot_bot_vs_human(df), use_container_width=True)

        st.subheader("Bandwidth Usage by Endpoint")
        bw = get_bandwidth_usage(df)
        if bw['total_bytes'].sum() == 0:
            st.info("No bandwidth data in this dataset (bytes column not found or all zero).")
        else:
            st.dataframe(bw, use_container_width=True, hide_index=True)

    except Exception as e:
        st.error(f"Traffic tab error: {e}")


# ────────────────────────── TAB 2: ERRORS ─────────────────────────────────────
with tab_errors:
    try:
        st.subheader("HTTP Status Code Distribution")
        status_df = get_status_distribution(df)
        st.plotly_chart(plot_status_distribution(status_df), use_container_width=True)

        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Error Rate Heatmap (Day × Hour)")
            if 'hour' in df.columns and 'day_of_week' in df.columns:
                st.plotly_chart(plot_error_heatmap(df), use_container_width=True)
            else:
                st.info("Heatmap requires timestamp data.")

        with col2:
            st.subheader("Top 404 Paths")
            paths_404 = get_top_404_paths(df, n=10)
            if paths_404.empty:
                st.success("✅ No 404 errors found.")
            else:
                st.plotly_chart(plot_top_404_paths(paths_404), use_container_width=True)

        st.subheader("Full Error Breakdown")
        error_summary = get_error_summary(df)
        if error_summary.empty:
            st.success("✅ No error responses found.")
        else:
            st.dataframe(error_summary.head(50), use_container_width=True, hide_index=True)

    except Exception as e:
        st.error(f"Errors tab error: {e}")


# ────────────────────────── TAB 3: SECURITY ───────────────────────────────────
with tab_security:
    try:
        st.subheader("🔐 Authentication Failure Analysis")
        st.plotly_chart(plot_brute_force_timeline(df), use_container_width=True)

        st.subheader(f"Brute-Force Detection (≥{bf_threshold} failures in {bf_window}min)")
        bf_result = detect_brute_force(df, window_minutes=bf_window, threshold=bf_threshold)

        if bf_result.empty:
            st.success("✅ No brute-force patterns detected with current settings.")
            st.caption("Tip: Lower the 'Brute-Force Threshold' slider in the sidebar to detect more patterns.")
        else:
            st.error(f"⚠️ {len(bf_result)} suspicious IP(s) detected!")
            for _, row in bf_result.iterrows():
                st.markdown(
                    f'<div class="alert-box">🚨 <b>{row["ip"]}</b> — '
                    f'{row["failures_in_window"]} failures in {bf_window}m window '
                    f'| Last seen: {row["window_end"]}</div>',
                    unsafe_allow_html=True
                )
            st.dataframe(bf_result, use_container_width=True, hide_index=True)

    except Exception as e:
        st.error(f"Security tab error: {e}")


# ────────────────────────── TAB 4: ANOMALY DETECTION ──────────────────────────
with tab_anomaly:
    try:
        hourly = get_hourly_traffic(df)

        st.subheader(f"📡 Traffic Anomaly Detection (Z-Score ≥ {z_threshold})")
        anomalies = detect_traffic_anomalies(df, z_threshold=z_threshold)
        st.plotly_chart(plot_anomalies(anomalies, hourly), use_container_width=True)

        if anomalies.empty:
            st.success("✅ No statistical anomalies at current threshold.")
            st.caption("Tip: Lower the Z-Score threshold slider to detect more patterns.")
        else:
            st.warning(f"⚠️ {len(anomalies)} anomalous IP-window combinations detected.")
            st.dataframe(anomalies, use_container_width=True, hide_index=True)

        st.divider()
        st.subheader("🤖 Isolation Forest — ML Behavioral Anomaly Detection")
        st.caption(
            "Flags IPs with abnormal behavioral profiles using machine learning "
            "(volume + error rate + path diversity + bot signals)."
        )
        n_ips = df['ip'].nunique()
        if n_ips < 10:
            st.warning(f"Need ≥10 unique IPs for Isolation Forest. Found: {n_ips}")
        elif st.button("Run Isolation Forest", type="primary"):
            with st.spinner("Training Isolation Forest..."):
                if_result = run_isolation_forest(df, contamination=0.05)

            if if_result.empty:
                st.warning("No results returned.")
            else:
                flagged = if_result[if_result['is_anomaly']]
                st.error(f"🚨 {len(flagged)} IPs flagged as behaviorally anomalous")
                st.dataframe(if_result, use_container_width=True, hide_index=True)
                st.download_button(
                    "📥 Download Anomaly Report (CSV)",
                    if_result.to_csv(index=False),
                    "anomaly_report.csv",
                    "text/csv"
                )

    except Exception as e:
        st.error(f"Anomaly tab error: {e}")


# ────────────────────────── TAB 5: RAW DATA ───────────────────────────────────
with tab_raw:
    st.subheader("Parsed Log Data Preview")
    st.caption(f"{len(df):,} rows × {len(df.columns)} columns")
    st.dataframe(df.head(500), use_container_width=True, hide_index=True)

    col1, col2 = st.columns(2)
    with col1:
        st.download_button(
            "📥 Export Full Dataset as CSV",
            df.to_csv(index=False),
            "parsed_logs.csv",
            "text/csv"
        )
    with col2:
        try:
            st.download_button(
                "📥 Export as Parquet",
                df.to_parquet(index=False),
                "parsed_logs.parquet",
                "application/octet-stream"
            )
        except Exception:
            st.info("Install pyarrow to enable Parquet export: `pip install pyarrow`")

    st.subheader("Column Info")
    info_df = pd.DataFrame({
        'Column':   df.columns,
        'Dtype':    [str(d) for d in df.dtypes],
        'Non-Null': df.notna().sum().values,
        'Null %':   (df.isna().mean() * 100).round(1).astype(str) + '%',
        'Sample':   [str(df[c].iloc[0]) if len(df) > 0 else 'N/A' for c in df.columns],
    })
    st.dataframe(info_df, use_container_width=True, hide_index=True)
