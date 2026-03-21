"""
app.py — Streamlit Dashboard (Thin UI Layer)
--------------------------------------------
This file ONLY handles UI rendering.
All business logic lives in src/ modules.

This is the correct separation of concerns:
  src/parser.py    → Data ingestion
  src/analyzer.py  → Analysis & feature engineering
  src/anomaly.py   → ML-based anomaly detection
  src/visualizer.py → Chart generation
  app.py           → UI wiring only
"""

import logging
import streamlit as st
import pandas as pd
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
    page_title="Log Analyzer | Apache Intelligence Platform",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ─── CSS ──────────────────────────────────────────────────────────────────────

st.markdown("""
<style>
  /* Dark background */
  .stApp { background-color: #0d1117; }

  /* Metric cards */
  [data-testid="metric-container"] {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 8px;
      padding: 16px;
  }

  /* Sidebar */
  [data-testid="stSidebar"] { background-color: #161b22; }

  /* Section headers */
  h2, h3 { color: #58a6ff !important; }

  /* Alert boxes */
  .alert-box {
      background: #1f1f2e;
      border-left: 4px solid #e74c3c;
      padding: 12px 16px;
      border-radius: 4px;
      margin: 8px 0;
  }
</style>
""", unsafe_allow_html=True)


# ─── Sidebar ──────────────────────────────────────────────────────────────────

with st.sidebar:
    st.title("🔍 Log Analyzer")
    st.caption("Apache Intelligence Platform v2.0")
    st.divider()

    uploaded_file = st.file_uploader(
        "Upload Apache Log File",
        type=['log', 'txt', 'gz'],
        help="Supports Apache Combined Log Format (.log, .log.gz)"
    )

    st.divider()
    st.subheader("⚙️ Detection Settings")
    z_threshold  = st.slider("Z-Score Threshold (Anomaly)", 1.0, 5.0, 3.0, 0.5)
    bf_window    = st.slider("Brute-Force Window (min)", 1, 30, 5)
    bf_threshold = st.slider("Brute-Force Threshold (failures)", 5, 100, 20)

    st.divider()
    st.caption("💡 No log file? Download the [NASA HTTP dataset](https://www.kaggle.com/datasets/shawon10/web-log-dataset) to test.")


# ─── Main Content ─────────────────────────────────────────────────────────────

st.title("🔍 Apache Log Intelligence Platform")
st.markdown("**Enterprise-grade log parsing, anomaly detection, and security analysis.**")

if uploaded_file is None:
    st.info("👈 Upload an Apache `.log` file from the sidebar to begin analysis.")
    st.markdown("""
    ### Expected Log Format
    ```
    192.168.1.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.0" 200 2326 "http://ref.com/" "Mozilla/5.0"
    ```
    This is the standard **Apache Combined Log Format** used by virtually all Apache and Nginx servers.

    **Get real data:**
    - [NASA HTTP Logs (Kaggle)](https://www.kaggle.com/datasets/shawon10/web-log-dataset)
    - [Web Server Access Logs (Kaggle)](https://www.kaggle.com/datasets/eliasdabbas/web-server-access-log)
    """)
    st.stop()


# ─── Parse Log File ───────────────────────────────────────────────────────────

@st.cache_data(show_spinner="Parsing log file...")
def load_and_parse(file_bytes: bytes, filename: str) -> pd.DataFrame:
    """Parse uploaded file — cached so re-renders don't re-parse."""
    suffix = Path(filename).suffix
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(file_bytes)
        tmp_path = tmp.name

    try:
        df = parse_log_file(tmp_path)
        df = add_features(df)
    finally:
        os.unlink(tmp_path)

    return df


try:
    df = load_and_parse(uploaded_file.read(), uploaded_file.name)
except Exception as e:
    st.error(f"❌ Failed to parse log file: {e}")
    st.markdown("**Ensure the file uses Apache Combined Log Format.** Check the sidebar for an example.")
    st.stop()


# ─── KPI Summary Cards ────────────────────────────────────────────────────────

st.subheader("📊 Summary")
stats = get_summary_stats(df)

cols = st.columns(4)
kpi_map = [
    ("Total Requests",  f"{stats['total_requests']:,}",        "📥"),
    ("Unique IPs",      f"{stats['unique_ips']:,}",            "🌐"),
    ("Error Rate",      stats['error_rate'],                    "❌"),
    ("Bot Traffic",     stats['bot_traffic_pct'],               "🤖"),
]
for col, (label, value, icon) in zip(cols, kpi_map):
    col.metric(f"{icon} {label}", value)

cols2 = st.columns(4)
kpi_map2 = [
    ("Date Range",      f"{stats['date_range_days']} days",    "📅"),
    ("Server Errors",   f"{stats['server_errors']:,}",         "🔥"),
    ("Total Bandwidth", stats['total_bytes_gb'],                "💾"),
    ("Top Status",      f"HTTP {stats['top_status']}",         "✅"),
]
for col, (label, value, icon) in zip(cols2, kpi_map2):
    col.metric(f"{icon} {label}", value)


# ─── Navigation Tabs ──────────────────────────────────────────────────────────

tab_traffic, tab_errors, tab_security, tab_anomaly, tab_raw = st.tabs([
    "📈 Traffic", "🚨 Errors", "🔐 Security", "🧠 Anomaly Detection", "🗂️ Raw Data"
])


# ────────────────────────── TAB 1: TRAFFIC ────────────────────────────────────
with tab_traffic:
    st.subheader("Request Volume Over Time")
    hourly = get_hourly_traffic(df)
    st.plotly_chart(plot_hourly_traffic(hourly), use_container_width=True)

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Top IP Addresses")
        top_ips = get_top_ips(df, n=15)
        st.plotly_chart(plot_top_ips(top_ips), use_container_width=True)
    with col2:
        st.subheader("Bot vs Human Traffic")
        st.plotly_chart(plot_bot_vs_human(df), use_container_width=True)

    st.subheader("Bandwidth Usage by Endpoint")
    bw = get_bandwidth_usage(df)
    st.dataframe(bw, use_container_width=True, hide_index=True)


# ────────────────────────── TAB 2: ERRORS ─────────────────────────────────────
with tab_errors:
    st.subheader("HTTP Status Code Distribution")
    status_df = get_status_distribution(df)
    st.plotly_chart(plot_status_distribution(status_df), use_container_width=True)

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Error Rate Heatmap (Day × Hour)")
        st.plotly_chart(plot_error_heatmap(df), use_container_width=True)
    with col2:
        st.subheader("Top 404 Paths (Scanner Detection)")
        paths_404 = get_top_404_paths(df, n=10)
        st.plotly_chart(plot_top_404_paths(paths_404), use_container_width=True)

    st.subheader("Full Error Breakdown")
    error_summary = get_error_summary(df)
    st.dataframe(error_summary.head(50), use_container_width=True, hide_index=True)


# ────────────────────────── TAB 3: SECURITY ───────────────────────────────────
with tab_security:
    st.subheader("🔐 Authentication Failure Analysis")
    st.plotly_chart(plot_brute_force_timeline(df), use_container_width=True)

    st.subheader(f"Brute-Force Detection (≥{bf_threshold} failures in {bf_window}min)")
    bf_result = detect_brute_force(df, window_minutes=bf_window, threshold=bf_threshold)

    if bf_result.empty:
        st.success("✅ No brute-force patterns detected with current settings.")
    else:
        st.error(f"⚠️ {len(bf_result)} suspicious IP(s) detected!")
        for _, row in bf_result.iterrows():
            st.markdown(
                f'<div class="alert-box">🚨 <b>{row["ip"]}</b> — '
                f'{row["failures_in_window"]} failures in {bf_window}m window '
                f'| Last attempt: {row["window_end"]}</div>',
                unsafe_allow_html=True
            )
        st.dataframe(bf_result, use_container_width=True, hide_index=True)


# ────────────────────────── TAB 4: ANOMALY DETECTION ──────────────────────────
with tab_anomaly:
    st.subheader(f"📡 Traffic Anomaly Detection (Z-Score ≥ {z_threshold})")

    anomalies = detect_traffic_anomalies(df, z_threshold=z_threshold)
    st.plotly_chart(plot_anomalies(anomalies, hourly), use_container_width=True)

    if anomalies.empty:
        st.success("✅ No statistical anomalies at current threshold.")
    else:
        st.warning(f"⚠️ {len(anomalies)} anomalous IP-window combinations detected.")
        st.dataframe(anomalies, use_container_width=True, hide_index=True)

    st.divider()
    st.subheader("🤖 Isolation Forest — Behavioral Anomaly Detection")
    st.caption(
        "Uses machine learning to flag IPs with abnormal behavioral patterns "
        "(volume, error rate, path diversity, bot signals) — not just raw request count."
    )

    if st.button("Run Isolation Forest", type="primary"):
        with st.spinner("Training Isolation Forest on IP behavior features..."):
            if_result = run_isolation_forest(df, contamination=0.05)

        if if_result.empty:
            st.warning("Insufficient data for Isolation Forest (need ≥10 unique IPs).")
        else:
            flagged = if_result[if_result['is_anomaly']]
            st.error(f"🚨 {len(flagged)} IPs flagged as behaviorally anomalous")
            st.dataframe(if_result, use_container_width=True, hide_index=True)

            csv = if_result.to_csv(index=False)
            st.download_button(
                "📥 Download Anomaly Report (CSV)",
                csv,
                file_name="anomaly_report.csv",
                mime="text/csv"
            )


# ────────────────────────── TAB 5: RAW DATA ───────────────────────────────────
with tab_raw:
    st.subheader("Parsed Log Data")
    st.caption(f"{len(df):,} rows | {df.columns.tolist()}")
    st.dataframe(df.head(500), use_container_width=True, hide_index=True)

    col1, col2 = st.columns(2)
    with col1:
        csv_data = df.to_csv(index=False)
        st.download_button("📥 Export as CSV", csv_data, "parsed_logs.csv", "text/csv")
    with col2:
        st.download_button(
            "📥 Export as Parquet",
            df.to_parquet(index=False),
            "parsed_logs.parquet",
            "application/octet-stream"
        )

    st.subheader("DataFrame Info")
    info_df = pd.DataFrame({
        'Column':    df.columns,
        'Dtype':     [str(d) for d in df.dtypes],
        'Non-Null':  df.notna().sum().values,
        'Null':      df.isna().sum().values,
        'Null %':    (df.isna().mean() * 100).round(2).values,
    })
    st.dataframe(info_df, use_container_width=True, hide_index=True)
