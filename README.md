# 🔍 Apache Log Intelligence Platform

> **Real-world log parsing, statistical anomaly detection, and security analysis built on production Apache server logs.**

![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python)
![Streamlit](https://img.shields.io/badge/Streamlit-1.28+-red?logo=streamlit)
![Plotly](https://img.shields.io/badge/Plotly-5.18+-purple?logo=plotly)
![scikit-learn](https://img.shields.io/badge/scikit--learn-1.3+-orange?logo=scikit-learn)
![pytest](https://img.shields.io/badge/Tests-pytest-green?logo=pytest)

---

## 📋 Table of Contents

- [Problem Statement](#-problem-statement)
- [Dataset](#-dataset)
- [Tech Stack](#-tech-stack)
- [Architecture](#-architecture)
- [Pipeline](#-full-pipeline)
- [Features](#-features)
- [How to Run](#-how-to-run)
- [CLI Usage](#-cli-usage)
- [Screenshots](#-screenshots)
- [Future Improvements](#-future-improvements)

---

## 🎯 Problem Statement

Apache and Nginx web servers generate millions of raw log lines daily. These logs contain critical signals:

- **Security threats**: Brute-force login attempts, directory scanners, DDoS sources
- **Reliability issues**: 5xx error spikes indicating server failures
- **Traffic patterns**: Peak load windows, bot vs human ratios

**This project turns raw `.log` files into actionable intelligence** through:
1. Regex-based parsing of the Apache Combined Log Format
2. Statistical anomaly detection (Z-score on hourly traffic per IP)
3. ML-based behavioral profiling (Isolation Forest on multi-dimensional IP features)
4. Brute-force detection via sliding-window failure counting
5. Interactive Streamlit dashboard + headless CLI for pipeline integration

---

## 📦 Dataset

### Real Dataset Used: NASA HTTP Logs

| Property | Value |
|----------|-------|
| Source | [Kaggle: NASA HTTP Log](https://www.kaggle.com/datasets/shawon10/web-log-dataset) |
| Format | Apache Combined Log Format (raw `.log`) |
| Size | ~1.8 million requests |
| Time Period | July 1995 |
| Why relevant | Real production traffic with 404s, 500s, and traffic spikes |

```bash
# Download from Kaggle CLI
kaggle datasets download -d shawon10/web-log-dataset -p data/raw/ --unzip
```

**Alternative Dataset**: [Web Server Access Log (Kaggle)](https://www.kaggle.com/datasets/eliasdabbas/web-server-access-log) — 2019 modern traffic with bot signatures.

---

## 🛠️ Tech Stack

| Layer | Technology | Why |
|-------|-----------|-----|
| Parsing | `re` (stdlib) | Regex — the real-world tool for log parsing |
| Data | `pandas` + `pyarrow` | DataFrame manipulation + Parquet storage |
| Numerics | `numpy` | Z-score computation |
| ML | `scikit-learn` (IsolationForest) | Unsupervised behavioral anomaly detection |
| Visualization | `plotly` | Interactive charts (industry standard) |
| Dashboard | `streamlit` | Rapid data app delivery |
| Testing | `pytest` | Unit + integration testing |

---

## 🏗️ Architecture

```
Log_Analyzer/
├── app.py                    ← Streamlit UI (thin layer — no business logic here)
├── cli.py                    ← CLI tool for headless/pipeline usage
├── requirements.txt
├── README.md
│
├── src/                      ← All business logic lives here
│   ├── __init__.py
│   ├── parser.py             ← Regex parsing of raw Apache log files
│   ├── analyzer.py           ← Feature engineering + statistical analysis
│   ├── anomaly.py            ← Isolation Forest + IQR outlier detection
│   └── visualizer.py         ← Plotly chart functions (dark theme)
│
├── data/
│   ├── raw/                  ← Original unmodified log files (never edit these)
│   │   └── NASA_access_log_Jul95.log
│   └── processed/            ← Parsed Parquet files (fast reload)
│       └── parsed_logs.parquet
│
├── notebooks/
│   └── exploration.ipynb     ← EDA and initial analysis
│
├── outputs/
│   └── reports/              ← Generated HTML/CSV reports
│
└── tests/
    ├── test_parser.py        ← Unit tests for parser.py
    └── test_analyzer.py      ← Unit tests for analyzer.py
```

---

## ⚙️ Full Pipeline

```
Raw Apache .log file
        │
        ▼
[1. INGESTION]  src/parser.py
   parse_log_file()  — Regex match each line
   Supports: .log, .log.gz, batch directory parsing
        │
        ▼
[2. TYPE CASTING]  src/parser.py → _cast_columns()
   status     → Int16
   bytes       → int64 (handles '-' → 0)
   timestamp   → UTC-aware datetime
        │
        ▼
[3. FEATURE ENGINEERING]  src/analyzer.py → add_features()
   hour, day_of_week, date
   is_error, is_client_error, is_server_error
   is_bot (user-agent signature matching)
        │
        ▼
[4. ANALYSIS]  src/analyzer.py
   get_status_distribution()
   get_hourly_traffic()
   get_top_ips()
   get_top_404_paths()
   get_bandwidth_usage()
        │
        ▼
[5. ANOMALY DETECTION]  src/analyzer.py + src/anomaly.py
   Rule-based:   detect_traffic_anomalies() — Z-score per IP-hour window
   Rule-based:   detect_brute_force()       — Sliding window 401/403 counting
   ML-based:     run_isolation_forest()     — Behavioral profiling
        │
        ▼
[6. OUTPUT]
   Streamlit Dashboard  ← Interactive exploration
   CLI Report           ← Pipeline integration
   CSV/Parquet Export   ← Downstream processing
```

---

## ✨ Features

### 📊 Traffic Analysis
- **Request volume over time** — line chart with filled area, reveals traffic spikes
- **Peak hour analysis** — average requests by hour for capacity planning
- **Bot vs human split** — donut chart separating automated from organic traffic
- **Bandwidth by endpoint** — identifies bandwidth-heavy paths or data exfiltration risks

### 🚨 Error Analysis
- **HTTP status distribution** — color-coded bar chart (green/orange/red by category)
- **Error rate heatmap** — day × hour grid, reveals deployment-correlated errors
- **Top 404 paths** — identifies active directory scanners and vulnerability probers

### 🔐 Security Analysis
- **Authentication failure timeline** — stacked bar chart by attacking IP
- **Brute-force detection** — sliding window algorithm: flags IP with ≥N failures in M minutes
- **Configurable thresholds** — adjust window and threshold via Streamlit sidebar

### 🧠 Anomaly Detection
- **Z-score traffic anomaly** — flags IPs exceeding mean + k*std requests in any hour window
- **Isolation Forest** — multi-dimensional behavioral model: volume, error rate, path diversity, bot signals
- **IQR fallback** — simpler outlier detection if scikit-learn is unavailable

---

## 🚀 How to Run

### 1. Clone the Repository
```bash
git clone https://github.com/aryankule-08-a11y/Log_Analyzer.git
cd Log_Analyzer
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Download Real Dataset
```bash
# Create data directory
mkdir -p data/raw

# Option A: Kaggle CLI
kaggle datasets download -d shawon10/web-log-dataset -p data/raw/ --unzip

# Option B: Manual download from:
# https://www.kaggle.com/datasets/shawon10/web-log-dataset
# Place the .log file in data/raw/
```

### 4. Run the Dashboard
```bash
streamlit run app.py
```
Then open `http://localhost:8501` and upload your `.log` file.

### 5. Run Tests
```bash
pytest tests/ -v --cov=src
```

---

## 💻 CLI Usage

The CLI enables headless operation — use it in cron jobs, CI/CD pipelines, and shell scripts.

```bash
# Parse and print summary report
python cli.py --input data/raw/access.log --report

# Top 10 IPs by request volume
python cli.py --input data/raw/access.log --top-ips 10

# Run anomaly detection with custom Z-score
python cli.py --input data/raw/access.log --anomaly --z-score 2.5

# Detect brute-force: ≥20 failures in 5-minute window
python cli.py --input data/raw/access.log --brute-force --threshold 20 --window 5

# Batch process entire directory of gzipped logs
python cli.py --input data/raw/ --batch "*.log.gz" --report --anomaly

# Save parsed data to Parquet for fast future reloads
python cli.py --input data/raw/access.log --save-parquet data/processed/logs.parquet
```

---

## 📸 Screenshots

> *(Add screenshots after running the dashboard on a real dataset)*

| Screenshot | Description |
|------------|-------------|
| `screenshots/01_raw_log_preview.png` | First 10 lines of raw Apache log in terminal |
| `screenshots/02_parsed_dataframe.png` | `df.head()` after parsing — typed columns |
| `screenshots/03_parse_stats.png` | CLI output showing parse rate |
| `screenshots/04_status_distribution.png` | Color-coded status code bar chart |
| `screenshots/05_traffic_over_time.png` | Traffic line chart with anomalies overlaid |
| `screenshots/06_top_ips.png` | Top IP horizontal bar chart |
| `screenshots/07_anomaly_detection.png` | Z-score flagged IP-window DataFrame |
| `screenshots/08_brute_force.png` | Brute-force suspects table |
| `screenshots/09_error_heatmap.png` | Day × Hour error rate heatmap |
| `screenshots/10_isolation_forest.png` | ML anomaly output with decision scores |
| `screenshots/11_dashboard_full.png` | Full Streamlit dashboard |
| `screenshots/12_cli_output.png` | CLI summary report in terminal |
| `screenshots/13_folder_structure.png` | `tree` command showing project structure |

---

## 🔮 Future Improvements

| Priority | Feature | Impact |
|----------|---------|--------|
| High | Real-time log tailing (`tail -f`) with Streamlit auto-refresh | Live monitoring |
| High | Elasticsearch integration for large-scale (>1GB) logs | Scalability |
| Medium | DBSCAN clustering of IP request patterns | Better attack grouping |
| Medium | Prophet time-series forecasting for traffic trends | Capacity planning |
| Medium | Alerting: email/webhook on anomaly detection trigger | Production use |
| Low | Docker containerization | Easy deployment |
| Low | GitHub Actions CI: run pytest on every push | Code reliability |

---

## 📄 License

MIT License — see [LICENSE](LICENSE)

---

*Built to demonstrate real-world data engineering and analysis skills — not a tutorial project.*
