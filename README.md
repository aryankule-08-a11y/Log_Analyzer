# 🔍 Log Analyzer Dashboard

<div align="center">

![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-1.28+-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)
![Plotly](https://img.shields.io/badge/Plotly-5.18+-3F4F75?style=for-the-badge&logo=plotly&logoColor=white)

**Enterprise-grade log analysis solution for security, usage, and performance insights**

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Installation](#-installation)
- [Usage](#-usage)
- [Sample Data Structure](#-sample-data-structure)
- [Architecture](#-architecture)
- [Screenshots](#-screenshots)
- [Tech Stack](#-tech-stack)
- [Contributing](#-contributing)

---

## 🎯 Overview

**Log Analyzer Dashboard** is a professional, industry-level Streamlit web application designed for analyzing server log files. It provides comprehensive security analysis, usage patterns, and performance metrics with a modern, intuitive UI/UX.

### Target Users
- 🔐 **Security Teams** - Monitor and detect suspicious login activities
- 💻 **System Administrators** - Track system performance and usage
- 📊 **Data Analysts** - Generate reports and analyze patterns

---

## ✨ Features

### 📤 File Upload System
- Multi-file CSV upload support
- Automatic file validation
- Real-time preview of uploaded data (first 10 rows)
- Memory-efficient processing for medium-size files

### 🔧 Data Preprocessing
- Automatic missing value handling
- DateTime column detection and conversion
- Numeric column type enforcement
- Duplicate removal
- Comprehensive cleaning summary

### 🔐 Security Analysis Module
- **Failed Login Detection** - Identify unsuccessful login attempts
- **Suspicious User Identification** - Flag users with multiple failed attempts
- **Risk Level Classification** - Critical, High, Moderate risk categorization
- **Real-time Alerts** - Visual warnings for high-risk activities
- **Interactive Charts** - Visualize security threats over time

### 📊 Usage Analysis Module
- **Most Active Users** - Identify power users
- **Service Usage Statistics** - Track endpoint/API popularity
- **Time-based Analysis** - Hourly and daily activity patterns
- **Interactive Visualizations** - Pie charts, bar graphs, area charts

### ⚡ Performance Analysis Module
- **Session Duration Statistics** - Per-user performance metrics
- **Slowest Services** - Identify performance bottlenecks
- **Longest Sessions** - Track outlier sessions
- **Distribution Histograms** - Visualize duration patterns

### 📝 Report Generation
- **HTML Profiling Report** - Comprehensive data profiling via ydata-profiling
- **CSV Export** - Suspicious users, active users, slow services
- **Full Data Export** - Download cleaned datasets
- **Summary Statistics** - Statistical overview export

### 🎨 UI/UX Features
- Modern gradient-based design
- Dark theme optimized
- Responsive sidebar navigation
- Real-time metrics display
- Loading spinners and progress indicators
- Clear success/error messaging
- Tabbed interface for organized content

---

## 🚀 Installation

### Prerequisites
- Python 3.9 or higher
- pip package manager

### Step-by-Step Setup

1. **Clone or navigate to the project directory**
```bash
cd log_analyzer_dashboard
```

2. **Create a virtual environment (recommended)**
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS/Linux
source venv/bin/activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Run the application**
```bash
streamlit run app.py
```

5. **Access the dashboard**
   - Open your browser and navigate to `http://localhost:8501`

---

## 📖 Usage

### Step 1: Upload Data
1. Navigate to **📤 Upload Data** in the sidebar
2. Drag and drop or click to upload CSV log file(s)
3. Preview your data to verify it loaded correctly
4. Click **🚀 Clean & Process Data** to preprocess

### Step 2: Analyze Security
1. Navigate to **🔐 Security Analysis**
2. Adjust the failed login threshold slider
3. Review alerts for suspicious users
4. Examine security visualizations

### Step 3: Analyze Usage
1. Navigate to **📊 Usage Analysis**
2. Explore tabs for Users, Services, and Time Analysis
3. Identify most active users and popular services
4. Review activity patterns by hour and day

### Step 4: Analyze Performance
1. Navigate to **⚡ Performance Analysis**
2. Review session duration statistics
3. Identify slowest services
4. Examine duration distribution

### Step 5: Generate Reports
1. Navigate to **📝 Reports**
2. Generate HTML profiling report
3. Download CSV summary reports
4. Export cleaned data

---

## 📊 Sample Data Structure

Your CSV log files should follow this structure:

| Column | Type | Description | Example |
|--------|------|-------------|---------|
| `timestamp` | datetime | Event timestamp | 2024-01-15 10:30:00 |
| `user` | string | Username/user ID | john_doe |
| `service` | string | Endpoint/API accessed | /api/login |
| `status` | string | Result (success/failed) | success |
| `duration` | float | Session duration (seconds) | 125.5 |
| `ip_address` | string | Client IP address | 192.168.1.100 |
| `action` | string | Action performed | login |
| `user_agent` | string | Browser/client info | Chrome/120.0 |
| `response_code` | int | HTTP response code | 200 |

### Sample CSV Format
```csv
timestamp,user,service,status,duration,ip_address,action,user_agent,response_code
2024-01-15 08:15:23,john_doe,/api/login,success,1.25,192.168.1.100,login,Chrome/120.0,200
2024-01-15 08:16:45,attacker,/api/login,failed,0.12,10.0.0.55,login,curl/7.81.0,401
```

> **Note:** Column names are case-insensitive. The app auto-detects common patterns like 'user', 'username', 'timestamp', 'time', etc.

---

## 🏗 Architecture

```
log_analyzer_dashboard/
├── app.py              # Main Streamlit application
├── requirements.txt    # Python dependencies
├── sample_logs.csv     # Sample log data for testing
└── README.md           # Documentation
```

### Code Structure (app.py)

```
├── Configuration & Styling
│   ├── load_custom_css()          # Custom CSS for UI
│   
├── Data Loading & Validation
│   ├── validate_csv_file()        # File validation
│   ├── load_csv_data()            # Multi-file loading
│   
├── Data Preprocessing
│   ├── preprocess_data()          # Clean and transform data
│   ├── get_data_summary()         # Generate data summary
│   
├── Security Analysis Module
│   ├── detect_failed_logins()     # Find failed attempts
│   ├── identify_suspicious_users()# Flag risky users
│   ├── create_security_charts()   # Security visualizations
│   
├── Usage Analysis Module
│   ├── get_most_active_users()    # Top users by activity
│   ├── get_service_usage()        # Service statistics
│   ├── get_activity_by_time()     # Time-based patterns
│   ├── create_usage_charts()      # Usage visualizations
│   
├── Performance Analysis Module
│   ├── get_session_duration_stats()  # Duration metrics
│   ├── get_slowest_services()        # Performance bottlenecks
│   ├── get_longest_sessions()        # Outlier sessions
│   ├── create_performance_charts()   # Performance visualizations
│   
├── Report Generation
│   ├── generate_html_report()     # ydata-profiling report
│   ├── create_csv_report()        # CSV exports
│   ├── get_download_link()        # Download helpers
│   
└── Main Application
    └── main()                     # Application entry point
```

---

## 🛠 Tech Stack

| Component | Technology |
|-----------|------------|
| **Frontend Framework** | Streamlit 1.28+ |
| **Data Processing** | Pandas 2.0+, NumPy 1.24+ |
| **Visualization** | Plotly 5.18+, Matplotlib 3.7+ |
| **Data Profiling** | ydata-profiling 4.5+ |
| **Language** | Python 3.9+ |

---

## 📸 Key Components

### Dashboard Metrics
- Total log records count
- Failed login attempts with percentage
- Suspicious users with risk level
- Critical risk user count

### Visualizations
- 📊 Bar charts (failed logins by user, active users)
- 🥧 Pie charts (service usage, risk distribution)
- 📈 Line/Area charts (activity over time)
- 📉 Histograms (session duration distribution)

### Interactive Elements
- Threshold sliders for security analysis
- Tabbed navigation for organized content
- Expandable sections for details
- Download buttons for reports

---

## 🎯 Best Practices Implemented

- ✅ **Modular Code** - Separate functions for each task
- ✅ **Type Hints** - Full type annotations
- ✅ **Documentation** - Comprehensive docstrings
- ✅ **Error Handling** - Graceful error management
- ✅ **Session State** - Persistent data across pages
- ✅ **Responsive Design** - Works on various screen sizes
- ✅ **Memory Efficient** - Optimized for medium-size files

---

## 📄 License

This project is open source and available under the MIT License.

---

## 🙏 Acknowledgments

Built with ❤️ using:
- [Streamlit](https://streamlit.io/)
- [Plotly](https://plotly.com/)
- [Pandas](https://pandas.pydata.org/)
- [ydata-profiling](https://github.com/ydataai/ydata-profiling)

---

<div align="center">

**🔍 Log Analyzer Dashboard** - Enterprise Log Analysis Solution

*For Security Teams • System Administrators • Data Analysts*

</div>
