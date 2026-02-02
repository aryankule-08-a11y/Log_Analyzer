
# Log Analyzer Pro

A modern, production-ready Log Analyzer application built with Python and Streamlit.

## Features
- 📊 **Dashboard View**: Overview of log metrics (Errors, Warnings, Info).
- 📈 **Interactive Charts**:
  - Log Level Distribution (Pie Chart)
  - Log Volume over Time (Line Chart)
  - Heatmap (Activity by Hour/Day)
  - Top Error Messages (Bar Chart)
- 🔍 **Advanced Filtering**: Filter by Date Range, Log Level, and Keywords.
- ⚙️ **Robust Parsing**: Supports `.log`, `.txt`, and `.csv` files.
- 🚀 **Performance**: Efficient regex parsing.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/aryankule-08-a11y/Log_Analyzer.git
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

Run the Streamlit application:
```bash
streamlit run app.py
```

Upload your log file (or use the provided `sample.log`) to start analyzing!

## Technologies
- Streamlit
- Pandas
- Plotly
- Python
