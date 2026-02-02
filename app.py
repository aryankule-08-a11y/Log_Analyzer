# Required Dependencies: streamlit, pandas, plotly
# Run: streamlit run app.py

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import re
from datetime import datetime
import io
import time

# --- Page Configuration ---
st.set_page_config(
    page_title="Log Analyzer Pro",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Custom Styling (CSS) ---
st.markdown("""
    <style>
    .main {
        background-color: #f8f9fa;
    }
    .stApp.dark-theme .main {
        background-color: #0e1117;
    }
    h1, h2, h3 {
        font-family: 'Inter', sans-serif;
        font-weight: 600;
    }
    .metric-card {
        background-color: white;
        padding: 20px;
        border-radius: 10px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        text-align: center;
    }
    .stDataFrame {
        border-radius: 10px;
        overflow: hidden;
    }
    /* Hide Streamlit default hamburger and footer for cleaner look */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    </style>
    """, unsafe_allow_html=True)

# --- Helper Functions ---

@st.cache_data
def load_data(file):
    """
    Parses the uploaded log file and returns a DataFrame.
    Supports CSV (pre-parsed) or raw text logs (.log, .txt).
    """
    if file.name.endswith('.csv'):
        try:
            df = pd.read_csv(file)
            # Ensure required columns exist, roughly
            if 'timestamp' not in df.columns:
                # Try to auto-detect or rename
                pass
            return df
        except Exception as e:
            st.error(f"Error reading CSV: {e}")
            return None
    
    # Text parsing logic
    content = file.getvalue().decode("utf-8")
    lines = content.split('\n')
    
    parsed_data = []
    
    # Generic Log Pattern Regex
    # Matches: Timestamp (various formats) | Level (various) | Message
    # Example: 2023-10-25 14:30:00 [INFO] Connection established
    log_pattern = re.compile(
        r'(?P<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s*[:|-]?\s*'  # Timestamp
        r'(?:\[(?P<level_bracket>[A-Z]+)\]|(?P<level_no_bracket>[A-Z]+))\s*[:|-]?\s*'      # Level
        r'(?P<message>.*)'                                                                  # Message
    )

    for line in lines:
        if not line.strip():
            continue
            
        match = log_pattern.search(line)
        if match:
            data = match.groupdict()
            level = data.get('level_bracket') or data.get('level_no_bracket')
            parsed_data.append({
                'timestamp': data['timestamp'],
                'level': level,
                'message': data['message'].strip()
            })
        else:
            # Handle non-matching lines (maybe multiline errors or header)
            # For now, we skip or add to previous valid log as continuation
            pass

    if not parsed_data:
         # Fallback: Create simple line-based DF if regex fails completely
         return pd.DataFrame({'raw_log': lines})

    df = pd.DataFrame(parsed_data)
    
    # Standardize Timestamp
    try:
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    except Exception:
        pass 
    return df

def convert_df(df):
    """
    Converts DataFrame to CSV for download.
    """
    return df.to_csv(index=False).encode('utf-8')

# --- Main App Layout ---

def main():
    # Sidebar
    st.sidebar.title("Settings & Input")
    
    # File Upload
    uploaded_file = st.sidebar.file_uploader("Upload Log File", type=['log', 'txt', 'csv'])
    
    # App Info / Settings
    with st.sidebar.expander("About & Settings", expanded=True):
        st.info("Supported formats: .log, .txt, .csv")
        st.markdown("Use standard log formats: `YYYY-MM-DD HH:MM:SS [LEVEL] Message`")
        if st.checkbox("Enable Antigravity Mode"):
            try:
                import antigravity
            except ImportError:
                st.warning("Antigravity module not found.")
        
    if not uploaded_file:
        # Landing Page State
        st.title("📂 Log Analyzer Pro")
        st.markdown("### Welcome! Upload a log file to generate insights.")
        st.stop()

    # Process File
    with st.spinner('Parsing logs...'):
        # Simulate slight delay for UX (loading spinner visibility)
        time.sleep(0.5)
        df = load_data(uploaded_file)

    if df is None or df.empty:
        st.error("Could not parse file or file is empty.")
        st.stop()
        
    # Data Preprocessing
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        min_date = df['timestamp'].min()
        max_date = df['timestamp'].max()
    
    # --- Sidebar Filters ---
    st.sidebar.subheader("Filters")
    
    # Date Range Filter
    if 'timestamp' in df.columns and not df['timestamp'].isnull().all():
        start_date, end_date = st.sidebar.date_input(
            "Date Range",
            [min_date.date(), max_date.date()]
        )
        # Filter by date
        df = df[(df['timestamp'].dt.date >= start_date) & (df['timestamp'].dt.date <= end_date)]

    # Level Filter
    if 'level' in df.columns:
        all_levels = df['level'].unique().tolist()
        selected_levels = st.sidebar.multiselect("Log Levels", all_levels, default=all_levels)
        df = df[df['level'].isin(selected_levels)]
        
    # Search Filter
    search_term = st.sidebar.text_input("Heuristic Search (Keyword)", "")
    if search_term and 'message' in df.columns:
        df = df[df['message'].str.contains(search_term, case=False, na=False)]

    # --- Dashboard View ---
    
    st.title("📊 Log Analysis Dashboard")
    st.markdown("---")
    
    # Quick Metrics
    total_logs = len(df)
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Logs", total_logs)
    
    if 'level' in df.columns:
        error_count = len(df[df['level'] == 'ERROR'])
        warning_count = len(df[df['level'] == 'WARNING'])
        info_count = len(df[df['level'] == 'INFO'])
        
        with col2:
            st.metric("Errors", error_count, delta_color="inverse")
        with col3:
            st.metric("Warnings", warning_count, delta_color="normal")
        with col4:
            st.metric("Info/Other", info_count)

    st.markdown("---")

    # --- Charts Section ---
    
    if 'level' in df.columns:
        c1, c2 = st.columns(2)
        
        with c1:
            st.subheader("Log Level Distribution")
            fig_pie = px.pie(df, names='level', hole=0.4, title="Distribution of Log Levels")
            fig_pie.update_traces(textinfo='percent+label')
            st.plotly_chart(fig_pie, use_container_width=True)
            
        with c2:
             if 'timestamp' in df.columns:
                st.subheader("Log Volume Over Time")
                # Resample by hour or day depending on range
                time_df = df.set_index('timestamp').resample('H').size().reset_index(name='count')
                fig_line = px.line(time_df, x='timestamp', y='count', title="Logs per Hour", markers=True)
                fig_line.update_layout(xaxis_title="Time", yaxis_title="Count")
                st.plotly_chart(fig_line, use_container_width=True)

    # Heatmap (if timestamp exists)
    if 'timestamp' in df.columns:
        st.subheader("Activity Heatmap (Hour vs Day)")
        df['hour'] = df['timestamp'].dt.hour
        df['day'] = df['timestamp'].dt.day_name()
        heatmap_data = df.groupby(['day', 'hour']).size().reset_index(name='count')
        
        fig_heat = px.density_heatmap(
            heatmap_data, 
            x='hour', 
            y='day', 
            z='count', 
            nbinsx=24, 
            title="Log Density by Day & Hour",
            color_continuous_scale='Virid'
        )
        st.plotly_chart(fig_heat, use_container_width=True)

    # Top Errors
    if 'level' in df.columns and 'message' in df.columns:
        st.subheader("Top Frequent Errors")
        error_df = df[df['level'] == 'ERROR']
        if not error_df.empty:
            top_errors = error_df['message'].value_counts().head(10).reset_index()
            top_errors.columns = ['Message', 'Count']
            
            fig_bar = px.bar(
                top_errors, 
                x='Count', 
                y='Message', 
                orientation='h', 
                title="Top 10 Error Messages",
                color='Count'
            )
            fig_bar.update_layout(yaxis={'categoryorder': 'total ascending'})
            st.plotly_chart(fig_bar, use_container_width=True)
        else:
            st.info("No errors found in the filtered selection.")

    # --- Data Table Section ---
    st.markdown("---")
    st.subheader("📋 Detailed Log View")
    
    st.dataframe(
        df, 
        use_container_width=True, 
        height=400,
        column_config={
            "timestamp": st.column_config.DatetimeColumn("Timestamp", format="D MMM YYYY, h:mm a"),
        }
    )
    
    # Export
    csv = convert_df(df)
    st.download_button(
        label="📥 Download Filtered Logs (CSV)",
        data=csv,
        file_name='filtered_logs.csv',
        mime='text/csv',
    )


if __name__ == "__main__":
    main()
