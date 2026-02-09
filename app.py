"""
Log Analyzer Dashboard
======================
A professional, industry-level Streamlit web application for analyzing server log files.
Provides security, usage, and performance insights with modern UI/UX.

Author: AI Assistant
Version: 1.0.0
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from datetime import datetime
import io
import base64
from typing import Tuple, List, Dict, Optional
import warnings

warnings.filterwarnings('ignore')

# ============================================================================
# PAGE CONFIGURATION
# ============================================================================
st.set_page_config(
    page_title="Log Analyzer Dashboard",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================================
# CUSTOM CSS STYLING
# ============================================================================
def load_custom_css():
    """Load custom CSS for professional styling."""
    st.markdown("""
    <style>
        /* Main container styling */
        .main .block-container {
            padding-top: 2rem;
            padding-bottom: 2rem;
        }
        
        /* Sidebar styling */
        [data-testid="stSidebar"] {
            background: linear-gradient(180deg, #1e3a5f 0%, #0d1b2a 100%);
        }
        
        [data-testid="stSidebar"] .css-1d391kg {
            padding-top: 2rem;
        }
        
        /* Header styling */
        .main-header {
            font-size: 2.5rem;
            font-weight: 700;
            background: linear-gradient(90deg, #00d4ff, #7b2cbf);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            text-align: center;
            padding: 1rem 0;
        }
        
        .sub-header {
            font-size: 1.1rem;
            color: #8892b0;
            text-align: center;
            margin-bottom: 2rem;
        }
        
        /* Card styling */
        .metric-card {
            background: linear-gradient(135deg, #1e3a5f 0%, #2d5a87 100%);
            border-radius: 15px;
            padding: 1.5rem;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            border: 1px solid rgba(255, 255, 255, 0.1);
            margin-bottom: 1rem;
        }
        
        .metric-value {
            font-size: 2.5rem;
            font-weight: 700;
            color: #00d4ff;
        }
        
        .metric-label {
            font-size: 0.9rem;
            color: #8892b0;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        /* Alert styling */
        .alert-danger {
            background: linear-gradient(135deg, #ff4757 0%, #c0392b 100%);
            border-radius: 10px;
            padding: 1rem;
            color: white;
            margin: 0.5rem 0;
            border-left: 4px solid #ff6b6b;
        }
        
        .alert-warning {
            background: linear-gradient(135deg, #ffa502 0%, #e67e22 100%);
            border-radius: 10px;
            padding: 1rem;
            color: white;
            margin: 0.5rem 0;
            border-left: 4px solid #ffcc00;
        }
        
        .alert-success {
            background: linear-gradient(135deg, #2ed573 0%, #27ae60 100%);
            border-radius: 10px;
            padding: 1rem;
            color: white;
            margin: 0.5rem 0;
            border-left: 4px solid #7bed9f;
        }
        
        /* Table styling */
        .dataframe {
            border-radius: 10px;
            overflow: hidden;
        }
        
        /* Section headers */
        .section-header {
            font-size: 1.5rem;
            font-weight: 600;
            color: #00d4ff;
            margin: 2rem 0 1rem 0;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid #2d5a87;
        }
        
        /* Sidebar navigation */
        .nav-item {
            padding: 0.75rem 1rem;
            margin: 0.25rem 0;
            border-radius: 8px;
            transition: all 0.3s ease;
        }
        
        .nav-item:hover {
            background: rgba(0, 212, 255, 0.1);
        }
        
        /* Button styling */
        .stButton > button {
            background: linear-gradient(90deg, #00d4ff, #7b2cbf);
            color: white;
            border: none;
            border-radius: 25px;
            padding: 0.5rem 2rem;
            font-weight: 600;
            transition: all 0.3s ease;
        }
        
        .stButton > button:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(0, 212, 255, 0.4);
        }
        
        /* File uploader */
        [data-testid="stFileUploader"] {
            border: 2px dashed #2d5a87;
            border-radius: 15px;
            padding: 2rem;
            background: rgba(30, 58, 95, 0.3);
        }
        
        /* Expander styling */
        .streamlit-expanderHeader {
            background: linear-gradient(90deg, #1e3a5f, #2d5a87);
            border-radius: 10px;
        }
        
        /* Progress bar */
        .stProgress > div > div {
            background: linear-gradient(90deg, #00d4ff, #7b2cbf);
        }
        
        /* Footer */
        .footer {
            text-align: center;
            padding: 2rem;
            color: #8892b0;
            font-size: 0.9rem;
        }
    </style>
    """, unsafe_allow_html=True)


# ============================================================================
# DATA LOADING AND VALIDATION
# ============================================================================
def validate_csv_file(file) -> Tuple[bool, str]:
    """
    Validate if the uploaded file is a proper CSV.
    
    Args:
        file: Uploaded file object
        
    Returns:
        Tuple of (is_valid, message)
    """
    if file is None:
        return False, "No file uploaded."
    
    # Check file extension
    if not file.name.lower().endswith('.csv'):
        return False, f"❌ Invalid file format: '{file.name}'. Please upload a CSV file."
    
    # Check file size (max 100MB)
    file_size = file.size / (1024 * 1024)  # Convert to MB
    if file_size > 100:
        return False, f"❌ File too large ({file_size:.2f} MB). Maximum size is 100 MB."
    
    return True, "✅ File validation successful."


def load_csv_data(files: List) -> Tuple[Optional[pd.DataFrame], str]:
    """
    Load and concatenate multiple CSV files.
    
    Args:
        files: List of uploaded file objects
        
    Returns:
        Tuple of (DataFrame or None, status message)
    """
    if not files:
        return None, "No files provided."
    
    dataframes = []
    
    for file in files:
        try:
            df = pd.read_csv(file)
            df['source_file'] = file.name  # Track source file
            dataframes.append(df)
        except Exception as e:
            return None, f"❌ Error reading '{file.name}': {str(e)}"
    
    if dataframes:
        combined_df = pd.concat(dataframes, ignore_index=True)
        return combined_df, f"✅ Successfully loaded {len(files)} file(s) with {len(combined_df):,} records."
    
    return None, "❌ No data could be loaded."


# ============================================================================
# DATA PREPROCESSING
# ============================================================================
def preprocess_data(df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict]:
    """
    Preprocess the log data: handle missing values, convert types, etc.
    
    Args:
        df: Raw DataFrame
        
    Returns:
        Tuple of (cleaned DataFrame, preprocessing summary)
    """
    summary = {
        'original_rows': len(df),
        'original_cols': len(df.columns),
        'missing_before': df.isnull().sum().sum(),
        'duplicates_removed': 0,
        'datetime_converted': False,
        'numeric_converted': [],
        'missing_after': 0
    }
    
    # Create a copy to avoid modifying original
    cleaned_df = df.copy()
    
    # Remove duplicates
    before_dedup = len(cleaned_df)
    cleaned_df = cleaned_df.drop_duplicates()
    summary['duplicates_removed'] = before_dedup - len(cleaned_df)
    
    # Identify and convert datetime columns
    datetime_cols = ['timestamp', 'time', 'datetime', 'date', 'login_time', 
                     'logout_time', 'created_at', 'updated_at', 'session_start',
                     'session_end']
    
    for col in cleaned_df.columns:
        if col.lower() in datetime_cols or 'time' in col.lower() or 'date' in col.lower():
            try:
                cleaned_df[col] = pd.to_datetime(cleaned_df[col], errors='coerce')
                summary['datetime_converted'] = True
            except:
                pass
    
    # Identify and convert numeric columns
    numeric_cols = ['duration', 'requests', 'response_time', 'bytes', 'size',
                    'count', 'attempts', 'session_duration', 'failed_attempts']
    
    for col in cleaned_df.columns:
        if col.lower() in numeric_cols or any(x in col.lower() for x in ['count', 'num', 'duration', 'size']):
            try:
                cleaned_df[col] = pd.to_numeric(cleaned_df[col], errors='coerce')
                summary['numeric_converted'].append(col)
            except:
                pass
    
    # Handle missing values
    for col in cleaned_df.columns:
        if cleaned_df[col].dtype in ['int64', 'float64']:
            # Fill numeric with median
            cleaned_df[col] = cleaned_df[col].fillna(cleaned_df[col].median())
        elif cleaned_df[col].dtype == 'object':
            # Fill categorical with mode or 'Unknown'
            mode_val = cleaned_df[col].mode()
            cleaned_df[col] = cleaned_df[col].fillna(mode_val[0] if len(mode_val) > 0 else 'Unknown')
    
    summary['missing_after'] = cleaned_df.isnull().sum().sum()
    summary['final_rows'] = len(cleaned_df)
    summary['final_cols'] = len(cleaned_df.columns)
    
    return cleaned_df, summary


def get_data_summary(df: pd.DataFrame) -> Dict:
    """
    Generate a comprehensive data summary.
    
    Args:
        df: DataFrame to summarize
        
    Returns:
        Dictionary with summary statistics
    """
    return {
        'total_records': len(df),
        'total_columns': len(df.columns),
        'column_types': df.dtypes.value_counts().to_dict(),
        'memory_usage': df.memory_usage(deep=True).sum() / (1024 * 1024),  # MB
        'numeric_cols': df.select_dtypes(include=[np.number]).columns.tolist(),
        'categorical_cols': df.select_dtypes(include=['object']).columns.tolist(),
        'datetime_cols': df.select_dtypes(include=['datetime64']).columns.tolist()
    }


# ============================================================================
# SECURITY ANALYSIS MODULE
# ============================================================================
def detect_failed_logins(df: pd.DataFrame, status_col: str = 'status') -> pd.DataFrame:
    """
    Detect failed login attempts from the log data.
    
    Args:
        df: Log DataFrame
        status_col: Column name containing login status
        
    Returns:
        DataFrame with failed login records
    """
    if status_col not in df.columns:
        # Try to find a suitable column
        for col in df.columns:
            if 'status' in col.lower() or 'result' in col.lower() or 'success' in col.lower():
                status_col = col
                break
        else:
            return pd.DataFrame()
    
    # Identify failed patterns
    failed_patterns = ['failed', 'failure', 'fail', 'error', 'denied', 'rejected', 
                       'invalid', 'unauthorized', '0', 'false', 'no']
    
    failed_mask = df[status_col].astype(str).str.lower().isin(failed_patterns)
    return df[failed_mask]


def identify_suspicious_users(df: pd.DataFrame, user_col: str = 'user', 
                              threshold: int = 5) -> pd.DataFrame:
    """
    Identify users with suspiciously high failed login attempts.
    
    Args:
        df: Failed logins DataFrame
        user_col: Column name containing user IDs
        threshold: Number of failed attempts to flag as suspicious
        
    Returns:
        DataFrame with suspicious users and their attempt counts
    """
    if df.empty or user_col not in df.columns:
        # Try to find user column
        for col in df.columns:
            if 'user' in col.lower() or 'username' in col.lower() or 'account' in col.lower():
                user_col = col
                break
        else:
            return pd.DataFrame()
    
    user_counts = df[user_col].value_counts().reset_index()
    user_counts.columns = ['User', 'Failed_Attempts']
    suspicious = user_counts[user_counts['Failed_Attempts'] >= threshold]
    suspicious['Risk_Level'] = suspicious['Failed_Attempts'].apply(
        lambda x: 'Critical' if x >= threshold * 2 else 'High' if x >= threshold * 1.5 else 'Moderate'
    )
    
    return suspicious


def create_security_charts(df: pd.DataFrame, failed_df: pd.DataFrame, 
                           suspicious_df: pd.DataFrame) -> Dict:
    """
    Create security-related visualizations.
    
    Args:
        df: Original DataFrame
        failed_df: Failed logins DataFrame
        suspicious_df: Suspicious users DataFrame
        
    Returns:
        Dictionary containing Plotly figure objects
    """
    charts = {}
    
    # Failed login attempts by user (top 15)
    if not failed_df.empty:
        user_col = None
        for col in failed_df.columns:
            if 'user' in col.lower() or 'username' in col.lower():
                user_col = col
                break
        
        if user_col:
            top_failed = failed_df[user_col].value_counts().head(15)
            fig = px.bar(
                x=top_failed.values,
                y=top_failed.index,
                orientation='h',
                title='🚨 Top 15 Users with Failed Login Attempts',
                labels={'x': 'Failed Attempts', 'y': 'User'},
                color=top_failed.values,
                color_continuous_scale='Reds'
            )
            fig.update_layout(
                plot_bgcolor='rgba(0,0,0,0)',
                paper_bgcolor='rgba(0,0,0,0)',
                font_color='#8892b0',
                showlegend=False,
                height=500
            )
            charts['failed_by_user'] = fig
    
    # Failed logins over time
    time_col = None
    for col in failed_df.columns:
        if 'time' in col.lower() or 'date' in col.lower():
            if pd.api.types.is_datetime64_any_dtype(failed_df[col]):
                time_col = col
                break
    
    if time_col and not failed_df.empty:
        failed_time = failed_df.copy()
        failed_time['hour'] = failed_time[time_col].dt.hour
        hourly_failed = failed_time['hour'].value_counts().sort_index()
        
        fig = px.line(
            x=hourly_failed.index,
            y=hourly_failed.values,
            title='⏰ Failed Login Attempts by Hour',
            labels={'x': 'Hour of Day', 'y': 'Failed Attempts'},
            markers=True
        )
        fig.update_traces(line_color='#ff4757', fill='tozeroy', fillcolor='rgba(255, 71, 87, 0.2)')
        fig.update_layout(
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font_color='#8892b0',
            height=400
        )
        charts['failed_by_hour'] = fig
    
    # Risk level distribution
    if not suspicious_df.empty and 'Risk_Level' in suspicious_df.columns:
        risk_counts = suspicious_df['Risk_Level'].value_counts()
        fig = px.pie(
            values=risk_counts.values,
            names=risk_counts.index,
            title='🎯 Risk Level Distribution',
            color=risk_counts.index,
            color_discrete_map={'Critical': '#ff4757', 'High': '#ffa502', 'Moderate': '#2ed573'}
        )
        fig.update_layout(
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font_color='#8892b0',
            height=400
        )
        charts['risk_distribution'] = fig
    
    return charts


# ============================================================================
# USAGE ANALYSIS MODULE
# ============================================================================
def get_most_active_users(df: pd.DataFrame, user_col: str = 'user', top_n: int = 10) -> pd.DataFrame:
    """
    Identify the most active users based on log entries.
    
    Args:
        df: Log DataFrame
        user_col: Column name containing user IDs
        top_n: Number of top users to return
        
    Returns:
        DataFrame with most active users
    """
    # Find user column
    for col in df.columns:
        if 'user' in col.lower() or 'username' in col.lower() or 'account' in col.lower():
            user_col = col
            break
    
    if user_col not in df.columns:
        return pd.DataFrame()
    
    activity = df[user_col].value_counts().head(top_n).reset_index()
    activity.columns = ['User', 'Activity_Count']
    activity['Percentage'] = (activity['Activity_Count'] / len(df) * 100).round(2)
    
    return activity


def get_service_usage(df: pd.DataFrame, service_col: str = 'service') -> pd.DataFrame:
    """
    Analyze service usage statistics.
    
    Args:
        df: Log DataFrame
        service_col: Column name containing service names
        
    Returns:
        DataFrame with service usage statistics
    """
    # Find service column
    for col in df.columns:
        if 'service' in col.lower() or 'endpoint' in col.lower() or 'api' in col.lower() or 'action' in col.lower():
            service_col = col
            break
    
    if service_col not in df.columns:
        return pd.DataFrame()
    
    usage = df[service_col].value_counts().reset_index()
    usage.columns = ['Service', 'Usage_Count']
    usage['Percentage'] = (usage['Usage_Count'] / len(df) * 100).round(2)
    
    return usage


def get_activity_by_time(df: pd.DataFrame) -> Dict:
    """
    Analyze login activity by hour and day.
    
    Args:
        df: Log DataFrame
        
    Returns:
        Dictionary with hourly and daily activity
    """
    result = {}
    
    # Find datetime column
    time_col = None
    for col in df.columns:
        if pd.api.types.is_datetime64_any_dtype(df[col]):
            time_col = col
            break
    
    if time_col is None:
        return result
    
    df_time = df.copy()
    df_time['hour'] = df_time[time_col].dt.hour
    df_time['day'] = df_time[time_col].dt.day_name()
    
    result['hourly'] = df_time['hour'].value_counts().sort_index()
    result['daily'] = df_time['day'].value_counts()
    
    return result


def create_usage_charts(df: pd.DataFrame, active_users: pd.DataFrame, 
                        service_usage: pd.DataFrame, time_activity: Dict) -> Dict:
    """
    Create usage-related visualizations.
    
    Args:
        df: Original DataFrame
        active_users: Most active users DataFrame
        service_usage: Service usage DataFrame
        time_activity: Time-based activity dictionary
        
    Returns:
        Dictionary containing Plotly figure objects
    """
    charts = {}
    
    # Most active users chart
    if not active_users.empty:
        fig = px.bar(
            active_users,
            x='User',
            y='Activity_Count',
            title='👥 Most Active Users',
            color='Activity_Count',
            color_continuous_scale='Blues'
        )
        fig.update_layout(
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font_color='#8892b0',
            height=400
        )
        charts['active_users'] = fig
    
    # Service usage pie chart
    if not service_usage.empty:
        fig = px.pie(
            service_usage.head(10),
            values='Usage_Count',
            names='Service',
            title='🔧 Service Usage Distribution',
            color_discrete_sequence=px.colors.sequential.Viridis
        )
        fig.update_layout(
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font_color='#8892b0',
            height=450
        )
        charts['service_usage'] = fig
    
    # Hourly activity
    if 'hourly' in time_activity:
        hourly = time_activity['hourly']
        fig = px.area(
            x=hourly.index,
            y=hourly.values,
            title='📈 Activity by Hour of Day',
            labels={'x': 'Hour', 'y': 'Number of Logs'}
        )
        fig.update_traces(fill='tozeroy', line_color='#00d4ff', fillcolor='rgba(0, 212, 255, 0.3)')
        fig.update_layout(
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font_color='#8892b0',
            height=400
        )
        charts['hourly_activity'] = fig
    
    # Daily activity
    if 'daily' in time_activity:
        daily = time_activity['daily']
        day_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        daily = daily.reindex([d for d in day_order if d in daily.index])
        
        fig = px.bar(
            x=daily.index,
            y=daily.values,
            title='📅 Activity by Day of Week',
            labels={'x': 'Day', 'y': 'Number of Logs'},
            color=daily.values,
            color_continuous_scale='Viridis'
        )
        fig.update_layout(
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font_color='#8892b0',
            height=400
        )
        charts['daily_activity'] = fig
    
    return charts


# ============================================================================
# PERFORMANCE ANALYSIS MODULE
# ============================================================================
def get_session_duration_stats(df: pd.DataFrame, duration_col: str = 'duration') -> pd.DataFrame:
    """
    Calculate session duration statistics per user.
    
    Args:
        df: Log DataFrame
        duration_col: Column name containing session duration
        
    Returns:
        DataFrame with duration statistics per user
    """
    # Find duration column
    for col in df.columns:
        if 'duration' in col.lower() or 'time' in col.lower() and 'session' in col.lower():
            duration_col = col
            break
    
    # Find user column
    user_col = None
    for col in df.columns:
        if 'user' in col.lower() or 'username' in col.lower():
            user_col = col
            break
    
    if duration_col not in df.columns or user_col is None:
        return pd.DataFrame()
    
    stats = df.groupby(user_col)[duration_col].agg(['mean', 'min', 'max', 'count']).reset_index()
    stats.columns = ['User', 'Avg_Duration', 'Min_Duration', 'Max_Duration', 'Session_Count']
    stats = stats.round(2).sort_values('Avg_Duration', ascending=False)
    
    return stats


def get_slowest_services(df: pd.DataFrame, service_col: str = 'service', 
                         duration_col: str = 'duration', top_n: int = 10) -> pd.DataFrame:
    """
    Identify the slowest services based on response time.
    
    Args:
        df: Log DataFrame
        service_col: Column name containing service names
        duration_col: Column name containing response time/duration
        top_n: Number of services to return
        
    Returns:
        DataFrame with slowest services
    """
    # Find appropriate columns
    for col in df.columns:
        if 'service' in col.lower() or 'endpoint' in col.lower() or 'api' in col.lower():
            service_col = col
            break
    
    for col in df.columns:
        if 'duration' in col.lower() or 'response' in col.lower() or 'time' in col.lower():
            if pd.api.types.is_numeric_dtype(df[col]):
                duration_col = col
                break
    
    if service_col not in df.columns or duration_col not in df.columns:
        return pd.DataFrame()
    
    service_perf = df.groupby(service_col)[duration_col].agg(['mean', 'max', 'count']).reset_index()
    service_perf.columns = ['Service', 'Avg_Duration', 'Max_Duration', 'Request_Count']
    service_perf = service_perf.sort_values('Avg_Duration', ascending=False).head(top_n)
    
    return service_perf.round(2)


def get_longest_sessions(df: pd.DataFrame, top_n: int = 10) -> pd.DataFrame:
    """
    Get the longest sessions from the log data.
    
    Args:
        df: Log DataFrame
        top_n: Number of sessions to return
        
    Returns:
        DataFrame with longest sessions
    """
    # Find duration column
    duration_col = None
    for col in df.columns:
        if 'duration' in col.lower():
            if pd.api.types.is_numeric_dtype(df[col]):
                duration_col = col
                break
    
    if duration_col is None:
        return pd.DataFrame()
    
    # Find user column
    user_col = None
    for col in df.columns:
        if 'user' in col.lower():
            user_col = col
            break
    
    if user_col:
        result = df.nlargest(top_n, duration_col)[[user_col, duration_col]].reset_index(drop=True)
        result.columns = ['User', 'Duration']
    else:
        result = df.nlargest(top_n, duration_col)[[duration_col]].reset_index(drop=True)
        result.columns = ['Duration']
    
    return result


def create_performance_charts(df: pd.DataFrame, duration_stats: pd.DataFrame,
                               slowest_services: pd.DataFrame) -> Dict:
    """
    Create performance-related visualizations.
    
    Args:
        df: Original DataFrame
        duration_stats: Session duration statistics DataFrame
        slowest_services: Slowest services DataFrame
        
    Returns:
        Dictionary containing Plotly figure objects
    """
    charts = {}
    
    # Session duration histogram
    duration_col = None
    for col in df.columns:
        if 'duration' in col.lower():
            if pd.api.types.is_numeric_dtype(df[col]):
                duration_col = col
                break
    
    if duration_col:
        fig = px.histogram(
            df,
            x=duration_col,
            nbins=50,
            title='📊 Session Duration Distribution',
            labels={duration_col: 'Duration'},
            color_discrete_sequence=['#7b2cbf']
        )
        fig.update_layout(
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font_color='#8892b0',
            height=400
        )
        charts['duration_histogram'] = fig
    
    # Average duration by user
    if not duration_stats.empty:
        top_users = duration_stats.head(15)
        fig = px.bar(
            top_users,
            x='User',
            y='Avg_Duration',
            title='⏱️ Average Session Duration by User',
            color='Avg_Duration',
            color_continuous_scale='Purples'
        )
        fig.update_layout(
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font_color='#8892b0',
            height=400,
            xaxis_tickangle=-45
        )
        charts['duration_by_user'] = fig
    
    # Slowest services
    if not slowest_services.empty:
        fig = px.bar(
            slowest_services,
            x='Avg_Duration',
            y='Service',
            orientation='h',
            title='🐢 Slowest Services (by Average Duration)',
            color='Avg_Duration',
            color_continuous_scale='Oranges'
        )
        fig.update_layout(
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font_color='#8892b0',
            height=450
        )
        charts['slowest_services'] = fig
    
    return charts


# ============================================================================
# REPORT GENERATION MODULE
# ============================================================================
def generate_html_report(df: pd.DataFrame) -> str:
    """
    Generate a comprehensive HTML profiling report.
    First tries ydata-profiling, falls back to custom report.
    
    Args:
        df: DataFrame to profile
        
    Returns:
        HTML string of the report
    """
    # Try ydata-profiling first
    try:
        from ydata_profiling import ProfileReport
        
        profile = ProfileReport(
            df,
            title="Log Analyzer - Data Profiling Report",
            minimal=True,
            explorative=True,
            dark_mode=True
        )
        
        return profile.to_html()
    except ImportError:
        pass  # Fall through to custom report
    except Exception:
        pass  # Fall through to custom report
    
    # Generate custom HTML report
    return _generate_custom_html_report(df)


def _generate_custom_html_report(df: pd.DataFrame) -> str:
    """
    Generate a custom HTML profiling report without external dependencies.
    
    Args:
        df: DataFrame to profile
        
    Returns:
        HTML string of the report
    """
    from datetime import datetime
    
    # Calculate statistics
    total_rows = len(df)
    total_cols = len(df.columns)
    memory_mb = df.memory_usage(deep=True).sum() / (1024 * 1024)
    missing_total = df.isnull().sum().sum()
    missing_pct = (missing_total / (total_rows * total_cols) * 100) if total_rows * total_cols > 0 else 0
    duplicate_rows = df.duplicated().sum()
    
    # Column analysis
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    categorical_cols = df.select_dtypes(include=['object']).columns.tolist()
    datetime_cols = df.select_dtypes(include=['datetime64']).columns.tolist()
    
    # Generate column details HTML
    column_details_html = ""
    for col in df.columns:
        col_type = str(df[col].dtype)
        missing = df[col].isnull().sum()
        missing_pct_col = (missing / total_rows * 100) if total_rows > 0 else 0
        unique = df[col].nunique()
        
        if df[col].dtype in ['int64', 'float64']:
            stats = f"""
            <div class="stat-grid">
                <div class="stat-item"><span class="stat-label">Mean:</span> {df[col].mean():.2f}</div>
                <div class="stat-item"><span class="stat-label">Std:</span> {df[col].std():.2f}</div>
                <div class="stat-item"><span class="stat-label">Min:</span> {df[col].min():.2f}</div>
                <div class="stat-item"><span class="stat-label">Max:</span> {df[col].max():.2f}</div>
                <div class="stat-item"><span class="stat-label">Median:</span> {df[col].median():.2f}</div>
            </div>
            """
        elif df[col].dtype == 'object':
            top_values = df[col].value_counts().head(5)
            top_html = "<br>".join([f"{v}: {c}" for v, c in zip(top_values.index, top_values.values)])
            stats = f"""
            <div class="stat-grid">
                <div class="stat-item"><span class="stat-label">Top Values:</span><br>{top_html}</div>
            </div>
            """
        else:
            stats = "<div class='stat-grid'><div class='stat-item'>DateTime column</div></div>"
        
        column_details_html += f"""
        <div class="column-card">
            <div class="column-header">
                <h3>{col}</h3>
                <span class="column-type">{col_type}</span>
            </div>
            <div class="column-stats">
                <div class="mini-stat">
                    <span class="mini-value">{unique:,}</span>
                    <span class="mini-label">Unique</span>
                </div>
                <div class="mini-stat">
                    <span class="mini-value">{missing:,}</span>
                    <span class="mini-label">Missing</span>
                </div>
                <div class="mini-stat">
                    <span class="mini-value">{missing_pct_col:.1f}%</span>
                    <span class="mini-label">Missing %</span>
                </div>
            </div>
            {stats}
        </div>
        """
    
    # Sample data HTML
    sample_html = df.head(10).to_html(classes='data-table', index=False)
    
    html_report = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Log Analyzer - Data Profiling Report</title>
        <style>
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
            
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #0d1b2a 0%, #1b263b 100%);
                color: #e0e1dd;
                min-height: 100vh;
                padding: 2rem;
            }}
            
            .container {{
                max-width: 1400px;
                margin: 0 auto;
            }}
            
            .header {{
                text-align: center;
                padding: 2rem 0;
                border-bottom: 2px solid #415a77;
                margin-bottom: 2rem;
            }}
            
            .header h1 {{
                font-size: 2.5rem;
                background: linear-gradient(90deg, #00d4ff, #7b2cbf);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
            }}
            
            .header p {{
                color: #8892b0;
                margin-top: 0.5rem;
            }}
            
            .section {{
                background: rgba(27, 38, 59, 0.8);
                border-radius: 15px;
                padding: 1.5rem;
                margin-bottom: 2rem;
                border: 1px solid #415a77;
            }}
            
            .section-title {{
                font-size: 1.5rem;
                color: #00d4ff;
                margin-bottom: 1rem;
                padding-bottom: 0.5rem;
                border-bottom: 1px solid #415a77;
            }}
            
            .metrics-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 1rem;
            }}
            
            .metric-card {{
                background: linear-gradient(135deg, #1e3a5f 0%, #2d5a87 100%);
                border-radius: 10px;
                padding: 1.5rem;
                text-align: center;
            }}
            
            .metric-value {{
                font-size: 2rem;
                font-weight: 700;
                color: #00d4ff;
            }}
            
            .metric-label {{
                font-size: 0.9rem;
                color: #8892b0;
                text-transform: uppercase;
                letter-spacing: 1px;
                margin-top: 0.5rem;
            }}
            
            .column-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
                gap: 1rem;
            }}
            
            .column-card {{
                background: rgba(65, 90, 119, 0.3);
                border-radius: 10px;
                padding: 1rem;
                border: 1px solid #415a77;
            }}
            
            .column-header {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 1rem;
            }}
            
            .column-header h3 {{
                color: #00d4ff;
                font-size: 1.1rem;
            }}
            
            .column-type {{
                background: #7b2cbf;
                color: white;
                padding: 0.25rem 0.75rem;
                border-radius: 15px;
                font-size: 0.75rem;
            }}
            
            .column-stats {{
                display: flex;
                gap: 1rem;
                margin-bottom: 1rem;
            }}
            
            .mini-stat {{
                text-align: center;
                flex: 1;
            }}
            
            .mini-value {{
                display: block;
                font-size: 1.25rem;
                font-weight: 600;
                color: #e0e1dd;
            }}
            
            .mini-label {{
                font-size: 0.75rem;
                color: #8892b0;
            }}
            
            .stat-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(100px, 1fr));
                gap: 0.5rem;
            }}
            
            .stat-item {{
                font-size: 0.85rem;
                color: #8892b0;
            }}
            
            .stat-label {{
                color: #00d4ff;
            }}
            
            .data-table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 1rem;
            }}
            
            .data-table th {{
                background: #1e3a5f;
                color: #00d4ff;
                padding: 0.75rem;
                text-align: left;
                font-weight: 600;
            }}
            
            .data-table td {{
                padding: 0.75rem;
                border-bottom: 1px solid #415a77;
            }}
            
            .data-table tr:nth-child(even) {{
                background: rgba(65, 90, 119, 0.2);
            }}
            
            .data-table tr:hover {{
                background: rgba(0, 212, 255, 0.1);
            }}
            
            .footer {{
                text-align: center;
                padding: 2rem;
                color: #8892b0;
                font-size: 0.9rem;
            }}
            
            .type-badge {{
                display: inline-block;
                padding: 0.25rem 0.75rem;
                border-radius: 15px;
                font-size: 0.8rem;
                margin-right: 0.5rem;
                margin-bottom: 0.5rem;
            }}
            
            .type-numeric {{ background: #2ed573; color: #0d1b2a; }}
            .type-categorical {{ background: #ffa502; color: #0d1b2a; }}
            .type-datetime {{ background: #7b2cbf; color: white; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔍 Log Analyzer - Data Profiling Report</h1>
                <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="section">
                <h2 class="section-title">📊 Dataset Overview</h2>
                <div class="metrics-grid">
                    <div class="metric-card">
                        <div class="metric-value">{total_rows:,}</div>
                        <div class="metric-label">Total Rows</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value">{total_cols}</div>
                        <div class="metric-label">Total Columns</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value">{memory_mb:.2f} MB</div>
                        <div class="metric-label">Memory Usage</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value">{missing_total:,}</div>
                        <div class="metric-label">Missing Values</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value">{missing_pct:.1f}%</div>
                        <div class="metric-label">Missing %</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value">{duplicate_rows:,}</div>
                        <div class="metric-label">Duplicate Rows</div>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h2 class="section-title">📋 Column Types</h2>
                <p style="margin-bottom: 1rem;">
                    <span class="type-badge type-numeric">Numeric: {len(numeric_cols)}</span>
                    <span class="type-badge type-categorical">Categorical: {len(categorical_cols)}</span>
                    <span class="type-badge type-datetime">DateTime: {len(datetime_cols)}</span>
                </p>
            </div>
            
            <div class="section">
                <h2 class="section-title">🔬 Column Analysis</h2>
                <div class="column-grid">
                    {column_details_html}
                </div>
            </div>
            
            <div class="section">
                <h2 class="section-title">👀 Sample Data (First 10 Rows)</h2>
                {sample_html}
            </div>
            
            <div class="footer">
                <p>🔍 Log Analyzer Dashboard - Data Profiling Report</p>
                <p>Enterprise Log Analysis Solution</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    return html_report


def create_csv_report(data: pd.DataFrame, report_name: str) -> str:
    """
    Create a CSV report for download.
    
    Args:
        data: DataFrame to export
        report_name: Name of the report
        
    Returns:
        CSV string
    """
    return data.to_csv(index=False)


def get_download_link(content: str, filename: str, file_type: str = 'csv') -> str:
    """
    Generate a download link for file content.
    
    Args:
        content: File content as string
        filename: Name for the downloaded file
        file_type: Type of file (csv, html)
        
    Returns:
        HTML anchor tag for download
    """
    mime_types = {
        'csv': 'text/csv',
        'html': 'text/html'
    }
    
    b64 = base64.b64encode(content.encode()).decode()
    mime = mime_types.get(file_type, 'text/plain')
    
    return f'<a href="data:{mime};base64,{b64}" download="{filename}">📥 Download {filename}</a>'


# ============================================================================
# MAIN APPLICATION
# ============================================================================
def main():
    """Main application entry point."""
    
    # Load custom CSS
    load_custom_css()
    
    # Initialize session state
    if 'data' not in st.session_state:
        st.session_state.data = None
    if 'cleaned_data' not in st.session_state:
        st.session_state.cleaned_data = None
    if 'preprocessing_summary' not in st.session_state:
        st.session_state.preprocessing_summary = None
    
    # Sidebar Navigation
    with st.sidebar:
        st.markdown("""
        <div style="text-align: center; padding: 1rem 0;">
            <h1 style="color: #00d4ff; font-size: 1.8rem;">🔍 Log Analyzer</h1>
            <p style="color: #8892b0; font-size: 0.9rem;">Enterprise Dashboard</p>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("---")
        
        # Navigation menu
        page = st.radio(
            "📋 Navigation",
            options=[
                "📤 Upload Data",
                "🔐 Security Analysis",
                "📊 Usage Analysis",
                "⚡ Performance Analysis",
                "📝 Reports"
            ],
            label_visibility="collapsed"
        )
        
        st.markdown("---")
        
        # Quick Stats in Sidebar
        if st.session_state.cleaned_data is not None:
            df = st.session_state.cleaned_data
            st.markdown("### 📈 Quick Stats")
            st.metric("Total Records", f"{len(df):,}")
            st.metric("Columns", f"{len(df.columns)}")
            
            # Memory usage
            memory_mb = df.memory_usage(deep=True).sum() / (1024 * 1024)
            st.metric("Memory Usage", f"{memory_mb:.2f} MB")
        
        st.markdown("---")
        st.markdown("""
        <div style="text-align: center; color: #8892b0; font-size: 0.8rem;">
            <p>v1.0.0</p>
            <p>Built with ❤️ using Streamlit</p>
        </div>
        """, unsafe_allow_html=True)
    
    # Main Content Area
    st.markdown('<h1 class="main-header">🔍 Log Analyzer Dashboard</h1>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">Enterprise-grade log analysis for security, usage, and performance insights</p>', unsafe_allow_html=True)
    
    # ========== UPLOAD DATA PAGE ==========
    if page == "📤 Upload Data":
        st.markdown("## 📤 Upload Log Files")
        st.markdown("Upload one or more CSV log files to begin analysis. Supported format: `.csv`")
        
        # File uploader
        uploaded_files = st.file_uploader(
            "Drag and drop files here or click to browse",
            type=['csv'],
            accept_multiple_files=True,
            help="Upload CSV log files. Maximum file size: 100MB each."
        )
        
        if uploaded_files:
            # Validate files
            all_valid = True
            for file in uploaded_files:
                is_valid, message = validate_csv_file(file)
                if not is_valid:
                    st.error(message)
                    all_valid = False
            
            if all_valid:
                with st.spinner("Loading files..."):
                    df, status = load_csv_data(uploaded_files)
                
                if df is not None:
                    st.success(status)
                    st.session_state.data = df
                    
                    # Show file info
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Files Uploaded", len(uploaded_files))
                    with col2:
                        st.metric("Total Records", f"{len(df):,}")
                    with col3:
                        st.metric("Columns", len(df.columns))
                    
                    # Data Preview
                    st.markdown("### 👀 Data Preview (First 10 Rows)")
                    st.dataframe(df.head(10), use_container_width=True)
                    
                    # Preprocessing
                    st.markdown("### 🔧 Data Preprocessing")
                    
                    if st.button("🚀 Clean & Process Data", type="primary"):
                        with st.spinner("Preprocessing data..."):
                            cleaned_df, summary = preprocess_data(df)
                            st.session_state.cleaned_data = cleaned_df
                            st.session_state.preprocessing_summary = summary
                        
                        st.success("✅ Data preprocessing completed!")
                        
                        # Show preprocessing summary
                        st.markdown("#### Preprocessing Summary")
                        
                        col1, col2, col3, col4 = st.columns(4)
                        with col1:
                            st.metric("Original Rows", f"{summary['original_rows']:,}")
                        with col2:
                            st.metric("Duplicates Removed", f"{summary['duplicates_removed']:,}")
                        with col3:
                            st.metric("Missing Values Fixed", 
                                     f"{summary['missing_before'] - summary['missing_after']:,}")
                        with col4:
                            st.metric("Final Rows", f"{summary['final_rows']:,}")
                        
                        # Data types info
                        with st.expander("📊 Data Type Information"):
                            data_summary = get_data_summary(cleaned_df)
                            
                            st.markdown("**Numeric Columns:**")
                            st.write(data_summary['numeric_cols'] if data_summary['numeric_cols'] else "None detected")
                            
                            st.markdown("**Categorical Columns:**")
                            st.write(data_summary['categorical_cols'] if data_summary['categorical_cols'] else "None detected")
                            
                            st.markdown("**DateTime Columns:**")
                            st.write(data_summary['datetime_cols'] if data_summary['datetime_cols'] else "None detected")
                else:
                    st.error(status)
        else:
            # Sample data structure info
            with st.expander("📋 Expected CSV Structure"):
                st.markdown("""
                Your CSV file should contain columns similar to:
                
                | Column | Description | Example |
                |--------|-------------|---------|
                | `timestamp` | Login/event time | 2024-01-15 10:30:00 |
                | `user` | Username or user ID | john_doe |
                | `service` | Service/endpoint accessed | /api/login |
                | `status` | Success/failure | success, failed |
                | `duration` | Session duration (seconds) | 125.5 |
                | `ip_address` | Client IP | 192.168.1.100 |
                
                **Note:** Column names are case-insensitive and the app will auto-detect common patterns.
                """)
    
    # ========== SECURITY ANALYSIS PAGE ==========
    elif page == "🔐 Security Analysis":
        st.markdown("## 🔐 Security Analysis")
        
        if st.session_state.cleaned_data is None:
            st.warning("⚠️ Please upload and process data first!")
            st.info("Go to '📤 Upload Data' to get started.")
        else:
            df = st.session_state.cleaned_data
            
            # Threshold selector
            col1, col2 = st.columns([1, 3])
            with col1:
                threshold = st.slider(
                    "Failed Login Threshold",
                    min_value=1,
                    max_value=20,
                    value=5,
                    help="Users with more than this many failed logins will be flagged as suspicious"
                )
            
            # Detect failed logins
            failed_df = detect_failed_logins(df)
            suspicious_df = identify_suspicious_users(failed_df, threshold=threshold)
            
            # Key Metrics
            st.markdown("### 📊 Security Metrics")
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("Total Log Records", f"{len(df):,}")
            with col2:
                st.metric("Failed Logins", f"{len(failed_df):,}", 
                         delta=f"{(len(failed_df)/len(df)*100):.1f}%" if len(df) > 0 else "0%")
            with col3:
                st.metric("Suspicious Users", f"{len(suspicious_df):,}",
                         delta="High Risk" if len(suspicious_df) > 5 else "Normal")
            with col4:
                critical_count = len(suspicious_df[suspicious_df['Risk_Level'] == 'Critical']) if not suspicious_df.empty and 'Risk_Level' in suspicious_df.columns else 0
                st.metric("Critical Risk Users", critical_count)
            
            # Alerts
            st.markdown("### ⚠️ Security Alerts")
            
            if not suspicious_df.empty:
                critical_users = suspicious_df[suspicious_df['Risk_Level'] == 'Critical'] if 'Risk_Level' in suspicious_df.columns else pd.DataFrame()
                high_risk_users = suspicious_df[suspicious_df['Risk_Level'] == 'High'] if 'Risk_Level' in suspicious_df.columns else pd.DataFrame()
                
                if not critical_users.empty:
                    for _, user in critical_users.iterrows():
                        st.markdown(f"""
                        <div class="alert-danger">
                            🚨 <strong>CRITICAL:</strong> User <strong>{user['User']}</strong> has 
                            {user['Failed_Attempts']} failed login attempts!
                        </div>
                        """, unsafe_allow_html=True)
                
                if not high_risk_users.empty:
                    for _, user in high_risk_users.iterrows():
                        st.markdown(f"""
                        <div class="alert-warning">
                            ⚠️ <strong>HIGH RISK:</strong> User <strong>{user['User']}</strong> has 
                            {user['Failed_Attempts']} failed login attempts.
                        </div>
                        """, unsafe_allow_html=True)
            else:
                st.markdown("""
                <div class="alert-success">
                    ✅ <strong>ALL CLEAR:</strong> No suspicious activity detected based on current threshold.
                </div>
                """, unsafe_allow_html=True)
            
            # Suspicious Users Table
            if not suspicious_df.empty:
                st.markdown("### 🔍 Suspicious Users")
                st.dataframe(
                    suspicious_df.style.background_gradient(subset=['Failed_Attempts'], cmap='Reds'),
                    use_container_width=True
                )
            
            # Charts
            st.markdown("### 📈 Security Visualizations")
            charts = create_security_charts(df, failed_df, suspicious_df)
            
            if 'failed_by_user' in charts:
                st.plotly_chart(charts['failed_by_user'], use_container_width=True)
            
            col1, col2 = st.columns(2)
            with col1:
                if 'failed_by_hour' in charts:
                    st.plotly_chart(charts['failed_by_hour'], use_container_width=True)
            with col2:
                if 'risk_distribution' in charts:
                    st.plotly_chart(charts['risk_distribution'], use_container_width=True)
    
    # ========== USAGE ANALYSIS PAGE ==========
    elif page == "📊 Usage Analysis":
        st.markdown("## 📊 Usage Analysis")
        
        if st.session_state.cleaned_data is None:
            st.warning("⚠️ Please upload and process data first!")
            st.info("Go to '📤 Upload Data' to get started.")
        else:
            df = st.session_state.cleaned_data
            
            # Get usage statistics
            active_users = get_most_active_users(df)
            service_usage = get_service_usage(df)
            time_activity = get_activity_by_time(df)
            
            # Key Metrics
            st.markdown("### 📊 Usage Metrics")
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                unique_users = df[df.columns[df.columns.str.contains('user', case=False)].tolist()[0]].nunique() if any(df.columns.str.contains('user', case=False)) else "N/A"
                st.metric("Unique Users", f"{unique_users:,}" if isinstance(unique_users, int) else unique_users)
            with col2:
                unique_services = df[df.columns[df.columns.str.contains('service|endpoint|api', case=False)].tolist()[0]].nunique() if any(df.columns.str.contains('service|endpoint|api', case=False)) else "N/A"
                st.metric("Unique Services", f"{unique_services:,}" if isinstance(unique_services, int) else unique_services)
            with col3:
                st.metric("Total Events", f"{len(df):,}")
            with col4:
                peak_hour = time_activity['hourly'].idxmax() if 'hourly' in time_activity and not time_activity['hourly'].empty else "N/A"
                st.metric("Peak Hour", f"{peak_hour}:00" if isinstance(peak_hour, (int, np.integer)) else peak_hour)
            
            # Tabs for different views
            tab1, tab2, tab3 = st.tabs(["👥 Users", "🔧 Services", "📅 Time Analysis"])
            
            with tab1:
                st.markdown("### Most Active Users")
                if not active_users.empty:
                    st.dataframe(
                        active_users.style.background_gradient(subset=['Activity_Count'], cmap='Blues'),
                        use_container_width=True
                    )
                    
                    charts = create_usage_charts(df, active_users, pd.DataFrame(), {})
                    if 'active_users' in charts:
                        st.plotly_chart(charts['active_users'], use_container_width=True)
                else:
                    st.info("No user data available for analysis.")
            
            with tab2:
                st.markdown("### Service Usage Statistics")
                if not service_usage.empty:
                    st.dataframe(
                        service_usage.style.background_gradient(subset=['Usage_Count'], cmap='Greens'),
                        use_container_width=True
                    )
                    
                    charts = create_usage_charts(df, pd.DataFrame(), service_usage, {})
                    if 'service_usage' in charts:
                        st.plotly_chart(charts['service_usage'], use_container_width=True)
                else:
                    st.info("No service data available for analysis.")
            
            with tab3:
                st.markdown("### Activity Over Time")
                charts = create_usage_charts(df, pd.DataFrame(), pd.DataFrame(), time_activity)
                
                if 'hourly_activity' in charts:
                    st.plotly_chart(charts['hourly_activity'], use_container_width=True)
                
                if 'daily_activity' in charts:
                    st.plotly_chart(charts['daily_activity'], use_container_width=True)
                
                if not charts:
                    st.info("No time-series data available for analysis.")
    
    # ========== PERFORMANCE ANALYSIS PAGE ==========
    elif page == "⚡ Performance Analysis":
        st.markdown("## ⚡ Performance Analysis")
        
        if st.session_state.cleaned_data is None:
            st.warning("⚠️ Please upload and process data first!")
            st.info("Go to '📤 Upload Data' to get started.")
        else:
            df = st.session_state.cleaned_data
            
            # Get performance statistics
            duration_stats = get_session_duration_stats(df)
            slowest_services = get_slowest_services(df)
            longest_sessions = get_longest_sessions(df)
            
            # Key Metrics
            st.markdown("### ⚡ Performance Metrics")
            
            # Find duration column for stats
            duration_col = None
            for col in df.columns:
                if 'duration' in col.lower() and pd.api.types.is_numeric_dtype(df[col]):
                    duration_col = col
                    break
            
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                avg_duration = df[duration_col].mean() if duration_col else "N/A"
                st.metric("Avg Session Duration", f"{avg_duration:.2f}s" if isinstance(avg_duration, float) else avg_duration)
            with col2:
                max_duration = df[duration_col].max() if duration_col else "N/A"
                st.metric("Max Session Duration", f"{max_duration:.2f}s" if isinstance(max_duration, float) else max_duration)
            with col3:
                min_duration = df[duration_col].min() if duration_col else "N/A"
                st.metric("Min Session Duration", f"{min_duration:.2f}s" if isinstance(min_duration, float) else min_duration)
            with col4:
                std_duration = df[duration_col].std() if duration_col else "N/A"
                st.metric("Std Deviation", f"{std_duration:.2f}s" if isinstance(std_duration, float) else std_duration)
            
            # Performance Charts
            charts = create_performance_charts(df, duration_stats, slowest_services)
            
            # Tabs for different views
            tab1, tab2, tab3 = st.tabs(["📊 Overview", "🐢 Slow Services", "⏱️ Long Sessions"])
            
            with tab1:
                st.markdown("### Session Duration Distribution")
                if 'duration_histogram' in charts:
                    st.plotly_chart(charts['duration_histogram'], use_container_width=True)
                
                if 'duration_by_user' in charts:
                    st.plotly_chart(charts['duration_by_user'], use_container_width=True)
                
                if not charts:
                    st.info("No duration data available for analysis. Ensure your data has a 'duration' column.")
            
            with tab2:
                st.markdown("### Slowest Services")
                if not slowest_services.empty:
                    st.dataframe(
                        slowest_services.style.background_gradient(subset=['Avg_Duration'], cmap='OrRd'),
                        use_container_width=True
                    )
                    
                    if 'slowest_services' in charts:
                        st.plotly_chart(charts['slowest_services'], use_container_width=True)
                else:
                    st.info("No service performance data available.")
            
            with tab3:
                st.markdown("### Longest Sessions")
                if not longest_sessions.empty:
                    st.dataframe(
                        longest_sessions.style.background_gradient(subset=['Duration'], cmap='Purples'),
                        use_container_width=True
                    )
                else:
                    st.info("No session duration data available.")
    
    # ========== REPORTS PAGE ==========
    elif page == "📝 Reports":
        st.markdown("## 📝 Report Generation")
        
        if st.session_state.cleaned_data is None:
            st.warning("⚠️ Please upload and process data first!")
            st.info("Go to '📤 Upload Data' to get started.")
        else:
            df = st.session_state.cleaned_data
            
            st.markdown("Generate comprehensive reports for your log data analysis.")
            
            # Report options
            st.markdown("### 📊 Available Reports")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("""
                <div class="metric-card">
                    <h3 style="color: #00d4ff;">📈 Data Profiling Report</h3>
                    <p style="color: #8892b0;">Comprehensive HTML report with data statistics, 
                    distributions, correlations, and more.</p>
                </div>
                """, unsafe_allow_html=True)
                
                if st.button("🔄 Generate Profiling Report", type="primary"):
                    with st.spinner("Generating report... This may take a moment."):
                        html_report = generate_html_report(df)
                    
                    st.success("✅ Report generated successfully!")
                    
                    # Download button
                    b64 = base64.b64encode(html_report.encode()).decode()
                    href = f'<a href="data:text/html;base64,{b64}" download="log_profiling_report.html" style="color: #00d4ff; text-decoration: none; font-weight: bold;">📥 Download HTML Report</a>'
                    st.markdown(href, unsafe_allow_html=True)
            
            with col2:
                st.markdown("""
                <div class="metric-card">
                    <h3 style="color: #00d4ff;">📋 CSV Summary Reports</h3>
                    <p style="color: #8892b0;">Export analysis results as CSV files for 
                    further processing.</p>
                </div>
                """, unsafe_allow_html=True)
            
            # CSV Reports Section
            st.markdown("### 📋 Export CSV Reports")
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.markdown("#### 🚨 Suspicious Users")
                failed_df = detect_failed_logins(df)
                suspicious_df = identify_suspicious_users(failed_df)
                
                if not suspicious_df.empty:
                    csv = suspicious_df.to_csv(index=False)
                    st.download_button(
                        label="📥 Download Report",
                        data=csv,
                        file_name="suspicious_users_report.csv",
                        mime="text/csv"
                    )
                    st.caption(f"{len(suspicious_df)} suspicious users found")
                else:
                    st.info("No suspicious users to report")
            
            with col2:
                st.markdown("#### 👥 Active Users")
                active_users = get_most_active_users(df, top_n=50)
                
                if not active_users.empty:
                    csv = active_users.to_csv(index=False)
                    st.download_button(
                        label="📥 Download Report",
                        data=csv,
                        file_name="active_users_report.csv",
                        mime="text/csv"
                    )
                    st.caption(f"Top {len(active_users)} active users")
                else:
                    st.info("No user data available")
            
            with col3:
                st.markdown("#### 🐢 Slow Services")
                slow_services = get_slowest_services(df, top_n=50)
                
                if not slow_services.empty:
                    csv = slow_services.to_csv(index=False)
                    st.download_button(
                        label="📥 Download Report",
                        data=csv,
                        file_name="slow_services_report.csv",
                        mime="text/csv"
                    )
                    st.caption(f"{len(slow_services)} services analyzed")
                else:
                    st.info("No service data available")
            
            # Full Data Export
            st.markdown("### 💾 Full Data Export")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("Export the cleaned dataset:")
                csv = df.to_csv(index=False)
                st.download_button(
                    label="📥 Download Cleaned Data (CSV)",
                    data=csv,
                    file_name="cleaned_log_data.csv",
                    mime="text/csv"
                )
            
            with col2:
                st.markdown("Data summary statistics:")
                summary_stats = df.describe(include='all').transpose()
                csv = summary_stats.to_csv()
                st.download_button(
                    label="📥 Download Summary Statistics",
                    data=csv,
                    file_name="data_summary_statistics.csv",
                    mime="text/csv"
                )
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div class="footer">
        <p>🔍 <strong>Log Analyzer Dashboard</strong> | Enterprise Log Analysis Solution</p>
        <p>Built for Security Teams • System Administrators • Data Analysts</p>
    </div>
    """, unsafe_allow_html=True)


# ============================================================================
# ENTRY POINT
# ============================================================================
if __name__ == "__main__":
    main()
