"""
visualizer.py
-------------
Plotly chart generation functions for log analysis dashboards.

All charts use a consistent dark theme and return plotly Figure objects.
Figures can be displayed in Streamlit (st.plotly_chart) or saved as HTML/PNG.

Design decisions:
  - Dark theme: matches server dashboard aesthetics
  - Color coding: green=success, orange=warning, red=error (intuitive)
  - No hardcoded data: all functions accept DataFrames
"""

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# ─── Theme ────────────────────────────────────────────────────────────────────

DARK_THEME = "plotly_dark"

_STATUS_COLOR_MAP = {
    'Success (2xx)':      '#2ecc71',
    'Redirect (3xx)':     '#3498db',
    'Client Error (4xx)': '#f39c12',
    'Server Error (5xx)': '#e74c3c',
}


# ─── Status Distribution ──────────────────────────────────────────────────────

def plot_status_distribution(status_df: pd.DataFrame) -> go.Figure:
    """
    Bar chart of HTTP status code counts, color-coded by category.

    Industry use: SREs set alerting thresholds on 5xx rates.
    A sudden spike here means something broke in production.

    Parameters
    ----------
    status_df : pd.DataFrame
        Output of analyzer.get_status_distribution()
        Columns: status_code, count, category
    """
    fig = px.bar(
        status_df,
        x='status_code',
        y='count',
        color='category',
        color_discrete_map=_STATUS_COLOR_MAP,
        title='HTTP Status Code Distribution',
        labels={'status_code': 'Status Code', 'count': 'Request Count', 'category': 'Category'},
        template=DARK_THEME,
        text='count',
    )
    fig.update_traces(textposition='outside', textfont_size=11)
    fig.update_layout(
        legend_title_text='Status Category',
        xaxis=dict(type='category'),
        plot_bgcolor='rgba(0,0,0,0)',
        margin=dict(t=60, b=40),
    )
    return fig


# ─── Traffic Over Time ────────────────────────────────────────────────────────

def plot_hourly_traffic(hourly_df: pd.DataFrame) -> go.Figure:
    """
    Filled line chart of request volume over time.

    Industry use: Capacity planning, DDoS early detection,
    identifying off-hours anomalies.

    Parameters
    ----------
    hourly_df : pd.DataFrame
        Output of analyzer.get_hourly_traffic()
        Columns: hour_bucket, request_count
    """
    fig = go.Figure()

    fig.add_trace(go.Scatter(
        x=hourly_df['hour_bucket'],
        y=hourly_df['request_count'],
        mode='lines',
        fill='tozeroy',
        fillcolor='rgba(52, 152, 219, 0.15)',
        line=dict(color='#3498db', width=2),
        name='Requests',
        hovertemplate='%{x}<br>Requests: %{y:,}<extra></extra>',
    ))

    fig.update_layout(
        title='Request Volume Over Time',
        xaxis_title='Time',
        yaxis_title='Requests per Hour',
        template=DARK_THEME,
        hovermode='x unified',
        margin=dict(t=60, b=40),
        plot_bgcolor='rgba(0,0,0,0)',
    )
    return fig


# ─── Top IP Addresses ─────────────────────────────────────────────────────────

def plot_top_ips(ip_df: pd.DataFrame) -> go.Figure:
    """
    Horizontal bar chart of top IPs by request count.
    Color intensity maps to error rate — redder = higher error rate.

    Industry use: Identifies candidates for IP rate-limiting or blocking.

    Parameters
    ----------
    ip_df : pd.DataFrame
        Output of analyzer.get_top_ips()
        Columns: ip, total_requests, error_requests, error_rate
    """
    fig = px.bar(
        ip_df.sort_values('total_requests'),
        x='total_requests',
        y='ip',
        orientation='h',
        color='error_rate',
        color_continuous_scale='RdYlGn_r',
        title='Top IP Addresses by Request Volume',
        labels={
            'total_requests': 'Total Requests',
            'ip': 'IP Address',
            'error_rate': 'Error Rate'
        },
        template=DARK_THEME,
        text='total_requests',
        hover_data=['error_requests', 'bot_requests'],
    )
    fig.update_traces(textposition='outside')
    fig.update_layout(
        coloraxis_colorbar=dict(title='Error Rate'),
        margin=dict(t=60, b=40, l=140),
        plot_bgcolor='rgba(0,0,0,0)',
    )
    return fig


# ─── Error Rate Heatmap ───────────────────────────────────────────────────────

def plot_error_heatmap(df: pd.DataFrame) -> go.Figure:
    """
    Heatmap of error rate indexed by (day of week × hour of day).

    Industry use: Reveals WHEN errors spike — often tied to deployments,
    batch jobs, or bot activity at specific hours.

    Parameters
    ----------
    df : pd.DataFrame
        Feature-engineered log DataFrame (requires is_error, hour, day_of_week).
    """
    day_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']

    pivot = df.pivot_table(
        values='is_error',
        index='day_of_week',
        columns='hour',
        aggfunc='mean',
    ).fillna(0)

    # Reorder rows by weekday
    pivot = pivot.reindex([d for d in day_order if d in pivot.index])

    fig = px.imshow(
        pivot,
        title='Error Rate Heatmap — Day × Hour of Day',
        labels=dict(x='Hour of Day', y='Day of Week', color='Error Rate'),
        color_continuous_scale='RdYlGn_r',
        template=DARK_THEME,
        aspect='auto',
        zmin=0, zmax=1,
    )
    fig.update_layout(
        margin=dict(t=60, b=40),
        xaxis=dict(dtick=1),
    )
    return fig


# ─── Anomaly Detection ────────────────────────────────────────────────────────

def plot_anomalies(anomaly_df: pd.DataFrame, hourly_df: pd.DataFrame) -> go.Figure:
    """
    Overlay detected anomalous IPs on the traffic timeline as scatter markers.

    Parameters
    ----------
    anomaly_df : pd.DataFrame
        Output of analyzer.detect_traffic_anomalies()
    hourly_df : pd.DataFrame
        Output of analyzer.get_hourly_traffic()
    """
    fig = plot_hourly_traffic(hourly_df)

    if anomaly_df.empty:
        return fig

    # Build timestamp for each anomaly (date + hour → datetime)
    anomaly_df = anomaly_df.copy()
    anomaly_df['ts'] = pd.to_datetime(
        anomaly_df['date'].astype(str) + ' ' + anomaly_df['hour'].astype(str) + ':00:00'
    )

    fig.add_trace(go.Scatter(
        x=anomaly_df['ts'],
        y=anomaly_df['request_count'],
        mode='markers',
        marker=dict(color='#e74c3c', size=12, symbol='x', line=dict(width=2)),
        name='Anomaly Detected',
        hovertemplate=(
            'IP: %{customdata[0]}<br>'
            'Requests: %{y}<br>'
            'Z-Score: %{customdata[1]:.2f}<extra></extra>'
        ),
        customdata=anomaly_df[['ip', 'z_score']].values,
    ))

    return fig


# ─── 404 Paths ────────────────────────────────────────────────────────────────

def plot_top_404_paths(paths_df: pd.DataFrame) -> go.Figure:
    """
    Horizontal bar chart of paths most frequently returning 404.

    Industry use: High 404 counts on sequential paths (e.g., /admin/1, /admin/2)
    = directory scanner or vulnerability probe in progress.
    """
    fig = px.bar(
        paths_df.sort_values('count'),
        x='count',
        y='path',
        orientation='h',
        title='Top 404 Paths — Scanner / Broken Link Detection',
        labels={'count': '404 Count', 'path': 'Request Path'},
        template=DARK_THEME,
        color='count',
        color_continuous_scale='Reds',
        text='count',
    )
    fig.update_traces(textposition='outside')
    fig.update_layout(
        margin=dict(t=60, b=40, l=260),
        plot_bgcolor='rgba(0,0,0,0)',
        showlegend=False,
    )
    return fig


# ─── Bot vs Human Traffic ─────────────────────────────────────────────────────

def plot_bot_vs_human(df: pd.DataFrame) -> go.Figure:
    """
    Donut chart showing bot vs human traffic split.

    Industry use: High bot traffic inflates raw metric counts.
    Knowing the split is critical for accurate capacity planning.
    """
    counts = df['is_bot'].value_counts()
    labels = ['Human Traffic', 'Bot Traffic']
    values = [counts.get(False, 0), counts.get(True, 0)]
    colors = ['#2ecc71', '#e74c3c']

    fig = go.Figure(data=[go.Pie(
        labels=labels,
        values=values,
        hole=0.55,
        marker=dict(colors=colors, line=dict(color='#1a1a2e', width=2)),
        textinfo='label+percent',
        hovertemplate='%{label}: %{value:,} requests (%{percent})<extra></extra>',
    )])

    fig.update_layout(
        title='Bot vs Human Traffic Distribution',
        template=DARK_THEME,
        margin=dict(t=60, b=40),
        showlegend=True,
    )
    return fig


# ─── Brute Force Timeline ─────────────────────────────────────────────────────

def plot_brute_force_timeline(df: pd.DataFrame) -> go.Figure:
    """
    Stacked bar chart of 401/403 responses over time, grouped by IP.
    Shows when brute-force bursts occurred.

    Parameters
    ----------
    df : pd.DataFrame
        Full feature-engineered log DataFrame.
    """
    auth_fail = df[df['status'].isin([401, 403])].copy()
    if auth_fail.empty:
        return go.Figure().update_layout(
            title='No Authentication Failures Detected',
            template=DARK_THEME
        )

    auth_fail['hour_bucket'] = auth_fail['timestamp'].dt.floor('h')

    hourly_fail = (
        auth_fail.groupby(['hour_bucket', 'ip'])
        .size()
        .reset_index(name='failures')
    )

    # Only show top 5 offending IPs for readability
    top_ips = auth_fail['ip'].value_counts().head(5).index.tolist()
    hourly_fail = hourly_fail[hourly_fail['ip'].isin(top_ips)]

    fig = px.bar(
        hourly_fail,
        x='hour_bucket',
        y='failures',
        color='ip',
        title='Authentication Failures Over Time (Top 5 IPs)',
        labels={'hour_bucket': 'Time', 'failures': 'Failed Auth Requests', 'ip': 'IP Address'},
        template=DARK_THEME,
        barmode='stack',
    )
    fig.update_layout(margin=dict(t=60, b=40))
    return fig
