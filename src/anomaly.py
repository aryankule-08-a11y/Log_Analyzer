"""
anomaly.py
----------
ML-based anomaly detection using Isolation Forest.

Detects anomalous IPs based on multi-dimensional behavioral features:
  - Request volume
  - Error rate
  - Bot traffic signature
  - Path diversity (scanning behaviour)
  - Bytes transferred
"""

import logging
import pandas as pd
import numpy as np

logger = logging.getLogger(__name__)

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logger.warning(
        "scikit-learn not installed. ML anomaly detection disabled. "
        "Run: pip install scikit-learn"
    )


# ─── Feature Extraction ───────────────────────────────────────────────────────

def build_ip_feature_matrix(df: pd.DataFrame) -> pd.DataFrame:
    """
    Aggregate per-IP behavioral features used as input for the anomaly model.

    Features:
      total_requests  — volume indicator
      error_rate      — proportion of 4xx/5xx responses
      avg_bytes       — average response size
      bot_rate        — proportion of bot user-agents
      unique_paths    — number of distinct endpoints accessed
      status_std      — variance in status codes (variety = scanning signal)
      p95_request_gap — 95th percentile gap between consecutive requests (bursts)
    """
    # Per-IP time-gap between consecutive requests (burst detection)
    sorted_df = df.sort_values(['ip', 'timestamp'])
    sorted_df['request_gap_sec'] = (
        sorted_df.groupby('ip')['timestamp']
        .diff()
        .dt.total_seconds()
    )

    ip_features = df.groupby('ip').agg(
        total_requests  = ('ip',              'count'),
        error_rate      = ('is_error',        'mean'),
        avg_bytes       = ('bytes',           'mean'),
        bot_rate        = ('is_bot',          'mean'),
        unique_paths    = ('path',            'nunique'),
        status_std      = ('status',          'std'),
    ).reset_index()

    # 95th percentile request gap per IP
    gap_p95 = (
        sorted_df.groupby('ip')['request_gap_sec']
        .quantile(0.95)
        .reset_index()
        .rename(columns={'request_gap_sec': 'p95_request_gap'})
    )

    ip_features = ip_features.merge(gap_p95, on='ip', how='left')
    ip_features = ip_features.fillna(0)

    return ip_features


# ─── Isolation Forest ─────────────────────────────────────────────────────────

FEATURE_COLS = [
    'total_requests', 'error_rate', 'avg_bytes',
    'bot_rate', 'unique_paths', 'status_std', 'p95_request_gap'
]


def run_isolation_forest(
    df: pd.DataFrame,
    contamination: float = 0.05,
    n_estimators: int = 200
) -> pd.DataFrame:
    """
    Detect anomalous IPs using Isolation Forest.

    Isolation Forest works on the principle that anomalies are easier to
    "isolate" in feature space — they require fewer splits in random trees.
    Anomaly score of -1 = outlier, 1 = normal.

    Parameters
    ----------
    contamination : float
        Expected proportion of anomalies in the dataset.
        0.05 = we expect ~5% of IPs to be anomalous.
    n_estimators : int
        Number of trees. Higher = more stable results. Default 200.

    Returns
    -------
    pd.DataFrame
        IP-level feature matrix with 'anomaly_score' (-1 or 1)
        and 'is_anomaly' boolean column.
    """
    if not SKLEARN_AVAILABLE:
        logger.error("scikit-learn required for Isolation Forest. Skipping.")
        return pd.DataFrame()

    if len(df) < 10:
        logger.warning("Too few rows (%d) for Isolation Forest. Need ≥10.", len(df))
        return pd.DataFrame()

    ip_features = build_ip_feature_matrix(df)
    X = ip_features[FEATURE_COLS].values

    # Standardize: Isolation Forest is sensitive to scale differences
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=42,
        n_jobs=-1
    )

    ip_features['raw_score']     = model.fit_predict(X_scaled)
    ip_features['decision_score'] = model.decision_function(X_scaled).round(4)
    ip_features['is_anomaly']    = ip_features['raw_score'] == -1

    n_flagged = ip_features['is_anomaly'].sum()
    logger.info(
        "Isolation Forest: flagged %d / %d IPs as anomalous (%.1f%%)",
        n_flagged, len(ip_features),
        n_flagged / len(ip_features) * 100 if len(ip_features) else 0
    )

    return (
        ip_features
        .sort_values(['is_anomaly', 'decision_score'], ascending=[False, True])
        .reset_index(drop=True)
    )


# ─── IQR-based outlier (fallback, no sklearn) ─────────────────────────────────

def detect_iqr_outliers(df: pd.DataFrame, column: str = 'total_requests') -> pd.DataFrame:
    """
    Simple IQR-based outlier detection as a fallback when sklearn is not available.

    Any IP with request count > Q3 + 1.5 * IQR is flagged.

    Used in:
      - Environments where scikit-learn is not installed
      - As a quick pre-filter before running the full model
    """
    ip_counts = df.groupby('ip').size().reset_index(name=column)
    q1 = ip_counts[column].quantile(0.25)
    q3 = ip_counts[column].quantile(0.75)
    iqr = q3 - q1
    upper_fence = q3 + 1.5 * iqr

    outliers = ip_counts[ip_counts[column] > upper_fence].copy()
    outliers['upper_fence'] = round(upper_fence, 2)
    outliers['excess'] = (outliers[column] - upper_fence).round(2)

    logger.info(
        "IQR outliers (Q3+1.5*IQR=%.1f): flagged %d IPs",
        upper_fence, len(outliers)
    )
    return outliers.sort_values(column, ascending=False).reset_index(drop=True)
