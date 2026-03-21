"""
test_analyzer.py
----------------
Unit tests for src/analyzer.py

Run with: pytest tests/ -v
"""

import pytest
import pandas as pd
import numpy as np
from datetime import datetime, timezone, timedelta

from src.analyzer import (
    add_features,
    get_status_distribution,
    get_error_summary,
    get_hourly_traffic,
    get_top_ips,
    detect_traffic_anomalies,
    detect_brute_force,
    get_top_404_paths,
    get_summary_stats,
)


# ─── Fixtures ─────────────────────────────────────────────────────────────────

def _make_log_df(rows: list[dict]) -> pd.DataFrame:
    """Build a minimal parsed log DataFrame from a list of row dicts."""
    base_ts = datetime(2024, 1, 15, 8, 0, 0, tzinfo=timezone.utc)
    defaults = {
        'ip': '192.168.1.1',
        'user': None,
        'method': 'GET',
        'path': '/index.html',
        'protocol': 'HTTP/1.1',
        'status': 200,
        'bytes': 1024,
        'referrer': None,
        'user_agent': 'Mozilla/5.0',
    }
    records = []
    for i, row in enumerate(rows):
        r = {**defaults, **row}
        if 'timestamp' not in r:
            r['timestamp'] = pd.Timestamp(base_ts + timedelta(seconds=i * 30), tz='UTC')
        else:
            r['timestamp'] = pd.Timestamp(r['timestamp'], tz='UTC')
        records.append(r)

    df = pd.DataFrame(records)
    df['status'] = df['status'].astype('Int16')
    df['bytes']  = df['bytes'].astype('int64')
    return df


@pytest.fixture
def sample_df():
    """Mixed traffic: successes, errors, bots, and a suspicious IP."""
    return _make_log_df([
        {'ip': '10.0.0.1', 'status': 200},
        {'ip': '10.0.0.1', 'status': 200},
        {'ip': '10.0.0.2', 'status': 404},
        {'ip': '10.0.0.2', 'status': 500},
        {'ip': '10.0.0.3', 'status': 200, 'user_agent': 'Googlebot/2.1'},
        {'ip': '10.0.0.3', 'status': 200, 'user_agent': 'python-requests/2.28'},
        {'ip': '45.33.12.1', 'status': 401},
        {'ip': '45.33.12.1', 'status': 401},
        {'ip': '45.33.12.1', 'status': 401},
    ])


# ─── add_features ─────────────────────────────────────────────────────────────

class TestAddFeatures:

    def test_adds_hour_column(self, sample_df):
        df = add_features(sample_df)
        assert 'hour' in df.columns

    def test_adds_is_error_column(self, sample_df):
        df = add_features(sample_df)
        assert 'is_error' in df.columns

    def test_404_is_error(self, sample_df):
        df = add_features(sample_df)
        assert df[df['status'] == 404]['is_error'].all()

    def test_200_is_not_error(self, sample_df):
        df = add_features(sample_df)
        assert not df[df['status'] == 200]['is_error'].any()

    def test_bot_detection_googlebot(self, sample_df):
        df = add_features(sample_df)
        bot_rows = df[df['user_agent'].str.contains('Googlebot', na=False)]
        assert bot_rows['is_bot'].all()

    def test_bot_detection_python_requests(self, sample_df):
        df = add_features(sample_df)
        bot_rows = df[df['user_agent'].str.contains('python-requests', na=False)]
        assert bot_rows['is_bot'].all()

    def test_human_not_flagged_as_bot(self, sample_df):
        df = add_features(sample_df)
        human_rows = df[df['user_agent'] == 'Mozilla/5.0']
        assert not human_rows['is_bot'].any()

    def test_500_is_server_error(self, sample_df):
        df = add_features(sample_df)
        assert df[df['status'] == 500]['is_server_error'].all()

    def test_does_not_modify_original(self, sample_df):
        original_cols = list(sample_df.columns)
        _ = add_features(sample_df)
        assert list(sample_df.columns) == original_cols


# ─── get_status_distribution ──────────────────────────────────────────────────

class TestStatusDistribution:

    def test_returns_dataframe(self, sample_df):
        df = add_features(sample_df)
        result = get_status_distribution(df)
        assert isinstance(result, pd.DataFrame)

    def test_has_expected_columns(self, sample_df):
        df = add_features(sample_df)
        result = get_status_distribution(df)
        assert {'status_code', 'count', 'category'}.issubset(set(result.columns))

    def test_status_200_present(self, sample_df):
        df = add_features(sample_df)
        result = get_status_distribution(df)
        assert 200 in result['status_code'].values

    def test_category_server_error_for_500(self, sample_df):
        df = add_features(sample_df)
        result = get_status_distribution(df)
        row_500 = result[result['status_code'] == 500]
        if not row_500.empty:
            assert row_500['category'].iloc[0] == 'Server Error (5xx)'


# ─── detect_traffic_anomalies ─────────────────────────────────────────────────

class TestDetectTrafficAnomalies:

    def test_returns_dataframe(self, sample_df):
        df = add_features(sample_df)
        result = detect_traffic_anomalies(df)
        assert isinstance(result, pd.DataFrame)

    def test_anomaly_on_high_volume_ip(self):
        """IP with 100 requests in one hour while others have 1 should be flagged."""
        base = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        rows = [{'ip': 'normal.ip', 'timestamp': base + timedelta(minutes=i)} for i in range(5)]
        rows += [
            {'ip': 'attacker.ip', 'timestamp': base + timedelta(seconds=i)}
            for i in range(100)
        ]
        df = _make_log_df(rows)
        df = add_features(df)
        anomalies = detect_traffic_anomalies(df, z_threshold=2.0)
        assert 'attacker.ip' in anomalies['ip'].values

    def test_z_score_column_present(self, sample_df):
        df = add_features(sample_df)
        result = detect_traffic_anomalies(df, z_threshold=0.0)
        if not result.empty:
            assert 'z_score' in result.columns

    def test_empty_df_returns_empty(self):
        empty = pd.DataFrame()
        result = detect_traffic_anomalies(empty)
        assert result.empty


# ─── detect_brute_force ───────────────────────────────────────────────────────

class TestDetectBruteForce:

    def test_detects_rapid_401s(self):
        """30 failed logins in < 5 minutes from one IP should be flagged."""
        base = datetime(2024, 1, 15, 8, 0, 0, tzinfo=timezone.utc)
        rows = [
            {
                'ip': 'brute.force.ip',
                'status': 401,
                'path': '/login',
                'timestamp': base + timedelta(seconds=i * 5)
            }
            for i in range(30)
        ]
        # add a normal IP
        rows.append({'ip': '192.168.1.1', 'status': 200, 'timestamp': base})

        df = _make_log_df(rows)
        df = add_features(df)
        result = detect_brute_force(df, window_minutes=5, threshold=20)

        assert len(result) >= 1
        assert 'brute.force.ip' in result['ip'].values

    def test_no_401s_returns_empty(self, sample_df):
        # Remove all 401 rows
        clean_df = sample_df[sample_df['status'] != 401].copy()
        clean_df = add_features(clean_df)
        result = detect_brute_force(clean_df, window_minutes=5, threshold=5)
        assert result.empty

    def test_normal_ip_not_flagged(self):
        """An IP with only 2 failures should not be flagged."""
        base = datetime(2024, 1, 15, 8, 0, 0, tzinfo=timezone.utc)
        rows = [
            {'ip': '192.168.1.1', 'status': 401, 'timestamp': base},
            {'ip': '192.168.1.1', 'status': 401, 'timestamp': base + timedelta(minutes=1)},
            {'ip': '192.168.1.1', 'status': 200, 'timestamp': base + timedelta(minutes=2)},
        ]
        df = _make_log_df(rows)
        df = add_features(df)
        result = detect_brute_force(df, window_minutes=5, threshold=10)
        assert '192.168.1.1' not in result.get('ip', pd.Series()).values


# ─── get_summary_stats ────────────────────────────────────────────────────────

class TestGetSummaryStats:

    def test_returns_dict(self, sample_df):
        df = add_features(sample_df)
        stats = get_summary_stats(df)
        assert isinstance(stats, dict)

    def test_total_requests_matches_df_length(self, sample_df):
        df = add_features(sample_df)
        stats = get_summary_stats(df)
        assert stats['total_requests'] == len(df)

    def test_all_expected_keys_present(self, sample_df):
        df = add_features(sample_df)
        stats = get_summary_stats(df)
        expected = {
            'total_requests', 'unique_ips', 'error_rate',
            'bot_traffic_pct', 'total_bytes_gb', 'server_errors'
        }
        assert expected.issubset(stats.keys())
