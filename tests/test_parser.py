"""
test_parser.py
--------------
Unit tests for src/parser.py

Run with: pytest tests/ -v
"""

import io
import pytest
import pandas as pd
from pathlib import Path
from unittest.mock import patch, mock_open

# We test the core regex and column-casting logic directly
from src.parser import APACHE_LOG_PATTERN, _cast_columns, parse_log_file


# ─── Sample Log Lines ─────────────────────────────────────────────────────────

VALID_LINE = (
    '192.168.1.1 - frank [10/Oct/2000:13:55:36 -0700] '
    '"GET /apache_pb.gif HTTP/1.0" 200 2326 '
    '"http://www.example.com/start.html" "Mozilla/5.0 (Windows NT 10.0)"'
)

VALID_LINE_NO_REFERRER = (
    '10.0.0.55 - - [15/Jan/2024:08:19:33 +0000] '
    '"POST /api/login HTTP/1.1" 401 0'
)

MALFORMED_LINE = "this is not a log line at all"
EMPTY_LINE = ""


# ─── Regex Matching Tests ─────────────────────────────────────────────────────

class TestRegexPattern:

    def test_matches_full_combined_log(self):
        m = APACHE_LOG_PATTERN.match(VALID_LINE)
        assert m is not None, "Full Combined Log line should match"

    def test_extracts_ip(self):
        m = APACHE_LOG_PATTERN.match(VALID_LINE)
        assert m.group('ip') == '192.168.1.1'

    def test_extracts_method(self):
        m = APACHE_LOG_PATTERN.match(VALID_LINE)
        assert m.group('method') == 'GET'

    def test_extracts_path(self):
        m = APACHE_LOG_PATTERN.match(VALID_LINE)
        assert m.group('path') == '/apache_pb.gif'

    def test_extracts_status(self):
        m = APACHE_LOG_PATTERN.match(VALID_LINE)
        assert m.group('status') == '200'

    def test_extracts_bytes(self):
        m = APACHE_LOG_PATTERN.match(VALID_LINE)
        assert m.group('bytes') == '2326'

    def test_extracts_user_agent(self):
        m = APACHE_LOG_PATTERN.match(VALID_LINE)
        assert 'Mozilla' in m.group('user_agent')

    def test_matches_minimal_line_no_referrer(self):
        m = APACHE_LOG_PATTERN.match(VALID_LINE_NO_REFERRER)
        assert m is not None

    def test_does_not_match_malformed_line(self):
        m = APACHE_LOG_PATTERN.match(MALFORMED_LINE)
        assert m is None

    def test_captures_401_status(self):
        m = APACHE_LOG_PATTERN.match(VALID_LINE_NO_REFERRER)
        assert m.group('status') == '401'

    def test_captures_dash_bytes_as_dash(self):
        line = (
            '192.168.1.2 - - [10/Oct/2000:13:55:36 -0700] '
            '"GET /missing.html HTTP/1.0" 404 -'
        )
        m = APACHE_LOG_PATTERN.match(line)
        assert m is not None
        assert m.group('bytes') == '-'


# ─── Column Casting Tests ─────────────────────────────────────────────────────

class TestCastColumns:

    def _make_raw_df(self):
        """Create a minimal raw DataFrame as if returned from regex matching."""
        return pd.DataFrame([{
            'ip': '192.168.1.1',
            'user': 'frank',
            'timestamp': '10/Oct/2000:13:55:36 -0700',
            'method': 'GET',
            'path': '/index.html',
            'protocol': 'HTTP/1.0',
            'status': '200',
            'bytes': '1024',
            'referrer': '-',
            'user_agent': 'Mozilla/5.0',
        }])

    def test_status_cast_to_int(self):
        df = _cast_columns(self._make_raw_df())
        assert pd.api.types.is_integer_dtype(df['status'])

    def test_bytes_cast_to_int(self):
        df = _cast_columns(self._make_raw_df())
        assert pd.api.types.is_integer_dtype(df['bytes'])

    def test_dash_bytes_becomes_zero(self):
        raw = self._make_raw_df()
        raw['bytes'] = '-'
        df = _cast_columns(raw)
        assert df['bytes'].iloc[0] == 0

    def test_timestamp_is_datetime(self):
        df = _cast_columns(self._make_raw_df())
        assert pd.api.types.is_datetime64_any_dtype(df['timestamp'])

    def test_timestamp_is_utc_aware(self):
        df = _cast_columns(self._make_raw_df())
        assert df['timestamp'].dt.tz is not None

    def test_bad_timestamp_row_dropped(self):
        raw = self._make_raw_df()
        bad_row = raw.copy()
        bad_row['timestamp'] = 'not-a-timestamp'
        combined = pd.concat([raw, bad_row], ignore_index=True)
        result = _cast_columns(combined)
        assert len(result) == 1, "Row with bad timestamp should be dropped"


# ─── File Not Found ───────────────────────────────────────────────────────────

class TestParseLogFile:

    def test_raises_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            parse_log_file("/nonexistent/path/access.log")

    def test_raises_value_error_on_empty_valid_file(self, tmp_path):
        empty_log = tmp_path / "empty.log"
        empty_log.write_text("this is not a log line\n" * 5)
        with pytest.raises(ValueError, match="No valid Apache log lines found"):
            parse_log_file(empty_log)

    def test_parses_valid_log_file(self, tmp_path):
        log_file = tmp_path / "test.log"
        log_file.write_text(VALID_LINE + "\n" + VALID_LINE_NO_REFERRER + "\n")
        df = parse_log_file(log_file)
        assert len(df) == 2
        assert 'ip' in df.columns
        assert 'status' in df.columns
        assert 'timestamp' in df.columns

    def test_output_has_expected_columns(self, tmp_path):
        log_file = tmp_path / "test.log"
        log_file.write_text(VALID_LINE + "\n")
        df = parse_log_file(log_file)
        expected_cols = {'ip', 'user', 'timestamp', 'method', 'path', 'status', 'bytes'}
        assert expected_cols.issubset(set(df.columns))
