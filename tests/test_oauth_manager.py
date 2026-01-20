"""Tests for OAuth manager module."""

from datetime import datetime, timedelta, timezone

import pytest

from mcp_launchpad.oauth.manager import _format_timedelta, _format_time_ago


class TestFormatTimedelta:
    """Tests for _format_timedelta function."""

    def test_negative_timedelta_returns_expired(self) -> None:
        """Test that negative timedeltas return 'Expired'."""
        td = timedelta(seconds=-1)
        assert _format_timedelta(td) == "Expired"

        td = timedelta(days=-1)
        assert _format_timedelta(td) == "Expired"

    def test_zero_seconds(self) -> None:
        """Test formatting of 0 seconds."""
        td = timedelta(seconds=0)
        assert _format_timedelta(td) == "0 seconds"

    def test_seconds_range(self) -> None:
        """Test formatting of seconds (1-59)."""
        assert _format_timedelta(timedelta(seconds=1)) == "1 seconds"
        assert _format_timedelta(timedelta(seconds=30)) == "30 seconds"
        assert _format_timedelta(timedelta(seconds=59)) == "59 seconds"

    def test_one_minute_singular(self) -> None:
        """Test singular form for 1 minute."""
        td = timedelta(minutes=1)
        assert _format_timedelta(td) == "1 minute"

    def test_minutes_plural(self) -> None:
        """Test plural form for multiple minutes."""
        assert _format_timedelta(timedelta(minutes=2)) == "2 minutes"
        assert _format_timedelta(timedelta(minutes=30)) == "30 minutes"
        assert _format_timedelta(timedelta(minutes=59)) == "59 minutes"

    def test_one_hour_singular(self) -> None:
        """Test singular form for 1 hour."""
        td = timedelta(hours=1)
        assert _format_timedelta(td) == "1 hour"

    def test_hours_plural(self) -> None:
        """Test plural form for multiple hours."""
        assert _format_timedelta(timedelta(hours=2)) == "2 hours"
        assert _format_timedelta(timedelta(hours=12)) == "12 hours"
        assert _format_timedelta(timedelta(hours=23)) == "23 hours"

    def test_one_day_singular(self) -> None:
        """Test singular form for 1 day."""
        td = timedelta(days=1)
        assert _format_timedelta(td) == "1 day"

    def test_days_plural(self) -> None:
        """Test plural form for multiple days (up to 13)."""
        assert _format_timedelta(timedelta(days=2)) == "2 days"
        assert _format_timedelta(timedelta(days=7)) == "7 days"
        assert _format_timedelta(timedelta(days=13)) == "13 days"

    def test_weeks_threshold(self) -> None:
        """Test that 14+ days converts to weeks."""
        assert _format_timedelta(timedelta(days=14)) == "2 weeks"
        assert _format_timedelta(timedelta(days=21)) == "3 weeks"

    def test_one_week_singular(self) -> None:
        """Test singular form would apply for 1 week (7-13 days show as days)."""
        # Note: 7-13 days show as days, not weeks
        # 14 days = 2 weeks (plural)
        # So singular "week" requires exactly 7 days to round down to 1 week
        # But 7 days is < 14, so it shows as "7 days"
        # First week display is at 14 days = 2 weeks
        pass  # Covered by days_plural test

    def test_boundary_between_units(self) -> None:
        """Test boundaries between time units."""
        # 59 seconds -> seconds
        assert _format_timedelta(timedelta(seconds=59)) == "59 seconds"
        # 60 seconds -> 1 minute
        assert _format_timedelta(timedelta(seconds=60)) == "1 minute"

        # 59 minutes -> minutes
        assert _format_timedelta(timedelta(minutes=59)) == "59 minutes"
        # 60 minutes -> 1 hour
        assert _format_timedelta(timedelta(minutes=60)) == "1 hour"

        # 23 hours -> hours
        assert _format_timedelta(timedelta(hours=23)) == "23 hours"
        # 24 hours -> 1 day
        assert _format_timedelta(timedelta(hours=24)) == "1 day"


class TestFormatTimeAgo:
    """Tests for _format_time_ago function."""

    def test_formats_as_time_ago(self) -> None:
        """Test that result includes 'ago' suffix."""
        now = datetime.now(timezone.utc)
        past = now - timedelta(minutes=5)
        result = _format_time_ago(past)
        assert result.endswith(" ago")

    def test_timezone_aware_datetime(self) -> None:
        """Test with timezone-aware datetime."""
        now = datetime.now(timezone.utc)
        past = now - timedelta(hours=2)
        result = _format_time_ago(past)
        assert "2 hours ago" == result

    def test_timezone_naive_datetime_assumed_utc(self) -> None:
        """Test that timezone-naive datetime is assumed to be UTC."""
        now = datetime.now(timezone.utc)
        # Create naive datetime that would be 1 hour ago if interpreted as UTC
        past_naive = (now - timedelta(hours=1)).replace(tzinfo=None)
        result = _format_time_ago(past_naive)
        assert "1 hour ago" == result

    def test_recent_time(self) -> None:
        """Test formatting of very recent times."""
        now = datetime.now(timezone.utc)
        past = now - timedelta(seconds=30)
        result = _format_time_ago(past)
        assert "seconds ago" in result

    def test_minutes_ago(self) -> None:
        """Test formatting of minutes ago."""
        now = datetime.now(timezone.utc)
        past = now - timedelta(minutes=45)
        result = _format_time_ago(past)
        assert "45 minutes ago" == result

    def test_hours_ago(self) -> None:
        """Test formatting of hours ago."""
        now = datetime.now(timezone.utc)
        past = now - timedelta(hours=5)
        result = _format_time_ago(past)
        assert "5 hours ago" == result

    def test_days_ago(self) -> None:
        """Test formatting of days ago."""
        now = datetime.now(timezone.utc)
        past = now - timedelta(days=3)
        result = _format_time_ago(past)
        assert "3 days ago" == result
