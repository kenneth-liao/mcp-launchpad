"""Tests for output module."""

import json

import pytest

from mcp_launchpad.output import (
    OutputHandler,
    format_error_json,
    format_json,
    maybe_parse_json,
)


class TestFormatJson:
    """Tests for format_json function."""

    def test_format_success(self):
        """Test formatting successful response."""
        result = format_json({"key": "value"})
        parsed = json.loads(result)
        assert parsed["success"] is True
        assert parsed["data"] == {"key": "value"}

    def test_format_success_with_list(self):
        """Test formatting list data."""
        result = format_json([1, 2, 3])
        parsed = json.loads(result)
        assert parsed["success"] is True
        assert parsed["data"] == [1, 2, 3]

    def test_format_json_parses_json_strings(self):
        """Test that format_json auto-parses JSON strings."""
        data = {"result": '{"teams": [{"name": "Team A"}]}'}
        result = format_json(data)
        parsed = json.loads(result)
        assert parsed["success"] is True
        assert parsed["data"]["result"] == {"teams": [{"name": "Team A"}]}

    def test_format_success_false(self):
        """Test formatting with success=False."""
        error_data = {"success": False, "error": "message"}
        result = format_json(error_data, success=False)
        parsed = json.loads(result)
        assert parsed == error_data


class TestMaybeParseJson:
    """Tests for maybe_parse_json function."""

    def test_simple_json_string(self):
        """Test parsing a simple JSON string."""
        data = '{"key": "value"}'
        result = maybe_parse_json(data)
        assert result == {"key": "value"}

    def test_json_array_string(self):
        """Test parsing a JSON array string."""
        data = '[1, 2, 3]'
        result = maybe_parse_json(data)
        assert result == [1, 2, 3]

    def test_nested_dict_with_json_string(self):
        """Test parsing nested dict with JSON string values."""
        data = {
            "result": '{"teams": [{"name": "Team A"}]}',
            "other": "plain string",
        }
        result = maybe_parse_json(data)
        assert result == {
            "result": {"teams": [{"name": "Team A"}]},
            "other": "plain string",
        }

    def test_list_with_json_string_items(self):
        """Test parsing list with JSON string items."""
        data = ['{"a": 1}', '{"b": 2}']
        result = maybe_parse_json(data)
        assert result == [{"a": 1}, {"b": 2}]

    def test_non_json_string_unchanged(self):
        """Test that non-JSON strings are left untouched."""
        data = "just a regular string"
        result = maybe_parse_json(data)
        assert result == "just a regular string"

    def test_invalid_json_string_unchanged(self):
        """Test that invalid JSON strings are left as strings."""
        data = '{"invalid": json}'
        result = maybe_parse_json(data)
        assert result == '{"invalid": json}'

    def test_already_parsed_object_unchanged(self):
        """Test that already-parsed objects remain unchanged."""
        data = {"key": "value", "nested": {"inner": 123}}
        result = maybe_parse_json(data)
        assert result == data

    def test_json_string_with_whitespace(self):
        """Test parsing JSON string with leading/trailing whitespace."""
        data = '  {"key": "value"}  '
        result = maybe_parse_json(data)
        assert result == {"key": "value"}

    def test_deeply_nested_json_strings(self):
        """Test parsing deeply nested structures with JSON strings."""
        data = {
            "level1": {
                "level2": '{"level3": {"key": "value"}}',
            }
        }
        result = maybe_parse_json(data)
        assert result == {
            "level1": {
                "level2": {"level3": {"key": "value"}},
            }
        }


class TestFormatErrorJson:
    """Tests for format_error_json function."""

    def test_basic_error(self):
        """Test formatting a basic error."""
        error = ValueError("Something went wrong")
        result = format_error_json(error)
        parsed = json.loads(result)

        assert parsed["success"] is False
        assert parsed["error"]["type"] == "ValueError"
        assert parsed["error"]["message"] == "Something went wrong"
        assert "traceback" in parsed["error"]

    def test_error_with_type_override(self):
        """Test formatting error with custom type."""
        error = Exception("Generic error")
        result = format_error_json(error, error_type="CustomError")
        parsed = json.loads(result)

        assert parsed["error"]["type"] == "CustomError"

    def test_error_with_help_text(self):
        """Test formatting error with help text."""
        error = ValueError("Bad value")
        result = format_error_json(error, help_text="Try using a different value")
        parsed = json.loads(result)

        assert parsed["error"]["help"] == "Try using a different value"


class TestOutputHandler:
    """Tests for OutputHandler class."""

    def test_json_mode_flag(self):
        """Test json_mode flag is set correctly."""
        handler_json = OutputHandler(json_mode=True)
        handler_human = OutputHandler(json_mode=False)

        assert handler_json.json_mode is True
        assert handler_human.json_mode is False

    def test_default_human_mode(self):
        """Test default mode is human."""
        handler = OutputHandler()
        assert handler.json_mode is False

    def test_success_json_mode(self, capsys):
        """Test success output in JSON mode."""
        handler = OutputHandler(json_mode=True)
        handler.success({"result": "test"})

        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["success"] is True
        assert parsed["data"]["result"] == "test"

    def test_success_human_mode_with_message(self, capsys):
        """Test success output in human mode with custom message."""
        handler = OutputHandler(json_mode=False)
        handler.success({"data": "value"}, human_message="Operation completed!")

        captured = capsys.readouterr()
        assert "Operation completed!" in captured.out

    def test_success_human_mode_default(self, capsys):
        """Test success output in human mode without custom message."""
        handler = OutputHandler(json_mode=False)
        handler.success({"key": "value"})

        captured = capsys.readouterr()
        # Should output JSON-formatted data
        assert "key" in captured.out
        assert "value" in captured.out

    def test_success_parses_json_strings_json_mode(self, capsys):
        """Test success output parses JSON strings in JSON mode."""
        handler = OutputHandler(json_mode=True)
        handler.success({"result": '{"teams": [{"name": "Team A"}]}'})

        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["success"] is True
        assert parsed["data"]["result"] == {"teams": [{"name": "Team A"}]}

    def test_success_parses_json_strings_human_mode(self, capsys):
        """Test success output parses JSON strings in human mode."""
        handler = OutputHandler(json_mode=False)
        handler.success({"result": '{"teams": [{"name": "Team A"}]}'})

        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        # Should be parsed, not escaped
        assert parsed["result"] == {"teams": [{"name": "Team A"}]}

    def test_error_json_mode(self, capsys):
        """Test error output in JSON mode."""
        handler = OutputHandler(json_mode=True)

        with pytest.raises(SystemExit) as excinfo:
            handler.error(ValueError("Test error"), help_text="Try again")

        assert excinfo.value.code == 1
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["success"] is False
        assert parsed["error"]["message"] == "Test error"

    def test_error_human_mode(self, capsys):
        """Test error output in human mode."""
        handler = OutputHandler(json_mode=False)

        with pytest.raises(SystemExit) as excinfo:
            handler.error(ValueError("Human error"))

        assert excinfo.value.code == 1
        captured = capsys.readouterr()
        assert "Error:" in captured.err
        assert "Human error" in captured.err

    def test_table_json_mode(self, capsys):
        """Test table output in JSON mode."""
        handler = OutputHandler(json_mode=True)
        headers = ["Name", "Status"]
        rows = [["server1", "active"], ["server2", "inactive"]]
        handler.table(headers, rows)

        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["success"] is True
        assert len(parsed["data"]) == 2
        assert parsed["data"][0] == {"Name": "server1", "Status": "active"}

    def test_table_human_mode(self, capsys):
        """Test table output in human mode."""
        handler = OutputHandler(json_mode=False)
        headers = ["Name", "Status"]
        rows = [["server1", "active"], ["server2", "inactive"]]
        handler.table(headers, rows)

        captured = capsys.readouterr()
        assert "Name" in captured.out
        assert "Status" in captured.out
        assert "server1" in captured.out
        assert "server2" in captured.out
