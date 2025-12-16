"""Tests for the suggestions module."""

import pytest

from mcp_launchpad.connection import ToolInfo
from mcp_launchpad.suggestions import (
    find_similar_tools,
    format_tool_suggestions,
    format_validation_error,
    is_tool_not_found_error,
    is_validation_error,
)


class TestIsTooNotFoundError:
    """Tests for is_tool_not_found_error function."""

    def test_basic_tool_not_found(self):
        assert is_tool_not_found_error("Tool not found")
        assert is_tool_not_found_error("tool not found")
        assert is_tool_not_found_error("Tool xyz not found")

    def test_mcp_error_code(self):
        assert is_tool_not_found_error("MCP error -32602: Tool list-all-teams not found")

    def test_not_a_tool_error(self):
        assert not is_tool_not_found_error("Connection failed")
        assert not is_tool_not_found_error("Invalid arguments")
        assert not is_tool_not_found_error("Success")


class TestIsValidationError:
    """Tests for is_validation_error function."""

    def test_validation_error_messages(self):
        assert is_validation_error("Input validation error")
        assert is_validation_error("Invalid arguments for tool")
        assert is_validation_error('{"code": "invalid_type"}')

    def test_required_field_error(self):
        # Must have "required" in the message along with expected/received
        assert is_validation_error('required, expected "string", received "undefined"')

    def test_not_validation_error(self):
        assert not is_validation_error("Tool not found")
        assert not is_validation_error("Connection timeout")
        assert not is_validation_error("Success")


class TestFindSimilarTools:
    """Tests for find_similar_tools function."""

    @pytest.fixture
    def sample_tools(self):
        return [
            ToolInfo(
                server="test",
                name="list_projects",
                description="List all projects",
                input_schema={"required": ["teamId"]},
            ),
            ToolInfo(
                server="test",
                name="get_project",
                description="Get a specific project",
                input_schema={"required": ["projectId"]},
            ),
            ToolInfo(
                server="test",
                name="list_deployments",
                description="List all deployments",
                input_schema={"required": ["projectId"]},
            ),
            ToolInfo(
                server="test",
                name="create_project",
                description="Create a new project",
                input_schema={"required": ["name"]},
            ),
            ToolInfo(
                server="test",
                name="delete_deployment",
                description="Delete a deployment",
                input_schema={"required": ["deploymentId"]},
            ),
        ]

    def test_exact_substring_match(self, sample_tools):
        """Test that tools containing the search term are found."""
        results = find_similar_tools("list", sample_tools)
        names = [t.name for t in results]
        assert "list_projects" in names
        assert "list_deployments" in names

    def test_word_overlap_match(self, sample_tools):
        """Test that tools with overlapping words are found."""
        results = find_similar_tools("list_project", sample_tools)
        names = [t.name for t in results]
        assert "list_projects" in names
        # create_project shares "project"
        assert "create_project" in names or "get_project" in names

    def test_fuzzy_match_typo(self, sample_tools):
        """Test that similar names with typos are found."""
        results = find_similar_tools("list_project", sample_tools)
        names = [t.name for t in results]
        # Should find list_projects even without the 's'
        assert "list_projects" in names

    def test_max_suggestions(self, sample_tools):
        """Test that max_suggestions limits results."""
        results = find_similar_tools("project", sample_tools, max_suggestions=2)
        assert len(results) <= 2

    def test_empty_tools(self):
        """Test with no available tools."""
        results = find_similar_tools("anything", [])
        assert results == []

    def test_no_matches(self, sample_tools):
        """Test with a query that has no matches."""
        results = find_similar_tools("xyznonexistent", sample_tools)
        # May return empty or low-scoring matches
        assert len(results) <= 5


class TestFormatToolSuggestions:
    """Tests for format_tool_suggestions function."""

    @pytest.fixture
    def sample_tools(self):
        return [
            ToolInfo(
                server="vercel",
                name="list_projects",
                description="List all projects",
                input_schema={"required": ["teamId"], "properties": {"teamId": {"type": "string"}}},
            ),
            ToolInfo(
                server="vercel",
                name="get_project",
                description="Get a specific project",
                input_schema={"required": [], "properties": {}},
            ),
        ]

    def test_format_with_suggestions(self, sample_tools):
        result = format_tool_suggestions("list_project", "vercel", sample_tools)
        assert "Tool 'list_project' not found on server 'vercel'" in result
        assert "Similar tools:" in result
        assert "list_projects" in result
        assert "requires: teamId" in result

    def test_format_without_suggestions(self):
        result = format_tool_suggestions("nonexistent", "vercel", [])
        assert "Tool 'nonexistent' not found on server 'vercel'" in result
        assert "mcpl list vercel" in result

    def test_format_shows_required_params(self, sample_tools):
        result = format_tool_suggestions("project", "vercel", sample_tools)
        # Tools with required params should show them
        assert "teamId" in result


class TestFormatValidationError:
    """Tests for format_validation_error function."""

    def test_format_with_tool_info(self):
        tool_info = ToolInfo(
            server="vercel",
            name="list_projects",
            description="List all projects",
            input_schema={
                "required": ["teamId"],
                "properties": {
                    "teamId": {"type": "string"},
                    "limit": {"type": "integer"},
                },
            },
        )
        result = format_validation_error(
            "list_projects",
            "vercel",
            "Missing required parameter",
            tool_info,
        )
        assert "Invalid arguments for tool 'list_projects'" in result
        assert "Required parameters: teamId" in result
        assert "Optional parameters: limit" in result
        assert "mcpl call vercel list_projects" in result

    def test_format_without_tool_info(self):
        result = format_validation_error(
            "list_projects",
            "vercel",
            "MCP error -32602: Invalid arguments",
            None,
        )
        assert "Invalid arguments for tool 'list_projects'" in result
        assert "mcpl inspect vercel list_projects --example" in result


class TestVerifyCommand:
    """Integration tests for verify command would go here."""

    # These would require mocking the MCP servers
    pass
