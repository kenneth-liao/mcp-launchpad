"""Tests for search module."""

import pytest

from mcp_launchpad.connection import ToolInfo
from mcp_launchpad.search import (
    SearchMethod,
    SearchResult,
    ToolSearcher,
    build_search_text,
    tokenize,
)


class TestTokenize:
    """Tests for tokenize function."""

    def test_basic_tokenization(self):
        """Test basic text tokenization."""
        tokens = tokenize("hello world")
        assert tokens == ["hello", "world"]

    def test_case_insensitive(self):
        """Test tokenization is case-insensitive."""
        tokens = tokenize("Hello WORLD")
        assert tokens == ["hello", "world"]

    def test_split_on_underscores(self):
        """Test splitting on underscores."""
        tokens = tokenize("create_issue")
        assert tokens == ["create", "issue"]

    def test_split_on_hyphens(self):
        """Test splitting on hyphens."""
        tokens = tokenize("mcp-server-github")
        assert tokens == ["mcp", "server", "github"]

    def test_mixed_delimiters(self):
        """Test splitting on mixed delimiters."""
        tokens = tokenize("create_new-issue here")
        assert tokens == ["create", "new", "issue", "here"]

    def test_empty_string(self):
        """Test tokenizing empty string."""
        tokens = tokenize("")
        assert tokens == []

    def test_only_delimiters(self):
        """Test tokenizing string with only delimiters."""
        tokens = tokenize("_-_ -_-")
        assert tokens == []

    def test_numbers(self):
        """Test tokenizing with numbers."""
        tokens = tokenize("issue123 v2 test")
        assert tokens == ["issue123", "v2", "test"]

    def test_non_ascii_letters_are_kept(self):
        """Non-ASCII words must not be cut apart at accented or non-Latin letters."""
        assert tokenize("Créer un problème") == ["créer", "un", "problème"]
        assert tokenize("получить данные") == ["получить", "данные"]
        assert tokenize("搜索 工具") == ["搜索", "工具"]


class TestBuildSearchText:
    """Tests for build_search_text function."""

    def test_builds_searchable_text(self, sample_tools: list[ToolInfo]):
        """Test building searchable text from tool."""
        tool = sample_tools[0]  # github/create_issue
        text = build_search_text(tool)
        assert "github" in text
        assert "create_issue" in text
        assert "issue" in text.lower()

    def test_includes_all_parts(self):
        """Test all parts are included in search text."""
        tool = ToolInfo(
            server="my-server",
            name="my_tool",
            description="This is a description",
            input_schema={},
        )
        text = build_search_text(tool)
        assert "my-server" in text
        assert "my_tool" in text
        assert "This is a description" in text


class TestSearchResult:
    """Tests for SearchResult dataclass."""

    def test_to_dict(self, sample_tools: list[ToolInfo]):
        """Test converting SearchResult to dictionary."""
        result = SearchResult(tool=sample_tools[0], score=1.5)
        d = result.to_dict()
        assert d["server"] == "github"
        assert d["tool"] == "create_issue"
        assert "description" in d
        assert d["score"] == 1.5
        assert "requiredParams" in d


class TestToolSearcher:
    """Tests for ToolSearcher class."""

    def test_empty_tools(self):
        """Test searching with no tools."""
        searcher = ToolSearcher([])
        results = searcher.search("anything")
        assert results == []

    def test_search_bm25_basic(self, sample_tools: list[ToolInfo]):
        """Test basic BM25 search."""
        searcher = ToolSearcher(sample_tools)
        results = searcher.search("github issue", method=SearchMethod.BM25)

        assert len(results) > 0
        # GitHub tools should rank higher
        assert results[0].tool.server == "github"

    def test_search_bm25_empty_query(self, sample_tools: list[ToolInfo]):
        """Test BM25 search with empty query."""
        searcher = ToolSearcher(sample_tools)
        results = searcher.search_bm25("")
        assert results == []

    def test_search_bm25_limit(self, sample_tools: list[ToolInfo]):
        """Test BM25 search respects limit."""
        searcher = ToolSearcher(sample_tools)
        results = searcher.search("issue", method=SearchMethod.BM25, limit=2)
        assert len(results) <= 2

    def test_search_regex_basic(self, sample_tools: list[ToolInfo]):
        """Test basic regex search."""
        searcher = ToolSearcher(sample_tools)
        results = searcher.search("create.*issue", method=SearchMethod.REGEX)

        assert len(results) > 0
        assert any(r.tool.name == "create_issue" for r in results)

    def test_search_regex_case_insensitive(self, sample_tools: list[ToolInfo]):
        """Test regex search is case-insensitive."""
        searcher = ToolSearcher(sample_tools)
        results = searcher.search("GITHUB", method=SearchMethod.REGEX)

        assert len(results) > 0
        assert all(r.tool.server == "github" for r in results)

    def test_search_regex_invalid_pattern(self, sample_tools: list[ToolInfo]):
        """Test regex search with invalid pattern."""
        searcher = ToolSearcher(sample_tools)

        with pytest.raises(ValueError) as excinfo:
            searcher.search("[invalid", method=SearchMethod.REGEX)

        assert "Invalid regex pattern" in str(excinfo.value)

    def test_search_regex_empty_tools(self):
        """Test regex search with no tools."""
        searcher = ToolSearcher([])
        results = searcher.search_regex("anything")
        assert results == []

    def test_search_exact_basic(self, sample_tools: list[ToolInfo]):
        """Test basic exact match search."""
        searcher = ToolSearcher(sample_tools)
        results = searcher.search("slack", method=SearchMethod.EXACT)

        assert len(results) == 1
        assert results[0].tool.server == "slack"

    def test_search_exact_case_insensitive(self, sample_tools: list[ToolInfo]):
        """Test exact match is case-insensitive."""
        searcher = ToolSearcher(sample_tools)
        results = searcher.search("SLACK", method=SearchMethod.EXACT)

        assert len(results) == 1
        assert results[0].tool.server == "slack"

    def test_search_exact_partial_match(self, sample_tools: list[ToolInfo]):
        """Test exact match with partial string."""
        searcher = ToolSearcher(sample_tools)
        results = searcher.search("issue", method=SearchMethod.EXACT)

        # Should match multiple tools with "issue" in name or description
        assert len(results) >= 2

    def test_search_exact_no_match(self, sample_tools: list[ToolInfo]):
        """Test exact match with no matches."""
        searcher = ToolSearcher(sample_tools)
        results = searcher.search("nonexistent_tool_xyz", method=SearchMethod.EXACT)

        assert results == []

    def test_search_exact_empty_tools(self):
        """Test exact search with no tools."""
        searcher = ToolSearcher([])
        results = searcher.search_exact("anything")
        assert results == []

    def test_search_exact_scoring(self, sample_tools: list[ToolInfo]):
        """Test exact match scoring prioritizes name > server > description."""
        # Add a tool where query matches name
        tools = sample_tools + [
            ToolInfo(
                server="other",
                name="issue_tracker",
                description="Tracks things",
                input_schema={},
            )
        ]
        searcher = ToolSearcher(tools)
        results = searcher.search("issue", method=SearchMethod.EXACT)

        # Tools with "issue" in name should score higher than description-only
        name_matches = [r for r in results if "issue" in r.tool.name.lower()]
        desc_only_matches = [
            r
            for r in results
            if "issue" not in r.tool.name.lower()
            and "issue" in r.tool.description.lower()
        ]

        if name_matches and desc_only_matches:
            assert name_matches[0].score > desc_only_matches[0].score

    def test_search_limit(self, sample_tools: list[ToolInfo]):
        """Test search respects limit parameter."""
        searcher = ToolSearcher(sample_tools)

        for method in SearchMethod:
            results = searcher.search("issue", method=method, limit=1)
            assert len(results) <= 1

    def test_search_unknown_method(self, sample_tools: list[ToolInfo]):
        """Test search with invalid method raises error."""
        searcher = ToolSearcher(sample_tools)

        # This would only happen if someone bypasses enum validation
        with pytest.raises(ValueError) as excinfo:
            searcher.search("test", method="invalid")  # type: ignore

        assert "Unknown search method" in str(excinfo.value)

    def test_bm25_index_built_lazily(self, sample_tools: list[ToolInfo]):
        """Test BM25 index is built only on first search."""
        searcher = ToolSearcher(sample_tools)

        # Index should not exist yet
        assert searcher._bm25 is None
        assert searcher._corpus is None

        # First search builds index
        searcher.search_bm25("test")

        assert searcher._bm25 is not None
        assert searcher._corpus is not None

    def test_bm25_index_reused(self, sample_tools: list[ToolInfo]):
        """Test BM25 index is reused across searches."""
        searcher = ToolSearcher(sample_tools)

        # First search
        searcher.search_bm25("github")
        bm25_id = id(searcher._bm25)

        # Second search should reuse same index
        searcher.search_bm25("sentry")
        assert id(searcher._bm25) == bm25_id


class TestSearchMethodEnum:
    """Tests for SearchMethod enum."""

    def test_enum_values(self):
        """Test enum string values."""
        assert SearchMethod.BM25.value == "bm25"
        assert SearchMethod.REGEX.value == "regex"
        assert SearchMethod.EXACT.value == "exact"

    def test_enum_from_string(self):
        """Test creating enum from string value."""
        assert SearchMethod("bm25") == SearchMethod.BM25
        assert SearchMethod("regex") == SearchMethod.REGEX
        assert SearchMethod("exact") == SearchMethod.EXACT
