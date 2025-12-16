"""Tool search implementations: BM25, regex, and exact match."""

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any

from rank_bm25 import BM25Okapi

from .connection import ToolInfo


class SearchMethod(str, Enum):
    """Available search methods."""

    BM25 = "bm25"
    REGEX = "regex"
    EXACT = "exact"


@dataclass
class SearchResult:
    """A single search result."""

    tool: ToolInfo
    score: float

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "server": self.tool.server,
            "tool": self.tool.name,
            "description": self.tool.description,
            "requiredParams": self.tool.get_required_params(),
            "score": round(self.score, 3),
        }


def tokenize(text: str) -> list[str]:
    """Tokenize text for BM25 indexing."""
    # Convert to lowercase and split on non-alphanumeric characters
    text = text.lower()
    # Split on underscores, hyphens, spaces, and other non-alphanumeric
    tokens = re.split(r"[^a-z0-9]+", text)
    return [t for t in tokens if t]


def build_search_text(tool: ToolInfo) -> str:
    """Build the searchable text for a tool."""
    # Include server name, tool name, and description
    parts = [tool.server, tool.name, tool.description]
    return " ".join(parts)


class ToolSearcher:
    """Searches tools using various methods."""

    def __init__(self, tools: list[ToolInfo]):
        self.tools = tools
        self._bm25: BM25Okapi | None = None
        self._corpus: list[list[str]] | None = None

    def _build_bm25_index(self) -> None:
        """Build BM25 index lazily."""
        if self._bm25 is None:
            self._corpus = [tokenize(build_search_text(t)) for t in self.tools]
            self._bm25 = BM25Okapi(self._corpus)

    def search_bm25(self, query: str, limit: int = 10) -> list[SearchResult]:
        """Search using BM25 ranking algorithm."""
        if not self.tools:
            return []

        self._build_bm25_index()
        assert self._bm25 is not None

        query_tokens = tokenize(query)
        if not query_tokens:
            return []

        scores = self._bm25.get_scores(query_tokens)

        # Pair tools with scores and sort
        results = [
            SearchResult(tool=tool, score=float(score))
            for tool, score in zip(self.tools, scores)
            if score > 0
        ]
        results.sort(key=lambda r: r.score, reverse=True)

        return results[:limit]

    def search_regex(self, pattern: str, limit: int = 10) -> list[SearchResult]:
        """Search using regex pattern matching."""
        if not self.tools:
            return []

        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            raise ValueError(f"Invalid regex pattern: {e}")

        results = []
        for tool in self.tools:
            search_text = build_search_text(tool)
            matches = list(regex.finditer(search_text))
            if matches:
                # Score based on number of matches and their positions
                score = len(matches) + sum(
                    1.0 / (m.start() + 1) for m in matches
                )
                results.append(SearchResult(tool=tool, score=score))

        results.sort(key=lambda r: r.score, reverse=True)
        return results[:limit]

    def search_exact(self, query: str, limit: int = 10) -> list[SearchResult]:
        """Search using exact substring matching."""
        if not self.tools:
            return []

        query_lower = query.lower()
        results = []

        for tool in self.tools:
            search_text = build_search_text(tool).lower()
            if query_lower in search_text:
                # Score higher for matches in name vs description
                score = 0.0
                if query_lower in tool.name.lower():
                    score += 2.0
                if query_lower in tool.server.lower():
                    score += 1.5
                if query_lower in tool.description.lower():
                    score += 1.0
                results.append(SearchResult(tool=tool, score=score))

        results.sort(key=lambda r: r.score, reverse=True)
        return results[:limit]

    def search(
        self,
        query: str,
        method: SearchMethod = SearchMethod.BM25,
        limit: int = 10,
    ) -> list[SearchResult]:
        """Search tools using the specified method."""
        if method == SearchMethod.BM25:
            return self.search_bm25(query, limit)
        elif method == SearchMethod.REGEX:
            return self.search_regex(query, limit)
        elif method == SearchMethod.EXACT:
            return self.search_exact(query, limit)
        else:
            raise ValueError(f"Unknown search method: {method}")

