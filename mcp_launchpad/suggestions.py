"""Tool suggestion utilities for better error recovery."""

from __future__ import annotations

import re
from difflib import SequenceMatcher
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .connection import ToolInfo


def find_similar_tools(
    tool_name: str,
    available_tools: list["ToolInfo"],
    max_suggestions: int = 5,
) -> list["ToolInfo"]:
    """Find tools with similar names to the requested tool.

    Uses a combination of:
    1. Substring matching (tool name contains query or vice versa)
    2. Word overlap (shared words between names)
    3. Sequence similarity (fuzzy string matching)

    Args:
        tool_name: The tool name that wasn't found
        available_tools: List of available tools to search through
        max_suggestions: Maximum number of suggestions to return

    Returns:
        List of similar tools, sorted by relevance
    """
    if not available_tools:
        return []

    # Normalize the search term
    search_lower = tool_name.lower()
    search_words = set(re.split(r"[_\-\s]+", search_lower))

    scored_tools: list[tuple[float, "ToolInfo"]] = []

    for tool in available_tools:
        name_lower = tool.name.lower()
        name_words = set(re.split(r"[_\-\s]+", name_lower))

        score = 0.0

        # Exact match (shouldn't happen, but handle it)
        if name_lower == search_lower:
            score = 1.0
        else:
            # Substring matching (high weight)
            if search_lower in name_lower or name_lower in search_lower:
                score += 0.5

            # Word overlap (medium weight)
            common_words = search_words & name_words
            if common_words:
                word_overlap = len(common_words) / max(len(search_words), len(name_words))
                score += 0.3 * word_overlap

            # Sequence similarity (lower weight, catches typos)
            seq_similarity = SequenceMatcher(None, search_lower, name_lower).ratio()
            score += 0.2 * seq_similarity

        if score > 0.1:  # Minimum threshold
            scored_tools.append((score, tool))

    # Sort by score descending
    scored_tools.sort(key=lambda x: x[0], reverse=True)

    return [tool for _, tool in scored_tools[:max_suggestions]]


def format_tool_suggestions(
    tool_name: str,
    server_name: str,
    similar_tools: list["ToolInfo"],
) -> str:
    """Format a helpful error message with tool suggestions.

    Args:
        tool_name: The tool name that wasn't found
        server_name: The server that was queried
        similar_tools: List of similar tools to suggest

    Returns:
        Formatted error message with suggestions
    """
    lines = [f"Tool '{tool_name}' not found on server '{server_name}'."]

    if similar_tools:
        lines.append("")
        lines.append("Similar tools:")
        for tool in similar_tools:
            required = tool.get_required_params()
            if required:
                params_hint = f" (requires: {', '.join(required)})"
            else:
                params_hint = ""
            lines.append(f"  - {tool.name}{params_hint}")
        lines.append("")
        lines.append(f"Try: mcpl list {server_name}")
    else:
        lines.append("")
        lines.append(f"Use 'mcpl list {server_name}' to see available tools.")

    return "\n".join(lines)


def is_tool_not_found_error(error_message: str) -> bool:
    """Check if an error message indicates a tool was not found.

    Args:
        error_message: The error message to check

    Returns:
        True if this is a "tool not found" error
    """
    lower_msg = error_message.lower()
    return (
        "tool not found" in lower_msg
        or "not found" in lower_msg and "tool" in lower_msg
        or "-32602" in error_message and "not found" in lower_msg
    )


def is_validation_error(error_message: str) -> bool:
    """Check if an error message indicates a validation/parameter error.

    Args:
        error_message: The error message to check

    Returns:
        True if this is a validation error
    """
    lower_msg = error_message.lower()
    return (
        "validation error" in lower_msg
        or "invalid arguments" in lower_msg
        or "invalid_type" in lower_msg
        or "required" in lower_msg and ("expected" in lower_msg or "received" in lower_msg)
    )


def format_validation_error(
    tool_name: str,
    server_name: str,
    error_message: str,
    tool_info: "ToolInfo | None" = None,
) -> str:
    """Format a helpful error message for validation errors.

    Args:
        tool_name: The tool that was called
        server_name: The server that was called
        error_message: The original error message
        tool_info: Optional tool info for generating example call

    Returns:
        Formatted error message with helpful context
    """
    lines = [f"Invalid arguments for tool '{tool_name}' on server '{server_name}'."]
    lines.append("")

    # Try to extract the specific validation issues
    if tool_info:
        required = tool_info.get_required_params()
        if required:
            lines.append(f"Required parameters: {', '.join(required)}")

        properties = tool_info.input_schema.get("properties", {})
        optional = [p for p in properties if p not in required]
        if optional:
            shown = optional[:5]
            suffix = ", ..." if len(optional) > 5 else ""
            lines.append(f"Optional parameters: {', '.join(shown)}{suffix}")

        lines.append("")
        lines.append("Example:")
        lines.append(f"  {tool_info.get_example_call()}")
    else:
        # Include the original error for context
        lines.append("Details:")
        # Clean up the error message a bit
        cleaned = error_message.replace("MCP error -32602: ", "").replace("Input validation error: ", "")
        lines.append(f"  {cleaned[:200]}")
        lines.append("")
        lines.append(f"Try: mcpl inspect {server_name} {tool_name} --example")

    return "\n".join(lines)
