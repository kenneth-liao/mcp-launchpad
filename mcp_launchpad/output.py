"""Output formatters for human-readable and JSON output."""

import json
import sys
import traceback
from typing import Any

import click


def maybe_parse_json(data: Any) -> Any:
    """Recursively parse JSON strings into objects.

    MCP tools often return JSON as a string. This function detects and parses
    such strings to provide properly formatted output instead of escaped JSON.
    """
    if isinstance(data, str):
        stripped = data.strip()
        if stripped.startswith(("{", "[")) and stripped.endswith(("}", "]")):
            try:
                return json.loads(data)
            except json.JSONDecodeError:
                pass
    elif isinstance(data, dict):
        return {k: maybe_parse_json(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [maybe_parse_json(item) for item in data]
    return data


def format_json(data: Any, success: bool = True) -> str:
    """Format data as JSON output."""
    if success:
        output = {"success": True, "data": maybe_parse_json(data)}
    else:
        output = data  # Error dict already has success: false
    return json.dumps(output, indent=2, default=str)


def format_error_json(
    error: Exception,
    error_type: str | None = None,
    help_text: str | None = None,
) -> str:
    """Format an error as JSON with helpful information."""
    return json.dumps(
        {
            "success": False,
            "error": {
                "type": error_type or type(error).__name__,
                "message": str(error),
                "traceback": traceback.format_exc(),
                "help": help_text or "",
            },
        },
        indent=2,
    )


def output_json(data: Any, success: bool = True) -> None:
    """Output data as JSON to stdout."""
    click.echo(format_json(data, success))


def output_error_json(
    error: Exception,
    error_type: str | None = None,
    help_text: str | None = None,
) -> None:
    """Output an error as JSON to stdout."""
    click.echo(format_error_json(error, error_type, help_text))
    sys.exit(1)


def output_human(message: str) -> None:
    """Output a human-readable message."""
    click.echo(message)


def output_error_human(error: Exception, help_text: str | None = None) -> None:
    """Output an error in human-readable format."""
    click.secho(f"Error: {error}", fg="red", err=True)
    if help_text:
        click.echo(f"\n{help_text}", err=True)
    sys.exit(1)


class OutputHandler:
    """Handles output formatting based on mode (JSON or human)."""

    def __init__(self, json_mode: bool = False):
        self.json_mode = json_mode

    def success(self, data: Any, human_message: str | None = None) -> None:
        """Output success response."""
        if self.json_mode:
            output_json(data)
        else:
            if human_message:
                output_human(human_message)
            else:
                output_human(json.dumps(maybe_parse_json(data), indent=2, default=str))

    def error(
        self,
        error: Exception,
        error_type: str | None = None,
        help_text: str | None = None,
    ) -> None:
        """Output error response."""
        if self.json_mode:
            output_error_json(error, error_type, help_text)
        else:
            output_error_human(error, help_text)

    def table(self, headers: list[str], rows: list[list[str]]) -> None:
        """Output a table (human mode only, JSON mode outputs raw data)."""
        if self.json_mode:
            # Convert to list of dicts for JSON
            data = [dict(zip(headers, row, strict=True)) for row in rows]
            output_json(data)
        else:
            # Calculate column widths
            widths = [len(h) for h in headers]
            for row in rows:
                for i, cell in enumerate(row):
                    widths[i] = max(widths[i], len(str(cell)))

            # Print header
            header_line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
            click.secho(header_line, bold=True)
            click.echo("-" * len(header_line))

            # Print rows
            for row in rows:
                click.echo(
                    "  ".join(str(c).ljust(widths[i]) for i, c in enumerate(row))
                )
