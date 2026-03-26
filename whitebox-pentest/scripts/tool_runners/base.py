"""Base protocol for VulnScout tool runners.

All tool runners (semgrep, joern, codeql, secrets, trivy, checkov, etc.)
should implement this interface for dynamic discovery and registration.
"""
from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class ToolRunner(Protocol):
    """Protocol that all tool runners should implement."""

    name: str

    def is_available(self) -> bool:
        """Return True if the external tool is installed and accessible."""
        ...

    def run(self, target: str, **kwargs: Any) -> list[dict[str, Any]]:
        """Run the tool and return normalized findings."""
        ...

    def supported_languages(self) -> set[str]:
        """Return set of language names this tool supports."""
        ...
