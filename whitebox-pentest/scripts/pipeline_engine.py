#!/usr/bin/env python3
"""Event-driven pipeline engine with streaming results.

Replaces the monolithic run_tools() with an event-driven architecture:
  - Each tool runner produces findings as events
  - Findings stream to JSONL as they're discovered
  - Error recovery: if one tool crashes, others continue
  - Colored terminal output for real-time feedback
"""
from __future__ import annotations

import json
import logging
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable

log = logging.getLogger("vuln-scout")


class EventType(Enum):
    TOOL_STARTED = auto()
    TOOL_FINISHED = auto()
    TOOL_FAILED = auto()
    FINDING_DISCOVERED = auto()
    VERIFICATION_COMPLETE = auto()
    CHAIN_DETECTED = auto()
    ANALYSIS_COMPLETE = auto()
    PIPELINE_COMPLETE = auto()


@dataclass
class PipelineEvent:
    event_type: EventType
    tool_name: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)
    finding: dict[str, Any] | None = None
    chain: dict[str, Any] | None = None
    error: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class PipelineResult:
    findings: list[dict[str, Any]] = field(default_factory=list)
    events: list[PipelineEvent] = field(default_factory=list)
    tools_succeeded: list[str] = field(default_factory=list)
    tools_failed: list[str] = field(default_factory=list)
    tool_statuses: dict[str, dict[str, Any]] = field(default_factory=dict)
    duration_seconds: float = 0.0


# ANSI color codes for terminal output
_SEVERITY_COLORS = {
    "critical": "\033[91m",  # Red
    "high": "\033[93m",      # Yellow
    "medium": "\033[33m",    # Orange-ish
    "low": "\033[36m",       # Cyan
    "info": "\033[90m",      # Gray
}
_RESET = "\033[0m"
_BOLD = "\033[1m"


def _colorize_finding(finding: dict[str, Any]) -> str:
    """Format a finding for terminal output with colors."""
    severity = finding.get("severity", "info")
    color = _SEVERITY_COLORS.get(severity, "")
    vuln_type = finding.get("type", "unknown")
    file_path = finding.get("file", "unknown")
    line = finding.get("line", 0)
    tool = finding.get("source_tool", "unknown")
    verdict = finding.get("verdict", "unverified")
    return f"{color}[{severity.upper()}]{_RESET} {vuln_type} at {file_path}:{line} ({tool}, {verdict})"


class EventHandler:
    """Handles pipeline events -- writes to JSONL stream and terminal."""

    def __init__(self, jsonl_path: Path | None = None, verbose: bool = True):
        self._jsonl_path = jsonl_path
        self._verbose = verbose
        self._jsonl_file = None
        if jsonl_path:
            jsonl_path.parent.mkdir(parents=True, exist_ok=True)
            self._jsonl_file = open(jsonl_path, "w")

    def handle(self, event: PipelineEvent) -> None:
        if event.event_type == EventType.TOOL_STARTED:
            if self._verbose:
                print(f"  {_BOLD}Starting {event.tool_name}...{_RESET}", file=sys.stderr)

        elif event.event_type == EventType.TOOL_FINISHED:
            count = len(event.findings)
            if self._verbose:
                print(f"  {event.tool_name}: {count} findings", file=sys.stderr)

        elif event.event_type == EventType.TOOL_FAILED:
            if self._verbose:
                print(f"  {_SEVERITY_COLORS['high']}WARN: {event.tool_name} failed: {event.error}{_RESET}", file=sys.stderr)

        elif event.event_type == EventType.FINDING_DISCOVERED:
            if event.finding and self._verbose:
                print(f"  {_colorize_finding(event.finding)}", file=sys.stderr)
            if event.finding and self._jsonl_file:
                self._jsonl_file.write(json.dumps(event.finding) + "\n")
                self._jsonl_file.flush()

        elif event.event_type == EventType.CHAIN_DETECTED:
            if event.chain and self._verbose:
                print(f"  {_BOLD}Chain: {event.chain.get('name', 'unknown')}{_RESET}", file=sys.stderr)

    def close(self) -> None:
        if self._jsonl_file:
            self._jsonl_file.close()


ToolRunnerFunc = Callable[..., list[dict[str, Any]]]


def _normalize_runner_output(output: Any, tool_name: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Accept legacy list outputs and new {findings, status} outputs."""
    if isinstance(output, dict) and "findings" in output:
        findings = output.get("findings") or []
        status = dict(output.get("status") or {})
    else:
        findings = output or []
        status = {}

    status.setdefault("state", "succeeded")
    status.setdefault("tool", tool_name)
    status.setdefault("findings", len(findings))
    return findings, status


def run_pipeline(
    tool_tasks: list[tuple[str, ToolRunnerFunc, dict[str, Any]]],
    max_workers: int = 4,
    jsonl_path: Path | None = None,
    verbose: bool = True,
) -> PipelineResult:
    """Run tool runners with event-driven pipeline.

    Args:
        tool_tasks: List of (tool_name, runner_func, kwargs) tuples.
        max_workers: Maximum parallel workers.
        jsonl_path: Optional path for streaming JSONL output.
        verbose: Whether to print colored output to stderr.

    Returns:
        PipelineResult with all findings and event history.
    """
    result = PipelineResult()
    handler = EventHandler(jsonl_path, verbose)
    start_time = time.monotonic()

    try:
        futures: dict[Future, str] = {}

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            for tool_name, runner_func, kwargs in tool_tasks:
                handler.handle(PipelineEvent(EventType.TOOL_STARTED, tool_name=tool_name))
                future = executor.submit(runner_func, **kwargs)
                futures[future] = tool_name

            for future in as_completed(futures):
                tool_name = futures[future]
                try:
                    findings, status = _normalize_runner_output(future.result(), tool_name)
                    event = PipelineEvent(
                        EventType.TOOL_FINISHED,
                        tool_name=tool_name,
                        findings=findings,
                    )
                    handler.handle(event)
                    result.events.append(event)
                    result.tool_statuses[tool_name] = status
                    result.tools_succeeded.append(tool_name)

                    # Emit individual finding events for streaming
                    for finding in findings:
                        finding_event = PipelineEvent(
                            EventType.FINDING_DISCOVERED,
                            tool_name=tool_name,
                            finding=finding,
                        )
                        handler.handle(finding_event)

                    result.findings.extend(findings)

                except Exception as e:
                    error_msg = str(e)
                    state = "timed_out" if "timed out" in error_msg.lower() else "failed"
                    event = PipelineEvent(
                        EventType.TOOL_FAILED,
                        tool_name=tool_name,
                        error=error_msg,
                    )
                    handler.handle(event)
                    result.events.append(event)
                    result.tools_failed.append(tool_name)
                    result.tool_statuses[tool_name] = {
                        "tool": tool_name,
                        "state": state,
                        "findings": 0,
                        "reason": error_msg,
                    }
                    log.warning("%s failed: %s", tool_name, error_msg)

    finally:
        result.duration_seconds = time.monotonic() - start_time
        handler.close()

    return result
