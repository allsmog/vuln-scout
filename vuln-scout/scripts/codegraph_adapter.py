#!/usr/bin/env python3
"""Optional CodeGraph sidecar integration.

CodeGraph is used for fast code intelligence: symbol lookup, context gathering,
impact/affected-file hints, and indexed file structure. It is deliberately not
used as a security verifier; Joern remains responsible for CPG/data-flow proof.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any


def is_available() -> bool:
    return shutil.which("codegraph") is not None


def is_initialized(target: str | Path) -> bool:
    return (Path(target).resolve() / ".codegraph").is_dir()


def _base_status(target: Path) -> dict[str, Any]:
    if not is_available():
        return {
            "tool": "codegraph",
            "state": "unavailable",
            "findings": 0,
            "reason": "codegraph binary not found",
        }
    if not is_initialized(target):
        return {
            "tool": "codegraph",
            "state": "not_initialized",
            "findings": 0,
            "reason": ".codegraph directory not found",
        }
    return {"tool": "codegraph", "state": "available", "findings": 0}


def _run(target: Path, args: list[str], timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["codegraph", *args],
        cwd=target,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _json_or_text(text: str) -> Any:
    text = text.strip()
    if not text:
        return {}
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def status(target: str | Path, include_raw: bool = False) -> dict[str, Any]:
    root = Path(target).resolve()
    base = _base_status(root)
    if base["state"] != "available":
        return base
    try:
        result = _run(root, ["status", str(root), "--json"], timeout=20)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "tool": "codegraph",
            "state": "failed",
            "findings": 0,
            "reason": str(exc),
        }
    if result.returncode != 0 and "--json" in (result.stderr or result.stdout):
        try:
            result = _run(root, ["status", str(root)], timeout=20)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {
                "tool": "codegraph",
                "state": "failed",
                "findings": 0,
                "reason": str(exc),
            }
    payload = _json_or_text(result.stdout)
    state = "succeeded" if result.returncode == 0 else "failed"
    report: dict[str, Any] = {
        "tool": "codegraph",
        "state": state,
        "findings": 0,
        "initialized": True,
    }
    if isinstance(payload, dict):
        report.update({key: value for key, value in payload.items() if key not in {"tool", "state", "findings"}})
    elif include_raw and payload:
        report["output"] = payload
    if result.returncode != 0:
        report["reason"] = (result.stderr or result.stdout or "codegraph status failed").strip()[:1000]
    return report


def search(target: str | Path, query: str, kind: str | None = None, limit: int = 20) -> dict[str, Any]:
    root = Path(target).resolve()
    base = _base_status(root)
    if base["state"] != "available":
        return base
    args = ["query", query, "--limit", str(limit), "--json"]
    if kind:
        args.extend(["--kind", kind])
    try:
        result = _run(root, args)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"tool": "codegraph", "state": "failed", "findings": 0, "reason": str(exc)}
    return {
        "tool": "codegraph",
        "state": "succeeded" if result.returncode == 0 else "failed",
        "findings": 0,
        "query": query,
        "results": _json_or_text(result.stdout),
        "reason": "" if result.returncode == 0 else (result.stderr or result.stdout).strip()[:1000],
    }


def context(target: str | Path, task: str, max_nodes: int = 20, fmt: str = "markdown") -> dict[str, Any]:
    root = Path(target).resolve()
    base = _base_status(root)
    if base["state"] != "available":
        return base
    fmt = "json" if fmt == "json" else "markdown"
    args = ["context", task, "--format", fmt, "--max-nodes", str(max_nodes)]
    try:
        result = _run(root, args, timeout=90)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"tool": "codegraph", "state": "failed", "findings": 0, "reason": str(exc)}
    payload = _json_or_text(result.stdout) if fmt == "json" else result.stdout
    return {
        "tool": "codegraph",
        "state": "succeeded" if result.returncode == 0 else "failed",
        "findings": 0,
        "task": task,
        "context": payload,
        "reason": "" if result.returncode == 0 else (result.stderr or result.stdout).strip()[:1000],
    }


def affected(target: str | Path, files: list[str], depth: int = 5, filter_glob: str | None = None) -> dict[str, Any]:
    root = Path(target).resolve()
    base = _base_status(root)
    if base["state"] != "available":
        return base | {"affected_files": []}
    if not files:
        return {"tool": "codegraph", "state": "skipped", "findings": 0, "affected_files": []}
    args = ["affected", *files, "--depth", str(depth), "--json"]
    if filter_glob:
        args.extend(["--filter", filter_glob])
    try:
        result = _run(root, args, timeout=90)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"tool": "codegraph", "state": "failed", "findings": 0, "reason": str(exc), "affected_files": []}
    payload = _json_or_text(result.stdout)
    affected_files = _extract_paths(payload)
    return {
        "tool": "codegraph",
        "state": "succeeded" if result.returncode == 0 else "failed",
        "findings": 0,
        "affected_files": affected_files,
        "raw": payload,
        "reason": "" if result.returncode == 0 else (result.stderr or result.stdout).strip()[:1000],
    }


def _extract_paths(payload: Any) -> list[str]:
    if isinstance(payload, list):
        if all(isinstance(item, str) for item in payload):
            return sorted(set(payload))
        paths = [
            str(item.get("path") or item.get("file"))
            for item in payload
            if isinstance(item, dict) and (item.get("path") or item.get("file"))
        ]
        return sorted(set(paths))
    if isinstance(payload, dict):
        for key in ("affected", "affected_files", "affectedTests", "files", "tests"):
            value = payload.get(key)
            if isinstance(value, list):
                return _extract_paths(value)
    if isinstance(payload, str):
        return sorted({line.strip() for line in payload.splitlines() if line.strip()})
    return []
