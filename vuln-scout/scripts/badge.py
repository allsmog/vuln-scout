#!/usr/bin/env python3
"""Generate a shields.io-style SVG security badge from a VulnScout findings artifact.

The badge displays "VulnScout | <score>" with a color reflecting the security
posture.  Score is computed by deducting points for findings by severity.

Usage in READMEs: ![VulnScout](./vuln-scout-badge.svg)
"""
from __future__ import annotations

from typing import Any

# Score-to-color thresholds (shields.io palette)
COLOR_THRESHOLDS = [
    (90, "#4c1"),      # bright green
    (70, "#97ca00"),   # yellow-green
    (50, "#dfb317"),   # yellow
    (30, "#fe7d37"),   # orange
    (0, "#e05d44"),    # red
]

LABEL_TEXT = "VulnScout"
LABEL_BG = "#555"

# SVG template -- follows shields.io flat badge layout:
# 20px height, 3px rounded corners, Verdana 11px
SVG_TEMPLATE = """\
<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="20" role="img" aria-label="{label}: {value}">
  <title>{label}: {value}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="{total_width}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="{label_width}" height="20" fill="{label_bg}"/>
    <rect x="{label_width}" width="{value_width}" height="20" fill="{value_bg}"/>
    <rect width="{total_width}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
    <text aria-hidden="true" x="{label_x}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="{label_text_width}">{label}</text>
    <text x="{label_x}" y="140" transform="scale(.1)" fill="#fff" textLength="{label_text_width}">{label}</text>
    <text aria-hidden="true" x="{value_x}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="{value_text_width}">{value}</text>
    <text x="{value_x}" y="140" transform="scale(.1)" fill="#fff" textLength="{value_text_width}">{value}</text>
  </g>
</svg>"""


def _compute_score(summary: dict[str, Any]) -> int:
    """Compute a security score (0-100) from the findings summary."""
    score = 100
    score -= summary.get("critical", 0) * 25
    score -= summary.get("high", 0) * 10
    score -= summary.get("medium", 0) * 3
    score -= summary.get("low", 0) * 1
    return max(0, score)


def _color_for_score(score: int) -> str:
    """Return the badge color for a given score."""
    for threshold, color in COLOR_THRESHOLDS:
        if score >= threshold:
            return color
    return COLOR_THRESHOLDS[-1][1]


def _estimate_text_width(text: str) -> int:
    """Rough pixel-width estimate for Verdana 11px (shields.io convention).

    This uses a simplified per-character width table.  The values are
    approximations matching what shields.io produces for common ASCII.
    """
    # Average character width in tenths of a pixel at font-size 110 (scale .1)
    # For simplicity, use ~6.5px per character at rendered size, * 10 for SVG coords
    return len(text) * 65


def generate(artifact: dict[str, Any]) -> str:
    """Generate an SVG badge string from a findings artifact."""
    summary = artifact.get("summary", {})
    score = _compute_score(summary)
    color = _color_for_score(score)
    value_text = str(score)

    label_text_width = _estimate_text_width(LABEL_TEXT)
    value_text_width = _estimate_text_width(value_text)

    # Pixel widths (at 1x scale): text width / 10 + padding
    label_width = label_text_width // 10 + 10
    value_width = value_text_width // 10 + 10
    total_width = label_width + value_width

    # Center positions (in 10x SVG coordinate space)
    label_x = (label_width * 10) // 2
    value_x = label_width * 10 + (value_width * 10) // 2

    return SVG_TEMPLATE.format(
        total_width=total_width,
        label_width=label_width,
        value_width=value_width,
        label_bg=LABEL_BG,
        value_bg=color,
        label=LABEL_TEXT,
        value=value_text,
        label_x=label_x,
        value_x=value_x,
        label_text_width=label_text_width,
        value_text_width=value_text_width,
    )
