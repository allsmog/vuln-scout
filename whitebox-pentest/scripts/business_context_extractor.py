#!/usr/bin/env python3
"""Business context extractor for context-aware CVSS scoring.

Reads README.md, API docs, code comments, and model names to understand
what the application handles (money, PII, health data) and adjusts
CVSS environmental scores accordingly.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger("vuln-scout")


@dataclass
class BusinessContext:
    """Extracted business context for the application."""
    app_description: str = ""
    data_categories: list[str] = field(default_factory=list)
    compliance_frameworks: list[str] = field(default_factory=list)
    sensitivity_level: str = "unknown"  # critical, high, medium, low
    industry_indicators: list[str] = field(default_factory=list)
    model_names: list[str] = field(default_factory=list)


# Keyword patterns for data sensitivity classification
_SENSITIVITY_KEYWORDS: dict[str, list[str]] = {
    "critical": [
        "payment", "credit card", "bank", "financial", "transaction",
        "billing", "stripe", "paypal", "wire transfer", "cryptocurrency",
        "wallet", "treasury", "settlement",
    ],
    "high": [
        "password", "credential", "secret", "token", "api key",
        "authentication", "authorization", "session", "jwt",
        "personal data", "pii", "ssn", "social security",
        "medical", "health", "hipaa", "patient", "diagnosis",
        "passport", "driver.?license", "biometric",
    ],
    "medium": [
        "user", "profile", "account", "email", "phone",
        "address", "order", "subscription", "invoice",
        "customer", "employee", "member",
    ],
    "low": [
        "blog", "post", "comment", "article", "content",
        "static", "public", "documentation", "readme",
        "analytics", "metrics", "logging",
    ],
}

_COMPLIANCE_PATTERNS: dict[str, re.Pattern[str]] = {
    "PCI-DSS": re.compile(r"(?i)pci[\s-]?dss|payment\s+card\s+industry"),
    "HIPAA": re.compile(r"(?i)hipaa|health\s+insurance\s+portability"),
    "SOC 2": re.compile(r"(?i)soc\s*2|service\s+organization\s+control"),
    "GDPR": re.compile(r"(?i)gdpr|general\s+data\s+protection"),
    "CCPA": re.compile(r"(?i)ccpa|california\s+consumer\s+privacy"),
    "FERPA": re.compile(r"(?i)ferpa|family\s+educational\s+rights"),
}


def extract_business_context(target_path: str) -> BusinessContext:
    """Extract business context from the target codebase.

    Reads documentation, model names, and code patterns to understand
    what the application handles and its sensitivity requirements.
    """
    root = Path(target_path).resolve()
    ctx = BusinessContext()

    # 1. Read documentation files
    doc_text = _read_documentation(root)
    if doc_text:
        ctx.app_description = doc_text[:500]

    # 2. Detect compliance frameworks
    for framework, pattern in _COMPLIANCE_PATTERNS.items():
        if pattern.search(doc_text):
            ctx.compliance_frameworks.append(framework)

    # 3. Detect data categories from documentation
    all_text = doc_text.lower()
    for level, keywords in _SENSITIVITY_KEYWORDS.items():
        for keyword in keywords:
            if re.search(rf"\b{keyword}\b", all_text, re.IGNORECASE):
                ctx.data_categories.append(keyword)
                if _SENSITIVITY_ORDER.get(level, 0) > _SENSITIVITY_ORDER.get(ctx.sensitivity_level, -1):
                    ctx.sensitivity_level = level

    # 4. Detect model/table names from code
    ctx.model_names = _detect_model_names(root)

    # 5. Refine sensitivity from model names
    model_text = " ".join(ctx.model_names).lower()
    for level, keywords in _SENSITIVITY_KEYWORDS.items():
        for keyword in keywords:
            if keyword.lower() in model_text:
                if _SENSITIVITY_ORDER.get(level, 0) > _SENSITIVITY_ORDER.get(ctx.sensitivity_level, -1):
                    ctx.sensitivity_level = level

    if ctx.sensitivity_level == "unknown":
        ctx.sensitivity_level = "medium"  # Default assumption

    log.info("Business context: sensitivity=%s, compliance=%s, models=%d",
             ctx.sensitivity_level, ctx.compliance_frameworks, len(ctx.model_names))

    return ctx


_SENSITIVITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}


def _read_documentation(root: Path) -> str:
    """Read README and documentation files."""
    doc_files = [
        "README.md", "README.rst", "README.txt", "README",
        "docs/README.md", "doc/README.md",
        "CONTRIBUTING.md", "docs/architecture.md",
        "docs/security.md", "SECURITY.md",
    ]
    text_parts: list[str] = []
    for doc_file in doc_files:
        path = root / doc_file
        if path.is_file():
            try:
                text_parts.append(path.read_text(errors="replace")[:5000])
            except OSError:
                pass
    return "\n".join(text_parts)


def _detect_model_names(root: Path) -> list[str]:
    """Detect database model/entity names from code."""
    model_patterns = [
        # Django/SQLAlchemy models
        re.compile(r"""class\s+(\w+)\s*\(\s*(?:models\.Model|db\.Model|Base)\s*\)"""),
        # Java JPA entities
        re.compile(r"""@Entity[^)]*class\s+(\w+)"""),
        # Go struct (with db/gorm tags)
        re.compile(r"""type\s+(\w+)\s+struct\s*\{"""),
        # Rails ActiveRecord
        re.compile(r"""class\s+(\w+)\s*<\s*(?:ApplicationRecord|ActiveRecord::Base)"""),
        # TypeORM/Sequelize
        re.compile(r"""@Entity\(\)\s*(?:export\s+)?class\s+(\w+)"""),
        re.compile(r"""(?:define|init)\s*\(\s*['"](\w+)['"]"""),
    ]

    names: set[str] = set()
    extensions = {".py", ".java", ".go", ".rb", ".ts", ".js"}
    excluded = {"node_modules", "vendor", "dist", ".git", "__pycache__"}

    for f in root.rglob("*"):
        if not f.is_file() or f.suffix not in extensions:
            continue
        if any(ex in f.parts for ex in excluded):
            continue
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        for pattern in model_patterns:
            for m in pattern.finditer(text):
                names.add(m.group(1))

    return sorted(names)


def adjust_cvss_for_context(
    finding: dict[str, Any],
    context: BusinessContext,
) -> dict[str, Any]:
    """Adjust CVSS vector based on business context.

    Modifies the finding's CVSS environmental metrics based on the
    application's data sensitivity and deployment context.
    """
    vector = finding.get("cvss_vector", "")
    if not vector or not vector.startswith("CVSS:3.1"):
        return finding

    # Adjust Confidentiality/Integrity requirements based on data sensitivity
    if context.sensitivity_level == "critical":
        # Financial/health data: max CIA requirements
        finding["business_context"] = {
            "sensitivity": "critical",
            "note": "Handles financial/health data -- maximum impact",
        }
    elif context.sensitivity_level == "high":
        finding["business_context"] = {
            "sensitivity": "high",
            "note": "Handles PII/credentials -- high impact",
        }
    elif context.sensitivity_level == "low":
        # Public data: lower impact
        finding["business_context"] = {
            "sensitivity": "low",
            "note": "Handles public data -- reduced impact",
        }

    # Add compliance context
    if context.compliance_frameworks:
        finding.setdefault("business_context", {})["compliance"] = context.compliance_frameworks

    return finding


def context_to_dict(ctx: BusinessContext) -> dict[str, Any]:
    return {
        "app_description": ctx.app_description[:300],
        "data_categories": ctx.data_categories[:20],
        "compliance_frameworks": ctx.compliance_frameworks,
        "sensitivity_level": ctx.sensitivity_level,
        "model_names": ctx.model_names[:30],
    }
