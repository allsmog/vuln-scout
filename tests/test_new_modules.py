"""Tests for all Wave 1-4 modules.

Covers: semantic FP checks, entry point mapper, correlation engine,
chain detector, service graph, claude analyzer, rule generator,
auto propagate, vuln class detectors, auto triage, cache manager,
feedback collector, knowledge graph, verification levels, poc generator,
blast radius, security mutator, diff security, business context extractor.
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

import sys

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ROOT / "whitebox-pentest" / "scripts"

# Add scripts dir to path so inter-module imports work (chain_detector -> service_graph, etc.)
sys.path.insert(0, str(SCRIPTS_DIR))


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    # Register in sys.modules so dataclasses and inter-module imports work
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


artifact_utils = load_module("artifact_utils", SCRIPTS_DIR / "artifact_utils.py")
correlation_engine = load_module("correlation_engine", SCRIPTS_DIR / "correlation_engine.py")
chain_detector = load_module("chain_detector", SCRIPTS_DIR / "chain_detector.py")
entry_point_mapper = load_module("entry_point_mapper", SCRIPTS_DIR / "entry_point_mapper.py")
auto_triage = load_module("auto_triage", SCRIPTS_DIR / "auto_triage.py")
knowledge_graph = load_module("knowledge_graph", SCRIPTS_DIR / "knowledge_graph.py")
security_mutator = load_module("security_mutator", SCRIPTS_DIR / "security_mutator.py")
poc_generator = load_module("poc_generator", SCRIPTS_DIR / "poc_generator.py")
business_context = load_module("business_context_extractor", SCRIPTS_DIR / "business_context_extractor.py")
feedback_collector = load_module("feedback_collector", SCRIPTS_DIR / "feedback_collector.py")
cache_manager = load_module("cache_manager", SCRIPTS_DIR / "cache_manager.py")
service_graph = load_module("service_graph", SCRIPTS_DIR / "service_graph.py")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(**overrides) -> dict:
    base = {
        "id": "VSCOUT-0001", "stable_key": "vscout:abc123",
        "kind": "finding", "severity": "high", "type": "sql-injection",
        "title": "SQL injection", "file": "api.py", "line": 42,
        "verdict": "unverified", "confidence": "medium",
        "source_tool": "semgrep", "message": "SQLi detected",
        "evidence": [{"type": "pattern-match", "label": "test",
                      "path": "api.py", "line": 42, "excerpt": "db.query(f'...')"}],
    }
    base.update(overrides)
    return base


# ===================================================================
# Semantic FP Checks
# ===================================================================

class SemanticFPTests(unittest.TestCase):
    def test_parameterized_query_detected(self):
        finding = {"type": "sql-injection"}
        ctx = "db.query('SELECT * FROM users WHERE id = ?', [userId])"
        result = artifact_utils.semantic_fp_check(finding, ctx)
        self.assertIsNotNone(result)
        self.assertIn("parameter", result.lower())

    def test_no_fp_on_string_concat(self):
        finding = {"type": "sql-injection"}
        ctx = 'db.query("SELECT * FROM users WHERE id = " + userId)'
        result = artifact_utils.semantic_fp_check(finding, ctx)
        self.assertIsNone(result)

    def test_subprocess_list_args_detected(self):
        finding = {"type": "command-injection"}
        ctx = 'subprocess.run(["git", "commit", "-m", message])'
        result = artifact_utils.semantic_fp_check(finding, ctx)
        self.assertIsNotNone(result)

    def test_json_response_xss_fp(self):
        finding = {"type": "xss"}
        ctx = "res.json({ user: userData })"
        result = artifact_utils.semantic_fp_check(finding, ctx)
        self.assertIsNotNone(result)

    def test_ssrf_allowlist_detected(self):
        finding = {"type": "ssrf"}
        ctx = "if hostname not in allowed_hosts: raise ValueError()"
        result = artifact_utils.semantic_fp_check(finding, ctx)
        self.assertIsNotNone(result)

    def test_env_var_secret_detected(self):
        finding = {"type": "hardcoded-secret"}
        ctx = 'api_key = os.environ["API_KEY"]'
        result = artifact_utils.semantic_fp_check(finding, ctx)
        self.assertIsNotNone(result)

    def test_path_basename_detected(self):
        finding = {"type": "path-traversal"}
        ctx = "const name = path.basename(userFile)"
        result = artifact_utils.semantic_fp_check(finding, ctx)
        self.assertIsNotNone(result)

    def test_unknown_type_returns_none(self):
        finding = {"type": "unknown-vuln-type"}
        ctx = "some random code"
        result = artifact_utils.semantic_fp_check(finding, ctx)
        self.assertIsNone(result)

    def test_apply_semantic_fp_checks_demotes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a test file with parameterized query
            test_file = Path(tmpdir) / "api.py"
            test_file.write_text("db.query('SELECT * FROM users WHERE id = ?', [uid])\n" * 5)

            findings = [_make_finding(file="api.py", line=3)]
            result, demoted = artifact_utils.apply_semantic_fp_checks(findings, tmpdir)
            self.assertEqual(demoted, 1)
            self.assertEqual(result[0]["kind"], "hotspot")
            self.assertEqual(result[0]["confidence"], "low")


# ===================================================================
# Correlation Engine
# ===================================================================

class CorrelationTests(unittest.TestCase):
    def test_multi_tool_gets_high_confidence(self):
        findings = [_make_finding(source_tool="multi", confidence="medium")]
        result = correlation_engine.correlate_findings(findings)
        self.assertEqual(result[0]["confidence"], "high")

    def test_single_tool_high_gets_demoted(self):
        findings = [_make_finding(source_tool="semgrep", confidence="high")]
        result = correlation_engine.correlate_findings(findings)
        self.assertEqual(result[0]["confidence"], "medium")

    def test_verified_finding_not_changed(self):
        findings = [_make_finding(verdict="verified", confidence="verified")]
        result = correlation_engine.correlate_findings(findings)
        self.assertEqual(result[0]["confidence"], "verified")

    def test_targeted_joern_params_generated(self):
        findings = [
            _make_finding(source_tool="semgrep", verdict="unverified", rule_id="sqli-rule"),
        ]
        params = correlation_engine.generate_targeted_joern_params(findings)
        self.assertEqual(len(params), 1)
        self.assertEqual(params[0]["type"], "sql-injection")
        self.assertEqual(params[0]["file"], "api.py")

    def test_joern_script_selection(self):
        self.assertEqual(correlation_engine.select_joern_script("sql-injection"), "verify-sqli.sc")
        self.assertEqual(correlation_engine.select_joern_script("xss"), "verify-xss.sc")
        self.assertEqual(correlation_engine.select_joern_script("unknown"), "verify-generic.sc")


# ===================================================================
# Chain Detector
# ===================================================================

class ChainDetectorTests(unittest.TestCase):
    def test_ssrf_to_sqli_chain(self):
        findings = [
            _make_finding(id="V1", type="ssrf", file="proxy.go", line=10),
            _make_finding(id="V2", type="sql-injection", file="internal.py", line=20),
        ]
        updated, chains = chain_detector.detect_chains(findings)
        self.assertGreaterEqual(len(chains), 1)
        self.assertIn("SSRF", chains[0]["name"])
        self.assertEqual(updated[0].get("chain_role"), "entry")
        self.assertEqual(updated[1].get("chain_role"), "sink")

    def test_path_traversal_to_secret(self):
        findings = [
            _make_finding(id="V1", type="path-traversal", file="files.ts", line=10),
            _make_finding(id="V2", type="hardcoded-secret", file=".env", line=3),
        ]
        _, chains = chain_detector.detect_chains(findings)
        self.assertGreaterEqual(len(chains), 1)
        self.assertIn("Secret", chains[0]["name"])

    def test_no_chain_for_single_finding(self):
        findings = [_make_finding(id="V1", type="xss")]
        _, chains = chain_detector.detect_chains(findings)
        self.assertEqual(len(chains), 0)

    def test_auth_bypass_chain(self):
        findings = [
            _make_finding(id="V1", type="auth-bypass", severity="high"),
            _make_finding(id="V2", type="sql-injection", severity="critical", file="admin.py"),
        ]
        _, chains = chain_detector.detect_chains(findings)
        self.assertGreaterEqual(len(chains), 1)
        chain_names = [c["name"] for c in chains]
        self.assertTrue(any("Auth Bypass" in n for n in chain_names))


# ===================================================================
# Entry Point Mapper
# ===================================================================

class EntryPointTests(unittest.TestCase):
    def test_prioritize_unauthenticated_first(self):
        EP = entry_point_mapper.EntryPoint
        entries = [
            EP(method="GET", path="/admin", file="a.ts", line=1, framework="Express", has_auth=True),
            EP(method="POST", path="/login", file="b.ts", line=1, framework="Express", has_auth=False),
        ]
        result = entry_point_mapper.prioritize_for_scanning(entries)
        self.assertFalse(result[0].has_auth)
        self.assertTrue(result[1].has_auth)

    def test_entry_points_to_dict(self):
        EP = entry_point_mapper.EntryPoint
        entries = [EP(method="GET", path="/", file="app.ts", line=1, framework="Express")]
        dicts = entry_point_mapper.entry_points_to_dict(entries)
        self.assertEqual(len(dicts), 1)
        self.assertEqual(dicts[0]["method"], "GET")
        self.assertEqual(dicts[0]["path"], "/")

    def test_empty_dir_returns_empty(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            entries = entry_point_mapper.discover_entry_points(tmpdir)
            self.assertEqual(len(entries), 0)


# ===================================================================
# Auto Triage
# ===================================================================

class AutoTriageTests(unittest.TestCase):
    def test_test_file_demoted_to_info(self):
        findings = [_make_finding(file="tests/test_api.py")]
        result = auto_triage.auto_triage(findings)
        self.assertEqual(result[0]["severity"], "info")
        self.assertEqual(result[0]["kind"], "hotspot")

    def test_auth_reduces_severity(self):
        findings = [_make_finding(severity="high")]
        eps = [{"file": "api.py", "has_auth": True, "method": "GET", "path": "/"}]
        result = auto_triage.auto_triage(findings, eps)
        self.assertEqual(result[0]["severity"], "medium")

    def test_unauthenticated_boosts_severity(self):
        findings = [_make_finding(severity="medium")]
        eps = [{"file": "api.py", "has_auth": False, "method": "POST", "path": "/"}]
        result = auto_triage.auto_triage(findings, eps)
        self.assertEqual(result[0]["severity"], "high")

    def test_vendor_file_demoted(self):
        findings = [_make_finding(file="vendor/lib/helper.py")]
        result = auto_triage.auto_triage(findings)
        self.assertEqual(result[0]["severity"], "info")


# ===================================================================
# Verification Levels
# ===================================================================

class VerificationLevelTests(unittest.TestCase):
    def test_l0_pattern_match(self):
        finding = _make_finding(verdict="unverified")
        level = artifact_utils.compute_verification_level(finding)
        self.assertEqual(level, 0)

    def test_l1_dataflow_verified(self):
        finding = _make_finding(verdict="verified")
        level = artifact_utils.compute_verification_level(finding)
        self.assertEqual(level, 1)

    def test_l2_claude_verified(self):
        finding = _make_finding(verdict="unverified",
                                claude_analysis={"verdict": "verified"})
        level = artifact_utils.compute_verification_level(finding)
        self.assertEqual(level, 2)

    def test_l4_dynamic_verified(self):
        finding = _make_finding(dynamic_verified=True)
        level = artifact_utils.compute_verification_level(finding)
        self.assertEqual(level, 4)

    def test_apply_to_list(self):
        findings = [_make_finding(), _make_finding(verdict="verified")]
        result = artifact_utils.apply_verification_levels(findings)
        self.assertEqual(result[0]["verification_level"], 0)
        self.assertEqual(result[1]["verification_level"], 1)


# ===================================================================
# Knowledge Graph
# ===================================================================

class KnowledgeGraphTests(unittest.TestCase):
    def test_build_from_findings(self):
        findings = [_make_finding(id="V1"), _make_finding(id="V2", file="b.py")]
        graph = knowledge_graph.build_knowledge_graph(findings)
        self.assertGreaterEqual(len(graph._entities), 4)  # 2 findings + 2 files

    def test_blast_radius(self):
        findings = [_make_finding(id="V1")]
        graph = knowledge_graph.build_knowledge_graph(findings)
        radius = graph.get_blast_radius("finding:V1")
        self.assertIn("api.py", radius["affected_files"])

    def test_chain_relationships(self):
        findings = [_make_finding(id="V1"), _make_finding(id="V2")]
        chains = [{"id": "c1", "finding_ids": ["V1", "V2"]}]
        graph = knowledge_graph.build_knowledge_graph(findings, chains=chains)
        neighbors = graph.get_neighbors("finding:V1", "forward")
        neighbor_ids = [n.id for n in neighbors]
        self.assertIn("finding:V2", neighbor_ids)

    def test_save_and_load(self):
        findings = [_make_finding(id="V1")]
        graph = knowledge_graph.build_knowledge_graph(findings)
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            graph.save(f.name)
            loaded = knowledge_graph.KnowledgeGraph.load(f.name)
            self.assertEqual(len(loaded._entities), len(graph._entities))

    def test_entities_by_kind(self):
        findings = [_make_finding(id="V1")]
        eps = [{"method": "GET", "path": "/", "file": "api.py", "line": 1, "framework": "Express"}]
        graph = knowledge_graph.build_knowledge_graph(findings, entry_points=eps)
        endpoints = graph.get_entities_by_kind("endpoint")
        self.assertGreaterEqual(len(endpoints), 1)


# ===================================================================
# Security Mutator
# ===================================================================

class SecurityMutatorTests(unittest.TestCase):
    def test_find_mutations_in_test_code(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "app.py"
            test_file.write_text("subprocess.run(cmd, shell=False)\n")
            mutations = security_mutator.find_mutations(tmpdir)
            self.assertGreaterEqual(len(mutations), 1)
            self.assertEqual(mutations[0].mutation_type, "enable-shell")

    def test_mutation_report(self):
        m = security_mutator.Mutation(
            file="app.py", line=10, original="shell=False",
            mutated="shell=True", mutation_type="enable-shell",
            description="test",
        )
        report = security_mutator.mutation_report([m])
        self.assertEqual(report["total_mutations"], 1)
        self.assertIn("enable-shell", report["by_type"])

    def test_diff_security_new_findings(self):
        current = {"findings": [_make_finding(stable_key="k1"), _make_finding(stable_key="k2")]}
        baseline = {"findings": [_make_finding(stable_key="k1")]}
        diff = security_mutator.diff_security(current, baseline)
        self.assertEqual(len(diff.new_findings), 1)
        self.assertEqual(len(diff.fixed_findings), 0)

    def test_diff_security_fixed_findings(self):
        current = {"findings": [_make_finding(stable_key="k1")]}
        baseline = {"findings": [_make_finding(stable_key="k1"), _make_finding(stable_key="k2")]}
        diff = security_mutator.diff_security(current, baseline)
        self.assertEqual(len(diff.fixed_findings), 1)
        self.assertLess(diff.regression_score, 0)

    def test_diff_security_changed_severity(self):
        current = {"findings": [_make_finding(stable_key="k1", severity="critical")]}
        baseline = {"findings": [_make_finding(stable_key="k1", severity="high")]}
        diff = security_mutator.diff_security(current, baseline)
        self.assertEqual(len(diff.changed_findings), 1)


# ===================================================================
# PoC Generator
# ===================================================================

class PocGeneratorTests(unittest.TestCase):
    def test_generate_sqli_poc(self):
        finding = _make_finding(type="sql-injection", cvss_score=9.8)
        script = poc_generator.generate_poc(finding)
        self.assertIsNotNone(script)
        self.assertIn("SQL injection", script)
        self.assertIn("dry_run", script)

    def test_generate_ssrf_poc(self):
        finding = _make_finding(type="ssrf")
        script = poc_generator.generate_poc(finding)
        self.assertIsNotNone(script)
        self.assertIn("169.254.169.254", script)

    def test_no_poc_for_unknown_type(self):
        finding = _make_finding(type="unknown-vuln")
        script = poc_generator.generate_poc(finding)
        self.assertIsNone(script)

    def test_blast_radius_analysis(self):
        finding = _make_finding(type="sql-injection", file="payment/handler.py")
        all_findings = [finding, _make_finding(id="V2", file="payment/handler.py")]
        result = poc_generator.analyze_blast_radius(finding, all_findings)
        self.assertEqual(result["data_sensitivity"], "critical")
        self.assertTrue(result["related_findings_in_file"] > 0)


# ===================================================================
# Business Context Extractor
# ===================================================================

class BusinessContextTests(unittest.TestCase):
    def test_extract_from_readme(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            readme = Path(tmpdir) / "README.md"
            readme.write_text("# Payment Processing App\nHandles credit card transactions and PCI-DSS compliance.")
            ctx = business_context.extract_business_context(tmpdir)
            self.assertEqual(ctx.sensitivity_level, "critical")
            self.assertIn("PCI-DSS", ctx.compliance_frameworks)

    def test_default_to_medium(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = business_context.extract_business_context(tmpdir)
            self.assertEqual(ctx.sensitivity_level, "medium")

    def test_adjust_cvss_for_context(self):
        finding = _make_finding(cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N")
        ctx = business_context.BusinessContext(sensitivity_level="critical")
        result = business_context.adjust_cvss_for_context(finding, ctx)
        self.assertIn("business_context", result)
        self.assertEqual(result["business_context"]["sensitivity"], "critical")


# ===================================================================
# Feedback Collector
# ===================================================================

class FeedbackCollectorTests(unittest.TestCase):
    def test_record_and_retrieve(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fc = feedback_collector.FeedbackCollector(tmpdir)
            findings = [
                _make_finding(stable_key="k1", verdict="false_positive", rule_id="rule-1"),
                _make_finding(stable_key="k2", verdict="verified", rule_id="rule-2"),
            ]
            fc.record_scan(findings, "scan-001")
            fc.record_scan(findings, "scan-002")

            # k1 was FP in 2 scans -> auto-suppress
            suppressions = fc.get_auto_suppressions()
            self.assertIn("k1", suppressions)
            self.assertNotIn("k2", suppressions)

    def test_regression_detection(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fc = feedback_collector.FeedbackCollector(tmpdir)
            # First scan: verified finding
            fc.record_scan([_make_finding(stable_key="k1", verdict="verified")], "scan-001")

            # Second scan: same key but unverified (regression)
            findings = [_make_finding(stable_key="k1", verdict="unverified")]
            regressions = fc.get_regressions(findings)
            self.assertEqual(len(regressions), 1)


# ===================================================================
# Cache Manager
# ===================================================================

class CacheManagerTests(unittest.TestCase):
    def test_store_and_retrieve(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "api.py"
            test_file.write_text("some code")
            cache = cache_manager.ScanCache(tmpdir)
            findings = [_make_finding()]
            cache.store_findings("api.py", findings)
            cache.save()

            # Reload and retrieve
            cache2 = cache_manager.ScanCache(tmpdir)
            cached = cache2.get_cached_findings("api.py")
            self.assertIsNotNone(cached)
            self.assertEqual(len(cached), 1)

    def test_changed_file_invalidates_cache(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "api.py"
            test_file.write_text("original code")
            cache = cache_manager.ScanCache(tmpdir)
            cache.store_findings("api.py", [_make_finding()])
            cache.save()

            # Modify file
            test_file.write_text("modified code")
            cache2 = cache_manager.ScanCache(tmpdir)
            cached = cache2.get_cached_findings("api.py")
            self.assertIsNone(cached)  # Cache miss due to changed content

    def test_get_changed_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            f1 = Path(tmpdir) / "a.py"
            f2 = Path(tmpdir) / "b.py"
            f1.write_text("code a")
            f2.write_text("code b")

            cache = cache_manager.ScanCache(tmpdir)
            cache.store_findings("a.py", [])
            cache.store_findings("b.py", [])
            cache.save()

            # Modify only a.py
            f1.write_text("code a modified")
            cache2 = cache_manager.ScanCache(tmpdir)
            changed = cache2.get_changed_files(["a.py", "b.py"])
            self.assertIn("a.py", changed)
            self.assertNotIn("b.py", changed)


# ===================================================================
# Service Graph
# ===================================================================

class ServiceGraphTests(unittest.TestCase):
    def test_empty_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            graph = service_graph.build_service_graph(tmpdir)
            self.assertEqual(len(graph.services), 0)

    def test_reachability(self):
        graph = service_graph.ServiceGraph()
        graph.services = [
            service_graph.Service(name="api", exposure="external"),
            service_graph.Service(name="db", exposure="internal"),
            service_graph.Service(name="cache", exposure="internal"),
        ]
        graph.edges = [("api", "db"), ("api", "cache")]
        reachable = graph.get_reachable_services("api")
        self.assertIn("db", reachable)
        self.assertIn("cache", reachable)
        self.assertTrue(graph.is_externally_reachable("api"))
        self.assertFalse(graph.is_externally_reachable("db"))

    def test_to_dict(self):
        graph = service_graph.ServiceGraph()
        graph.services = [service_graph.Service(name="api")]
        d = graph.to_dict()
        self.assertEqual(len(d["services"]), 1)
        self.assertEqual(d["services"][0]["name"], "api")
