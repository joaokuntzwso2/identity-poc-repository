import ast
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

OIDC = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(OIDC))
from bff_runtime_config import RuntimeConfigurationError, build_cases_runtime_env

class BffRuntimeConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        (self.repo / "var").mkdir(mode=0o700)
        policy = self.repo / "deploy/ciam-v10/oidc/bff-runtime-policy.json"
        policy.parent.mkdir(parents=True)
        policy.write_bytes((OIDC / "bff-runtime-policy.json").read_bytes())

    def test_repeatable_restart_without_manual_exports(self):
        first = build_cases_runtime_env(self.repo, {})
        second = build_cases_runtime_env(self.repo, {})
        self.assertEqual(first, second)
        self.assertEqual(first["WSO2_CASES_API_AUDIENCE"],
                         "urn:ciampoc:service-requests:v1")
        self.assertEqual(first["WSO2_CASES_SCOPES_ENABLED"], "1")
        self.assertEqual(first["WSO2_TOTP_STEPUP_ACR"],
                         "urn:ciampoc:assurance:totp:v1")
        self.assertEqual(first["WSO2_TOTP_STEPUP_AMR"], "totp")
        self.assertEqual(first["CIAM_CASES_BACKEND"], "jsonl")
        self.assertTrue(Path(first["CIAM_BUSINESS_DATA_DIR"]).is_absolute())
        mode = stat.S_IMODE(Path(first["CIAM_BUSINESS_DATA_DIR"]).stat().st_mode)
        self.assertEqual(mode, 0o700)

    def test_clean_install_creates_private_parent_and_storage(self):
        (self.repo / "var").rmdir()
        env = build_cases_runtime_env(self.repo, {})
        self.assertEqual(Path(env["CIAM_BUSINESS_DATA_DIR"]).resolve(),
                         (self.repo / "var/ciam-business-data").resolve())
        self.assertEqual(stat.S_IMODE((self.repo / "var").stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.repo / "var/ciam-business-data").stat().st_mode), 0o700)

    def test_symlink_parent_is_rejected(self):
        (self.repo / "var").rmdir()
        external = self.repo / "external"
        external.mkdir()
        (self.repo / "var").symlink_to(external, target_is_directory=True)
        with self.assertRaises(RuntimeConfigurationError):
            build_cases_runtime_env(self.repo, {})

    def test_unsafe_parent_permissions_are_rejected(self):
        parent = self.repo / "var"
        parent.chmod(0o777)
        with self.assertRaisesRegex(RuntimeConfigurationError, "PERMISSIONS_UNSAFE"):
            build_cases_runtime_env(self.repo, {})
        self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o777)

    def test_existing_case_ledger_is_preserved(self):
        storage = self.repo / "var/ciam-business-data"
        storage.mkdir(mode=0o700)
        ledger = storage / "requests-aurora.jsonl"
        saved = b'{"caseId":"not-a-real-case","state":"OPEN"}\n'
        ledger.write_bytes(saved)
        build_cases_runtime_env(self.repo, {})
        self.assertEqual(ledger.read_bytes(), saved)

    def test_conflicting_inherited_security_configuration_fails_closed(self):
        for key, bad in (
            ("WSO2_CASES_SCOPES_ENABLED", "0"),
            ("WSO2_CASES_API_AUDIENCE", "other"),
            ("WSO2_TOTP_STEPUP_AMR", "none"),
            ("WSO2_TOTP_STEPUP_ACR", ""),
            ("CIAM_CASES_BACKEND", "postgres"),
            ("CIAM_BUSINESS_DATA_DIR", "/tmp/other-ledger"),
        ):
            with self.subTest(key=key):
                with self.assertRaisesRegex(RuntimeConfigurationError, "BFF_RUNTIME_CONFLICT_"):
                    build_cases_runtime_env(self.repo, {key: bad})
        self.assertFalse((self.repo / "var/ciam-business-data").exists())

    def test_existing_storage_symlink_is_refused(self):
        external = self.repo / "outside"
        external.mkdir()
        (self.repo / "var/ciam-business-data").symlink_to(external, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeConfigurationError, "SYMLINK"):
            build_cases_runtime_env(self.repo, {})

    def test_insecure_storage_permissions_are_refused_without_chmod(self):
        storage = self.repo / "var/ciam-business-data"
        storage.mkdir(mode=0o700)
        storage.chmod(0o755)
        with self.assertRaisesRegex(RuntimeConfigurationError, "PERMISSIONS_UNSAFE"):
            build_cases_runtime_env(self.repo, {})
        self.assertEqual(stat.S_IMODE(storage.stat().st_mode), 0o755)

    def test_policy_downgrade_and_unknown_keys_are_refused(self):
        path = self.repo / "deploy/ciam-v10/oidc/bff-runtime-policy.json"
        config = json.loads(path.read_text())
        config["casesScopesEnabled"] = False
        path.write_text(json.dumps(config))
        with self.assertRaisesRegex(RuntimeConfigurationError, "SECURITY_DRIFT"):
            build_cases_runtime_env(self.repo, {})
        config["casesScopesEnabled"] = True
        config["extra"] = "unexpected"
        path.write_text(json.dumps(config))
        with self.assertRaisesRegex(RuntimeConfigurationError, "SCHEMA_INVALID"):
            build_cases_runtime_env(self.repo, {})

    def test_launcher_integrates_runtime_before_node_spawn(self):
        source = (OIDC / "bootstrap.py").read_text()
        tree = ast.parse(source)
        fn = next(x for x in tree.body
                  if isinstance(x, ast.FunctionDef) and x.name == "start_bff")
        occurrences = []
        for item in ast.walk(fn):
            if isinstance(item, ast.Call) and isinstance(item.func, ast.Name):
                if item.func.id in ("build_cases_runtime_env",):
                    occurrences.append(item.lineno)
        pops = [item.lineno for item in ast.walk(fn) if isinstance(item, ast.Call)
                and isinstance(item.func, ast.Attribute)
                and item.func.attr == "Popen"]
        self.assertEqual(len(occurrences), 1)
        self.assertEqual(len(pops), 1)
        self.assertLess(occurrences[0], pops[0])

if __name__ == "__main__":
    unittest.main()
