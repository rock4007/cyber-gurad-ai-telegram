"""Type 11 — Deployment Tests: Railway config, Procfile, env vars, imports, requirements."""

import importlib
import os
import sys
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]


# ===================================================================
# Railway configuration
# ===================================================================

class TestRailwayConfig:
    def test_railway_toml_exists(self):
        # Bot-side railway.toml
        bot_toml = PROJECT_ROOT / "cyberguard-telegram" / "railway.toml"
        assert bot_toml.exists(), "cyberguard-telegram/railway.toml is missing"

    def test_railway_toml_valid_toml(self):
        import tomllib
        path = PROJECT_ROOT / "cyberguard-telegram" / "railway.toml"
        if not path.exists():
            pytest.skip("railway.toml not found")
        with open(path, "rb") as f:
            data = tomllib.load(f)
        assert "build" in data
        assert data["build"]["builder"] == "NIXPACKS"
        assert "deploy" in data
        assert "startCommand" in data["deploy"]

    def test_railway_json_exists(self):
        rj = PROJECT_ROOT / "railway.json"
        assert rj.exists(), "railway.json is missing"

    def test_railway_json_valid_json(self):
        import json
        path = PROJECT_ROOT / "railway.json"
        if not path.exists():
            pytest.skip("railway.json not found")
        with open(path) as f:
            data = json.load(f)
        assert data["build"]["builder"] == "NIXPACKS"
        assert "startCommand" in data["deploy"]
        assert "uvicorn" in data["deploy"]["startCommand"]


# ===================================================================
# Procfile
# ===================================================================

class TestProcfile:
    def test_procfile_exists(self):
        procfile = PROJECT_ROOT / "Procfile"
        assert procfile.exists(), "Procfile is missing"

    def test_procfile_has_web_process(self):
        procfile = PROJECT_ROOT / "Procfile"
        if not procfile.exists():
            pytest.skip("Procfile not found")
        content = procfile.read_text().strip()
        assert content.startswith("web:"), "Procfile must start with 'web:'"
        assert "uvicorn" in content
        assert "app.main:app" in content


# ===================================================================
# Requirements file
# ===================================================================

class TestRequirements:
    def test_requirements_txt_exists(self):
        req = PROJECT_ROOT / "requirements.txt"
        assert req.exists(), "requirements.txt is missing"

    def test_requirements_has_core_deps(self):
        req = PROJECT_ROOT / "requirements.txt"
        if not req.exists():
            pytest.skip("requirements.txt not found")
        content = req.read_text().lower()
        core_deps = [
            "fastapi",
            "uvicorn",
            "python-telegram-bot",
            "sqlalchemy",
            "asyncpg",
            "redis",
            "httpx",
            "pydantic-settings",
        ]
        for dep in core_deps:
            assert dep in content, f"Missing core dependency: {dep}"

    def test_requirements_pinned_versions(self):
        req = PROJECT_ROOT / "requirements.txt"
        if not req.exists():
            pytest.skip("requirements.txt not found")
        lines = [l.strip() for l in req.read_text().splitlines() if l.strip() and not l.startswith("#")]
        for line in lines:
            assert "==" in line, f"Dependency not pinned: {line}"


# ===================================================================
# Required environment variables
# ===================================================================

class TestRequiredEnvVars:
    def test_all_required_env_vars_set(self):
        required = [
            "ENVIRONMENT",
            "BOT_TOKEN",
            "ANTHROPIC_API_KEY",
            "DATABASE_URL",
            "REDIS_URL",
            "ADMIN_IDS",
            "BACKEND_URL",
        ]
        for var in required:
            value = os.environ.get(var, "")
            assert value, f"Required env var {var} is not set"

    def test_environment_valid_value(self):
        env = os.environ.get("ENVIRONMENT", "")
        assert env in ("development", "production"), f"ENVIRONMENT must be development or production, got: {env}"


# ===================================================================
# Import health checks — all critical modules importable
# ===================================================================

class TestImportHealth:
    def test_import_config(self):
        mod = importlib.import_module("config")
        assert hasattr(mod, "settings")
        assert hasattr(mod, "PLAN_LIMITS")

    def test_import_database_models(self):
        mod = importlib.import_module("database.models")
        assert hasattr(mod, "User")
        assert hasattr(mod, "ScanLog")
        assert hasattr(mod, "ModerationLog")
        assert hasattr(mod, "BotUser")
        assert hasattr(mod, "UserModeration")

    def test_import_scanner_service(self):
        mod = importlib.import_module("services.scanner")
        assert hasattr(mod, "AsyncScannerService")
        assert hasattr(mod, "ScannerService")

    def test_import_formatter(self):
        mod = importlib.import_module("services.formatter")
        assert hasattr(mod, "format_phone")
        assert hasattr(mod, "format_url")
        assert hasattr(mod, "format_file")

    def test_import_origin_intel(self):
        mod = importlib.import_module("services.origin_intel")
        assert hasattr(mod, "OriginIntelligenceService")

    def test_import_transcription(self):
        mod = importlib.import_module("services.transcription")
        assert hasattr(mod, "WhisperTranscriptionService")

    def test_import_handlers(self):
        for handler_name in ["start", "phone", "url", "file", "image", "voice", "social"]:
            mod = importlib.import_module(f"handlers.{handler_name}")
            register_fn = f"register_{handler_name}_handlers"
            assert hasattr(mod, register_fn), f"handlers.{handler_name} missing {register_fn}"

    def test_import_middleware(self):
        mod_moderation = importlib.import_module("middleware.moderation")
        assert hasattr(mod_moderation, "run_moderation")
        assert hasattr(mod_moderation, "require_moderation")

        mod_guards = importlib.import_module("middleware.guards")
        assert hasattr(mod_guards, "check_text_policy")

        mod_quota = importlib.import_module("middleware.quota")
        assert hasattr(mod_quota, "QuotaGuard")
        assert hasattr(mod_quota, "check_quota")

    def test_import_app_modules(self):
        from app.schemas import ScanRequest, ScanResult, ScanResponse
        assert ScanRequest is not None
        assert ScanResult is not None

        from app.services.ai_client import ClaudeClient
        assert ClaudeClient is not None

        from app.services.cache import get_cached_scan, set_cached_scan
        assert callable(get_cached_scan)

    def test_import_fraud_scanner(self):
        from app.services.fraud_scanner import FraudScannerService
        assert FraudScannerService is not None

    def test_import_threat_intel(self):
        from app.services.threat_intel import ThreatIntelService
        assert ThreatIntelService is not None

    def test_import_compliance(self):
        from app.security.compliance import enforce_user_provided_only, pseudonymize_user_id
        assert callable(enforce_user_provided_only)
        assert callable(pseudonymize_user_id)


# ===================================================================
# Project structure validation
# ===================================================================

class TestProjectStructure:
    def test_bot_directory_structure(self):
        bot_root = PROJECT_ROOT / "cyberguard-telegram"
        assert (bot_root / "handlers").is_dir()
        assert (bot_root / "services").is_dir()
        assert (bot_root / "middleware").is_dir()
        assert (bot_root / "database").is_dir()
        assert (bot_root / "config.py").is_file()

    def test_app_directory_structure(self):
        app_root = PROJECT_ROOT / "app"
        assert (app_root / "api").is_dir()
        assert (app_root / "services").is_dir()
        assert (app_root / "db").is_dir()
        assert (app_root / "security").is_dir()
        assert (app_root / "schemas.py").is_file()
        assert (app_root / "config.py").is_file()

    def test_tests_directory_exists(self):
        tests_dir = PROJECT_ROOT / "tests"
        assert tests_dir.is_dir()
        assert (tests_dir / "conftest.py").is_file()

    def test_pyproject_toml_exists(self):
        pyproject = PROJECT_ROOT / "pyproject.toml"
        assert pyproject.exists(), "pyproject.toml is missing"


# ===================================================================
# Pyproject.toml validation
# ===================================================================

class TestPyprojectConfig:
    def test_pyproject_valid_toml(self):
        import tomllib
        path = PROJECT_ROOT / "pyproject.toml"
        if not path.exists():
            pytest.skip("pyproject.toml not found")
        with open(path, "rb") as f:
            data = tomllib.load(f)
        assert "tool" in data
        assert "pytest" in data["tool"]

    def test_pyproject_pytest_config(self):
        import tomllib
        path = PROJECT_ROOT / "pyproject.toml"
        if not path.exists():
            pytest.skip("pyproject.toml not found")
        with open(path, "rb") as f:
            data = tomllib.load(f)
        pytest_config = data["tool"]["pytest"]["ini_options"]
        assert pytest_config["asyncio_mode"] == "auto"
        assert "tests" in pytest_config.get("testpaths", [])
