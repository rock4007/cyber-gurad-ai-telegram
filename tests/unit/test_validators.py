import importlib.util
from pathlib import Path


def _load_phone_module():
    root = Path(__file__).resolve().parents[2]
    phone_path = root / "cyberguard-telegram" / "handlers" / "phone.py"
    spec = importlib.util.spec_from_file_location("cg_phone_handler", phone_path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_extract_phone_candidate():
    phone = _load_phone_module()
    text = "Please check this number +1 (415) 555-2671 urgently"
    candidate = phone._extract_phone_candidate(text)
    assert candidate is not None
    assert candidate.startswith("+1415")


def test_validate_phone_valid_number():
    phone = _load_phone_module()
    valid, parsed = phone._validate_phone("+14155552671")
    assert valid is True
    assert parsed is not None


def test_validate_phone_invalid_number():
    phone = _load_phone_module()
    valid, parsed = phone._validate_phone("123")
    assert valid is False
    assert parsed is None
