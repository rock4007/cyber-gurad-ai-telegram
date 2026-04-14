import pytest

from app.security.compliance import CONSENT_ERROR, enforce_user_provided_only, hash_content, pseudonymize_user_id


def test_consent_enforced():
    with pytest.raises(ValueError) as exc:
        enforce_user_provided_only("test content", False)
    assert CONSENT_ERROR in str(exc.value)


def test_pseudonymize_user_id_hashes():
    hashed = pseudonymize_user_id("user-123")
    assert isinstance(hashed, str)
    assert len(hashed) == 64


def test_hash_content_stable():
    assert hash_content("abc") == hash_content("abc")
