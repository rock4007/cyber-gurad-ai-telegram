from app.security.compliance import enforce_user_provided_only, pseudonymize_user_id


def test_enforce_user_provided_only_requires_consent() -> None:
    try:
        enforce_user_provided_only("Suspicious SMS", consent_confirmed=False)
        assert False, "Expected ValueError"
    except ValueError:
        assert True


def test_pseudonymize_user_id() -> None:
    hashed = pseudonymize_user_id("12345")
    assert hashed is not None
    assert hashed != "12345"
    assert len(hashed) == 64
