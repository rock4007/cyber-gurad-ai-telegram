import time

from app.security.compliance import hash_content


def test_bulk_hashing_load_smoke():
    start = time.perf_counter()
    for idx in range(1000):
        hash_content(f"payload-{idx}")
    elapsed = time.perf_counter() - start

    # Smoke threshold to catch obvious performance regressions.
    assert elapsed < 2.0
