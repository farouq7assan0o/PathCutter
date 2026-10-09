"""Seeds that once broke an engine, plus a smoke sweep of the same differential checks used by tests/fuzz.py."""
import pytest

from fuzz import check

KNOWN = [34467, 35703, 36970, 37529, 38827, 46861, 51695, 54001]    # incremental exposure: stale verdict on nodes that
                                                                    # needed the exact simple-path check in the base


@pytest.mark.parametrize("seed", KNOWN)
def test_known_failing_seeds(seed):
    assert check(seed) is None


@pytest.mark.parametrize("seed", range(1000000, 1004000))
def test_differential_smoke(seed):
    assert check(seed) is None
