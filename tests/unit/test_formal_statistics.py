from __future__ import annotations

import pytest

from stac_attack_lab.reporting.statistics import mcnemar_exact


def test_mcnemar_exact_matches_hand_computed_binomial_tail() -> None:
    assert mcnemar_exact(1, 3) == 0.625
    assert mcnemar_exact(0, 0) == 1.0
    assert mcnemar_exact(0, 4) == 0.125


def test_mcnemar_exact_rejects_negative_counts() -> None:
    with pytest.raises(ValueError, match="must_be_nonnegative"):
        mcnemar_exact(-1, 2)
