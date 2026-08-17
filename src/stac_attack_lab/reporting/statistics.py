from __future__ import annotations

from math import comb, sqrt


def wilson_ci(successes: int, total: int) -> tuple[float, float]:
    if total == 0:
        return 0.0, 0.0
    z = 1.96
    phat = successes / total
    denom = 1 + z * z / total
    center = (phat + z * z / (2 * total)) / denom
    margin = z * sqrt((phat * (1 - phat) + z * z / (4 * total)) / total) / denom
    return max(0.0, center - margin), min(1.0, center + margin)


def mcnemar_exact(b: int, c: int) -> float:
    if b < 0 or c < 0:
        raise ValueError("mcnemar_discordant_counts_must_be_nonnegative")
    discordant = b + c
    if discordant == 0:
        return 1.0
    lower_tail: float = sum(int(comb(discordant, k)) for k in range(min(b, c) + 1)) / (
        2**discordant
    )
    return min(1.0, 2 * lower_tail)
