from __future__ import annotations

from math import sqrt


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
    return 1.0 if b + c == 0 else min(1.0, 2 * min(b, c) / (b + c))
