from __future__ import annotations

import subprocess
import sys
from time import monotonic

import pytest

from stac_attack_lab.execution.deadline import wall_clock_deadline
from stac_attack_lab.interactions.base import CollectionBudget
from stac_attack_lab.interactions.safeclaw_collection import SafeClawSubprocessVictimDriver


def test_deadline_interrupts_blocked_pipe_and_reaps_child() -> None:
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"], stdout=subprocess.PIPE, text=True
    )
    started = monotonic()
    try:
        assert child.stdout is not None
        with pytest.raises(TimeoutError, match="wall_time_budget"), wall_clock_deadline(0.1):
            child.stdout.readline()
    finally:
        child.terminate()
        child.wait(timeout=2)
        if child.stdout:
            child.stdout.close()
    assert monotonic() - started < 2


def test_driver_abort_cannot_wait_forever_for_finish() -> None:
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    driver = object.__new__(SafeClawSubprocessVictimDriver)
    driver._process = child
    driver._budget = CollectionBudget()
    driver._stderr = None
    driver._temporary = None
    started = monotonic()
    try:
        driver.abort()
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=2)
        if child.stdin:
            child.stdin.close()
        if child.stdout:
            child.stdout.close()
    assert child.poll() is not None
    assert monotonic() - started < 8
    assert driver._process is None


def test_nested_deadline_does_not_extend_outer() -> None:
    import time

    started = monotonic()
    with pytest.raises(TimeoutError), wall_clock_deadline(0.1), wall_clock_deadline(10):
        time.sleep(2)
    assert monotonic() - started < 1
