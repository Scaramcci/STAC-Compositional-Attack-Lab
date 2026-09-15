"""POSIX deadlines that interrupt blocking I/O, with bounded nested cleanup."""

from __future__ import annotations

import signal
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from time import monotonic
from types import FrameType


@contextmanager
def wall_clock_deadline(seconds: float) -> Iterator[None]:
    if seconds <= 0:
        raise TimeoutError("construction_wall_time_budget_exhausted")
    if threading.current_thread() is not threading.main_thread():
        raise RuntimeError("construction_deadline_requires_main_thread")
    previous_handler = signal.getsignal(signal.SIGALRM)
    previous_delay, previous_interval = signal.getitimer(signal.ITIMER_REAL)
    started = monotonic()

    def expired(signum: int, frame: FrameType | None) -> None:
        del signum, frame
        raise TimeoutError("construction_wall_time_budget_exhausted")

    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(
        signal.ITIMER_REAL, min(seconds, previous_delay) if previous_delay else seconds
    )
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        remaining = previous_delay - (monotonic() - started)
        if previous_delay and remaining > 0:
            signal.setitimer(signal.ITIMER_REAL, remaining, previous_interval)
