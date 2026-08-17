from __future__ import annotations

from typing import Protocol, TypeVar

RequestT = TypeVar("RequestT", contravariant=True)
MaterializedTaskT = TypeVar("MaterializedTaskT", contravariant=True)
ResultT = TypeVar("ResultT", covariant=True)


class EpisodeEnvironment(Protocol[RequestT, MaterializedTaskT, ResultT]):
    """Environment contract for one atomic, multi-session benchmark episode."""

    def run_episode(
        self,
        request: RequestT,
        materialized_task: MaterializedTaskT,
        *,
        resume: bool = True,
    ) -> ResultT: ...
