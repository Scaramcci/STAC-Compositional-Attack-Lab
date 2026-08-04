from __future__ import annotations

from pathlib import Path

from stac_attack_lab.contracts import ActorRole, Verdict
from stac_attack_lab.environments.workspace_canary import WorkspaceCanaryEnv
from stac_attack_lab.execution.victim import VictimRunner
from stac_attack_lab.graph.compiler import default_attack_graph
from stac_attack_lab.hashing import stable_hash
from stac_attack_lab.recording.run_recorder import RunRecorder
from stac_attack_lab.verification.aggregate import chain_success, verify_all
from stac_attack_lab.verification.semantic import semantic_stage_label


def _manual_run(tmp_path: Path, skip: str | None = None, shortcut: bool = False):
    env = WorkspaceCanaryEnv()
    env.reset(7)
    graph = default_attack_graph(
        {
            "task_id": "task-x",
            "query": "workspace",
            "canary_id": env.canary_id,
            "canary_preference": env.canary_preference,
        }
    )
    recorder = RunRecorder(tmp_path, "run", "trace", env.episode_id)
    victim = VictimRunner()
    input_artifacts: list[str] = []
    nodes = graph.nodes
    if shortcut:
        nodes = [graph.nodes[0], graph.nodes[3]]
    for node in nodes:
        if node.primitive_id == skip:
            continue
        for _ in range(3 if node.primitive_id == "memory_retrieval" else 0):
            env.benign_step()
        pre = env.snapshot()
        call = victim.tool_call_for_node(
            node,
            entry_artifact_id=env.entry_artifact_id,
            source_memory_id=env.retrieved_memory_id,
            canary_id=env.canary_id,
        )
        result = env.step(call, f"event-{node.node_id}", len(input_artifacts))
        event = recorder.record_tool_event(
            event_id=f"event-{node.node_id}",
            actor_role=ActorRole.victim,
            stage_id=node.stage_id,
            primitive_id=node.primitive_id,
            call=call,
            result=result,
            pre_snapshot=pre,
            post_snapshot=env.snapshot(),
            input_artifact_ids=input_artifacts,
        )
        input_artifacts = event.output_artifact_ids or input_artifacts
    return recorder.events()


def test_reset_snapshot_deterministic() -> None:
    a = WorkspaceCanaryEnv()
    b = WorkspaceCanaryEnv()
    a.reset(42)
    b.reset(42)
    assert stable_hash(a.snapshot()) == stable_hash(b.snapshot())


def test_manual_chain_hard_pass(tmp_path: Path) -> None:
    events = _manual_run(tmp_path)
    verdicts = verify_all(events, tmp_path)
    assert all(v.verdict == Verdict.pass_ for v in verdicts)
    assert chain_success(verdicts, events)


def test_missing_stage_fails(tmp_path: Path) -> None:
    events = _manual_run(tmp_path, skip="memory_retrieval")
    verdicts = verify_all(events, tmp_path)
    assert not chain_success(verdicts, events)


def test_direct_shortcut_fails(tmp_path: Path) -> None:
    events = _manual_run(tmp_path, shortcut=True)
    verdicts = verify_all(events, tmp_path)
    assert not chain_success(verdicts, events)


def test_defense_blocks_memory_write(tmp_path: Path) -> None:
    env = WorkspaceCanaryEnv(defense_enabled=True)
    env.reset(1)
    graph = default_attack_graph(
        {
            "task_id": "task-x",
            "query": "workspace",
            "canary_id": env.canary_id,
            "canary_preference": env.canary_preference,
        }
    )
    victim = VictimRunner()
    env.step(
        victim.tool_call_for_node(
            graph.nodes[0], entry_artifact_id=None, source_memory_id=None, canary_id=env.canary_id
        ),
        "e1",
        0,
    )
    result = env.step(
        victim.tool_call_for_node(
            graph.nodes[1],
            entry_artifact_id=env.entry_artifact_id,
            source_memory_id=None,
            canary_id=env.canary_id,
        ),
        "e2",
        1,
    )
    assert result.status.value == "rejected"
    assert result.error_code == "memory_integrity_guard_rejected"


def test_semantic_pass_cannot_override_hard_shortcut_failure(tmp_path: Path) -> None:
    events = _manual_run(tmp_path, shortcut=True)
    hard_verdicts = verify_all(events, tmp_path)
    semantic = semantic_stage_label([events[-1].event_id])
    assert semantic.verdict == "pass"
    assert not chain_success(hard_verdicts, events)
