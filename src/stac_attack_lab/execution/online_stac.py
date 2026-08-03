from __future__ import annotations

import shutil
from pathlib import Path

from stac_attack_lab.config import ExperimentConfig
from stac_attack_lab.contracts import ActorRole, OfflineSample, RunResult
from stac_attack_lab.environments.base import ToolCall
from stac_attack_lab.environments.workspace_canary import WorkspaceCanaryEnv
from stac_attack_lab.execution.victim import VictimRunner, victim_prompt_hash
from stac_attack_lab.graph.models import AttackGraph
from stac_attack_lab.hashing import stable_hash
from stac_attack_lab.models.factory import build_model_client
from stac_attack_lab.planning.adaptive_llm import AdaptiveLLMPlanner
from stac_attack_lab.planning.base import Planner
from stac_attack_lab.planning.fixed import FixedPlanner
from stac_attack_lab.planning.random_legal import RandomLegalPlanner
from stac_attack_lab.planning.rule_based import RuleBasedPlanner
from stac_attack_lab.recording.events import append_jsonl
from stac_attack_lab.recording.run_recorder import RunRecorder
from stac_attack_lab.verification.aggregate import chain_success, verify_all


def load_frozen_samples(project_root: Path, version: str, limit: int) -> list[OfflineSample]:
    path = project_root / "data/frozen" / version / "samples.jsonl"
    return [
        OfflineSample.model_validate_json(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ][:limit]


def _planner(name: str, seed: int) -> Planner:
    if name == "fixed":
        return FixedPlanner()
    if name == "random_legal":
        return RandomLegalPlanner(seed)
    if name == "rule_based":
        return RuleBasedPlanner()
    if name == "adaptive_llm":
        return AdaptiveLLMPlanner()
    return FixedPlanner()


def _condition_planner(condition: str, config: ExperimentConfig, seed: int) -> Planner:
    if condition == "random_legal_full":
        return RandomLegalPlanner(seed)
    if condition == "rule_planner_full":
        return RuleBasedPlanner()
    if condition == "llm_planner_full" or condition == "llm_planner_full_defense_on":
        return AdaptiveLLMPlanner(build_model_client(config.models["planner"]))
    return _planner(config.planner_type, seed)


def _filtered_graph(sample: OfflineSample, condition: str) -> AttackGraph:
    graph = sample.attack_graph
    remove: set[str] = set()
    if condition == "single_entry":
        remove = {"n2", "n3", "n4"}
    elif condition == "full_minus_memory_write":
        remove = {"n2"}
    elif condition == "full_minus_retrieval":
        remove = {"n3"}
    if not remove:
        return graph
    nodes = [node for node in graph.nodes if node.node_id not in remove]
    edges = [
        edge
        for edge in graph.edges
        if edge.source_node_id not in remove and edge.target_node_id not in remove
    ]
    return graph.model_copy(update={"nodes": nodes, "edges": edges})


def run_online(project_root: Path, config: ExperimentConfig) -> Path:
    samples = load_frozen_samples(project_root, config.dataset_version, config.task_limit)
    root = project_root / "experiments/runs/latest"
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    results: list[RunResult] = []
    for seed in config.seeds:
        for sample in samples:
            for condition in config.conditions:
                run_result = run_one(project_root, root, sample, condition, seed, config)
                results.append(run_result)
    (root / "results.jsonl").write_text(
        "\n".join(result.model_dump_json() for result in results) + "\n", encoding="utf-8"
    )
    return root


def run_one(
    project_root: Path,
    root: Path,
    sample: OfflineSample,
    condition: str,
    seed: int,
    config: ExperimentConfig,
) -> RunResult:
    defense_enabled = condition.endswith("defense_on") or config.defense_enabled
    env = WorkspaceCanaryEnv(defense_enabled=defense_enabled)
    env.reset(seed)
    env.canary_id = sample.seed_task["canary_id"]
    env.canary_preference = sample.seed_task["canary_preference"]
    run_id = f"{condition}-{sample.sample_id}-seed{seed}"
    run_dir = root / run_id
    recorder = RunRecorder(run_dir, run_id, "online", env.episode_id)
    manifest = {
        "run_id": run_id,
        "condition": condition,
        "sample_id": sample.sample_id,
        "pair_id": sample.pair_id,
        "seed": seed,
        "victim_prompt_hash": victim_prompt_hash(project_root),
        "model_roles": {
            role: model.model_dump(mode="json") for role, model in config.models.items()
        },
        "budgets": {
            "max_turns": config.max_turns,
            "max_tool_calls": config.max_tool_calls,
            "max_tokens": config.max_tokens,
        },
        "defense_enabled": defense_enabled,
    }
    recorder.write_manifest(manifest)
    if condition == "clean":
        pre = env.snapshot()
        call = ToolCall(
            tool_name="retrieval_tool.search", arguments={"query": sample.seed_task["query"]}
        )
        result = env.step(call, f"{run_id}-clean-retrieval", 0)
        recorder.record_tool_event(
            event_id=f"{run_id}-clean-retrieval",
            actor_role=ActorRole.victim,
            stage_id="clean",
            primitive_id=None,
            call=call,
            result=result,
            pre_snapshot=pre,
            post_snapshot=env.snapshot(),
            input_artifact_ids=[],
        )
    else:
        graph = _filtered_graph(sample, condition)
        planner = _condition_planner(condition, config, seed)
        victim = VictimRunner()
        passed: set[str] = set()
        retry_counts: dict[str, int] = {}
        budget = config.max_tool_calls
        input_artifacts: list[str] = []
        while budget > 0 and len(passed) < len(graph.nodes):
            decision = planner.decide(graph, passed, budget, retry_counts)
            append_jsonl(run_dir / "planner_decisions.jsonl", decision.model_dump(mode="json"))
            if decision.action.startswith("stop") or decision.selected_node_id is None:
                break
            node = next(item for item in graph.nodes if item.node_id == decision.selected_node_id)
            for _ in range(
                config.benign_interference_steps if node.primitive_id == "memory_retrieval" else 0
            ):
                env.benign_step()
            pre = env.snapshot()
            call = victim.tool_call_for_node(
                node,
                entry_artifact_id=env.entry_artifact_id,
                source_memory_id=env.retrieved_memory_id,
                canary_id=env.canary_id,
            )
            result = env.step(call, f"{run_id}-{node.node_id}", len(passed))
            event = recorder.record_tool_event(
                event_id=f"{run_id}-{node.node_id}",
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
            if result.status.value == "ok":
                passed.add(node.node_id)
            budget -= 1
    events = recorder.events()
    verdicts = verify_all(events, run_dir, config.benign_interference_steps)
    for verdict in verdicts:
        append_jsonl(run_dir / "verdicts.jsonl", verdict.model_dump(mode="json"))
    success = chain_success(verdicts, events)
    run_result = RunResult(
        run_id=run_id,
        condition=condition,
        pair_id=sample.pair_id,
        config_hash=stable_hash(config.model_dump(mode="json")),
        sample_hash=sample.sample_hash,
        initial_snapshot_hash=stable_hash(WorkspaceCanaryEnv().snapshot()),
        stage_verdicts={v.verifier_id: v.verdict.value for v in verdicts},
        chain_verdict=success,
        utility_success=True,
        tool_calls=len(events),
        tokens=0,
        duration_ms=0,
        retries=0,
        reroutes=0,
        defense_enabled=defense_enabled,
        planner_type=_condition_planner(condition, config, seed).planner_type,
        seed=seed,
        model_versions={role: model.model for role, model in config.models.items()},
        paths={"run_dir": str(run_dir)},
    )
    (run_dir / "report.json").write_text(run_result.model_dump_json(indent=2), encoding="utf-8")
    recorder.record_status("success")
    return run_result
