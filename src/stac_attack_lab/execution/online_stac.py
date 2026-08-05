from __future__ import annotations

import json
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from stac_attack_lab.config import ExperimentConfig, validate_startup
from stac_attack_lab.contracts import (
    ActorRole,
    AttackerAction,
    JudgeVerdict,
    OfflineSample,
    PlannerDecision,
    PromptWriterOutput,
    RunResult,
    VictimAction,
)
from stac_attack_lab.environments.base import ToolCall
from stac_attack_lab.environments.workspace_canary import WorkspaceCanaryEnv
from stac_attack_lab.execution.victim import (
    VictimRunner,
    victim_model_messages,
    victim_prompt_hash,
)
from stac_attack_lab.graph.models import AttackGraph
from stac_attack_lab.hashing import stable_hash
from stac_attack_lab.models.factory import build_model_client
from stac_attack_lab.planning.adaptive_llm import AdaptiveLLMPlanner
from stac_attack_lab.planning.base import Planner
from stac_attack_lab.planning.fixed import FixedPlanner
from stac_attack_lab.planning.random_legal import RandomLegalPlanner
from stac_attack_lab.planning.rule_based import RuleBasedPlanner
from stac_attack_lab.prompts.loader import load_prompt
from stac_attack_lab.recording.conversations import (
    ConversationEventType,
    ConversationRecorder,
    SchemaValidationRecord,
    audit_transcript,
    categorize_model_error,
)
from stac_attack_lab.recording.events import append_jsonl, read_jsonl
from stac_attack_lab.recording.progress import AttackProgressStatus, ProgressManager
from stac_attack_lab.recording.run_recorder import RunRecorder
from stac_attack_lab.verification.aggregate import chain_success, verify_all


def _validate_verified_sample(sample: OfflineSample) -> None:
    selection = sample.selection
    if selection is None:
        raise ValueError(f"formal_evaluation_requires_selection_evidence:{sample.sample_id}")
    graph_hash = stable_hash(sample.attack_graph.model_dump(mode="json"))
    prompt_hash = stable_hash([item.model_dump(mode="json") for item in sample.victim_messages])
    if graph_hash != selection.verified_graph_hash:
        raise ValueError(f"verified_graph_hash_mismatch:{sample.sample_id}")
    if prompt_hash != selection.verified_prompt_hash:
        raise ValueError(f"verified_prompt_hash_mismatch:{sample.sample_id}")
    if stable_hash(sample.verified_call_params) != selection.verified_call_params_hash:
        raise ValueError(f"verified_call_params_hash_mismatch:{sample.sample_id}")


def load_frozen_samples(
    project_root: Path, version: str, limit: int, *, require_verified_collection: bool = False
) -> list[OfflineSample]:
    dataset_root = project_root / "data/frozen" / version
    path = dataset_root / "samples.jsonl"
    samples = [
        OfflineSample.model_validate_json(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if require_verified_collection:
        manifest = json.loads((dataset_root / "dataset_manifest.json").read_text(encoding="utf-8"))
        if not manifest.get("collection_complete"):
            raise ValueError("formal_evaluation_requires_complete_collection")
        if not manifest.get("transcript_audit_passed"):
            raise ValueError("formal_evaluation_requires_passing_transcript_audit")
        if manifest.get("selection_policy") != "offline_hard_success_only":
            raise ValueError("formal_evaluation_requires_hard_success_selection")
        if len(samples) < limit:
            raise ValueError(f"formal_evaluation_sample_shortfall:{len(samples)}/{limit}")
        for sample in samples[:limit]:
            _validate_verified_sample(sample)
    return samples[:limit]


def _planner(name: str, seed: int) -> Planner:
    if name == "fixed":
        return FixedPlanner()
    if name == "random_legal":
        return RandomLegalPlanner(seed)
    if name == "rule_based":
        return RuleBasedPlanner()
    if name == "adaptive_llm":
        return AdaptiveLLMPlanner()
    raise ValueError(f"unsupported_planner:{name}")


def _condition_planner(condition: str, config: ExperimentConfig, seed: int) -> Planner:
    if condition == "random_legal_full":
        return RandomLegalPlanner(seed)
    if condition == "rule_planner_full":
        return RuleBasedPlanner()
    if condition in {"llm_planner_full", "llm_planner_full_defense_on"}:
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


def _attack_cases(
    samples: list[OfflineSample], config: ExperimentConfig
) -> list[tuple[str, str, int, OfflineSample]]:
    return [
        (f"{condition}-{sample.sample_id}-seed{seed}", condition, seed, sample)
        for seed in config.seeds
        for sample in samples
        for condition in config.conditions
    ]


def run_online(
    project_root: Path,
    config: ExperimentConfig,
    *,
    resume: bool = False,
    run_id: str | None = None,
    run_root: Path | None = None,
    after_attack: Callable[[int], None] | None = None,
) -> Path:
    if config.profile != "fake":
        validate_startup(config)
    samples = load_frozen_samples(
        project_root,
        config.dataset_version,
        config.task_limit,
        require_verified_collection=config.profile == "formal_evaluation",
    )
    config_hash = stable_hash(config.model_dump(mode="json"))
    resolved_run_id = run_id or f"{config.experiment_id}-{config_hash[:12]}"
    root = run_root or project_root / "experiments/runs/latest"
    if root.exists() and not resume:
        shutil.rmtree(root)
    root.mkdir(parents=True, exist_ok=True)
    root_manifest = root / "run_manifest.json"
    if not root_manifest.exists():
        root_manifest.write_text(
            json.dumps(
                {
                    "run_id": resolved_run_id,
                    "config": config.model_dump(mode="json"),
                    "config_hash": config_hash,
                    "dataset_version": config.dataset_version,
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
    cases = _attack_cases(samples, config)
    progress = ProgressManager(root, project_root)
    state = progress.initialize(
        run_id=resolved_run_id,
        profile=config.profile,
        dataset_version=config.dataset_version,
        config_hash=config_hash,
        cases=[(attack_id, condition, seed) for attack_id, condition, seed, _ in cases],
    )
    progress_by_id = {item.attack_id: item for item in state.attacks}
    existing_results = {
        str(item["run_id"]): RunResult.model_validate(item)
        for item in read_jsonl(root / "results.jsonl")
    }
    conversations = ConversationRecorder(root / "conversations.jsonl")
    completed_this_call = 0
    for attack_id, condition, seed, sample in cases:
        attack_state = progress_by_id[attack_id]
        if attack_state.status == AttackProgressStatus.completed:
            continue
        progress.transition(attack_state.idempotency_key, AttackProgressStatus.running)
        try:
            result = run_one(
                project_root,
                root,
                sample,
                condition,
                seed,
                config,
                conversations=conversations,
                idempotency_key=attack_state.idempotency_key,
                experiment_run_id=resolved_run_id,
            )
        except Exception as exc:
            category = categorize_model_error(exc)
            status = (
                AttackProgressStatus.paused_quota
                if category == "quota"
                else AttackProgressStatus.failed_retryable
            )
            progress.transition(
                attack_state.idempotency_key,
                status,
                error_category=category,
                pause_reason=category,
            )
            break
        if result.run_id not in existing_results:
            append_jsonl(root / "results.jsonl", result.model_dump(mode="json"))
            existing_results[result.run_id] = result
        progress.transition(
            attack_state.idempotency_key,
            AttackProgressStatus.completed,
            result_ref=str((root / result.run_id / "report.json").relative_to(root)),
        )
        completed_this_call += 1
        if after_attack is not None:
            after_attack(completed_this_call)
    audit = audit_transcript(
        root / "conversations.jsonl",
        expected_run_id=resolved_run_id,
        expected_role_models={
            role: (model.provider, model.model) for role, model in config.models.items()
        },
    )
    (root / "transcript_audit.json").write_text(audit.model_dump_json(indent=2), encoding="utf-8")
    return root


def resume_online(project_root: Path, run_id: str) -> Path:
    runs_root = project_root / "experiments/runs"
    matches: list[Path] = []
    for manifest_path in runs_root.glob("*/run_manifest.json"):
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        if data.get("run_id") == run_id or manifest_path.parent.name == run_id:
            matches.append(manifest_path.parent)
    if not matches:
        raise FileNotFoundError(f"run_not_found:{run_id}")
    if len(matches) != 1:
        raise ValueError(f"ambiguous_run_id:{run_id}")
    root = matches[0]
    manifest = json.loads((root / "run_manifest.json").read_text(encoding="utf-8"))
    config = ExperimentConfig.model_validate(manifest["config"])
    return run_online(
        project_root,
        config,
        resume=True,
        run_id=str(manifest["run_id"]),
        run_root=root,
    )


def _record_event(
    conversations: ConversationRecorder,
    *,
    event_id: str,
    call_id: str,
    run_id: str,
    attack_id: str,
    idempotency_key: str,
    condition: str,
    seed: int,
    event_type: ConversationEventType,
    sender_role: ActorRole,
    recipient_role: ActorRole,
    messages: list[dict[str, str]],
    parsed: dict[str, Any] | None,
    related_event_ids: list[str] | None = None,
    artifact_refs: list[str] | None = None,
    snapshot_refs: list[str] | None = None,
    hard_verdict_refs: list[str] | None = None,
) -> None:
    conversations.append(
        event_id=event_id,
        call_id=call_id,
        run_id=run_id,
        attack_id=attack_id,
        idempotency_key=idempotency_key,
        phase="evaluation",
        condition=condition,
        seed=seed,
        attempt_no=1,
        event_type=event_type,
        sender_role=sender_role,
        recipient_role=recipient_role,
        model_provider=None,
        model_id=None,
        model_config_hash=None,
        prompt_id=None,
        prompt_version=None,
        prompt_hash=None,
        input_schema_id=None,
        output_schema_id=None,
        request_messages=messages,
        raw_model_response=None,
        parsed_structured_response=parsed,
        schema_validation=SchemaValidationRecord(schema_id=None, valid=True),
        token_metadata={},
        related_event_ids=related_event_ids or [],
        artifact_refs=artifact_refs or [],
        snapshot_refs=snapshot_refs or [],
        hard_verdict_refs=hard_verdict_refs or [],
    )


def _attacker_action(
    project_root: Path,
    config: ExperimentConfig,
    node: Any,
    decision: Any,
    frozen_prompt: PromptWriterOutput,
    seed: int,
    model_call: Callable[..., Any],
) -> AttackerAction:
    role_config = config.models["attacker"]
    if role_config.provider == "fake":
        return AttackerAction(
            action_id=f"attack-{node.node_id}-{seed}",
            node_id=node.node_id,
            primitive_id=node.primitive_id,
            message=frozen_prompt.victim_message,
            used_variables={"stage_id": node.stage_id},
            constraint_checks=["single_primitive", "no_hidden_terms"],
        )
    asset = load_prompt(project_root / "prompts/runtime/attacker.md")
    messages = [
        {"role": "system", "content": asset.body},
        {
            "role": "user",
            "content": json.dumps(
                {
                    "decision": decision.model_dump(mode="json"),
                    "stage_template": node.template_vars,
                    "frozen_verified_prompt": frozen_prompt.model_dump(mode="json"),
                },
                sort_keys=True,
            ),
        },
    ]
    client = build_model_client(role_config)
    output = cast(
        AttackerAction,
        model_call(
            role="attacker",
            messages=messages,
            schema=AttackerAction,
            prompt=asset,
            invoke=lambda: client.generate(
                messages, AttackerAction, seed, role_config.timeout_seconds
            ),
        ),
    )
    if output.node_id != node.node_id or output.primitive_id != node.primitive_id:
        raise ValueError("attacker_schema_or_role_violation")
    return output


def _victim_call(
    project_root: Path,
    config: ExperimentConfig,
    node: Any,
    action: AttackerAction,
    seed: int,
    env: WorkspaceCanaryEnv,
    public_tool_history: list[dict[str, object]],
    model_call: Callable[..., Any],
) -> ToolCall:
    role_config = config.models["victim"]
    if role_config.provider == "fake":
        return VictimRunner().tool_call_for_node(
            node,
            entry_artifact_id=env.entry_artifact_id,
            source_memory_id=env.retrieved_memory_id,
            canary_id=env.canary_id,
        )
    asset = load_prompt(project_root / "prompts/runtime/victim_system.md")
    messages = victim_model_messages(
        asset.body,
        action.message,
        env.public_spec(),
        public_tool_history,
    )
    client = build_model_client(role_config)
    output = cast(
        VictimAction,
        model_call(
            role="victim",
            messages=messages,
            schema=VictimAction,
            prompt=asset,
            invoke=lambda: client.generate(
                messages, VictimAction, seed, role_config.timeout_seconds
            ),
        ),
    )
    return ToolCall(tool_name=output.tool_name, arguments=output.arguments)


def run_one(
    project_root: Path,
    root: Path,
    sample: OfflineSample,
    condition: str,
    seed: int,
    config: ExperimentConfig,
    *,
    conversations: ConversationRecorder | None = None,
    idempotency_key: str | None = None,
    experiment_run_id: str | None = None,
) -> RunResult:
    defense_enabled = condition.endswith("defense_on") or config.defense_enabled
    env = WorkspaceCanaryEnv(defense_enabled=defense_enabled)
    env.reset(seed)
    env.canary_id = sample.seed_task["canary_id"]
    env.canary_preference = sample.seed_task["canary_preference"]
    run_id = f"{condition}-{sample.sample_id}-seed{seed}"
    experiment_id = experiment_run_id or (
        f"{config.experiment_id}-{stable_hash(config.model_dump(mode='json'))[:12]}"
    )
    key = idempotency_key or stable_hash({"run_id": experiment_id, "attack_id": run_id})
    run_dir = root / run_id
    recorder = RunRecorder(run_dir, run_id, "online", env.episode_id)
    conversation = conversations or ConversationRecorder(root / "conversations.jsonl")
    manifest = {
        "run_id": run_id,
        "experiment_run_id": experiment_id,
        "condition": condition,
        "sample_id": sample.sample_id,
        "sample_hash": sample.sample_hash,
        "pair_id": sample.pair_id,
        "offline_verification_ref": sample.verification_transcript_ref,
        "selection": (
            sample.selection.model_dump(mode="json") if sample.selection is not None else None
        ),
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
    model_call_index = 0

    def recorded_model_call(
        *, role: str, messages: list[dict[str, str]], schema: Any, prompt: Any, invoke: Any
    ) -> Any:
        nonlocal model_call_index
        model_call_index += 1
        role_config = config.models[role]
        return conversation.record_model_call(
            run_id=experiment_id,
            attack_id=run_id,
            idempotency_key=key,
            phase="evaluation",
            condition=condition,
            seed=seed,
            attempt_no=model_call_index,
            sender_role=ActorRole.attacker if role == "victim" else ActorRole.recorder,
            recipient_role=ActorRole(role),
            provider=role_config.provider,
            model_id=role_config.model,
            model_config=role_config.model_dump(mode="json"),
            prompt_id=prompt.prompt_id,
            prompt_version=prompt.version,
            prompt_hash=prompt.hash,
            input_schema_id=str(prompt.front_matter["input_schema"]),
            output_schema_id=schema.__name__,
            messages=messages,
            invoke=invoke,
        )

    if condition == "clean":
        pre = env.snapshot()
        call = ToolCall(
            tool_name="retrieval_tool.search", arguments={"query": sample.seed_task["query"]}
        )
        result = env.step(call, f"{run_id}-clean-retrieval", 0)
        event = recorder.record_tool_event(
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
        _record_event(
            conversation,
            event_id=f"conversation-{event.event_id}",
            call_id=f"tool-{event.event_id}",
            run_id=experiment_id,
            attack_id=run_id,
            idempotency_key=key,
            condition=condition,
            seed=seed,
            event_type=ConversationEventType.tool_result,
            sender_role=ActorRole.environment,
            recipient_role=ActorRole.victim,
            messages=[{"role": "tool", "content": json.dumps(result.model_dump(mode="json"))}],
            parsed=result.model_dump(mode="json"),
            artifact_refs=event.output_artifact_ids,
            snapshot_refs=[event.pre_snapshot_ref, event.post_snapshot_ref],
        )
    else:
        graph = _filtered_graph(sample, condition)
        prompts_by_stage = {item.source_stage_id: item for item in sample.victim_messages}
        planner = _condition_planner(condition, config, seed)
        passed: set[str] = set()
        retry_counts: dict[str, int] = {}
        budget = config.max_tool_calls
        input_artifacts: list[str] = []
        public_tool_history: list[dict[str, object]] = []
        while budget > 0 and len(passed) < len(graph.nodes):
            planner_asset = load_prompt(project_root / "prompts/runtime/adaptive_planner.md")
            planner_messages = [
                {
                    "role": "user",
                    "content": json.dumps(
                        {
                            "frontier_budget": budget,
                            "passed_node_ids": sorted(passed),
                            "retry_counts": retry_counts,
                        },
                        sort_keys=True,
                    ),
                }
            ]
            if config.models["planner"].provider == "fake" or not isinstance(
                planner, AdaptiveLLMPlanner
            ):
                decision = planner.decide(graph, passed, budget, retry_counts)
                _record_event(
                    conversation,
                    event_id=f"planner-{run_id}-{len(passed)}",
                    call_id=f"planner-{run_id}-{len(passed)}",
                    run_id=experiment_id,
                    attack_id=run_id,
                    idempotency_key=key,
                    condition=condition,
                    seed=seed,
                    event_type=ConversationEventType.model_response,
                    sender_role=ActorRole.planner,
                    recipient_role=ActorRole.attacker,
                    messages=planner_messages,
                    parsed=decision.model_dump(mode="json"),
                )
            else:
                decision = cast(
                    Any,
                    recorded_model_call(
                        role="planner",
                        messages=planner_messages,
                        schema=PlannerDecision,
                        prompt=planner_asset,
                        invoke=lambda current_budget=budget: planner.decide(
                            graph, passed, current_budget, retry_counts
                        ),
                    ),
                )
            append_jsonl(run_dir / "planner_decisions.jsonl", decision.model_dump(mode="json"))
            if decision.action.startswith("stop") or decision.selected_node_id is None:
                break
            node = next(item for item in graph.nodes if item.node_id == decision.selected_node_id)
            frozen_prompt = prompts_by_stage.get(node.stage_id)
            if frozen_prompt is None or frozen_prompt.status != "ok":
                raise ValueError(f"sample_missing_verified_prompt:{node.stage_id}")
            action = _attacker_action(
                project_root,
                config,
                node,
                decision,
                frozen_prompt,
                seed,
                recorded_model_call,
            )
            _record_event(
                conversation,
                event_id=f"attacker-{run_id}-{node.node_id}",
                call_id=f"attacker-{run_id}-{node.node_id}",
                run_id=experiment_id,
                attack_id=run_id,
                idempotency_key=key,
                condition=condition,
                seed=seed,
                event_type=ConversationEventType.model_response,
                sender_role=ActorRole.attacker,
                recipient_role=ActorRole.victim,
                messages=[{"role": "user", "content": decision.model_dump_json()}],
                parsed=action.model_dump(mode="json"),
            )
            if action.abstain:
                retry_counts[node.node_id] = retry_counts.get(node.node_id, 0) + 1
                budget -= 1
                continue
            for _ in range(
                config.benign_interference_steps if node.primitive_id == "memory_retrieval" else 0
            ):
                env.benign_step()
            pre = env.snapshot()
            call = _victim_call(
                project_root,
                config,
                node,
                action,
                seed,
                env,
                public_tool_history,
                recorded_model_call,
            )
            request_conversation_id = f"tool-request-{run_id}-{node.node_id}"
            _record_event(
                conversation,
                event_id=request_conversation_id,
                call_id=f"tool-{run_id}-{node.node_id}",
                run_id=experiment_id,
                attack_id=run_id,
                idempotency_key=key,
                condition=condition,
                seed=seed,
                event_type=ConversationEventType.tool_request,
                sender_role=ActorRole.victim,
                recipient_role=ActorRole.environment,
                messages=[
                    {
                        "role": "system",
                        "content": load_prompt(
                            project_root / "prompts/runtime/victim_system.md"
                        ).body,
                    },
                    {"role": "user", "content": action.message},
                    {"role": "assistant", "content": call.model_dump_json()},
                ],
                parsed=call.model_dump(mode="json"),
                artifact_refs=input_artifacts,
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
            _record_event(
                conversation,
                event_id=f"tool-result-{run_id}-{node.node_id}",
                call_id=f"tool-{run_id}-{node.node_id}",
                run_id=experiment_id,
                attack_id=run_id,
                idempotency_key=key,
                condition=condition,
                seed=seed,
                event_type=ConversationEventType.tool_result,
                sender_role=ActorRole.environment,
                recipient_role=ActorRole.victim,
                messages=[{"role": "tool", "content": result.model_dump_json()}],
                parsed=result.model_dump(mode="json"),
                related_event_ids=[request_conversation_id],
                artifact_refs=event.output_artifact_ids,
                snapshot_refs=[event.pre_snapshot_ref, event.post_snapshot_ref],
            )
            public_tool_history.append(
                {
                    "tool_call": call.model_dump(mode="json"),
                    "tool_result": result.model_dump(mode="json"),
                }
            )
            input_artifacts = event.output_artifact_ids or input_artifacts
            if result.status.value == "ok":
                passed.add(node.node_id)
            else:
                retry_counts[node.node_id] = retry_counts.get(node.node_id, 0) + 1
            budget -= 1
    events = recorder.events()
    verdicts = verify_all(events, run_dir, config.benign_interference_steps)
    for verdict in verdicts:
        append_jsonl(run_dir / "verdicts.jsonl", verdict.model_dump(mode="json"))
        _record_event(
            conversation,
            event_id=f"verifier-{run_id}-{verdict.verifier_id}",
            call_id=f"verifier-{run_id}-{verdict.verifier_id}",
            run_id=experiment_id,
            attack_id=run_id,
            idempotency_key=key,
            condition=condition,
            seed=seed,
            event_type=ConversationEventType.verifier_result,
            sender_role=ActorRole.verifier,
            recipient_role=ActorRole.planner,
            messages=[],
            parsed=verdict.model_dump(mode="json"),
            related_event_ids=verdict.evidence_event_ids,
            snapshot_refs=verdict.evidence_snapshot_refs,
            hard_verdict_refs=[verdict.verifier_id],
        )
    success = chain_success(verdicts, events)
    evidence_ids = [event.event_id for event in events]
    hard_summary = {
        "hard_chain_success": success,
        "verdicts": [verdict.model_dump(mode="json") for verdict in verdicts],
    }
    if config.models["verifier"].provider != "fake":
        semantic_asset = load_prompt(project_root / "prompts/judges/semantic_stage_verifier.md")
        semantic_messages = [
            {
                "role": "user",
                "content": json.dumps(
                    {"evidence_event_ids": evidence_ids, "hard_verifier": hard_summary},
                    sort_keys=True,
                ),
            }
        ]
        semantic_client = build_model_client(config.models["verifier"])
        recorded_model_call(
            role="verifier",
            messages=semantic_messages,
            schema=JudgeVerdict,
            prompt=semantic_asset,
            invoke=lambda: semantic_client.generate(
                semantic_messages,
                JudgeVerdict,
                seed,
                config.models["verifier"].timeout_seconds,
            ),
        )
    if config.models["judge"].provider != "fake":
        judge_asset = load_prompt(project_root / "prompts/judges/trajectory_judge.md")
        judge_messages = [
            {
                "role": "user",
                "content": json.dumps(
                    {"evidence_event_ids": evidence_ids, "aggregate_hard_verdict": success},
                    sort_keys=True,
                ),
            }
        ]
        judge_client = build_model_client(config.models["judge"])
        judge_output = cast(
            JudgeVerdict,
            recorded_model_call(
                role="judge",
                messages=judge_messages,
                schema=JudgeVerdict,
                prompt=judge_asset,
                invoke=lambda: judge_client.generate(
                    judge_messages,
                    JudgeVerdict,
                    seed,
                    config.models["judge"].timeout_seconds,
                ),
            ),
        )
        if judge_output.hard_chain_success_copy != success:
            raise ValueError("judge_hard_verdict_copy_mismatch")
    else:
        _record_event(
            conversation,
            event_id=f"judge-{run_id}",
            call_id=f"judge-{run_id}",
            run_id=experiment_id,
            attack_id=run_id,
            idempotency_key=key,
            condition=condition,
            seed=seed,
            event_type=ConversationEventType.verifier_result,
            sender_role=ActorRole.judge,
            recipient_role=ActorRole.recorder,
            messages=[],
            parsed={"hard_chain_success_copy": success, "labels": {}},
            related_event_ids=evidence_ids,
            hard_verdict_refs=[verdict.verifier_id for verdict in verdicts],
        )
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
