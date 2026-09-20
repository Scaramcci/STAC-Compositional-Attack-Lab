from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from stac_attack_lab.flow.models import (
    Artifact,
    ClaimVerdict,
    DependencyClaim,
    DependencyRelation,
    DomainRef,
    EvidenceMethod,
    EvidenceRef,
    ExecutionStatus,
    FlowObservation,
    InterventionResult,
    ObservationProfile,
    PrimitiveKind,
)
from stac_attack_lab.flow.profile import load_observation_profile
from stac_attack_lab.hashing import stable_hash
from stac_attack_lab.interactions.collector import InteractionCollectionPlan, collect_interactions
from stac_attack_lab.interactions.fixture_adapter import JsonlFixtureInteractionAdapter
from stac_attack_lab.interactions.flow_v3 import (
    observations_from_interaction_graph,
    project_effect_graph,
)
from stac_attack_lab.interactions.models import InteractionGraph
from stac_attack_lab.interactions.normalizer import normalize_trajectory
from stac_attack_lab.verification.flow_v3 import verify_effect_graph

ROOT = Path(__file__).resolve().parents[2]
PROFILE_PATH = ROOT / "configs/flow/observation_profile_v3.json"
LEGACY_FIXTURE = ROOT / "tests/fixtures/interactions/authorized_synthetic.jsonl"
FACT_MATRIX = ROOT / "tests/fixtures/flow_v3/fact_matrix.json"


def _profile() -> ObservationProfile:
    return load_observation_profile(PROFILE_PATH)


def _evidence(
    evidence_id: str, method: EvidenceMethod = EvidenceMethod.direct_observation
) -> EvidenceRef:
    return EvidenceRef(
        evidence_id=evidence_id,
        producer="synthetic_fixture",
        locator=f"fixture:{evidence_id}",
        content_hash=stable_hash(evidence_id),
        hash_scope="synthetic_fixture_record",
        privacy_scope="public",
        method=method,
        method_version="1.0",
        sealed_input_id="fixture-seal",
    )


def _domain(name: str, evidence_id: str = "ev") -> DomainRef:
    return DomainRef(
        domain_id=f"domain:{name}",
        instance_id=f"instance:{name}",
        role=name,
        actual_session_id=f"session:{name}",
        workspace_scope="workspace:one",
        tenant_scope="tenant:fixture",
        identity_evidence_ids=[evidence_id],
    )


def _artifact(name: str, source: str, *, content: str = "same") -> Artifact:
    return Artifact(
        artifact_id=f"artifact:{name}",
        source_instance_id=source,
        artifact_type="text",
        content_hash=stable_hash(content),
        encoding="utf-8",
        hash_scope="exact_utf8_bytes",
        immutable_value_ref=f"fixture:{name}",
        source_locator=f"fixture:{name}",
        evidence_ids=["ev"],
    )


def _project(
    observations: list[FlowObservation],
    *,
    artifacts: list[Artifact] | None = None,
    evidence: list[EvidenceRef] | None = None,
    claims: list[DependencyClaim] | None = None,
):
    return project_effect_graph(
        source_graph_id="source",
        source_graph_hash=stable_hash("source"),
        observations=observations,
        artifacts=artifacts or [],
        evidence=evidence or [_evidence("ev")],
        profile=_profile(),
        external_claims=claims,
    )


def test_fact_matrix_is_neutral_engineering_fixture() -> None:
    fixture = json.loads(FACT_MATRIX.read_text(encoding="utf-8"))
    assert fixture["fixture_kind"] == "engineering_golden_not_human_annotation"
    assert len(fixture["cases"]) == 17
    facts = json.dumps([item["facts"] for item in fixture["cases"]]).upper()
    assert all(word not in facts for word in ("TRANSFER", "DERIVE", "UPDATE"))


def test_same_content_different_sources_remain_distinct() -> None:
    artifacts = [_artifact("one", "source:one"), _artifact("two", "source:two")]
    observations = [
        FlowObservation(
            observation_id=f"result:{index}",
            event_type="tool_result",
            source_event_ids=[f"event:{index}"],
            domain=_domain(f"tool:{index}"),
            endpoint_domain=_domain("agent"),
            execution_status=ExecutionStatus.observed,
            evidence_ids=["ev"],
            output_artifact_ids=[artifact.artifact_id],
            operation_instance_id=f"call:{index}",
        )
        for index, artifact in enumerate(artifacts)
    ]
    graph = _project(observations, artifacts=artifacts)
    assert len(graph.artifacts) == 2
    assert graph.artifacts[0].content_hash == graph.artifacts[1].content_hash
    assert graph.artifacts[0].source_instance_id != graph.artifacts[1].source_instance_id


def test_one_tool_call_projects_multiple_effects_without_claiming_input_contribution() -> None:
    source, result = _artifact("source", "user"), _artifact("call", "agent", content="call")
    observation = FlowObservation(
        observation_id="tool-call",
        event_type="tool_call",
        source_event_ids=["event:call"],
        domain=_domain("agent"),
        endpoint_domain=_domain("tool"),
        execution_status=ExecutionStatus.observed,
        evidence_ids=["ev"],
        input_artifact_ids=[source.artifact_id],
        output_artifact_ids=[result.artifact_id],
        invocation_id="invocation:one",
        operation_instance_id="operation:one",
    )
    graph = _project([observation], artifacts=[source, result])
    assert {item.primitive for item in graph.effects} == {
        PrimitiveKind.derive,
        PrimitiveKind.transfer,
    }
    data_claim = next(item for item in graph.claims if item.relation == DependencyRelation.data_dep)
    verified = verify_effect_graph(graph, [_evidence("ev")])
    verified_claim = next(item for item in verified.claims if item.claim_id == data_claim.claim_id)
    assert verified_claim.dependency_verdict == ClaimVerdict.unknown
    assert verified_claim.intervention_result == InterventionResult.not_evaluated


def test_committed_versions_keep_scope_occurrence_and_rollback_identity() -> None:
    observations: list[FlowObservation] = []
    for name, workspace, before, after in (
        ("a-to-b", "workspace:one", "A", "B"),
        ("b-to-a", "workspace:one", "B", "A"),
        ("other", "workspace:two", "A", "B"),
    ):
        observations.append(
            FlowObservation(
                observation_id=name,
                event_type="state_write",
                source_event_ids=[f"event:{name}"],
                domain=_domain("tool"),
                execution_status=ExecutionStatus.committed,
                evidence_ids=["ev"],
                commit_evidence_ids=["commit"],
                operation_instance_id=name,
                resource_id="file:/same/path",
                resource_scope=workspace,
                before_version_id=before,
                after_version_id=after,
                resource_state="present",
            )
        )
    graph = _project(
        observations,
        evidence=[_evidence("ev"), _evidence("commit", EvidenceMethod.resource_commit)],
    )
    assert len(graph.resource_versions) == 3
    assert len({item.resource_version_id for item in graph.resource_versions}) == 3
    assert {item.workspace_scope for item in graph.resource_versions} == {
        "workspace:one",
        "workspace:two",
    }


@pytest.mark.parametrize(
    ("status", "before", "after", "reason"),
    [
        (ExecutionStatus.failed, "A", "B", "resource_write_not_committed"),
        (ExecutionStatus.unknown, "A", "B", "resource_write_not_committed"),
        (ExecutionStatus.committed, "A", "A", "resource_write_no_effect_observed"),
    ],
)
def test_failed_unknown_and_noop_writes_do_not_create_update(
    status: ExecutionStatus, before: str, after: str, reason: str
) -> None:
    observation = FlowObservation(
        observation_id="write",
        event_type="state_write",
        source_event_ids=["event:write"],
        domain=_domain("tool"),
        execution_status=status,
        evidence_ids=["ev"],
        commit_evidence_ids=["commit"],
        operation_instance_id="write",
        resource_id="file:/x",
        resource_scope="workspace:one",
        before_version_id=before,
        after_version_id=after,
    )
    graph = _project(
        [observation],
        evidence=[_evidence("ev"), _evidence("commit", EvidenceMethod.resource_commit)],
    )
    assert not any(item.primitive == PrimitiveKind.update for item in graph.effects)
    assert reason in {item.reason_code for item in graph.unresolved}


def test_read_from_is_version_scoped_and_log_order_invariant() -> None:
    artifact = _artifact("read", "tool", content="partial")
    write = FlowObservation(
        observation_id="z-write",
        event_type="state_write",
        source_event_ids=["event:write"],
        domain=_domain("tool"),
        execution_status=ExecutionStatus.committed,
        evidence_ids=["ev"],
        commit_evidence_ids=["commit"],
        operation_instance_id="write",
        resource_id="file:/x",
        resource_scope="workspace:one",
        before_version_id="A",
        after_version_id="B",
    )
    read = FlowObservation(
        observation_id="a-read",
        event_type="state_read",
        source_event_ids=["event:read"],
        domain=_domain("tool"),
        endpoint_domain=_domain("agent"),
        execution_status=ExecutionStatus.observed,
        evidence_ids=["read"],
        operation_instance_id="read",
        resource_id="file:/x",
        resource_scope="workspace:one",
        read_version_id="B",
        read_scope="partial",
        output_artifact_ids=[artifact.artifact_id],
    )
    evidence = [
        _evidence("ev"),
        _evidence("commit", EvidenceMethod.resource_commit),
        _evidence("read", EvidenceMethod.resource_commit),
    ]
    first = _project([read, write], artifacts=[artifact], evidence=evidence)
    second = _project([write, read], artifacts=[artifact], evidence=evidence)
    assert first.graph_hash == second.graph_hash
    verified = verify_effect_graph(first, evidence)
    claim = next(item for item in verified.claims if item.relation == DependencyRelation.read_from)
    assert claim.dependency_verdict == ClaimVerdict.verified
    assert (
        next(item for item in verified.ports if item.port_id == claim.source_port_id).value_scope
        == "partial"
    )


def test_restart_request_without_actual_transition_is_unresolved() -> None:
    graph = _project(
        [
            FlowObservation(
                observation_id="restart",
                event_type="lifecycle",
                source_event_ids=["event:restart"],
                domain=_domain("agent"),
                execution_status=ExecutionStatus.observed,
                evidence_ids=["ev"],
                restart_requested=True,
                actual_session_before="session:one",
                actual_session_after="session:one",
            )
        ]
    )
    assert not graph.effects
    assert (
        graph.unresolved[0].reason_code == "restart_requested_without_observed_session_transition"
    )


def test_attempted_send_does_not_verify_delivery() -> None:
    artifact = _artifact("attempt", "agent")
    observation = FlowObservation(
        observation_id="attempt",
        event_type="tool_call",
        source_event_ids=["event:attempt"],
        domain=_domain("agent"),
        endpoint_domain=_domain("remote-tool"),
        execution_status=ExecutionStatus.attempted,
        evidence_ids=["ev"],
        output_artifact_ids=[artifact.artifact_id],
        operation_instance_id="attempt",
    )
    verified = verify_effect_graph(_project([observation], artifacts=[artifact]), [_evidence("ev")])
    delivery = next(
        item for item in verified.claims if item.relation == DependencyRelation.delivered_to
    )
    assert delivery.dependency_verdict == ClaimVerdict.unknown
    assert delivery.reason_code == "claim_evidence_missing"


def test_atomic_transaction_groups_multiple_updates_without_order() -> None:
    observations = [
        FlowObservation(
            observation_id=name,
            event_type="state_write",
            source_event_ids=[f"event:{name}"],
            domain=_domain("tool"),
            execution_status=ExecutionStatus.committed,
            evidence_ids=["ev"],
            commit_evidence_ids=["commit"],
            operation_instance_id=name,
            transaction_id="transaction:one",
            resource_id=resource,
            resource_scope="workspace:one",
            before_version_id="before",
            after_version_id="after",
        )
        for name, resource in (("file-write", "file:/x"), ("acl-write", "acl:/x"))
    ]
    graph = _project(
        observations,
        evidence=[_evidence("ev"), _evidence("commit", EvidenceMethod.resource_commit)],
    )
    assert len(graph.effect_groups) == 1
    assert len(graph.effect_groups[0].effect_ids) == 2
    assert graph.effect_groups[0].atomicity == "atomic"
    assert graph.effect_groups[0].ordered_pairs == []


def test_control_dependency_requires_trusted_instrumentation() -> None:
    condition = _artifact("condition", "policy")
    output = _artifact("output", "agent", content="fixed")
    source = FlowObservation(
        observation_id="condition",
        event_type="model_response",
        source_event_ids=["event:condition"],
        domain=_domain("agent"),
        execution_status=ExecutionStatus.observed,
        evidence_ids=["ev"],
        output_artifact_ids=[condition.artifact_id],
        operation_instance_id="condition",
    )
    target = FlowObservation(
        observation_id="call",
        event_type="tool_call",
        source_event_ids=["event:call"],
        domain=_domain("agent"),
        endpoint_domain=_domain("tool"),
        execution_status=ExecutionStatus.observed,
        evidence_ids=["control"],
        output_artifact_ids=[output.artifact_id],
        operation_instance_id="call",
        control_source_observation_ids=[source.observation_id],
    )
    direct_graph = _project([source, target], artifacts=[condition, output])
    direct = verify_effect_graph(direct_graph, [_evidence("ev"), _evidence("control")])
    assert (
        next(
            item for item in direct.claims if item.relation == DependencyRelation.control_dep
        ).dependency_verdict
        == ClaimVerdict.unknown
    )
    trusted = _evidence("control", EvidenceMethod.trusted_control)
    trusted_graph = _project(
        [source, target], artifacts=[condition, output], evidence=[_evidence("ev"), trusted]
    )
    verified = verify_effect_graph(trusted_graph, [_evidence("ev"), trusted])
    assert (
        next(
            item for item in verified.claims if item.relation == DependencyRelation.control_dep
        ).dependency_verdict
        == ClaimVerdict.verified
    )


def test_duplicate_logs_do_not_duplicate_effects_and_projection_is_stable() -> None:
    artifact = _artifact("result", "tool")
    base = FlowObservation(
        observation_id="first",
        event_type="tool_result",
        source_event_ids=["event:result"],
        domain=_domain("tool"),
        endpoint_domain=_domain("agent"),
        execution_status=ExecutionStatus.observed,
        evidence_ids=["ev"],
        output_artifact_ids=[artifact.artifact_id],
        operation_instance_id="call",
    )
    duplicate = base.model_copy(update={"observation_id": "duplicate", "sequence_no": 99})
    one = _project([base], artifacts=[artifact])
    two = _project([duplicate, base], artifacts=[artifact])
    assert len(one.effects) == len(two.effects) == 1
    assert one.graph_hash == two.graph_hash


def test_unrelated_event_does_not_upgrade_existing_claim() -> None:
    source, output = _artifact("source", "user"), _artifact("output", "agent", content="out")
    derive = FlowObservation(
        observation_id="derive",
        event_type="model_response",
        source_event_ids=["event:derive"],
        domain=_domain("agent"),
        execution_status=ExecutionStatus.observed,
        evidence_ids=["ev"],
        input_artifact_ids=[source.artifact_id],
        output_artifact_ids=[output.artifact_id],
    )
    unrelated = FlowObservation(
        observation_id="unrelated",
        event_type="message",
        source_event_ids=["event:unrelated"],
        domain=_domain("other"),
        execution_status=ExecutionStatus.observed,
        evidence_ids=["ev"],
    )
    base = verify_effect_graph(_project([derive], artifacts=[source, output]), [_evidence("ev")])
    extended = verify_effect_graph(
        _project([derive, unrelated], artifacts=[source, output]), [_evidence("ev")]
    )
    base_claim = next(item for item in base.claims if item.relation == DependencyRelation.data_dep)
    extended_claim = next(
        item for item in extended.claims if item.relation == DependencyRelation.data_dep
    )
    assert (
        base_claim.dependency_verdict == extended_claim.dependency_verdict == ClaimVerdict.unknown
    )


def test_deleting_only_matching_evidence_removes_verified_claim() -> None:
    source, output = _artifact("source", "tool"), _artifact("output", "agent", content="out")
    observation = FlowObservation(
        observation_id="response",
        event_type="model_response",
        source_event_ids=["event:response"],
        domain=_domain("agent"),
        execution_status=ExecutionStatus.observed,
        evidence_ids=["ev"],
        input_artifact_ids=[source.artifact_id],
        output_artifact_ids=[output.artifact_id],
    )
    graph = _project([observation], artifacts=[source, output])
    original = next(item for item in graph.claims if item.relation == DependencyRelation.data_dep)
    exact = _evidence("exact", EvidenceMethod.exact_projection)
    claim = original.model_copy(update={"evidence_ids": [exact.evidence_id], "hypothesis": False})
    with_claim = _project(
        [observation], artifacts=[source, output], evidence=[_evidence("ev"), exact], claims=[claim]
    )
    verified_with = verify_effect_graph(with_claim, [_evidence("ev"), exact])
    selected_with = next(item for item in verified_with.claims if item.claim_id == claim.claim_id)
    assert selected_with.dependency_verdict == ClaimVerdict.verified
    without = claim.model_copy(update={"evidence_ids": []})
    without_graph = _project([observation], artifacts=[source, output], claims=[without])
    verified_without = verify_effect_graph(without_graph, [_evidence("ev")])
    selected = next(item for item in verified_without.claims if item.claim_id == without.claim_id)
    assert selected.dependency_verdict == ClaimVerdict.unknown


def test_provider_context_method_verifies_available_input_but_not_data_dependency() -> None:
    source, output = _artifact("source", "tool"), _artifact("output", "agent", content="out")
    observation = FlowObservation(
        observation_id="response",
        event_type="model_response",
        source_event_ids=["event:response"],
        domain=_domain("agent"),
        execution_status=ExecutionStatus.observed,
        evidence_ids=["ev"],
        input_artifact_ids=[source.artifact_id],
        output_artifact_ids=[output.artifact_id],
        operation_instance_id="response",
    )
    base = _project([observation], artifacts=[source, output])
    candidate = next(item for item in base.claims if item.relation == DependencyRelation.data_dep)
    context = _evidence("context", EvidenceMethod.provider_request_context)
    available = candidate.model_copy(
        update={
            "claim_id": "available",
            "relation": DependencyRelation.available_input,
            "evidence_ids": [context.evidence_id],
            "hypothesis": False,
        }
    )
    data = candidate.model_copy(
        update={
            "claim_id": "data",
            "evidence_ids": [context.evidence_id],
            "hypothesis": False,
        }
    )
    graph = _project(
        [observation],
        artifacts=[source, output],
        evidence=[_evidence("ev"), context],
        claims=[available, data],
    )
    verified = verify_effect_graph(graph, [_evidence("ev"), context])
    verdicts = {item.claim_id: item for item in verified.claims}
    assert verdicts["available"].dependency_verdict == ClaimVerdict.verified
    assert verdicts["data"].dependency_verdict == ClaimVerdict.unknown


def test_alpha_renaming_preserves_graph_structure() -> None:
    artifact = _artifact("value", "tool")
    first = FlowObservation(
        observation_id="old-observation",
        event_type="tool_result",
        source_event_ids=["old-event"],
        domain=_domain("tool"),
        endpoint_domain=_domain("agent"),
        execution_status=ExecutionStatus.observed,
        evidence_ids=["ev"],
        output_artifact_ids=[artifact.artifact_id],
        operation_instance_id="stable-operation",
    )
    renamed = first.model_copy(
        update={"observation_id": "new-observation", "source_event_ids": ["new-event"]}
    )
    left, right = _project([first], artifacts=[artifact]), _project([renamed], artifacts=[artifact])
    left_shape = (
        sorted(item.primitive.value for item in left.effects),
        sorted(item.relation.value for item in left.claims),
        sorted((len(item.input_port_ids), len(item.output_port_ids)) for item in left.effects),
    )
    right_shape = (
        sorted(item.primitive.value for item in right.effects),
        sorted(item.relation.value for item in right.claims),
        sorted((len(item.input_port_ids), len(item.output_port_ids)) for item in right.effects),
    )
    assert left_shape == right_shape


def test_bad_schema_version_and_bad_reference_fail_closed() -> None:
    with pytest.raises(ValidationError):
        FlowObservation.model_validate(
            {
                "schema_version": "2.0",
                "observation_id": "bad",
                "event_type": "message",
                "source_event_ids": [],
                "domain": _domain("agent").model_dump(mode="json"),
                "execution_status": "observed",
                "evidence_ids": [],
            }
        )
    observation = FlowObservation(
        observation_id="bad-ref",
        event_type="message",
        source_event_ids=["event"],
        domain=_domain("agent"),
        execution_status=ExecutionStatus.observed,
        evidence_ids=["missing"],
    )
    graph = _project([observation])
    assert "observation_evidence_reference_missing" in {
        item.reason_code for item in graph.unresolved
    }


def test_legacy_observation_to_effect_graph_to_verdict_integration(tmp_path: Path) -> None:
    adapter = JsonlFixtureInteractionAdapter(LEGACY_FIXTURE)
    summary = collect_interactions(
        InteractionCollectionPlan(
            collection_id="flow-v3-integration",
            source_task_ids=["construction-synthetic-001"],
            seed=31,
        ),
        adapter,
        tmp_path / "raw",
    )
    graph_path, _ = normalize_trajectory(
        summary.trajectory_paths[0],
        collection_root=summary.collection_root,
        output_root=tmp_path / "normalized",
    )
    legacy = InteractionGraph.model_validate_json(graph_path.read_text(encoding="utf-8"))
    observations, artifacts, evidence = observations_from_interaction_graph(legacy)
    projected = project_effect_graph(
        source_graph_id=legacy.graph_id,
        source_graph_hash=legacy.graph_hash,
        observations=observations,
        artifacts=artifacts,
        evidence=evidence,
        profile=_profile(),
    )
    verified = verify_effect_graph(projected, evidence)
    assert projected.schema_version == "3.0"
    assert projected.effects
    assert {item.primitive for item in projected.effects} >= {
        PrimitiveKind.transfer,
        PrimitiveKind.derive,
    }
    assert any(item.dependency_verdict == ClaimVerdict.verified for item in verified.claims)
    assert all(
        item.intervention_result == InterventionResult.not_evaluated for item in verified.claims
    )
