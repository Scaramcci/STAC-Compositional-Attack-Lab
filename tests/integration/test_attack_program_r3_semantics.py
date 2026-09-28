"""Counterexamples required before the R3 evidence migration."""

from __future__ import annotations

from pathlib import Path

import pytest

from stac_attack_lab.attack_program.demo_r2 import _event, _observation
from stac_attack_lab.attack_program.development import _decision
from stac_attack_lab.attack_program.models import (
    AttackCandidate,
    Patch,
    PrimitiveOccurrence,
    PrimitiveRelation,
)
from stac_attack_lab.attack_program.observation import independent_verdict, validate_graph
from stac_attack_lab.attack_program.pipeline import GateError, build_catalog, make_split

ROOT = Path(__file__).resolve().parents[2]


def _task(task_id: str = "pse-2.1-001"):
    import json

    entry = next(e for e in build_catalog(ROOT).entries if e.task_id == task_id)
    return json.loads((ROOT / entry.task_path).read_text())


def test_unknown_task_is_not_declared_safe_by_pse_rule():
    obs = _observation("c", mode="safe", marker="CANARY_TEST")
    task = _task("cdf-3.9-001")
    obs = obs.model_copy(update={"task_id": task["metadata"]["task_id"]})
    verdict, _, _ = independent_verdict(task, obs, {"score": None})
    assert verdict["harm"] == "unknown"


def test_s2_leak_can_be_observed_without_propagation_proof():
    task = _task()
    marker = task["taint_assets"][0]["marker"]
    obs = _observation("c", mode="harm", marker=marker)
    obs = obs.model_copy(update={"events": obs.events[:1]})
    verdict, nodes, _ = independent_verdict(task, obs, {"score": None})
    assert verdict["harm"].startswith("observed_harm")
    assert verdict["propagation_contribution"] == "unknown"
    assert verdict["primitive_evidence"]["Act"] == "unknown"
    assert not any(n.primitive == "Act" for n in nodes)


def test_graph_empty_node_evidence_is_stable_gate_error():
    obs = _observation("c", mode="safe", marker="CANARY_TEST")
    with pytest.raises(GateError, match="primitive_relation_evidence_invalid"):
        validate_graph(
            [
                PrimitiveOccurrence(occurrence_id="a", primitive="Ingest"),
                PrimitiveOccurrence(occurrence_id="b", primitive="Act"),
            ],
            [PrimitiveRelation(source_id="a", target_id="b", kind="precedes", evidence_refs=["x"])],
            obs,
        )


def test_unmapped_memory_write_does_not_prove_persist():
    task = _task()
    marker = task["taint_assets"][0]["marker"]
    obs = _observation("c", mode="harm", marker=marker)
    obs = obs.model_copy(
        update={"events": [e for e in obs.events if e.event_type != "tool_request"]}
    )
    verdict, _, _ = independent_verdict(task, obs, {"score": None})
    assert verdict["primitive_evidence"]["Persist"] == "unknown"


def test_actual_response_event_creates_act_occurrence():
    task = _task()
    marker = task["taint_assets"][0]["marker"]
    obs = _observation("c", mode="harm", marker=marker)
    response = _event("c", 6, "response", "observed", session="session-B")
    response = response.model_copy(
        update={"evidence": {"session_id": "s2", "response_hash": "not-the-response"}}
    )
    obs = obs.model_copy(update={"events": [*obs.events[:-1], response]})
    verdict, nodes, _ = independent_verdict(task, obs, {"score": None})
    assert verdict["primitive_evidence"]["Act"] == "unknown"
    assert not any(n.primitive == "Act" for n in nodes)


def test_observation_from_different_materialized_payload_is_rejected():
    catalog = build_catalog(ROOT)
    split = make_split(catalog)
    entry = next(e for e in catalog.entries if e.task_id == "pse-2.1-001")
    candidate = AttackCandidate(
        candidate_id="candidate",
        task_id=entry.task_id,
        task_group_id=entry.task_group_id,
        source_split="development",
        patches=[Patch(pointer=entry.attack_surfaces[0].pointer, value="payload B")],
    )
    obs = _observation("candidate", mode="safe", marker="CANARY_TEST").model_copy(
        update={
            "schema_version": "attack-observation/2",
            "materialized_task_hash": "payload-A-hash",
        }
    )
    record, _ = _decision(candidate, obs, ROOT, catalog, split, "attempt-0001")
    assert record["status"] == "error"
    assert record["reason_codes"] == ["observation_materialized_hash_mismatch"]
