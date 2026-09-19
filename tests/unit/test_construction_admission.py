from __future__ import annotations

import json
from pathlib import Path

from stac_attack_lab.execution.construction_admission import construction_admission
from stac_attack_lab.execution.sample_generation import (
    build_sample_library,
    load_sample_generation_config,
)
from stac_attack_lab.hashing import stable_hash
from stac_attack_lab.interactions.models import InteractionGraph, RawInteractionTrajectory

ROOT = Path(__file__).resolve().parents[2]


def test_identity_through_collection_normalization_mining_and_independent_admission(
    tmp_path: Path,
) -> None:
    source = json.loads(
        (ROOT / "tests/fixtures/interactions/authorized_synthetic.jsonl")
        .read_text()
        .splitlines()[0]
    )
    for e in source["source_events"]:
        session = e["session_id"]
        e.setdefault("public_payload", {}).update(
            {
                "actual_session_identity_sha256": stable_hash(session),
                "workspace_identity_sha256": stable_hash("workspace"),
                "memory_index_namespace_sha256": stable_hash("index"),
            }
        )
        if e["event_id"] == "e1":
            e["operation"] = "deliver_external_ingress"
        if e["event_id"] == "e5":
            e["operation"] = "request_new_session"
        if e["event_id"] == "e6":
            e["operation"] = "memory_retrieve_later_session"
            e["public_payload"].update(
                retrieval_hit=True,
                restart_requested=True,
                previous_delivery_session_identity_sha256=stable_hash("session-1"),
                new_session_request_action_id="restart-1",
            )
        if e["event_id"] == "e7":
            e["public_payload"]["use_evidence_kind"] = "explicit_provider_output_reference"
    fixture = tmp_path / "fixture.jsonl"
    fixture.write_text(json.dumps(source) + "\n")
    config = load_sample_generation_config(
        ROOT / "tests/fixtures/sample_generation.json"
    ).model_copy(
        update={
            "source_fixture_path": str(fixture),
            "source_task_ids": [source["source_task_id"]],
            "output_root": str(tmp_path / "build"),
            "target_accepted_samples": 1,
        }
    )
    library = build_sample_library(ROOT, config)
    build = library.parent
    raw = RawInteractionTrajectory.model_validate_json(
        next(build.rglob("raw_trajectory.json")).read_text()
    )
    graph = InteractionGraph.model_validate_json(
        next(build.rglob("interaction_graph.json")).read_text()
    )
    assert all(e.public_payload.get("actual_session_identity_sha256") for e in graph.events)
    assert (build / "extraction").is_dir()
    assert stable_hash("session-2") in next(build.rglob("source_events.jsonl")).read_text()
    report = construction_admission(raw, graph, accepted_count=1, library_audit_passed=True)
    assert report["checks"]["cross_session_persistence_read_use"], report
    assert report["structural_checks_passed"], report
    assert report["pilot_admitted"] is False  # Runtime engineering review is still required.
    # A two-event accepted chain cannot bypass the complete engineering gate.
    short = graph.model_copy(update={"edges": []})
    assert (
        construction_admission(raw, short, accepted_count=1, library_audit_passed=True)["checks"][
            "cross_session_persistence_read_use"
        ]
        is False
    )
    # Same session, empty retrieval, different namespace, unrelated lifecycle and hash-only
    # result identities must never certify a causal read/use path.
    for update in (
        {"actual_session_identity_sha256": stable_hash("session-1")},
        {"retrieval_hit": False},
        {"memory_index_namespace_sha256": stable_hash("different-index")},
        {"new_session_request_action_id": "unrelated"},
    ):
        changed = graph.model_copy(
            update={
                "events": [
                    e.model_copy(update={"public_payload": {**e.public_payload, **update}})
                    if e.event_id == "e6"
                    else e
                    for e in graph.events
                ]
            }
        )
        assert (
            construction_admission(raw, changed, accepted_count=1, library_audit_passed=True)[
                "checks"
            ]["cross_session_persistence_read_use"]
            is False
        )
