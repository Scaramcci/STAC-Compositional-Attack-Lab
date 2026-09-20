from __future__ import annotations

from typing import Any

from stac_attack_lab.execution.provider_evidence import (
    verify_context_candidate,
    verify_derivation_candidate,
)
from stac_attack_lab.flow.models import (
    DependencyClaim,
    DependencyRelation,
    EvidenceMethod,
    EvidenceRef,
)
from stac_attack_lab.hashing import stable_hash
from stac_attack_lab.interactions.models import RawInteractionTrajectory


def _provider_refs(
    *,
    record_ids: list[str],
    records: dict[str, dict[str, Any]],
    trajectory: RawInteractionTrajectory,
    method: EvidenceMethod,
) -> list[EvidenceRef]:
    sealed_input_id = next(
        (
            item.content_hash
            for item in trajectory.evidence_refs
            if item.kind == "provider_boundary_evidence"
        ),
        trajectory.config_hash,
    )
    refs: list[EvidenceRef] = []
    for reference in record_ids:
        parts = reference.split(":")
        record_id = parts[1] if len(parts) == 3 and parts[0] == "provider-evidence" else reference
        if record_id not in records:
            continue
        record_hash = str(records[record_id].get("record_sha256") or "")
        refs.append(
            EvidenceRef(
                evidence_id=f"provider:{record_id}:{method.value}",
                producer="stac.execution.provider_evidence",
                locator=reference,
                content_hash=record_hash or None,
                hash_scope="canonical_provider_evidence_record",
                privacy_scope=(
                    "synthetic_private" if trajectory.source_split == "synthetic" else "private"
                ),
                method=method,
                method_version="1.0",
                sealed_input_id=sealed_input_id,
            )
        )
    return refs


def verify_and_adapt_provider_claims(
    *,
    trajectory: RawInteractionTrajectory,
    source_artifact: Any,
    source_event: Any,
    consumer_event: Any,
    candidate: dict[str, Any],
    records: dict[str, dict[str, Any]],
    bundle_status: dict[str, Any],
    source_port_id: str,
    consumer_input_port_id: str,
    consumer_output_port_id: str,
) -> tuple[list[DependencyClaim], list[EvidenceRef]]:
    """Run the existing strict verifier, then translate only its result to v3."""

    context = verify_context_candidate(
        trajectory=trajectory,
        source_artifact=source_artifact,
        source_event=source_event,
        consumer_event=consumer_event,
        candidate=candidate,
        records=records,
        bundle_status=bundle_status,
    )
    derivation = verify_derivation_candidate(
        trajectory=trajectory,
        source_artifact=source_artifact,
        source_event=source_event,
        consumer_event=consumer_event,
        candidate=candidate,
        records=records,
        bundle_status=bundle_status,
    )
    evidence: list[EvidenceRef] = []
    claims: list[DependencyClaim] = []

    context_refs: list[EvidenceRef] = []
    if context.get("state") == "observed":
        context_refs = _provider_refs(
            record_ids=[str(item) for item in context.get("evidence_ref_ids", [])],
            records=records,
            trajectory=trajectory,
            method=EvidenceMethod.provider_request_context,
        )
        evidence.extend(context_refs)
    claims.append(
        DependencyClaim(
            claim_id="claim-" + stable_hash([candidate, "available_input"])[:20],
            relation=DependencyRelation.available_input,
            source_port_id=source_port_id,
            target_port_id=consumer_input_port_id,
            evidence_ids=[item.evidence_id for item in context_refs],
            verifier_id="stac.execution.provider_evidence.verify_context_candidate",
            rule_version="1.0",
            reason_code=str(context.get("reason_code", "provider_context_unknown")),
        )
    )

    derivation_refs: list[EvidenceRef] = []
    if derivation.get("state") == "observed":
        derivation_refs = _provider_refs(
            record_ids=[str(item) for item in derivation.get("evidence_ref_ids", [])],
            records=records,
            trajectory=trajectory,
            method=EvidenceMethod.exact_projection,
        )
        evidence.extend(derivation_refs)
    claims.append(
        DependencyClaim(
            claim_id="claim-" + stable_hash([candidate, "data_dep"])[:20],
            relation=DependencyRelation.data_dep,
            source_port_id=source_port_id,
            target_port_id=consumer_output_port_id,
            evidence_ids=[item.evidence_id for item in derivation_refs],
            verifier_id="stac.execution.provider_evidence.verify_derivation_candidate",
            rule_version=str(candidate.get("rule_id", "unknown")),
            reason_code=str(derivation.get("reason_code", "provider_derivation_unknown")),
        )
    )
    unique = {item.evidence_id: item for item in evidence}
    return claims, sorted(unique.values(), key=lambda item: item.evidence_id)
