"""Prepared semantics and authorization lifecycle, without Docker or real credentials."""

import json
from pathlib import Path

import pytest

from stac_attack_lab.attack_program import r4_batch
from stac_attack_lab.attack_program.pipeline import JUDGE, PATCH, GateError
from stac_attack_lab.hashing import stable_hash

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    monkeypatch.setattr(
        r4_batch,
        "_upstream_preflight",
        lambda _: {
            "commit": r4_batch.build_catalog(ROOT).upstream_commit,
            "judge_hash": r4_batch.file_hash(ROOT / JUDGE),
            "patch_hash": r4_batch.file_hash(ROOT / PATCH),
            "image_digest": "sha256:" + "1" * 64,
        },
    )
    monkeypatch.setattr(
        r4_batch,
        "_project_env",
        lambda _: {
            "SAFECLAW_MODEL": "test-model",
            "SAFECLAW_BASE_URL": "https://example.test/api/v3",
        },
    )
    batch = tmp_path / "batch"
    r4_batch.prepare_disabled(
        ROOT, ROOT / "configs/attack_program/r4_development_candidate.json", batch
    )
    return batch


def rehash(batch, mutate):
    path = batch / "manifest.json"
    value = json.loads(path.read_text())
    mutate(value)
    value["manifest_hash"] = stable_hash({k: v for k, v in value.items() if k != "manifest_hash"})
    path.write_text(json.dumps(value))


@pytest.mark.parametrize("change", ["missing", "empty", "outside"])
def test_prepared_requires_exact_sources_even_when_rehashed(prepared, change):
    def mutate(value):
        sources = value["processing_source_hashes"]
        if change == "missing":
            sources.pop(next(iter(sources)))
        elif change == "empty":
            sources.clear()
        else:
            sources["../../etc/passwd"] = "0" * 64

    rehash(prepared, mutate)
    with pytest.raises(GateError, match="source"):
        r4_batch.validate_prepared(ROOT, prepared)


def test_same_leaf_name_in_new_output_cannot_reuse_authorization_identity(prepared):
    other = prepared.parent / "another-parent" / prepared.name
    r4_batch.prepare_disabled(ROOT, prepared / "candidate.json", other)
    original, fresh = r4_batch._manifest(prepared), r4_batch._manifest(other)
    assert original["manifest_hash"] != fresh["manifest_hash"]
    assert original["run_id"] != fresh["run_id"]


@pytest.mark.parametrize(
    "key,value",
    [
        ("candidate_id", "other"),
        ("task_id", "pse-2.1-002"),
        ("victim_model_id", "other"),
        ("victim_endpoint_host", "elsewhere.test"),
        ("max_http_attempts", {"attacker": 1, "victim": 12}),
        ("per_request_timeout_seconds", 0),
        ("image", "different"),
        ("schema_version", "attack-r4-prepared-batch/999"),
    ],
)
def test_prepared_semantics_cannot_be_rehashed(prepared, key, value):
    rehash(prepared, lambda m: m.update({key: value}))
    with pytest.raises(GateError):
        r4_batch.validate_prepared(ROOT, prepared)


def test_missing_status_is_actionable(tmp_path):
    assert r4_batch.batch_status(ROOT, tmp_path / "missing")["status"] == "disabled"


def test_unauthorized_bind_run_are_zero_request(prepared):
    with pytest.raises(GateError, match="authorized"):
        r4_batch.bind_disabled(ROOT, prepared)
    with pytest.raises(GateError, match="authorized"):
        r4_batch.run_disabled(ROOT, prepared)
    assert not (prepared / "binding.json").exists()
    assert not (prepared / "execution").exists()


def test_real_direct_runtime_has_no_binding_bypass():
    from stac_attack_lab.attack_program.r4_runtime import execute_case

    candidate = r4_batch.load_candidate(
        ROOT / "configs/attack_program/r4_development_candidate.json"
    )
    catalog = r4_batch.build_catalog(ROOT)
    with pytest.raises(GateError, match="binding"):
        execute_case(
            ROOT,
            candidate,
            catalog,
            r4_batch.make_split(catalog),
            run_id="bypass",
            mode="real",
            request_budget=12,
            request_timeout=90,
            episode_deadline=900,
        )


@pytest.fixture
def bound_fake(prepared, monkeypatch):
    batch = prepared.parent / "fake"
    manifest = r4_batch.prepare_disabled(
        ROOT, prepared / "candidate.json", batch, local_fake="harm"
    )
    authorization = batch / "fake-authorization.json"
    r4_batch._write(
        authorization,
        {
            "schema_version": "attack-r4-authorization/1",
            "scope": "local_fake",
            "manifest_hash": manifest["manifest_hash"],
            "text": r4_batch.authorization_text(manifest),
        },
        private=True,
    )
    digest = r4_batch.file_hash(authorization)
    r4_batch.bind_disabled(
        ROOT,
        batch,
        authorization=authorization,
        authorization_sha256=digest,
        acknowledge=True,
        local_fake=True,
    )
    return batch, authorization, digest


def test_wait_before_activation_does_not_use_episode_time(bound_fake, monkeypatch):
    batch, _, _ = bound_fake
    binding = r4_batch._read_json(batch / "binding.json")
    now = binding["bound_at"] + 1000
    monkeypatch.setattr(r4_batch.time, "time", lambda: now)
    activation = r4_batch.activate(ROOT, batch)
    assert activation["deadline_at"] == now + 900
    assert activation["deadline_at"] <= binding["expires_at"]
    assert r4_batch.batch_status(ROOT, batch)["status"] == "active"


def test_expired_binding_cannot_activate_or_rebind(bound_fake, monkeypatch):
    batch, auth, digest = bound_fake
    expires = r4_batch._read_json(batch / "binding.json")["expires_at"]
    monkeypatch.setattr(r4_batch.time, "time", lambda: expires)
    assert r4_batch.batch_status(ROOT, batch)["status"] == "expired"
    with pytest.raises(GateError, match="expired"):
        r4_batch.activate(ROOT, batch)
    assert not (batch / "execution").exists()
    with pytest.raises(GateError, match="already_exists"):
        r4_batch.bind_disabled(
            ROOT,
            batch,
            authorization=auth,
            authorization_sha256=digest,
            acknowledge=True,
            local_fake=True,
        )


def test_concurrent_launch_has_one_winner(bound_fake):
    from concurrent.futures import ThreadPoolExecutor

    batch, _, _ = bound_fake

    def attempt():
        try:
            r4_batch.activate(ROOT, batch)
            return "active"
        except GateError as exc:
            return str(exc)

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _: attempt(), range(2)))
    assert sorted(outcomes) == ["active", "runtime_launch_already_reserved"]


def test_fake_scope_and_reference_cannot_authorize_real(bound_fake):
    batch, auth, digest = bound_fake
    with pytest.raises(GateError, match="scope"):
        r4_batch.run_disabled(
            ROOT,
            batch,
            authorization=auth,
            authorization_sha256=digest,
            acknowledge=True,
            local_fake=False,
        )
    auth.write_text("{}")
    with pytest.raises(GateError, match="authorization"):
        r4_batch.activate(ROOT, batch)
    assert not (batch / "execution").exists()


def test_send_exception_seals_count_and_terminal_no_relaunch(bound_fake, monkeypatch):
    from stac_attack_lab.attack_program import r4_runtime

    batch, auth, digest = bound_fake
    frozen = (batch / "manifest.json").read_bytes()

    def failed(root, candidate, catalog, split, **kwargs):
        r4_batch.runtime_context(root, batch, candidate, kwargs["run_id"], kwargs["mode"])
        r4_batch._write(
            kwargs["diagnostic_path"],
            {
                "stage": "session_execution",
                "relay_reservations": [{"accepted": "reserved", "sequence": 1}],
                "error_type": "ConnectionError",
            },
            private=True,
        )
        raise ConnectionError("send uncertain")

    monkeypatch.setattr(r4_runtime, "execute_case", failed)
    with pytest.raises(ConnectionError):
        r4_batch.run_disabled(
            ROOT,
            batch,
            authorization=auth,
            authorization_sha256=digest,
            acknowledge=True,
            local_fake=True,
        )
    status = r4_batch.batch_status(ROOT, batch)
    assert status["status"] == "terminal"
    assert status["terminal"]["victim_http_attempts"] == 1
    assert not status["terminal"]["unused_limits_transferable"]
    assert frozen == (batch / "manifest.json").read_bytes()
    with pytest.raises(GateError, match="reserved"):
        r4_batch.run_disabled(
            ROOT,
            batch,
            authorization=auth,
            authorization_sha256=digest,
            acknowledge=True,
            local_fake=True,
        )


def test_runtime_claim_is_single_use_and_expiration_not_reset(bound_fake, monkeypatch):
    batch, _, _ = bound_fake
    activation = r4_batch.activate(ROOT, batch)
    candidate = r4_batch.load_candidate(batch / "candidate.json")
    run_id = r4_batch._manifest(batch)["run_id"]
    r4_batch.runtime_context(ROOT, batch, candidate, run_id, "harm")
    with pytest.raises(GateError, match="already_claimed"):
        r4_batch.runtime_context(ROOT, batch, candidate, run_id, "harm")
    monkeypatch.setattr(r4_batch.time, "time", lambda: activation["deadline_at"])
    with pytest.raises(GateError, match="expired"):
        r4_batch.runtime_context(ROOT, batch, candidate, run_id, "harm")


@pytest.mark.parametrize(
    "base",
    [
        "https://user:secret@example.test/v1",
        "https://example.test/v1?api_key=x",
        "https://example.test/v1#key",
        "https://example.test/a/../v1",
        "https://example.test/%2e/v1",
    ],
)
def test_endpoint_rejects_secret_or_ambiguous_identity(base):
    with pytest.raises(GateError, match="endpoint"):
        r4_batch.endpoint_identity(base)


def test_runtime_retry_overlay_rejects_wrong_pinned_bytes():
    from stac_attack_lab.attack_program.r4_runtime import retry_overlay

    with pytest.raises(GateError, match="retry_source"):
        retry_overlay("openai-completions", "return new OpenAI({});")


def test_real_mode_cannot_use_fake_execution_context(bound_fake):
    from stac_attack_lab.attack_program.r4_runtime import execute_case

    batch, _, _ = bound_fake
    r4_batch.activate(ROOT, batch)
    candidate = r4_batch.load_candidate(batch / "candidate.json")
    catalog = r4_batch.build_catalog(ROOT)
    with pytest.raises(GateError, match="context_mismatch"):
        execute_case(
            ROOT,
            candidate,
            catalog,
            r4_batch.make_split(catalog),
            run_id=r4_batch._manifest(batch)["run_id"],
            mode="real",
            request_budget=12,
            request_timeout=90,
            episode_deadline=900,
            execution_batch=batch,
        )
    assert not (batch / "execution/runtime_claim.json").exists()


def test_cli_fake_bind_run_status_and_independent_replay(prepared, monkeypatch, capsys):
    import sys

    from test_attack_program_r4_semantics import _bundle

    from stac_attack_lab.attack_program import cli, r4_runtime
    from stac_attack_lab.attack_program.r4 import RuntimeBundle, replay_case

    batch = prepared.parent / "cli-fake"

    def command(*args):
        monkeypatch.setattr(sys, "argv", ["stac-attack-program", *map(str, args)])
        return cli.main()

    assert (
        command(
            "r4-prepare",
            "--candidate",
            prepared / "candidate.json",
            "--output",
            batch,
            "--local-fake-mode",
            "normal",
        )
        == 0
    )
    manifest = r4_batch._manifest(batch)
    auth = batch / "fake-authorization.json"
    r4_batch._write(
        auth,
        {
            "schema_version": "attack-r4-authorization/1",
            "scope": "local_fake",
            "manifest_hash": manifest["manifest_hash"],
            "text": r4_batch.authorization_text(manifest),
        },
    )
    digest = r4_batch.file_hash(auth)
    assert command("r4-bind", "--batch", batch) == 2
    assert (
        command(
            "r4-bind",
            "--batch",
            batch,
            "--authorization",
            auth,
            "--authorization-sha256",
            digest,
            "--local-fake-authorized",
        )
        == 0
    )

    def offline_execute(root, candidate, catalog, split, **kwargs):
        context = r4_batch.runtime_context(root, batch, candidate, kwargs["run_id"], kwargs["mode"])
        value = _bundle().model_dump()
        value.update(
            run_id=kwargs["run_id"],
            candidate_id=candidate.candidate_id,
            materialized_task_hash=context["manifest"]["materialized_task_hash"],
            execution_binding_hash=context["binding_hash"],
        )
        return RuntimeBundle.model_validate(value)

    monkeypatch.setattr(r4_runtime, "execute_case", offline_execute)
    assert (
        command(
            "r4-run-batch",
            "--batch",
            batch,
            "--authorization",
            auth,
            "--authorization-sha256",
            digest,
            "--local-fake-authorized",
        )
        == 0
    )
    assert command("r4-status", "--batch", batch) == 0
    assert r4_batch.batch_status(ROOT, batch)["status"] == "terminal"
    assert (
        replay_case(ROOT, batch / "execution/case", batch.parent / "cli-audit")["status"] == "valid"
    )
    assert (
        command(
            "r4-run-batch",
            "--batch",
            batch,
            "--authorization",
            auth,
            "--authorization-sha256",
            digest,
            "--local-fake-authorized",
        )
        == 2
    )
    capsys.readouterr()


def test_partial_missing_ledger_preserves_unknown(bound_fake, monkeypatch):
    from stac_attack_lab.attack_program import r4_runtime

    batch, auth, digest = bound_fake

    def failed(root, candidate, catalog, split, **kwargs):
        r4_batch.runtime_context(root, batch, candidate, kwargs["run_id"], kwargs["mode"])
        r4_batch._write(
            kwargs["diagnostic_path"],
            {"relay_reservations": [], "reservation_capture_complete": False},
        )
        raise RuntimeError("ledger unavailable")

    monkeypatch.setattr(r4_runtime, "execute_case", failed)
    with pytest.raises(RuntimeError):
        r4_batch.run_disabled(
            ROOT,
            batch,
            authorization=auth,
            authorization_sha256=digest,
            acknowledge=True,
            local_fake=True,
        )
    terminal = r4_batch.batch_status(ROOT, batch)["terminal"]
    assert terminal["victim_http_attempts"] is None
    assert terminal["request_count_status"] == "unknown"
