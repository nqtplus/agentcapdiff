import pathlib
import runpy
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
CHECKER = runpy.run_path(
    str(ROOT / "scripts" / "check_release_transaction_integrity.py"),
    run_name="check_release_transaction_integrity",
)
STATE = runpy.run_path(
    str(ROOT / "scripts" / "release_transaction_state.py"),
    run_name="release_transaction_state",
)
SOURCE = "a" * 40
OTHER_SOURCE = "b" * 40
TAG = "v1.0.0"


def _copy_transaction_contract(tmp_path: pathlib.Path) -> None:
    workflow_dir = tmp_path / ".github" / "workflows"
    scripts_dir = tmp_path / "scripts"
    workflow_dir.mkdir(parents=True)
    scripts_dir.mkdir(parents=True)
    (workflow_dir / "release.yml").write_text(
        (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (scripts_dir / "release_transaction_state.py").write_text(
        (ROOT / "scripts" / "release_transaction_state.py").read_text(encoding="utf-8"),
        encoding="utf-8",
    )


def _release(*, draft: bool, immutable: bool, source: str = SOURCE) -> dict[str, object]:
    marker = STATE["ownership_marker"](source)
    return {
        "tagName": TAG,
        "isDraft": draft,
        "isImmutable": immutable,
        "body": f"release notes\n{marker}\n",
    }


def test_release_transaction_integrity_contract_passes_for_repository():
    result = subprocess.run(
        [sys.executable, "scripts/check_release_transaction_integrity.py"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "release-transaction-integrity: PASS" in result.stdout


def test_transaction_contract_rejects_cancel_in_progress(tmp_path: pathlib.Path):
    _copy_transaction_contract(tmp_path)
    release = tmp_path / ".github" / "workflows" / "release.yml"
    text = release.read_text(encoding="utf-8").replace(
        "cancel-in-progress: false",
        "cancel-in-progress: true",
        1,
    )
    release.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="cancel|missing required control"):
        CHECKER["check"](tmp_path)


def test_transaction_contract_rejects_source_tag_cleanup(tmp_path: pathlib.Path):
    _copy_transaction_contract(tmp_path)
    release = tmp_path / ".github" / "workflows" / "release.yml"
    text = release.read_text(encoding="utf-8").replace(
        'gh release delete "$GITHUB_REF_NAME" --yes',
        'gh release delete "$GITHUB_REF_NAME" --cleanup-tag --yes',
        1,
    )
    release.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="preserve the source tag|missing required control"):
        CHECKER["check"](tmp_path)


def test_transaction_contract_rejects_unguarded_release_mutation(tmp_path: pathlib.Path):
    _copy_transaction_contract(tmp_path)
    release = tmp_path / ".github" / "workflows" / "release.yml"
    text = release.read_text(encoding="utf-8")
    marker = (
        "      - name: Create draft release with exact validated assets\n"
        "        id: create_release\n"
        "        if: steps.release_state.outputs.already_published != 'true'\n"
    )
    replacement = (
        "      - name: Create draft release with exact validated assets\n"
        "        id: create_release\n"
    )
    assert marker in text
    release.write_text(text.replace(marker, replacement, 1), encoding="utf-8")

    with pytest.raises(ValueError, match="idempotency-guarded"):
        CHECKER["check"](tmp_path)


def test_release_presence_matches_exact_tag_only():
    release_presence = STATE["release_presence"]
    payload = [{"tagName": "v0.9.0"}, {"tagName": TAG}]

    assert release_presence(payload, TAG) == "present"
    assert release_presence(payload, "v1.0.1") == "missing"


def test_release_presence_rejects_duplicate_tag_state():
    release_presence = STATE["release_presence"]
    payload = [{"tagName": TAG}, {"tagName": TAG}]

    with pytest.raises(ValueError, match="multiple releases"):
        release_presence(payload, TAG)


def test_release_classification_is_bound_to_exact_source_marker():
    classify = STATE["classify_release"]
    payload = _release(draft=True, immutable=False)

    assert classify(payload, TAG, SOURCE) == "draft-owned"
    assert classify(payload, TAG, OTHER_SOURCE) == "draft-unowned"


def test_release_classification_distinguishes_retry_and_committed_states():
    classify = STATE["classify_release"]

    assert classify(_release(draft=True, immutable=False), TAG, SOURCE) == "draft-owned"
    assert classify(_release(draft=False, immutable=False), TAG, SOURCE) == "mutable-owned"
    assert classify(_release(draft=False, immutable=True), TAG, SOURCE) == "immutable-owned"


def test_release_classification_rejects_impossible_draft_immutable_state():
    classify = STATE["classify_release"]

    with pytest.raises(ValueError, match="both draft and immutable"):
        classify(_release(draft=True, immutable=True), TAG, SOURCE)


def test_release_state_cli_fails_closed_on_malformed_json():
    script = ROOT / "scripts" / "release_transaction_state.py"
    result = subprocess.run(
        [sys.executable, str(script), "--mode", "exists", "--tag", TAG],
        input="not-json",
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert "release-state: FAIL" in result.stderr
