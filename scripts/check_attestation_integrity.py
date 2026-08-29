from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPOSITORY = "nqtplus/agentcapdiff"
SIGNER_WORKFLOW = f"{REPOSITORY}/.github/workflows/release.yml"


class AttestationIntegrityError(ValueError):
    """Raised when release attestation controls are weakened or incomplete."""


def _read(path: Path) -> str:
    if not path.is_file():
        raise AttestationIntegrityError(f"required attestation-integrity file missing: {path}")
    return path.read_text(encoding="utf-8")


def _require_fragments(text: str, fragments: tuple[str, ...], label: str) -> None:
    for fragment in fragments:
        if fragment not in text:
            raise AttestationIntegrityError(f"{label} missing required control: {fragment}")


def _check_release_workflow(root: Path) -> None:
    release = _read(root / ".github" / "workflows" / "release.yml")
    required = (
        "id: attest_provenance",
        "id: attest_sbom",
        "subject-checksums: release/SHA256SUMS",
        "PROVENANCE_BUNDLE: ${{ steps.attest_provenance.outputs.bundle-path }}",
        "SBOM_BUNDLE: ${{ steps.attest_sbom.outputs.bundle-path }}",
        "python scripts/verify_release_attestations.py",
        '--tag "$GITHUB_REF_NAME"',
        '--source-sha "$GITHUB_SHA"',
        '--provenance-bundle "$PROVENANCE_BUNDLE"',
        '--sbom-bundle "$SBOM_BUNDLE"',
    )
    _require_fragments(release, required, "release workflow")
    if release.count("subject-checksums: release/SHA256SUMS") != 2:
        raise AttestationIntegrityError(
            "release workflow must bind both provenance and SBOM attestations to SHA256SUMS"
        )
    for forbidden in ("subject-path:", "subject-digest:"):
        if forbidden in release:
            raise AttestationIntegrityError(
                f"release workflow must not rediscover attestation subjects via {forbidden}"
            )

    verify_index = release.find("python scripts/verify_release_attestations.py")
    publish_index = release.find("gh release create")
    if verify_index < 0 or publish_index < 0 or verify_index > publish_index:
        raise AttestationIntegrityError(
            "release attestation verification must complete before release publication"
        )
    if "--require-published-release" in release:
        raise AttestationIntegrityError(
            "producer prepublication verification must not require a release "
            "that does not exist yet"
        )


def _check_verifier(root: Path) -> None:
    verifier = _read(root / "scripts" / "verify_release_attestations.py")
    required = (
        f'REPOSITORY = "{REPOSITORY}"',
        'SIGNER_WORKFLOW = f"{REPOSITORY}/.github/workflows/release.yml"',
        "https://token.actions.githubusercontent.com",
        "https://slsa.dev/provenance/v1",
        "https://spdx.dev/Document/v2.3",
        '"--repo"',
        '"--signer-workflow"',
        '"--source-ref"',
        '"--source-digest"',
        '"--signer-digest"',
        '"--cert-oidc-issuer"',
        '"--deny-self-hosted-runners"',
        '"--predicate-type"',
        '"--bundle"',
        '"--require-published-release"',
        '"isDraft"',
        '"isPrerelease"',
        '"isImmutable"',
        '"assets"',
        "agentcapdiff-release-source:",
        'f"repos/{REPOSITORY}/commits/{tag}"',
        'f"repos/{REPOSITORY}/compare/{source_sha}...main"',
        "published release asset set mismatch",
        'result.get("verificationResult")',
        'verification.get("statement")',
        'statement.get("predicate")',
        'digests.get("sha256")',
    )
    _require_fragments(verifier, required, "release attestation verifier")
    for forbidden in ("shell=True", "os.system("):
        if forbidden in verifier:
            raise AttestationIntegrityError(
                f"release attestation verifier uses unsafe subprocess pattern: {forbidden}"
            )


def _check_consumer_guidance(root: Path) -> None:
    guidance = _read(root / "docs" / "attestation-verification.md")
    required = (
        "scripts/verify_release_attestations.py",
        "SHA256SUMS",
        "--repo nqtplus/agentcapdiff",
        "--signer-workflow nqtplus/agentcapdiff/.github/workflows/release.yml",
        "--source-ref",
        "--source-digest",
        "--signer-digest",
        "--deny-self-hosted-runners",
        "--require-published-release",
        "published, immutable",
        "tag resolves to the exact reviewed source SHA",
        "requirements/action-runtime-lock.txt",
        "--require-hashes",
        "--no-deps",
        "pip check",
        "https://slsa.dev/provenance/v1",
        "https://spdx.dev/Document/v2.3",
    )
    _require_fragments(guidance, required, "consumer attestation guidance")


def check(root: Path) -> None:
    root = root.resolve()
    _check_release_workflow(root)
    _check_verifier(root)
    _check_consumer_guidance(root)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify AgentCapDiff release attestation identity and binding controls."
    )
    parser.add_argument("--root", type=Path, default=Path("."))
    args = parser.parse_args(argv)
    try:
        check(args.root)
    except (OSError, UnicodeDecodeError, AttestationIntegrityError) as exc:
        print(f"attestation-integrity: FAIL: {exc}", file=sys.stderr)
        return 1
    print("attestation-integrity: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
