from agentcapdiff.diffing import capability_fingerprint


def test_scope_evidence_does_not_change_capability_fingerprint():
    assert capability_fingerprint(["filesystem.read"]) == capability_fingerprint(["filesystem.read"])
