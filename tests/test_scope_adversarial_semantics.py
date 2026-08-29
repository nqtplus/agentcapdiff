from agentcapdiff.formats import markdown_diff_report
from agentcapdiff.models import ToolRecord
from agentcapdiff.scopes import (
    infer_filesystem_scope,
    infer_network_scope,
    scope_is_expansion,
    scope_uncertainty_increased,
)


def _property(name: str, schema: dict) -> dict:
    return {"type": "object", "properties": {name: schema}}


def test_default_is_annotation_not_a_filesystem_restriction():
    tool = ToolRecord(
        "read_file",
        input_schema=_property("path", {"type": "string", "default": "./reports/**"}),
    )
    scope = infer_filesystem_scope(tool)
    assert scope.kind == "unknown"
    assert scope.values == ()


def test_examples_are_annotations_not_network_restrictions():
    tool = ToolRecord(
        "fetch_url",
        input_schema=_property(
            "url",
            {"type": "string", "examples": ["https://api.example.com/v1"]},
        ),
    )
    scope = infer_network_scope(tool)
    assert scope.kind == "unknown"
    assert scope.values == ()


def test_anyof_with_unbounded_alternative_is_unknown():
    tool = ToolRecord(
        "read_file",
        input_schema={
            "anyOf": [
                _property("path", {"enum": ["./reports/**"]}),
                _property("path", {"type": "string"}),
            ]
        },
    )
    assert infer_filesystem_scope(tool).kind == "unknown"


def test_oneof_with_all_finite_alternatives_preserves_union():
    tool = ToolRecord(
        "fetch_url",
        input_schema={
            "oneOf": [
                _property("url", {"const": "https://api.example.com/v1"}),
                _property("url", {"const": "https://backup.example.com/v1"}),
            ]
        },
    )
    scope = infer_network_scope(tool)
    assert scope.kind == "restricted"
    assert scope.values == (
        "https://api.example.com/v1",
        "https://backup.example.com/v1",
    )


def test_not_enum_is_not_treated_as_positive_scope_evidence():
    tool = ToolRecord(
        "read_file",
        input_schema={
            "type": "object",
            "not": _property("path", {"enum": ["./secrets/**"]}),
        },
    )
    assert infer_filesystem_scope(tool).kind == "unknown"


def test_unused_defs_do_not_create_reassuring_scope():
    tool = ToolRecord(
        "read_file",
        input_schema={
            "type": "object",
            "$defs": {
                "unused": _property("path", {"enum": ["./reports/**"]}),
            },
        },
    )
    assert infer_filesystem_scope(tool).kind == "unknown"


def test_allof_finite_branch_with_neutral_branch_stays_restricted():
    tool = ToolRecord(
        "read_file",
        input_schema={
            "allOf": [
                _property("path", {"enum": ["./reports/**"]}),
                {"type": "object", "properties": {"mode": {"type": "string"}}},
            ]
        },
    )
    scope = infer_filesystem_scope(tool)
    assert scope.kind == "restricted"
    assert scope.values == ("./reports/**",)


def test_camel_case_scope_aliases_are_normalized():
    filesystem = ToolRecord(
        "read_file",
        input_schema=_property("allowedPath", {"const": "./reports/**"}),
    )
    network = ToolRecord(
        "fetch_url",
        input_schema=_property("requestUrl", {"const": "https://api.example.com/v1"}),
    )
    assert infer_filesystem_scope(filesystem).values == ("./reports/**",)
    assert infer_network_scope(network).values == ("https://api.example.com/v1",)


def test_unconstrained_schema_overrides_reassuring_description():
    tool = ToolRecord(
        "read_file",
        "Read files restricted to ./reports/**",
        input_schema=_property("path", {"type": "string"}),
    )
    assert infer_filesystem_scope(tool).kind == "unknown"


def test_restricted_to_unknown_is_uncertainty_increase_not_proven_expansion():
    before = {"kind": "restricted", "values": ["./reports/**"]}
    after = {"kind": "unknown", "values": []}
    assert not scope_is_expansion(before, after)
    assert scope_uncertainty_increased(before, after)


def test_markdown_flags_loss_of_scope_certainty_for_review():
    diff = {
        "base_risk_score": 10,
        "head_risk_score": 10,
        "scope_changes": [
            {
                "capability": "filesystem.read",
                "tool": "read_file",
                "before": {"kind": "restricted", "values": ["./reports/**"]},
                "after": {"kind": "unknown", "values": []},
            }
        ],
        "scope_expansions": [],
    }
    report = markdown_diff_report(diff)
    assert "SCOPE UNCERTAINTY INCREASED" in report
    assert "REVIEW REQUIRED" in report
