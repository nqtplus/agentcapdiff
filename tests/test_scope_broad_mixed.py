from agentcapdiff.models import ToolRecord
from agentcapdiff.scopes import infer_filesystem_scope


def test_broad_path_marker_dominates_finite_paths():
    scope = infer_filesystem_scope(ToolRecord("read_file", input_schema={"properties": {"path": {"enum": ["./reports/**", "/**"]}}}))
    assert scope.kind == "broad"
