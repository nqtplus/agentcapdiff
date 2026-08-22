from agentcapdiff.models import ToolRecord
from agentcapdiff.scopes import infer_filesystem_scope, infer_network_scope


def test_multiple_finite_paths_remain_restricted():
    tool = ToolRecord("read_file", input_schema={"properties": {"path": {"enum": ["./reports/**", "./exports/**"]}}})
    scope = infer_filesystem_scope(tool)
    assert scope.kind == "restricted"
    assert set(scope.values) == {"./reports/**", "./exports/**"}


def test_multiple_finite_domains_remain_restricted():
    tool = ToolRecord("fetch_url", input_schema={"properties": {"domain": {"enum": ["api.example.com", "cdn.example.com"]}}})
    scope = infer_network_scope(tool)
    assert scope.kind == "restricted"
    assert set(scope.values) == {"api.example.com", "cdn.example.com"}
