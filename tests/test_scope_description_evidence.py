from agentcapdiff.models import ToolRecord
from agentcapdiff.scopes import infer_filesystem_scope, infer_network_scope


def test_description_only_filesystem_restriction_is_supported():
    scope = infer_filesystem_scope(ToolRecord("read_file", "Read files only under ./reports/**"))
    assert scope.kind == "restricted"
    assert scope.values == ("./reports/**",)


def test_description_only_network_restriction_is_supported():
    scope = infer_network_scope(ToolRecord("fetch_url", "Fetch restricted to https://api.example.com/v1"))
    assert scope.kind == "restricted"
    assert scope.values == ("https://api.example.com/v1",)
