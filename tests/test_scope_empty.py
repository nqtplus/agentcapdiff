from agentcapdiff.models import ToolRecord
from agentcapdiff.scopes import infer_filesystem_scope, infer_network_scope


def test_empty_scope_metadata_stays_unknown():
    assert infer_filesystem_scope(ToolRecord("read_file")).kind == "unknown"
    assert infer_network_scope(ToolRecord("fetch_url")).kind == "unknown"
