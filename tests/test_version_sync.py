from pathlib import Path

import agentcapdiff


def test_runtime_version_matches_pyproject():
    pyproject = Path("pyproject.toml").read_text(encoding="utf-8")
    assert f'version = "{agentcapdiff.__version__}"' in pyproject
