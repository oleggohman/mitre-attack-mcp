"""Version consistency."""

import tomllib
from pathlib import Path

from mitre_mcp_server import server


def test_version_matches_pyproject():
    root = Path(__file__).resolve().parent.parent
    data = tomllib.loads((root / "pyproject.toml").read_text())
    assert server.__version__ == "0.4.0"
    assert server.__version__ == data["project"]["version"]
