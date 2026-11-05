"""Protocol tests: the server as a real stdio subprocess (testing plan D5).

The fixture is synchronous with an anyio blocking portal: an async module-scoped fixture fails at
teardown under the repo's function-scoped event loop. No network: the data directory is a temp dir
of symlinks to the cached bundles and any download attempt is pointed at a dead proxy.
"""

import json
import os
import sys
from pathlib import Path

import pytest
from anyio.from_thread import start_blocking_portal
from mcp import Client
from mcp.client.stdio import StdioServerParameters, stdio_client
from tool_args import ARGS, DEFAULT_WIRE_BUDGET

from mitre_mcp_server import server

pytestmark = pytest.mark.protocol

DEAD_PROXY = "http://127.0.0.1:9"


def _env(data_dir: Path, layer_dir: Path) -> dict:
    return {
        "MITRE_MCP_DATA_DIR": str(data_dir),
        "MITRE_MCP_LAYER_DIR": str(layer_dir),
        "HTTP_PROXY": DEAD_PROXY,
        "HTTPS_PROXY": DEAD_PROXY,
        "http_proxy": DEAD_PROXY,
        "https_proxy": DEAD_PROXY,
    }


def _linked_data_dir(root: Path) -> Path:
    """Temp data dir whose bundles are symlinks to the cached files at their expected layout."""
    data = root / "data"
    for domain in server.DOMAINS:
        src = server.get_stix_path(domain)
        if not src.exists():
            msg = f"STIX bundle for {domain} not available at {src}"
            if os.environ.get("MITRE_MCP_REQUIRE_DATA") == "1":
                pytest.fail(msg)
            pytest.skip(msg)
        rel = src.relative_to(server.DATA_DIR)
        link = data / rel
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(src)
    return data


@pytest.fixture(scope="module")
def session(tmp_path_factory):
    root = tmp_path_factory.mktemp("proto")
    data = _linked_data_dir(root)
    err_path = root / "stderr.log"
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "mitre_mcp_server.server"],
        env=_env(data, root / "layers"),
    )
    with open(err_path, "w") as err, start_blocking_portal() as portal:
        with portal.wrap_async_context_manager(Client(stdio_client(params, errlog=err))) as client:
            yield portal, client, err_path
    # Exiting the context closed stdin; the server must have exited (no hang) and logged to stderr.


def _call(session, name, args):
    portal, client, _ = session
    return portal.call(client.call_tool, name, args)


def test_tool_count_matches_in_process_and_table(session):
    portal, client, _ = session
    tools = portal.call(client.list_tools).tools
    in_process = {t.name for t in portal.call(server.mcp.list_tools)}
    assert {t.name for t in tools} == in_process == set(ARGS)
    assert len(tools) == len(ARGS)


def test_every_tool_has_description_and_object_schema(session):
    portal, client, _ = session
    for tool in portal.call(client.list_tools).tools:
        assert tool.description and tool.description.strip(), tool.name
        assert tool.input_schema["type"] == "object", tool.name
        assert tool.output_schema is not None, tool.name


CALLS = [
    ("get_technique_by_id", {"technique_id": "T1059.001", "domain": "enterprise"}),
    ("get_technique_by_id", {"technique_id": "T0800", "domain": "ics"}),
    ("get_all_tactics", {"domain": "mobile"}),
    ("get_technique_by_id", {"technique_id": "AML.T0000", "domain": "atlas"}),
    ("get_all_subtechniques", {"domain": "enterprise", "limit": 5, "offset": 5}),
    ("generate_technique_layer", {"techniques": ["T1059", "T1003.001"], "domain": "enterprise"}),
]


@pytest.mark.parametrize("name,args", CALLS, ids=[f"{n}-{a.get('domain')}" for n, a in CALLS])
def test_calls_over_the_wire(session, name, args):
    res = _call(session, name, args)
    assert res.is_error is False
    assert json.loads(res.content[0].text) == res.structured_content["result"]
    result = res.structured_content["result"]
    assert result.get("found", result.get("success", True)) is not False
    if "limit" in args:
        assert result["returned"] == args["limit"]
        assert result["offset"] == args["offset"]


def test_group_techniques_wire_size_within_budget(session):
    res = _call(session, "get_group_techniques", {"group_name": "Scattered Spider"})
    assert res.is_error is False
    assert len(res.model_dump_json(by_alias=True)) <= DEFAULT_WIRE_BUDGET
    assert res.structured_content["result"]["group"]["attack_id"] == "G1015"


def test_invalid_domain_is_an_error_and_server_survives(session):
    bad = _call(session, "get_technique_by_id", {"technique_id": "T1059", "domain": "bogus"})
    assert bad.is_error is True
    assert "Error executing tool" in bad.content[0].text
    good = _call(session, "get_technique_by_id", {"technique_id": "T1059", "domain": "enterprise"})
    assert good.is_error is False


def test_stderr_reports_existing_data_and_no_download(session):
    _, _, err_path = session
    text = err_path.read_text()
    assert "Using existing data" in text
    assert "Loaded 4 domains" in text
    assert "Downloading" not in text


def test_console_script_lists_tools(tmp_path):
    script = Path(sys.executable).parent / "mitre-mcp-server"
    if not script.exists():
        msg = f"console script not installed at {script}"
        if os.environ.get("MITRE_MCP_REQUIRE_DATA") == "1":
            pytest.fail(msg)
        pytest.skip(msg)
    data = _linked_data_dir(tmp_path)
    params = StdioServerParameters(command=str(script), env=_env(data, tmp_path / "layers"))
    with open(tmp_path / "stderr.log", "w") as err, start_blocking_portal() as portal:
        with portal.wrap_async_context_manager(Client(stdio_client(params, errlog=err))) as client:
            tools = portal.call(client.list_tools).tools
    assert len(tools) == len(ARGS)
