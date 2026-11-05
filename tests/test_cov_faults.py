"""Registry-driven fault injection (testing plan D3 #10).

For every ARGS cell the data object returned by `server.get_attack_data` is replaced by a stub
whose every attribute is a callable raising RuntimeError("injected"). The tool's own handlers
therefore run. Expected outcome, one of:
  (a) a documented failure response: non-empty message and no data (found/success False, or an
      empty primary list / count 0);
  (b) only for cells listed in `fault_raises` (with a reason): UnexpectedToolError whose cause
      chain contains the injected RuntimeError.
Anything else (other exception types, success-looking responses) is a crash.
"""

import asyncio

import pytest
from conftest import require_domain
from tool_args import ARGS, cell_args, nonempty, tool_domains

from mitre_mcp_server import server

_TOOLS = {t.name: t.input_schema for t in asyncio.run(server.mcp.list_tools())}
CELLS = [
    (t, d)
    for t in sorted(_TOOLS)
    if t in ARGS and ARGS[t].fault_na is None
    for d in tool_domains(_TOOLS[t])
]


class _Raiser:
    """Callable that raises on call and on any attribute read."""

    def __call__(self, *args, **kwargs):
        raise RuntimeError("injected")

    def __getattr__(self, name):
        raise RuntimeError("injected")

    def __iter__(self):
        raise RuntimeError("injected")


class _Boom:
    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)
        return _Raiser()


def _chain(exc):
    while exc is not None:
        yield exc
        exc = exc.__cause__ or exc.__context__


def test_fault_na_cells_have_reasons():
    for tool, spec in ARGS.items():
        if spec.fault_na is not None:
            assert spec.fault_na.strip(), tool
            assert tool in {"get_layer_metadata", "get_data_stats"}, f"{tool}: unexpected fault_na"


@pytest.mark.parametrize("tool,domain", CELLS, ids=[f"{t}-{d}" for t, d in CELLS])
async def test_data_access_failure_is_handled(tool, domain, monkeypatch):
    if domain:
        require_domain(domain)
    args = cell_args(tool, domain, "default", _TOOLS[tool])  # built from real data before patching
    monkeypatch.setattr(server, "get_attack_data", lambda domain="enterprise": _Boom())
    spec = ARGS[tool]
    try:
        res = await server.mcp.call_tool(tool, args)
    except Exception as exc:
        injected = any(isinstance(e, RuntimeError) and str(e) == "injected" for e in _chain(exc))
        assert type(exc).__name__ == "UnexpectedToolError" and injected, (
            f"crash: {type(exc).__name__}: {exc!r} (cause {exc.__cause__!r})"
        )
        assert spec.fault_raises, (
            f"{tool} raised the injected error but has no fault_raises entry "
            "(add one with a reason, or handle the error in the tool)"
        )
        return
    assert not spec.fault_raises, f"{tool} handled the fault: remove its stale fault_raises entry"
    result = res.structured_content["result"]
    message = result.get("message") or result.get("formatted")
    assert isinstance(message, str) and message.strip(), "failure response without message"
    assert not nonempty(result), f"success-looking response on data failure: {message}"
