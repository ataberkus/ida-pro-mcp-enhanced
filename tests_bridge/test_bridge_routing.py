import pytest


def _tool(name):
    return {"name": name, "description": "", "inputSchema": {"type": "object", "properties": {}}}


def test_single_instance_unprefixed(discovery):
    target = discovery.InstanceTarget(id="a", host="127.0.0.1", port=13337, prefix="")
    table = discovery.build_tool_table([target], {"a": [_tool("decompile"), _tool("xrefs_to")]})
    names = {t["name"] for t in table.list_tools()}
    assert names == {"ida_list_instances", "decompile", "xrefs_to"}


def test_two_instances_prefixed_and_shared_withdrawn(discovery):
    a = discovery.InstanceTarget(id="a", host="127.0.0.1", port=13337, prefix="crackme_exe__")
    b = discovery.InstanceTarget(id="b", host="127.0.0.1", port=13338, prefix="library_dll__")
    tools = {"a": [_tool("decompile")], "b": [_tool("decompile")]}
    table = discovery.build_tool_table([a, b], tools)
    names = {t["name"] for t in table.list_tools()}
    assert "decompile" not in names  # ambiguous shared name withdrawn
    assert "crackme_exe__decompile" in names
    assert "library_dll__decompile" in names
    assert "ida_list_instances" in names


def test_route_resolves_prefixed_name(discovery):
    a = discovery.InstanceTarget(id="a", host="127.0.0.1", port=13337, prefix="crackme_exe__")
    b = discovery.InstanceTarget(id="b", host="127.0.0.1", port=13338, prefix="library_dll__")
    tools = {"a": [_tool("decompile")], "b": [_tool("decompile")]}
    table = discovery.build_tool_table([a, b], tools)
    host, port, inner = discovery.route_tool_call(table, "library_dll__decompile")
    assert (host, port) == ("127.0.0.1", 13338)
    assert inner == "decompile"  # prefix stripped before proxying


def test_route_unknown_prefix_raises(discovery):
    a = discovery.InstanceTarget(id="a", host="127.0.0.1", port=13337, prefix="crackme_exe__")
    b = discovery.InstanceTarget(id="b", host="127.0.0.1", port=13338, prefix="library_dll__")
    table = discovery.build_tool_table([a, b], {"a": [_tool("decompile")], "b": [_tool("decompile")]})
    with pytest.raises(KeyError, match="ida_list_instances"):
        discovery.route_tool_call(table, "ghost__decompile")


def test_single_instance_keeps_unprefixed_names(discovery):
    target = discovery.InstanceTarget(id="a", host="127.0.0.1", port=13337, prefix="")
    table = discovery.build_tool_table([target], {"a": [_tool("decompile")]})
    host, port, inner = discovery.route_tool_call(table, "decompile")
    assert (host, port, inner) == ("127.0.0.1", 13337, "decompile")
