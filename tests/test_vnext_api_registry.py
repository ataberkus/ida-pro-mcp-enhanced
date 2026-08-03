from __future__ import annotations

import importlib.util
import pathlib
import sys

from _mcp_spec_support import call_rpc, load_ida_rpc_module
from ida_pro_mcp.vnext.policy import CANONICAL_TOOLS


def _load_vnext_api():
    rpc = load_ida_rpc_module()
    module_name = "_test_stub_ida_mcp.api_vnext"
    if module_name in sys.modules:
        return rpc, sys.modules[module_name]
    path = pathlib.Path(__file__).resolve().parents[1] / "src" / "ida_pro_mcp" / "ida_mcp" / "api_vnext.py"
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return rpc, module


def test_vnext_registry_is_bounded_and_annotated():
    rpc, _module = _load_vnext_api()
    tools = call_rpc(rpc.MCP_SERVER, "tools/list")["tools"]
    names = {tool["name"] for tool in tools}
    assert names <= CANONICAL_TOOLS
    assert len(names) <= 35
    assert {"server_capabilities", "analysis_run", "mutation_preview"} <= names
    for tool in tools:
        assert "annotations" in tool
        assert tool["_meta"]["ida_mcp"]["canonical"] is True


def test_vnext_prompts_and_resources_are_registered():
    rpc, _module = _load_vnext_api()
    prompts = call_rpc(rpc.MCP_SERVER, "prompts/list")["prompts"]
    assert {prompt["name"] for prompt in prompts} == {
        "triage_binary",
        "explain_function",
        "trace_input_to_sink",
        "deobfuscate_component",
        "compare_binaries",
        "review_patch",
        "generate_report",
    }
    resources = call_rpc(rpc.MCP_SERVER, "resources/list")["resources"]
    assert "ida://server/capabilities" in {resource["uri"] for resource in resources}
    templates = call_rpc(rpc.MCP_SERVER, "resources/templates/list")["resourceTemplates"]
    assert any("/jobs/{job_id}" in resource["uriTemplate"] for resource in templates)


def test_readonly_profile_hides_commit_debug_and_python_tools():
    rpc, _module = _load_vnext_api()
    rpc.configure_tool_policy(scopes={"read"}, legacy_tools=False)
    names = {tool["name"] for tool in call_rpc(rpc.MCP_SERVER, "tools/list")["tools"]}
    assert "mutation_preview" in names
    assert "mutation_commit" not in names
    assert "debug_session" not in names
    assert "python_execute" not in names
