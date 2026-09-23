"""Bridge test fixtures: load IDA-free modules by file path.

The ida_mcp package __init__ imports idaapi (only available inside IDA), so
bridge tests must import the standalone modules directly from their file paths
without triggering the package __init__.
"""

import importlib.util
import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
IDA_MCP_DIR = REPO_ROOT / "src" / "ida_pro_mcp" / "ida_mcp"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session", autouse=True)
def _isolated_instance_dir(tmp_path_factory):
    """Keep GUI discovery off the real instances dir for the whole session."""
    target = str(tmp_path_factory.mktemp("instances"))
    previous = os.environ.get("IDA_MCP_INSTANCE_DIR")
    os.environ["IDA_MCP_INSTANCE_DIR"] = target
    try:
        yield target
    finally:
        if previous is None:
            os.environ.pop("IDA_MCP_INSTANCE_DIR", None)
        else:
            os.environ["IDA_MCP_INSTANCE_DIR"] = previous


@pytest.fixture(scope="session")
def discovery():
    return _load_module("ida_mcp_discovery", IDA_MCP_DIR / "bridge_discovery.py")
