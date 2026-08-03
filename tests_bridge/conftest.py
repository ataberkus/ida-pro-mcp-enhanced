"""Bridge test fixtures: load IDA-free modules by file path.

The ida_mcp package __init__ imports idaapi (only available inside IDA), so
bridge tests must import the standalone modules (discovery, registry) directly
from their file paths without triggering the package __init__.
"""

import importlib.util
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


@pytest.fixture(scope="session")
def discovery():
    return _load_module("ida_mcp_discovery", IDA_MCP_DIR / "bridge_discovery.py")


@pytest.fixture(scope="session")
def registry():
    return _load_module("ida_mcp_registry", IDA_MCP_DIR / "registry.py")
