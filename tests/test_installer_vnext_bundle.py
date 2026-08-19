from pathlib import Path

from ida_pro_mcp import installer


def test_installer_declares_embedded_ida_vnext_bundle():
    """The IDA installer must bundle vNext outside the bridge environment."""
    source = Path(installer.IDA_VNEXT_PKG)
    assert source.is_dir()
    assert (source / "contracts.py").is_file()
    assert (source / "function_review.py").is_file()
    assert Path(installer.IDA_VNEXT_INIT).is_file()
