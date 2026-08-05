import gzip
import subprocess
import sys

from ida_pro_mcp.vnext.trace_reader import iter_records_from_blobs


def test_trace_reader_skips_corrupt_segments_and_lines():
    valid = gzip.compress(
        b'{"tool":"decompile","isError":false}\nnot-json\n', mtime=0
    )

    assert list(iter_records_from_blobs([b"corrupt", valid])) == [
        {"tool": "decompile", "isError": False}
    ]


def test_trace_dump_help_does_not_import_gui_plugin():
    result = subprocess.run(
        [sys.executable, "-m", "ida_pro_mcp.trace_dump", "--help"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0, result.stderr
    assert "Export the tools/call trace" in result.stdout
