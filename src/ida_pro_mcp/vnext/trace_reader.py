"""IDA GUI-independent reader for the append-only MCP trace netnode."""

import gzip
import json
from collections.abc import Iterator


IDB_NETNODE_NAME = "$ ida_mcp.trace"
TAG_META = ord("M")
TAG_INDEX = ord("I")
TAG_DATA = ord("D")
CHUNK_SIZE = 1024


def read_netnode_blobs() -> list[bytes]:
    """Return every stored trace segment in segment-id order."""
    import ida_netnode

    node = ida_netnode.netnode(IDB_NETNODE_NAME, 0, False)
    if node == ida_netnode.BADNODE:
        return []
    pairs: list[tuple[int, int]] = []
    index = node.altfirst(TAG_INDEX)
    while index != ida_netnode.BADNODE:
        pairs.append((index, node.altval(index, TAG_INDEX)))
        index = node.altnext(index, TAG_INDEX)
    pairs.sort()

    blobs: list[bytes] = []
    for _, start in pairs:
        blob = node.getblob(start, TAG_DATA)
        if isinstance(blob, tuple):
            blob = blob[0]
        if blob:
            blobs.append(bytes(blob))
    return blobs


def iter_records_from_blobs(blobs: list[bytes]) -> Iterator[dict]:
    """Decode valid JSONL records from compressed trace segments."""
    for blob in blobs:
        try:
            raw = gzip.decompress(blob)
        except OSError:
            continue
        for line in raw.splitlines():
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def iter_netnode_records() -> Iterator[dict]:
    """Iterate every trace record from the currently open IDB."""
    yield from iter_records_from_blobs(read_netnode_blobs())


__all__ = [
    "CHUNK_SIZE",
    "IDB_NETNODE_NAME",
    "TAG_DATA",
    "TAG_INDEX",
    "TAG_META",
    "iter_netnode_records",
    "iter_records_from_blobs",
    "read_netnode_blobs",
]
