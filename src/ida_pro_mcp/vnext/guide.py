"""MCP ``initialize`` instructions shared by the IDA plugin, supervisor, and bridge."""

TOOL_GUIDE = """\
IDA Pro reverse-engineering tools. Suggested flow:
1. analysis_run(mode="triage") first: entrypoints, imports, strings, ranked functions.
2. Read code with analysis_run(mode="function", targets=[...]) or decompile(addr); page long pseudocode with line_offset/line_limit and continue from next_line_offset.
3. Pseudocode lines carry /*0xEA*/ markers: the address of that line, usable as any addr argument.
4. graph_query: kind="callsite_args" for concrete call arguments; "callers"/"path" for reachability; "xrefs"/"calls"/"cfg"/"field_xrefs" for references and structure.
5. search(kind=text|regex|bytes|constant|instruction|crypto|ctree, targets=[...]) finds things; entity_query lists functions, globals, imports, strings, segments, entrypoints, locals.
6. memory_read(kind=bytes|integer|string|global|struct|patch_diff) reads static data.
Edits: mutation_preview(operations, commit=true) applies annotate-only edits (rename, comment, type) in one call; other edits: mutation_preview, review, then mutation_commit(transaction_id); mutation_rollback undoes the latest.
Addresses accept hex (0x401000), symbol names (demangled short names too), name+0xN.
Prefer small limits and page with next_cursor (decompile: next_line_offset). Oversized results are truncated with a notice saying how to narrow the request."""

SUPERVISOR_GUIDE = TOOL_GUIDE + """
Databases: idb_open(input_path) opens a binary; long analyses return state="opening" (or pass wait=false) and calls fail fast until idb_list shows state="ready".
database= is optional when exactly one database is open; otherwise pass a session id, filename, or basename from idb_list.
analysis_run(mode="binary_diff", options={"right_database": ...}) diffs two open databases (database= is the left side)."""

BRIDGE_GUIDE = TOOL_GUIDE + """
Tools are prefixed per running IDA instance; ida_list_instances maps prefixes to instances."""
