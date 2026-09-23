# Tools improvement: cut, agent ergonomics, new capabilities

Date: 2026-09-23
Branch: one feature branch, three phases (A → B → C), one or more commits per phase.
Evidence: audit reports `agent://AuditCore`, `agent://AuditMutate`, `agent://AuditVnext`,
`agent://AuditServer`, `agent://AuditErgonomics` (file:line grounded, grep-verified callers).

## Decisions

- Tool visibility stays allow-all (commit c419026 intent preserved). Discoverability is
  fixed with docstring cross-references, not by hiding tools.
- Legacy MCP tools superseded by a canonical tool are **deleted** as tools. If a canonical
  tool delegates to the legacy implementation via `_legacy_call`, the implementation
  survives as a private helper (or the canonical tool calls it directly); only the
  `@tool` registration and its policy entry go.
- New capabilities extend existing canonical tools (`entity_query`, `memory_read`,
  `analysis_run`, `mutation_preview`) with new `kind`/`mode` values. No new top-level tools.

## Invariants (every phase)

- All IDA SDK calls stay on the main thread (`@idasync` / existing `_legacy_call` path).
- Canonical tool names, parameters, and output envelopes keep working, except where Phase B
  changes them explicitly (enums narrow accepted values to those already accepted).
- After each phase: `uv run ida-mcp-test tests/crackme03.elf -q` and
  `uv run ida-mcp-test tests/typed_fixture.elf -q` pass. Tests whose only purpose was
  pinning a deleted tool/helper are deleted with it, not rewritten.

## Phase A — Cut

Rule: delete only after `lsp references` / grep confirms no production caller remains.
When a deleted tool was the delegation target of a canonical tool, rewire the canonical
tool to the surviving private implementation in the same commit.

### A1. Dead code (no production callers)
- `vnext/runtime.py` (whole file).
- utils: `handle_large_output`, `get_analysis_prompt` + `DEFAULT_ANALYSIS_PROMPT`,
  `DEMANGLED_TO_EA` + `create_demangled_to_ea_map`, `get_xrefs_from_internal`,
  `refresh_decompiler_widget`.
- api_analysis: `_value_to_le_bytes`, local `clamp_int` (use `utils.clamp_int`),
  one-line delegates `_raw_bin_search`, `_next_head`, `_operand_type`, `_make_searcher`.
- api_core: `_get_func`, `_segment_name_for_ea` (use compat), unused `max_lines` param of
  `_classify_hit_lines`.
- vnext: `merge_analysis_graphs`, `parse_local_renames`, `RevisionTracker.set`,
  dot/mermaid investigation exporters, `default_profile_enabled` (inline `True`),
  `JobRecord.resumable`, `checkpoint_estimate_bytes`, dead `rollback(restore_checkpoint=)`
  branch, `AuditLog` jsonl sink, `force_recompile` policy line, canonical debug names in the
  debug `set_scope` replacement loop, `_legacy_call` unreachable raise / duplicate except /
  dispatch fallback, `binary_diff` stub mode + `compare_binaries` prompt.
- sync: `is_window_active`. http: `get_cors_policy`, `server_port`, inline
  `_check_origin`/`_check_host`. trace: `_TAG_*`/`_CHUNK` aliases.
- `_sigmaker.py`: SIMD-only scan chain (`SigText`, `_ByteIndex`, `_select_seed_run`,
  `_seed_via_index`, `_refine_offsets_into`, `_find_all_simd`, `find_all_offsets`,
  `_CANCEL_POLL_STRIDE`), `MinimalFunctionSignatureGenerator` + `_DecodedInstruction` +
  `_decode_function_for_anchors` + `make_function_signature`, `SignatureParser` +
  `SearchResults` + `from_signature`/`search`/`count_matches`, `InMemoryBuffer` FILE mode and
  unused address mappings, unused `WildcardPolicy` constructors, `IDAVersionInfo`,
  `ProgressReporter`/`UserCanceledError` if unreferenced after the above.
  Precondition: confirm `_speedups` is not shipped/built anywhere in the repo.

### A2. Superseded tools (delete `@tool` + policy entry + tests that only pin them)
| Delete | Superseded by |
|---|---|
| `investigate_binary` (api_investigation.py) | `investigation_start`, `analysis_run(triage)` |
| `diff_before_after` | `mutation_preview` / `mutation_commit` / `mutation_rollback` |
| `list_funcs`, `func_query` | `entity_query(kind="functions")` |
| `xrefs_to` | `xref_query(direction="to")` / `graph_query(kind="xrefs")` |
| `find_regex` | `entity_query(kind="strings", regex=…)` (add case-sensitivity flag first) |
| `dbg_regs_all`, `dbg_regs_remote`, `dbg_gpregs_remote`, `dbg_gpregs`, `dbg_regs_named_remote`, `dbg_regs_named` | `dbg_regs` gains `thread` + `names` args; `debug_state` |
| `make_signature_for_range`, `find_xref_signatures` | `signature_create` |
| `type_apply_batch` | `set_type` (batch) / `mutation_preview` |
| `search_structs` | `type_query(kind="struct"/"udt", filter=…)` |
| Resources: types/structs catalogs, `struct/{name}`, `import/{name}`, `export/{name}`, `xrefs/from`, `idb/segments` | `type_query`, `type_inspect`, `entity_query`, `graph_query`, `survey_binary` |

`make_signature` and `make_signature_for_function` merge into one legacy implementation
(anchor flag) behind `signature_create`. `set_comments`/`append_comments` stay as tools
(mapped by `_OPERATION_TARGETS`) but share one implementation.

### A3. Duplicate helpers → one each
- Callee enumeration (3 → 1, `call_only` flag), caller enumeration (2 → 1),
  disasm renderer (3 → 1), basic-block iterator (capped), segment perm read
  (`compat.get_segment_perm`), `_exec_segments`/`_all_segments` → `_segments(exec_only)`.
- `func_profile` and `export_funcs(json)` reuse `analyze_batch` section builders;
  `_analyze_function_internal` reuses them with its compaction.
- Cursor codecs in api_vnext: one generic per-target cursor for search(instruction) and
  graph_query.
- Mutation flat-form alias stack (`_MUTATION_KIND_ALIASES`, `_reshape_mutation_arguments`,
  `_merge_mutation_fields`, …) → accept canonical shape only; aliases that are documented
  in the tool schema stay as a single dict lookup.
- `_ida_synchronized` → `@idasync`.
- api_python: `_py_eval_locked`/`_py_exec_file_locked` → one capture helper.
- sync: one `_get_env_seconds(name, default, max)`; one kernel-version parser (compat's).
- `bridge_discovery.py` registry read path merged into `discovery.py`; one
  `_get_ida_user_dir`; one `IDB_MANAGEMENT_TOOLS`; idalib `_WORKSPACE_POLICY` mirror removed.
- `rename` stops placing functions into the `/vibe/` dirtree.
- `installer_tui.py` → numbered `input()` menu.
- stdlib: `Path.is_relative_to`, `dataclasses.replace` in `JobManager._copy`,
  `reprlib` for `_bounded_repr`.

## Phase B — Agent ergonomics (canonical tools first, then surviving legacy tools)

1. Closed vocabularies become `Literal[...]` in signatures: `search.kind`,
   `memory_read.kind`, `analysis_run.mode`, `graph_query.kind`, `entity_query.kind`,
   `type_query.kind`, `debug_*` action/mode, `python_execute.mode`, `dataflow_trace.direction`,
   `mutation_preview` operation `kind`. Verify zeromcp emits `enum` for `Literal`; if not,
   add that to the schema generator (one place).
2. `options`/`budgets` dicts become TypedDicts (`total=False`) with every key documented:
   `analysis_run`, `taint_analyze`, `debug_trace`, `investigation_start`.
3. Every unsupported-value error appends `Allowed: a, b, c` (pattern already in
   `type_query` and mutation kinds). One helper, used everywhere.
4. Mutable defaults (`=[]`, `=[...]`) → `None` + normalize.
5. Docstring template for every canonical tool (and each surviving legacy tool):
   line 1 WHEN (use instead of / before which sibling), line 2 RETURNS (shape, envelope keys),
   line 3 LIMITS/NEXT (caps, truncation field, continuation param, follow-up tool).
   Multiplexers document per-kind arity and pagination. Legacy tools with a canonical
   equivalent say `Prefer <canonical>(…)` on line 1.
6. Truncation: canonical tools signal `truncated` + `next_cursor` only; the rpc 50k
   download indirection is mentioned in docstrings of tools that can hit it.
7. Out of scope for B: renaming parameters across tools (breaking; low value vs. cost),
   changing visibility.

## Phase C — New capabilities

All read paths are READ scope. Results use `ToolEnvelope` with `truncated`/`next_cursor`.

### C1. RTTI / vtables — `entity_query(kind="classes" | "vtables")`
- MSVC (PE): locate `??_R4` / `RTTICompleteObjectLocator` via names and by scanning
  `.rdata` for COL candidates (signature 0/1, self-RVA check on x64); walk
  TypeDescriptor → name (demangled), ClassHierarchyDescriptor → base class array;
  vtable = address after the COL pointer; slots until the first non-code pointer.
- Itanium (ELF/Mach-O): `_ZTV*` / `_ZTI*` names and `__cxxabiv1::__class_type_info`,
  `__si_class_type_info`, `__vmi_class_type_info` vtable references; offset-to-top +
  typeinfo ptr + slots.
- Output per class: `name`, `vtable`, `bases[]`, `slots[{index, addr, func_name}]`, `abi`.
- Filter by name regex; paginate.

### C2. Switch tables — `entity_query(kind="switches", targets=[func…])`
- Iterate function items; `ida_nalt.get_switch_info(ea)`; `ida_xref.calc_switch_cases`.
- Output: `insn`, `jumptable`, `ncases`, `default`, `cases[{values[], target}]`.
- No targets → all functions, paginated.

### C3. Patches — `entity_query(kind="patches")` + `memory_read(kind="patch_diff")`
- `ida_bytes.visit_patched_bytes` → `{ea, file_offset, original, patched}`, contiguous
  runs coalesced.
- `patch_diff` returns IDA `.dif` text (`filename` header + `offset: orig new` lines)
  inline. Writing to the input file is excluded (destructive; agent can write the file).

### C4. FLIRT / TIL
- `entity_query(kind="signatures" | "type_libraries")`: enumerate available `.sig` / `.til`
  files under IDA's `sig/` and `til/` dirs for the current processor, plus which are already
  applied/loaded (`ida_funcs.get_idasgn_qty`/`get_idasgn_desc`, loaded TILs).
- `mutation_preview` kinds `apply_flirt {name}` and `load_til {name}` (MODIFY scope),
  committed through the existing transaction flow; commit reports functions renamed /
  types added. Preview is structural (validates the file exists for this processor).

### C5. Function similarity — `analysis_run(mode="similar", targets=[func], options={limit, min_score})`
- Per function: mnemonic sequence (from `FuncItems`), block count, edge count, call count.
- Score = Jaccard on mnemonic 3-gram sets, candidates pre-filtered by size ratio
  (0.5×–2×) of instruction count.
- `ponytail:` comment: O(n) full scan per query; upgrade to MinHash/LSH index if large
  binaries are slow.
- Output: ranked `[{addr, name, score, insn_count}]`.

## Testing

- Phase A: existing suites on both fixtures; deleted-tool tests removed with the tool.
- Phase B: one test that `tools/list` schema for a Literal param contains `enum`; one test
  that an invalid `kind` error lists allowed values. No per-docstring tests.
- Phase C, one semantic test per capability:
  - switches: fixture function with a switch (add to `typed_fixture` source if none exists)
    → case targets match disassembly.
  - patches: `patch` a byte → `entity_query(patches)` shows orig/new → `patch_diff` line
    matches → revert.
  - similarity: a function is its own top match with score 1.0.
  - FLIRT/TIL: list non-empty on the fixture; `load_til` round-trip via preview/commit/
    rollback where the TIL is available, runtime skip otherwise.
  - RTTI: generic test skips when no RTTI; sanity run against
    `C:\CodeBlocks\x64dbg\bin\x64\x64dbg.dll` (MSVC C++) per CLAUDE.md.
