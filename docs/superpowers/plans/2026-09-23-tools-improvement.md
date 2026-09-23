# Tools Improvement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cut ~4.6k lines of dead/duplicate code and superseded tools, make the canonical tool surface self-describing for agents, and add RTTI, switch, patch, FLIRT/TIL, and similarity capabilities.

**Architecture:** Three sequential phases on branch `tools-improvement`. Phase A tasks own disjoint files and run in parallel. Phase B changes the schema generator first, then the docstrings and signatures. Phase C adds one new module, `api_recovery.py`, and hooks it into the existing canonical dispatchers.

**Tech Stack:** Python 3.11, IDA 9.x SDK / idalib, vendored zeromcp, `uv run ida-mcp-test` (in-IDA tests), `uv run pytest tests` (host tests).

**Spec:** `docs/superpowers/specs/2026-09-23-tools-improvement-design.md`

## Global Constraints

- All IDA SDK calls run on the main thread: `@tool` + `@idasync` for legacy tools; canonical api_vnext tools reach IDA only via `_legacy_call` or `@idasync` helpers.
- Tool visibility stays allow-all. Do not change `LEGACY_TOOLS_ENABLED` or `CANONICAL_TOOLS` membership except to remove the names of deleted tools.
- Delete only after `lsp references` or grep shows no production caller. Tests whose only purpose was pinning a deleted symbol get deleted with it.
- Baselines to hold (or to drop only by the count of deleted tests): crackme03 `314 passed`, typed_fixture `295 passed, 1 skipped`, pytest `291 passed`.
- Subagents do NOT run the full suites. Each task runs only its own targeted check; the integration owner (Main) runs the suites at the end of each phase.
- Mark deliberate shortcuts with a `# ponytail:` comment.

Commands:
- `uv run ida-mcp-test tests/crackme03.elf -q`
- `uv run ida-mcp-test tests/typed_fixture.elf -q`
- `uv run ida-mcp-test tests/typed_fixture.elf -p "*<pattern>*"` (targeted)
- `uv run pytest tests -q -p no:cacheprovider`

---

## Phase A — Cut (tasks A1–A5 parallel, disjoint file ownership)

Cross-task contract: `api_vnext.py` and `vnext/policy.py` are owned by **A3**. If A1, A2 or A4 deletes a tool that api_vnext dispatches to (`_legacy_call("<name>")`) or that policy.py lists, message A3 over hub with the tool name and its replacement. A3 rewires the call and drops the policy entry. `utils.py` is owned by A2.

### Task A1: Signature engine
**Files:** `ida_mcp/_sigmaker.py`, `ida_mcp/api_sigmaker.py`, `ida_mcp/tests/test_api_sigmaker*.py`
- [ ] Delete from `_sigmaker.py` the SIMD chain (`SigText`, `_ByteIndex`, `_select_seed_run`, `_seed_via_index`, `_refine_offsets_into`, `_find_all_simd`, `find_all_offsets`, `_CANCEL_POLL_STRIDE`, `_shared_buffer` and any `_speedups` import), `MinimalFunctionSignatureGenerator`, `_DecodedInstruction`, `_decode_function_for_anchors`, `SignatureMaker._function_generator`/`make_function_signature`, `SignatureParser`, `SearchResults`, `from_signature`/`search`/`count_matches`, `InMemoryBuffer` FILE mode and address mappings (delete `InMemoryBuffer` entirely if only the SIMD path used it), the unused `WildcardPolicy` constructors (keep `for_x86`, `detect_from_processor`, `current`), and `IDAVersionInfo`, `ProgressReporter` and `UserCanceledError` if they are unreferenced afterwards. Replace `configure_logging` with `logging.getLogger(__name__)`.
- [ ] Delete the tools `make_signature_for_range` and `find_xref_signatures`. Merge `make_signature` into `make_signature_for_function` via a private `_make_signatures(addrs, anchor: Literal["function","exact"], ...)`. Keep `make_signature` as a tool that calls it with `anchor="exact"`.
- [ ] Tell A3: `make_signature_for_range` and `find_xref_signatures` are deleted (drop them from policy/aliases).
- [ ] Check: `uv run ida-mcp-test tests/crackme03.elf -p "*sig*"` passes.
- [ ] Commit `refactor(sigmaker): drop dead SIMD/parser/generator paths and superseded tools`.

### Task A2: Core/analysis/utils/compat
**Files:** `api_core.py`, `api_analysis.py`, `utils.py`, `compat.py`, matching tests.
- [ ] Dead code: in utils delete `handle_large_output`, `get_analysis_prompt` + `DEFAULT_ANALYSIS_PROMPT`, `DEMANGLED_TO_EA` + `create_demangled_to_ea_map`, `get_xrefs_from_internal`, `refresh_decompiler_widget`; in api_analysis delete `_value_to_le_bytes`, the local `clamp_int`, `_raw_bin_search`, `_next_head`, `_operand_type`, `_make_searcher` (inline them); in api_core delete `_get_func` and `_segment_name_for_ea` (use `compat.get_func` / `compat.get_segment_name`), and the dead `max_lines` parameter.
- [ ] Superseded tools: delete `list_funcs`, `func_query`, `xrefs_to`. Before deleting `find_regex`, add `"case_sensitive": NotRequired[bool]` to `EntityQuery`; when it is false, `entity_query` compiles its regex with `re.IGNORECASE` (default true, i.e. current behaviour). Callers that need the old `find_regex` behaviour pass `case_sensitive: false`. Keep `imports`, but implement it as a filter-free call into the `imports_query` path.
- [ ] Duplicate helpers: one callee enumerator `_collect_callees(func, call_only: bool)`, one caller enumerator, one disasm renderer, one capped basic-block iterator, `compat.get_segment_perm(seg)`, `_segments(exec_only)`. `func_profile` and `export_funcs(json)` reuse the analyze_batch section builders. Drop the dead fallbacks in `compat.get_func`, `get_segment_info` and `get_segment_name`.
- [ ] Tell A3 which tools were deleted (`list_funcs`, `func_query`, `xrefs_to`, `find_regex`) and that `utils` symbol X was removed if api_vnext imports it.
- [ ] Check: `uv run ida-mcp-test tests/crackme03.elf -c api_core` and `-c api_analysis` pass.
- [ ] Commit `refactor(core): remove dead helpers and superseded listing/xref tools`.

### Task A3: vNext + composite + investigation (owner of api_vnext.py and vnext/policy.py)
**Files:** `api_vnext.py`, `api_composite.py`, `api_investigation.py`, `api_survey.py`, `__init__.py`, `vnext/*`, matching tests.
- [ ] Delete `api_investigation.py` (and its import in `__init__.py`) and `diff_before_after`. Keep any `api_survey._build_*` helper that has a remaining caller.
- [ ] Delete `vnext/runtime.py`, `merge_analysis_graphs`, `parse_local_renames`, `RevisionTracker.set`, the dot/mermaid exporters, `default_profile_enabled` (inline `True` at its http.py call sites), `JobRecord.resumable`, `checkpoint_estimate_bytes`, the `rollback(restore_checkpoint=)` branch, the `AuditLog` jsonl sink, the `force_recompile` policy, the canonical debug names in the debug replacement loop, the `_legacy_call` dead branches, and the `binary_diff` mode plus the `compare_binaries` prompt.
- [ ] Cursor unification: replace `_instruction_cursor_states`/`_instruction_next_cursor`/`_batch_cursor_states`/`_batch_next_cursor` with one `_per_target_cursor_states(cursor, n, key)` + `_per_target_next_cursor(result, pending, n, key)`. Keep `start` support for the instruction search kind.
- [ ] Mutation alias stack: keep `_MUTATION_KIND_ALIASES` as a single dict lookup. Delete `_reshape_mutation_arguments` branches that exist only for undocumented flat forms, but keep the flat-form handling that the `mutation_preview` Annotated text documents. Delete `_mutation_before_state` only if the preview output contract still holds without it (check `test_vnext*`); otherwise keep it.
- [ ] Replace `_ida_synchronized` with `@idasync`. stdlib: `Path.is_relative_to`, `dataclasses.replace` in `JobManager._copy`.
- [ ] Apply the rewiring messages from A1, A2 and A4 (remove deleted names from policy.py; repoint every `_legacy_call`).
- [ ] Check: `uv run pytest tests -q -p no:cacheprovider -k "vnext or policy or function_review or analysis_quality"` passes.
- [ ] Commit `refactor(vnext): drop dead plumbing, superseded tools, duplicate cursors`.

### Task A4: Mutating/memory/types/debug/python/resources
**Files:** `api_debug.py`, `api_types.py`, `api_modify.py`, `api_python.py`, `api_resources.py`, `api_memory.py`, `api_stack.py`, `ui_function_review.py`, `profile.py`, matching tests.
- [ ] Delete `dbg_regs_all`, `dbg_regs_remote`, `dbg_gpregs_remote`, `dbg_gpregs`, `dbg_regs_named_remote`, `dbg_regs_named`; add `thread: int | None = None` and `names: list[str] | None = None` to `dbg_regs`.
- [ ] Delete `type_apply_batch` and `search_structs` (tell A3). Delete the resources that duplicate tools: the types/structs catalogs, `struct/{name}`, `import/{name}`, `export/{name}`, `xrefs/from`, `idb/segments`.
- [ ] `set_comments` and `append_comments` share one `_comment_batch(items, append: bool)`. `rename` stops calling `_place_func_in_vibe_dir` (delete the helper and the `dir`/`dir_error` fields). `_py_eval_locked`/`_py_exec_file_locked` collapse into one capture helper. Merge `_parse_type_tinfo`/`_parse_function_tinfo`. Merge `_require_mapped_range` into `_read_mapped_bytes`.
- [ ] Check: `uv run ida-mcp-test tests/typed_fixture.elf -c api_types`, `-c api_modify`, `-c api_memory`, `-c api_resources` pass.
- [ ] Commit `refactor(api): remove duplicate register/type/resource tools and helpers`.

### Task A5: Server side
**Files:** `sync.py`, `http.py`, `trace.py`, `discovery.py`, `bridge_discovery.py`, `bridge_server.py`, `idalib_server.py`, `idalib_supervisor.py`, `installer.py`, `installer_tui.py`, `test.py`, `trace_dump.py`, matching tests under `tests/`.
- [ ] Delete `sync.is_window_active`, `http.get_cors_policy` and `server_port` (inline `_check_origin`/`_check_host`), and the `trace.py` `_TAG_*`/`_CHUNK` aliases.
- [ ] Add one `_get_env_seconds(name, default, maximum)` in sync.py and use it in all 4 parsers. Use compat's kernel-version parser. Replace `_bounded_repr` with `reprlib`.
- [ ] Merge the `bridge_discovery.py` registry read path into `discovery.py` (keep the public names used by `bridge_server.py`, importing them from `discovery`). Use one `_get_ida_user_dir` and one `IDB_MANAGEMENT_TOOLS`, and remove idalib's `_WORKSPACE_POLICY` mirror (use `rpc.get_workspace_policy()`).
- [ ] Replace the `installer_tui.py` raw-key loop with a numbered `input()` menu that keeps the same function signatures.
- [ ] Check: `uv run pytest tests -q -p no:cacheprovider -k "discovery or installer or supervisor or worker or transport or zeromcp or trace"` passes.
- [ ] Commit `refactor(server): dedupe discovery/env parsing, simplify installer TUI`.

### Task A-int (Main): Integration
- [ ] Run all three suites and fix cross-task breakage. The only allowed count drops are tests that were deleted.
- [ ] `glob`/grep for leftover references to every deleted name (including README/docs tool lists) and update them.

---

## Phase B — Agent ergonomics

### Task B1: Schema generator + allowed-values errors (Main)
**Files:** `zeromcp/mcp.py:_type_to_json_schema`, `tests/test_mcp_spec_schema_generation.py`
- [ ] Failing test: a tool parameter `Literal["a","b"]` produces `{"type":"string","enum":["a","b"]}`.
- [ ] Implement: in `_type_to_json_schema`, `if origin is Literal: vals = list(get_args(py_type)); return {"type": <json type of vals[0]>, "enum": vals}`.
- [ ] Commit `feat(schema): emit enum for Literal parameters`.

### Task B2: Canonical surface (api_vnext.py)
- [ ] Every closed vocabulary becomes `Literal[...]`: search.kind, memory_read.kind, analysis_run.mode, graph_query.kind, dataflow_trace.direction, debug_* action/mode params, python_execute.mode, signature_create.format, investigation_export format.
- [ ] Add TypedDicts (`total=False`) with an Annotated doc per key: `AnalysisOptions` (detail_level, include_asm, max_depth, direction, limit, min_score), `TaintOptions`, `DebugTraceOptions`, `InvestigationBudgets`.
- [ ] Mutable defaults → `None`.
- [ ] Every "Unsupported …" error appends `Allowed: …` via one helper `_unsupported(what, value, allowed)` that raises `VNextError(NOT_SUPPORTED, f"Unsupported {what}: {value}. Allowed: {', '.join(allowed)}")`.
- [ ] Docstrings use the 3-line template (WHEN vs siblings / RETURNS / LIMITS+NEXT). Multiplexers list per-kind arity and pagination.
- [ ] Check: `uv run pytest tests -q -p no:cacheprovider -k "vnext or mcp_spec"` passes; add one test that an invalid `analysis_run` mode error contains `Allowed:`.
- [ ] Commit `feat(vnext): typed enums, documented options, actionable errors`.

### Task B3: Legacy surface docstrings (parallel with B2, different files)
- [ ] Every surviving legacy `@tool` with a canonical equivalent gets line 1 `Prefer <canonical>(...)` + WHEN/RETURNS/LIMITS. `entity_query` and `type_query` get `Literal` kinds and `Allowed:` errors. Mutable defaults → `None`.
- [ ] Check: `uv run ida-mcp-test tests/crackme03.elf -q` (targeted modules only) passes.
- [ ] Commit `docs(tools): cross-reference legacy tools to canonical equivalents`.

---

## Phase C — New capabilities (new module `ida_mcp/api_recovery.py`, tests `ida_mcp/tests/test_api_recovery.py`)

Contract: `api_recovery.py` exposes pure collectors, called on the main thread, that return `list[dict]` rows with an `"addr"` hex string key, so entity_query's filter/sort/paginate pipeline applies unchanged:
- `collect_switches(func_eas: list[int] | None) -> list[dict]`: `{addr, func, jumptable, ncases, default, cases:[{values, target}]}`
- `collect_patches() -> list[dict]`: `{addr, file_offset, size, original, patched}` (hex strings, contiguous runs coalesced)
- `patch_diff_text() -> str`: IDA `.dif` format
- `collect_classes() -> list[dict]`: `{addr (vtable), name, abi, bases:[str], slots:[{index, addr, name}]}`; `kind="vtables"` uses the same rows
- `collect_signature_files() -> list[dict]`, `collect_type_libraries() -> list[dict]`: `{name, path, description, applied|loaded: bool}` (addr = "0x0")
- `similar_functions(ea: int, limit: int, min_score: float) -> list[dict]`: `{addr, name, score, insn_count}`
- `apply_flirt(name) -> dict`, `load_til(name) -> dict`

Hook points:
- `api_core.entity_query`: allowed kinds += `switches, patches, classes, vtables, signatures, type_libraries`. `_collect_entities(kind, query)` routes the new kinds to `api_recovery`. `EntityQuery` gains `targets: NotRequired[list[str]]` (used by `switches`).
- `api_vnext.memory_read`: kind `patch_diff` → `{"text": patch_diff_text()}` (queries ignored; default `None`).
- `api_vnext._analysis_sync`: mode `similar` → `similar_functions(resolve(targets[0]), options.limit=20, options.min_score=0.3)`.
- `api_vnext._OPERATION_TARGETS`: `apply_flirt`, `load_til` → new `@unsafe @tool @idasync` legacy tools `apply_flirt_signature(items)` / `load_type_library(items)` in api_recovery, scope `MODIFY`, registered in policy.py with `replacement="mutation_preview"`.

### Task C1: Switches + patches
- [ ] Failing tests: (a) typed_fixture has a switch → `entity_query({"kind":"switches"})` returns ≥1 row with ≥2 cases whose targets are in the same function; if typed_fixture.c lacks a dense switch, add one to `typed_fixture.c`, rebuild the fixture, and record the build command in the test module docstring. (b) `patch` 1 byte → `entity_query({"kind":"patches"})` row has `original != patched` → `memory_read(kind="patch_diff")` text contains `: <orig> <new>` → restore the original byte.
- [ ] Implement `collect_switches` (`ida_nalt.get_switch_info`, `ida_xref.calc_switch_cases`), `collect_patches` (`ida_bytes.visit_patched_bytes`, `ida_loader.get_fileregion_offset`), and `patch_diff_text`.
- [ ] Commit `feat: switch table and patch enumeration`.

### Task C2: RTTI / vtables
- [ ] Implement MSVC COL scan (PE: data segments, signature 0/1, x64 self-RVA check, TypeDescriptor name `.?AV…` demangled, CHD base array) and Itanium (`_ZTV*` names, typeinfo `_ZTI*`, `__si`/`__vmi` base parsing). Vtable slots run until the first pointer that is not to code.
- [ ] Test: generic, skips with `skip_test("no RTTI")` when empty; otherwise every row's first slot is a function start. Sanity-run against `C:\CodeBlocks\x64dbg\bin\x64\x64dbg.dll` if it exists and report the row count.
- [ ] Commit `feat: RTTI class and vtable recovery`.

### Task C3: FLIRT / TIL
- [ ] Implement listing via `idadir("sig")`/`idadir("til")` walks filtered to the current processor dir, with applied state from `ida_funcs.get_idasgn_qty`/`get_idasgn_desc_with_matches` (or `get_idasgn_desc`), and loaded TILs from `ida_typeinf.get_idati()` base chain. Apply via `ida_funcs.plan_to_apply_idasgn` + `ida_auto.auto_wait()`, and load via `ida_typeinf.add_til(name, ADDTIL_DEFAULT)`.
- [ ] Tests: the listings are non-empty on the fixture; `mutation_preview([{"kind":"load_til","name":<first unloaded til>}])` → commit → the TIL shows `loaded: true` → rollback. Skip if no unloaded TIL exists.
- [ ] Commit `feat: FLIRT signature and type library listing/applying`.

### Task C4: Similarity
- [ ] Implement: per function, mnemonic list via `idautils.FuncItems` + `ida_ua.print_insn_mnem`; 3-gram set; candidates with an instruction-count ratio in [0.5, 2]; Jaccard score; sort desc; `# ponytail: O(n) scan per query, MinHash/LSH index if slow on large IDBs`.
- [ ] Test: `analysis_run(mode="similar", targets=[main])` → top row addr == main, score == 1.0.
- [ ] Commit `feat: function similarity search`.

### Task C-int (Main)
- [ ] Wire policies, run all three suites, update the README tool docs, and update the api count comment in `__init__.py`.
