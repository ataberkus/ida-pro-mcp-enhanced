from typing import Annotated
import ast
import contextlib
import io
import os
import traceback
import threading
import idaapi
import idc
import ida_bytes
import ida_dbg
import ida_entry
import ida_frame
import ida_funcs
import ida_hexrays
import ida_ida
import ida_kernwin
import ida_lines
import ida_nalt
import ida_name
import ida_segment
import ida_typeinf
import ida_xref

from .rpc import tool, unsafe
from .sync import idasync
from .utils import parse_address, get_function

# ============================================================================
# Python Evaluation
# ============================================================================


def _make_exec_globals() -> dict:
    """Create an execution context with IDA modules available."""

    def lazy_import(module_name):
        try:
            return __import__(module_name)
        except Exception:
            return None

    return {
        "__builtins__": __builtins__,
        "idaapi": idaapi,
        "idc": idc,
        "idautils": lazy_import("idautils"),
        "ida_allins": lazy_import("ida_allins"),
        "ida_auto": lazy_import("ida_auto"),
        "ida_bitrange": lazy_import("ida_bitrange"),
        "ida_bytes": ida_bytes,
        "ida_dbg": ida_dbg,
        "ida_dirtree": lazy_import("ida_dirtree"),
        "ida_diskio": lazy_import("ida_diskio"),
        "ida_entry": ida_entry,
        "ida_expr": lazy_import("ida_expr"),
        "ida_fixup": lazy_import("ida_fixup"),
        "ida_fpro": lazy_import("ida_fpro"),
        "ida_frame": ida_frame,
        "ida_funcs": ida_funcs,
        "ida_gdl": lazy_import("ida_gdl"),
        "ida_graph": lazy_import("ida_graph"),
        "ida_hexrays": ida_hexrays,
        "ida_ida": ida_ida,
        "ida_idd": lazy_import("ida_idd"),
        "ida_idp": lazy_import("ida_idp"),
        "ida_ieee": lazy_import("ida_ieee"),
        "ida_kernwin": ida_kernwin,
        "ida_libfuncs": lazy_import("ida_libfuncs"),
        "ida_lines": ida_lines,
        "ida_loader": lazy_import("ida_loader"),
        "ida_merge": lazy_import("ida_merge"),
        "ida_mergemod": lazy_import("ida_mergemod"),
        "ida_moves": lazy_import("ida_moves"),
        "ida_nalt": ida_nalt,
        "ida_name": ida_name,
        "ida_netnode": lazy_import("ida_netnode"),
        "ida_offset": lazy_import("ida_offset"),
        "ida_pro": lazy_import("ida_pro"),
        "ida_problems": lazy_import("ida_problems"),
        "ida_range": lazy_import("ida_range"),
        "ida_regfinder": lazy_import("ida_regfinder"),
        "ida_registry": lazy_import("ida_registry"),
        "ida_search": lazy_import("ida_search"),
        "ida_segment": ida_segment,
        "ida_segregs": lazy_import("ida_segregs"),
        "ida_srclang": lazy_import("ida_srclang"),
        "ida_strlist": lazy_import("ida_strlist"),
        "ida_struct": lazy_import("ida_struct"),
        "ida_tryblks": lazy_import("ida_tryblks"),
        "ida_typeinf": ida_typeinf,
        "ida_ua": lazy_import("ida_ua"),
        "ida_undo": lazy_import("ida_undo"),
        "ida_xref": ida_xref,
        "ida_enum": lazy_import("ida_enum"),
        "parse_address": parse_address,
        "get_function": get_function,
    }


_PY_EXEC_LOCK = threading.Lock()
_PY_VALUE_MAX_CHARS = 20000


def _capped_text(s: str) -> str:
    if len(s) > _PY_VALUE_MAX_CHARS:
        return s[:_PY_VALUE_MAX_CHARS] + f"...<truncated {len(s) - _PY_VALUE_MAX_CHARS} chars>"
    return s


def _run_captured(run) -> dict:
    """Run ``run()`` under the exec lock with stdout/stderr captured."""
    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()
    try:
        with _PY_EXEC_LOCK, contextlib.redirect_stdout(stdout_capture), contextlib.redirect_stderr(stderr_capture):
            result_value = run()
        return {
            "result": _capped_text(result_value or ""),
            "stdout": _capped_text(stdout_capture.getvalue()),
            "stderr": _capped_text(stderr_capture.getvalue()),
        }
    except Exception as exc:
        return {
            "result": "",
            "stdout": _capped_text(stdout_capture.getvalue()),
            "stderr": _capped_text(traceback.format_exc()),
            "error": f"{type(exc).__name__}: {exc}",
        }


def _eval_code(code: str) -> str | None:
    exec_globals = _make_exec_globals()
    exec_locals = {}

    def _exec_and_pick(source) -> str | None:
        exec(source, exec_globals, exec_locals)
        exec_globals.update(exec_locals)
        # Return 'result' variable if explicitly set, else the last assigned variable
        if "result" in exec_locals:
            return str(exec_locals["result"])
        if exec_locals:
            return str(exec_locals[list(exec_locals.keys())[-1]])
        return None

    # Parse code with AST to properly handle execution
    try:
        tree = ast.parse(code)
    except SyntaxError:
        # If parsing fails, fall back to direct exec
        return _exec_and_pick(code)

    if not tree.body:
        return None
    if len(tree.body) == 1 and isinstance(tree.body[0], ast.Expr):
        # Single expression - use eval
        return str(eval(code, exec_globals))
    if isinstance(tree.body[-1], ast.Expr):
        # Multiple statements, last one is an expression (Jupyter-style)
        exec_tree = ast.Module(body=tree.body[:-1], type_ignores=[])
        exec(compile(exec_tree, "<string>", "exec"), exec_globals, exec_locals)
        exec_globals.update(exec_locals)
        eval_tree = ast.Expression(body=tree.body[-1].value)
        return str(eval(compile(eval_tree, "<string>", "eval"), exec_globals))
    # All statements (no trailing expression)
    return _exec_and_pick(code)


@tool
@idasync
@unsafe
def py_eval(
    code: Annotated[str, "Python code"],
) -> dict:
    """Prefer python_execute(mode="eval", code=...) (delegates here; requires isolated python scope).
    WHEN: evaluate Python statements/expression in the IDA context with stdout/stderr captured.
    RETURNS: {result?, stdout, stderr, error?}.
    LIMITS: UNSAFE; output text capped (truncated marker); exceptions surface as error entries, not raises."""
    return _run_captured(lambda: _eval_code(code))


def _exec_file(file_path: str) -> str | None:
    exec_globals = _make_exec_globals()
    exec_globals["__file__"] = file_path
    exec_globals["__name__"] = "__main__"
    exec_globals["__package__"] = None
    with open(file_path, "r", encoding="utf-8") as f:
        code = f.read()
    exec(compile(code, file_path, "exec"), exec_globals)
    result = exec_globals.get("result")
    return None if result is None else str(result)


@tool
@idasync
@unsafe
def py_exec_file(
    file_path: Annotated[str, "Absolute path to a Python script to execute"],
) -> dict:
    """Prefer python_execute(mode="file", path=...) (delegates here; requires isolated python scope).
    WHEN: run a whole script file in the IDA context (single shared globals dict) with stdout/stderr captured.
    RETURNS: {result?, stdout, stderr, error?}.
    LIMITS: UNSAFE; missing file returns error entries; top-level definitions visible to all script code."""
    if not os.path.isfile(file_path):
        error = f"File not found: {file_path}"
        return {"result": "", "stdout": "", "stderr": error, "error": error}
    return _run_captured(lambda: _exec_file(file_path))
