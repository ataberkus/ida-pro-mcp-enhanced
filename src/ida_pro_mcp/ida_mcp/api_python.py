from typing import Annotated
import ast
import contextlib
import io
import os
import sys
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


@tool
@idasync
@unsafe
def py_eval(
    code: Annotated[str, "Python code"],
) -> dict:
    """Execute Python in IDA context and return result/stdout/stderr."""
    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()

    try:
        with _PY_EXEC_LOCK, contextlib.redirect_stdout(stdout_capture), contextlib.redirect_stderr(stderr_capture):
            return _py_eval_locked(code, stdout_capture, stderr_capture)
    except Exception as exc:
        import traceback

        return {
            "result": "",
            "stdout": _capped_text(stdout_capture.getvalue()),
            "stderr": _capped_text(traceback.format_exc()),
            "error": f"{type(exc).__name__}: {exc}",
        }


def _py_eval_locked(code: str, stdout_capture: io.StringIO, stderr_capture: io.StringIO) -> dict:
    import traceback

    try:
        exec_globals = _make_exec_globals()
        result_value = None
        exec_locals = {}

        # Parse code with AST to properly handle execution
        try:
            tree = ast.parse(code)
        except SyntaxError:
            # If parsing fails, fall back to direct exec
            exec(code, exec_globals, exec_locals)
            exec_globals.update(exec_locals)
            if "result" in exec_locals:
                result_value = str(exec_locals["result"])
            elif exec_locals:
                last_key = list(exec_locals.keys())[-1]
                result_value = str(exec_locals[last_key])
        else:
            if not tree.body:
                # Empty code
                pass
            elif len(tree.body) == 1 and isinstance(tree.body[0], ast.Expr):
                # Single expression - use eval
                result_value = str(eval(code, exec_globals))
            elif isinstance(tree.body[-1], ast.Expr):
                # Multiple statements, last one is an expression (Jupyter-style)
                # Execute all statements except the last
                if len(tree.body) > 1:
                    exec_tree = ast.Module(body=tree.body[:-1], type_ignores=[])
                    exec(
                        compile(exec_tree, "<string>", "exec"),
                        exec_globals,
                        exec_locals,
                    )
                    exec_globals.update(exec_locals)
                # Eval only the last expression
                eval_tree = ast.Expression(body=tree.body[-1].value)
                result_value = str(
                    eval(compile(eval_tree, "<string>", "eval"), exec_globals)
                )
            else:
                # All statements (no trailing expression)
                exec(code, exec_globals, exec_locals)
                exec_globals.update(exec_locals)
                # Return 'result' variable if explicitly set
                if "result" in exec_locals:
                    result_value = str(exec_locals["result"])
                # Return last assigned variable
                elif exec_locals:
                    last_key = list(exec_locals.keys())[-1]
                    result_value = str(exec_locals[last_key])

        # Collect output
        stdout_text = stdout_capture.getvalue()
        stderr_text = stderr_capture.getvalue()

        return {
            "result": _capped_text(result_value or ""),
            "stdout": _capped_text(stdout_text),
            "stderr": _capped_text(stderr_text),
        }

    except Exception as exc:
        return {
            "result": "",
            "stdout": _capped_text(stdout_capture.getvalue()),
            "stderr": _capped_text(traceback.format_exc()),
            "error": f"{type(exc).__name__}: {exc}",
        }


@tool
@idasync
@unsafe
def py_exec_file(
    file_path: Annotated[str, "Absolute path to a Python script to execute"],
) -> dict:
    """Execute a Python script file in IDA context and return stdout/stderr.

    Unlike py_eval, this runs the entire file with exec() using a single shared
    globals dict (no locals split), so top-level definitions are visible to all
    code in the script.
    """
    if not os.path.isfile(file_path):
        error = f"File not found: {file_path}"
        return {"result": "", "stdout": "", "stderr": error, "error": error}

    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()

    try:
        with _PY_EXEC_LOCK, contextlib.redirect_stdout(stdout_capture), contextlib.redirect_stderr(stderr_capture):
            return _py_exec_file_locked(file_path, stdout_capture, stderr_capture)
    except Exception as exc:
        import traceback

        return {
            "result": "",
            "stdout": _capped_text(stdout_capture.getvalue()),
            "stderr": _capped_text(traceback.format_exc()),
            "error": f"{type(exc).__name__}: {exc}",
        }


def _py_exec_file_locked(file_path: str, stdout_capture: io.StringIO, stderr_capture: io.StringIO) -> dict:
    try:
        exec_globals = _make_exec_globals()
        exec_globals["__file__"] = file_path
        exec_globals["__name__"] = "__main__"
        exec_globals["__package__"] = None

        with open(file_path, "r", encoding="utf-8") as f:
            code = f.read()

        exec(compile(code, file_path, "exec"), exec_globals)

        stdout_text = stdout_capture.getvalue()
        stderr_text = stderr_capture.getvalue()

        result_value = ""
        if "result" in exec_globals and exec_globals["result"] is not None:
            result_value = str(exec_globals["result"])

        return {
            "result": _capped_text(result_value),
            "stdout": _capped_text(stdout_text),
            "stderr": _capped_text(stderr_text),
        }

    except Exception as exc:
        import traceback

        return {
            "result": "",
            "stdout": _capped_text(stdout_capture.getvalue()),
            "stderr": _capped_text(traceback.format_exc()),
            "error": f"{type(exc).__name__}: {exc}",
        }
