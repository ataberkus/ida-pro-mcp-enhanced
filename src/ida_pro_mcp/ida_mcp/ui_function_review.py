"""In-IDA Hex-Rays function review dialog.

Main-thread only: every function here is called from the IDA UI action handler
and calls IDA APIs directly.

Right-click a decompiled (or disassembled) function to run the same analysis
as analysis_run(mode="function"), edit names/comments, copy an MCP agent
prompt, and apply accepted edits through mutation_preview / mutation_commit.
"""

from __future__ import annotations

from typing import Any

import ida_hexrays
import ida_kernwin

from ida_pro_mcp.vnext.contracts import VNextError
from ida_pro_mcp.vnext.function_review import (
    attach_review_views,
    build_mutation_operations,
    selected_local_renames,
)

from .sync import ida_major, ida_minor


def _qt_modules():
    if (ida_major > 9) or (ida_major == 9 and ida_minor >= 2):
        from PySide6 import QtCore, QtGui, QtWidgets
    else:
        from PyQt5 import QtCore, QtGui, QtWidgets
    return QtCore, QtGui, QtWidgets


def _collect_hexrays_locals(ea: int) -> list[dict[str, Any]]:
    if not ida_hexrays.init_hexrays_plugin():
        return []
    try:
        cfunc = ida_hexrays.decompile(ea)
    except Exception:
        return []
    if cfunc is None:
        return []
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for lvar in cfunc.lvars:
        name = str(getattr(lvar, "name", "") or "").strip()
        if not name or name in seen:
            continue
        seen.add(name)
        is_arg = False
        checker = getattr(lvar, "is_arg_var", None)
        if callable(checker):
            try:
                is_arg = bool(checker())
            except Exception:
                is_arg = False
        elif checker is not None:
            is_arg = bool(checker)
        rows.append({"name": name, "is_arg": is_arg})
    return rows


def collect_function_review(ea: int, *, database: str = "") -> dict[str, Any]:
    """Gather analysis_run(function) evidence plus Hex-Rays locals."""
    import idc

    from .api_composite import _analyze_function_internal

    analysis = _analyze_function_internal(ea)
    analysis["locals"] = _collect_hexrays_locals(ea)
    analysis["function_comment"] = idc.get_func_cmt(ea, False) or idc.get_func_cmt(ea, True) or ""
    return attach_review_views(analysis, database=database)


def apply_function_review(
    *,
    addr: str,
    current_name: str,
    new_name: str,
    comment: str,
    local_renames: list[dict[str, str]],
    current_comment: str = "",
) -> dict[str, Any]:
    """Stage and commit accepted review edits through the mutation path."""
    from .api_vnext import mutation_commit, mutation_preview

    if not str(addr or "").strip():
        return {"ok": False, "error": "Address is required"}
    operations = build_mutation_operations(
        addr=addr,
        current_name=current_name,
        new_name=new_name,
        comment=comment,
        current_comment=current_comment,
        local_renames=local_renames,
    )
    if not operations:
        return {"ok": False, "error": "Nothing to apply"}
    preview = mutation_preview(operations)
    transaction_id = preview.get("transaction_id")
    if not transaction_id:
        return {"ok": False, "error": "mutation_preview did not return a transaction id", "preview": preview}
    receipt = mutation_commit(transaction_id)
    return {"ok": True, "preview": preview, "receipt": receipt}


def copy_text_to_clipboard(text: str) -> bool:
    try:
        _QtCore, QtGui, QtWidgets = _qt_modules()
    except Exception:
        return False
    app = QtWidgets.QApplication.instance()
    if app is None:
        return False
    clipboard = app.clipboard() if hasattr(app, "clipboard") else QtGui.QGuiApplication.clipboard()
    clipboard.setText(text)
    return True


def _warn(message: str) -> None:
    ida_kernwin.warning(message)


def _info(message: str) -> None:
    ida_kernwin.info(message)


class FunctionReviewForm(ida_kernwin.PluginForm):
    def __init__(self, review: dict[str, Any]):
        super().__init__()
        self.review = review
        self._name_edit = None
        self._comment_edit = None
        self._analysis_view = None
        self._local_table = None
        self._Qt = None

    def OnCreate(self, form):
        QtCore, _QtGui, QtWidgets = _qt_modules()
        self._Qt = QtCore.Qt
        converter = getattr(self, "FormToPyQtWidget", None) or getattr(self, "FormToPySideWidget", None)
        self.parent = converter(form)
        self._populate(QtWidgets)

    def _populate(self, QtWidgets):
        review = self.review
        layout = QtWidgets.QVBoxLayout()
        layout.setContentsMargins(8, 8, 8, 8)

        title = f"{review.get('name') or '(unnamed)'}  {review.get('addr') or ''}"
        layout.addWidget(QtWidgets.QLabel(title))

        self._analysis_view = QtWidgets.QPlainTextEdit()
        self._analysis_view.setReadOnly(True)
        self._analysis_view.setPlainText(str(review.get("summary") or ""))
        self._analysis_view.setMinimumHeight(220)
        layout.addWidget(self._analysis_view)

        name_row = QtWidgets.QHBoxLayout()
        name_row.addWidget(QtWidgets.QLabel("New name"))
        self._name_edit = QtWidgets.QLineEdit(str(review.get("name") or ""))
        name_row.addWidget(self._name_edit)
        layout.addLayout(name_row)

        layout.addWidget(QtWidgets.QLabel("Comment"))
        self._comment_edit = QtWidgets.QPlainTextEdit()
        self._comment_edit.setPlainText(str(review.get("function_comment") or ""))
        self._comment_edit.setMaximumHeight(90)
        layout.addWidget(self._comment_edit)

        layout.addWidget(QtWidgets.QLabel("Local renames (fill New only for names you want to change)"))
        self._local_table = QtWidgets.QTableWidget()
        self._local_table.setColumnCount(3)
        self._local_table.setHorizontalHeaderLabels(["Kind", "Current", "New"])
        rows = list(review.get("local_rows") or [])
        self._local_table.setRowCount(len(rows))
        for index, row in enumerate(rows):
            kind = "arg" if str(row.get("is_arg")) in {"1", "True", "true"} else "local"
            kind_item = QtWidgets.QTableWidgetItem(kind)
            self._make_readonly(kind_item)
            current_item = QtWidgets.QTableWidgetItem(str(row.get("name") or ""))
            self._make_readonly(current_item)
            self._local_table.setItem(index, 0, kind_item)
            self._local_table.setItem(index, 1, current_item)
            self._local_table.setItem(index, 2, QtWidgets.QTableWidgetItem(str(row.get("new") or "")))
        header = self._local_table.horizontalHeader()
        header.setStretchLastSection(True)
        self._local_table.setMinimumHeight(140)
        layout.addWidget(self._local_table)

        buttons = QtWidgets.QHBoxLayout()
        apply_btn = QtWidgets.QPushButton("Apply")
        copy_btn = QtWidgets.QPushButton("Copy prompt")
        close_btn = QtWidgets.QPushButton("Close")
        apply_btn.clicked.connect(self._on_apply)
        copy_btn.clicked.connect(self._on_copy_prompt)
        close_btn.clicked.connect(lambda: self.Close(0))
        buttons.addWidget(apply_btn)
        buttons.addWidget(copy_btn)
        buttons.addStretch(1)
        buttons.addWidget(close_btn)
        layout.addLayout(buttons)
        self.parent.setLayout(layout)

    def _make_readonly(self, item) -> None:
        flags = item.flags()
        editable = getattr(self._Qt, "ItemIsEditable", None)
        if editable is None:
            editable = self._Qt.ItemFlag.ItemIsEditable
        item.setFlags(flags & ~editable)

    def _local_renames(self) -> list[dict[str, str]]:
        rows: list[dict[str, str]] = []
        if self._local_table is None:
            return rows
        for index in range(self._local_table.rowCount()):
            current = self._local_table.item(index, 1)
            new = self._local_table.item(index, 2)
            rows.append(
                {
                    "name": current.text() if current else "",
                    "new": new.text() if new else "",
                }
            )
        return selected_local_renames(rows)

    def _on_copy_prompt(self):
        prompt = str(self.review.get("prompt") or "")
        if not prompt:
            _warn("MCP: no prompt to copy")
            return
        if copy_text_to_clipboard(prompt):
            ida_kernwin.msg("[MCP] Function-review prompt copied to the clipboard.\n")
        else:
            _warn("MCP: failed to copy prompt to the clipboard")

    def _on_apply(self):
        new_name = self._name_edit.text() if self._name_edit is not None else ""
        comment = self._comment_edit.toPlainText() if self._comment_edit is not None else ""
        try:
            result = apply_function_review(
                addr=str(self.review.get("addr") or ""),
                current_name=str(self.review.get("name") or ""),
                new_name=new_name,
                comment=comment,
                current_comment=str(self.review.get("function_comment") or ""),
                local_renames=self._local_renames(),
            )
        except VNextError as exc:
            _warn(f"MCP: {exc}")
            return
        except Exception as exc:
            _warn(f"MCP: apply failed: {exc}")
            return
        if not result.get("ok"):
            _warn(f"MCP: {result.get('error') or 'apply failed'}")
            return
        addr = self.review.get("addr")
        if addr:
            try:
                from .utils import refresh_decompiler_ctext, parse_address

                refresh_decompiler_ctext(parse_address(str(addr)))
            except Exception:
                pass
        _info("MCP: applied function-review edits.")
        self.Close(0)


def show_function_review(ea: int) -> None:
    """Collect analysis for *ea* and open the review dialog."""
    from . import compat

    func = compat.get_func(ea)
    if func is None:
        _warn("MCP: cursor is not inside a function")
        return

    ida_kernwin.show_wait_box("HIDECANCEL\nMCP: analyzing function...")
    try:
        review = collect_function_review(func.start_ea)
    except Exception as exc:
        ida_kernwin.hide_wait_box()
        _warn(f"MCP: analysis failed: {exc}")
        return
    ida_kernwin.hide_wait_box()

    if review.get("error"):
        _warn(f"MCP: {review['error']}")
        if not review.get("decompiled") and not review.get("name"):
            return

    try:
        form = FunctionReviewForm(review)
        flags = getattr(ida_kernwin.PluginForm, "WOPN_DP_FLOATING", 0)
        form.Show("MCP Function Review", options=flags)
    except Exception as exc:
        if copy_text_to_clipboard(str(review.get("prompt") or "")):
            _info(f"MCP: UI unavailable ({exc}). Prompt copied to the clipboard.")
        else:
            ida_kernwin.msg(str(review.get("prompt") or ""))
            _warn(f"MCP: UI unavailable ({exc}). Prompt printed to the output window.")
