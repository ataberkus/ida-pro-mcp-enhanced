import functools
import re
import itertools
import logging
import os
import queue
import sys
import tempfile
import threading
import time
import traceback

import idaapi
import ida_kernwin
import ida_pro
import idc
from .rpc import McpToolError
from .zeromcp.jsonrpc import get_current_cancel_event, RequestCancelledError

# ============================================================================
# IDA Synchronization & Error Handling
# ============================================================================

def _parse_kernel_version(version: str) -> tuple[int, int]:
    nums = [int(part) for part in re.findall(r"\d+", version)]
    return (nums[0] if nums else 0, nums[1] if len(nums) > 1 else 0)


ida_major, ida_minor = _parse_kernel_version(idaapi.get_kernel_version())


class IDAError(McpToolError):
    def __init__(self, message: str):
        super().__init__(message)

    @property
    def message(self) -> str:
        return self.args[0]


class IDASyncError(Exception):
    pass


class CancelledError(RequestCancelledError):
    """Raised when a request is cancelled via notifications/cancelled."""

    pass


logger = logging.getLogger(__name__)
_TOOL_TIMEOUT_ENV = "IDA_MCP_TOOL_TIMEOUT_SEC"
_DEFAULT_TOOL_TIMEOUT_SEC = 60.0
_SEARCH_PAGE_BUDGET_ENV = "IDA_MCP_SEARCH_PAGE_BUDGET_SEC"
_DEFAULT_SEARCH_PAGE_BUDGET_SEC = 5.0
_MAX_SEARCH_PAGE_BUDGET_SEC = 20.0
_CONTENDED_SEARCH_PAGE_BUDGET_ENV = "IDA_MCP_CONTENDED_SEARCH_PAGE_BUDGET_SEC"
_DEFAULT_CONTENDED_SEARCH_PAGE_BUDGET_SEC = 0.25
_MAX_CONTENDED_SEARCH_PAGE_BUDGET_SEC = 1.0
_SYNC_QUEUE_TIMEOUT_ENV = "IDA_MCP_SYNC_QUEUE_TIMEOUT_SEC"
_DEFAULT_SYNC_QUEUE_TIMEOUT_SEC = 10.0
_RESULT_GRACE_SEC = 5.0
_MAX_SYNC_QUEUE_TOTAL_WAIT_SEC = 60.0
_MAX_SYNC_QUEUE_TOTAL_WAIT_ENV = "IDA_MCP_SYNC_QUEUE_MAX_WAIT_SEC"
_SYNC_LOG_ENV = "IDA_MCP_SYNC_LOG"
_ERROR_LOG_ENV = "IDA_MCP_ERROR_LOG"
_sync_request_ids = itertools.count(1)
_sync_diag_lock = threading.Lock()
_tool_context = threading.local()

# Per-tool monotonic deadline (or None if no timeout). Tools can read this to
# self-monitor and return partial results before the hard timeout fires.
_deadline_state = threading.local()


def get_tool_deadline() -> float | None:
    """Return the monotonic deadline for the current tool call, or None."""
    return getattr(_deadline_state, "deadline", None)


def _get_tool_timeout_seconds() -> float:
    value = os.getenv(_TOOL_TIMEOUT_ENV, "").strip()
    if value == "":
        return _DEFAULT_TOOL_TIMEOUT_SEC
    try:
        timeout = float(value)
    except ValueError:
        return _DEFAULT_TOOL_TIMEOUT_SEC
    if timeout <= 0 or timeout != timeout or timeout == float("inf"):
        return _DEFAULT_TOOL_TIMEOUT_SEC
    return timeout


def _get_max_sync_queue_total_wait_seconds() -> float:
    value = os.getenv(_MAX_SYNC_QUEUE_TOTAL_WAIT_ENV, "").strip()
    if value == "":
        return _MAX_SYNC_QUEUE_TOTAL_WAIT_SEC
    try:
        total = float(value)
    except ValueError:
        return _MAX_SYNC_QUEUE_TOTAL_WAIT_SEC
    if total <= 0 or total != total or total == float("inf"):
        return _MAX_SYNC_QUEUE_TOTAL_WAIT_SEC
    return total


def get_search_page_budget_seconds(*, contended: bool = False) -> float:
    """Return a bounded search-page budget below common MCP client timeouts."""
    value = os.getenv(_SEARCH_PAGE_BUDGET_ENV, "").strip()
    if value == "":
        budget = _DEFAULT_SEARCH_PAGE_BUDGET_SEC
    else:
        try:
            budget = float(value)
        except ValueError:
            budget = _DEFAULT_SEARCH_PAGE_BUDGET_SEC
    if budget <= 0:
        budget = _DEFAULT_SEARCH_PAGE_BUDGET_SEC
    budget = min(budget, _MAX_SEARCH_PAGE_BUDGET_SEC)
    if not contended:
        return budget

    contended_value = os.getenv(_CONTENDED_SEARCH_PAGE_BUDGET_ENV, "").strip()
    if contended_value == "":
        contended_budget = _DEFAULT_CONTENDED_SEARCH_PAGE_BUDGET_SEC
    else:
        try:
            contended_budget = float(contended_value)
        except ValueError:
            contended_budget = _DEFAULT_CONTENDED_SEARCH_PAGE_BUDGET_SEC
    if contended_budget <= 0:
        contended_budget = _DEFAULT_CONTENDED_SEARCH_PAGE_BUDGET_SEC
    return min(budget, contended_budget, _MAX_CONTENDED_SEARCH_PAGE_BUDGET_SEC)


def get_pending_ui_request_count() -> int:
    """Return callbacks waiting behind the active Qt main-thread request."""
    dispatcher = globals().get("_qt_main_thread_dispatcher")
    if dispatcher is None:
        return 0
    pending = getattr(dispatcher, "_pending_callbacks", ())
    return len(pending)


def get_active_ui_request_function() -> str | None:
    """Return the function name of the active Qt UI request, if any."""
    dispatcher = globals().get("_qt_main_thread_dispatcher")
    if dispatcher is None:
        return None
    active = getattr(dispatcher, "_active_callback", None)
    if active is None:
        return None
    name = getattr(active, "_ida_mcp_function", None)
    return str(name) if name else "<active>"


def _get_sync_queue_timeout_seconds() -> float:
    value = os.getenv(_SYNC_QUEUE_TIMEOUT_ENV, "").strip()
    if value == "":
        return _DEFAULT_SYNC_QUEUE_TIMEOUT_SEC
    try:
        timeout = float(value)
    except ValueError:
        return _DEFAULT_SYNC_QUEUE_TIMEOUT_SEC
    return timeout if timeout > 0 else _DEFAULT_SYNC_QUEUE_TIMEOUT_SEC


def _get_default_log_directory() -> str:
    directory = os.path.join(tempfile.gettempdir(), "ida_pro_enhanced_logs")
    try:
        os.makedirs(directory, exist_ok=True)
    except OSError:
        return tempfile.gettempdir()
    return directory


def _get_sync_log_path() -> str:
    override = os.getenv(_SYNC_LOG_ENV, "").strip()
    if override:
        return os.path.abspath(os.path.expandvars(os.path.expanduser(override)))
    return os.path.join(
        _get_default_log_directory(), f"ida-pro-mcp-sync-{os.getpid()}.log"
    )


_SYNC_LOG_PATH = _get_sync_log_path()


def _get_error_log_path() -> str:
    override = os.getenv(_ERROR_LOG_ENV, "").strip()
    if override:
        return os.path.abspath(os.path.expandvars(os.path.expanduser(override)))
    return os.path.join(
        os.path.dirname(_SYNC_LOG_PATH), f"ida-pro-mcp-errors-{os.getpid()}.log"
    )


_ERROR_LOG_PATH = _get_error_log_path()
_ERROR_STAGES = {
    "call_stack_mismatch",
    "cleanup_exception",
    "decompile_failed",
    "queue_start_timeout",
    "queue_submit_exception",
    "result_timeout",
    "reentrant_rejected",
    "tool_exception",
    "tool_reported_error",
    "ui_turn_defer_exception",
}


def get_sync_log_path() -> str:
    """Return the request-level synchronization diagnostic log path."""
    return _SYNC_LOG_PATH


def get_error_log_path() -> str:
    """Return the error-only diagnostic log path."""
    return _ERROR_LOG_PATH


def _append_diagnostic_line(path: str, line: str) -> None:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "a", encoding="utf-8") as log_file:
        log_file.write(line + "\n")


def _sync_diag(request_id: int, stage: str, **fields) -> None:
    """Append one structured synchronization event without risking the request."""
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())
    details = " ".join(
        f"{key}={_bounded_repr(value)}" for key, value in fields.items()
    )
    line = (
        f"{timestamp} pid={os.getpid()} tid={threading.get_ident()} "
        f"request={request_id} stage={stage} {details}".rstrip()
    )
    try:
        with _sync_diag_lock:
            _append_diagnostic_line(_SYNC_LOG_PATH, line)
            if stage in _ERROR_STAGES:
                _append_diagnostic_line(_ERROR_LOG_PATH, line)
    except OSError:
        logger.exception("Unable to write IDA MCP sync diagnostics")
    logger.info("IDA MCP sync: %s", line)


def _bounded_repr(value, limit: int = 2000) -> str:
    """Return a single-line bounded representation suitable for diagnostics."""
    try:
        rendered = repr(value)
    except BaseException as exc:
        rendered = f"<unrepresentable {type(value).__name__}: {exc}>"
    rendered = rendered.replace("\r", "\\r").replace("\n", "\\n")
    if len(rendered) > limit:
        rendered = rendered[: limit - 3] + "..."
    return rendered


def log_tool_diagnostic(stage: str, **fields) -> None:
    """Append a diagnostic event associated with the active IDA tool request."""
    request_id = getattr(_tool_context, "request_id", 0)
    function = getattr(_tool_context, "function", None)
    if function is not None and "function" not in fields:
        fields["function"] = function
    _sync_diag(request_id, stage, **fields)


_REPORTED_ERROR_KEYS = {"error", "errors", "failure", "failures", "decompile_error"}


def _reported_error_summary(value, *, max_depth: int = 4, max_items: int = 32) -> str | None:
    """Summarize structured failures returned as ordinary tool values."""
    findings: list[str] = []

    def visit(item, path: str, depth: int) -> None:
        if len(findings) >= max_items or depth > max_depth:
            return
        if isinstance(item, dict):
            if item.get("ok") is False:
                findings.append(f"{path}.ok=False")
            status = item.get("status")
            if isinstance(status, str) and status.lower() in {"error", "failed", "failure"}:
                findings.append(f"{path}.status={_bounded_repr(status, 200)}")
            for key, child in item.items():
                child_path = f"{path}.{key}"
                if str(key).lower() in _REPORTED_ERROR_KEYS:
                    if child not in (None, False, "", [], {}):
                        context = {
                            context_key: item[context_key]
                            for context_key in (
                                "input",
                                "addr",
                                "function_addr",
                                "function_name",
                                "name",
                                "index",
                                "kind",
                                "reason",
                            )
                            if context_key in item
                            and not isinstance(item[context_key], (dict, list, tuple))
                        }
                        context_text = (
                            f" context={_bounded_repr(context, 500)}" if context else ""
                        )
                        findings.append(
                            f"{child_path}={_bounded_repr(child, 500)}{context_text}"
                        )
                elif isinstance(child, (dict, list, tuple)):
                    visit(child, child_path, depth + 1)
        elif isinstance(item, (list, tuple)):
            for index, child in enumerate(item[:max_items]):
                visit(child, f"{path}[{index}]", depth + 1)

    visit(value, "$", 0)
    if not findings:
        return None
    return "; ".join(findings)[:2000]


def _result_outcome(result) -> str:
    if isinstance(result, BaseException):
        return "error"
    if _reported_error_summary(result) is not None:
        return "reported_error"
    return "ok"


def _load_qt_core():
    using_pyside6 = (ida_major > 9) or (ida_major == 9 and ida_minor >= 2)
    if using_pyside6:
        from PySide6 import QtCore
    else:
        from PyQt5 import QtCore
    return QtCore


_HEADLESS = False

try:
    _qt_core = _load_qt_core()
except ImportError:
    # Headless idalib (IDA 9.2+): PySide6/PyQt5 refuse to load outside the
    # GUI. Fall back to IDA's execute_sync scheduler, which works in both
    # GUI and headless modes.
    _HEADLESS = True
    _qt_core = None

if _HEADLESS:
    _DISPATCH_EVENT_TYPE = None
    _QtDispatchEvent = None  # type: ignore[assignment,misc]
    _QtMainThreadDispatcher = None  # type: ignore[assignment,misc]
    _qt_main_thread_dispatcher = None
else:
    _DISPATCH_EVENT_TYPE = _qt_core.QEvent.Type(_qt_core.QEvent.registerEventType())


    class _QtDispatchEvent(_qt_core.QEvent):
        def __init__(self, callback):
            super().__init__(_DISPATCH_EVENT_TYPE)
            self.callback = callback


    class _QtMainThreadDispatcher(_qt_core.QObject):
        def __init__(self):
            super().__init__()
            self._pending_callbacks = []
            self._active_callback = None

        def _run_next(self):
            if self._active_callback is not None or not self._pending_callbacks:
                return
            callback = self._pending_callbacks.pop(0)
            self._active_callback = callback
            try:
                callback()
            finally:
                self._active_callback = None
                if self._pending_callbacks:
                    # Drain on a fresh event-loop turn. Hex-Rays may pump nested Qt
                    # events while decompiling; keeping the dispatcher active until
                    # the callback returns prevents those deliveries from entering
                    # IDA concurrently.
                    _qt_core.QCoreApplication.postEvent(
                        self, _QtDispatchEvent(None)
                    )

        def event(self, event):
            if event.type() == _DISPATCH_EVENT_TYPE:
                callback = event.callback
                event.callback = None
                if callback is not None:
                    self._pending_callbacks.append(callback)
                if self._active_callback is not None:
                    request_id = getattr(callback, "_ida_mcp_request_id", 0)
                    _sync_diag(
                        request_id,
                        "ui_event_deferred",
                        function=getattr(callback, "_ida_mcp_function", "<drain>"),
                        active_request=getattr(
                            self._active_callback, "_ida_mcp_request_id", None
                        ),
                        pending=len(self._pending_callbacks),
                    )
                    return True
                self._run_next()
                return True
            return super().event(event)


    _qt_main_thread_dispatcher = _QtMainThreadDispatcher()


_SYNC_SCHEDULER = "execute_sync" if _HEADLESS else "qt_post_event"


def _post_to_main_thread(callback) -> None:
    """Post a thread-safe event to the Qt object owned by IDA's main thread."""
    if _HEADLESS:
        idaapi.execute_sync(callback, idaapi.MFF_WRITE)
        return
    event = _QtDispatchEvent(callback)
    _qt_core.QCoreApplication.postEvent(_qt_main_thread_dispatcher, event)


def _defer_until_next_ui_turn(callback) -> None:
    """Run callback on a later Qt event-loop turn."""
    if _HEADLESS:
        # No Qt event loop exists; execute_sync already ran the callback on
        # the IDA main thread, so release the worker immediately.
        callback()
        return
    _qt_core.QTimer.singleShot(0, callback)


call_stack: list[str] = []
_sync_diag(
    0,
    "module_loaded",
    queue_timeout=_get_sync_queue_timeout_seconds(),
    scheduler=_SYNC_SCHEDULER,
    log_path=_SYNC_LOG_PATH,
    error_log_path=_ERROR_LOG_PATH,
)


def _sync_wrapper(ff):
    """Run ff synchronously through IDA's Qt main-thread event queue."""
    request_id = next(_sync_request_ids)
    queued_at = time.monotonic()
    queue_timeout = _get_sync_queue_timeout_seconds()
    res_container = queue.Queue(maxsize=1)
    started_event = threading.Event()
    state_lock = threading.Lock()
    state = {"started": False, "abandoned": False}
    on_main_thread = ida_pro.is_main_thread()
    _sync_diag(
        request_id,
        "created",
        function=ff.__name__,
        caller_thread=threading.get_ident(),
        main_thread=on_main_thread,
        queue_timeout=queue_timeout,
    )

    def release_result_after_ui_turn(result) -> None:
        def release_result():
            res_container.put(result)
            _sync_diag(
                request_id,
                "ui_turn_released",
                function=ff.__name__,
                outcome=_result_outcome(result),
            )

        if on_main_thread:
            release_result()
            return
        try:
            _defer_until_next_ui_turn(release_result)
        except BaseException as exc:
            error = IDASyncError(
                f"Unable to defer completion of UI request {request_id} "
                f"({ff.__name__}): {exc}; diagnostics: {_SYNC_LOG_PATH}"
            )
            res_container.put(error)
            _sync_diag(
                request_id,
                "ui_turn_defer_exception",
                function=ff.__name__,
                error=repr(exc),
                traceback=traceback.format_exc().replace("\n", "\\n"),
            )

    def runned():
        with state_lock:
            if state["abandoned"]:
                _sync_diag(
                    request_id,
                    "late_callback_skipped",
                    function=ff.__name__,
                    queued_for=time.monotonic() - queued_at,
                )
                return False
            state["started"] = True
            started_event.set()

        callback_started_at = time.monotonic()
        _sync_diag(
            request_id,
            "ui_started",
            function=ff.__name__,
            queued_for=callback_started_at - queued_at,
            main_thread=ida_pro.is_main_thread(),
        )
        if call_stack and not on_main_thread:
            last_func_name = call_stack[-1]
            error = IDASyncError(
                f"Call stack is not empty while calling the function "
                f"{ff.__name__} from {last_func_name}"
            )
            _sync_diag(
                request_id,
                "reentrant_rejected",
                function=ff.__name__,
                error=repr(error),
            )
            release_result_after_ui_turn(error)
            return False
        if call_stack:
            _sync_diag(
                request_id,
                "nested_main_thread_call",
                function=ff.__name__,
                parent_function=call_stack[-1],
                depth=len(call_stack) + 1,
            )

        call_stack.append(ff.__name__)
        old_batch = None
        result = None
        previous_request_id = getattr(_tool_context, "request_id", None)
        previous_function = getattr(_tool_context, "function", None)
        _tool_context.request_id = request_id
        _tool_context.function = ff.__name__
        try:
            old_batch = idc.batch(1)
            result = ff()
            reported_error = _reported_error_summary(result)
            if reported_error is not None:
                _sync_diag(
                    request_id,
                    "tool_reported_error",
                    function=ff.__name__,
                    summary=reported_error,
                )
        except BaseException as exc:
            result = exc
            _sync_diag(
                request_id,
                "tool_exception",
                function=ff.__name__,
                error=repr(exc),
                traceback=traceback.format_exc().replace("\n", "\\n"),
            )
        finally:
            cleanup_error = None
            if old_batch is not None:
                try:
                    idc.batch(old_batch)
                except BaseException as exc:
                    cleanup_error = exc
                    _sync_diag(
                        request_id,
                        "cleanup_exception",
                        function=ff.__name__,
                        error=repr(exc),
                        traceback=traceback.format_exc(),
                    )
            if call_stack and call_stack[-1] == ff.__name__:
                call_stack.pop()
            else:
                _sync_diag(
                    request_id,
                    "call_stack_mismatch",
                    function=ff.__name__,
                    stack=list(call_stack),
                )
                call_stack.clear()
            if previous_request_id is None:
                _tool_context.__dict__.pop("request_id", None)
            else:
                _tool_context.request_id = previous_request_id
            if previous_function is None:
                _tool_context.__dict__.pop("function", None)
            else:
                _tool_context.function = previous_function
            if cleanup_error is not None and not isinstance(result, BaseException):
                result = cleanup_error

        _sync_diag(
            request_id,
            "ui_finished",
            function=ff.__name__,
            elapsed=time.monotonic() - callback_started_at,
            outcome=_result_outcome(result),
        )
        # Release the worker on a later Qt turn. A chained request can then be
        # posted safely even if this dispatch event has not returned yet.
        release_result_after_ui_turn(result)
        return False

    runned._ida_mcp_request_id = request_id
    runned._ida_mcp_function = ff.__name__

    if on_main_thread:
        runned()
    else:
        try:
            _post_to_main_thread(runned)
        except BaseException as exc:
            _sync_diag(
                request_id,
                "queue_submit_exception",
                function=ff.__name__,
                scheduler=_SYNC_SCHEDULER,
                error=repr(exc),
                traceback=traceback.format_exc().replace("\n", "\\n"),
            )
            raise IDASyncError(
                f"IDA rejected Qt UI request {request_id} for {ff.__name__}: "
                f"{exc}; diagnostics: {_SYNC_LOG_PATH}"
            ) from exc

        _sync_diag(
            request_id,
            "queued",
            function=ff.__name__,
            scheduler=_SYNC_SCHEDULER,
        )

        # Wait for UI start. If another MCP tool is already running on the UI
        # thread (e.g. survey_binary for 20s+), keep extending the idle timer so
        # concurrent callers do not abandon and skip late callbacks.
        max_total = _get_max_sync_queue_total_wait_seconds()
        total_deadline = queued_at + max(queue_timeout, max_total)
        idle_deadline = time.monotonic() + queue_timeout
        while not started_event.is_set():
            remaining = idle_deadline - time.monotonic()
            if remaining <= 0:
                if started_event.is_set():
                    break
                active_function = get_active_ui_request_function()
                if active_function is not None:
                    if time.monotonic() >= total_deadline:
                        break
                    idle_deadline = time.monotonic() + queue_timeout
                    _sync_diag(
                        request_id,
                        "queue_wait_extended",
                        function=ff.__name__,
                        waited=time.monotonic() - queued_at,
                        active_function=active_function,
                        queue_timeout=queue_timeout,
                    )
                    continue
                break
            started_event.wait(timeout=min(1.0, max(remaining, 0.05)))

        if not state["started"]:
            with state_lock:
                timed_out_before_start = not state["started"]
                if timed_out_before_start:
                    state["abandoned"] = True
            if timed_out_before_start:
                waited = time.monotonic() - queued_at
                _sync_diag(
                    request_id,
                    "queue_start_timeout",
                    function=ff.__name__,
                    waited=waited,
                    queue_timeout=queue_timeout,
                )
                raise IDASyncError(
                    f"IDA Qt UI queue did not start request {request_id} "
                    f"({ff.__name__}) within {waited:.2f}s idle "
                    f"(limit {queue_timeout:.2f}s; total limit {max_total:.2f}s); "
                    f"diagnostics: {_SYNC_LOG_PATH}"
                )

    timeout = _normalize_timeout(getattr(ff, "__ida_mcp_timeout_sec__", None))
    result_timeout = (timeout if timeout and timeout > 0 else _DEFAULT_TOOL_TIMEOUT_SEC) + _RESULT_GRACE_SEC
    try:
        res = res_container.get(timeout=result_timeout)
    except queue.Empty:
        with state_lock:
            state["abandoned"] = True
        _sync_diag(
            request_id,
            "result_timeout",
            function=ff.__name__,
            waited=result_timeout,
            tool_timeout=timeout,
        )
        raise IDASyncError(
            f"IDA tool {ff.__name__} did not complete within {result_timeout:.2f}s "
            f"(tool timeout {timeout:.2f}s); diagnostics: {_SYNC_LOG_PATH}"
        )
    _sync_diag(
        request_id,
        "worker_received",
        function=ff.__name__,
        total_elapsed=time.monotonic() - queued_at,
        outcome=_result_outcome(res),
    )
    if isinstance(res, BaseException):
        raise res
    return res


def _normalize_timeout(value: object) -> float | None:
    if value is None:
        return None
    try:
        timeout = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    if timeout <= 0 or timeout != timeout or timeout == float("inf"):
        return None
    return timeout


def sync_wrapper(ff, timeout_override: float | None = None):
    """Wrapper to enable timeout and cancellation during IDA synchronization.

    Note: Batch mode is now handled in _sync_wrapper to ensure it's always
    applied consistently for all synchronized operations.
    """
    # Capture cancel event from thread-local before execute_sync
    cancel_event = get_current_cancel_event()

    timeout = timeout_override
    if timeout is None:
        timeout = _get_tool_timeout_seconds()
    if timeout > 0 or cancel_event is not None:

        def timed_ff():
            # Calculate deadline when execution starts on IDA main thread,
            # not when the request was queued (avoids stale deadlines).
            deadline = time.monotonic() + timeout if timeout > 0 else None

            # Python profiling cannot interrupt pure-C IDA SDK scans. The
            # native cancellation flag is thread-safe and is polled by search,
            # decompiler, string-list, and auto-analysis APIs.
            ida_kernwin.clr_cancelled()
            cancel_fired_at: list[float | None] = [None]
            native_timer: threading.Timer | None = None
            if deadline is not None:

                def _fire_native_cancel():
                    cancel_fired_at[0] = time.monotonic()
                    ida_kernwin.set_cancelled()

                native_timer = threading.Timer(timeout, _fire_native_cancel)
                native_timer.daemon = True
                native_timer.start()

            def profilefunc(frame, event, arg):
                if cancel_event is not None and cancel_event.is_set():
                    ida_kernwin.set_cancelled()
                    raise CancelledError("Request was cancelled")
                fired_at = cancel_fired_at[0]
                if fired_at is not None and time.monotonic() < fired_at + 5.0:
                    return
                if deadline is not None and time.monotonic() >= deadline:
                    raise IDASyncError(f"Tool timed out after {timeout:.2f}s")

            old_profile = sys.getprofile()
            sys.setprofile(profilefunc)
            _deadline_state.deadline = deadline
            try:
                return ff()
            finally:
                sys.setprofile(old_profile)
                if native_timer is not None:
                    native_timer.cancel()
                ida_kernwin.clr_cancelled()
                _deadline_state.deadline = None

        timed_ff.__name__ = ff.__name__
        return _sync_wrapper(timed_ff)
    return _sync_wrapper(ff)


def idasync(f):
    """Run the function on the IDA main thread in write mode.

    This is the unified decorator for all IDA synchronization.
    Previously there were separate @idaread and @idawrite decorators,
    but since read-only operations in IDA might actually require write
    access (e.g., decompilation), we now use a single decorator.
    """

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ff = functools.partial(f, *args, **kwargs)
        ff.__name__ = f.__name__
        timeout_override = _normalize_timeout(
            getattr(f, "__ida_mcp_timeout_sec__", None)
        )
        if timeout_override is None:
            timeout_override = _normalize_timeout(
                getattr(wrapper, "__ida_mcp_timeout_sec__", None)
            )
        else:
            setattr(wrapper, "__ida_mcp_timeout_sec__", timeout_override)
        return sync_wrapper(ff, timeout_override)

    return wrapper


def tool_timeout(seconds: float):
    """Decorator to override per-tool timeout (seconds).

    Order no longer matters: the attribute is propagated through
    __wrapped__ chains by both this decorator and idasync.
    """

    try:
        seconds_value = float(seconds)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        raise ValueError("tool_timeout requires seconds > 0")
    if seconds_value <= 0 or seconds_value != seconds_value or seconds_value == float("inf"):
        raise ValueError("tool_timeout requires seconds > 0")

    def decorator(func):
        setattr(func, "__ida_mcp_timeout_sec__", seconds_value)
        wrapped = func
        seen = set()
        while wrapped is not None and id(wrapped) not in seen:
            seen.add(id(wrapped))
            wrapped = getattr(wrapped, "__wrapped__", None)
            if wrapped is None:
                break
            setattr(wrapped, "__ida_mcp_timeout_sec__", seconds_value)
        return func

    return decorator


def is_window_active():
    """Returns whether IDA is currently active."""
    if _HEADLESS:
        return False
    # Source: https://github.com/OALabs/hexcopy-ida/blob/8b0b2a3021d7dc9010c01821b65a80c47d491b61/hexcopy.py#L30
    using_pyside6 = (ida_major > 9) or (ida_major == 9 and ida_minor >= 2)

    if using_pyside6:
        from PySide6 import QtWidgets
    else:
        from PyQt5 import QtWidgets

    app = QtWidgets.QApplication.instance()
    if app is None:
        return False
    return app.activeWindow() is not None
