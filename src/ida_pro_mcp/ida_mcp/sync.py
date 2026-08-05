import functools
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

ida_major, ida_minor = map(int, idaapi.get_kernel_version().split("."))


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
_SYNC_QUEUE_TIMEOUT_ENV = "IDA_MCP_SYNC_QUEUE_TIMEOUT_SEC"
_DEFAULT_SYNC_QUEUE_TIMEOUT_SEC = 10.0
_SYNC_LOG_ENV = "IDA_MCP_SYNC_LOG"
_sync_request_ids = itertools.count(1)
_sync_diag_lock = threading.Lock()

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
        return float(value)
    except ValueError:
        return _DEFAULT_TOOL_TIMEOUT_SEC


def _get_sync_queue_timeout_seconds() -> float:
    value = os.getenv(_SYNC_QUEUE_TIMEOUT_ENV, "").strip()
    if value == "":
        return _DEFAULT_SYNC_QUEUE_TIMEOUT_SEC
    try:
        timeout = float(value)
    except ValueError:
        return _DEFAULT_SYNC_QUEUE_TIMEOUT_SEC
    return timeout if timeout > 0 else _DEFAULT_SYNC_QUEUE_TIMEOUT_SEC


def _get_sync_log_path() -> str:
    override = os.getenv(_SYNC_LOG_ENV, "").strip()
    if override:
        return os.path.abspath(os.path.expandvars(os.path.expanduser(override)))
    return os.path.join(
        tempfile.gettempdir(), f"ida-pro-mcp-sync-{os.getpid()}.log"
    )


_SYNC_LOG_PATH = _get_sync_log_path()


def get_sync_log_path() -> str:
    """Return the request-level synchronization diagnostic log path."""
    return _SYNC_LOG_PATH


def _sync_diag(request_id: int, stage: str, **fields) -> None:
    """Append one structured synchronization event without risking the request."""
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())
    details = " ".join(f"{key}={value!r}" for key, value in fields.items())
    line = (
        f"{timestamp} pid={os.getpid()} tid={threading.get_ident()} "
        f"request={request_id} stage={stage} {details}".rstrip()
    )
    try:
        with _sync_diag_lock:
            with open(_SYNC_LOG_PATH, "a", encoding="utf-8") as log_file:
                log_file.write(line + "\n")
    except OSError:
        logger.exception("Unable to write IDA MCP sync diagnostics")
    logger.info("IDA MCP sync: %s", line)


def _defer_until_next_ui_turn(callback) -> None:
    """Run callback after the current native UI request has fully returned."""
    using_pyside6 = (ida_major > 9) or (ida_major == 9 and ida_minor >= 2)
    if using_pyside6:
        from PySide6.QtCore import QTimer
    else:
        from PyQt5.QtCore import QTimer

    QTimer.singleShot(0, callback)


call_stack = queue.LifoQueue()
_sync_diag(
    0,
    "module_loaded",
    queue_timeout=_get_sync_queue_timeout_seconds(),
    log_path=_SYNC_LOG_PATH,
)


def _sync_wrapper(ff):
    """Run ff synchronously through IDA's asynchronous UI request queue."""
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
                outcome="error" if isinstance(result, BaseException) else "ok",
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
        if not call_stack.empty():
            try:
                last_func_name = call_stack.get_nowait()
            except queue.Empty:
                last_func_name = "<empty>"
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

        call_stack.put(ff.__name__)
        old_batch = None
        result = None
        try:
            old_batch = idc.batch(1)
            result = ff()
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
            try:
                call_stack.get_nowait()
            except queue.Empty:
                pass
            if cleanup_error is not None and not isinstance(result, BaseException):
                result = cleanup_error

        _sync_diag(
            request_id,
            "ui_finished",
            function=ff.__name__,
            elapsed=time.monotonic() - callback_started_at,
            outcome="error" if isinstance(result, BaseException) else "ok",
        )
        # A zero-delay Qt callback runs only after this native UI request has
        # returned, preventing immediately chained requests from losing wakeups.
        release_result_after_ui_turn(result)
        # execute_ui_requests repeats callbacks that return True.
        return False

    if on_main_thread:
        runned()
    else:
        try:
            accepted = ida_kernwin.execute_ui_requests([runned])
        except BaseException as exc:
            _sync_diag(
                request_id,
                "queue_submit_exception",
                function=ff.__name__,
                error=repr(exc),
                traceback=traceback.format_exc().replace("\n", "\\n"),
            )
            raise IDASyncError(
                f"IDA rejected UI request {request_id} for {ff.__name__}: {exc}; "
                f"diagnostics: {_SYNC_LOG_PATH}"
            ) from exc

        _sync_diag(
            request_id,
            "queued",
            function=ff.__name__,
            accepted=accepted,
        )
        if accepted is False:
            raise IDASyncError(
                f"IDA rejected UI request {request_id} for {ff.__name__}; "
                f"diagnostics: {_SYNC_LOG_PATH}"
            )

        if not started_event.wait(queue_timeout):
            with state_lock:
                timed_out_before_start = not state["started"]
                if timed_out_before_start:
                    state["abandoned"] = True
            if timed_out_before_start:
                _sync_diag(
                    request_id,
                    "queue_start_timeout",
                    function=ff.__name__,
                    waited=queue_timeout,
                )
                raise IDASyncError(
                    f"IDA UI queue did not start request {request_id} "
                    f"({ff.__name__}) within {queue_timeout:.2f}s; "
                    f"diagnostics: {_SYNC_LOG_PATH}"
                )

    res = res_container.get()
    _sync_diag(
        request_id,
        "worker_received",
        function=ff.__name__,
        total_elapsed=time.monotonic() - queued_at,
        outcome="error" if isinstance(res, BaseException) else "ok",
    )
    if isinstance(res, BaseException):
        raise res
    return res


def _normalize_timeout(value: object) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


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
        return sync_wrapper(ff, timeout_override)

    return wrapper


def tool_timeout(seconds: float):
    """Decorator to override per-tool timeout (seconds).

    IMPORTANT: Must be applied BEFORE @idasync (i.e., listed AFTER it)
    so the attribute exists when it captures the function in closure.

    Correct order:
        @tool
        @idasync
        @tool_timeout(90.0)  # innermost
        def my_func(...):
    """

    def decorator(func):
        setattr(func, "__ida_mcp_timeout_sec__", seconds)
        return func

    return decorator


def is_window_active():
    """Returns whether IDA is currently active."""
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
