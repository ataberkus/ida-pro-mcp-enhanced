import logging
import queue
import functools
import os
import sys
import threading
import time
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

# Only one worker may submit work to IDA's main thread at a time. This avoids
# piling up execute_sync waiters when IDA temporarily stops dispatching MFF_WRITE
# requests (for example while a modal operation is active).
_dispatch_lock = threading.Lock()

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


call_stack = queue.LifoQueue()


def _sync_wrapper(ff):
    """Run ff on IDA's main thread without allowing queue stalls to hang RPC."""

    res_container = queue.Queue()
    started_event = threading.Event()
    abandoned_event = threading.Event()

    def runned():
        # Hex-Rays requires execute_sync callbacks to return an integer. In IDA
        # 9.4, returning None can leave the submitting worker parked in qsem_wait.
        started_event.set()
        if abandoned_event.is_set():
            return 0

        if not call_stack.empty():
            try:
                last_func_name = call_stack.get_nowait()
            except queue.Empty:
                last_func_name = "<empty>"
            # execute_sync() discards exceptions escaping this callback. Return
            # the error through the queue so the HTTP worker cannot wait forever.
            res_container.put(
                IDASyncError(
                    f"Call stack is not empty while calling the function "
                    f"{ff.__name__} from {last_func_name}"
                )
            )
            return 0

        call_stack.put(ff.__name__)
        old_batch = None
        result = None
        try:
            # Enable batch mode for all synchronized operations.
            old_batch = idc.batch(1)
            result = ff()
        except Exception as x:
            result = x
        finally:
            cleanup_error = None
            if old_batch is not None:
                try:
                    idc.batch(old_batch)
                except Exception as x:
                    cleanup_error = x
            # A synchronous re-entrant call may already have consumed our
            # marker. Never block the IDA main thread while cleaning it up.
            try:
                call_stack.get_nowait()
            except queue.Empty:
                pass
            if cleanup_error is not None and not isinstance(result, Exception):
                result = cleanup_error

        res_container.put(result)
        return 1

    if ida_pro.is_main_thread():
        # execute_sync is unnecessary on IDA's main thread and can deadlock on
        # a re-entrant tool call.
        runned()
    else:
        queue_timeout = _get_sync_queue_timeout_seconds()
        if not _dispatch_lock.acquire(timeout=queue_timeout):
            raise IDASyncError(
                "Another IDA main-thread request is still pending; "
                "wait for it to finish or restart IDA"
            )

        dispatch_done = threading.Event()

        def dispatch():
            try:
                return_code = idaapi.execute_sync(runned, idaapi.MFF_WRITE)
                if return_code == -1 and res_container.empty():
                    res_container.put(
                        IDASyncError("IDA rejected the main-thread execution request")
                    )
            except Exception as x:
                if res_container.empty():
                    res_container.put(x)
            finally:
                dispatch_done.set()
                _dispatch_lock.release()

        dispatch_thread = threading.Thread(
            target=dispatch,
            name=f"ida-mcp-sync-{ff.__name__}",
            daemon=True,
        )
        dispatch_thread.start()

        cancel_event = get_current_cancel_event()
        queue_deadline = time.monotonic() + queue_timeout
        while not started_event.is_set() and not dispatch_done.is_set():
            if cancel_event is not None and cancel_event.is_set():
                abandoned_event.set()
                raise CancelledError("Request was cancelled before IDA dispatched it")
            remaining = queue_deadline - time.monotonic()
            if remaining <= 0:
                abandoned_event.set()
                raise IDASyncError(
                    "IDA main-thread queue did not start the request within "
                    f"{queue_timeout:.2f}s; close any modal dialog or restart IDA"
                )
            started_event.wait(min(0.05, remaining))

        if dispatch_done.is_set() and not started_event.is_set() and res_container.empty():
            res_container.put(
                IDASyncError("IDA main-thread execution ended without running the request")
            )

    res = res_container.get()
    if isinstance(res, Exception):
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
