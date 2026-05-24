"""Centralized task management system.

Architecture:
- TaskManager (QObject singleton) manages all async work
- TaskRunnable (QRunnable) for pool-based short tasks
- DedicatedTask for long-running I/O-bound polling loops
- PeriodicTaskManager for timer-driven periodic pool tasks

All background work goes through TaskManager to ensure:
- No unbounded thread creation
- Proper cleanup on shutdown
- Cancel, timeout, retry support
- Serialized route refresh
- Signal/Slot for cross-thread communication
"""

import logging
import threading
import time
import uuid
from typing import Any, Callable, Optional

from PyQt5.QtCore import QObject, QThreadPool, QTimer, pyqtSignal, QRunnable

logger = logging.getLogger(__name__)


class TaskSignals(QObject):
    """Signals emitted by task results.
    
    QRunnable cannot inherit QObject, so signals live here.
    Connected in the submitting thread (main/GUI thread) for safe UI updates.
    """
    finished = pyqtSignal(object)
    error = pyqtSignal(str)
    progress = pyqtSignal(object)


class TaskRunnable(QRunnable):
    """A cancellable QRunnable with timeout and retry support.

    Usage:
        def my_work(a, b):
            return a + b

        task = TaskRunnable(my_work, args=(1, 2), task_id="calc")
        task.signals.finished.connect(self._on_result)
        QThreadPool.globalInstance().start(task)
    """

    def __init__(
        self,
        fn: Callable,
        args: tuple = (),
        kwargs: dict = None,
        task_id: str = "",
        timeout: float = 0,
        retry: int = 0,
        retry_delay: float = 1.0,
    ):
        super().__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs or {}
        self.task_id = task_id or str(uuid.uuid4())
        self.timeout = timeout
        self.retry = retry
        self.retry_delay = retry_delay
        self.signals = TaskSignals()
        self._cancelled = threading.Event()
        self._running = threading.Event()
        self._start_time: float = 0.0
        self._result: Any = None
        self._error: Optional[str] = None

    @property
    def is_cancelled(self) -> bool:
        return self._cancelled.is_set()

    @property
    def is_running(self) -> bool:
        return self._running.is_set()

    @property
    def result(self) -> Any:
        return self._result

    @property
    def error(self) -> Optional[str]:
        return self._error

    def cancel(self):
        self._cancelled.set()

    def wait(self, timeout: float = None) -> bool:
        """Wait for this task to complete. Returns True if completed."""
        return self._running.wait(timeout)

    def run(self):
        """Execute the task function with retry support."""
        self._running.set()
        self._start_time = time.monotonic()

        if self._cancelled.is_set():
            self._running.clear()
            return

        last_exception: Optional[Exception] = None
        attempts = 1 + self.retry

        for attempt in range(attempts):
            if self._cancelled.is_set():
                break

            if self.timeout > 0 and (time.monotonic() - self._start_time) > self.timeout:
                self._error = f"Task timed out after {self.timeout}s"
                if not self._cancelled.is_set():
                    self.signals.error.emit(self._error)
                self._running.clear()
                return

            try:
                self._result = self.fn(*self.args, **self.kwargs)
                self._error = None
                if not self._cancelled.is_set():
                    self.signals.finished.emit(self._result)
                self._running.clear()
                return
            except Exception as e:
                last_exception = e
                if attempt < attempts - 1 and not self._cancelled.is_set():
                    logger.debug("Task %s attempt %d failed, retrying in %.1fs: %s",
                                 self.task_id, attempt + 1, self.retry_delay, e)
                    time.sleep(self.retry_delay)

        self._error = str(last_exception) if last_exception else "Unknown error"
        if not self._cancelled.is_set():
            self.signals.error.emit(self._error)
        self._running.clear()


class PeriodicTaskMgr(QObject):
    """Manages a timer-driven periodic task submitted to the thread pool.

    Instead of a dedicated polling thread, a QTimer periodically submits
    a TaskRunnable to QThreadPool. This avoids occupying a thread
    during the sleep interval.
    """

    def __init__(self, interval_ms: int, fn: Callable, task_id: str = "",
                 parent: QObject = None):
        super().__init__(parent)
        self._fn = fn
        self._task_id = task_id or str(uuid.uuid4())
        self._interval_ms = interval_ms
        self._timer = QTimer(self)
        self._timer.setSingleShot(False)
        self._timer.setInterval(interval_ms)
        self._timer.timeout.connect(self._tick)
        self._running = False
        self._current_task: Optional[TaskRunnable] = None
        self._lock = threading.Lock()

    @property
    def is_running(self) -> bool:
        return self._running

    def start(self):
        if self._running:
            return
        self._running = True
        self._timer.start()
        logger.debug("PeriodicTaskMgr '%s' started (interval=%dms)",
                     self._task_id, self._interval_ms)

    def stop(self):
        self._running = False
        self._timer.stop()
        self._cancel_current()
        logger.debug("PeriodicTaskMgr '%s' stopped", self._task_id)

    def _cancel_current(self):
        with self._lock:
            if self._current_task:
                self._current_task.cancel()
                self._current_task = None

    def _tick(self):
        if not self._running:
            return
        with self._lock:
            if self._current_task and self._current_task.is_running:
                return
            self._current_task = TaskRunnable(self._fn, task_id=self._task_id + "_tick")
            QThreadPool.globalInstance().start(self._current_task)


class DedicatedTask:
    """Wraps a long-running I/O-bound polling loop in its own thread.

    Used for:
    - ETW tracer (blocks on EvtQuery)
    - TUN reader (blocks on TUN read)
    - WinDivert reply reader (blocks on WinDivertRecv)

    These cannot go in QThreadPool because they block indefinitely on I/O.
    """

    def __init__(self, poll_fn: Callable, task_id: str = "",
                 interval: float = 0):
        self.poll_fn = poll_fn
        self.task_id = task_id or str(uuid.uuid4())
        self.interval = interval
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> bool:
        if self.is_running:
            return True
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._loop,
            daemon=True,
            name=f"d-{self.task_id}",
        )
        self._thread.start()
        logger.debug("DedicatedTask '%s' started", self.task_id)
        return True

    def stop(self, timeout: float = 3.0):
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
            self._thread = None
        logger.debug("DedicatedTask '%s' stopped", self.task_id)

    def _loop(self):
        while not self._stop_event.is_set():
            try:
                self.poll_fn()
            except Exception as e:
                logger.exception("DedicatedTask '%s' error: %s", self.task_id, e)
            if self.interval > 0 and not self._stop_event.is_set():
                self._stop_event.wait(self.interval)

    @property
    def stop_event(self) -> threading.Event:
        return self._stop_event


class TaskManager(QObject):
    """Central singleton that manages all async work in the application.

    Provides:
    - submit() — run a short task via QThreadPool
    - submit_serial() — run a task serially on a named queue (e.g. route refresh)
    - schedule_periodic() — run a function on an interval via QTimer + pool
    - start_dedicated() — run a long-running I/O loop in its own thread
    - cancel(), cancel_all() — task lifecycle
    - shutdown() — graceful application shutdown

    All task results communicate via pyqtSignal for thread-safe GUI updates.
    """

    _instance: Optional['TaskManager'] = None
    _instance_lock = threading.Lock()

    def __init__(self, parent: QObject = None, max_threads: int = 8):
        super().__init__(parent)
        self._pool = QThreadPool.globalInstance()
        self._pool.setMaxThreadCount(max_threads)
        self._tasks: dict[str, TaskRunnable] = {}
        self._dedicated: dict[str, DedicatedTask] = {}
        self._periodic: dict[str, PeriodicTaskMgr] = {}
        self._task_lock = threading.Lock()

        # Serial queues: queue_name -> lock (only one task runs at a time)
        self._serial_locks: dict[str, threading.Lock] = {}
        self._serial_pending: dict[str, bool] = {}
        self._serial_latest_fn: dict[str, tuple] = {}

        self._shutting_down = False

    # ------------------------------------------------------------------
    # Singleton
    # ------------------------------------------------------------------

    @classmethod
    def instance(cls, parent: QObject = None) -> 'TaskManager':
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = cls(parent=parent)
                    logger.info("TaskManager created (max_threads=%d)",
                                cls._instance._pool.maxThreadCount())
        return cls._instance

    # ------------------------------------------------------------------
    # Pool: short tasks
    # ------------------------------------------------------------------

    def submit(
        self,
        fn: Callable,
        args: tuple = (),
        kwargs: dict = None,
        task_id: str = "",
        timeout: float = 0,
        retry: int = 0,
        retry_delay: float = 1.0,
    ) -> TaskRunnable:
        if self._shutting_down:
            raise RuntimeError("TaskManager is shutting down")

        runnable = TaskRunnable(
            fn=fn, args=args, kwargs=kwargs,
            task_id=task_id, timeout=timeout,
            retry=retry, retry_delay=retry_delay,
        )

        with self._task_lock:
            if task_id and task_id in self._tasks:
                old = self._tasks[task_id]
                old.cancel()
            self._tasks[runnable.task_id] = runnable

        self._pool.start(runnable)
        return runnable

    def submit_serial(
        self,
        queue_name: str,
        fn: Callable,
        args: tuple = (),
        kwargs: dict = None,
        timeout: float = 0,
        on_finished: Callable = None,
        on_error: Callable = None,
    ) -> bool:
        """Submit a task to a serial queue. Only one task per queue runs at a time.
        
        If a task is already running on this queue, the new one is marked pending
        and submitted automatically when the current task finishes
        (latest-one-wins for refresh-style tasks).
        
        Returns True if the task was submitted or queued.
        """
        if self._shutting_down:
            return False

        if queue_name not in self._serial_locks:
            self._serial_locks[queue_name] = threading.Lock()
            self._serial_pending[queue_name] = False

        lock = self._serial_locks[queue_name]
        task_id = f"serial_{queue_name}"

        def _release_and_check(_result=None):
            """Release lock and submit pending task if any."""
            pending_exists = self._serial_pending.get(queue_name, False)
            if pending_exists:
                self._serial_pending[queue_name] = False
                lock.release()
                # Re-acquire and run latest
                if lock.acquire(blocking=False):
                    latest = self._serial_latest_fn.get(queue_name)
                    if latest:
                        fn2, args2, kwargs2 = latest
                        self._serial_latest_fn[queue_name] = None
                        r = self.submit(fn=fn2, args=args2, kwargs=kwargs2,
                                        task_id=task_id, timeout=timeout)
                        if on_finished:
                            r.signals.finished.connect(on_finished)
                        if on_error:
                            r.signals.error.connect(on_error)
                        r.signals.finished.connect(lambda x: lock.release())
                        r.signals.error.connect(lambda x: lock.release())
            else:
                lock.release()

        def _make_task():
            runnable = self.submit(fn=fn, args=args, kwargs=kwargs,
                                   task_id=task_id, timeout=timeout)
            if on_finished:
                runnable.signals.finished.connect(on_finished)
            if on_error:
                runnable.signals.error.connect(on_error)
            runnable.signals.finished.connect(_release_and_check)
            runnable.signals.error.connect(_release_and_check)
            return True

        if lock.acquire(blocking=False):
            self._serial_pending[queue_name] = False
            self._serial_latest_fn[queue_name] = None
            return _make_task()
        else:
            self._serial_pending[queue_name] = True
            self._serial_latest_fn[queue_name] = (fn, args, kwargs or {})
            logger.debug("Serial queue '%s' busy, marking pending", queue_name)
            return True

    # ------------------------------------------------------------------
    # Periodic tasks (QTimer + pool)
    # ------------------------------------------------------------------

    def schedule_periodic(
        self,
        interval_ms: int,
        fn: Callable,
        task_id: str = "",
    ) -> PeriodicTaskMgr:
        mgr = PeriodicTaskMgr(interval_ms=interval_ms, fn=fn,
                               task_id=task_id, parent=self)
        self._periodic[mgr._task_id] = mgr
        mgr.start()
        return mgr

    # ------------------------------------------------------------------
    # Dedicated long-running I/O threads
    # ------------------------------------------------------------------

    def start_dedicated(
        self,
        poll_fn: Callable,
        task_id: str = "",
        interval: float = 0,
    ) -> DedicatedTask:
        task = DedicatedTask(poll_fn=poll_fn, task_id=task_id, interval=interval)
        self._dedicated[task.task_id] = task
        task.start()
        return task

    # ------------------------------------------------------------------
    # Cancel / status
    # ------------------------------------------------------------------

    def cancel(self, task_id: str):
        with self._task_lock:
            task = self._tasks.pop(task_id, None)
            if task:
                task.cancel()

    def cancel_all(self):
        with self._task_lock:
            for task in self._tasks.values():
                task.cancel()
            self._tasks.clear()

    def task_count(self) -> int:
        return self._pool.activeThreadCount()

    # ------------------------------------------------------------------
    # Graceful shutdown
    # ------------------------------------------------------------------

    def shutdown(self, timeout: int = 5):
        logger.info("TaskManager shutting down...")
        self._shutting_down = True

        # Stop all periodic timers
        for mgr in list(self._periodic.values()):
            mgr.stop()
        self._periodic.clear()

        # Stop all dedicated threads
        for task in list(self._dedicated.values()):
            task.stop(timeout=2.0)
        self._dedicated.clear()

        # Cancel all pending pool tasks
        self.cancel_all()

        # Wait for pool to drain
        if not self._pool.waitForDone(timeout * 1000):
            logger.warning("Thread pool did not finish within %ds", timeout)

        logger.info("TaskManager shutdown complete")


def get_task_manager(parent: QObject = None) -> TaskManager:
    """Get the global TaskManager singleton."""
    return TaskManager.instance(parent=parent)
