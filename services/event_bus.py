import threading
import logging
from collections.abc import Callable
from typing import Any

from PyQt5.QtCore import QObject, QTimer, pyqtSignal

logger = logging.getLogger(__name__)


class RingBuffer:
    """Fixed-size thread-safe ring buffer with auto-overwrite."""

    def __init__(self, max_size: int = 1000):
        self._max = max_size
        self._buf: list[Any] = [None] * max_size
        self._pos = 0
        self._count = 0
        self._lock = threading.Lock()

    def append(self, item: Any):
        with self._lock:
            self._buf[self._pos] = item
            self._pos = (self._pos + 1) % self._max
            if self._count < self._max:
                self._count += 1

    def get_all(self) -> list:
        with self._lock:
            if self._count < self._max:
                return [x for x in self._buf[:self._count] if x is not None]
            return [self._buf[(self._pos + i) % self._max] for i in range(self._count)]

    def get_slice(self, start: int, end: int) -> list:
        with self._lock:
            if start < 0 or end > self._count or start >= end:
                return []
            if self._count < self._max:
                return [x for x in self._buf[start:end] if x is not None]
            items = [self._buf[(self._pos + i) % self._max] for i in range(self._count)]
            return items[start:end]

    def clear(self):
        with self._lock:
            self._buf = [None] * self._max
            self._pos = 0
            self._count = 0

    def __len__(self):
        with self._lock:
            return self._count

    @property
    def max_size(self) -> int:
        return self._max


class EventBus(QObject):
    """Unified event bus with ring buffer, batch dispatch via Qt signal.

    All ETW events -> EventBus -> ring buffer -> batch Qt signal -> GUI
    """

    batch_ready = pyqtSignal(list)

    def __init__(self, max_size: int = 2000, batch_interval_ms: int = 300, parent=None):
        super().__init__(parent)
        self._buffer = RingBuffer(max_size)
        self._pending: list = []
        self._batch_interval = batch_interval_ms
        self._timer = QTimer(self)
        self._timer.setSingleShot(False)
        self._timer.setInterval(batch_interval_ms)
        self._timer.timeout.connect(self._flush)
        self._lock = threading.Lock()
        self._listeners: list[Callable] = []
        self._running = False

    def add_listener(self, cb: Callable):
        self._listeners.append(cb)

    def remove_listener(self, cb: Callable):
        if cb in self._listeners:
            self._listeners.remove(cb)

    def publish(self, event):
        self._buffer.append(event)
        with self._lock:
            self._pending.append(event)
        for cb in self._listeners:
            try:
                cb(event)
            except Exception as e:
                logger.warning("EventBus listener error: %s", e)

    def _flush(self):
        batch = []
        with self._lock:
            if self._pending:
                batch = list(self._pending)
                self._pending.clear()
        if batch:
            try:
                self.batch_ready.emit(batch)
            except Exception as e:
                logger.warning("EventBus batch_ready emit error: %s", e)

    def get_all(self) -> list:
        return self._buffer.get_all()

    def clear(self):
        self._buffer.clear()
        with self._lock:
            self._pending.clear()

    def start(self):
        self._running = True
        self._timer.start()

    def stop(self):
        self._running = False
        self._timer.stop()
        self._flush()

    @property
    def size(self) -> int:
        return len(self._buffer)

    @property
    def max_size(self) -> int:
        return self._buffer.max_size


_event_bus_instance: EventBus | None = None
_event_bus_lock = threading.Lock()


def get_event_bus() -> EventBus:
    global _event_bus_instance
    if _event_bus_instance is None:
        with _event_bus_lock:
            if _event_bus_instance is None:
                _event_bus_instance = EventBus()
    return _event_bus_instance
