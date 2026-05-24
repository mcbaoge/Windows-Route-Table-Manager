"""ETW-based network event tracer using wevtapi EvtQuery.

Polls Microsoft-Windows-DNS-Client/Operational for DNS events.
Falls back to raw ETW session if EvtQuery not available.

Pushes typed DnsEvent objects to EventBus for GUI display.

Thread model: DedicatedTask via TaskManager (long-running I/O poller).
"""

import ctypes
import ctypes.wintypes
from ctypes import POINTER, byref, create_string_buffer
import logging
import re
import threading
import time
from xml.parsers.expat import ParserCreate

from services.event_types import DnsEvent
from services.event_bus import get_event_bus
from services.task_manager import get_task_manager

logger = logging.getLogger(__name__)

CHANNEL_DNS_CLIENT = "Microsoft-Windows-DNS-Client/Operational"

_wevtapi = ctypes.WinDLL("wevtapi", use_last_error=True)
_k32 = ctypes.WinDLL("kernel32", use_last_error=True)

_EvtQuery = _wevtapi.EvtQuery
_EvtQuery.argtypes = [
    ctypes.c_void_p,
    ctypes.c_wchar_p,
    ctypes.c_wchar_p,
    ctypes.wintypes.ULONG,
]
_EvtQuery.restype = ctypes.c_void_p

_EvtNext = _wevtapi.EvtNext
_EvtNext.argtypes = [
    ctypes.c_void_p,
    ctypes.wintypes.ULONG,
    POINTER(ctypes.c_void_p),
    ctypes.wintypes.ULONG,
    ctypes.wintypes.ULONG,
    POINTER(ctypes.wintypes.ULONG),
]
_EvtNext.restype = ctypes.wintypes.BOOL

_EvtRender = _wevtapi.EvtRender
_EvtRender.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.wintypes.ULONG,
    ctypes.wintypes.ULONG,
    ctypes.c_void_p,
    POINTER(ctypes.wintypes.ULONG),
    POINTER(ctypes.wintypes.ULONG),
]
_EvtRender.restype = ctypes.wintypes.BOOL

_EvtClose = _wevtapi.EvtClose
_EvtClose.argtypes = [ctypes.c_void_p]
_EvtClose.restype = ctypes.wintypes.BOOL

_SleepEx = _k32.SleepEx
_SleepEx.argtypes = [ctypes.wintypes.ULONG, ctypes.wintypes.BOOL]
_SleepEx.restype = ctypes.wintypes.ULONG

EvtQueryChannelPath = 0x1
EvtQueryReverseDirection = 0x100
EvtRenderEventXml = 1

MAX_EVENT_BATCH = 32
POLL_INTERVAL_SEC = 0.5

_QTYPE_MAP = {"1": "A", "28": "AAAA", "5": "CNAME", "15": "MX", "2": "NS",
              "6": "SOA", "33": "SRV", "16": "TXT", "12": "PTR", "255": "ANY"}


def _parse_query_results(text: str) -> list[str]:
    parts = text.split(";")
    answers = []
    for p in parts:
        p = p.strip()
        if not p:
            continue
        if p.startswith("type:") or p.startswith("type  "):
            continue
        if not p.startswith("::") and not p.startswith("0:"):
            if p not in answers:
                answers.append(p)
    return answers


def _parse_dns_event(xml: str, pid: int) -> DnsEvent | None:
    result = {
        "query": "",
        "query_type": "A",
        "answers": [],
        "status": "success",
        "server_ip": "",
        "rtt_ms": 0.0,
    }

    try:
        parser = ParserCreate()
        data_name: str | None = None
        data_text: list[str] = []

        def start_elem(name, attrs):
            nonlocal data_name, data_text
            if name == "Data" and "Name" in attrs:
                data_name = attrs["Name"]
                data_text = []

        def end_elem(name):
            nonlocal data_name, data_text
            if name != "Data" or data_name is None:
                return
            text = "".join(data_text).strip()
            dn = data_name
            data_name = None
            data_text = []
            if not text:
                return
            if dn == "QueryName":
                result["query"] = text
            elif dn == "QueryType":
                result["query_type"] = _QTYPE_MAP.get(text, text)
            elif dn in ("Status", "QueryStatus", "ResponseStatus"):
                if text != "0":
                    result["status"] = "error"
            elif dn in ("DnsServerIpAddress", "DNSServerAddress"):
                result["server_ip"] = text.split(";")[0].strip()
            elif dn in ("QueryResults",):
                parsed = _parse_query_results(text)
                for a in parsed:
                    if a not in result["answers"]:
                        result["answers"].append(a)
            elif dn == "RTT" and text:
                try:
                    result["rtt_ms"] = float(text) / 1000.0
                except ValueError:
                    pass

        def char_data(data):
            nonlocal data_text
            if data_name is not None:
                data_text.append(data)

        parser.StartElementHandler = start_elem
        parser.EndElementHandler = end_elem
        parser.CharacterDataHandler = char_data
        parser.Parse(xml, True)

    except Exception as e:
        logger.debug("DNS XML parse error: %s", e)

    if not result["query"]:
        return None

    return DnsEvent(
        timestamp=time.time(),
        query=result["query"],
        query_type=result["query_type"],
        answers=result["answers"],
        rtt_ms=result["rtt_ms"],
        pid=pid,
        process_name=_pid_to_name(pid),
        status=result["status"],
        server_ip=result["server_ip"],
    )


def _extract_event_data(xml: str) -> tuple[int, int]:
    pid = 0
    eid = 0
    try:
        pid_m = re.search(r'ProcessID="(\d+)"', xml)
        eid_m = re.search(r'<EventID>(\d+)</EventID>', xml)
        if pid_m:
            pid = int(pid_m.group(1))
        if eid_m:
            eid = int(eid_m.group(1))
    except Exception:
        pass
    return pid, eid


_pid_cache: dict[int, tuple[str, float]] = {}
_pid_cache_lock = threading.Lock()
_PID_CACHE_TTL = 5.0


def _pid_to_name(pid: int) -> str:
    if pid <= 0:
        return "System"
    now = time.time()
    with _pid_cache_lock:
        if pid in _pid_cache:
            name, cached_at = _pid_cache[pid]
            if now - cached_at < _PID_CACHE_TTL:
                return name
    try:
        import psutil
        proc = psutil.Process(pid)
        name = proc.name()
    except Exception:
        name = f"pid:{pid}"
    with _pid_cache_lock:
        _pid_cache[pid] = (name, now)
    return name


class ETWTracer:
    """Polls Microsoft-Windows-DNS-Client/Operational for DNS events.

    Uses structured XPath queries with EventRecordID tracking to only
    fetch new events on each poll. Runs as a DedicatedTask via TaskManager.
    """

    def __init__(self):
        self._dedicated_task = None
        self._running = False
        self._stop_event = threading.Event()
        self._max_record_id: int = 0
        self._initialized = False

    def start(self) -> bool:
        if self._running:
            return True

        if not self._check_channel():
            logger.warning("DNS Client channel not accessible")
            return False

        self._running = True
        self._stop_event.clear()

        tm = get_task_manager()
        self._dedicated_task = tm.start_dedicated(
            poll_fn=self._poll_once,
            task_id="etw-dns",
            interval=POLL_INTERVAL_SEC,
        )
        logger.info("ETW DNS poller started (DedicatedTask)")
        return True

    def stop(self):
        self._running = False
        self._stop_event.set()
        if self._dedicated_task:
            self._dedicated_task.stop(timeout=3.0)
            self._dedicated_task = None
        logger.info("ETW DNS poller stopped")

    def _check_channel(self) -> bool:
        try:
            channel = ctypes.create_unicode_buffer(CHANNEL_DNS_CLIENT)
            query = ctypes.c_wchar_p("*")
            h = _EvtQuery(
                None, channel, query,
                EvtQueryChannelPath | EvtQueryReverseDirection,
            )
            if h:
                _EvtClose(h)
                return True
            return False
        except Exception as e:
            logger.debug("DNS channel check failed: %s", e)
            return False

    def _poll_once(self):
        """Called by DedicatedTask on each poll interval."""
        if not self._running or self._stop_event.is_set():
            return
        try:
            if not self._initialized:
                self._find_max_record_id()
            else:
                self._poll_new_events()
        except Exception as e:
            logger.debug("DNS poll error: %s", e)

    def _find_max_record_id(self):
        channel = ctypes.create_unicode_buffer(CHANNEL_DNS_CLIENT)
        query = ctypes.c_wchar_p("*")

        h_query = _EvtQuery(
            None, channel, query,
            EvtQueryChannelPath | EvtQueryReverseDirection,
        )
        if not h_query:
            return

        try:
            handles = (ctypes.c_void_p * 1)()
            returned = ctypes.wintypes.ULONG(0)

            ok = _EvtNext(h_query, 1, handles, 1000, 0, byref(returned))
            if ok and returned.value > 0:
                self._update_max_record_id(handles[0])
                _EvtClose(handles[0])
                self._initialized = True
                logger.info("ETW initialized, max EventRecordID = %d", self._max_record_id)
        finally:
            _EvtClose(h_query)

    def _poll_new_events(self):
        xpath = "*[System[EventRecordID > {}]]".format(self._max_record_id)
        query = ctypes.c_wchar_p(xpath)
        channel = ctypes.create_unicode_buffer(CHANNEL_DNS_CLIENT)

        h_query = _EvtQuery(
            None, channel, query,
            EvtQueryChannelPath,
        )
        if not h_query:
            return

        try:
            while True:
                handles = (ctypes.c_void_p * MAX_EVENT_BATCH)()
                returned = ctypes.wintypes.ULONG(0)

                ok = _EvtNext(h_query, MAX_EVENT_BATCH, handles, 500, 0, byref(returned))
                if not ok or returned.value == 0:
                    break

                for i in range(returned.value):
                    self._process_event(handles[i])
                    _EvtClose(handles[i])
        finally:
            _EvtClose(h_query)

    def _update_max_record_id(self, evt_handle):
        buf = create_string_buffer(512)
        used = ctypes.wintypes.ULONG(0)
        props = ctypes.wintypes.ULONG(0)

        ok = _EvtRender(None, evt_handle, EvtRenderEventXml,
                         512, buf, byref(used), byref(props))
        if not ok or used.value == 0:
            return

        xml = buf.raw[:used.value].decode("utf-16-le", errors="replace").strip("\x00").strip()
        m = re.search(r'<EventRecordID>(\d+)</EventRecordID>', xml)
        if m:
            rid = int(m.group(1))
            if rid > self._max_record_id:
                self._max_record_id = rid

    def _process_event(self, evt_handle):
        buf_size = ctypes.wintypes.ULONG(8192)
        buf = create_string_buffer(buf_size.value)
        used = ctypes.wintypes.ULONG(0)
        props = ctypes.wintypes.ULONG(0)

        ok = _EvtRender(None, evt_handle, EvtRenderEventXml,
                         buf_size, buf, byref(used), byref(props))
        if not ok and used.value > buf_size.value:
            buf_size.value = used.value
            buf = create_string_buffer(buf_size.value)
            ok = _EvtRender(None, evt_handle, EvtRenderEventXml,
                             buf_size, buf, byref(used), byref(props))

        if not ok or used.value == 0:
            return

        xml = buf.raw[:used.value].decode("utf-16-le", errors="replace").strip("\x00").strip()

        m = re.search(r'<EventRecordID>(\d+)</EventRecordID>', xml)
        if m:
            rid = int(m.group(1))
            if rid > self._max_record_id:
                self._max_record_id = rid

        pid, eid = _extract_event_data(xml)

        if eid in (3008, 3011, 3018, 3020):
            evt = _parse_dns_event(xml, pid)
            if evt is not None:
                get_event_bus().publish(evt)
