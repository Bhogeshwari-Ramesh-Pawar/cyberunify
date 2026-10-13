"""Syslog receivers: one UDP or TCP listener per syslog integration.

Received lines are buffered and handed to the pipeline in batches off the event loop,
so a burst of firewall logs never blocks the dashboard.
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from collections.abc import Callable
from typing import Any

log = logging.getLogger("cyberunify.syslog")
MAX_LINE = 64 * 1024
MAX_BUFFER = 50_000  # per integration; beyond this, drop rather than run out of memory


class _UDP(asyncio.DatagramProtocol):
    def __init__(self, sink: Callable[[str], None]):
        self.sink = sink

    def datagram_received(self, data: bytes, addr) -> None:
        for line in data[:MAX_LINE].decode("utf-8", errors="replace").splitlines():
            if line.strip():
                self.sink(line)


class SyslogManager:
    def __init__(self, deliver: Callable[[int, list[str]], None], bind_host: str = "0.0.0.0"):
        self.deliver = deliver  # called in a worker thread with (integration_id, lines)
        self.bind_host = bind_host
        self.listeners: dict[int, tuple[Any, int, str]] = {}  # id → (transport/server, port, protocol)
        self.buffers: dict[int, list[str]] = defaultdict(list)
        self.dropped: dict[int, int] = defaultdict(int)
        self._flusher: asyncio.Task | None = None

    def _sink(self, integration_id: int) -> Callable[[str], None]:
        def put(line: str) -> None:
            buf = self.buffers[integration_id]
            if len(buf) < MAX_BUFFER:
                buf.append(line)
            else:
                self.dropped[integration_id] += 1
        return put

    async def _tcp_handler(self, integration_id: int, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        sink = self._sink(integration_id)
        try:
            while not reader.at_eof():
                line = await reader.readline()
                if not line:
                    break
                text = line[:MAX_LINE].decode("utf-8", errors="replace").strip()
                if text:
                    sink(text)
        except (ConnectionError, asyncio.LimitOverrunError):
            pass
        finally:
            writer.close()

    async def start(self, integration: dict[str, Any]) -> str | None:
        """Start listening. Returns an error message, or None on success."""
        iid = integration["id"]
        cfg = integration["config"]
        port, protocol = int(cfg.get("port") or 5514), (cfg.get("protocol") or "udp").lower()
        current = self.listeners.get(iid)
        if current and current[1:] == (port, protocol):
            return None
        await self.stop(iid)
        loop = asyncio.get_running_loop()
        try:
            if protocol == "tcp":
                server = await asyncio.start_server(lambda r, w: self._tcp_handler(iid, r, w),
                                                    self.bind_host, port, limit=MAX_LINE)
                self.listeners[iid] = (server, port, protocol)
            else:
                transport, _ = await loop.create_datagram_endpoint(lambda: _UDP(self._sink(iid)),
                                                                   local_addr=(self.bind_host, port))
                self.listeners[iid] = (transport, port, protocol)
        except PermissionError:
            return f"Permission denied for {protocol.upper()} port {port} (ports below 1024 need admin rights; try 5514)."
        except OSError as err:
            return f"Cannot listen on {protocol.upper()} port {port}: {err.strerror or err} (is another program using it?)"
        log.info("syslog integration %s listening on %s/%s", iid, protocol, port)
        return None

    async def stop(self, integration_id: int) -> None:
        entry = self.listeners.pop(integration_id, None)
        if not entry:
            return
        handle = entry[0]
        handle.close()
        if isinstance(handle, asyncio.AbstractServer):
            await handle.wait_closed()

    async def sync(self, integrations: list[dict[str, Any]]) -> dict[int, str | None]:
        """Make the running listeners match the enabled syslog integrations."""
        wanted = {i["id"]: i for i in integrations if i["type"] == "syslog" and i["enabled"] and not i["demo"]}
        for iid in list(self.listeners):
            if iid not in wanted:
                await self.stop(iid)
        return {iid: await self.start(integ) for iid, integ in wanted.items()}

    def is_listening(self, integration_id: int) -> bool:
        return integration_id in self.listeners

    async def flush(self) -> None:
        for iid in list(self.buffers):
            lines = self.buffers.pop(iid, [])
            if lines:
                await asyncio.to_thread(self.deliver, iid, lines)

    async def run(self) -> None:
        while True:
            await asyncio.sleep(1)
            try:
                await self.flush()
            except Exception:
                log.exception("syslog flush failed")

    def start_flusher(self) -> None:
        self._flusher = asyncio.create_task(self.run())

    async def shutdown(self) -> None:
        if self._flusher:
            self._flusher.cancel()
        for iid in list(self.listeners):
            await self.stop(iid)
