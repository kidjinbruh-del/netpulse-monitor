# services/speedtest/service.py — замер скорости до удалённого узла
# download: инициатор (B) просит цель (A) запустить start_download → A пушит в download_in@B
# upload: инициатор (B) пушит в upload_in@A
# ping: простой RPC RTT

import asyncio
import time
import uuid

from netpulse.p2p_core.internal_modules.base import ModuleGeneric
from netpulse.p2p_core.internal_modules.memory import Pipe
from netpulse.p2p_core.networking.protocol import MsgPack
from netpulse.p2p_core.services.rpc import rpc, generator, stream_wrapper, stream_consumer


DEFAULT_DURATION = 30.0
DEFAULT_CHUNK = 256 * 1024
DEFAULT_MAX_CHUNKS = 100_000_000
DEFAULT_PARALLEL = 1


class Speedtest(ModuleGeneric):
    def __init__(self, name, context):
        super().__init__(name, context)
        self._uploads = {}   # test_id -> {bytes, chunks, start, end}
        self._downloads = {} # test_id -> {bytes, chunks, start, end, event}
        self._download_events = {}  # test_id -> asyncio.Event

    async def start(self):
        self.log.info("Speedtest service started")

    async def stop(self):
        self.log.info("Speedtest service stopped")

    # ------------------------------------------------------------------ #
    #  ping
    # ------------------------------------------------------------------ #
    @rpc
    async def ping(self, data: dict) -> dict:
        return {"ok": True, "pong_ts": time.time(), "echo": data}

    # ------------------------------------------------------------------ #
    #  Генератор для совместимости (не используется напрямую для stream, но оставляем)
    # ------------------------------------------------------------------ #
    @generator
    def generate(self, data: dict):
        chunk_size = int(data.get("chunk_size", DEFAULT_CHUNK))
        chunk_size = max(1024, min(chunk_size, 4 * 1024 * 1024))
        duration = float(data.get("duration", DEFAULT_DURATION))
        max_chunks = int(data.get("max_chunks", DEFAULT_MAX_CHUNKS))
        chunk = b"\x00" * chunk_size
        start = time.time()
        count = 0
        while count < max_chunks and (time.time() - start) < duration:
            yield chunk
            count += 1

    # ------------------------------------------------------------------ #
    #  Download: цель пушит в инициатора (download_in)
    # ------------------------------------------------------------------ #
    @rpc
    async def start_download(self, data: dict) -> dict:
        """Цель (A) запускает поток к инициатору (B) в download_in."""
        dst = data.get("dst") or data.get("initiator")
        if not dst:
            return {"ok": False, "error": "dst (initiator) обязателен"}
        test_id = data.get("test_id") or str(uuid.uuid4())
        chunk_size = int(data.get("chunk_size", DEFAULT_CHUNK))
        chunk_size = max(1024, min(chunk_size, 4 * 1024 * 1024))
        duration = float(data.get("duration", DEFAULT_DURATION))
        max_chunks = int(data.get("max_chunks", DEFAULT_MAX_CHUNKS))
        # защита
        duration = max(1, min(duration, 120))
        max_chunks = max(1, min(max_chunks, 200_000_000))

        chunk = b"\x00" * chunk_size
        pipe = self.ctx.memory.create_pipe(buff=8)
        dispatcher = self.ctx.memory.create_dispatcher([pipe])

        def gen():
            cnt = 0
            t0 = time.time()
            while cnt < max_chunks and (time.time() - t0) < duration:
                yield chunk
                cnt += 1

        template = MsgPack(
            source=self.ctx.NODE,
            dst=dst,
            service="speedtest",
            method="download_in",
            label=test_id,
            data={"test_id": test_id},
        )
        self.ctx.memory.attach_transport(pipe, template, self.ctx.network.router)
        dispatcher.start(gen)
        self.log.info(f"start_download {test_id[:8]} -> {dst} {chunk_size}B x {duration}s")
        return {"ok": True, "test_id": test_id}

    @stream_wrapper("download_in")
    async def prepare_download(self, data: dict) -> dict:
        test_id = (data or {}).get("test_id") or str(uuid.uuid4())
        buff = int(self.ctx.config.memory.default_buff) if hasattr(self.ctx.config, "memory") else 10
        # event для ожидания завершения
        ev = asyncio.Event()
        self._downloads[test_id] = {"bytes": 0, "chunks": 0, "start": time.time(), "buff": buff}
        self._download_events[test_id] = ev
        return {"test_id": test_id, "buff": buff}

    @stream_consumer("download_in")
    async def download_in(self, pipe: Pipe, ctx: dict):
        test_id = ctx.get("test_id") or ctx.get("label") or "unknown"
        buff = int(ctx.get("buff", 10))
        router = self.ctx.network.router
        label = ctx.get("label")
        if label:
            await router.send_stream_ack(label, buff)
        total = 0
        chunks = 0
        async for chunk in pipe:
            total += len(chunk) if isinstance(chunk, (bytes, bytearray)) else 0
            chunks += 1
            if label and pipe.size < buff:
                await router.send_stream_ack(label, buff)
        # сохраняем
        if test_id in self._downloads:
            self._downloads[test_id]["bytes"] = total
            self._downloads[test_id]["chunks"] = chunks
            self._downloads[test_id]["end"] = time.time()
        else:
            self._downloads[test_id] = {"bytes": total, "chunks": chunks, "start": time.time(), "end": time.time(), "buff": buff}
        ev = self._download_events.get(test_id)
        if ev and not ev.is_set():
            ev.set()
        self.log.info(f"download_in {test_id[:8]} done: {chunks} ch, {total} B")

    @rpc
    async def get_download_result(self, data: dict) -> dict:
        test_id = (data or {}).get("test_id")
        if not test_id or test_id not in self._downloads:
            return {"ok": False, "error": "test_id not found"}
        return {"ok": True, "result": self._downloads[test_id]}

    # ------------------------------------------------------------------ #
    #  Upload: инициатор пушит в upload_in цели
    # ------------------------------------------------------------------ #
    @stream_wrapper("upload_in")
    async def prepare_upload(self, data: dict) -> dict:
        test_id = (data or {}).get("test_id") or str(uuid.uuid4())
        buff = int(self.ctx.config.memory.default_buff) if hasattr(self.ctx.config, "memory") else 10
        self._uploads[test_id] = {"bytes": 0, "chunks": 0, "start": time.time(), "buff": buff}
        return {"test_id": test_id, "buff": buff}

    @stream_consumer("upload_in")
    async def upload_in(self, pipe: Pipe, ctx: dict):
        test_id = ctx.get("test_id") or ctx.get("label") or "unknown"
        buff = int(ctx.get("buff", 10))
        router = self.ctx.network.router
        label = ctx.get("label")
        if label:
            await router.send_stream_ack(label, buff)
        total = 0
        chunks = 0
        async for chunk in pipe:
            total += len(chunk) if isinstance(chunk, (bytes, bytearray)) else 0
            chunks += 1
            if label and pipe.size < buff:
                await router.send_stream_ack(label, buff)
        if test_id in self._uploads:
            self._uploads[test_id]["bytes"] = total
            self._uploads[test_id]["chunks"] = chunks
            self._uploads[test_id]["end"] = time.time()
        else:
            self._uploads[test_id] = {"bytes": total, "chunks": chunks, "start": time.time(), "end": time.time(), "buff": buff}
        self.log.info(f"upload_in {test_id[:8]} done: {chunks} ch, {total} B")

    @rpc
    async def get_upload_result(self, data: dict) -> dict:
        test_id = (data or {}).get("test_id")
        if not test_id or test_id not in self._uploads:
            return {"ok": False, "error": "test_id not found"}
        return {"ok": True, "result": self._uploads[test_id]}

    # ------------------------------------------------------------------ #
    #  Helpers
    # ------------------------------------------------------------------ #
    async def _measure_ping(self, dst: str, count: int = 5) -> dict:
        rtts = []
        for _ in range(count):
            ts = time.time()
            try:
                await self.ctx.network.call(dst=dst, service="speedtest", method="ping", data={"ts": ts}, timeout=5)
                rtts.append((time.time() - ts) * 1000)
            except Exception:
                rtts.append(None)
            await asyncio.sleep(0.05)
        ok_rtts = [x for x in rtts if x is not None]
        return {
            "rtts": rtts,
            "avg": sum(ok_rtts) / len(ok_rtts) if ok_rtts else None,
            "min": min(ok_rtts) if ok_rtts else None,
            "max": max(ok_rtts) if ok_rtts else None,
            "loss": (len(rtts) - len(ok_rtts)) / len(rtts) * 100,
        }

    async def _test_download(self, dst: str, duration: float, chunk_size: int, max_chunks: int) -> dict:
        test_id = str(uuid.uuid4())
        # подготовим локальный приём (создаст entry в _downloads)
        # wrapper создастся при STREAM_OPEN, но создадим заранее event
        ev = asyncio.Event()
        self._downloads[test_id] = {"bytes": 0, "chunks": 0, "start": time.time(), "buff": 10}
        self._download_events[test_id] = ev
        start = time.time()
        try:
            # попросим цель начать слать
            res = await self.ctx.network.call(dst=dst, service="speedtest", method="start_download", data={"dst": self.ctx.NODE, "test_id": test_id, "duration": duration, "chunk_size": chunk_size, "max_chunks": max_chunks}, timeout=10)
            if not res.get("ok"):
                return {"ok": False, "error": res.get("error", "start_download failed"), "bytes": 0, "chunks": 0, "elapsed": time.time() - start}
            # ждём завершения (с запасом)
            try:
                await asyncio.wait_for(ev.wait(), timeout=duration + 10)
            except asyncio.TimeoutError:
                pass
            # результат из локального _downloads
            r = self._downloads.get(test_id, {})
            total_bytes = r.get("bytes", 0)
            total_chunks = r.get("chunks", 0)
            elapsed = r.get("end", time.time()) - r.get("start", start)
            if elapsed <= 0:
                elapsed = time.time() - start
            mbps = (total_bytes * 8 / 1_000_000 / elapsed) if elapsed > 0 else 0
            return {"ok": True, "bytes": total_bytes, "chunks": total_chunks, "elapsed": elapsed, "mbps": mbps}
        except Exception as e:
            return {"ok": False, "error": str(e), "bytes": 0, "chunks": 0, "elapsed": time.time() - start}
        finally:
            self._downloads.pop(test_id, None)
            self._download_events.pop(test_id, None)

    async def _test_upload(self, dst: str, duration: float, chunk_size: int, max_chunks: int) -> dict:
        test_id = str(uuid.uuid4())
        chunk = b"\x00" * chunk_size
        pipe = self.ctx.memory.create_pipe(buff=8)
        dispatcher = self.ctx.memory.create_dispatcher([pipe])
        sent = {"bytes": 0, "chunks": 0}
        def gen():
            cnt = 0
            t0 = time.time()
            while cnt < max_chunks and (time.time() - t0) < duration:
                yield chunk
                cnt += 1
                sent["chunks"] = cnt
                sent["bytes"] += chunk_size
        template = MsgPack(
            source=self.ctx.NODE,
            dst=dst,
            service="speedtest",
            method="upload_in",
            label=test_id,
            data={"test_id": test_id},
        )
        self.ctx.memory.attach_transport(pipe, template, self.ctx.network.router)
        start = time.time()
        task = dispatcher.start(gen)
        try:
            await asyncio.wait_for(task, timeout=duration + 10)
        except asyncio.TimeoutError:
            pass
        await asyncio.sleep(0.5)
        elapsed = time.time() - start
        # пробуем получить точный приём на удалённом узле
        total_bytes = sent["bytes"]
        total_chunks = sent["chunks"]
        for _ in range(5):
            try:
                res = await self.ctx.network.call(dst=dst, service="speedtest", method="get_upload_result", data={"test_id": test_id}, timeout=5)
                if res.get("ok"):
                    r = res["result"]
                    if r.get("bytes", 0) > 0:
                        total_bytes = r.get("bytes", total_bytes)
                        total_chunks = r.get("chunks", total_chunks)
                    mbps = (total_bytes * 8 / 1_000_000 / elapsed) if elapsed > 0 else 0
                    return {"ok": True, "bytes": total_bytes, "chunks": total_chunks, "elapsed": elapsed, "mbps": mbps}
            except Exception:
                pass
            await asyncio.sleep(0.5)
        mbps = (total_bytes * 8 / 1_000_000 / elapsed) if elapsed > 0 else 0
        return {"ok": True, "bytes": total_bytes, "chunks": total_chunks, "elapsed": elapsed, "mbps": mbps}

    # ------------------------------------------------------------------ #
    #  Главный RPC — запускает тест с инициатора (вызывается локально)
    # ------------------------------------------------------------------ #
    @rpc
    async def run_test(self, data: dict) -> dict:
        dst = data.get("dst") or data.get("target") or data.get("node")
        if not dst:
            return {"ok": False, "error": "dst обязателен"}
        if dst == self.ctx.NODE:
            return {"ok": False, "error": "dst == self — выберите удалённый узел"}
        direction = (data.get("direction") or "download").strip().lower()
        if direction not in ("download", "upload", "bidirectional", "both"):
            direction = "download"
        if direction == "both":
            direction = "bidirectional"
        duration = float(data.get("duration", DEFAULT_DURATION))
        duration = max(1, min(duration, 120))
        chunk_size = int(data.get("chunk_size", DEFAULT_CHUNK))
        chunk_size = max(1024, min(chunk_size, 4 * 1024 * 1024))
        max_chunks = int(data.get("max_chunks", DEFAULT_MAX_CHUNKS))
        max_chunks = max(1, min(max_chunks, 200_000_000))
        parallel = int(data.get("parallel", DEFAULT_PARALLEL))
        parallel = max(1, min(parallel, 8))
        ping_count = int(data.get("ping_count", 5))
        ping_count = max(1, min(ping_count, 20))
        ping_res = await self._measure_ping(dst, count=ping_count)
        result = {"ok": True, "dst": dst, "direction": direction, "params": {"duration": duration, "chunk_size": chunk_size, "max_chunks": max_chunks, "parallel": parallel}, "ping": ping_res}
        try:
            if direction == "download":
                tasks = [self._test_download(dst, duration, chunk_size, max_chunks) for _ in range(parallel)]
                parts = await asyncio.gather(*tasks)
                total_bytes = sum(p.get("bytes", 0) for p in parts if p.get("ok"))
                total_chunks = sum(p.get("chunks", 0) for p in parts if p.get("ok"))
                elapsed = max((p.get("elapsed", 0) for p in parts), default=0)
                mbps = (total_bytes * 8 / 1_000_000 / elapsed) if elapsed > 0 else 0
                result["download"] = {"parts": parts, "bytes": total_bytes, "chunks": total_chunks, "elapsed": elapsed, "mbps": mbps}
            elif direction == "upload":
                tasks = [self._test_upload(dst, duration, chunk_size, max_chunks) for _ in range(parallel)]
                parts = await asyncio.gather(*tasks)
                total_bytes = sum(p.get("bytes", 0) for p in parts if p.get("ok"))
                total_chunks = sum(p.get("chunks", 0) for p in parts if p.get("ok"))
                elapsed = max((p.get("elapsed", 0) for p in parts), default=0)
                mbps = (total_bytes * 8 / 1_000_000 / elapsed) if elapsed > 0 else 0
                result["upload"] = {"parts": parts, "bytes": total_bytes, "chunks": total_chunks, "elapsed": elapsed, "mbps": mbps}
            elif direction == "bidirectional":
                dur_half = duration / 2 if duration > 4 else duration
                if parallel == 1:
                    dl = await self._test_download(dst, dur_half, chunk_size, max_chunks)
                    ul = await self._test_upload(dst, dur_half, chunk_size, max_chunks)
                    result["download"] = dl
                    result["upload"] = ul
                else:
                    dl_tasks = [self._test_download(dst, dur_half, chunk_size, max_chunks) for _ in range(parallel)]
                    dl_parts = await asyncio.gather(*dl_tasks)
                    dl_bytes = sum(p.get("bytes", 0) for p in dl_parts if p.get("ok"))
                    dl_chunks = sum(p.get("chunks", 0) for p in dl_parts if p.get("ok"))
                    dl_elapsed = max((p.get("elapsed", 0) for p in dl_parts), default=0)
                    dl_mbps = (dl_bytes * 8 / 1_000_000 / dl_elapsed) if dl_elapsed > 0 else 0
                    result["download"] = {"parts": dl_parts, "bytes": dl_bytes, "chunks": dl_chunks, "elapsed": dl_elapsed, "mbps": dl_mbps}
                    ul_tasks = [self._test_upload(dst, dur_half, chunk_size, max_chunks) for _ in range(parallel)]
                    ul_parts = await asyncio.gather(*ul_tasks)
                    ul_bytes = sum(p.get("bytes", 0) for p in ul_parts if p.get("ok"))
                    ul_chunks = sum(p.get("chunks", 0) for p in ul_parts if p.get("ok"))
                    ul_elapsed = max((p.get("elapsed", 0) for p in ul_parts), default=0)
                    ul_mbps = (ul_bytes * 8 / 1_000_000 / ul_elapsed) if ul_elapsed > 0 else 0
                    result["upload"] = {"parts": ul_parts, "bytes": ul_bytes, "chunks": ul_chunks, "elapsed": ul_elapsed, "mbps": ul_mbps}
        except Exception as e:
            result["ok"] = False
            result["error"] = str(e)
        return result
