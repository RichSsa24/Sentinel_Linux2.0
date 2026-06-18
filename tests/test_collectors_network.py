"""Tests for `sentinel.collectors.network`.

The collector reads ``/proc/net/tcp`` (Linux-only), so every test drives it
against a synthetic ``/proc/net`` tree built under ``tmp_path`` via the
injectable ``proc_root``. Layers:

1. **Line parsing** — ``parse_net_line`` is pure; its hex address/port decoding,
   IPv6 handling, header skipping and rejection of adversarial input are pinned.
2. **Scanning** — the first scan is a silent baseline; listen/connection
   open/close are classified; untracked states, a missing file and the scan cap
   are all handled safely.
3. **Exactly-once (the payoff)** — through the real ``Pipeline``, a re-baseline
   race re-emits an identical socket-open, yet the consumer sees it once.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
from collections.abc import Callable
from pathlib import Path

import pytest

from sentinel.collectors.netparse import parse_net_line
from sentinel.collectors.network import NetworkCollector
from sentinel.events import Event
from sentinel.pipeline.queue import BoundedEventQueue
from sentinel.pipeline.runner import Pipeline
from tests.conftest import settings_no_env_file

_HEADER = (
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
    "retrnsmt   uid  timeout inode\n"
)

# Hex state codes used in /proc/net/tcp.
_LISTEN = "0A"
_ESTABLISHED = "01"
_TIME_WAIT = "06"


def _hex_addr(ip: str, *, ipv6: bool) -> str:
    """Encode an IP the way the kernel does in /proc/net/tcp (little-endian)."""
    if ipv6:
        packed = ipaddress.IPv6Address(ip).packed
        words = b"".join(packed[i : i + 4][::-1] for i in range(0, 16, 4))
        return words.hex().upper()
    return ipaddress.IPv4Address(ip).packed[::-1].hex().upper()


def _row(
    *,
    local: str,
    lport: int,
    remote: str = "0.0.0.0",
    rport: int = 0,
    state: str = _LISTEN,
    uid: int = 0,
    inode: int = 1,
    slot: int = 0,
    ipv6: bool = False,
) -> str:
    """Build one well-formed /proc/net/tcp data row."""
    la = f"{_hex_addr(local, ipv6=ipv6)}:{lport:04X}"
    ra = f"{_hex_addr(remote, ipv6=ipv6)}:{rport:04X}"
    cols = [
        f"{slot}:", la, ra, state, "00000000:00000000", "00:00000000",
        "00000000", str(uid), "0", str(inode), "1", "0" * 16, "100", "0", "0",
    ]  # fmt: skip
    return " " + " ".join(cols)


def _mk_net(root: Path, *, tcp: list[str] | None = None, tcp6: list[str] | None = None) -> None:
    """Materialise a synthetic /proc/net/{tcp,tcp6} from row lists."""
    net = root / "net"
    net.mkdir(parents=True, exist_ok=True)
    if tcp is not None:
        (net / "tcp").write_text(_HEADER + "\n".join(tcp) + "\n", encoding="utf-8")
    if tcp6 is not None:
        (net / "tcp6").write_text(_HEADER + "\n".join(tcp6) + "\n", encoding="utf-8")


def _collector(root: Path, **kwargs: object) -> NetworkCollector:
    return NetworkCollector(proc_root=root, host="testhost", **kwargs)  # type: ignore[arg-type]


async def _drain(collector: NetworkCollector) -> list[Event]:
    """Run one scan/diff cycle and return the events it would enqueue."""
    queue = BoundedEventQueue(maxsize=256)
    await collector._drain_once(queue)
    events: list[Event] = []
    while not queue.empty():
        events.append(await queue.get())
        queue.task_done()
    return events


async def _wait_for(predicate: Callable[[], bool], timeout: float = 5.0) -> bool:  # noqa: ASYNC109 — poll loop, not an `asyncio.timeout()` block
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.01)
    return False


class TestParseNetLine:
    def test_ipv4_listen_row(self) -> None:
        sock = parse_net_line(_row(local="127.0.0.1", lport=22, inode=999), proto="tcp")
        assert sock is not None
        assert sock.local_ip == "127.0.0.1"
        assert sock.local_port == 22
        assert sock.state == "LISTEN"
        assert sock.inode == 999

    def test_ipv4_established_row_has_remote(self) -> None:
        line = _row(
            local="10.0.0.5", lport=4444, remote="93.184.216.34", rport=443,
            state=_ESTABLISHED, uid=1000, inode=555,
        )  # fmt: skip
        sock = parse_net_line(line, proto="tcp")
        assert sock is not None
        assert sock.state == "ESTABLISHED"
        assert sock.remote_ip == "93.184.216.34"
        assert sock.remote_port == 443
        assert sock.uid == 1000

    def test_ipv6_row_decodes_address(self) -> None:
        line = _row(local="::1", lport=8080, remote="::", state=_LISTEN, ipv6=True)
        sock = parse_net_line(line, proto="tcp6")
        assert sock is not None
        assert sock.local_ip == "::1"
        assert sock.local_port == 8080

    def test_header_line_returns_none(self) -> None:
        assert parse_net_line(_HEADER.strip(), proto="tcp") is None

    def test_too_few_fields_returns_none(self) -> None:
        assert parse_net_line("0: 0100007F:0016 00000000:0000 0A", proto="tcp") is None

    def test_unknown_state_returns_none(self) -> None:
        assert parse_net_line(_row(local="127.0.0.1", lport=1, state="FF"), proto="tcp") is None

    def test_bad_local_hex_returns_none(self) -> None:
        # 'G' is not a hex digit — the address must be rejected, not coerced.
        bad = _row(local="127.0.0.1", lport=22).replace("0100007F", "0100007G")
        assert parse_net_line(bad, proto="tcp") is None

    def test_bad_remote_hex_returns_none(self) -> None:
        line = _row(local="127.0.0.1", lport=22, remote="8.8.8.8", rport=53,
                    state=_ESTABLISHED)  # fmt: skip
        broken = line.replace(_hex_addr("8.8.8.8", ipv6=False), "ZZZZZZZZ")
        assert parse_net_line(broken, proto="tcp") is None

    def test_short_address_hex_returns_none(self) -> None:
        assert parse_net_line("0: 0100:0016 00000000:0000 0A 0 0 0 0 0 5", proto="tcp") is None

    def test_endpoint_without_colon_returns_none(self) -> None:
        line = "0: 0100007F0016 00000000:0000 0A x x x 0 0 5 1 0 0 0 0"
        assert parse_net_line(line, proto="tcp") is None

    def test_out_of_range_port_returns_none(self) -> None:
        line = "0: 0100007F:1FFFF 00000000:0000 0A x x x 0 0 5 1 0 0 0 0"
        assert parse_net_line(line, proto="tcp") is None

    def test_non_integer_inode_returns_none(self) -> None:
        line = "0: 0100007F:0016 00000000:0000 0A x x x 0 0 notaninode"
        assert parse_net_line(line, proto="tcp") is None

    def test_short_ipv6_address_returns_none(self) -> None:
        line = "0: 0100:0016 00000000000000000000000000000000:0000 0A x x x 0 0 5 1 0 0 0 0"
        assert parse_net_line(line, proto="tcp6") is None

    def test_non_hex_ipv6_address_returns_none(self) -> None:
        # 32 chars but not valid hex — bytes.fromhex must reject it.
        line = "0: " + "Z" * 32 + ":0016 " + "0" * 32 + ":0000 0A x x x 0 0 5"
        assert parse_net_line(line, proto="tcp6") is None

    def test_non_hex_port_returns_none(self) -> None:
        assert parse_net_line("0: 0100007F:GGGG 00000000:0000 0A x x x 0 0 5", proto="tcp") is None


class TestConstruction:
    def test_rejects_non_positive_poll_interval(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="poll_interval"):
            NetworkCollector(proc_root=tmp_path, poll_interval=0)


class TestScanning:
    @pytest.mark.asyncio
    async def test_first_scan_is_silent_baseline(self, tmp_path: Path) -> None:
        _mk_net(tmp_path, tcp=[_row(local="0.0.0.0", lport=22, inode=10)])
        collector = _collector(tmp_path)

        assert await _drain(collector) == []
        assert collector.stats["tracked"] == 1

    @pytest.mark.asyncio
    async def test_detects_new_listening_socket(self, tmp_path: Path) -> None:
        _mk_net(tmp_path, tcp=[])
        collector = _collector(tmp_path)
        await _drain(collector)  # empty baseline

        _mk_net(tmp_path, tcp=[_row(local="0.0.0.0", lport=4444, inode=77)])
        events = await _drain(collector)

        assert len(events) == 1
        event = events[0]
        assert event.event.action == "network_listen_started"
        assert event.event.category.value == "network"
        assert event.source.ip == "0.0.0.0"
        assert event.source.port == 4444
        # A listener has no fixed peer.
        assert event.destination.ip is None

    @pytest.mark.asyncio
    async def test_detects_closed_listening_socket(self, tmp_path: Path) -> None:
        _mk_net(tmp_path, tcp=[_row(local="0.0.0.0", lport=22, inode=10)])
        collector = _collector(tmp_path)
        await _drain(collector)  # baseline includes :22

        _mk_net(tmp_path, tcp=[])
        events = await _drain(collector)

        assert len(events) == 1
        assert events[0].event.action == "network_listen_stopped"
        assert events[0].source.port == 22

    @pytest.mark.asyncio
    async def test_detects_new_established_connection(self, tmp_path: Path) -> None:
        _mk_net(tmp_path, tcp=[])
        collector = _collector(tmp_path)
        await _drain(collector)

        _mk_net(
            tmp_path,
            tcp=[
                _row(
                    local="10.0.0.5",
                    lport=51000,
                    remote="93.184.216.34",
                    rport=443,
                    state=_ESTABLISHED,
                    inode=900,
                )
            ],
        )
        events = await _drain(collector)

        assert len(events) == 1
        event = events[0]
        assert event.event.action == "network_connection_opened"
        assert event.destination.ip == "93.184.216.34"
        assert event.destination.port == 443

    @pytest.mark.asyncio
    async def test_detects_closed_connection(self, tmp_path: Path) -> None:
        line = _row(local="10.0.0.5", lport=51000, remote="8.8.8.8", rport=53,
                    state=_ESTABLISHED, inode=901)  # fmt: skip
        _mk_net(tmp_path, tcp=[line])
        collector = _collector(tmp_path)
        await _drain(collector)

        _mk_net(tmp_path, tcp=[])
        events = await _drain(collector)

        assert len(events) == 1
        assert events[0].event.action == "network_connection_closed"

    @pytest.mark.asyncio
    async def test_untracked_state_is_ignored(self, tmp_path: Path) -> None:
        # A TIME_WAIT socket is neither LISTEN nor ESTABLISHED — never tracked.
        _mk_net(tmp_path, tcp=[_row(local="10.0.0.5", lport=5, state=_TIME_WAIT)])
        collector = _collector(tmp_path)

        assert await _drain(collector) == []
        assert collector.stats["tracked"] == 0

    @pytest.mark.asyncio
    async def test_track_connections_false_ignores_established(self, tmp_path: Path) -> None:
        _mk_net(tmp_path, tcp=[])
        collector = _collector(tmp_path, track_connections=False)
        await _drain(collector)

        _mk_net(
            tmp_path,
            tcp=[
                _row(local="0.0.0.0", lport=22, inode=10),
                _row(
                    local="10.0.0.5",
                    lport=40000,
                    remote="1.1.1.1",
                    rport=443,
                    state=_ESTABLISHED,
                    inode=11,
                ),
            ],
        )
        events = await _drain(collector)

        assert len(events) == 1
        assert events[0].event.action == "network_listen_started"

    @pytest.mark.asyncio
    async def test_ipv6_listener_detected(self, tmp_path: Path) -> None:
        _mk_net(tmp_path, tcp=[], tcp6=[])
        collector = _collector(tmp_path)
        await _drain(collector)

        _mk_net(
            tmp_path,
            tcp=[],
            tcp6=[_row(local="::1", lport=9000, remote="::", inode=222, ipv6=True)],
        )
        events = await _drain(collector)

        assert len(events) == 1
        assert events[0].source.ip == "::1"
        assert events[0].source.port == 9000

    @pytest.mark.asyncio
    async def test_missing_proc_net_is_not_fatal(self, tmp_path: Path) -> None:
        collector = _collector(tmp_path)  # no /proc/net created at all

        assert await _drain(collector) == []
        assert collector.stats["tracked"] == 0

    @pytest.mark.asyncio
    async def test_max_sockets_cap_bounds_the_scan(self, tmp_path: Path) -> None:
        rows = [_row(local="0.0.0.0", lport=p, inode=p) for p in range(1000, 1005)]
        _mk_net(tmp_path, tcp=rows)
        collector = _collector(tmp_path, max_sockets=2)
        await _drain(collector)

        assert collector.stats["tracked"] == 2

    @pytest.mark.asyncio
    async def test_run_does_a_final_scan_when_already_stopped(self, tmp_path: Path) -> None:
        # stopping is set before run() → the poll loop is skipped and run()
        # performs exactly one catch-up scan, then exits cleanly.
        _mk_net(tmp_path, tcp=[_row(local="0.0.0.0", lport=22, inode=10)])
        collector = _collector(tmp_path)
        await collector.stop()

        await collector.run(BoundedEventQueue(maxsize=8))

        assert collector._seeded is True
        assert collector.stats["tracked"] == 1

    @pytest.mark.asyncio
    async def test_service_restart_is_close_then_open(self, tmp_path: Path) -> None:
        _mk_net(tmp_path, tcp=[_row(local="0.0.0.0", lport=22, inode=10)])
        collector = _collector(tmp_path)
        await _drain(collector)

        # Same ip:port, new inode → a different socket instance (a restart).
        _mk_net(tmp_path, tcp=[_row(local="0.0.0.0", lport=22, inode=20)])
        events = await _drain(collector)

        actions = sorted(e.event.action for e in events)
        assert actions == ["network_listen_started", "network_listen_stopped"]
        assert len({e.event.id for e in events}) == 2


class TestExactlyOnceUnderRebaseline:
    @pytest.mark.asyncio
    async def test_rebaseline_reemit_is_deduped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SENTINEL_ENV", "test")
        monkeypatch.setenv("SENTINEL_DEDUP_WINDOW_SECONDS", "300")
        settings = settings_no_env_file()
        received: list[str] = []

        async def consumer(event: Event) -> None:
            received.append(event.event.id)

        _mk_net(tmp_path, tcp=[])
        collector = _collector(tmp_path, poll_interval=0.02)
        pipeline = Pipeline(settings)
        pipeline.set_consumer(consumer)
        pipeline.register(collector)

        run_task = asyncio.create_task(pipeline.run())
        try:
            assert await _wait_for(lambda: collector._seeded)  # empty baseline

            _mk_net(tmp_path, tcp=[_row(local="0.0.0.0", lport=31337, inode=42)])
            assert await _wait_for(
                lambda: collector.stats["emitted"] == 1 and pipeline.stats["queue_size"] == 0
            )

            # Re-baseline race: forget the socket, re-detect it as opened with the
            # same identity → identical event.id → collapses in the dedup window.
            collector._baseline = {}
            assert await _wait_for(
                lambda: collector.stats["emitted"] == 2 and pipeline.stats["queue_size"] == 0
            )
        finally:
            await pipeline.stop()
            with contextlib.suppress(asyncio.CancelledError):
                await asyncio.wait_for(run_task, timeout=5.0)

        assert collector.stats["emitted"] == 2
        assert len(received) == 1
        assert pipeline.stats["processed"] == 1
        assert pipeline.stats["deduped"] == 1
