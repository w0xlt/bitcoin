#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Collect the fixed async-PNB mmap stream without controlling bitcoind."""

import argparse
import csv
import hashlib
import json
import math
import mmap
import os
import platform
import shutil
import signal
import struct
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path


MAGIC = b"APNBPRB\0"
SCHEMA = 4
COLLECTOR_SCHEMA = 2
HEADER_SIZE = 128
RECORD_SIZE = 256
CAPACITY = 65_536
ENDIAN = 0x01020304
STATUS_TEST_GATES = 1
STATUS_LOSS = 2
STATUS_CLOSED = 4
SLOT_CLAIM = 1 << 63
HEADER = struct.Struct("<8s5IiI4xQqqQQQ4Ii20x")
EVENT = struct.Struct("<QQIIq16q24s24s32s")
ACK_OFFSET = 72
EVENT_NAMES = {
    1: "complete_message_ready",
    2: "handler_start",
    3: "handler_complete",
    4: "response_queued",
    5: "job_submit",
    6: "slot_submit",
    7: "worker_wake",
    8: "pnb_start",
    9: "pnb_end",
    10: "result_publication",
    11: "busy_send_prefix_summary",
    12: "result_collection",
    13: "continuation",
    14: "test_gate_entered",
    15: "test_interface_registered",
    16: "test_interface_unregistered",
    17: "test_shutdown_started",
    18: "handler_prefix_complete",
    19: "handler_tail_complete",
    20: "test_target_disconnected",
    21: "message_front_ready",
    22: "receive_queue_state",
    23: "outbound_queued",
    24: "socket_sent",
    25: "outbound_dropped",
    26: "causal_link",
    27: "peer_created",
    28: "handshake_complete",
    29: "peer_finalized",
    30: "discouragement",
    31: "send_queue_state",
    32: "block_requested",
    33: "block_request_removed",
    34: "block_timeout",
}
BLOCK_HASH_EVENTS = set(range(5, 21)) | {32, 33, 34}
OUTPUT_NAMES = (
    "manifest.json", "events.jsonl", "resources.csv", "rpc.jsonl", "summary.json")
RESOURCE_FIELDS = (
    "monotonic_ns", "wall_ns", "clock_capture_uncertainty_ns",
    "process_user_seconds", "process_system_seconds",
    "thread_msghand_seconds", "thread_pnb_seconds", "thread_network_seconds",
    "thread_validation_seconds", "thread_other_seconds", "rss_bytes", "thread_count",
    "voluntary_ctxt_switches", "nonvoluntary_ctxt_switches", "rchar", "wchar",
    "syscr", "syscw", "read_bytes", "write_bytes")


class CollectionError(RuntimeError):
    pass


def checksum(data):
    result = 1_469_598_103_934_665_603
    for byte in data:
        result ^= byte
        result = (result * 1_099_511_628_211) & 0xffffffffffffffff
    return result


def decode_text(raw):
    return raw.split(b"\0", 1)[0].decode("ascii", errors="strict")


def validate_slot(expected, epoch, published_before, record, stored_checksum,
                  published_after):
    """Return None for an in-flight publication; raise on retained-run faults."""
    if published_before & SLOT_CLAIM:
        return None
    if published_before == 0 or published_before < expected:
        return None
    if published_before > expected:
        raise CollectionError(
            f"sequence gap/overwrite: expected {expected}, slot has {published_before}")
    if published_after != published_before:
        raise CollectionError(
            f"unstable slot read: sequence {expected}, before {published_before}, "
            f"after {published_after}")
    if stored_checksum != checksum(record):
        raise CollectionError(f"checksum failure at sequence {expected}")
    unpacked = EVENT.unpack(record)
    if unpacked[0] != expected:
        raise CollectionError(
            f"record sequence mismatch: expected {expected}, record has {unpacked[0]}")
    if unpacked[1] != epoch:
        raise CollectionError(
            f"process epoch changed at sequence {expected}: "
            f"expected {epoch}, record has {unpacked[1]}")
    if unpacked[2] not in EVENT_NAMES:
        raise CollectionError(f"unknown event {unpacked[2]} at sequence {expected}")
    return unpacked


class ProbeStream:
    def __init__(self, path, pid):
        unresolved = Path(path)
        if not unresolved.is_file() or unresolved.is_symlink():
            raise CollectionError(f"probe is not a regular non-symlink file: {unresolved}")
        expected_size = HEADER_SIZE + CAPACITY * RECORD_SIZE
        if unresolved.stat().st_size != expected_size:
            raise CollectionError(
                f"probe size mismatch: expected {expected_size}, got {unresolved.stat().st_size}")
        self.path = unresolved.resolve()
        flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        self.fd = os.open(self.path, flags)
        self.mapping = mmap.mmap(self.fd, 0, access=mmap.ACCESS_WRITE)
        self.pid = pid
        self.expected = 1
        self.header = self.read_header(initial=True)
        self.epoch = self.header[8]
        self.creation_wall_ns = self.header[9]
        self.creation_steady_ns = self.header[10]

    def read_header(self, initial=False):
        header = HEADER.unpack_from(self.mapping, 0)
        if header[:6] != (MAGIC, SCHEMA, HEADER_SIZE, RECORD_SIZE, CAPACITY, ENDIAN):
            raise CollectionError(f"probe ABI mismatch: {header[:6]!r}")
        if header[6] != self.pid:
            raise CollectionError(f"probe PID mismatch: expected {self.pid}, got {header[6]}")
        if header[7] & ~(STATUS_TEST_GATES | STATUS_LOSS | STATUS_CLOSED):
            raise CollectionError(f"unknown probe status bits: {header[7]:#x}")
        if header[7] & STATUS_TEST_GATES:
            raise CollectionError("test-gate probe streams are not retainable measurements")
        if header[7] & STATUS_LOSS or header[13]:
            raise CollectionError(
                f"producer reported sequence loss: status={header[7]:#x} count={header[13]}")
        if header[8] == 0:
            raise CollectionError("zero process epoch")
        if header[9] <= 0 or header[10] <= 0:
            raise CollectionError("nonpositive probe clock origin")
        if not initial and header[8] != self.epoch:
            raise CollectionError(
                f"process epoch changed: expected {self.epoch}, got {header[8]}")
        if not initial and header[9:11] != (
                self.creation_wall_ns, self.creation_steady_ns):
            raise CollectionError("probe clock origins changed during collection")
        if header[11] < header[12]:
            raise CollectionError(
                f"consumer acknowledgement exceeds producer: {header[12]} > {header[11]}")
        if header[11] > header[12] + CAPACITY:
            raise CollectionError(
                f"probe lag exceeds capacity: producer={header[11]} ack={header[12]}")
        self.header = header
        return header

    def read_one(self, sequence):
        offset = HEADER_SIZE + ((sequence - 1) & (CAPACITY - 1)) * RECORD_SIZE
        before = struct.unpack_from("<Q", self.mapping, offset)[0]
        if before == 0 or before < sequence:
            return None
        record = bytes(self.mapping[offset + 8:offset + 248])
        stored_checksum = struct.unpack_from("<Q", self.mapping, offset + 248)[0]
        after = struct.unpack_from("<Q", self.mapping, offset)[0]
        return validate_slot(sequence, self.epoch, before, record, stored_checksum, after)

    def acknowledge(self, sequence):
        struct.pack_into("<Q", self.mapping, ACK_OFFSET, sequence)

    def close(self):
        self.mapping.close()
        os.close(self.fd)


class DurableEventBatch:
    """Publish consumer acknowledgement only after JSONL durability."""

    def __init__(self, output, acknowledge, sync=os.fsync, initial_sequence=0):
        self.output = output
        self.acknowledge = acknowledge
        self.sync = sync
        self.pending_sequence = initial_sequence
        self.durable_sequence = initial_sequence
        self.flushes = 0

    def note_written(self, sequence):
        if sequence != self.pending_sequence + 1:
            raise CollectionError(
                f"nonconsecutive event write: {self.pending_sequence} to {sequence}")
        self.pending_sequence = sequence

    def make_durable(self):
        if self.pending_sequence == self.durable_sequence:
            return False
        self.output.flush()
        self.sync(self.output.fileno())
        self.durable_sequence = self.pending_sequence
        self.acknowledge(self.durable_sequence)
        self.flushes += 1
        return True


class OpaqueIds:
    def __init__(self):
        self.ids = {}

    def get(self, raw, prefix):
        key = bytes(raw)
        identity = self.ids.get((prefix, key))
        if identity is None:
            identity = f"{prefix}{sum(1 for p, _ in self.ids if p == prefix) + 1:06d}"
            self.ids[(prefix, key)] = identity
        return identity


def decoded_event(unpacked, opaque):
    sequence, epoch, event, flags, steady_ns = unpacked[:5]
    values = list(unpacked[5:21])
    if event == 4 and values[2] != 0:
        raise CollectionError(
            f"response_queued reserved field is nonzero at sequence {sequence}")
    result = {
        "sequence": sequence,
        "process_epoch": epoch,
        "event": EVENT_NAMES[event],
        "event_code": event,
        "flags": flags,
        "steady_ns": steady_ns,
        "values": values,
    }
    text1, text2 = decode_text(unpacked[21]), decode_text(unpacked[22])
    if text1:
        result["text1"] = text1
    if text2:
        result["text2"] = text2
    raw_hash = unpacked[23]
    if any(raw_hash):
        key = "block_id" if event in BLOCK_HASH_EVENTS else "object_id"
        result[key] = opaque.get(raw_hash, "b" if key == "block_id" else "o")
    return result


def read_proc_stat(pid, tid=None):
    path = Path("/proc") / str(pid)
    if tid is not None:
        path /= Path("task") / str(tid)
    raw = (path / "stat").read_text(encoding="ascii")
    close = raw.rfind(")")
    if close < 0:
        raise CollectionError(f"malformed {path / 'stat'}")
    comm = raw[raw.find("(") + 1:close]
    fields = raw[close + 2:].split()
    return {
        "comm": comm,
        "utime": int(fields[11]),
        "stime": int(fields[12]),
        "threads": int(fields[17]),
        "start_ticks": int(fields[19]),
        "rss_pages": int(fields[21]),
    }


def read_key_values(path):
    result = {}
    for line in Path(path).read_text(encoding="ascii", errors="strict").splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        token = value.strip().split()[0] if value.strip() else "0"
        try:
            result[key] = int(token)
        except ValueError:
            continue
    return result


def thread_category(name):
    if "msghand" in name:
        return "msghand"
    if "p2p-pnb" in name:
        return "pnb"
    if any(token in name for token in ("net", "opencon", "dnsseed", "addcon", "i2p")):
        return "network"
    if any(token in name for token in ("scriptch", "loadblk", "import")):
        return "validation"
    return "other"


def capture_clock_pair(monotonic_clock=time.monotonic_ns, wall_clock=time.time_ns):
    """Capture wall time with a conservative representative monotonic interval.

    The wall read occurs between the two monotonic reads. The persisted
    monotonic midpoint M and uncertainty U=ceil((after-before)/2) therefore
    guarantee that the corresponding monotonic instant is in [M-U, M+U].
    """
    monotonic_before = monotonic_clock()
    wall = wall_clock()
    monotonic_after = monotonic_clock()
    if (type(monotonic_before) is not int or type(monotonic_after) is not int or
            type(wall) is not int or monotonic_before <= 0 or wall <= 0 or
            monotonic_after < monotonic_before):
        raise CollectionError("invalid bracketed collector clock capture")
    span = monotonic_after - monotonic_before
    return {
        "monotonic_ns": monotonic_before + span // 2,
        "wall_ns": wall,
        "clock_capture_uncertainty_ns": (span + 1) // 2,
    }


def sample_resources(pid, clock_ticks, page_size):
    stat = read_proc_stat(pid)
    status = read_key_values(f"/proc/{pid}/status")
    io = read_key_values(f"/proc/{pid}/io")
    thread_ticks = Counter()
    task_dir = Path(f"/proc/{pid}/task")
    for entry in task_dir.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            thread = read_proc_stat(pid, int(entry.name))
        except FileNotFoundError:
            continue
        thread_ticks[thread_category(thread["comm"])] += thread["utime"] + thread["stime"]
    return {
        **capture_clock_pair(),
        "process_user_seconds": stat["utime"] / clock_ticks,
        "process_system_seconds": stat["stime"] / clock_ticks,
        "thread_msghand_seconds": thread_ticks["msghand"] / clock_ticks,
        "thread_pnb_seconds": thread_ticks["pnb"] / clock_ticks,
        "thread_network_seconds": thread_ticks["network"] / clock_ticks,
        "thread_validation_seconds": thread_ticks["validation"] / clock_ticks,
        "thread_other_seconds": thread_ticks["other"] / clock_ticks,
        "rss_bytes": stat["rss_pages"] * page_size,
        "thread_count": stat["threads"],
        "voluntary_ctxt_switches": status.get("voluntary_ctxt_switches", 0),
        "nonvoluntary_ctxt_switches": status.get("nonvoluntary_ctxt_switches", 0),
        **{key: io.get(key, 0) for key in
           ("rchar", "wchar", "syscr", "syscw", "read_bytes", "write_bytes")},
    }


def filtered_peer(peer):
    scalar = (
        "id", "inbound", "network", "transport_protocol_type", "connection_type",
        "bytesrecv", "bytessent", "conntime", "timeoffset", "pingtime", "minping",
        "pingwait", "version", "startingheight", "synced_headers", "synced_blocks",
        "presynced_headers", "addr_processed", "addr_rate_limited", "relaytxes",
        "minfeefilter", "bip152_hb_to", "bip152_hb_from")
    result = {key: peer[key] for key in scalar
              if key in peer and isinstance(peer[key], (int, float, bool, str))}
    if isinstance(peer.get("inflight"), list):
        result["inflight"] = [value for value in peer["inflight"]
                              if isinstance(value, int)]
    for key in ("bytessent_per_msg", "bytesrecv_per_msg"):
        if isinstance(peer.get(key), dict):
            result[key] = {str(name): value for name, value in peer[key].items()
                           if isinstance(value, (int, float))}
    return result


def run_rpc(cli, cli_args, expected_chain, *, runner=subprocess.run,
            clock_capture=capture_clock_pair):
    def call(method):
        completed = runner(
            [cli, *cli_args, method], check=True, capture_output=True,
            text=True, timeout=30)
        return json.loads(completed.stdout)

    chain = call("getblockchaininfo")
    totals = call("getnettotals")
    network = call("getnetworkinfo")
    peers = call("getpeerinfo")
    if chain.get("chain") != expected_chain:
        raise CollectionError(
            f"RPC chain mismatch: expected {expected_chain}, got {chain.get('chain')}")
    return {
        **clock_capture(),
        "chain": {
            key: chain[key] for key in
            ("chain", "blocks", "headers", "verificationprogress", "initialblockdownload")
            if key in chain
        },
        "warnings_present": bool(chain.get("warnings") or network.get("warnings")),
        "network_totals": {
            key: totals[key] for key in ("totalbytesrecv", "totalbytessent", "timemillis")
            if key in totals and isinstance(totals[key], (int, float))
        },
        "network": {
            key: network[key] for key in
            ("networkactive", "connections", "connections_in", "connections_out")
            if key in network and isinstance(network[key], (int, float, bool))
        },
        "peers": [filtered_peer(peer) for peer in peers if isinstance(peer, dict)],
    }


def rpc_failure_row(error, *, clock_capture=capture_clock_pair):
    return {**clock_capture(), "error": type(error).__name__}


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                return digest.hexdigest()
            digest.update(chunk)


def artifact_facts(path, *, csv_header=False):
    with Path(path).open("rb") as source:
        rows = sum(1 for _line in source)
    return {
        "bytes": Path(path).stat().st_size,
        "data_rows": max(0, rows - 1) if csv_header else rows,
        "lines": rows,
        "sha256": sha256_file(path),
    }


def capture_probe_boundary(stream):
    """Bracket a probe producer snapshot in both collector clock domains."""
    monotonic_before = time.monotonic_ns()
    wall_before = time.time_ns()
    header = stream.read_header()
    wall_after = time.time_ns()
    monotonic_after = time.monotonic_ns()
    return {
        "producer_sequence": header[11],
        "collector_monotonic_before_ns": monotonic_before,
        "collector_monotonic_after_ns": monotonic_after,
        "collector_monotonic_midpoint_ns":
            monotonic_before + (monotonic_after - monotonic_before) // 2,
        "collector_wall_before_ns": wall_before,
        "collector_wall_after_ns": wall_after,
        "collector_wall_midpoint_ns": wall_before + (wall_after - wall_before) // 2,
        "capture_uncertainty_ns":
            (monotonic_after - monotonic_before + wall_after - wall_before + 1) // 2,
    }


def clock_mapping(probe_header, boundary):
    probe_wall = probe_header[9]
    probe_steady = probe_header[10]
    collector_wall = boundary["collector_wall_midpoint_ns"]
    collector_monotonic = boundary["collector_monotonic_midpoint_ns"]
    probe_wall_minus_steady = probe_wall - probe_steady
    collector_wall_minus_monotonic = collector_wall - collector_monotonic
    residual = collector_wall_minus_monotonic - probe_wall_minus_steady
    return {
        "probe_creation_wall_ns": probe_wall,
        "probe_creation_steady_ns": probe_steady,
        "collector_wall_ns": collector_wall,
        "collector_monotonic_ns": collector_monotonic,
        "probe_wall_minus_steady_ns": probe_wall_minus_steady,
        "collector_wall_minus_monotonic_ns": collector_wall_minus_monotonic,
        "steady_to_collector_monotonic_offset_ns": -residual,
        "steady_to_wall_offset_ns": probe_wall_minus_steady,
        "origin_residual_ns": residual,
        "capture_uncertainty_ns": boundary["capture_uncertainty_ns"],
        "mapping_uncertainty_ns": abs(residual) + boundary["capture_uncertainty_ns"],
        "compatibility": "wall_offset_bridge_with_reported_uncertainty",
        "method": "wall-offset bridge; residual may include pre-attach wall correction; no affine/drift claim",
    }


def environment_identity():
    cpu_model = "unavailable"
    try:
        for line in Path("/proc/cpuinfo").read_text(
                encoding="ascii", errors="replace").splitlines():
            if line.startswith("model name"):
                cpu_model = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    return {
        "system": platform.system(),
        "kernel": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "cpu_model": cpu_model,
        "logical_cpu_count": os.cpu_count(),
        "clock_ticks_per_second": os.sysconf("SC_CLK_TCK"),
        "page_size": os.sysconf("SC_PAGE_SIZE"),
    }


def write_json(path, value):
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8") as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)


def resolve_pid(args):
    if args.pid is not None:
        return args.pid
    raw = Path(args.pid_file).read_text(encoding="ascii").strip()
    if not raw.isdigit():
        raise CollectionError("PID file does not contain one positive decimal PID")
    return int(raw)


def run_self_tests():
    epoch = 0x123456789ABCDEF
    values = [0] * 16
    packed = EVENT.pack(7, epoch, 1, 0, 99, *values, b"ping", b"", bytes(32))
    good = checksum(packed)
    assert validate_slot(7, epoch, 0, packed, good, 0) is None
    assert validate_slot(7, epoch, 6, packed, good, 6) is None
    assert validate_slot(
        7, epoch, SLOT_CLAIM | 7, packed, good, SLOT_CLAIM | 7) is None
    assert validate_slot(7, epoch, 7, packed, good, 7)[0] == 7
    for arguments, expected in (
        ((7, epoch, 7, packed, good ^ 1, 7), "checksum"),
        ((7, epoch + 1, 7, packed, good, 7), "epoch"),
        ((7, epoch, 7, packed, good, 8), "unstable"),
        ((6, epoch, 7, packed, good, 7), "gap"),
    ):
        try:
            validate_slot(*arguments)
        except CollectionError as error:
            assert expected in str(error)
        else:
            raise AssertionError(f"missing {expected} failure")
    # Circular indexing and a clean, consecutive final drain.
    assert ((CAPACITY + 1 - 1) & (CAPACITY - 1)) == 0
    drained = []
    for sequence in range(1, 5):
        record = EVENT.pack(sequence, epoch, 1, 0, sequence, *values,
                            b"ping", b"", bytes(32))
        drained.append(validate_slot(
            sequence, epoch, sequence, record, checksum(record), sequence)[0])
    assert drained == [1, 2, 3, 4]

    # Clock origins are immutable producer authority. Reject invalid origins
    # at collection time, rather than deferring the fault to offline analysis.
    valid_header = [
        MAGIC, SCHEMA, HEADER_SIZE, RECORD_SIZE, CAPACITY, ENDIAN,
        123, 0, epoch, 10, 20, 0, 0, 0, 0, 0, 0, 0, -1,
    ]
    for origin_index in (9, 10):
        invalid_header = list(valid_header)
        invalid_header[origin_index] = 0
        probe = ProbeStream.__new__(ProbeStream)
        probe.pid = 123
        probe.mapping = bytearray(HEADER.pack(*invalid_header))
        try:
            probe.read_header(initial=True)
        except CollectionError as error:
            assert "clock origin" in str(error)
        else:
            raise AssertionError("nonpositive probe clock origin was accepted")

    # Acknowledgement is sequenced strictly after flush and fsync, and a final
    # forced drain publishes every written record rather than only a read cursor.
    timeline = []

    class Output:
        def flush(self):
            timeline.append("flush")

        @staticmethod
        def fileno():
            return 123

    durable = DurableEventBatch(
        Output(),
        lambda sequence: timeline.append(("ack", sequence)),
        sync=lambda descriptor: timeline.append(("fsync", descriptor)))
    durable.note_written(1)
    durable.note_written(2)
    assert durable.durable_sequence == 0 and timeline == []
    assert durable.make_durable()
    assert timeline == ["flush", ("fsync", 123), ("ack", 2)]
    assert durable.durable_sequence == durable.pending_sequence == 2
    assert not durable.make_durable()
    durable.note_written(3)
    assert durable.durable_sequence == 2
    durable.make_durable()
    assert timeline[-3:] == ["flush", ("fsync", 123), ("ack", 3)]

    privacy_record = EVENT.pack(
        8, epoch, 4, 0, 100, 1, 2, 99, *([0] * 13),
        b"ping", b"pong", bytes(32))
    privacy_unpacked = EVENT.unpack(privacy_record)
    try:
        decoded_event(privacy_unpacked, OpaqueIds())
    except CollectionError as error:
        assert "reserved field" in str(error)
    else:
        raise AssertionError("response nonce-like reserved value was retained")

    # The wall-offset bridge reports, rather than rejects, a large origin
    # residual because it may reflect legitimate wall correction before attach.
    header = [0] * 19
    header[9], header[10] = 5_000_000_000, 1_000_000_000
    boundary = {
        "collector_wall_midpoint_ns": 15_000_000_000,
        "collector_monotonic_midpoint_ns": 2_000_000_000,
        "capture_uncertainty_ns": 17,
    }
    mapping = clock_mapping(header, boundary)
    assert mapping["origin_residual_ns"] == 9_000_000_000
    assert mapping["mapping_uncertainty_ns"] == 9_000_000_017
    assert mapping["compatibility"] == "wall_offset_bridge_with_reported_uncertainty"

    monotonic_reads = iter((100, 142))
    captured = capture_clock_pair(
        monotonic_clock=lambda: next(monotonic_reads), wall_clock=lambda: 1_000)
    assert captured == {
        "monotonic_ns": 121,
        "wall_ns": 1_000,
        "clock_capture_uncertainty_ns": 21,
    }

    rpc_results = {
        "getblockchaininfo": {
            "chain": "regtest", "blocks": 1, "headers": 1,
            "verificationprogress": 1.0, "initialblockdownload": False},
        "getnettotals": {
            "totalbytesrecv": 2, "totalbytessent": 3, "timemillis": 4},
        "getnetworkinfo": {
            "networkactive": True, "connections": 0,
            "connections_in": 0, "connections_out": 0},
        "getpeerinfo": [],
    }

    class Completed:
        def __init__(self, value):
            self.stdout = json.dumps(value)

    def fake_runner(arguments, **_kwargs):
        return Completed(rpc_results[arguments[-1]])

    rpc_success = run_rpc(
        "bitcoin-cli", [], "regtest", runner=fake_runner,
        clock_capture=lambda: captured)
    assert set(rpc_success) == {
        "monotonic_ns", "wall_ns", "clock_capture_uncertainty_ns", "chain",
        "warnings_present", "network_totals", "network", "peers"}
    rpc_failure = rpc_failure_row(
        subprocess.TimeoutExpired("bitcoin-cli", 30),
        clock_capture=lambda: captured)
    assert set(rpc_failure) == {
        "monotonic_ns", "wall_ns", "clock_capture_uncertainty_ns", "error"}
    assert rpc_failure["error"] == "TimeoutExpired"
    print("async_pnb_collector self-test: PASS")


def collect(args):
    if platform.system() != "Linux" or not Path("/proc").is_dir():
        raise CollectionError("collector requires Linux /proc")
    probe_dir = Path(args.probe_dir)
    output_dir = Path(args.output)
    if not probe_dir.is_absolute() or not output_dir.is_absolute():
        raise CollectionError("--probe-dir and --output must be absolute paths")
    if not probe_dir.is_dir() or probe_dir.is_symlink():
        raise CollectionError("--probe-dir must be a non-symlink directory")
    if output_dir.exists():
        raise CollectionError("--output must not already exist")
    pid = resolve_pid(args)
    if pid <= 0:
        raise CollectionError("PID must be positive")
    proc_dir = Path(f"/proc/{pid}")
    if not proc_dir.is_dir():
        raise CollectionError(f"PID {pid} is not running")
    initial_stat = read_proc_stat(pid)
    probe_path = probe_dir / f"async-pnb-probe-{pid}.bin"
    stream = ProbeStream(probe_path, pid)
    start_boundary = capture_probe_boundary(stream)
    mapping = clock_mapping(stream.header, start_boundary)
    try:
        binary_sha256 = sha256_file(args.binary) if args.binary else None
    except OSError as error:
        stream.close()
        raise CollectionError(f"cannot hash supplied binary: {error}") from error

    output_dir.mkdir(mode=0o700)
    events_path = output_dir / "events.jsonl"
    resources_path = output_dir / "resources.csv"
    rpc_path = output_dir / "rpc.jsonl"
    summary_path = output_dir / "summary.json"
    manifest_path = output_dir / "manifest.json"
    for path in (events_path, rpc_path):
        path.touch(mode=0o600)

    start_mono = start_boundary["collector_monotonic_midpoint_ns"]
    start_wall = start_boundary["collector_wall_midpoint_ns"]
    measured_sequence_first = start_boundary["producer_sequence"] + 1
    env = environment_identity()
    manifest = {
        "collector_schema": COLLECTOR_SCHEMA,
        "probe_schema": SCHEMA,
        "process_epochs": [stream.epoch],
        "pid": pid,
        "sanitized_invocation": {
            "program": Path(sys.argv[0]).name,
            "pid_source": "--pid" if args.pid is not None else "--pid-file",
            "probe_dir": "<absolute-probe-dir>",
            "output": "<absolute-output-dir>",
            "duration_seconds": args.duration,
            "bitcoin_cli": Path(args.bitcoin_cli).name if args.bitcoin_cli else None,
            "bitcoin_cli_arg_count": len(args.bitcoin_cli_arg),
        },
        "binary_sha256": binary_sha256,
        "mode": args.mode,
        "intervals_seconds": {
            "event_flush": args.event_flush_interval,
            "resource": args.resource_interval,
            "rpc": args.rpc_interval,
        },
        "durability": {
            "ack_policy": "events_jsonl_flush_fsync_then_probe_ack",
            "maximum_batch_seconds": args.event_flush_interval,
            "lag_pressure_sequences": args.max_probe_lag,
        },
        "expected_chain": args.expected_chain,
        "environment": env,
        "clock_origin": {"monotonic_ns": start_mono, "wall_ns": start_wall},
        "clock_mapping": mapping,
        "sample_clock_capture": {
            "method": "wall read bracketed by monotonic reads",
            "representative_monotonic": "midpoint=floor((before+after)/2)",
            "uncertainty": "ceil((monotonic_after-monotonic_before)/2)",
        },
        "collection_window": {
            "start": start_boundary,
            "sequence_first": measured_sequence_first,
        },
        "complete": False,
        "valid": False,
    }
    write_json(manifest_path, manifest)

    event_counts = Counter()
    event_scope_counts = Counter()
    integrity_errors = []
    rpc_failures = 0
    resource_samples = 0
    rpc_samples = 0
    rpc_rows = 0
    first_event = None
    last_event = None
    first_measured_event_mono = None
    last_measured_event_mono = None
    first_resource = None
    last_resource = None
    first_resource_wall = None
    last_resource_wall = None
    maximum_resource_clock_uncertainty = 0
    first_rpc = None
    last_rpc = None
    first_rpc_wall = None
    last_rpc_wall = None
    maximum_rpc_clock_uncertainty = 0
    process_exit_state = "running_at_collection_end"
    stop_reason = "duration_complete"
    signal_seen = {"number": None}

    def on_signal(number, _frame):
        signal_seen["number"] = number

    old_handlers = {
        number: signal.signal(number, on_signal)
        for number in (signal.SIGINT, signal.SIGTERM)
    }
    opaque = OpaqueIds()
    clock_ticks = env["clock_ticks_per_second"]
    page_size = env["page_size"]
    next_resource = start_mono
    next_rpc = start_mono
    deadline = start_mono + int(args.duration * 1_000_000_000)
    cutoff = None
    cutoff_boundary = None
    cutoff_deadline = None
    durability = None
    maximum_durable_lag = 0
    maximum_read_ahead = 0

    try:
        with events_path.open("a", encoding="utf-8", buffering=1024 * 1024) as events_file, \
             resources_path.open("w", encoding="utf-8", newline="") as resources_file, \
             rpc_path.open("a", encoding="utf-8", buffering=1) as rpc_file:
            resource_writer = csv.DictWriter(resources_file, fieldnames=RESOURCE_FIELDS)
            resource_writer.writeheader()
            resources_file.flush()
            os.fsync(resources_file.fileno())
            durability = DurableEventBatch(events_file, stream.acknowledge)
            last_event_flush = time.monotonic_ns()

            while True:
                now = time.monotonic_ns()
                if signal_seen["number"] is not None and cutoff is None:
                    stop_reason = f"signal_{signal_seen['number']}"
                    cutoff_boundary = capture_probe_boundary(stream)
                    cutoff = cutoff_boundary["producer_sequence"]
                    cutoff_deadline = now + 5_000_000_000
                elif now >= deadline and cutoff is None:
                    cutoff_boundary = capture_probe_boundary(stream)
                    cutoff = cutoff_boundary["producer_sequence"]
                    cutoff_deadline = now + 5_000_000_000

                try:
                    current_stat = read_proc_stat(pid)
                    if current_stat["start_ticks"] != initial_stat["start_ticks"]:
                        raise CollectionError("PID was reused during collection")
                except FileNotFoundError:
                    if process_exit_state == "running_at_collection_end":
                        process_exit_state = "exited_during_collection"
                        if cutoff is None:
                            cutoff_boundary = capture_probe_boundary(stream)
                            cutoff = cutoff_boundary["producer_sequence"]
                            cutoff_deadline = now + 5_000_000_000

                header = stream.read_header()
                producer = header[11]
                durable = durability.durable_sequence
                maximum_durable_lag = max(maximum_durable_lag, producer - durable)
                if (durability.pending_sequence > durable and
                        producer - durable >= args.max_probe_lag):
                    durability.make_durable()
                    last_event_flush = time.monotonic_ns()
                target = min(producer, cutoff) if cutoff is not None else producer
                pending = []
                while stream.expected <= target:
                    event = stream.read_one(stream.expected)
                    if event is None:
                        break
                    decoded = decoded_event(event, opaque)
                    decoded["mapped_monotonic_ns"] = (
                        decoded["steady_ns"] +
                        mapping["steady_to_collector_monotonic_offset_ns"])
                    decoded["mapped_wall_ns"] = (
                        decoded["steady_ns"] +
                        mapping["steady_to_wall_offset_ns"])
                    decoded["collection_scope"] = (
                        "pre_attach_backlog"
                        if decoded["sequence"] < measured_sequence_first
                        else "measured")
                    pending.append(decoded)
                    stream.expected += 1
                if pending:
                    for event in pending:
                        events_file.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
                        event_counts[event["event"]] += 1
                        event_scope_counts[event["collection_scope"]] += 1
                        first_event = (event["steady_ns"] if first_event is None else
                                       min(first_event, event["steady_ns"]))
                        last_event = (event["steady_ns"] if last_event is None else
                                      max(last_event, event["steady_ns"]))
                        if event["collection_scope"] == "measured":
                            mapped_mono = event["mapped_monotonic_ns"]
                            first_measured_event_mono = (
                                mapped_mono if first_measured_event_mono is None else
                                min(first_measured_event_mono, mapped_mono))
                            last_measured_event_mono = (
                                mapped_mono if last_measured_event_mono is None else
                                max(last_measured_event_mono, mapped_mono))
                        durability.note_written(event["sequence"])

                read_sequence = stream.expected - 1
                maximum_read_ahead = max(
                    maximum_read_ahead,
                    read_sequence - durability.durable_sequence)
                now = time.monotonic_ns()
                force_for_lag = (
                    durability.pending_sequence > durability.durable_sequence and
                    producer - durability.durable_sequence >= args.max_probe_lag)
                interval_elapsed = (
                    durability.pending_sequence > durability.durable_sequence and
                    now - last_event_flush >=
                    int(args.event_flush_interval * 1_000_000_000))
                final_drain = (
                    cutoff is not None and read_sequence >= cutoff and
                    durability.pending_sequence > durability.durable_sequence)
                if force_for_lag or interval_elapsed or final_drain:
                    durability.make_durable()
                    last_event_flush = time.monotonic_ns()
                if producer - durability.durable_sequence > args.max_probe_lag:
                    raise CollectionError(
                        f"configured maximum durable probe lag exceeded: "
                        f"{producer - durability.durable_sequence} > {args.max_probe_lag}")

                now = time.monotonic_ns()
                if cutoff is None and now >= next_resource:
                    if process_exit_state == "running_at_collection_end":
                        sample = sample_resources(pid, clock_ticks, page_size)
                        resource_writer.writerow(sample)
                        resources_file.flush()
                        resource_samples += 1
                        first_resource = sample["monotonic_ns"] if first_resource is None else first_resource
                        last_resource = sample["monotonic_ns"]
                        first_resource_wall = (
                            sample["wall_ns"] if first_resource_wall is None
                            else first_resource_wall)
                        last_resource_wall = sample["wall_ns"]
                        maximum_resource_clock_uncertainty = max(
                            maximum_resource_clock_uncertainty,
                            sample["clock_capture_uncertainty_ns"])
                        if args.max_rss_mib is not None and sample["rss_bytes"] > args.max_rss_mib * 1024 * 1024:
                            raise CollectionError(
                                f"RSS abort threshold exceeded: {sample['rss_bytes']} bytes")
                    if args.min_output_free_mib is not None:
                        free = shutil.disk_usage(output_dir).free
                        if free < args.min_output_free_mib * 1024 * 1024:
                            raise CollectionError(
                                f"output free-space abort threshold crossed: {free} bytes")
                    next_resource = time.monotonic_ns() + int(
                        args.resource_interval * 1_000_000_000)

                if (cutoff is None and now >= next_rpc and
                        process_exit_state == "running_at_collection_end"):
                    try:
                        snapshot = run_rpc(
                            args.bitcoin_cli, args.bitcoin_cli_arg, args.expected_chain)
                        rpc_file.write(json.dumps(
                            snapshot, sort_keys=True, separators=(",", ":")) + "\n")
                        rpc_file.flush()
                        rpc_samples += 1
                        rpc_rows += 1
                        first_rpc = snapshot["monotonic_ns"] if first_rpc is None else first_rpc
                        last_rpc = snapshot["monotonic_ns"]
                        first_rpc_wall = (
                            snapshot["wall_ns"] if first_rpc_wall is None
                            else first_rpc_wall)
                        last_rpc_wall = snapshot["wall_ns"]
                        maximum_rpc_clock_uncertainty = max(
                            maximum_rpc_clock_uncertainty,
                            snapshot["clock_capture_uncertainty_ns"])
                    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as error:
                        rpc_failures += 1
                        failure = rpc_failure_row(error)
                        rpc_file.write(json.dumps(
                            failure, sort_keys=True, separators=(",", ":")) + "\n")
                        rpc_file.flush()
                        rpc_rows += 1
                        first_rpc = failure["monotonic_ns"] if first_rpc is None else first_rpc
                        last_rpc = failure["monotonic_ns"]
                        first_rpc_wall = (
                            failure["wall_ns"] if first_rpc_wall is None
                            else first_rpc_wall)
                        last_rpc_wall = failure["wall_ns"]
                        maximum_rpc_clock_uncertainty = max(
                            maximum_rpc_clock_uncertainty,
                            failure["clock_capture_uncertainty_ns"])
                    next_rpc = time.monotonic_ns() + int(
                        args.rpc_interval * 1_000_000_000)

                if (cutoff is not None and stream.expected > cutoff and
                        durability.durable_sequence >= cutoff):
                    # All reservations at the collection boundary are durable and acknowledged.
                    break
                if cutoff_deadline is not None and now >= cutoff_deadline:
                    raise CollectionError(
                        f"final drain timed out at sequence {stream.expected} of {cutoff}")
                time.sleep(0.002)

            resources_file.flush()
            os.fsync(resources_file.fileno())
            rpc_file.flush()
            os.fsync(rpc_file.fileno())
    except (CollectionError, OSError, UnicodeError, ValueError) as error:
        integrity_errors.append(str(error))
        stop_reason = "invalid_abort"
    finally:
        for number, handler in old_handlers.items():
            signal.signal(number, handler)
        if cutoff_boundary is None:
            try:
                cutoff_boundary = capture_probe_boundary(stream)
                cutoff = cutoff_boundary["producer_sequence"]
            except (CollectionError, OSError) as error:
                integrity_errors.append(str(error))
        try:
            final_header = stream.read_header()
        except (CollectionError, OSError) as error:
            integrity_errors.append(str(error))
            final_header = stream.header
        if cutoff_boundary is None:
            end_mono = time.monotonic_ns()
            end_wall = time.time_ns()
            cutoff = final_header[11] if cutoff is None else cutoff
            cutoff_boundary = {
                "producer_sequence": cutoff,
                "collector_monotonic_before_ns": end_mono,
                "collector_monotonic_after_ns": end_mono,
                "collector_monotonic_midpoint_ns": end_mono,
                "collector_wall_before_ns": end_wall,
                "collector_wall_after_ns": end_wall,
                "collector_wall_midpoint_ns": end_wall,
                "capture_uncertainty_ns": 0,
            }
        end_mapping = clock_mapping(final_header, cutoff_boundary)
        monotonic_elapsed_ns = (
            cutoff_boundary["collector_monotonic_midpoint_ns"] - start_mono)
        wall_elapsed_ns = (
            cutoff_boundary["collector_wall_midpoint_ns"] - start_wall)
        clock_drift_ns = wall_elapsed_ns - monotonic_elapsed_ns
        mapping["collection_wall_minus_monotonic_drift_ns"] = clock_drift_ns
        mapping["cutoff_capture_uncertainty_ns"] = (
            cutoff_boundary["capture_uncertainty_ns"])
        mapping["mapping_uncertainty_ns"] += (
            abs(clock_drift_ns) + cutoff_boundary["capture_uncertainty_ns"])
        end_mapping["collection_wall_minus_monotonic_drift_ns"] = clock_drift_ns
        if wall_elapsed_ns <= 0:
            integrity_errors.append("collector wall clock did not advance across collection")
        if final_header[7] & STATUS_CLOSED:
            process_exit_state = "closed_and_drained" if stream.expected > final_header[11] else "closed_not_drained"
            if stream.expected <= final_header[11]:
                integrity_errors.append("closed stream was not fully drained")
        if signal_seen["number"] is not None:
            integrity_errors.append("collection interrupted by signal")
        if rpc_samples == 0:
            integrity_errors.append("no valid bitcoin-cli RPC snapshot was collected")
        event_count = sum(event_counts.values())
        durable_sequence = durability.durable_sequence if durability else 0
        pending_sequence = durability.pending_sequence if durability else 0
        duration_ns = (
            cutoff_boundary["collector_monotonic_midpoint_ns"] - start_mono)
        if duration_ns <= 0:
            integrity_errors.append("nonpositive collector monotonic observation duration")
        expected_backlog = min(start_boundary["producer_sequence"], cutoff)
        expected_measured = max(0, cutoff - measured_sequence_first + 1)
        if event_scope_counts["pre_attach_backlog"] != expected_backlog:
            integrity_errors.append("pre-attach backlog event count mismatch")
        if event_scope_counts["measured"] != expected_measured:
            integrity_errors.append("measured-window event count mismatch")
        if event_count != cutoff or pending_sequence != cutoff or durable_sequence != cutoff:
            integrity_errors.append("full event stream was not durable through collection cutoff")
        if final_header[12] != durable_sequence:
            integrity_errors.append("probe acknowledgement disagrees with durable sequence")
        clock_slack = mapping["mapping_uncertainty_ns"]
        if (first_measured_event_mono is not None and
                first_measured_event_mono < start_mono - clock_slack):
            integrity_errors.append("measured event precedes mapped collection start")
        if (last_measured_event_mono is not None and
                last_measured_event_mono >
                cutoff_boundary["collector_monotonic_midpoint_ns"] + clock_slack):
            integrity_errors.append("measured event follows mapped collection cutoff")
        collection_window = {
            "sequence_first": measured_sequence_first,
            "sequence_last": cutoff,
            "pre_attach_sequence_last": start_boundary["producer_sequence"],
            "start": start_boundary,
            "end": cutoff_boundary,
            "duration_ns": duration_ns,
            "duration_source": "collector_python_monotonic_midpoints",
            "pre_attach_backlog_event_count": event_scope_counts["pre_attach_backlog"],
            "measured_event_count": event_scope_counts["measured"],
            "measured_event_mapped_monotonic_bounds_ns": [
                first_measured_event_mono, last_measured_event_mono],
        }
        data_artifacts = {
            "events.jsonl": artifact_facts(events_path),
            "resources.csv": artifact_facts(resources_path, csv_header=True),
            "rpc.jsonl": artifact_facts(rpc_path),
        }
        if data_artifacts["events.jsonl"]["data_rows"] != event_count:
            integrity_errors.append("events.jsonl row count changed before finalization")
        if data_artifacts["resources.csv"]["data_rows"] != resource_samples:
            integrity_errors.append("resources.csv row count changed before finalization")
        if data_artifacts["rpc.jsonl"]["data_rows"] != rpc_rows:
            integrity_errors.append("rpc.jsonl row count changed before finalization")
        summary = {
            "complete": True,
            "valid": not integrity_errors,
            "stop_reason": stop_reason,
            "process_exit_state": process_exit_state,
            "process_epoch": stream.epoch,
            "event_counts": dict(sorted(event_counts.items())),
            "event_scope_counts": dict(sorted(event_scope_counts.items())),
            "event_count": event_count,
            "event_sequence_first": 1 if event_count else None,
            "event_sequence_last": durable_sequence if event_count else None,
            "event_sequence_read_last": pending_sequence if event_count else None,
            "event_sequence_durable_last": durable_sequence if event_count else None,
            "durable_flushes": durability.flushes if durability else 0,
            "maximum_durable_lag": maximum_durable_lag,
            "maximum_read_ahead": maximum_read_ahead,
            "producer_sequence_observed": final_header[11],
            "collection_cutoff_sequence": cutoff,
            "collection_window": collection_window,
            "clock_mapping": mapping,
            "cutoff_clock_mapping": end_mapping,
            "consumer_ack": final_header[12],
            "loss_count": final_header[13],
            "probe_status": final_header[7],
            "integrity_errors": integrity_errors,
            "checksum_failures": sum("checksum" in error for error in integrity_errors),
            "unstable_read_failures": sum("unstable" in error for error in integrity_errors),
            "sequence_failures": sum(
                "sequence" in error or "overwrite" in error or "lag" in error
                for error in integrity_errors),
            "event_steady_bounds_ns": [first_event, last_event],
            "resource_samples": resource_samples,
            "resource_monotonic_bounds_ns": [first_resource, last_resource],
            "resource_wall_bounds_ns": [first_resource_wall, last_resource_wall],
            "resource_clock_capture_uncertainty_max_ns":
                maximum_resource_clock_uncertainty,
            "rpc_samples": rpc_samples,
            "rpc_rows": rpc_rows,
            "rpc_monotonic_bounds_ns": [first_rpc, last_rpc],
            "rpc_wall_bounds_ns": [first_rpc_wall, last_rpc_wall],
            "rpc_clock_capture_uncertainty_max_ns": maximum_rpc_clock_uncertainty,
            "rpc_failures": rpc_failures,
            "artifact_integrity": data_artifacts,
            "unavailable": [
                "peer_response_receive", "peer_rtt", "remote_processing"],
        }
        write_json(summary_path, summary)
        manifest_artifacts = {
            **data_artifacts,
            "summary.json": artifact_facts(summary_path),
        }
        manifest.update({
            "complete": True,
            "valid": summary["valid"],
            "stop_reason": stop_reason,
            "end_clock": {
                "monotonic_ns": cutoff_boundary["collector_monotonic_midpoint_ns"],
                "wall_ns": cutoff_boundary["collector_wall_midpoint_ns"]},
            "clock_mapping": mapping,
            "cutoff_clock_mapping": end_mapping,
            "collection_window": collection_window,
            "sample_clock_capture": {
                **manifest["sample_clock_capture"],
                "max_uncertainty_ns": {
                    "resources.csv": maximum_resource_clock_uncertainty,
                    "rpc.jsonl": maximum_rpc_clock_uncertainty,
                },
            },
            "artifacts": manifest_artifacts,
            "event_stream": {
                "process_epoch": stream.epoch,
                "count": event_count,
                "sequence_first": summary["event_sequence_first"],
                "sequence_last": summary["event_sequence_last"],
                "durable_sequence": durable_sequence,
                "event_counts": summary["event_counts"],
            },
        })
        write_json(manifest_path, manifest)
        stream.close()
    if integrity_errors:
        raise CollectionError("; ".join(integrity_errors))


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--pid", type=int)
    source.add_argument("--pid-file")
    parser.add_argument("--probe-dir")
    parser.add_argument("--output")
    parser.add_argument("--duration", type=float)
    parser.add_argument("--resource-interval", type=float, default=1.0)
    parser.add_argument("--rpc-interval", type=float, default=5.0)
    parser.add_argument("--event-flush-interval", type=float, default=0.05)
    parser.add_argument("--expected-chain", choices=("main", "test", "signet", "regtest"))
    parser.add_argument("--mode", choices=("control", "candidate"))
    parser.add_argument("--max-probe-lag", type=int, default=CAPACITY - 1024)
    parser.add_argument("--max-rss-mib", type=float)
    parser.add_argument("--min-output-free-mib", type=float)
    parser.add_argument("--bitcoin-cli")
    parser.add_argument("--bitcoin-cli-arg", action="append", default=[])
    parser.add_argument("--binary")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return args
    if (args.pid is None) == (args.pid_file is None):
        parser.error("exactly one of --pid and --pid-file is required")
    for name in ("probe_dir", "output", "duration", "expected_chain", "mode"):
        if getattr(args, name) is None:
            parser.error(f"--{name.replace('_', '-')} is required")
    if not args.bitcoin_cli:
        parser.error("--bitcoin-cli is required for expected-chain verification")
    for name in ("duration", "resource_interval", "rpc_interval", "event_flush_interval"):
        if not math.isfinite(getattr(args, name)) or getattr(args, name) <= 0:
            parser.error(f"--{name.replace('_', '-')} must be positive")
    if not 0 < args.max_probe_lag < CAPACITY:
        parser.error(f"--max-probe-lag must be between 1 and {CAPACITY - 1}")
    for name in ("max_rss_mib", "min_output_free_mib"):
        if getattr(args, name) is not None and getattr(args, name) <= 0:
            parser.error(f"--{name.replace('_', '-')} must be positive")
    return args


def main():
    args = parse_args()
    if args.self_test:
        run_self_tests()
        return
    try:
        collect(args)
    except CollectionError as error:
        print(f"async_pnb_collector: {error}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
