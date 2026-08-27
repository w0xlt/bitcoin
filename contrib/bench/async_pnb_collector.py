#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Collect the fixed async-PNB mmap stream without controlling bitcoind."""

import argparse
import csv
import hashlib
import json
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
HEADER_SIZE = 128
RECORD_SIZE = 256
CAPACITY = 65_536
ENDIAN = 0x01020304
STATUS_TEST_GATES = 1
STATUS_LOSS = 2
STATUS_CLOSED = 4
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
    "monotonic_ns", "wall_ns", "process_user_seconds", "process_system_seconds",
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
        if not initial and header[8] != self.epoch:
            raise CollectionError(
                f"process epoch changed: expected {self.epoch}, got {header[8]}")
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
        "monotonic_ns": time.monotonic_ns(),
        "wall_ns": time.time_ns(),
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


def run_rpc(cli, cli_args, expected_chain):
    def call(method):
        completed = subprocess.run(
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
        "monotonic_ns": time.monotonic_ns(),
        "wall_ns": time.time_ns(),
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


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                return digest.hexdigest()
            digest.update(chunk)


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

    start_mono = time.monotonic_ns()
    start_wall = time.time_ns()
    env = environment_identity()
    manifest = {
        "collector_schema": 1,
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
            "resource": args.resource_interval,
            "rpc": args.rpc_interval if args.bitcoin_cli else None,
        },
        "expected_chain": args.expected_chain,
        "environment": env,
        "clock_origin": {"monotonic_ns": start_mono, "wall_ns": start_wall},
        "complete": False,
        "valid": False,
    }
    write_json(manifest_path, manifest)

    event_counts = Counter()
    integrity_errors = []
    rpc_failures = 0
    resource_samples = 0
    rpc_samples = 0
    first_event = None
    last_event = None
    first_resource = None
    last_resource = None
    first_rpc = None
    last_rpc = None
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
    cutoff_deadline = None

    try:
        with events_path.open("a", encoding="utf-8", buffering=1) as events_file, \
             resources_path.open("w", encoding="utf-8", newline="") as resources_file, \
             rpc_path.open("a", encoding="utf-8", buffering=1) as rpc_file:
            resource_writer = csv.DictWriter(resources_file, fieldnames=RESOURCE_FIELDS)
            resource_writer.writeheader()
            resources_file.flush()
            os.fsync(resources_file.fileno())

            while True:
                now = time.monotonic_ns()
                if signal_seen["number"] is not None and cutoff is None:
                    stop_reason = f"signal_{signal_seen['number']}"
                    cutoff = stream.read_header()[11]
                    cutoff_deadline = now + 5_000_000_000
                elif now >= deadline and cutoff is None:
                    cutoff = stream.read_header()[11]
                    cutoff_deadline = now + 5_000_000_000

                try:
                    current_stat = read_proc_stat(pid)
                    if current_stat["start_ticks"] != initial_stat["start_ticks"]:
                        raise CollectionError("PID was reused during collection")
                except FileNotFoundError:
                    if process_exit_state == "running_at_collection_end":
                        process_exit_state = "exited_during_collection"
                        cutoff = stream.read_header()[11]
                        cutoff_deadline = now + 5_000_000_000

                header = stream.read_header()
                producer = header[11]
                durable = stream.expected - 1
                if producer - durable > args.max_probe_lag:
                    raise CollectionError(
                        f"configured maximum probe lag exceeded: {producer - durable} > "
                        f"{args.max_probe_lag}")
                target = min(producer, cutoff) if cutoff is not None else producer
                pending = []
                while stream.expected <= target:
                    event = stream.read_one(stream.expected)
                    if event is None:
                        break
                    pending.append(decoded_event(event, opaque))
                    stream.expected += 1
                if pending:
                    for event in pending:
                        events_file.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
                        event_counts[event["event"]] += 1
                        first_event = event["steady_ns"] if first_event is None else first_event
                        last_event = event["steady_ns"]
                    events_file.flush()
                    os.fsync(events_file.fileno())
                    stream.acknowledge(stream.expected - 1)

                now = time.monotonic_ns()
                if now >= next_resource and process_exit_state == "running_at_collection_end":
                    sample = sample_resources(pid, clock_ticks, page_size)
                    resource_writer.writerow(sample)
                    resources_file.flush()
                    resource_samples += 1
                    first_resource = sample["monotonic_ns"] if first_resource is None else first_resource
                    last_resource = sample["monotonic_ns"]
                    if args.max_rss_mib is not None and sample["rss_bytes"] > args.max_rss_mib * 1024 * 1024:
                        raise CollectionError(
                            f"RSS abort threshold exceeded: {sample['rss_bytes']} bytes")
                    next_resource = time.monotonic_ns() + int(
                        args.resource_interval * 1_000_000_000)

                if args.min_output_free_mib is not None:
                    free = shutil.disk_usage(output_dir).free
                    if free < args.min_output_free_mib * 1024 * 1024:
                        raise CollectionError(
                            f"output free-space abort threshold crossed: {free} bytes")

                if (args.bitcoin_cli and now >= next_rpc and
                        process_exit_state == "running_at_collection_end"):
                    try:
                        snapshot = run_rpc(
                            args.bitcoin_cli, args.bitcoin_cli_arg, args.expected_chain)
                        rpc_file.write(json.dumps(
                            snapshot, sort_keys=True, separators=(",", ":")) + "\n")
                        rpc_file.flush()
                        rpc_samples += 1
                        first_rpc = snapshot["monotonic_ns"] if first_rpc is None else first_rpc
                        last_rpc = snapshot["monotonic_ns"]
                    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as error:
                        rpc_failures += 1
                        rpc_file.write(json.dumps({
                            "monotonic_ns": time.monotonic_ns(),
                            "wall_ns": time.time_ns(),
                            "error": type(error).__name__,
                        }, sort_keys=True, separators=(",", ":")) + "\n")
                        rpc_file.flush()
                    next_rpc = time.monotonic_ns() + int(
                        args.rpc_interval * 1_000_000_000)

                if cutoff is not None and stream.expected > cutoff:
                    # All reservations at the collection boundary are durable.
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
        try:
            final_header = stream.read_header()
        except (CollectionError, OSError) as error:
            integrity_errors.append(str(error))
            final_header = stream.header
        if final_header[7] & STATUS_CLOSED:
            process_exit_state = "closed_and_drained" if stream.expected > final_header[11] else "closed_not_drained"
            if stream.expected <= final_header[11]:
                integrity_errors.append("closed stream was not fully drained")
        if signal_seen["number"] is not None:
            integrity_errors.append("collection interrupted by signal")
        if args.bitcoin_cli and rpc_samples == 0:
            integrity_errors.append("bitcoin-cli was supplied but no valid RPC snapshot was collected")
        summary = {
            "complete": True,
            "valid": not integrity_errors,
            "stop_reason": stop_reason,
            "process_exit_state": process_exit_state,
            "process_epoch": stream.epoch,
            "event_counts": dict(sorted(event_counts.items())),
            "event_sequence_first": 1 if event_counts else None,
            "event_sequence_last": stream.expected - 1 if event_counts else None,
            "producer_sequence_observed": final_header[11],
            "collection_cutoff_sequence": cutoff,
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
            "rpc_samples": rpc_samples,
            "rpc_monotonic_bounds_ns": [first_rpc, last_rpc],
            "rpc_failures": rpc_failures,
            "unavailable": (["rpc_state", "network_byte_deltas", "ibd_state_joins"]
                            if not args.bitcoin_cli else []) + [
                "peer_response_receive", "peer_rtt", "remote_processing"],
        }
        write_json(summary_path, summary)
        manifest.update({
            "complete": True,
            "valid": summary["valid"],
            "stop_reason": stop_reason,
            "end_clock": {"monotonic_ns": time.monotonic_ns(), "wall_ns": time.time_ns()},
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
    for name in ("duration", "resource_interval", "rpc_interval"):
        if getattr(args, name) <= 0:
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
