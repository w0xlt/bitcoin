#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Functional smoke and local async-PNB peer-service measurement harness."""

import csv
import hashlib
import json
import mmap
import os
import platform
import random
import shutil
import struct
import subprocess
import sys
import threading
import time
from decimal import Decimal
from pathlib import Path

from test_framework.blocktools import (
    NORMAL_GBT_REQUEST_PARAMS,
    add_witness_commitment,
    create_block,
    create_coinbase,
    get_legacy_sigopcount_block,
)
from test_framework.messages import (
    COIN,
    MAX_BLOCK_SIGOPS_COST,
    MAX_BLOCK_WEIGHT,
    MSG_BLOCK,
    MSG_CMPCT_BLOCK,
    MSG_TX,
    MSG_TYPE_MASK,
    WITNESS_SCALE_FACTOR,
    BlockTransactions,
    BlockTransactionsRequest,
    CBlockHeader,
    CBlockLocator,
    CInv,
    HeaderAndShortIDs,
    calculate_shortid,
    msg_block,
    msg_blocktxn,
    msg_cmpctblock,
    msg_getaddr,
    msg_getblocktxn,
    msg_getdata,
    msg_getheaders,
    msg_generic,
    msg_headers,
    msg_ping,
    msg_sendaddrv2,
    msg_sendcmpct,
    msg_verack,
    msg_version,
    msg_wtxidrelay,
)
from test_framework.p2p import (
    MIN_P2P_VERSION_SUPPORTED,
    P2PInterface,
    P2P_SERVICES,
    P2P_SUBVERSION,
    P2P_VERSION,
    p2p_lock,
)
from test_framework.script import CScript
from test_framework.test_framework import BitcoinTestFramework
from test_framework.wallet import MiniWallet, MiniWalletMode


MARKER_PREFIX = "ASYNC_PNB_PEER_SERVICE "
TARGET_WEIGHT = 3_900_000
GENERATED_CHAIN_TXS = 5_803
INCLUDED_CHAIN_TXS = 5_802
EXPECTED_BLOCK_WEIGHT = 3_899_532
EXPECTED_BLOCK_BYTES = 974_883
EXPECTED_LEGACY_SIGOPS = 5_802
PING_TIMEOUT = 60
MARKER_POLL = 0.002

PROBE_MAGIC = b"APNBPRB\0"
PROBE_SCHEMA = 2
PROBE_HEADER_SIZE = 64
PROBE_RECORD_SIZE = 256
PROBE_CAPACITY = 65_536
PROBE_ENDIAN = 0x01020304
PROBE_STATUS_TEST_GATES = 1
PROBE_STATUS_OVERFLOW = 2
PROBE_HEADER = struct.Struct("<8s6IQ5Ii")
PROBE_EVENT = struct.Struct("<QIIq16q24s24s32s")
PROBE_EVENTS = {
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
}
PROBE_GATES = {
    "none": 0,
    "worker_queued": 1,
    "validation_running": 2,
    "result_ready": 3,
    "handler_pre_poll": 4,
}


class ProbeSliceReader:
    """Minimal fixed-ABI reader used as the base of MarkerReader below."""

    def __init__(self, path, *, expect_test_gates):
        unresolved = Path(path)
        assert unresolved.is_file() and not unresolved.is_symlink()
        self.path = unresolved.resolve()
        expected_size = PROBE_HEADER_SIZE + PROBE_CAPACITY * PROBE_RECORD_SIZE
        assert self.path.stat().st_size == expected_size
        flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        self.fd = os.open(self.path, flags)
        self.mapping = mmap.mmap(self.fd, 0, access=mmap.ACCESS_WRITE)
        self.expect_test_gates = expect_test_gates
        self.header = self.read_header()

    def read_header(self):
        header = PROBE_HEADER.unpack_from(self.mapping, 0)
        assert header[:6] == (
            PROBE_MAGIC, PROBE_SCHEMA, PROBE_HEADER_SIZE,
            PROBE_RECORD_SIZE, PROBE_CAPACITY, PROBE_ENDIAN)
        status = header[6]
        assert status & ~(PROBE_STATUS_TEST_GATES | PROBE_STATUS_OVERFLOW) == 0
        assert bool(status & PROBE_STATUS_TEST_GATES) == self.expect_test_gates
        if status & PROBE_STATUS_OVERFLOW or header[8]:
            raise AssertionError(
                f"async-PNB probe overflow: {self.path} count={header[8]}")
        if header[7] > PROBE_CAPACITY:
            raise AssertionError(
                f"async-PNB probe capacity exceeded: {self.path} "
                f"next={header[7]} capacity={PROBE_CAPACITY}")
        if header[12]:
            raise AssertionError(
                f"async-PNB test gate timeout: {self.path} generation={header[12]}")
        self.header = header
        self.next_sequence = header[7]
        return header

    @staticmethod
    def checksum(record):
        result = 1_469_598_103_934_665_603
        for byte in record:
            result ^= byte
            result = (result * 1_099_511_628_211) & 0xffffffffffffffff
        return result

    def read_event(self, sequence):
        self.read_header()
        assert 1 <= sequence <= self.next_sequence
        offset = PROBE_HEADER_SIZE + (sequence - 1) * PROBE_RECORD_SIZE
        published_before = struct.unpack_from("<Q", self.mapping, offset)[0]
        if published_before == 0:
            return None
        assert published_before == sequence
        record = self.mapping[offset + 8:offset + 8 + PROBE_EVENT.size]
        checksum = struct.unpack_from("<Q", self.mapping, offset + 240)[0]
        published_after = struct.unpack_from("<Q", self.mapping, offset)[0]
        if published_before != published_after:
            raise AssertionError(
                f"async-PNB probe unstable publication: {self.path} "
                f"sequence={sequence} before={published_before} after={published_after}")
        if checksum != self.checksum(record):
            raise AssertionError(
                f"async-PNB probe checksum mismatch: {self.path} sequence={sequence}")
        return PROBE_EVENT.unpack(record)

    def close(self):
        self.mapping.close()
        os.close(self.fd)

PROFILES = {
    # One warmup and one retained isolated trial for every fixed class.
    "smoke": {"isolated_warmups": 1, "isolated_trials": 1, "mixed_trials": 0},
    # The paired AB/BA screening count from the fast plan.
    "curve": {"isolated_warmups": 0, "isolated_trials": 3, "mixed_trials": 0},
    # Six retained fixed-class mixed FIFO trials per arm.
    "mixed": {"isolated_warmups": 0, "isolated_trials": 0, "mixed_trials": 6},
    # The optional broad confirmation plus its fixed mixed screen.
    "default": {"isolated_warmups": 2, "isolated_trials": 20, "mixed_trials": 6},
}

SERVICE_CLASSES = ("ping", "version", "getaddr", "getblocktxn", "getheaders", "getdata")


class PeerServicePeer(P2PInterface):
    def __init__(self):
        super().__init__()
        self.block_requests = []
        self.block_request_types = []
        self.blocktxn_requests = []
        self.pong_nonces = []
        self.service_request = None

    def on_getdata(self, message):
        for inv in message.inv:
            if (inv.type & MSG_TYPE_MASK) in {MSG_BLOCK, MSG_CMPCT_BLOCK}:
                self.block_requests.append(inv.hash)
                self.block_request_types.append((inv.hash, inv.type & MSG_TYPE_MASK))

    def on_inv(self, message):
        pass

    def on_getblocktxn(self, message):
        self.blocktxn_requests.append(message.block_txn_request)

    def _record_service_response(self, response_type, message):
        request = self.service_request
        if request is None or response_type not in request["expected_types"]:
            return
        if response_type == "pong" and message.nonce != request.get("nonce"):
            return
        serialized = message.serialize()
        request["responses"].append({
            "message": message,
            "received_ns": time.perf_counter_ns(),
            "response_bytes": len(serialized),
            "response_sha256": hashlib.sha256(serialized).hexdigest(),
            "type": response_type,
        })
        received_types = {entry["type"] for entry in request["responses"]}
        if set(request["expected_types"]).issubset(received_types):
            request["event"].set()

    def on_version(self, message):
        self._record_service_response("version", message)
        assert message.nVersion >= MIN_P2P_VERSION_SUPPORTED
        if not self.p2p_connected_to_node:
            self.send_version()
            self.reconnect = False
        if message.nVersion >= 70016 and self.wtxidrelay:
            self.send_without_ping(msg_wtxidrelay())
        if self.support_addrv2:
            self.send_without_ping(msg_sendaddrv2())
        self.send_without_ping(msg_verack())
        self.nServices = message.nServices
        self.relay = message.relay

    def on_verack(self, message):
        self._record_service_response("verack", message)

    def on_addr(self, message):
        self._record_service_response("addr", message)

    def on_addrv2(self, message):
        self._record_service_response("addrv2", message)

    def on_blocktxn(self, message):
        self._record_service_response("blocktxn", message)

    def on_headers(self, message):
        self._record_service_response("headers", message)

    def on_notfound(self, message):
        self._record_service_response("notfound", message)

    def on_pong(self, message):
        self.pong_nonces.append(message.nonce)
        self._record_service_response("pong", message)

    def wait_for_block_request(self, block_hash):
        self.wait_until(lambda: self.block_requests.count(block_hash) >= 1, timeout=PING_TIMEOUT)
        assert self.block_requests.count(block_hash) == 1

    def begin_service_request(self, service, message, expected_types, nonce=None):
        with p2p_lock:
            assert self.is_connected
            assert self.service_request is None
            self.service_request = {
                "event": threading.Event(),
                "expected_types": tuple(expected_types),
                "nonce": nonce,
                "request_sent_ns": time.perf_counter_ns(),
                "responses": [],
                "service": service,
            }
            self.send_without_ping(message)

    def finish_service_request(self, timeout=PING_TIMEOUT):
        with p2p_lock:
            request = self.service_request
            assert request is not None
        completed = request["event"].wait(max(0, timeout) * self.timeout_factor)
        with p2p_lock:
            responses = list(request["responses"])
            connected = self.is_connected
            self.service_request = None
        return {
            "completed": completed,
            "connected": connected,
            "request_sent_ns": request["request_sent_ns"],
            "responses": responses,
            "service": request["service"],
        }


class MarkerReader:
    def __init__(self, directory, timeout_factor, *, expect_test_gates):
        unresolved = Path(directory)
        assert unresolved.is_dir() and not unresolved.is_symlink()
        self.directory = unresolved.resolve()
        self.events = []
        self.files = []
        self.file_paths = set()
        self.timeout = PING_TIMEOUT * timeout_factor
        self.expect_test_gates = expect_test_gates
        self.unstable_reads = 0
        self._discover()

    @staticmethod
    def _decode_text(value):
        return value.split(b"\0", 1)[0].decode("ascii", errors="strict")

    def _discover(self):
        candidates = []
        for unresolved in self.directory.glob("async-pnb-probe-*.bin"):
            assert unresolved.parent == self.directory and not unresolved.is_symlink()
            path = unresolved.resolve()
            if path in self.file_paths:
                continue
            suffix = path.name.removeprefix("async-pnb-probe-").removesuffix(".bin")
            assert suffix.isdigit(), path
            candidates.append((path.stat().st_mtime_ns, int(suffix), path))
        for _mtime, pid, path in sorted(candidates):
            reader = ProbeSliceReader(path, expect_test_gates=self.expect_test_gates)
            self.files.append({
                "event_count": 0,
                "expected_sequence": 1,
                "pid": pid,
                "reader": reader,
            })
            self.file_paths.add(path)

    @staticmethod
    def _decode_event(event, values, text1, text2):
        assert event in PROBE_EVENTS, event
        fields = {"event": PROBE_EVENTS[event]}
        if event == 1:
            fields.update(peer=values[0], msg_id=values[1], queue_bytes=values[2],
                          queue_depth=values[3], pause_recv=values[4], msg=text1)
        elif event == 2:
            fields.update(
                peer=values[0], msg_id=values[1], handler_turn_start_ns=values[2],
                handler_prefix_ns=values[3], ready_ns=values[4], poll_ns=values[5],
                ready_queue_bytes=values[6], ready_queue_depth=values[7],
                ready_pause_recv=values[8], poll_queue_bytes=values[9],
                poll_queue_depth=values[10], poll_pause_recv=values[11],
                active_slot=values[12], job=values[13], msg=text1)
        elif event == 3:
            fields.update(peer=values[0], msg_id=values[1], active_slot=values[2],
                          job=values[3], msg=text1)
        elif event == 4:
            fields.update(
                peer=values[0], msg_id=values[1], nonce=values[2],
                response_bytes=values[3], send_queue_bytes=values[4],
                send_queue_depth=values[5], pause_send=values[6],
                active_slot=values[7], job=values[8], msg=text1, response=text2)
        elif event == 5:
            fields.update(job=values[0], source=values[1], active_slot=values[2],
                          mode="async" if values[2] else "sync", continuation=text1)
        elif event == 6:
            fields.update(job=values[0], source=values[1], status_code=values[2],
                          active_slot=values[3], status=text1)
        elif event in {7, 8}:
            fields.update(job=values[0], active_slot=values[1])
        elif event == 9:
            fields.update(job=values[0], duration_ns=values[1], new_block=values[2],
                          active_slot=values[3])
        elif event == 10:
            fields.update(job=values[0], new_block=values[1], active_slot=values[2])
        elif event == 11:
            fields.update(
                job=values[0], source=values[1], count=values[2], total_ns=values[3],
                max_ns=values[4], max_peer=values[5], max_start_ns=values[6],
                max_end_ns=values[7], active_slot=values[8])
        elif event == 12:
            fields.update(job=values[0], source=values[1], new_block=values[2],
                          active_slot=values[3], continuation=text1)
        elif event == 13:
            fields.update(job=values[0], source=values[1], new_block=values[2],
                          continuation=text1)
        elif event == 14:
            fields.update(gate=values[0], generation=values[1], job=values[2],
                          peer=values[3])
        return fields

    def _poll_file(self, state):
        reader = state["reader"]
        reader.read_header()
        while state["expected_sequence"] <= reader.next_sequence:
            record = reader.read_event(state["expected_sequence"])
            if record is None:
                # next_sequence is reserved before release publication. This
                # is an in-flight append, not an unstable/torn slot; final
                # parsing after node exit requires every reservation below.
                return
            sequence, event, flags, steady_ns = record[:4]
            assert sequence == state["expected_sequence"]
            values = record[4:20]
            text1 = self._decode_text(record[20])
            text2 = self._decode_text(record[21])
            marker = self._decode_event(event, values, text1, text2)
            marker.update(
                flags=flags, probe_pid=state["pid"], probe_sequence=sequence,
                sequence=len(self.events) + 1, steady_ns=steady_ns)
            raw_hash = record[22]
            if any(raw_hash):
                marker["hash"] = raw_hash[::-1].hex()
            self.events.append(marker)
            state["event_count"] += 1
            state["expected_sequence"] += 1

    def poll(self):
        self._discover()
        for state in self.files:
            self._poll_file(state)

    def checkpoint(self):
        self.poll()
        return len(self.events)

    def wait(self, event, after=0, timeout=None, **fields):
        deadline = time.monotonic() + (self.timeout if timeout is None else timeout)
        while True:
            self.poll()
            matches = [
                marker for marker in self.events[after:]
                if marker.get("event") == event
                and all(marker.get(key) == value for key, value in fields.items())
            ]
            if matches:
                return matches[0]
            if time.monotonic() >= deadline:
                raise AssertionError(f"missing marker event={event} fields={fields}")
            time.sleep(MARKER_POLL)

    def unique(self, event, after=0, **fields):
        self.poll()
        matches = [
            marker for marker in self.events[after:]
            if marker.get("event") == event
            and all(marker.get(key) == value for key, value in fields.items())
        ]
        assert len(matches) == 1, (event, fields, len(matches))
        return matches[0]

    def assert_absent(self, event, after=0, **fields):
        self.poll()
        matches = [
            marker for marker in self.events[after:]
            if marker.get("event") == event
            and all(marker.get(key) == value for key, value in fields.items())
        ]
        assert not matches, (event, fields, matches)

    def arm_gate(self, gate, *, peer=-1):
        assert self.expect_test_gates and gate != "none"
        self.poll()
        state = self.files[-1]
        reader = state["reader"]
        header = reader.read_header()
        generation = header[10] + 1
        assert generation > header[11]
        assert -(1 << 31) <= peer < (1 << 31)
        struct.pack_into("<i", reader.mapping, 60, peer)
        struct.pack_into("<I", reader.mapping, 44, PROBE_GATES[gate])
        # Publish the generation after the peer and gate fields.
        struct.pack_into("<I", reader.mapping, 48, generation)
        return generation

    def release_gate(self, generation, *, clear=True):
        assert self.expect_test_gates
        reader = self.files[-1]["reader"]
        # Use the raw validated mapping so failure cleanup can still release a
        # generation after the reader has correctly made gate_error fatal.
        header = PROBE_HEADER.unpack_from(reader.mapping, 0)
        assert generation <= header[10]
        if header[11] < generation:
            struct.pack_into("<I", reader.mapping, 52, generation)
        if clear and generation == header[10]:
            struct.pack_into("<I", reader.mapping, 44, PROBE_GATES["none"])
            struct.pack_into("<i", reader.mapping, 60, -1)

    def wait_gate(self, gate, generation, after=0, **fields):
        return self.wait(
            "test_gate_entered", after, gate=PROBE_GATES[gate],
            generation=generation, **fields)

    def finalize(self, *, require_gate_none):
        self.poll()
        files = []
        for state in self.files:
            reader = state["reader"]
            header = reader.read_header()
            assert state["expected_sequence"] == header[7] + 1, (
                reader.path, state["expected_sequence"], header[7])
            if require_gate_none:
                assert header[9] == PROBE_GATES["none"], header
                assert header[11] == header[10], header
            files.append({
                "event_count": state["event_count"],
                "path": str(reader.path),
                "pid": state["pid"],
                "status": header[6],
                "overflow_count": header[8],
                "test_gate": header[9],
                "test_gate_generation": header[10],
                "test_gate_release": header[11],
                "test_gate_error": header[12],
            })
        return {
            "event_count": len(self.events),
            "files": files,
            "schema": PROBE_SCHEMA,
            "unstable_reads": self.unstable_reads,
        }

    def marker_lines(self):
        self.poll()
        return [
            MARKER_PREFIX + " ".join(
                f"{key}={value}" for key, value in marker.items()
                if key != "sequence") + "\n"
            for marker in self.events
        ]

    def remove_files(self):
        paths = [state["reader"].path for state in self.files]
        for state in self.files:
            state["reader"].close()
        for path in paths:
            assert path.parent == self.directory and not path.is_symlink()
            path.unlink()
        return [str(path) for path in paths]


class ResourceSampler:
    def __init__(self, pid, path):
        self.pid = pid
        self.path = Path(path)
        self.stop_event = threading.Event()
        self.start_ns = time.perf_counter_ns()
        self.file = self.path.open("x", newline="", encoding="utf-8")
        self.writer = csv.writer(self.file)
        self.writer.writerow((
            "wall_ns", "process_cpu_ticks", "rss_kib", "threads",
            "voluntary_context_switches", "involuntary_context_switches",
            "handler_cpu_ticks", "pnb_cpu_ticks", "script_cpu_ticks",
            "read_bytes", "write_bytes",
        ))
        self.thread = threading.Thread(target=self._run, name="resource-sampler", daemon=True)
        self.thread.start()

    def _sample(self):
        stat = Path(f"/proc/{self.pid}/stat").read_text(encoding="ascii")
        fields = stat[stat.rfind(")") + 2:].split()
        status = Path(f"/proc/{self.pid}/status").read_text(encoding="ascii")
        rss = next(int(line.split()[1]) for line in status.splitlines() if line.startswith("VmRSS:"))
        categories = {"handler": 0, "pnb": 0, "script": 0}
        voluntary = 0
        involuntary = 0
        threads = 0
        for task in Path(f"/proc/{self.pid}/task").iterdir():
            try:
                name = (task / "comm").read_text(encoding="ascii").strip()
                task_stat = (task / "stat").read_text(encoding="ascii")
                task_fields = task_stat[task_stat.rfind(")") + 2:].split()
                ticks = int(task_fields[11]) + int(task_fields[12])
                task_status = (task / "status").read_text(encoding="ascii").splitlines()
                task_voluntary = int(next(
                    line.split()[1] for line in task_status if line.startswith("voluntary_ctxt_switches:")))
                task_involuntary = int(next(
                    line.split()[1] for line in task_status if line.startswith("nonvoluntary_ctxt_switches:")))
            except (FileNotFoundError, StopIteration):
                continue
            threads += 1
            voluntary += task_voluntary
            involuntary += task_involuntary
            if "msghand" in name:
                categories["handler"] += ticks
            elif "p2p-pnb" in name:
                categories["pnb"] += ticks
            elif "scriptch" in name:
                categories["script"] += ticks
        io_values = {}
        for line in Path(f"/proc/{self.pid}/io").read_text(encoding="ascii").splitlines():
            key, value = line.split(":", 1)
            io_values[key] = int(value)
        return (
            int(fields[11]) + int(fields[12]), rss, threads, voluntary, involuntary,
            categories["handler"], categories["pnb"], categories["script"],
            io_values["read_bytes"], io_values["write_bytes"],
        )

    def _run(self):
        while not self.stop_event.is_set():
            try:
                self.writer.writerow((time.perf_counter_ns() - self.start_ns, *self._sample()))
                self.file.flush()
            except (FileNotFoundError, StopIteration):
                break
            self.stop_event.wait(0.05)

    def stop(self):
        self.stop_event.set()
        self.thread.join()
        self.file.close()


class AsyncPNBPeerService(BitcoinTestFramework):
    def add_options(self, parser):
        parser.add_argument("--output-dir")
        parser.add_argument("--peer-service-mode", choices=("control", "candidate"), default="candidate")
        parser.add_argument("--peer-service-profile", choices=tuple(PROFILES), default="curve")
        parser.add_argument("--peer-service-reference-run")
        parser.add_argument("--peer-service-seed", type=int, default=0xA51C0DE)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = False
        self.uses_wallet = False
        if self.options.randomseed is None:
            self.options.randomseed = self.options.peer_service_seed
        assert self.options.randomseed == self.options.peer_service_seed, \
            "--randomseed must match --peer-service-seed for paired inputs"
        portseed_explicit = any(
            arg == "--portseed" or arg.startswith("--portseed=") for arg in sys.argv[1:]
        )
        if self.options.output_dir is not None:
            assert portseed_explicit, "measurement runs require an explicit fixed --portseed"
        mode = self.options.peer_service_mode
        args = [
            f"-asyncpnbpeerservice={int(mode == 'candidate')}",
            "-loglevel=info",
            "-maxconnections=213",
            "-nodebug",
            "-nologratelimit",
            "-persistmempool=0",
            "-v2transport=0",
        ]
        args += ["-par=1", "-prevoutfetchthreads=0"]
        self.extra_args = [args]

    def setup_nodes(self):
        """Refresh the cached chain with an identical height-200 block in every arm."""
        self.probe_dir = Path(self.options.tmpdir).resolve()
        self.test_gates_enabled = self.options.output_dir is None
        self.extra_args[0] += [
            f"-asyncpnbpeerserviceprobedir={self.probe_dir}",
            f"-asyncpnbpeerservicetestgates={int(self.test_gates_enabled)}",
        ]
        self.add_nodes(self.num_nodes, self.extra_args)
        self.start_nodes()
        self.markers = MarkerReader(
            self.probe_dir, self.options.timeout_factor,
            expect_test_gates=self.test_gates_enabled)
        assert not self.uses_wallet and len(self.nodes) == 1
        node = self.nodes[0]
        assert node.getblockcount() == 199
        parent_hash = node.getbestblockhash()
        refresh_time = node.getblockheader(parent_hash)["time"] + 1
        node.setmocktime(refresh_time)
        block_hash = self.generate(node, 1, sync_fun=self.no_op)[0]
        block = node.getblock(blockhash=block_hash, verbosity=0)
        node.submitblock(block)
        chain_info = node.getblockchaininfo()
        assert chain_info["blocks"] == 200 and not chain_info["initialblockdownload"]
        header = node.getblockheader(block_hash)
        assert header["time"] == refresh_time
        self.deterministic_chain_start = {"hash": block_hash, "height": 200}
        self.refresh_block = {
            "hash": block_hash, "height": 200, "parent_hash": parent_hash, "time": refresh_time,
        }

    @staticmethod
    def _write_json(path, value):
        with path.open("x", encoding="utf-8") as output:
            json.dump(value, output, indent=2, sort_keys=True, allow_nan=False)
            output.write("\n")

    def _prepare_output(self):
        output = Path(self.options.output_dir).resolve()
        if output.exists():
            assert output.is_dir() and not output.is_symlink()
            assert not any(output.iterdir()), f"refusing to overwrite {output}"
        else:
            output.mkdir(parents=True)
        self.output_dir = output
        self.samples_file = (output / "samples.jsonl").open("x", encoding="utf-8")
        self.reference_run = None
        if self.options.peer_service_reference_run:
            reference_path = Path(self.options.peer_service_reference_run).resolve()
            with reference_path.open(encoding="utf-8") as reference_file:
                self.reference_run = json.load(reference_file)
            self.reference_run_path = str(reference_path)

    def _write_sample(self, sample):
        self.samples_file.write(json.dumps(sample, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n")
        self.samples_file.flush()

    @staticmethod
    def _empty_campaign_aggregate():
        fields = {
            "completed": 0,
            "correlation_failed": 0,
            "disconnected": 0,
            "eligible": 0,
            "failed": 0,
            "offered": 0,
            "ready_inside_pnb": 0,
            "response_inside_pnb": 0,
            "timed_out": 0,
        }
        return {
            **fields,
            "by_service": {service: dict(fields) for service in SERVICE_CLASSES},
        }

    def _map_peer_id(self, peer, *, require_subversion=True):
        sock = peer._transport.get_extra_info("socket")
        local = sock.getsockname()
        addr = f"{local[0]}:{local[1]}"
        matches = [entry for entry in self.nodes[0].getpeerinfo()
                   if entry["addr"] == addr
                   and (not require_subversion or entry["subver"] == P2P_SUBVERSION)]
        assert len(matches) == 1
        return matches[0]["id"]

    def _announce(self, peer, block):
        assert peer.block_requests.count(block.hash_int) == 0
        peer.send_without_ping(msg_headers([CBlockHeader(block)]))
        peer.wait_for_block_request(block.hash_int)

    def _wait_tip(self, block):
        self.wait_until(lambda: self.nodes[0].getbestblockhash() == block.hash_hex,
                        timeout=PING_TIMEOUT, check_interval=MARKER_POLL)

    def _initialize_block_inputs(self):
        node = self.nodes[0]
        tip_hash = node.getbestblockhash()
        tip = node.getblockheader(tip_hash)
        self.chain_start = {"hash": tip_hash, "height": node.getblockcount()}
        assert self.chain_start == self.deterministic_chain_start
        self.block_mocktime = tip["time"]
        node.setmocktime(self.block_mocktime)
        self.block_inputs = []
        self.block_input_hasher = hashlib.sha256()
        # MiniWallet's RAW_P2PK ECDSA signer uses Python's global PRNG. Reset it
        # here and at every block boundary so unrelated harness activity cannot
        # change serialized candidate/control inputs.
        random.seed(self.options.peer_service_seed)

    def _advance_block_mocktime(self):
        self.block_mocktime += 1
        self.nodes[0].setmocktime(self.block_mocktime)
        random.seed((self.options.peer_service_seed << 32) + len(self.block_inputs) + 1)

    def _record_block_input(self, block, kind, height):
        raw = block.serialize()
        self.block_input_hasher.update(len(raw).to_bytes(8, "little"))
        self.block_input_hasher.update(raw)
        self.block_inputs.append({
            "hash": block.hash_hex,
            "height": height,
            "kind": kind,
            "serialized_sha256": hashlib.sha256(raw).hexdigest(),
            "sequence": len(self.block_inputs) + 1,
        })

    def _quick_block(self):
        self._advance_block_mocktime()
        template = self.nodes[0].getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        block = create_block(tmpl=template, coinbase=create_coinbase(template["height"]))
        block.solve()
        assert block.is_valid()
        self._record_block_input(block, "quick", template["height"])
        return block

    def _invalid_quick_block(self):
        self._advance_block_mocktime()
        template = self.nodes[0].getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        block = create_block(tmpl=template, coinbase=create_coinbase(template["height"]))
        block.vtx[0].vout[0].nValue += COIN
        block.hashMerkleRoot = block.calc_merkle_root()
        block.solve()
        self._record_block_input(block, "invalid-coinbase", template["height"])
        return block

    def _create_funding(self, setup_peer, address_wallet, p2pk_wallet):
        self._advance_block_mocktime()
        utxo = min(address_wallet.get_utxos(mark_as_spent=False, confirmed_only=True),
                   key=lambda item: (item["txid"], item["vout"]))
        result = address_wallet.create_self_transfer(
            utxo_to_spend=utxo, fee_rate=0, fee=Decimal("0.00001000"))
        tx = result["tx"]
        tx.vout[0].scriptPubKey = CScript(p2pk_wallet.get_output_script())
        address_wallet.sign_tx(tx)
        seed = {"txid": tx.txid_hex, "vout": 0, "value": Decimal(tx.vout[0].nValue) / COIN}
        template = self.nodes[0].getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        block = create_block(tmpl=template,
                             coinbase=create_coinbase(template["height"], fees=1_000),
                             txlist=[tx])
        add_witness_commitment(block)
        block.solve()
        assert block.is_valid()
        self._record_block_input(block, "funding", template["height"])
        self._announce(setup_peer, block)
        setup_peer.send_without_ping(msg_block(block))
        self._wait_tip(block)
        return seed, block

    def _build_work_block(self, wallet, seed):
        self._advance_block_mocktime()
        template = self.nodes[0].getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        results = []
        current = seed
        for _ in range(GENERATED_CHAIN_TXS):
            result = wallet.create_self_transfer(
                utxo_to_spend=current, fee_rate=0, fee=Decimal("0.00000001"))
            result["tx"].vout[0].scriptPubKey = CScript(result["tx"].vout[0].scriptPubKey)
            results.append(result)
            current = result["new_utxo"]
        included = results[:INCLUDED_CHAIN_TXS]
        block = create_block(
            tmpl=template,
            coinbase=create_coinbase(template["height"], fees=INCLUDED_CHAIN_TXS),
            txlist=[result["tx"] for result in included],
        )
        overflow = create_block(
            tmpl=template,
            coinbase=create_coinbase(template["height"], fees=GENERATED_CHAIN_TXS),
            txlist=[result["tx"] for result in results],
        )
        assert block.get_weight() == EXPECTED_BLOCK_WEIGHT
        assert len(block.serialize()) == EXPECTED_BLOCK_BYTES
        assert block.get_weight() <= TARGET_WEIGHT <= MAX_BLOCK_WEIGHT
        assert overflow.get_weight() > TARGET_WEIGHT
        sigops = get_legacy_sigopcount_block(block)
        assert sigops == EXPECTED_LEGACY_SIGOPS
        assert sigops * WITNESS_SCALE_FACTOR <= MAX_BLOCK_SIGOPS_COST
        block.solve()
        assert block.is_valid()
        self._record_block_input(block, "work", template["height"])
        return block, included[-1]["new_utxo"]

    def _begin_service_request(self, peer, service, fixture):
        if service == "ping":
            nonce = fixture["nonce"]
            peer.begin_service_request(
                service, msg_ping(nonce), ("pong",), nonce=nonce)
        elif service == "version":
            version = msg_version()
            version.nVersion = P2P_VERSION
            version.strSubVer = P2P_SUBVERSION
            version.nServices = P2P_SERVICES
            version.relay = 1
            peer.begin_service_request(
                service, version, ("version", "verack"))
        elif service == "getaddr":
            peer.begin_service_request(
                service, msg_getaddr(),
                (("addrv2",) if peer.support_addrv2 else ("addr",)))
        elif service == "getblocktxn":
            request = msg_getblocktxn()
            request.block_txn_request = BlockTransactionsRequest(
                blockhash=fixture["recent_block"].hash_int)
            request.block_txn_request.from_absolute([0])
            peer.begin_service_request(
                service, request, ("blocktxn",))
        elif service == "getheaders":
            request = msg_getheaders()
            request.locator = CBlockLocator()
            request.locator.vHave = [fixture["recent_block"].hashPrevBlock]
            request.hashstop = fixture["recent_block"].hash_int
            peer.begin_service_request(
                service, request, ("headers",))
        elif service == "getdata":
            peer.begin_service_request(
                service,
                msg_getdata([CInv(MSG_TX, fixture["unknown_tx_hash"])]),
                ("notfound",))
        else:
            raise AssertionError(service)

    @staticmethod
    def _validate_service_response(timing, fixture):
        assert timing["completed"] and timing["connected"]
        service = timing["service"]
        responses = timing["responses"]
        response_types = [entry["type"] for entry in responses]
        if service == "ping":
            assert response_types == ["pong"]
            assert responses[0]["message"].nonce == fixture["nonce"]
        elif service == "version":
            assert response_types.count("version") == 1
            assert response_types.count("verack") == 1
            version = next(entry["message"] for entry in responses if entry["type"] == "version")
            assert version.nVersion >= MIN_P2P_VERSION_SUPPORTED
            assert version.nServices & P2P_SERVICES == P2P_SERVICES
        elif service == "getaddr":
            assert len(responses) == 1 and response_types[0] in {"addr", "addrv2"}
            assert responses[0]["message"].addrs
            assert any(addr.ip in fixture["seed_addresses"]
                       for addr in responses[0]["message"].addrs)
        elif service == "getblocktxn":
            assert response_types == ["blocktxn"]
            response = responses[0]["message"].block_transactions
            assert response.blockhash == fixture["recent_block"].hash_int
            assert len(response.transactions) == 1
            assert response.transactions[0].txid_int == fixture["recent_block"].vtx[0].txid_int
        elif service == "getheaders":
            assert response_types == ["headers"]
            headers = responses[0]["message"].headers
            assert len(headers) == 1
            assert headers[0].hash_int == fixture["recent_block"].hash_int
        elif service == "getdata":
            assert response_types == ["notfound"]
            inv = responses[0]["message"].vec
            assert len(inv) == 1
            assert inv[0].type == MSG_TX and inv[0].hash == fixture["unknown_tx_hash"]
        else:
            raise AssertionError(service)

    def _target_service(self, peer_id, timing, checkpoint, pnb=None):
        service = timing["service"]
        response_markers = []
        for response in timing["responses"]:
            marker = self.markers.wait(
                "response_queued", checkpoint, peer=peer_id,
                msg=service, response=response["type"])
            assert marker["response_bytes"] == response["response_bytes"]
            response_markers.append(marker)
        msg_ids = {marker["msg_id"] for marker in response_markers}
        assert len(msg_ids) == 1
        msg_id = msg_ids.pop()
        ready = self.markers.wait(
            "complete_message_ready", checkpoint, peer=peer_id, msg_id=msg_id)
        start = self.markers.wait(
            "handler_start", checkpoint, peer=peer_id, msg_id=msg_id)
        complete = self.markers.wait(
            "handler_complete", checkpoint, peer=peer_id, msg_id=msg_id)
        assert ready["msg"] == start["msg"] == complete["msg"] == service
        for response in response_markers:
            assert ready["steady_ns"] <= start["steady_ns"] <= response["steady_ns"]
        final_response = max(response_markers, key=lambda marker: marker["steady_ns"])
        target = {
            "active_job": final_response["job"],
            "handler_complete_ns": complete["steady_ns"],
            "handler_processing_ns": complete["steady_ns"] - start["steady_ns"],
            "handler_queue_delay_ns": start["steady_ns"] - ready["steady_ns"],
            "handler_prefix_ns": start["handler_prefix_ns"],
            "handler_scheduling_delay_ns": start["handler_turn_start_ns"] - ready["steady_ns"],
            "handler_turn_start_ns": start["handler_turn_start_ns"],
            "message_id": msg_id,
            "node_service_latency_ns": final_response["steady_ns"] - ready["steady_ns"],
            "poll_ns": start["poll_ns"],
            "poll_pause_recv": start["poll_pause_recv"],
            "poll_queue_bytes": start["poll_queue_bytes"],
            "poll_queue_depth": start["poll_queue_depth"],
            "ready_ns": ready["steady_ns"],
            "ready_pause_recv": ready["pause_recv"],
            "ready_queue_bytes": ready["queue_bytes"],
            "ready_queue_depth": ready["queue_depth"],
            "response_markers": response_markers,
            "response_queued_ns": final_response["steady_ns"],
            "response_transcript": [
                {key: response[key] for key in ("response_bytes", "response_sha256", "type")}
                for response in timing["responses"]
            ],
            "send_pause": final_response["pause_send"],
            "send_queue_bytes": final_response["send_queue_bytes"],
            "send_queue_depth": final_response["send_queue_depth"],
            "service": service,
        }
        assert target["handler_prefix_ns"] == start["steady_ns"] - start["handler_turn_start_ns"]
        assert ready["steady_ns"] <= start["poll_ns"] <= start["steady_ns"] <= complete["steady_ns"]
        pause_values = (
            target["ready_pause_recv"], target["poll_pause_recv"], target["send_pause"])
        self.pause_metrics["snapshots_checked"] += len(pause_values)
        self.pause_metrics["pause_observations"] += sum(bool(value) for value in pause_values)
        assert not any(pause_values), "measured receive/send queue pause invalidates campaign"
        if pnb is not None:
            target["ready_inside_pnb"] = pnb["start_ns"] < target["ready_ns"] < pnb["end_ns"]
            target["response_inside_pnb"] = (
                pnb["start_ns"] < target["response_queued_ns"] < pnb["end_ns"])
            target["residual_pnb_ns_at_ready"] = max(0, pnb["end_ns"] - target["ready_ns"])
            target["residual_delay_removed_ns"] = max(
                0, target["node_service_latency_ns"] - target["residual_pnb_ns_at_ready"])
        return target

    def _pnb_lifecycle(self, checkpoint, block_hash, job, continuation=None):
        submit = self.markers.unique("job_submit", checkpoint, hash=block_hash, job=job)
        if continuation is not None:
            assert submit["continuation"] == continuation
        start = self.markers.unique("pnb_start", checkpoint, hash=block_hash, job=job)
        end = self.markers.unique("pnb_end", checkpoint, hash=block_hash, job=job)
        completed = self.markers.unique(
            "continuation", checkpoint, hash=block_hash, job=job)
        if continuation is not None:
            assert completed["continuation"] == continuation
        assert submit["steady_ns"] <= start["steady_ns"] < end["steady_ns"]
        assert end["duration_ns"] == end["steady_ns"] - start["steady_ns"]
        assert end["steady_ns"] <= completed["steady_ns"]
        lifecycle = {
            "continuation": completed,
            "job_submit": submit,
            "pnb_start": start,
            "pnb_end": end,
        }
        if self.options.peer_service_mode == "candidate":
            slot = self.markers.unique(
                "slot_submit", checkpoint, hash=block_hash, job=job, status="accepted")
            wake = self.markers.unique("worker_wake", checkpoint, hash=block_hash, job=job)
            publication = self.markers.unique(
                "result_publication", checkpoint, hash=block_hash, job=job)
            summary = self.markers.unique(
                "busy_send_prefix_summary", checkpoint, hash=block_hash, job=job)
            collection = self.markers.unique(
                "result_collection", checkpoint, hash=block_hash, job=job)
            assert (submit["steady_ns"] <= wake["steady_ns"] <= start["steady_ns"]
                    < end["steady_ns"] <= publication["steady_ns"]
                    <= summary["steady_ns"] <= collection["steady_ns"]
                    <= completed["steady_ns"])
            assert submit["steady_ns"] <= slot["steady_ns"] <= collection["steady_ns"]
            assert summary["total_ns"] >= summary["max_ns"] >= 0
            assert (summary["count"] == 0) == (summary["max_peer"] == -1)
            lifecycle.update({
                "busy_send_prefix_summary": summary,
                "result_collection": collection,
                "result_publication": publication,
                "slot_submit": slot,
                "worker_wake": wake,
            })
        return lifecycle

    @staticmethod
    def _missing_coinbase_compact(block):
        compact = HeaderAndShortIDs()
        compact.header = CBlockHeader(block)
        compact.nonce = 0
        compact.use_witness = True
        key0, key1 = compact.get_siphash_keys()
        compact.shortids = [calculate_shortid(key0, key1, block.vtx[0].wtxid_int)]
        return compact

    @staticmethod
    def _missing_all_compact(block):
        compact = HeaderAndShortIDs()
        compact.initialize_from_block(block, prefill_list=[], use_witness=True)
        return compact

    def _wait_pnb_job(self, checkpoint, block, continuation):
        start = self.markers.wait("pnb_start", checkpoint, hash=block.hash_hex)
        end = self.markers.wait(
            "pnb_end", checkpoint, hash=block.hash_hex, job=start["job"])
        self._wait_tip(block)
        if self.options.peer_service_mode == "candidate":
            self.markers.wait(
                "result_publication", checkpoint, hash=block.hash_hex, job=start["job"])
            self.markers.wait(
                "result_collection", checkpoint, hash=block.hash_hex, job=start["job"])
        lifecycle = self._pnb_lifecycle(
            checkpoint, block.hash_hex, start["job"], continuation)
        return {
            "duration_ns": end["duration_ns"],
            "end_ns": end["steady_ns"],
            "job": start["job"],
            "lifecycle": lifecycle,
            "start_ns": start["steady_ns"],
        }

    def _deliver_full_block(self, source, block):
        self._announce(source, block)
        checkpoint = self.markers.checkpoint()
        source.send_without_ping(msg_block(block))
        return self._wait_pnb_job(checkpoint, block, "standard")

    def _deliver_blocktxn_block(self, source, block):
        self._announce(source, block)
        assert source.block_request_types[-1] == (block.hash_int, MSG_CMPCT_BLOCK)
        source.blocktxn_requests.clear()
        source.send_without_ping(
            msg_cmpctblock(self._missing_coinbase_compact(block).to_p2p()))
        source.wait_until(
            lambda: any(request.blockhash == block.hash_int
                        for request in source.blocktxn_requests),
            timeout=PING_TIMEOUT)
        request = next(request for request in source.blocktxn_requests
                       if request.blockhash == block.hash_int)
        assert request.to_absolute() == [0]
        response = msg_blocktxn()
        response.block_transactions = BlockTransactions(
            block.hash_int, [block.vtx[0]])
        checkpoint = self.markers.checkpoint()
        source.send_without_ping(response)
        return self._wait_pnb_job(checkpoint, block, "standard")

    def _deliver_optimistic_compact_block(self, source, blockers, block):
        assert len(blockers) == 3
        self._announce(blockers[0], block)
        assert blockers[0].block_request_types[-1] == (block.hash_int, MSG_CMPCT_BLOCK)
        missing = msg_cmpctblock(self._missing_coinbase_compact(block).to_p2p())
        for blocker in blockers:
            blocker.blocktxn_requests.clear()
            blocker.send_without_ping(missing)
            blocker.wait_until(
                lambda blocker=blocker: any(
                    request.blockhash == block.hash_int
                    for request in blocker.blocktxn_requests),
                timeout=PING_TIMEOUT)
        complete = HeaderAndShortIDs()
        complete.initialize_from_block(
            block, prefill_list=[0], use_witness=True)
        checkpoint = self.markers.checkpoint()
        source.send_without_ping(msg_cmpctblock(complete.to_p2p()))
        return self._wait_pnb_job(checkpoint, block, "optimistic_compact")

    def _calibrate_service_fixtures(self, fixture):
        """Prove every fixed request is eligible outside PNB before timing it."""
        transcripts = {}
        for index, service in enumerate(SERVICE_CLASSES):
            peer, peer_id = self._new_service_peer(service)
            service_fixture = {**fixture, "nonce": 0xC000000000000000 | index}
            checkpoint = self.markers.checkpoint()
            self._begin_service_request(peer, service, service_fixture)
            timing = peer.finish_service_request()
            self._validate_service_response(timing, service_fixture)
            target = self._target_service(peer_id, timing, checkpoint)
            transcripts[service] = target["response_transcript"]
            response_received_ns = max(
                response["received_ns"] for response in timing["responses"])
            self._write_sample({
                "completed": True,
                "connected": timing["connected"],
                "eligible": True,
                "kind": "calibration",
                "mode": self.options.peer_service_mode,
                "peer_id": peer_id,
                "peer_rtt_ns": response_received_ns - timing["request_sent_ns"],
                "request_sent_ns": timing["request_sent_ns"],
                "response_received_ns": response_received_ns,
                "response_transcript": target["response_transcript"],
                "service": service,
                "target": target,
                "workload": "outside_pnb",
            })
            peer.peer_disconnect()
            peer.wait_for_disconnect()
        return transcripts

    def _start_producer_form(self, source, block, producer_form, blockers=()):
        """Submit the final wire message for one of the three audited P2P routes."""
        if producer_form == "full_block":
            self._announce(source, block)
            checkpoint = self.markers.checkpoint()
            source.send_without_ping(msg_block(block))
            continuation = "standard"
        elif producer_form == "blocktxn":
            self._announce(source, block)
            source.blocktxn_requests.clear()
            source.send_without_ping(
                msg_cmpctblock(self._missing_all_compact(block).to_p2p()))
            source.wait_until(
                lambda: any(request.blockhash == block.hash_int
                            for request in source.blocktxn_requests),
                timeout=PING_TIMEOUT)
            request = next(request for request in source.blocktxn_requests
                           if request.blockhash == block.hash_int)
            indexes = request.to_absolute()
            assert indexes and indexes == sorted(set(indexes))
            response = msg_blocktxn()
            response.block_transactions = BlockTransactions(
                block.hash_int, [block.vtx[index] for index in indexes])
            checkpoint = self.markers.checkpoint()
            source.send_without_ping(response)
            continuation = "standard"
        elif producer_form == "optimistic_compact":
            assert len(blockers) == 3
            self._announce(blockers[0], block)
            missing = msg_cmpctblock(self._missing_all_compact(block).to_p2p())
            for blocker in blockers:
                blocker.blocktxn_requests.clear()
                blocker.send_without_ping(missing)
                blocker.wait_until(
                    lambda blocker=blocker: any(
                        request.blockhash == block.hash_int
                        for request in blocker.blocktxn_requests),
                    timeout=PING_TIMEOUT)
            complete = HeaderAndShortIDs()
            complete.initialize_from_block(
                block, prefill_list=list(range(len(block.vtx))), use_witness=True)
            checkpoint = self.markers.checkpoint()
            source.send_without_ping(msg_cmpctblock(complete.to_p2p()))
            continuation = "optimistic_compact"
        else:
            raise AssertionError(producer_form)

        start = self.markers.wait("pnb_start", checkpoint, hash=block.hash_hex)
        return checkpoint, start, continuation

    def _finish_measured_pnb(self, block, checkpoint, start, continuation):
        end = self.markers.wait(
            "pnb_end", checkpoint, hash=block.hash_hex, job=start["job"])
        self._wait_tip(block)
        if self.options.peer_service_mode == "candidate":
            self.markers.wait(
                "result_collection", checkpoint,
                hash=block.hash_hex, job=start["job"])
        lifecycle = self._pnb_lifecycle(
            checkpoint, block.hash_hex, start["job"], continuation)
        assert lifecycle["job_submit"]["source"] == self.source_id
        return {
            "duration_ns": end["duration_ns"],
            "end_ns": end["steady_ns"],
            "job": start["job"],
            "start_ns": start["steady_ns"],
        }, lifecycle

    def _record_request_sample(self, *, block, fixture, front_refused, lifecycle,
                               peer_id, phase, pnb, producer_form, send_position,
                               serial, service, target, timing, trial, workload):
        response_received_ns = max(
            response["received_ns"] for response in timing["responses"])
        sample = {
            "block_hash": block.hash_hex,
            "completed": timing["completed"],
            "connected": timing["connected"],
            "correlation_failed": False,
            "disconnected": not timing["connected"],
            "eligible": True,
            "front_refused": front_refused,
            "kind": "request",
            "lifecycle": lifecycle,
            "mode": self.options.peer_service_mode,
            "peer_id": peer_id,
            "peer_rtt_ns": response_received_ns - timing["request_sent_ns"],
            "phase": phase,
            "pnb": pnb,
            "producer_form": producer_form,
            "request_sent_ns": timing["request_sent_ns"],
            "response_count": len(timing["responses"]),
            "response_received_ns": response_received_ns,
            "response_transcript": target["response_transcript"],
            "send_position": send_position,
            "serial": serial,
            "service": service,
            "target": target,
            "timed_out": not timing["completed"],
            "trial": trial,
            "workload": workload,
        }
        if service == "ping": sample["nonce"] = fixture["nonce"]
        if service in {"getblocktxn", "getheaders"}:
            sample["fixture_block_hash"] = fixture["recent_block"].hash_hex
        if service == "getdata":
            sample["fixture_tx_hash"] = f"{fixture['unknown_tx_hash']:064x}"
        self._write_sample(sample)
        return sample

    def _measure_isolated_trial(self, source, block, fixture, service, phase,
                                trial, serial, producer_form="full_block", blockers=()):
        peer, peer_id = self._new_service_peer(service)
        service_fixture = {**fixture, "nonce": 0xD000000000000000 | serial}
        checkpoint, start, continuation = self._start_producer_form(
            source, block, producer_form, blockers)
        self._begin_service_request(peer, service, service_fixture)
        timing = peer.finish_service_request()
        pnb, lifecycle = self._finish_measured_pnb(
            block, checkpoint, start, continuation)
        self._validate_service_response(timing, service_fixture)
        target = self._target_service(peer_id, timing, checkpoint, pnb)
        assert target["ready_inside_pnb"]
        self.trial_inputs.append({
            "block_hash": block.hash_hex,
            "phase": phase,
            "producer_form": producer_form,
            "fixture_block_hash": fixture["recent_block"].hash_hex,
            "serial": serial,
            "service": service,
            "trial": trial,
            "workload": "isolated" if phase != "source_form" else "source_form",
        })
        sample = self._record_request_sample(
            block=block, fixture=service_fixture, front_refused=False,
            lifecycle=lifecycle, peer_id=peer_id, phase=phase, pnb=pnb,
            producer_form=producer_form, send_position=0, serial=serial,
            service=service, target=target, timing=timing, trial=trial,
            workload="isolated" if phase != "source_form" else "source_form")
        self._write_sample({
            "block_hash": block.hash_hex,
            "busy_send_prefix_summary": lifecycle.get("busy_send_prefix_summary"),
            "completed": 1,
            "failed": 0,
            "kind": "trial",
            "mode": self.options.peer_service_mode,
            "offered": 1,
            "phase": phase,
            "pnb": pnb,
            "producer_form": producer_form,
            "ready_inside_pnb": int(target["ready_inside_pnb"]),
            "response_inside_pnb": int(target["response_inside_pnb"]),
            "serial": serial,
            "service": service,
            "timed_out": 0,
            "trial": trial,
            "workload": sample["workload"],
        })
        if phase in {"trial", "warmup"}:
            aggregate = self.aggregate if phase == "trial" else self.warmup_aggregate
            for values in (aggregate, aggregate["by_service"][service]):
                values["offered"] += 1
                values["eligible"] += 1
                values["completed"] += 1
                values["ready_inside_pnb"] += int(target["ready_inside_pnb"])
                values["response_inside_pnb"] += int(target["response_inside_pnb"])
        peer.peer_disconnect()
        peer.wait_for_disconnect()
        return target

    def _measure_mixed_trial(self, source, block, fixture, trial, serial):
        entries = []
        for service in SERVICE_CLASSES:
            peer, peer_id = self._new_service_peer(service)
            entries.append((service, peer, peer_id))
        refused_peer, refused_peer_id = self._new_service_peer("ping")
        checkpoint, start, continuation = self._start_producer_form(
            source, block, "full_block")

        order = list(range(len(entries)))
        random.Random(self.options.peer_service_seed + serial).shuffle(order)
        fixtures = {}
        for position, index in enumerate(order):
            service, peer, _peer_id = entries[index]
            service_fixture = {
                **fixture, "nonce": 0xE000000000000000 | (serial << 8) | index}
            fixtures[service] = service_fixture
            self._begin_service_request(peer, service, service_fixture)
        refused_fixture = {
            **fixture, "nonce": 0xE100000000000000 | serial}
        refused_peer.send_without_ping(msg_generic(b"block", b""))
        self._begin_service_request(refused_peer, "ping", refused_fixture)

        deadline = time.monotonic() + PING_TIMEOUT * self.options.timeout_factor
        timings = {}
        for service, peer, _peer_id in entries:
            timings[service] = peer.finish_service_request(
                deadline - time.monotonic())
        refused_timing = refused_peer.finish_service_request(
            deadline - time.monotonic())
        pnb, lifecycle = self._finish_measured_pnb(
            block, checkpoint, start, continuation)

        send_position = {index: position for position, index in enumerate(order)}
        samples = []
        for index, (service, _peer, peer_id) in enumerate(entries):
            timing = timings[service]
            self._validate_service_response(timing, fixtures[service])
            target = self._target_service(peer_id, timing, checkpoint, pnb)
            assert target["ready_inside_pnb"]
            samples.append(self._record_request_sample(
                block=block, fixture=fixtures[service], front_refused=False,
                lifecycle=lifecycle, peer_id=peer_id, phase="trial", pnb=pnb,
                producer_form="full_block", send_position=send_position[index],
                serial=serial, service=service, target=target, timing=timing,
                trial=trial, workload="mixed_fifo"))
        self._validate_service_response(refused_timing, refused_fixture)
        refused_target = self._target_service(
            refused_peer_id, refused_timing, checkpoint, pnb)
        assert refused_target["ready_inside_pnb"]
        assert refused_target["response_queued_ns"] >= pnb["end_ns"]
        samples.append(self._record_request_sample(
            block=block, fixture=refused_fixture, front_refused=True,
            lifecycle=lifecycle, peer_id=refused_peer_id, phase="trial", pnb=pnb,
            producer_form="full_block", send_position=len(entries), serial=serial,
            service="ping", target=refused_target, timing=refused_timing,
            trial=trial, workload="mixed_fifo"))

        send_order = [SERVICE_CLASSES[index] for index in order]
        self.trial_inputs.append({
            "block_hash": block.hash_hex,
            "blocked_cohort": ["ping"],
            "phase": "trial",
            "producer_form": "full_block",
            "fixture_block_hash": fixture["recent_block"].hash_hex,
            "send_order": send_order,
            "serial": serial,
            "trial": trial,
            "workload": "mixed_fifo",
        })
        response_inside = sum(
            int(sample["target"]["response_inside_pnb"]) for sample in samples)
        completion_order = [
            {"front_refused": sample["front_refused"],
             "peer_id": sample["peer_id"], "service": sample["service"]}
            for sample in sorted(
                samples, key=lambda value: value["target"]["response_queued_ns"])
        ]
        response_times = sorted(
            sample["target"]["response_queued_ns"] for sample in samples)
        maximum_service_gap_ns = max(
            (later - earlier for earlier, later in zip(response_times, response_times[1:])),
            default=0)
        self._write_sample({
            "block_hash": block.hash_hex,
            "blocked_cohort": ["ping"],
            "busy_send_prefix_summary": lifecycle.get("busy_send_prefix_summary"),
            "completed": len(samples),
            "completion_order": completion_order,
            "failed": 0,
            "kind": "trial",
            "mode": self.options.peer_service_mode,
            "offered": len(samples),
            "phase": "trial",
            "pnb": pnb,
            "producer_form": "full_block",
            "ready_inside_pnb": len(samples),
            "response_inside_pnb": response_inside,
            "responses_per_pnb": len(samples),
            "send_order": send_order,
            "serial": serial,
            "maximum_service_gap_ns": maximum_service_gap_ns,
            "timed_out": 0,
            "trial": trial,
            "workload": "mixed_fifo",
        })
        for sample in samples:
            for values in (
                    self.aggregate,
                    self.aggregate["by_service"][sample["service"]]):
                values["offered"] += 1
                values["eligible"] += 1
                values["completed"] += 1
                values["ready_inside_pnb"] += int(
                    sample["target"]["ready_inside_pnb"])
                values["response_inside_pnb"] += int(
                    sample["target"]["response_inside_pnb"])
        for _service, peer, _peer_id in entries:
            peer.peer_disconnect()
            peer.wait_for_disconnect()
        refused_peer.peer_disconnect()
        refused_peer.wait_for_disconnect()

    def _new_service_peer(self, service):
        peer = PeerServicePeer()
        if service == "version":
            self.nodes[0].add_p2p_connection(
                peer, send_version=False, wait_for_verack=False)
            peer_id = self._map_peer_id(peer, require_subversion=False)
        else:
            self.nodes[0].add_p2p_connection(peer)
            peer_id = self._map_peer_id(peer)
        return peer, peer_id

    def _prove_service_fixtures(self, fixture):
        transcripts = {}
        for index, service in enumerate(SERVICE_CLASSES):
            peer, peer_id = self._new_service_peer(service)
            service_fixture = {**fixture, "nonce": 0xA100000000000000 | index}
            checkpoint = self.markers.checkpoint()
            self._begin_service_request(peer, service, service_fixture)
            timing = peer.finish_service_request()
            self._validate_service_response(timing, service_fixture)
            target = self._target_service(peer_id, timing, checkpoint)
            transcripts[service] = target["response_transcript"]
            peer.peer_disconnect()
            peer.wait_for_disconnect()
        return transcripts

    def _gated_real_pnb_overlap(self, source, p2pk_wallet, seed):
        """Resume a pre-cleared Ping handler while BlockChecked holds real PNB."""
        block, seed = self._build_work_block(p2pk_wallet, seed)
        peer, peer_id = self._new_service_peer("ping")
        fixture = {"nonce": 0xA600000000000000}
        self._announce(source, block)
        checkpoint = self.markers.checkpoint()
        latest_generation = self.markers.arm_gate("handler_pre_poll", peer=peer_id)
        try:
            self._begin_service_request(peer, "ping", fixture)
            ready = self.markers.wait(
                "complete_message_ready", checkpoint, peer=peer_id, msg="ping")
            handler_gate = self.markers.wait_gate(
                "handler_pre_poll", latest_generation, checkpoint,
                peer=peer_id, job=0)
            assert ready["steady_ns"] <= handler_gate["steady_ns"]
            self.markers.assert_absent(
                "handler_start", checkpoint, peer=peer_id,
                msg_id=ready["msg_id"])

            handler_generation = latest_generation
            latest_generation = self.markers.arm_gate("validation_running")
            source.send_without_ping(msg_block(block))
            start = self.markers.wait("pnb_start", checkpoint, hash=block.hash_hex)
            validation_gate = self.markers.wait_gate(
                "validation_running", latest_generation, checkpoint,
                hash=block.hash_hex, job=start["job"], peer=-1)
            assert start["steady_ns"] <= validation_gate["steady_ns"]
            self.markers.assert_absent(
                "pnb_end", checkpoint, hash=block.hash_hex, job=start["job"])

            # Release only the earlier handler latch. The newer validation
            # generation remains held inside the ProcessNewBlock stack.
            self.markers.release_gate(handler_generation, clear=False)
            timing = peer.finish_service_request()
            self._validate_service_response(timing, fixture)
            target = self._target_service(peer_id, timing, checkpoint)
            assert start["steady_ns"] < target["handler_turn_start_ns"]
            assert start["steady_ns"] < target["response_queued_ns"]
            self.markers.assert_absent(
                "pnb_end", checkpoint, hash=block.hash_hex, job=start["job"])
        finally:
            self.markers.release_gate(latest_generation)

        pnb = self._wait_pnb_job(checkpoint, block, "standard")
        assert target["response_queued_ns"] < pnb["end_ns"]
        peer.peer_disconnect()
        peer.wait_for_disconnect()
        return seed, {
            "block_hash": block.hash_hex,
            "handler_start_ns": target["handler_turn_start_ns"],
            "pnb_end_ns": pnb["end_ns"],
            "pnb_start_ns": pnb["start_ns"],
            "response_queued_ns": target["response_queued_ns"],
        }

    def _gated_disconnect_phase(self, phase, source, block):
        gate = {
            "queued": "worker_queued",
            "running": "validation_running",
            "result_ready": "result_ready",
        }[phase]
        self._announce(source, block)
        checkpoint = self.markers.checkpoint()
        generation = self.markers.arm_gate(gate)
        try:
            source.send_without_ping(msg_block(block))
            entered = self.markers.wait(
                "test_gate_entered", checkpoint, gate=PROBE_GATES[gate],
                generation=generation, hash=block.hash_hex)
            job = entered["job"]
            if phase == "queued":
                self.markers.assert_absent(
                    "worker_wake", checkpoint, hash=block.hash_hex, job=job)
                self.markers.assert_absent(
                    "pnb_start", checkpoint, hash=block.hash_hex, job=job)
                self.markers.assert_absent(
                    "pnb_end", checkpoint, hash=block.hash_hex, job=job)
            elif phase == "running":
                self.markers.unique(
                    "pnb_start", checkpoint, hash=block.hash_hex, job=job)
                self.markers.assert_absent(
                    "pnb_end", checkpoint, hash=block.hash_hex, job=job)
                self.markers.assert_absent(
                    "result_publication", checkpoint, hash=block.hash_hex, job=job)
            else:
                self.markers.unique(
                    "pnb_end", checkpoint, hash=block.hash_hex, job=job)
                self.markers.unique(
                    "result_publication", checkpoint, hash=block.hash_hex, job=job)
                self.markers.assert_absent(
                    "result_collection", checkpoint, hash=block.hash_hex, job=job)
                self.markers.assert_absent(
                    "continuation", checkpoint, hash=block.hash_hex, job=job)
            source.peer_disconnect()
            source.wait_for_disconnect()
        finally:
            self.markers.release_gate(generation)
        pnb = self._wait_pnb_job(checkpoint, block, "standard")
        assert pnb["job"] == entered["job"]
        return pnb

    def _gated_running_shutdown(self, source, block):
        node = self.nodes[0]
        self._announce(source, block)
        checkpoint = self.markers.checkpoint()
        generation = self.markers.arm_gate("validation_running")
        stop_errors = []
        stop_thread = None
        try:
            source.send_without_ping(msg_block(block))
            start = self.markers.wait("pnb_start", checkpoint, hash=block.hash_hex)
            self.markers.wait_gate(
                "validation_running", generation, checkpoint,
                hash=block.hash_hex, job=start["job"], peer=-1)
            self.markers.assert_absent(
                "pnb_end", checkpoint, hash=block.hash_hex, job=start["job"])

            def stop_node():
                try:
                    node.stop_node()
                except Exception as error:
                    stop_errors.append(error)

            stop_thread = threading.Thread(target=stop_node, name="gated-node-stop")
            stop_thread.start()
            self.markers.wait("test_shutdown_started", checkpoint)
            self.markers.assert_absent(
                "pnb_end", checkpoint, hash=block.hash_hex, job=start["job"])
        finally:
            self.markers.release_gate(generation)
        assert stop_thread is not None
        stop_thread.join(PING_TIMEOUT * self.options.timeout_factor)
        assert not stop_thread.is_alive() and not stop_errors, stop_errors
        self.markers.wait(
            "pnb_end", checkpoint, hash=block.hash_hex, job=start["job"])
        self.markers.wait(
            "result_collection", checkpoint, hash=block.hash_hex, job=start["job"])
        self.markers.wait("test_interface_unregistered", checkpoint)
        return self._pnb_lifecycle(
            checkpoint, block.hash_hex, start["job"], "standard")

    def _run_quick(self):
        node = self.nodes[0]
        assert node.getblockcount() == 200
        self._initialize_block_inputs()
        seed_addresses = {f"1.2.3.{index}" for index in range(1, 17)}
        for address in sorted(seed_addresses):
            node.addpeeraddress(address, 18444)

        source = node.add_p2p_connection(PeerServicePeer())
        blocker0 = node.add_p2p_connection(PeerServicePeer())
        blocker1 = node.add_p2p_connection(PeerServicePeer())
        blocker2 = node.add_outbound_p2p_connection(
            PeerServicePeer(), p2p_idx=0,
            connection_type="outbound-full-relay")
        source_id = self._map_peer_id(source)
        blocker_ids = [self._map_peer_id(peer) for peer in (blocker0, blocker1, blocker2)]
        for peer in (source, blocker0, blocker1, blocker2):
            peer.send_and_ping(msg_sendcmpct(announce=False, version=2))

        # Prove the three P2P producer forms and their exact continuation kinds.
        full_block = self._quick_block()
        self._deliver_full_block(source, full_block)
        for peer in (blocker1, blocker2):
            setup_block = self._quick_block()
            self._deliver_full_block(peer, setup_block)
        self.wait_until(
            lambda: all(
                next(info for info in node.getpeerinfo() if info["id"] == peer_id)["bip152_hb_to"]
                for peer_id in (source_id, blocker_ids[1], blocker_ids[2])),
            timeout=PING_TIMEOUT, check_interval=MARKER_POLL)

        blocktxn_block = self._quick_block()
        self._deliver_blocktxn_block(source, blocktxn_block)
        optimistic_block = self._quick_block()
        self._deliver_optimistic_compact_block(
            source, (blocker0, blocker1, blocker2), optimistic_block)

        # The service positive control below must contain only the producer and
        # one target peer. In particular, do not let an unrelated producer-proof
        # peer's ordinary SendMessages pass obscure the service mechanism under
        # test.
        for peer in (blocker0, blocker1, blocker2):
            peer.peer_disconnect()
            peer.wait_for_disconnect()
        self.wait_until(
            lambda: ({entry["id"] for entry in node.getpeerinfo()} == {source_id}
                     and node.getconnectioncount() == 1),
            timeout=PING_TIMEOUT, check_interval=MARKER_POLL)

        unknown_tx_hash = int.from_bytes(
            hashlib.sha256(b"async-pnb-peer-service-notfound").digest(), "big")
        base_fixture = {
            "recent_block": optimistic_block,
            "seed_addresses": seed_addresses,
            "unknown_tx_hash": unknown_tx_hash,
        }
        calibration_transcripts = self._prove_service_fixtures(base_fixture)

        # Use one real near-full PNB to prove all fixed services, source fencing,
        # and exact-front producer head-of-line blocking in a single mixed turn.
        address_wallet = MiniWallet(node)
        p2pk_wallet = MiniWallet(node, mode=MiniWalletMode.RAW_P2PK)
        seed, recent_block = self._create_funding(source, address_wallet, p2pk_wallet)
        isolated_block, seed = self._build_work_block(p2pk_wallet, seed)

        isolated_peer, isolated_peer_id = self._new_service_peer("ping")
        isolated_fixture = {
            "nonce": 0xA000000000000000,
            "recent_block": recent_block,
            "seed_addresses": seed_addresses,
            "unknown_tx_hash": unknown_tx_hash,
        }
        self._announce(source, isolated_block)
        isolated_checkpoint = self.markers.checkpoint()
        source.send_without_ping(msg_block(isolated_block))
        isolated_start = self.markers.wait(
            "pnb_start", isolated_checkpoint, hash=isolated_block.hash_hex)
        self._begin_service_request(isolated_peer, "ping", isolated_fixture)
        isolated_timing = isolated_peer.finish_service_request()
        isolated_end = self.markers.wait(
            "pnb_end", isolated_checkpoint, hash=isolated_block.hash_hex,
            job=isolated_start["job"])
        self._wait_tip(isolated_block)
        if self.options.peer_service_mode == "candidate":
            self.markers.wait(
                "result_collection", isolated_checkpoint,
                hash=isolated_block.hash_hex, job=isolated_start["job"])
        self._validate_service_response(isolated_timing, isolated_fixture)
        isolated_target = self._target_service(
            isolated_peer_id, isolated_timing, isolated_checkpoint, {
                "start_ns": isolated_start["steady_ns"],
                "end_ns": isolated_end["steady_ns"],
            })
        assert isolated_target["ready_inside_pnb"]
        # Keep the timing outcome observational. The ordinary prefix may wait
        # on ProcessOrphanTx(cs_main), and this functional oracle must not tune
        # topology or scheduling until a response happens inside PNB.
        isolated_outcome = {
            "handler_turn_started_inside_pnb": (
                isolated_start["steady_ns"]
                < isolated_target["handler_turn_start_ns"]
                < isolated_end["steady_ns"]),
            "ready_inside_pnb": isolated_target["ready_inside_pnb"],
            "response_inside_pnb": isolated_target["response_inside_pnb"],
        }
        self._pnb_lifecycle(
            isolated_checkpoint, isolated_block.hash_hex,
            isolated_start["job"], "standard")
        isolated_peer.peer_disconnect()
        isolated_peer.wait_for_disconnect()

        work_block, seed = self._build_work_block(p2pk_wallet, seed)
        service_entries = []
        for service in SERVICE_CLASSES:
            peer, peer_id = self._new_service_peer(service)
            service_entries.append((service, peer, peer_id))
        refused_peer, refused_peer_id = self._new_service_peer("ping")

        mixed_fixture = {
            "recent_block": recent_block,
            "seed_addresses": seed_addresses,
            "unknown_tx_hash": unknown_tx_hash,
        }
        self._announce(source, work_block)
        checkpoint = self.markers.checkpoint()
        source.send_without_ping(msg_block(work_block))
        start = self.markers.wait("pnb_start", checkpoint, hash=work_block.hash_hex)

        source_fixture = {**mixed_fixture, "nonce": 0xA200000000000000}
        self._begin_service_request(source, "ping", source_fixture)
        refused_peer.send_without_ping(msg_generic(b"block", b""))
        refused_fixture = {**mixed_fixture, "nonce": 0xA300000000000000}
        self._begin_service_request(refused_peer, "ping", refused_fixture)
        order = list(range(len(service_entries)))
        random.Random(self.options.peer_service_seed).shuffle(order)
        fixtures = {}
        for index in order:
            service, peer, _peer_id = service_entries[index]
            fixture = {**mixed_fixture, "nonce": 0xA400000000000000 | index}
            fixtures[service] = fixture
            self._begin_service_request(peer, service, fixture)

        deadline = time.monotonic() + PING_TIMEOUT * self.options.timeout_factor
        timings = {}
        for service, peer, _peer_id in service_entries:
            timings[service] = peer.finish_service_request(deadline - time.monotonic())
        source_timing = source.finish_service_request(deadline - time.monotonic())
        refused_timing = refused_peer.finish_service_request(deadline - time.monotonic())

        end = self.markers.wait(
            "pnb_end", checkpoint, hash=work_block.hash_hex, job=start["job"])
        self._wait_tip(work_block)
        if self.options.peer_service_mode == "candidate":
            self.markers.wait(
                "result_publication", checkpoint,
                hash=work_block.hash_hex, job=start["job"])
            collection = self.markers.wait(
                "result_collection", checkpoint,
                hash=work_block.hash_hex, job=start["job"])
        else:
            collection = {"steady_ns": end["steady_ns"]}
        self._pnb_lifecycle(
            checkpoint, work_block.hash_hex, start["job"], "standard")
        pnb = {
            "duration_ns": end["duration_ns"],
            "end_ns": end["steady_ns"],
            "job": start["job"],
            "start_ns": start["steady_ns"],
        }

        mixed_transcripts = {}
        mixed_outcomes = {}
        for service, _peer, peer_id in service_entries:
            timing = timings[service]
            self._validate_service_response(timing, fixtures[service])
            target = self._target_service(peer_id, timing, checkpoint, pnb)
            assert target["ready_inside_pnb"]
            mixed_transcripts[service] = target["response_transcript"]
            mixed_outcomes[service] = {
                "ready_inside_pnb": target["ready_inside_pnb"],
                "response_inside_pnb": target["response_inside_pnb"],
            }

        self._validate_service_response(source_timing, source_fixture)
        source_target = self._target_service(source_id, source_timing, checkpoint, pnb)
        assert source_target["ready_inside_pnb"]
        assert source_target["response_queued_ns"] >= collection["steady_ns"]
        self._validate_service_response(refused_timing, refused_fixture)
        refused_target = self._target_service(
            refused_peer_id, refused_timing, checkpoint, pnb)
        assert refused_target["ready_inside_pnb"]
        assert refused_target["response_queued_ns"] >= end["steady_ns"]

        # The mixed oracle is complete. Lifecycle gates below intentionally
        # isolate the source and one pre-cleared target so an unrelated
        # ordinary SendMessages cs_main wait cannot masquerade as a failure of
        # that specific receive-boundary authority.
        for _service, peer, _peer_id in service_entries:
            peer.peer_disconnect()
            peer.wait_for_disconnect()
        refused_peer.peer_disconnect()
        refused_peer.wait_for_disconnect()

        # Invalid-source punishment is applied before its later PING can run.
        invalid_source = node.add_p2p_connection(PeerServicePeer())
        invalid_block = self._invalid_quick_block()
        self._announce(invalid_source, invalid_block)
        invalid_checkpoint = self.markers.checkpoint()
        invalid_source.send_without_ping(msg_block(invalid_block))
        invalid_start = self.markers.wait(
            "pnb_start", invalid_checkpoint, hash=invalid_block.hash_hex)
        invalid_nonce = 0xA500000000000000
        invalid_source.send_without_ping(msg_ping(invalid_nonce))
        self.markers.wait(
            "pnb_end", invalid_checkpoint, hash=invalid_block.hash_hex,
            job=invalid_start["job"])
        if self.options.peer_service_mode == "candidate":
            self.markers.wait(
                "result_collection", invalid_checkpoint,
                hash=invalid_block.hash_hex, job=invalid_start["job"])
        invalid_source.wait_for_disconnect(timeout=PING_TIMEOUT)
        assert node.getbestblockhash() == work_block.hash_hex
        assert invalid_nonce not in invalid_source.pong_nonces
        self._pnb_lifecycle(
            invalid_checkpoint, invalid_block.hash_hex,
            invalid_start["job"], "standard")

        overlap_outcome = None
        if self.options.peer_service_mode == "candidate":
            seed, overlap_outcome = self._gated_real_pnb_overlap(
                source, p2pk_wallet, seed)
            # Disconnect at each authoritative occupied phase. Every gate is
            # released in a finally block so a failed quick oracle cannot
            # leave the node unkillable.
            for phase in ("queued", "running", "result_ready"):
                disconnect_source = node.add_p2p_connection(PeerServicePeer())
                self._gated_disconnect_phase(
                    phase, disconnect_source, self._quick_block())
        else:
            disconnect_source = node.add_p2p_connection(PeerServicePeer())
            disconnect_block = self._quick_block()
            self._announce(disconnect_source, disconnect_block)
            disconnect_checkpoint = self.markers.checkpoint()
            disconnect_source.send_without_ping(msg_block(disconnect_block))
            disconnect_start = self.markers.wait(
                "pnb_start", disconnect_checkpoint, hash=disconnect_block.hash_hex)
            disconnect_source.peer_disconnect()
            disconnect_source.wait_for_disconnect()
            self._wait_pnb_job(disconnect_checkpoint, disconnect_block, "standard")

        # Candidate shutdown is initiated while BlockChecked authoritatively
        # holds the worker inside the ProcessNewBlock stack. Control retains
        # the same synchronous completion/restart oracle without a phase claim.
        shutdown_source = node.add_p2p_connection(PeerServicePeer())
        shutdown_block, _seed = self._build_work_block(p2pk_wallet, seed)
        expected_height = node.getblockcount() + 1
        if self.options.peer_service_mode == "candidate":
            self._gated_running_shutdown(shutdown_source, shutdown_block)
        else:
            self._announce(shutdown_source, shutdown_block)
            shutdown_checkpoint = self.markers.checkpoint()
            shutdown_source.send_without_ping(msg_block(shutdown_block))
            shutdown_start = self.markers.wait(
                "pnb_start", shutdown_checkpoint, hash=shutdown_block.hash_hex)
            node.stop_node()
            self.markers.wait(
                "pnb_end", shutdown_checkpoint, hash=shutdown_block.hash_hex,
                job=shutdown_start["job"])
            self._pnb_lifecycle(
                shutdown_checkpoint, shutdown_block.hash_hex,
                shutdown_start["job"], "standard")
            self.markers.wait("test_interface_unregistered", shutdown_checkpoint)

        first_process_end = self.markers.checkpoint()
        assert len([
            event for event in self.markers.events[:first_process_end]
            if event["event"] == "test_interface_registered"
        ]) == 1
        assert len([
            event for event in self.markers.events[:first_process_end]
            if event["event"] == "test_interface_unregistered"
        ]) == 1

        restart_checkpoint = self.markers.checkpoint()
        self.start_node(0)
        self.markers.wait("test_interface_registered", restart_checkpoint)
        assert node.getblockcount() == expected_height
        assert node.getbestblockhash() == shutdown_block.hash_hex

        # Stop the restarted process explicitly so register/unregister counts
        # and the final gate header are authoritative before quick success.
        second_checkpoint = self.markers.checkpoint()
        node.stop_node()
        self.markers.wait("test_shutdown_started", second_checkpoint)
        self.markers.wait("test_interface_unregistered", second_checkpoint)
        probe = self.markers.finalize(require_gate_none=True)
        assert len(probe["files"]) == 2
        assert all(file["test_gate_error"] == 0 for file in probe["files"])
        assert len([
            event for event in self.markers.events
            if event["event"] == "test_interface_registered"
        ]) == 2
        assert len([
            event for event in self.markers.events
            if event["event"] == "test_interface_unregistered"
        ]) == 2
        self.markers.remove_files()

        self.log.info(
            "Deterministic input identity start_hash=%s end_hash=%s ordered_sha256=%s calibration=%s isolated=%s overlap=%s mixed=%s",
            self.chain_start["hash"], shutdown_block.hash_hex,
            self.block_input_hasher.hexdigest(), calibration_transcripts,
            isolated_outcome,
            overlap_outcome,
            {"outcomes": mixed_outcomes, "transcripts": mixed_transcripts})

    def _provenance(self, node, binary):
        source_dir = Path(self.config["environment"]["SRCDIR"])
        build_dir = Path(self.config["environment"]["BUILDDIR"])
        cache_path = build_dir / "CMakeCache.txt"
        cache_text = cache_path.read_text(encoding="utf-8")
        cache = {}
        for line in cache_text.splitlines():
            if line.startswith(("#", "//")) or "=" not in line or ":" not in line.split("=", 1)[0]:
                continue
            typed_key, value = line.split("=", 1)
            key = typed_key.split(":", 1)[0]
            cache[key] = value
        compiler = cache.get("CMAKE_CXX_COMPILER", "")
        compiler_version = subprocess.run(
            [compiler, "--version"], check=True, capture_output=True, text=True
        ).stdout.splitlines()[0]
        cpuinfo = Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="replace")
        cpu_model = next((line.split(":", 1)[1].strip() for line in cpuinfo.splitlines()
                          if line.startswith("model name")), "unknown")
        lscpu_output = json.loads(subprocess.run(
            ["lscpu", "--json"], check=True, capture_output=True, text=True).stdout)
        lscpu = {item["field"].rstrip(":"): item.get("data") for item in lscpu_output["lscpu"]}
        process_status = Path(f"/proc/{node.process.pid}/status").read_text(encoding="ascii")
        status_fields = {}
        for key in ("Cpus_allowed_list", "Mems_allowed_list"):
            status_fields[key.lower()] = next(
                line.split(":", 1)[1].strip() for line in process_status.splitlines()
                if line.startswith(f"{key}:")
            )
        cgroup_membership = Path(f"/proc/{node.process.pid}/cgroup").read_text(
            encoding="ascii").splitlines()
        cgroup_limits = {}
        unified = next((line.split(":", 2)[2] for line in cgroup_membership
                        if line.startswith("0::")), None)
        if unified is not None:
            cgroup_dir = Path("/sys/fs/cgroup") / unified.lstrip("/")
            for name in ("cpu.max", "cpuset.cpus.effective", "cpuset.mems.effective", "memory.max"):
                path = cgroup_dir / name
                if path.exists():
                    cgroup_limits[name] = path.read_text(encoding="ascii").strip()
        meminfo = Path("/proc/meminfo").read_text(encoding="ascii")
        mem_total_kib = int(next(line.split()[1] for line in meminfo.splitlines()
                                 if line.startswith("MemTotal:")))
        datadir = Path(node.datadir_path).resolve()
        statvfs = os.statvfs(datadir)
        storage = json.loads(subprocess.run(
            ["findmnt", "--json", "--bytes", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS,SIZE,AVAIL",
             "-T", str(datadir)], check=True, capture_output=True, text=True).stdout)["filesystems"][0]
        selected_cache = {
            key: cache.get(key) for key in (
                "CMAKE_BUILD_TYPE", "CMAKE_CXX_COMPILER", "CMAKE_CXX_FLAGS",
                "CMAKE_EXE_LINKER_FLAGS", "BUILD_BENCH", "BUILD_GUI", "WITH_CCACHE",
            )
        }
        source_status = subprocess.run(
            ["git", "-C", str(source_dir), "status", "--porcelain=v1"],
            check=True, capture_output=True, text=True).stdout
        return {
            "binary": str(binary.resolve()),
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "cmake_cache": selected_cache,
            "cmake_cache_sha256": hashlib.sha256(cache_text.encode()).hexdigest(),
            "clock_ticks_per_second": os.sysconf("SC_CLK_TCK"),
            "command": sys.argv,
            "compiler_version": compiler_version,
            "cpu_count": os.cpu_count(),
            "cpu_model": cpu_model,
            "cpu_topology": {
                "cores_per_socket": lscpu.get("Core(s) per socket"),
                "logical_cpus": lscpu.get("CPU(s)"),
                "numa_nodes": lscpu.get("NUMA node(s)"),
                "online_cpus": lscpu.get("On-line CPU(s) list"),
                "sockets": lscpu.get("Socket(s)"),
                "threads_per_core": lscpu.get("Thread(s) per core"),
            },
            "effective_affinity": {
                "cpu_count": len(os.sched_getaffinity(node.process.pid)),
                "cpus": sorted(os.sched_getaffinity(node.process.pid)),
                **status_fields,
            },
            "framework_portseed_option": self.options.port_seed,
            "cgroup": {"limits": cgroup_limits, "membership": cgroup_membership},
            "git_head": subprocess.run(
                ["git", "-C", str(source_dir), "rev-parse", "HEAD"],
                check=True, capture_output=True, text=True).stdout.strip(),
            "git_tree": subprocess.run(
                ["git", "-C", str(source_dir), "rev-parse", "HEAD^{tree}"],
                check=True, capture_output=True, text=True).stdout.strip(),
            "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "kernel": platform.uname()._asdict(),
            "mem_total_kib": mem_total_kib,
            "node_argv": node.args,
            "source_clean": not source_status,
            "source_status": source_status.splitlines(),
            "storage": {"datadir": str(datadir), "mount": storage},
            "storage_available_bytes": statvfs.f_bavail * statvfs.f_frsize,
            "storage_total_bytes": statvfs.f_blocks * statvfs.f_frsize,
        }

    def _run_campaign(self):
        node = self.nodes[0]
        assert node.getblockcount() == 200 and not node.getblockchaininfo()["initialblockdownload"]
        self._initialize_block_inputs()
        seed_addresses = {f"1.2.3.{index}" for index in range(1, 17)}
        for address in sorted(seed_addresses):
            node.addpeeraddress(address, 18444)

        setup_peer = node.add_p2p_connection(PeerServicePeer())
        address_wallet = MiniWallet(node)
        p2pk_wallet = MiniWallet(node, mode=MiniWalletMode.RAW_P2PK)
        seed, recent_block = self._create_funding(
            setup_peer, address_wallet, p2pk_wallet)
        node.disconnect_p2ps()
        self.wait_until(
            lambda: not node.getpeerinfo() and node.getconnectioncount() == 0,
            timeout=PING_TIMEOUT, check_interval=MARKER_POLL)

        source = node.add_p2p_connection(PeerServicePeer())
        self.source_id = self._map_peer_id(source)
        source.send_and_ping(msg_sendcmpct(announce=False, version=2))
        fixture = {
            "recent_block": recent_block,
            "seed_addresses": seed_addresses,
            "unknown_tx_hash": int.from_bytes(
                hashlib.sha256(b"async-pnb-peer-service-notfound").digest(), "big"),
        }
        calibration_transcripts = self._calibrate_service_fixtures(fixture)
        self._write_sample({
            "kind": "calibration_summary",
            "mode": self.options.peer_service_mode,
            "services": list(SERVICE_CLASSES),
            "transcripts": calibration_transcripts,
        })

        # One real near-full service trial for each audited producer route.
        # These are route probes, not part of the retained class aggregates.
        serial = 0
        block, seed = self._build_work_block(p2pk_wallet, seed)
        serial += 1
        self._measure_isolated_trial(
            source, block, fixture, "ping", "source_form", 0, serial,
            producer_form="full_block")
        fixture["recent_block"] = block
        self.wait_until(
            lambda: next(info for info in node.getpeerinfo()
                         if info["id"] == self.source_id)["bip152_hb_to"],
            timeout=PING_TIMEOUT, check_interval=MARKER_POLL)

        block, seed = self._build_work_block(p2pk_wallet, seed)
        serial += 1
        self._measure_isolated_trial(
            source, block, fixture, "ping", "source_form", 1, serial,
            producer_form="blocktxn")
        fixture["recent_block"] = block

        blocker0 = node.add_p2p_connection(PeerServicePeer())
        blocker1 = node.add_p2p_connection(PeerServicePeer())
        blocker2 = node.add_outbound_p2p_connection(
            PeerServicePeer(), p2p_idx=0,
            connection_type="outbound-full-relay")
        blocker_ids = [self._map_peer_id(peer)
                       for peer in (blocker0, blocker1, blocker2)]
        for peer in (blocker0, blocker1, blocker2):
            peer.send_and_ping(msg_sendcmpct(announce=False, version=2))
        for peer in (blocker1, blocker2):
            self._deliver_full_block(peer, self._quick_block())
        self.wait_until(
            lambda: all(
                next(info for info in node.getpeerinfo()
                     if info["id"] == peer_id)["bip152_hb_to"]
                for peer_id in blocker_ids[1:]),
            timeout=PING_TIMEOUT, check_interval=MARKER_POLL)
        block, seed = self._build_work_block(p2pk_wallet, seed)
        serial += 1
        self._measure_isolated_trial(
            source, block, fixture, "ping", "source_form", 2, serial,
            producer_form="optimistic_compact",
            blockers=(blocker0, blocker1, blocker2))
        fixture["recent_block"] = block
        for peer in (blocker0, blocker1, blocker2):
            peer.peer_disconnect()
            peer.wait_for_disconnect()
        self.wait_until(
            lambda: ({entry["id"] for entry in node.getpeerinfo()} == {self.source_id}
                     and node.getconnectioncount() == 1),
            timeout=PING_TIMEOUT, check_interval=MARKER_POLL)

        profile = PROFILES[self.options.peer_service_profile]
        for phase, count in (("warmup", profile["isolated_warmups"]),
                             ("trial", profile["isolated_trials"])):
            for trial in range(count):
                for service in SERVICE_CLASSES:
                    block, seed = self._build_work_block(p2pk_wallet, seed)
                    serial += 1
                    self._measure_isolated_trial(
                        source, block, fixture, service, phase, trial, serial)
                    fixture["recent_block"] = block
        for trial in range(profile["mixed_trials"]):
            block, seed = self._build_work_block(p2pk_wallet, seed)
            serial += 1
            self._measure_mixed_trial(
                source, block, fixture, trial, serial)
            fixture["recent_block"] = block
        assert {entry["id"] for entry in node.getpeerinfo()} == {self.source_id}
        assert node.getconnectioncount() == 1
        assert source.is_connected

    def _block_identity(self):
        return {
            "count": len(self.block_inputs),
            "items": self.block_inputs,
            "ordered_sha256": self.block_input_hasher.hexdigest(),
        }

    @staticmethod
    def _node_args_without_mode(args, mode):
        prefix = "-asyncpnbpeerservice="
        mode_args = [arg for arg in args if arg.startswith(prefix)]
        assert mode_args == [f"{prefix}{int(mode == 'candidate')}"]
        gate_args = [
            arg for arg in args if arg.startswith("-asyncpnbpeerservicetestgates=")]
        assert gate_args == ["-asyncpnbpeerservicetestgates=0"], \
            "retained profiles must disable lifecycle gates"
        probe_args = [
            arg for arg in args if arg.startswith("-asyncpnbpeerserviceprobedir=")]
        assert len(probe_args) == 1
        assert Path(probe_args[0].split("=", 1)[1]).is_absolute()
        return [
            "-asyncpnbpeerserviceprobedir=<per-run-tmpdir>"
            if arg.startswith("-asyncpnbpeerserviceprobedir=") else arg
            for arg in args if not arg.startswith(prefix)
        ]

    def _validate_reference_environment(self):
        if self.reference_run is None:
            return None
        assert self.reference_run.get("failure") is None, "paired reference run failed"
        assert self.reference_run.get("identity_check", {}).get("status") in {"passed", "unpaired"}, \
            "paired reference identity status is not successful"
        reference_mode = self.reference_run["mode"]
        assert {reference_mode, self.options.peer_service_mode} == {"control", "candidate"}, \
            "paired runs must use opposite modes"
        assert self._node_args_without_mode(
            self.reference_run["node_args"], reference_mode) == self._node_args_without_mode(
                self.extra_args[0], self.options.peer_service_mode), \
            "paired node arguments differ beyond -asyncpnbpeerservice"
        reference_provenance = self.reference_run["provenance"]
        for key in ("binary_sha256", "cmake_cache_sha256", "git_head", "git_tree", "harness_sha256"):
            assert reference_provenance[key] == self.provenance[key], f"paired {key} mismatch"
        assert reference_provenance["source_clean"] and self.provenance["source_clean"], \
            "paired measurements require a clean source tree"
        assert self.reference_run["framework_portseed_option"] == self.options.port_seed, \
            "paired framework port seed mismatch"
        return reference_mode

    def _check_reference_identity(self):
        reference_mode = self._validate_reference_environment()
        if reference_mode is None:
            return {"reference_run": None, "status": "unpaired"}
        expected = {
            "block_inputs": self.reference_run["block_inputs"],
            "chain": self.reference_run["chain"],
            "framework_randomseed_option": self.reference_run["framework_randomseed_option"],
            "framework_portseed_option": self.reference_run["framework_portseed_option"],
            "profile": self.reference_run["profile"],
            "refresh_block": self.reference_run["refresh_block"],
            "seed": self.reference_run["seed"],
            "trial_inputs": self.reference_run["trial_inputs"],
        }
        observed = {
            "block_inputs": self._block_identity(),
            "chain": {"start": self.chain_start, "end": self.chain_end},
            "framework_randomseed_option": self.options.randomseed,
            "framework_portseed_option": self.options.port_seed,
            "profile": self.options.peer_service_profile,
            "refresh_block": self.refresh_block,
            "seed": self.options.peer_service_seed,
            "trial_inputs": self.trial_inputs,
        }
        assert observed == expected, "candidate/control workload identity mismatch"
        return {"reference_mode": reference_mode, "reference_run": self.reference_run_path,
                "status": "passed"}

    def run_test(self):
        self.pause_metrics = {"pause_observations": 0, "snapshots_checked": 0}
        self.trial_inputs = []
        if self.options.output_dir is None:
            self._run_quick()
            return

        self._prepare_output()
        node = self.nodes[0]
        debug_log = node.debug_log_path
        pid = node.process.pid
        binary = Path(node.args[0])
        provenance = self._provenance(node, binary)
        self.provenance = provenance
        sampler = ResourceSampler(pid, self.output_dir / "resource.csv")
        self.aggregate = self._empty_campaign_aggregate()
        self.warmup_aggregate = self._empty_campaign_aggregate()
        self.block_inputs = []
        self.block_input_hasher = hashlib.sha256()
        self.chain_start = None
        self.chain_end = None
        started_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        started_ns = time.perf_counter_ns()
        failures = []

        def record_failure(stage, error):
            failures.append({"stage": stage, "reason": f"{type(error).__name__}: {error}"})

        try:
            # Reject same-mode, different-binary, source, build-config, harness,
            # or node-argument references before constructing expensive blocks.
            self._validate_reference_environment()
            self._run_campaign()
            self.chain_end = {"hash": node.getbestblockhash(), "height": node.getblockcount()}
            identity_check = self._check_reference_identity()
        except Exception as error:
            record_failure("campaign", error)
            identity_check = {"reference_run": self.options.peer_service_reference_run, "status": "failed"}
            if self.chain_start is not None:
                try:
                    self.chain_end = {"hash": node.getbestblockhash(), "height": node.getblockcount()}
                except Exception as endpoint_error:
                    record_failure("failure_endpoint", endpoint_error)
        try:
            node.stop_node()
        except Exception as error:
            record_failure("shutdown", error)
        for stage, cleanup in (
            ("resource_sampler", sampler.stop),
            ("samples_file", self.samples_file.close),
        ):
            try:
                cleanup()
            except Exception as error:
                record_failure(stage, error)

        probe_paths = [str(path) for path in sorted(self.markers.file_paths)]
        probe = {
            "events_artifact": "target.log",
            "preserved_paths": probe_paths,
            "status": "failed",
        }
        probe_lines = None
        try:
            probe = {
                **self.markers.finalize(require_gate_none=True),
                "events_artifact": "target.log",
                "status": "parsed",
            }
            assert all(file["status"] == 0 for file in probe["files"]), probe
            assert all(file["test_gate"] == PROBE_GATES["none"] for file in probe["files"]), probe
            probe_lines = self.markers.marker_lines()
        except Exception as error:
            record_failure("probe_parse", error)

        target_log_ok = False
        try:
            target_log = self.output_dir / "target.log"
            shutil.copyfile(debug_log, target_log)
            if probe_lines is not None:
                with target_log.open("a", encoding="utf-8") as output:
                    output.writelines(probe_lines)
            target_log_ok = True
        except Exception as error:
            record_failure("target_log", error)

        # A failed run keeps PID files in the per-run tmpdir as evidence. A
        # successful parse is serialized into the four existing artifacts,
        # after which the ephemeral mappings are removed.
        if not failures and target_log_ok and probe_lines is not None:
            try:
                probe["removed_paths"] = self.markers.remove_files()
                probe["status"] = "parsed_and_removed"
            except Exception as error:
                record_failure("probe_cleanup", error)
                probe["preserved_paths"] = probe_paths
        else:
            probe["preserved_paths"] = probe_paths

        failure = "; ".join(
            f"{item['stage']}: {item['reason']}" for item in failures
        ) or None

        self._write_json(self.output_dir / "run.json", {
            "aggregate": self.aggregate,
            "block_inputs": self._block_identity(),
            "chain": {"start": self.chain_start, "end": self.chain_end},
            "ended_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "failure": failure,
            "failures": failures,
            "identity_check": identity_check,
            "mode": self.options.peer_service_mode, "node_args": self.extra_args[0],
            "pause_metrics": {**self.pause_metrics,
                              "zero_pause_proof": self.pause_metrics["pause_observations"] == 0},
            "profile": self.options.peer_service_profile, "schema_version": 2,
            "probe": probe,
            "provenance": provenance,
            "refresh_block": self.refresh_block,
            "framework_portseed_option": self.options.port_seed,
            "framework_randomseed_option": self.options.randomseed,
            "input_random_seed": self.options.peer_service_seed,
            "seed": self.options.peer_service_seed, "started_utc": started_utc,
            "trial_inputs": self.trial_inputs,
            "warmup_aggregate": self.warmup_aggregate,
            "wall_ns": time.perf_counter_ns() - started_ns,
        })
        if failure is not None:
            raise AssertionError(failure)


if __name__ == "__main__":
    AsyncPNBPeerService(__file__).main()
