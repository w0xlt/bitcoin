#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Functional smoke and local async-PNB peer-service measurement harness."""

import csv
import hashlib
import json
import os
import platform
import random
import shutil
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
    MSG_TYPE_MASK,
    WITNESS_SCALE_FACTOR,
    CBlockHeader,
    msg_block,
    msg_getaddr,
    msg_headers,
    msg_ping,
)
from test_framework.p2p import P2PInterface, P2P_SUBVERSION, p2p_lock
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

PROFILES = {
    "curve": {"loads": [1, 10, 25, 50, 100], "warmups": 2, "trials": 20},
    "smoke": {"loads": [1, 10], "warmups": 0, "trials": 2},
    "mixed": {"loads": [25], "warmups": 2, "trials": 20},
    "default": {"loads": [50], "warmups": 2, "trials": 20},
}


class PeerServicePeer(P2PInterface):
    def __init__(self):
        super().__init__()
        self.block_requests = []
        self.ping = None

    def on_getdata(self, message):
        for inv in message.inv:
            if (inv.type & MSG_TYPE_MASK) == MSG_BLOCK:
                self.block_requests.append(inv.hash)

    def on_inv(self, message):
        pass

    def on_pong(self, message):
        if self.ping is None or message.nonce != self.ping["nonce"]:
            return
        self.ping["responses"].append(time.perf_counter_ns())
        self.ping["event"].set()

    def begin_ping(self, nonce):
        with p2p_lock:
            assert self.is_connected
            assert self.ping is None
            self.ping = {
                "nonce": nonce,
                "sent_ns": time.perf_counter_ns(),
                "responses": [],
                "event": threading.Event(),
            }
            self.send_without_ping(msg_ping(nonce))

    def finish_ping(self, timeout):
        with p2p_lock:
            ping = self.ping
            assert ping is not None
        completed = ping["event"].wait(max(0, timeout) * self.timeout_factor)
        with p2p_lock:
            responses = list(ping["responses"])
            connected = self.is_connected
            self.ping = None
        return {
            "completed": completed and len(responses) == 1,
            "connected": connected,
            "nonce": ping["nonce"],
            "request_sent_ns": ping["sent_ns"],
            "response_received_ns": responses[0] if responses else None,
            "response_count": len(responses),
        }

    def wait_for_block_request(self, block_hash):
        self.wait_until(lambda: self.block_requests.count(block_hash) >= 1, timeout=PING_TIMEOUT)
        assert self.block_requests.count(block_hash) == 1


class MarkerReader:
    def __init__(self, path, timeout_factor):
        self.path = Path(path)
        self.offset = 0
        self.events = []
        self.timeout = PING_TIMEOUT * timeout_factor

    @staticmethod
    def parse(line):
        marker_at = line.find(MARKER_PREFIX)
        if marker_at < 0:
            return None
        values = {}
        for item in line[marker_at + len(MARKER_PREFIX):].strip().split():
            if "=" not in item:
                continue
            key, value = item.split("=", 1)
            if value.lstrip("-").isdigit():
                value = int(value)
            values[key] = value
        return values if "event" in values else None

    def poll(self):
        with self.path.open(encoding="utf-8", errors="replace") as log:
            log.seek(self.offset)
            for line in log:
                marker = self.parse(line)
                if marker is not None:
                    marker["sequence"] = len(self.events) + 1
                    self.events.append(marker)
            self.offset = log.tell()

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
            except FileNotFoundError:
                continue
            threads += 1
            voluntary += int(next(line.split()[1] for line in task_status if line.startswith("voluntary_ctxt_switches:")))
            involuntary += int(next(line.split()[1] for line in task_status if line.startswith("nonvoluntary_ctxt_switches:")))
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
            except FileNotFoundError:
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
        parser.add_argument("--peer-service-seed", type=int, default=0xA51C0DE)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = False
        self.uses_wallet = False
        mode = self.options.peer_service_mode
        profile = self.options.peer_service_profile
        args = [
            f"-asyncpnbpeerservice={int(mode == 'candidate')}",
            "-loglevel=info",
            "-maxconnections=150",
            "-nodebug",
            "-nologratelimit",
            "-persistmempool=0",
            "-v2transport=0",
        ]
        if profile != "default":
            args += ["-par=1", "-prevoutfetchthreads=0"]
        self.extra_args = [args]

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

    def _write_sample(self, sample):
        self.samples_file.write(json.dumps(sample, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n")
        self.samples_file.flush()

    def _map_peer_id(self, peer):
        sock = peer._transport.get_extra_info("socket")
        local = sock.getsockname()
        addr = f"{local[0]}:{local[1]}"
        matches = [entry for entry in self.nodes[0].getpeerinfo()
                   if entry["addr"] == addr and entry["subver"] == P2P_SUBVERSION]
        assert len(matches) == 1
        return matches[0]["id"]

    def _announce(self, peer, block):
        assert peer.block_requests.count(block.hash_int) == 0
        peer.send_without_ping(msg_headers([CBlockHeader(block)]))
        peer.wait_for_block_request(block.hash_int)

    def _wait_tip(self, block):
        self.wait_until(lambda: self.nodes[0].getbestblockhash() == block.hash_hex,
                        timeout=PING_TIMEOUT, check_interval=MARKER_POLL)

    def _quick_block(self):
        template = self.nodes[0].getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        block = create_block(tmpl=template, coinbase=create_coinbase(template["height"]))
        block.solve()
        assert block.is_valid()
        return block

    def _create_funding(self, setup_peer, address_wallet, p2pk_wallet):
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
        self._announce(setup_peer, block)
        setup_peer.send_without_ping(msg_block(block))
        self._wait_tip(block)
        return seed

    def _build_work_block(self, wallet, seed):
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
        return block, included[-1]["new_utxo"]

    def _target_ping(self, peer_id, timing, checkpoint, pnb=None):
        if not timing["completed"]:
            return None
        response = self.markers.wait("response_queued", checkpoint,
                                     peer=peer_id, nonce=timing["nonce"])
        msg_id = response["msg_id"]
        ready = self.markers.wait("complete_message_ready", checkpoint,
                                  peer=peer_id, msg_id=msg_id)
        start = self.markers.wait("handler_start", checkpoint, peer=peer_id, msg_id=msg_id)
        complete = self.markers.wait("handler_complete", checkpoint, peer=peer_id, msg_id=msg_id)
        for event in ("complete_message_ready", "handler_start", "response_queued", "handler_complete"):
            self.markers.unique(event, checkpoint, peer=peer_id, msg_id=msg_id)
        target = {
            "active_job": response["job"],
            "handler_complete_ns": complete["steady_ns"],
            "handler_processing_ns": complete["steady_ns"] - start["steady_ns"],
            "handler_queue_delay_ns": start["steady_ns"] - ready["steady_ns"],
            "message_id": msg_id,
            "node_service_latency_ns": response["steady_ns"] - ready["steady_ns"],
            "poll_ns": start["poll_ns"],
            "poll_pause_recv": start["poll_pause_recv"],
            "poll_queue_bytes": start["poll_queue_bytes"],
            "poll_queue_depth": start["poll_queue_depth"],
            "ready_ns": ready["steady_ns"],
            "ready_pause_recv": ready["pause_recv"],
            "ready_queue_bytes": ready["queue_bytes"],
            "ready_queue_depth": ready["queue_depth"],
            "response_queued_ns": response["steady_ns"],
            "send_pause": response["pause_send"],
            "send_queue_bytes": response["send_queue_bytes"],
            "send_queue_depth": response["send_queue_depth"],
        }
        if pnb is not None:
            target["ready_inside_pnb"] = pnb["start_ns"] < target["ready_ns"] < pnb["end_ns"]
            target["response_inside_pnb"] = pnb["start_ns"] < target["response_queued_ns"] < pnb["end_ns"]
        return target

    def _calibrate(self, peer, peer_id, load, phase, trial, peer_index, nonce):
        checkpoint = self.markers.checkpoint()
        peer.begin_ping(nonce)
        timing = peer.finish_ping(PING_TIMEOUT)
        assert timing["completed"] and timing["connected"]
        target = self._target_ping(peer_id, timing, checkpoint)
        self._write_sample({
            "kind": "calibration", "load": load, "mode": self.options.peer_service_mode,
            "peer_id": peer_id, "peer_index": peer_index, "phase": phase, "trial": trial,
            "nonce": nonce, "request_sent_ns": timing["request_sent_ns"],
            "response_received_ns": timing["response_received_ns"],
            "peer_rtt_ns": timing["response_received_ns"] - timing["request_sent_ns"],
            "target": target,
        })

    def _measure_trial(self, source, peers, peer_ids, block, load, phase, trial, serial, mixed):
        for index, (peer, peer_id) in enumerate(zip(peers, peer_ids)):
            nonce = 0xC000000000000000 | (serial << 12) | index
            self._calibrate(peer, peer_id, load, phase, trial, index, nonce)

        self._announce(source, block)
        checkpoint = self.markers.checkpoint()
        source.send_without_ping(msg_block(block))
        pnb_start = self.markers.wait("pnb_start", checkpoint, hash=block.hash_hex)
        job = pnb_start["job"]

        order = list(range(load))
        random.Random(self.options.peer_service_seed + serial).shuffle(order)
        refused = set(order[:load // 2]) if mixed else set()
        timings = {}
        for index in order:
            if index in refused:
                peers[index].send_without_ping(msg_getaddr())
            nonce = 0xD000000000000000 | (serial << 12) | index
            peers[index].begin_ping(nonce)
        deadline = time.monotonic() + PING_TIMEOUT * self.options.timeout_factor
        for index in order:
            timings[index] = peers[index].finish_ping(deadline - time.monotonic())

        pnb_end = self.markers.wait("pnb_end", checkpoint, hash=block.hash_hex, job=job)
        pnb = {
            "duration_ns": pnb_end["duration_ns"], "end_ns": pnb_end["steady_ns"],
            "job": job, "start_ns": pnb_start["steady_ns"],
        }
        self._wait_tip(block)
        submit = self.markers.wait("job_submit", checkpoint, hash=block.hash_hex, job=job)
        assert submit["source"] == self.source_id
        if self.options.peer_service_mode == "candidate":
            self.markers.wait("worker_wake", checkpoint, hash=block.hash_hex, job=job)
            self.markers.wait("result_publication", checkpoint, hash=block.hash_hex, job=job)
            self.markers.wait("result_collection", checkpoint, hash=block.hash_hex, job=job)

        completed = 0
        ready_inside = 0
        response_inside = 0
        for index in range(load):
            timing = timings[index]
            target = self._target_ping(peer_ids[index], timing, checkpoint, pnb)
            completed += int(timing["completed"])
            ready_inside += int(target is not None and target["ready_inside_pnb"])
            response_inside += int(target is not None and target["response_inside_pnb"])
            self._write_sample({
                "kind": "request", "block_hash": block.hash_hex, "front_refused": index in refused,
                "load": load, "mode": self.options.peer_service_mode, "peer_id": peer_ids[index],
                "peer_index": index, "phase": phase, "trial": trial, "nonce": timing["nonce"],
                "completed": timing["completed"], "connected": timing["connected"],
                "response_count": timing["response_count"], "request_sent_ns": timing["request_sent_ns"],
                "response_received_ns": timing["response_received_ns"],
                "peer_rtt_ns": (timing["response_received_ns"] - timing["request_sent_ns"]
                                if timing["response_received_ns"] is not None else None),
                "target": target, "pnb": pnb,
            })
        assert ready_inside > 0, "no request overlapped real PNB"
        if self.options.peer_service_profile == "smoke":
            assert completed == load
            assert response_inside > 0
        self._write_sample({
            "kind": "trial", "block_hash": block.hash_hex, "completed": completed,
            "failed": load - completed, "load": load, "mode": self.options.peer_service_mode,
            "offered": load, "phase": phase, "pnb": pnb, "ready_inside_pnb": ready_inside,
            "response_inside_pnb": response_inside, "timed_out": sum(not value["completed"] for value in timings.values()),
            "trial": trial,
        })
        self.aggregate["offered"] += load
        self.aggregate["completed"] += completed
        self.aggregate["failed"] += load - completed
        self.aggregate["response_inside_pnb"] += response_inside

    def _run_quick(self):
        node = self.nodes[0]
        assert node.getblockcount() == 200
        source = node.add_p2p_connection(PeerServicePeer())
        service = node.add_p2p_connection(PeerServicePeer())
        service_id = self._map_peer_id(service)
        self.markers = MarkerReader(node.debug_log_path, self.options.timeout_factor)
        block = self._quick_block()
        self._announce(source, block)
        checkpoint = self.markers.checkpoint()
        source.send_without_ping(msg_block(block))
        start = self.markers.wait("pnb_start", checkpoint, hash=block.hash_hex)
        service.begin_ping(0xA5A5A5A5A5A5A5A5)
        timing = service.finish_ping(PING_TIMEOUT)
        assert timing["completed"]
        self._target_ping(service_id, timing, checkpoint)
        self.markers.wait("pnb_end", checkpoint, hash=block.hash_hex, job=start["job"])
        self._wait_tip(block)
        if self.options.peer_service_mode == "candidate":
            self.markers.wait("result_collection", checkpoint, hash=block.hash_hex, job=start["job"])

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
        meminfo = Path("/proc/meminfo").read_text(encoding="ascii")
        mem_total_kib = int(next(line.split()[1] for line in meminfo.splitlines()
                                 if line.startswith("MemTotal:")))
        statvfs = os.statvfs(self.output_dir)
        storage = subprocess.run(
            ["findmnt", "-n", "-o", "SOURCE,FSTYPE,OPTIONS", "-T", str(self.output_dir)],
            check=True, capture_output=True, text=True).stdout.strip()
        selected_cache = {
            key: cache.get(key) for key in (
                "CMAKE_BUILD_TYPE", "CMAKE_CXX_COMPILER", "CMAKE_CXX_FLAGS",
                "CMAKE_EXE_LINKER_FLAGS", "BUILD_BENCH", "BUILD_GUI", "WITH_CCACHE",
            )
        }
        return {
            "binary": str(binary.resolve()),
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "cmake_cache": selected_cache,
            "cmake_cache_sha256": hashlib.sha256(cache_text.encode()).hexdigest(),
            "command": sys.argv,
            "compiler_version": compiler_version,
            "cpu_count": os.cpu_count(),
            "cpu_model": cpu_model,
            "git_head": subprocess.run(
                ["git", "-C", str(source_dir), "rev-parse", "HEAD"],
                check=True, capture_output=True, text=True).stdout.strip(),
            "git_tree": subprocess.run(
                ["git", "-C", str(source_dir), "rev-parse", "HEAD^{tree}"],
                check=True, capture_output=True, text=True).stdout.strip(),
            "kernel": platform.uname()._asdict(),
            "mem_total_kib": mem_total_kib,
            "node_argv": node.args,
            "storage": storage,
            "storage_available_bytes": statvfs.f_bavail * statvfs.f_frsize,
            "storage_total_bytes": statvfs.f_blocks * statvfs.f_frsize,
        }

    def _run_campaign(self):
        if self.options.peer_service_profile == "smoke":
            assert self.options.peer_service_mode == "candidate"
        node = self.nodes[0]
        assert node.getblockcount() == 200 and not node.getblockchaininfo()["initialblockdownload"]
        setup_peer = node.add_p2p_connection(PeerServicePeer())
        address_wallet = MiniWallet(node)
        p2pk_wallet = MiniWallet(node, mode=MiniWalletMode.RAW_P2PK)
        seed = self._create_funding(setup_peer, address_wallet, p2pk_wallet)
        node.disconnect_p2ps()

        source = node.add_p2p_connection(PeerServicePeer())
        self.source_id = self._map_peer_id(source)
        self.markers = MarkerReader(node.debug_log_path, self.options.timeout_factor)
        profile = PROFILES[self.options.peer_service_profile]
        serial = 0
        for load in profile["loads"]:
            peers = [node.add_p2p_connection(PeerServicePeer()) for _ in range(load)]
            peer_ids = [self._map_peer_id(peer) for peer in peers]
            assert len(set(peer_ids + [self.source_id])) == load + 1
            for phase, count in (("warmup", profile["warmups"]), ("trial", profile["trials"])):
                for trial in range(count):
                    block, seed = self._build_work_block(p2pk_wallet, seed)
                    serial += 1
                    self._measure_trial(source, peers, peer_ids, block, load, phase, trial,
                                        serial, self.options.peer_service_profile == "mixed")
            for peer in peers:
                peer.peer_disconnect()
                peer.wait_for_disconnect()
        assert source.is_connected

    def run_test(self):
        if self.options.output_dir is None:
            self._run_quick()
            return

        self._prepare_output()
        node = self.nodes[0]
        debug_log = node.debug_log_path
        pid = node.process.pid
        binary = Path(node.args[0])
        provenance = self._provenance(node, binary)
        sampler = ResourceSampler(pid, self.output_dir / "resource.csv")
        self.aggregate = {"offered": 0, "completed": 0, "failed": 0, "response_inside_pnb": 0}
        started_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        started_ns = time.perf_counter_ns()
        failure = None
        try:
            self._run_campaign()
        except Exception as error:
            failure = f"{type(error).__name__}: {error}"
        try:
            node.stop_node()
        finally:
            sampler.stop()
            self.samples_file.close()
            shutil.copyfile(debug_log, self.output_dir / "target.log")

        self._write_json(self.output_dir / "run.json", {
            "aggregate": self.aggregate,
            "ended_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "failure": failure,
            "mode": self.options.peer_service_mode, "node_args": self.extra_args[0],
            "profile": self.options.peer_service_profile, "schema_version": 1,
            "provenance": provenance,
            "seed": self.options.peer_service_seed, "started_utc": started_utc,
            "wall_ns": time.perf_counter_ns() - started_ns,
        })
        if failure is not None:
            raise AssertionError(failure)


if __name__ == "__main__":
    AsyncPNBPeerService(__file__).main()
