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
        profile = self.options.peer_service_profile
        args = [
            f"-asyncpnbpeerservice={int(mode == 'candidate')}",
            "-loglevel=info",
            "-maxconnections=213",
            "-nodebug",
            "-nologratelimit",
            "-persistmempool=0",
            "-v2transport=0",
        ]
        if profile != "default":
            args += ["-par=1", "-prevoutfetchthreads=0"]
        self.extra_args = [args]

    def setup_nodes(self):
        """Refresh the cached chain with an identical height-200 block in every arm."""
        self.add_nodes(self.num_nodes, self.extra_args)
        self.start_nodes()
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
        return seed

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
            "handler_prefix_ns": start["handler_prefix_ns"],
            "handler_scheduling_delay_ns": start["handler_turn_start_ns"] - ready["steady_ns"],
            "handler_turn_start_ns": start["handler_turn_start_ns"],
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
        assert target["handler_prefix_ns"] == start["steady_ns"] - target["handler_turn_start_ns"]
        assert (target["handler_turn_start_ns"] <= target["poll_ns"]
                <= start["steady_ns"] <= target["response_queued_ns"]
                <= target["handler_complete_ns"])
        assert target["ready_ns"] <= target["poll_ns"]
        assert (target["handler_queue_delay_ns"]
                == target["handler_scheduling_delay_ns"] + target["handler_prefix_ns"])
        assert target["node_service_latency_ns"] == target["response_queued_ns"] - target["ready_ns"]
        pause_values = (target["ready_pause_recv"], target["poll_pause_recv"], target["send_pause"])
        self.pause_metrics["snapshots_checked"] += len(pause_values)
        self.pause_metrics["pause_observations"] += sum(bool(value) for value in pause_values)
        assert not any(pause_values), "measured receive/send queue pause invalidates campaign"
        if pnb is not None:
            target["ready_inside_pnb"] = pnb["start_ns"] < target["ready_ns"] < pnb["end_ns"]
            target["response_inside_pnb"] = pnb["start_ns"] < target["response_queued_ns"] < pnb["end_ns"]
        return target

    def _pnb_lifecycle(self, checkpoint, block_hash, job):
        submit = self.markers.unique("job_submit", checkpoint, hash=block_hash, job=job)
        start = self.markers.unique("pnb_start", checkpoint, hash=block_hash, job=job)
        end = self.markers.unique("pnb_end", checkpoint, hash=block_hash, job=job)
        assert submit["steady_ns"] <= start["steady_ns"] < end["steady_ns"]
        assert end["duration_ns"] == end["steady_ns"] - start["steady_ns"]
        lifecycle = {"job_submit": submit, "pnb_start": start, "pnb_end": end}
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
                    <= summary["steady_ns"] <= collection["steady_ns"])
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
        target_peer_ids = {entry["id"] for entry in self.nodes[0].getpeerinfo()}
        expected_peer_ids = {self.source_id, *peer_ids}
        assert target_peer_ids == expected_peer_ids
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
        nonce_by_index = {
            index: 0xD000000000000000 | (serial << 12) | index for index in range(load)
        }
        send_order = [
            {"front_refused": index in refused, "nonce": nonce_by_index[index], "peer_index": index}
            for index in order
        ]
        trial_input = {
            "block_hash": block.hash_hex,
            "expected_target_peer_count": load + 1,
            "load": load,
            "phase": phase,
            "refused_peer_indices": sorted(refused),
            "send_order": send_order,
            "serial": serial,
            "trial": trial,
        }
        self.trial_inputs.append(trial_input)
        send_position = {index: position for position, index in enumerate(order)}
        timings = {}
        for index in order:
            if index in refused:
                peers[index].send_without_ping(msg_getaddr())
            peers[index].begin_ping(nonce_by_index[index])
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
        lifecycle = self._pnb_lifecycle(checkpoint, block.hash_hex, job)
        busy_send_prefix = lifecycle.get("busy_send_prefix_summary")

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
                "send_position": send_position[index],
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
            if self.options.peer_service_mode == "candidate":
                assert response_inside > 0
            else:
                assert response_inside == 0
        self._write_sample({
            "kind": "trial", "block_hash": block.hash_hex, "completed": completed,
            "failed": load - completed, "load": load, "mode": self.options.peer_service_mode,
            "offered": load, "phase": phase, "pnb": pnb, "ready_inside_pnb": ready_inside,
            "refused_peer_indices": sorted(refused), "send_order": send_order,
            "source_peer_id": self.source_id, "service_peer_ids": peer_ids,
            "target_peer_count": len(target_peer_ids),
            "busy_send_prefix_summary": busy_send_prefix,
            "response_inside_pnb": response_inside, "timed_out": sum(not value["completed"] for value in timings.values()),
            "trial": trial,
        })
        aggregate = self.aggregate if phase == "trial" else self.warmup_aggregate
        aggregate["offered"] += load
        aggregate["completed"] += completed
        aggregate["failed"] += load - completed
        aggregate["response_inside_pnb"] += response_inside

    def _run_quick(self):
        node = self.nodes[0]
        assert node.getblockcount() == 200
        self._initialize_block_inputs()
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
            self.markers.wait("result_publication", checkpoint,
                              hash=block.hash_hex, job=start["job"])
            self.markers.wait("result_collection", checkpoint, hash=block.hash_hex, job=start["job"])
        self._pnb_lifecycle(checkpoint, block.hash_hex, start["job"])
        self.log.info(
            "Deterministic input identity start_hash=%s block_hash=%s ordered_sha256=%s",
            self.chain_start["hash"], block.hash_hex, self.block_input_hasher.hexdigest())

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
        setup_peer = node.add_p2p_connection(PeerServicePeer())
        address_wallet = MiniWallet(node)
        p2pk_wallet = MiniWallet(node, mode=MiniWalletMode.RAW_P2PK)
        seed = self._create_funding(setup_peer, address_wallet, p2pk_wallet)
        node.disconnect_p2ps()
        self.wait_until(
            lambda: not node.getpeerinfo() and node.getconnectioncount() == 0,
            timeout=PING_TIMEOUT, check_interval=MARKER_POLL)

        source = node.add_p2p_connection(PeerServicePeer())
        self.source_id = self._map_peer_id(source)
        self.markers = MarkerReader(node.debug_log_path, self.options.timeout_factor)
        profile = PROFILES[self.options.peer_service_profile]
        serial = 0
        for load in profile["loads"]:
            assert {entry["id"] for entry in node.getpeerinfo()} == {self.source_id}
            assert node.getconnectioncount() == 1
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
            self.wait_until(
                lambda: ({entry["id"] for entry in node.getpeerinfo()} == {self.source_id}
                         and node.getconnectioncount() == 1),
                timeout=PING_TIMEOUT, check_interval=MARKER_POLL)
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
        return [arg for arg in args if not arg.startswith(prefix)]

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
        self.aggregate = {"offered": 0, "completed": 0, "failed": 0, "response_inside_pnb": 0}
        self.warmup_aggregate = {"offered": 0, "completed": 0, "failed": 0, "response_inside_pnb": 0}
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
            ("target_log", lambda: shutil.copyfile(debug_log, self.output_dir / "target.log")),
        ):
            try:
                cleanup()
            except Exception as error:
                record_failure(stage, error)

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
            "profile": self.options.peer_service_profile, "schema_version": 1,
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
