#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Local A/B measurement of unrelated-peer PING service during P2P block processing.
This is a benchmark harness, not a timing-sensitive CI regression test.
"""

import hashlib
import json
import os
import platform
import re
import subprocess
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
    msg_headers,
    msg_ping,
)
from test_framework.p2p import P2PInterface, P2P_SUBVERSION, p2p_lock
from test_framework.script import CScript
from test_framework.test_framework import BitcoinTestFramework
from test_framework.wallet import MiniWallet, MiniWalletMode


SCHEMA_VERSION = 1
BASE_COMMIT = "11090c8bb359f894ef7d97b65aff52fe8191aec1"
MARKER_PREFIX = b"ASYNC_PNB_BENCH "

CONTROL_SAMPLES = 10
MEASURED_SAMPLES = 20
WARMUP_SAMPLES = 1

TARGET_WEIGHT = 3_900_000
GENERATED_CHAIN_TXS = 5_803
INCLUDED_CHAIN_TXS = 5_802
EXPECTED_BLOCK_WEIGHT = 3_899_532
EXPECTED_OVERFLOW_WEIGHT = 3_900_204
EXPECTED_BLOCK_BYTES = 974_883
EXPECTED_LEGACY_SIGOPS = 5_802
EXPECTED_SIGOPS_COST = 23_208

FUNDING_FEE_SAT = 1_000
CHAIN_TX_FEE_SAT = 1
MIN_WARMUP_PNB_NS = 25_000_000
MARKER_POLL_SECONDS = 0.002
BASE_TIMEOUT_SECONDS = 60

SOURCE_CONTROL_NONCE = 0xA110000000000000
UNRELATED_CONTROL_NONCE = 0xB110000000000000
SOURCE_CONTENDED_NONCE = 0xA120000000000000
UNRELATED_CONTENDED_NONCE = 0xB120000000000000

NODE_ARGS = (
    "-nodebug",
    "-loglevel=info",
    "-par=1",
    "-prevoutfetchthreads=0",
    "-persistmempool=0",
    "-v2transport=0",
    "-nologratelimit",
)

COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
SIGNED_DECIMAL_RE = re.compile(r"-?(0|[1-9][0-9]*)\Z")
UNSIGNED_DECIMAL_RE = re.compile(r"0|[1-9][0-9]*\Z")
INT64_MIN = -(1 << 63)
INT64_MAX = (1 << 63) - 1
UINT64_MAX = (1 << 64) - 1

MARKER_KEYS = {
    "pnb_start": ("event", "hash", "node_ns", "steady_ns"),
    "pnb_end": ("event", "hash", "node_ns", "steady_ns", "duration_ns"),
    "pong_queued": (
        "event",
        "peer",
        "nonce",
        "recv_node_ns",
        "queued_node_ns",
        "queued_steady_ns",
        "queue_ns",
    ),
}


class BenchmarkStop(RuntimeError):
    def __init__(self, code, **facts):
        super().__init__(code)
        self.code = code
        self.facts = facts


class MarkerParseError(ValueError):
    pass


def require(condition, code, **facts):
    if not condition:
        raise BenchmarkStop(code, **facts)


def percentile(values, percentile_value):
    require(bool(values), "S_CODE_PLAN_MISMATCH", percentile="empty_values")
    require(percentile_value in (50, 95), "S_CODE_PLAN_MISMATCH", percentile=percentile_value)
    ordered = sorted(values)
    index = (percentile_value * len(ordered) + 99) // 100 - 1
    return ordered[index]


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as file_handle:
        while True:
            chunk = file_handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


class BenchmarkPeer(P2PInterface):
    def __init__(self):
        super().__init__()
        self.requested_blocks = []
        self.outstanding_ping = None
        self.callback_error = None

    def on_getdata(self, message):
        for inventory in message.inv:
            if (inventory.type & MSG_TYPE_MASK) == MSG_BLOCK:
                self.requested_blocks.append(inventory.hash)

    def on_pong(self, message):
        if self.outstanding_ping is None or message.nonce != self.outstanding_ping["nonce"]:
            return
        if self.outstanding_ping["response_perf_ns"] is not None:
            self.callback_error = "duplicate matching PONG callback"
            self.outstanding_ping["event"].set()
            return
        self.outstanding_ping["response_perf_ns"] = time.perf_counter_ns()
        self.outstanding_ping["event"].set()

    def on_inv(self, message):
        pass

    def begin_ping(self, nonce):
        with p2p_lock:
            require(self.is_connected, "S_PEER_DISCONNECTED", operation="begin_ping")
            require(self.callback_error is None, "S_CODE_PLAN_MISMATCH", callback_error=self.callback_error)
            require(self.outstanding_ping is None, "S_CODE_PLAN_MISMATCH", outstanding_ping=True)
            self.outstanding_ping = {
                "nonce": nonce,
                "sent_perf_ns": None,
                "response_perf_ns": None,
                "event": threading.Event(),
            }
            self.outstanding_ping["sent_perf_ns"] = time.perf_counter_ns()
            self.send_without_ping(msg_ping(nonce))

    def finish_ping(self, timeout):
        with p2p_lock:
            require(self.outstanding_ping is not None, "S_CODE_PLAN_MISMATCH", outstanding_ping=False)
            ping = self.outstanding_ping
        completed = ping["event"].wait(timeout * self.timeout_factor)
        if not completed:
            require(self.is_connected, "S_PEER_DISCONNECTED", operation="finish_ping", nonce=ping["nonce"])
            raise BenchmarkStop("S_PONG_TIMEOUT", nonce=ping["nonce"])
        with p2p_lock:
            callback_error = self.callback_error
            sent_perf_ns = ping["sent_perf_ns"]
            response_perf_ns = ping["response_perf_ns"]
            self.outstanding_ping = None
        require(callback_error is None, "S_CODE_PLAN_MISMATCH", callback_error=callback_error)
        require(response_perf_ns is not None, "S_CODE_PLAN_MISMATCH", missing_response_timestamp=True)
        return sent_perf_ns, response_perf_ns

    def wait_for_block_request(self, block_hash, timeout):
        with p2p_lock:
            require(self.requested_blocks.count(block_hash) == 0, "S_BLOCK_REQUEST", block_hash=f"{block_hash:064x}", prior_count=self.requested_blocks.count(block_hash))
        try:
            self.wait_until(lambda: self.requested_blocks.count(block_hash) >= 1, timeout=timeout)
        except AssertionError as error:
            with p2p_lock:
                connected = self.is_connected
            if not connected:
                raise BenchmarkStop(
                    "S_PEER_DISCONNECTED",
                    operation="wait_for_block_request",
                    block_hash=f"{block_hash:064x}",
                ) from error
            raise BenchmarkStop("S_BLOCK_REQUEST", block_hash=f"{block_hash:064x}", framework_message=str(error)) from error
        with p2p_lock:
            request_count = self.requested_blocks.count(block_hash)
            connected = self.is_connected
        require(connected, "S_PEER_DISCONNECTED", operation="wait_for_block_request", block_hash=f"{block_hash:064x}")
        require(request_count == 1, "S_BLOCK_REQUEST", block_hash=f"{block_hash:064x}", request_count=request_count)


class MarkerReader:
    def __init__(self, debug_log_path, timeout):
        self.debug_log_path = Path(debug_log_path)
        self.timeout = timeout
        with self.debug_log_path.open("rb") as log_file:
            log_file.seek(0, os.SEEK_END)
            self.offset = log_file.tell()
        self.partial = b""
        self.sequence = 0
        self.events = []
        self.starts = {}
        self.ends = {}
        self.pongs = {}
        self.counts = {"pnb_start": 0, "pnb_end": 0, "pong_queued": 0}

    @staticmethod
    def parse_line(line):
        prefix_count = line.count(MARKER_PREFIX)
        if prefix_count == 0:
            return None
        if prefix_count != 1:
            raise MarkerParseError("marker prefix count is not one")
        suffix = line.split(MARKER_PREFIX, 1)[1]
        if not suffix.endswith(b"\n"):
            raise MarkerParseError("marker line is not newline terminated")
        suffix = suffix[:-1]
        if suffix.endswith(b"\r"):
            suffix = suffix[:-1]
        try:
            text = suffix.decode("ascii")
        except UnicodeDecodeError as error:
            raise MarkerParseError("marker suffix is not ASCII") from error
        if "\r" in text:
            raise MarkerParseError("embedded carriage return")
        if "\x00" in text:
            raise MarkerParseError("embedded NUL")
        tokens = text.split(" ")
        if not tokens or any(token == "" for token in tokens):
            raise MarkerParseError("empty marker token")
        pairs = []
        for token in tokens:
            if token.count("=") != 1:
                raise MarkerParseError("marker token must contain one equals sign")
            key, value = token.split("=", 1)
            if not key or not value:
                raise MarkerParseError("empty marker key or value")
            pairs.append((key, value))
        if pairs[0][0] != "event":
            raise MarkerParseError("event key is not first")
        event_name = pairs[0][1]
        if event_name not in MARKER_KEYS:
            raise MarkerParseError("unknown marker event")
        keys = tuple(key for key, _ in pairs)
        if keys != MARKER_KEYS[event_name]:
            raise MarkerParseError("marker keys differ from schema")
        values = dict(pairs)
        event = {"event": event_name}
        if event_name in ("pnb_start", "pnb_end"):
            if HASH_RE.fullmatch(values["hash"]) is None:
                raise MarkerParseError("invalid lowercase block hash")
            event["hash"] = values["hash"]
        signed_fields = {
            "pnb_start": ("node_ns", "steady_ns"),
            "pnb_end": ("node_ns", "steady_ns"),
            "pong_queued": ("peer", "recv_node_ns", "queued_node_ns", "queued_steady_ns", "queue_ns"),
        }[event_name]
        for field in signed_fields:
            value = values[field]
            if SIGNED_DECIMAL_RE.fullmatch(value) is None:
                raise MarkerParseError(f"invalid signed decimal for {field}")
            integer = int(value)
            if not INT64_MIN <= integer <= INT64_MAX:
                raise MarkerParseError(f"signed integer out of range for {field}")
            event[field] = integer
        if event_name == "pnb_end":
            value = values["duration_ns"]
            if UNSIGNED_DECIMAL_RE.fullmatch(value) is None:
                raise MarkerParseError("invalid duration decimal")
            duration = int(value)
            if duration > INT64_MAX:
                raise MarkerParseError("duration out of signed range")
            event["duration_ns"] = duration
        if event_name == "pong_queued":
            value = values["nonce"]
            if UNSIGNED_DECIMAL_RE.fullmatch(value) is None:
                raise MarkerParseError("invalid nonce decimal")
            nonce = int(value)
            if nonce > UINT64_MAX:
                raise MarkerParseError("nonce out of unsigned range")
            event["nonce"] = nonce
            if event["queue_ns"] != event["queued_node_ns"] - event["recv_node_ns"]:
                raise MarkerParseError("queue arithmetic mismatch")
        return event

    def ingest_line(self, line):
        try:
            event = self.parse_line(line)
        except MarkerParseError as error:
            raise BenchmarkStop("S_MARKER_PARSE", line_hex=line.hex(), parser_error=str(error)) from error
        if event is None:
            return
        self.sequence += 1
        event["sequence"] = self.sequence
        event["consumed"] = False
        event_name = event["event"]
        if event_name == "pnb_start":
            key = event["hash"]
            require(key not in self.starts, "S_DUPLICATE_MARKER", event=event_name, hash=key)
            self.starts[key] = event
        elif event_name == "pnb_end":
            key = event["hash"]
            require(key not in self.ends, "S_DUPLICATE_MARKER", event=event_name, hash=key)
            self.ends[key] = event
        else:
            key = event["nonce"]
            require(key not in self.pongs, "S_DUPLICATE_MARKER", event=event_name, nonce=key)
            self.pongs[key] = event
        self.events.append(event)
        self.counts[event_name] += 1

    def _poll(self):
        with self.debug_log_path.open("rb") as log_file:
            log_file.seek(self.offset)
            appended = log_file.read()
            self.offset += len(appended)
        combined = self.partial + appended
        lines = combined.split(b"\n")
        self.partial = lines.pop()
        for line in lines:
            self.ingest_line(line + b"\n")

    def sequence_checkpoint(self):
        self._poll()
        unconsumed = [event["sequence"] for event in self.events if not event["consumed"]]
        require(not unconsumed, "S_CODE_PLAN_MISMATCH", unconsumed_sequences=unconsumed)
        return self.sequence

    def _wait(self, store, key, after_sequence, event_name):
        deadline = time.perf_counter() + self.timeout
        while True:
            self._poll()
            event = store.get(key)
            if event is not None:
                require(event["sequence"] > after_sequence, "S_DUPLICATE_MARKER", event=event_name, sequence=event["sequence"], after_sequence=after_sequence)
                require(not event["consumed"], "S_DUPLICATE_MARKER", event=event_name, sequence=event["sequence"], consumed=True)
                event["consumed"] = True
                return event
            if time.perf_counter() >= deadline:
                facts = {"event": event_name, "after_sequence": after_sequence}
                if event_name == "pong_queued":
                    facts["nonce"] = key
                else:
                    facts["hash"] = key
                raise BenchmarkStop("S_MARKER_TIMEOUT", **facts)
            time.sleep(MARKER_POLL_SECONDS)

    def wait_pnb_start(self, block_hash, after_sequence):
        return self._wait(self.starts, block_hash, after_sequence, "pnb_start")

    def wait_pnb_end(self, block_hash, after_sequence):
        return self._wait(self.ends, block_hash, after_sequence, "pnb_end")

    def wait_pong(self, nonce, after_sequence):
        return self._wait(self.pongs, nonce, after_sequence, "pong_queued")

    def assert_all_consumed(self):
        self._poll()
        require(MARKER_PREFIX not in self.partial, "S_MARKER_PARSE", partial_hex=self.partial.hex())
        unconsumed = [event["sequence"] for event in self.events if not event["consumed"]]
        require(not unconsumed, "S_CODE_PLAN_MISMATCH", unconsumed_sequences=unconsumed)
        expected = {"pnb_start": 21, "pnb_end": 21, "pong_queued": 62}
        require(self.counts == expected, "S_CODE_PLAN_MISMATCH", marker_counts=self.counts, expected_marker_counts=expected)


class AsyncPNBBenchmark(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = False
        self.uses_wallet = False
        self.extra_args = [list(NODE_ARGS)]

        # BitcoinTestFramework.__init__ consumes this value immediately after this hook.
        if self.options.timeout_factor != 1:
            self.failure_written = False
            self.completed_records = 0
            self.output_safe = False
            self.samples_file = None
            try:
                self._validate_output_directory()
                raise BenchmarkStop(
                    "S_BUILD_PROVENANCE",
                    mismatched_options=["timeout_factor"],
                    observed_options={"timeout_factor": str(self.options.timeout_factor)},
                )
            except BenchmarkStop as error:
                if self.output_safe:
                    self.write_failure(error)
                raise

    def add_options(self, parser):
        parser.add_argument("--variant", required=True, choices=("baseline", "async"))
        parser.add_argument("--output-dir", required=True)
        parser.add_argument("--build-head", required=True)
        parser.add_argument("--prototype-commit")
        parser.add_argument("--baseline-summary")

    def setup_nodes(self):
        self.preflight()
        super().setup_nodes()

    def preflight(self):
        self.failure_written = False
        self.completed_records = 0
        self.output_safe = False
        self.samples_file = None
        try:
            self._check_preflight()
        except BenchmarkStop as error:
            if self.output_safe:
                self.write_failure(error)
            raise

    def _validate_output_directory(self):
        self.output_safe = False
        output_path = Path(self.options.output_dir)
        require(output_path.is_absolute(), "S_OUTPUT_PATH", output_dir=str(output_path), reason="not_absolute")
        require(output_path.exists(), "S_OUTPUT_PATH", output_dir=str(output_path), reason="missing")
        require(not output_path.is_symlink(), "S_OUTPUT_PATH", output_dir=str(output_path), reason="symlink")
        require(output_path.is_dir(), "S_OUTPUT_PATH", output_dir=str(output_path), reason="not_directory")
        entries = sorted(entry.name for entry in output_path.iterdir())
        require(not entries, "S_OUTPUT_PATH", output_dir=str(output_path), reason="nonempty", entries=entries)
        self.output_dir = output_path.resolve()
        self.output_safe = True

    def _run_git(self, arguments):
        command = ["git", "-C", str(self.source_dir), *arguments]
        result = subprocess.run(command, capture_output=True, text=True)
        require(
            result.returncode == 0,
            "S_BUILD_PROVENANCE",
            git_arguments=arguments,
            returncode=result.returncode,
            stderr=result.stderr.strip(),
        )
        return result.stdout.strip()

    def _read_cmake_cache(self):
        cache_path = self.build_dir / "CMakeCache.txt"
        require(cache_path.exists(), "S_BUILD_PROVENANCE", cmake_cache=str(cache_path), reason="missing")
        require(not cache_path.is_symlink(), "S_BUILD_PROVENANCE", cmake_cache=str(cache_path), reason="symlink")
        require(cache_path.is_file(), "S_BUILD_PROVENANCE", cmake_cache=str(cache_path), reason="not_regular")
        values = {}
        for line in cache_path.read_text(encoding="utf-8").splitlines():
            if not line or line.startswith(("#", "//")) or "=" not in line or ":" not in line.split("=", 1)[0]:
                continue
            typed_key, value = line.split("=", 1)
            key, _ = typed_key.split(":", 1)
            values[key] = value

        fixed_cache_values = {
            "BUILD_GUI": "OFF",
            "BUILD_TESTS": "OFF",
            "BUILD_BENCH": "OFF",
            "ENABLE_WALLET": "OFF",
            "WITH_CCACHE": "OFF",
        }
        empty_user_flag_values = {
            "APPEND_CPPFLAGS": "",
            "APPEND_CFLAGS": "",
            "APPEND_CXXFLAGS": "",
            "APPEND_LDFLAGS": "",
        }
        active_flag_keys = (
            "CMAKE_C_FLAGS",
            "CMAKE_CXX_FLAGS",
            "CMAKE_C_FLAGS_RELWITHDEBINFO",
            "CMAKE_CXX_FLAGS_RELWITHDEBINFO",
            "CMAKE_EXE_LINKER_FLAGS",
            "CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO",
            "CMAKE_MODULE_LINKER_FLAGS",
            "CMAKE_MODULE_LINKER_FLAGS_RELWITHDEBINFO",
            "CMAKE_SHARED_LINKER_FLAGS",
            "CMAKE_SHARED_LINKER_FLAGS_RELWITHDEBINFO",
            "CMAKE_STATIC_LINKER_FLAGS",
            "CMAKE_STATIC_LINKER_FLAGS_RELWITHDEBINFO",
        )
        required_keys = (
            "CMAKE_BUILD_TYPE",
            "CMAKE_C_COMPILER",
            "CMAKE_CXX_COMPILER",
            *fixed_cache_values,
            *empty_user_flag_values,
            *active_flag_keys,
        )
        missing = [key for key in required_keys if key not in values]
        require(not missing, "S_BUILD_PROVENANCE", missing_cmake_keys=missing)
        require(values["CMAKE_BUILD_TYPE"] == "RelWithDebInfo", "S_BUILD_PROVENANCE", cmake_build_type=values["CMAKE_BUILD_TYPE"])
        mismatched_cache_options = sorted(
            key for key, expected in fixed_cache_values.items()
            if values[key] != expected
        )
        require(
            not mismatched_cache_options,
            "S_BUILD_PROVENANCE",
            mismatched_cmake_options=mismatched_cache_options,
            observed_cmake_options={key: values[key] for key in mismatched_cache_options},
        )
        nonempty_user_flags = sorted(
            key for key in empty_user_flag_values
            if values[key]
        )
        require(
            not nonempty_user_flags,
            "S_BUILD_PROVENANCE",
            nonempty_user_flag_keys=nonempty_user_flags,
            observed_user_flags={key: values[key] for key in nonempty_user_flags},
        )

        require(values.get("SANITIZERS", "") == "", "S_BUILD_PROVENANCE", sanitizers=values.get("SANITIZERS", ""))
        enabled_ipo = sorted(
            key for key, value in values.items()
            if key.startswith("CMAKE_INTERPROCEDURAL_OPTIMIZATION")
            and value.upper() not in ("", "0", "FALSE", "NO", "OFF", "NOTFOUND")
        )
        require(not enabled_ipo, "S_BUILD_PROVENANCE", enabled_ipo_keys=enabled_ipo)
        compiler_launchers = {
            key: values.get(key, "")
            for key in ("CMAKE_C_COMPILER_LAUNCHER", "CMAKE_CXX_COMPILER_LAUNCHER")
            if values.get(key, "")
        }
        require(not compiler_launchers, "S_BUILD_PROVENANCE", compiler_launchers=compiler_launchers)
        compiler_arg1 = {
            key: values.get(key, "")
            for key in ("CMAKE_C_COMPILER_ARG1", "CMAKE_CXX_COMPILER_ARG1")
            if values.get(key, "")
        }
        require(not compiler_arg1, "S_BUILD_PROVENANCE", nonempty_compiler_arg1=compiler_arg1)
        compiler_commands = {
            key: values.get(key, "")
            for key in ("CMAKE_C_COMPILER", "CMAKE_CXX_COMPILER")
            if values.get(key, "")
        }
        ccache_compilers = sorted(key for key, value in compiler_commands.items() if "ccache" in value.lower())
        require(not ccache_compilers, "S_BUILD_PROVENANCE", ccache_compiler_keys=ccache_compilers)

        forbidden_fragments = ("sanitize", "lto", "profile", "coverage", "-pg", "/gl", "/ltcg", "-ipo", "-qipo")
        forbidden_effective_flags = sorted(
            key for key in active_flag_keys
            if any(fragment in values[key].lower() for fragment in forbidden_fragments)
        )
        require(not forbidden_effective_flags, "S_BUILD_PROVENANCE", forbidden_effective_flag_keys=forbidden_effective_flags)

        require(bool(values["CMAKE_C_COMPILER"]), "S_BUILD_PROVENANCE", cmake_c_compiler=values["CMAKE_C_COMPILER"])
        require(bool(values["CMAKE_CXX_COMPILER"]), "S_BUILD_PROVENANCE", cmake_cxx_compiler=values["CMAKE_CXX_COMPILER"])
        self.cmake_values = {
            "cmake_build_type": values["CMAKE_BUILD_TYPE"],
            "cmake_cxx_compiler": values["CMAKE_CXX_COMPILER"],
            "cmake_cxx_flags": values["CMAKE_CXX_FLAGS"],
        }

    def _benchmark_constants(self):
        return {
            "control_samples": CONTROL_SAMPLES,
            "measured_samples": MEASURED_SAMPLES,
            "warmup_samples": WARMUP_SAMPLES,
            "target_weight": TARGET_WEIGHT,
            "generated_chain_txs": GENERATED_CHAIN_TXS,
            "included_chain_txs": INCLUDED_CHAIN_TXS,
            "expected_block_weight": EXPECTED_BLOCK_WEIGHT,
            "expected_overflow_weight": EXPECTED_OVERFLOW_WEIGHT,
            "expected_block_bytes": EXPECTED_BLOCK_BYTES,
            "expected_legacy_sigops": EXPECTED_LEGACY_SIGOPS,
            "expected_sigops_cost": EXPECTED_SIGOPS_COST,
            "funding_fee_sat": FUNDING_FEE_SAT,
            "chain_tx_fee_sat": CHAIN_TX_FEE_SAT,
            "min_warmup_pnb_ns": MIN_WARMUP_PNB_NS,
        }

    @staticmethod
    def _nested_value(value, dotted_key):
        current = value
        for key in dotted_key.split("."):
            if type(current) is not dict or key not in current:
                return None, False
            current = current[key]
        return current, True

    @staticmethod
    def _check_exact_keys(value, expected_keys, dotted_key, differing_keys):
        if type(value) is not dict or set(value) != set(expected_keys):
            differing_keys.append(dotted_key)

    @staticmethod
    def _same_typed_json_value(observed, expected):
        if type(observed) is not type(expected):
            return False
        if type(expected) is dict:
            return set(observed) == set(expected) and all(
                AsyncPNBBenchmark._same_typed_json_value(observed[key], expected[key])
                for key in expected
            )
        if type(expected) is list:
            return len(observed) == len(expected) and all(
                AsyncPNBBenchmark._same_typed_json_value(observed_value, expected_value)
                for observed_value, expected_value in zip(observed, expected)
            )
        return observed == expected

    @staticmethod
    def _load_strict_json(path):
        def reject_nonstandard_constant(value):
            raise ValueError(f"nonstandard JSON constant: {value}")

        with path.open("r", encoding="utf-8") as json_file:
            return json.load(json_file, parse_constant=reject_nonstandard_constant)

    def _baseline_schema_differences(self, baseline):
        differing_keys = []
        self._check_exact_keys(
            baseline,
            ("schema_version", "benchmark", "build", "environment", "controls", "warmup", "trials", "marker_counts"),
            "summary.keys",
            differing_keys,
        )
        if type(baseline) is not dict:
            return differing_keys
        sections = ("benchmark", "build", "environment", "controls", "warmup", "trials", "marker_counts")
        if any(type(baseline.get(section)) is not dict for section in sections):
            differing_keys.extend(f"{section}.keys" for section in sections if type(baseline.get(section)) is not dict)
            return differing_keys

        self._check_exact_keys(
            baseline["benchmark"],
            ("name", "variant", "base_commit", "transport", "node_args", "random_seed", "port_seed", "constants", "setup_funding_txid", "workload_fingerprints"),
            "benchmark.keys",
            differing_keys,
        )
        self._check_exact_keys(
            baseline["build"],
            ("build_head", "prototype_commit", "binary_path", "binary_sha256", "harness_sha256", "cmake_build_type", "cmake_cxx_compiler", "cmake_cxx_flags"),
            "build.keys",
            differing_keys,
        )
        self._check_exact_keys(
            baseline["environment"],
            ("platform", "machine", "cpu_count", "python_version", "started_utc", "ended_utc"),
            "environment.keys",
            differing_keys,
        )
        self._check_exact_keys(baseline["controls"], ("source", "unrelated"), "controls.keys", differing_keys)
        self._check_exact_keys(
            baseline["warmup"],
            ("pnb_duration_ns", "source_queued_inside_pnb", "unrelated_queued_inside_pnb", "tx_payload_sha256"),
            "warmup.keys",
            differing_keys,
        )
        self._check_exact_keys(
            baseline["trials"],
            ("accepted_blocks", "pnb", "source", "unrelated", "workload"),
            "trials.keys",
            differing_keys,
        )
        self._check_exact_keys(baseline["marker_counts"], ("pnb_start", "pnb_end", "pong_queued"), "marker_counts.keys", differing_keys)
        self._check_exact_keys(
            baseline["benchmark"].get("constants"),
            self._benchmark_constants().keys(),
            "benchmark.constants.keys",
            differing_keys,
        )

        control_metric_keys = ("sample_count", "node_queue_ns_p50", "node_queue_ns_p95", "python_rtt_ns_p50", "python_rtt_ns_p95")
        trial_metric_keys = control_metric_keys + ("queued_inside_pnb_count", "receive_offset_ns_p50", "receive_offset_ns_p95")
        for role in ("source", "unrelated"):
            self._check_exact_keys(baseline["controls"].get(role), control_metric_keys, f"controls.{role}.keys", differing_keys)
            self._check_exact_keys(baseline["trials"].get(role), trial_metric_keys, f"trials.{role}.keys", differing_keys)
        self._check_exact_keys(
            baseline["trials"].get("pnb"),
            ("sample_count", "duration_ns_p50", "duration_ns_p95"),
            "trials.pnb.keys",
            differing_keys,
        )
        self._check_exact_keys(
            baseline["trials"].get("workload"),
            ("height_first", "height_last", "weight", "serialized_bytes", "non_coinbase_txs", "legacy_sigops", "sigops_cost", "total_fees_sat"),
            "trials.workload.keys",
            differing_keys,
        )

        string_paths = (
            "benchmark.name",
            "benchmark.variant",
            "benchmark.base_commit",
            "benchmark.transport",
            "benchmark.setup_funding_txid",
            "build.build_head",
            "build.binary_path",
            "build.binary_sha256",
            "build.harness_sha256",
            "build.cmake_build_type",
            "build.cmake_cxx_compiler",
            "build.cmake_cxx_flags",
            "environment.platform",
            "environment.machine",
            "environment.python_version",
            "environment.started_utc",
            "environment.ended_utc",
            "warmup.tx_payload_sha256",
        )
        for dotted_key in string_paths:
            value, present = self._nested_value(baseline, dotted_key)
            if not present or type(value) is not str:
                differing_keys.append(dotted_key)

        node_args = baseline["benchmark"].get("node_args")
        if type(node_args) is not list or any(type(value) is not str for value in node_args):
            differing_keys.append("benchmark.node_args")
        fingerprints = baseline["benchmark"].get("workload_fingerprints")
        if type(fingerprints) is not list or len(fingerprints) != 21 or any(type(value) is not str or HASH_RE.fullmatch(value) is None for value in fingerprints):
            differing_keys.append("benchmark.workload_fingerprints")
        for dotted_key in ("benchmark.setup_funding_txid", "warmup.tx_payload_sha256", "build.binary_sha256", "build.harness_sha256"):
            value, present = self._nested_value(baseline, dotted_key)
            if not present or type(value) is not str or HASH_RE.fullmatch(value) is None:
                differing_keys.append(dotted_key)
        for dotted_key in ("benchmark.base_commit", "build.build_head"):
            value, present = self._nested_value(baseline, dotted_key)
            if not present or type(value) is not str or COMMIT_RE.fullmatch(value) is None:
                differing_keys.append(dotted_key)
        for dotted_key in ("environment.started_utc", "environment.ended_utc"):
            value, present = self._nested_value(baseline, dotted_key)
            if not present or type(value) is not str or UTC_RE.fullmatch(value) is None:
                differing_keys.append(dotted_key)
        if baseline["build"].get("prototype_commit") is not None:
            differing_keys.append("build.prototype_commit")
        binary_path = baseline["build"].get("binary_path")
        if type(binary_path) is not str or not Path(binary_path).is_absolute():
            differing_keys.append("build.binary_path")

        integer_paths = (
            "schema_version",
            "benchmark.random_seed",
            "benchmark.port_seed",
            "environment.cpu_count",
            "warmup.pnb_duration_ns",
            "trials.accepted_blocks",
            "trials.pnb.sample_count",
            "trials.pnb.duration_ns_p50",
            "trials.pnb.duration_ns_p95",
            *(f"benchmark.constants.{key}" for key in self._benchmark_constants()),
            *(f"controls.{role}.{key}" for role in ("source", "unrelated") for key in control_metric_keys),
            *(f"trials.{role}.{key}" for role in ("source", "unrelated") for key in trial_metric_keys),
            *(f"trials.workload.{key}" for key in ("height_first", "height_last", "weight", "serialized_bytes", "non_coinbase_txs", "legacy_sigops", "sigops_cost", "total_fees_sat")),
            *(f"marker_counts.{key}" for key in ("pnb_start", "pnb_end", "pong_queued")),
        )
        for dotted_key in integer_paths:
            observed, present = self._nested_value(baseline, dotted_key)
            if not present or type(observed) is not int:
                differing_keys.append(dotted_key)

        cpu_count = baseline["environment"].get("cpu_count")
        if type(cpu_count) is not int or cpu_count <= 0:
            differing_keys.append("environment.cpu_count")
        warmup_duration = baseline["warmup"].get("pnb_duration_ns")
        if type(warmup_duration) is not int or warmup_duration < MIN_WARMUP_PNB_NS:
            differing_keys.append("warmup.pnb_duration_ns")
        for percentile_key in ("duration_ns_p50", "duration_ns_p95"):
            duration = baseline["trials"].get("pnb", {}).get(percentile_key) if type(baseline["trials"].get("pnb")) is dict else None
            if type(duration) is not int or duration <= 0:
                differing_keys.append(f"trials.pnb.{percentile_key}")

        exact_values = {
            "controls.source.sample_count": CONTROL_SAMPLES,
            "controls.unrelated.sample_count": CONTROL_SAMPLES,
            "trials.accepted_blocks": MEASURED_SAMPLES,
            "trials.pnb.sample_count": MEASURED_SAMPLES,
            "trials.source.sample_count": MEASURED_SAMPLES,
            "trials.unrelated.sample_count": MEASURED_SAMPLES,
            "trials.workload.height_first": 203,
            "trials.workload.height_last": 222,
            "trials.workload.weight": EXPECTED_BLOCK_WEIGHT,
            "trials.workload.serialized_bytes": EXPECTED_BLOCK_BYTES,
            "trials.workload.non_coinbase_txs": INCLUDED_CHAIN_TXS,
            "trials.workload.legacy_sigops": EXPECTED_LEGACY_SIGOPS,
            "trials.workload.sigops_cost": EXPECTED_SIGOPS_COST,
            "trials.workload.total_fees_sat": INCLUDED_CHAIN_TXS * CHAIN_TX_FEE_SAT,
            "marker_counts.pnb_start": 21,
            "marker_counts.pnb_end": 21,
            "marker_counts.pong_queued": 62,
        }
        for dotted_key, expected in exact_values.items():
            observed, present = self._nested_value(baseline, dotted_key)
            if not present or not self._same_typed_json_value(observed, expected):
                differing_keys.append(dotted_key)

        integer_metric_paths = []
        for role in ("source", "unrelated"):
            integer_metric_paths.extend(f"controls.{role}.{key}" for key in control_metric_keys if key != "sample_count")
            integer_metric_paths.extend(f"trials.{role}.{key}" for key in trial_metric_keys if key != "sample_count")
        for dotted_key in integer_metric_paths:
            observed, present = self._nested_value(baseline, dotted_key)
            if not present or type(observed) is not int or observed < 0:
                differing_keys.append(dotted_key)
        for dotted_key in ("trials.source.queued_inside_pnb_count", "trials.unrelated.queued_inside_pnb_count"):
            observed, present = self._nested_value(baseline, dotted_key)
            if not present or type(observed) is not int or not 0 <= observed <= MEASURED_SAMPLES:
                differing_keys.append(dotted_key)
        for dotted_key in ("warmup.source_queued_inside_pnb", "warmup.unrelated_queued_inside_pnb"):
            observed, present = self._nested_value(baseline, dotted_key)
            if not present or type(observed) is not bool:
                differing_keys.append(dotted_key)
        return sorted(set(differing_keys))

    def _load_and_validate_baseline_summary(self):
        summary_option = Path(self.options.baseline_summary)
        require(summary_option.is_absolute(), "S_COMPARISON_MISMATCH", differing_keys=["baseline_summary.absolute_path"])
        require(summary_option.exists(), "S_COMPARISON_MISMATCH", differing_keys=["baseline_summary.exists"])
        require(not summary_option.is_symlink(), "S_COMPARISON_MISMATCH", differing_keys=["baseline_summary.symlink"])
        require(summary_option.is_file(), "S_COMPARISON_MISMATCH", differing_keys=["baseline_summary.regular_file"])
        try:
            baseline = self._load_strict_json(summary_option)
        except (OSError, UnicodeError, ValueError) as error:
            raise BenchmarkStop("S_COMPARISON_MISMATCH", differing_keys=["baseline_summary.json"], parser_error=str(error)) from error

        schema_differences = self._baseline_schema_differences(baseline)
        require(not schema_differences, "S_COMPARISON_MISMATCH", differing_keys=schema_differences)
        current_harness_sha256 = sha256_file(self.harness_path)
        expected = {
            "schema_version": SCHEMA_VERSION,
            "benchmark.name": "p2p_async_pnb_benchmark",
            "benchmark.variant": "baseline",
            "benchmark.base_commit": BASE_COMMIT,
            "benchmark.transport": "v1",
            "benchmark.node_args": list(NODE_ARGS),
            "benchmark.random_seed": 0,
            "benchmark.port_seed": 16323,
            "benchmark.constants": self._benchmark_constants(),
            "build.harness_sha256": current_harness_sha256,
            "build.cmake_build_type": self.cmake_values["cmake_build_type"],
            "build.cmake_cxx_compiler": self.cmake_values["cmake_cxx_compiler"],
            "build.cmake_cxx_flags": self.cmake_values["cmake_cxx_flags"],
            "environment.platform": platform.platform(),
            "environment.machine": platform.machine(),
            "environment.cpu_count": os.cpu_count(),
        }
        differing_keys = []
        for dotted_key, expected_value in expected.items():
            observed, present = self._nested_value(baseline, dotted_key)
            if not present or not self._same_typed_json_value(observed, expected_value):
                differing_keys.append(dotted_key)
        baseline_head, present = self._nested_value(baseline, "build.build_head")
        if not present or type(baseline_head) is not str or COMMIT_RE.fullmatch(baseline_head) is None:
            differing_keys.append("build.build_head")
        require(not differing_keys, "S_COMPARISON_MISMATCH", differing_keys=sorted(set(differing_keys)))

        parent = self._run_git(["rev-parse", f"{baseline_head}^"])
        require(parent == BASE_COMMIT, "S_BUILD_PROVENANCE", baseline_build_head=baseline_head, baseline_parent=parent, expected_parent=BASE_COMMIT)
        ancestry = subprocess.run(
            ["git", "-C", str(self.source_dir), "merge-base", "--is-ancestor", baseline_head, self.options.build_head],
            capture_output=True,
            text=True,
        )
        require(
            ancestry.returncode == 0,
            "S_BUILD_PROVENANCE",
            baseline_build_head=baseline_head,
            async_build_head=self.options.build_head,
            merge_base_returncode=ancestry.returncode,
            stderr=ancestry.stderr.strip(),
        )
        self.baseline_summary_path = summary_option.resolve()
        self.baseline_summary = baseline

    def _check_preflight(self):
        self._validate_output_directory()
        require(COMMIT_RE.fullmatch(self.options.build_head) is not None, "S_BUILD_PROVENANCE", build_head=self.options.build_head)

        if self.options.variant == "baseline":
            unexpected = []
            if self.options.prototype_commit is not None:
                unexpected.append("--prototype-commit")
            if self.options.baseline_summary is not None:
                unexpected.append("--baseline-summary")
            require(not unexpected, "S_BUILD_PROVENANCE", unexpected_options=unexpected)
        else:
            require(self.options.prototype_commit is not None, "S_ASYNC_COMMIT_REQUIRED")
            require(self.options.baseline_summary is not None, "S_COMPARISON_MISMATCH", differing_keys=["baseline_summary.missing"])
            require(COMMIT_RE.fullmatch(self.options.prototype_commit) is not None, "S_BUILD_PROVENANCE", prototype_commit=self.options.prototype_commit)
            require(self.options.prototype_commit == self.options.build_head, "S_BUILD_PROVENANCE", prototype_commit=self.options.prototype_commit, build_head=self.options.build_head)

        expected_options = {
            "v1transport": True,
            "v2transport": False,
            "randomseed": 0,
            "port_seed": 16323,
            "valgrind": False,
            "trace_rpc": False,
            "usecli": False,
            "timeout_factor": 1,
        }
        observed_options = {key: getattr(self.options, key) for key in expected_options}
        mismatched_options = sorted(key for key, expected in expected_options.items() if observed_options[key] != expected)
        observed_option_facts = {
            key: str(value) if type(value) is float else value
            for key, value in observed_options.items()
        }
        require(
            not mismatched_options,
            "S_BUILD_PROVENANCE",
            mismatched_options=mismatched_options,
            observed_options=observed_option_facts,
        )

        require(self.config.has_option("environment", "SRCDIR"), "S_BUILD_PROVENANCE", missing_config_key="environment.SRCDIR")
        require(self.config.has_option("environment", "BUILDDIR"), "S_BUILD_PROVENANCE", missing_config_key="environment.BUILDDIR")
        require(self.config.has_option("environment", "EXEEXT"), "S_BUILD_PROVENANCE", missing_config_key="environment.EXEEXT")
        self.source_dir = Path(self.config["environment"]["SRCDIR"]).resolve()
        self.build_dir = Path(self.config["environment"]["BUILDDIR"]).resolve()
        require(self.source_dir.is_dir(), "S_BUILD_PROVENANCE", source_dir=str(self.source_dir))
        require(self.build_dir.is_dir(), "S_BUILD_PROVENANCE", build_dir=str(self.build_dir))

        head = self._run_git(["rev-parse", "HEAD"])
        require(head == self.options.build_head, "S_BUILD_PROVENANCE", source_head=head, build_head=self.options.build_head)
        status = self._run_git(["status", "--short"])
        require(status == "", "S_BUILD_PROVENANCE", git_status=status)

        require(self.binary_paths.bitcoin_cmd is None, "S_BUILD_PROVENANCE", bitcoin_cmd=self.binary_paths.bitcoin_cmd)
        configured_binary = Path(self.binary_paths.bitcoind)
        expected_binary = self.build_dir / "bin" / f"bitcoind{self.config['environment']['EXEEXT']}"
        require(not configured_binary.is_symlink(), "S_BUILD_PROVENANCE", binary_path=str(configured_binary), reason="symlink")
        require(configured_binary.resolve() == expected_binary.resolve(), "S_BUILD_PROVENANCE", binary_path=str(configured_binary.resolve()), expected_binary_path=str(expected_binary.resolve()))
        require(configured_binary.is_file(), "S_BUILD_PROVENANCE", binary_path=str(configured_binary), reason="not_regular")
        self.binary_path = configured_binary.resolve()

        harness_file = Path(__file__)
        expected_harness = self.source_dir / "test" / "functional" / "p2p_async_pnb_benchmark.py"
        require(not harness_file.is_symlink(), "S_BUILD_PROVENANCE", harness_path=str(harness_file), reason="symlink")
        require(harness_file.resolve() == expected_harness.resolve(), "S_BUILD_PROVENANCE", harness_path=str(harness_file.resolve()), expected_harness_path=str(expected_harness.resolve()))
        require(harness_file.is_file(), "S_BUILD_PROVENANCE", harness_path=str(harness_file), reason="not_regular")
        self.harness_path = harness_file.resolve()

        self._read_cmake_cache()
        if self.options.variant == "baseline":
            parent = self._run_git(["rev-parse", "HEAD^"])
            require(parent == BASE_COMMIT, "S_BUILD_PROVENANCE", build_parent=parent, expected_parent=BASE_COMMIT)
            self.baseline_summary = None
            self.baseline_summary_path = None
        else:
            self._load_and_validate_baseline_summary()

    def write_failure(self, error):
        require(not self.failure_written, "S_CODE_PLAN_MISMATCH", duplicate_failure_writer=True)
        failure = {
            "build_head": self.options.build_head,
            "code": error.code,
            "completed_records": self.completed_records,
            "facts": error.facts,
            "schema_version": SCHEMA_VERSION,
            "variant": self.options.variant,
        }
        with (self.output_dir / "failure.json").open("x", encoding="utf-8", newline="\n") as failure_file:
            json.dump(failure, failure_file, sort_keys=True, indent=2, allow_nan=False)
            failure_file.write("\n")
            failure_file.flush()
        self.failure_written = True

    def _marker_parser_self_check(self):
        block_hash = "0" * 64
        valid_cases = [
            (
                f"log prefix ASYNC_PNB_BENCH event=pnb_start hash={block_hash} node_ns=-1 steady_ns=2\n".encode(),
                {"event": "pnb_start", "hash": block_hash, "node_ns": -1, "steady_ns": 2},
            ),
            (
                f"ASYNC_PNB_BENCH event=pnb_end hash={block_hash} node_ns=3 steady_ns=4 duration_ns=1\r\n".encode(),
                {"event": "pnb_end", "hash": block_hash, "node_ns": 3, "steady_ns": 4, "duration_ns": 1},
            ),
            (
                b"ASYNC_PNB_BENCH event=pong_queued peer=-2 nonce=5 recv_node_ns=7 queued_node_ns=11 queued_steady_ns=13 queue_ns=4\n",
                {
                    "event": "pong_queued",
                    "peer": -2,
                    "nonce": 5,
                    "recv_node_ns": 7,
                    "queued_node_ns": 11,
                    "queued_steady_ns": 13,
                    "queue_ns": 4,
                },
            ),
        ]
        for line, expected in valid_cases:
            parsed = MarkerReader.parse_line(line)
            require(parsed == expected, "S_CODE_PLAN_MISMATCH", parser_self_check="valid_line", observed=parsed, expected=expected)

        invalid_cases = [
            f"ASYNC_PNB_BENCH hash={block_hash} event=pnb_start node_ns=1 steady_ns=2\n".encode(),
            f"ASYNC_PNB_BENCH event=pnb_start hash={block_hash} node_ns=1 node_ns=1 steady_ns=2\n".encode(),
            f"ASYNC_PNB_BENCH event=pnb_start hash={'A' * 64} node_ns=1 steady_ns=2\n".encode(),
            f"ASYNC_PNB_BENCH event=pnb_start hash={block_hash} node_ns=01 steady_ns=2\n".encode(),
            b"ASYNC_PNB_BENCH event=pong_queued peer=1 nonce=2 recv_node_ns=3 queued_node_ns=5 queued_steady_ns=7 queue_ns=1\n",
            b"ASYNC_PNB_BENCH event=unknown value=1\n",
        ]
        for line in invalid_cases:
            rejected = False
            try:
                MarkerReader.parse_line(line)
            except MarkerParseError:
                rejected = True
            require(rejected, "S_CODE_PLAN_MISMATCH", parser_self_check="invalid_line_accepted", line_hex=line.hex())

    def _require_chain_state(self, expected_height, expected_tip=None):
        node = self.nodes[0]
        observed_height = node.getblockcount()
        observed_tip = node.getbestblockhash()
        mempool = node.getrawmempool()
        require(observed_height == expected_height, "S_CHAINSTATE_MISMATCH", height=observed_height, expected_height=expected_height)
        if expected_tip is not None:
            require(observed_tip == expected_tip, "S_CHAINSTATE_MISMATCH", tip=observed_tip, expected_tip=expected_tip)
        require(mempool == [], "S_CHAINSTATE_MISMATCH", mempool=mempool)

    def _wait_for_tip(self, block_hash):
        self.wait_until(
            lambda: self.nodes[0].getbestblockhash() == block_hash,
            timeout=BASE_TIMEOUT_SECONDS,
            check_interval=MARKER_POLL_SECONDS,
        )

    @staticmethod
    def _require_unrequested(peer, block):
        with p2p_lock:
            request_count = peer.requested_blocks.count(block.hash_int)
        require(request_count == 0, "S_BLOCK_REQUEST", block_hash=block.hash_hex, prior_count=request_count)

    def _announce_and_wait_for_request(self, peer, block):
        self._require_unrequested(peer, block)
        peer.send_without_ping(msg_headers([CBlockHeader(block)]))
        peer.wait_for_block_request(block.hash_int, BASE_TIMEOUT_SECONDS)
        require(peer.is_connected, "S_PEER_DISCONNECTED", operation="block_request", block_hash=block.hash_hex)

    def _deliver_setup_block(self, setup_peer, block):
        self._announce_and_wait_for_request(setup_peer, block)
        setup_peer.send_without_ping(msg_block(block))
        self._wait_for_tip(block.hash_hex)
        setup_peer.sync_with_ping(timeout=BASE_TIMEOUT_SECONDS)

    def _create_funding_block(self, node, address_wallet, raw_p2pk_wallet):
        utxos = address_wallet.get_utxos(mark_as_spent=False, confirmed_only=True)
        require(bool(utxos), "S_CHAINSTATE_MISMATCH", funding_utxos=0)
        selected = min(utxos, key=lambda utxo: (utxo["txid"], utxo["vout"]))
        selected_sat = int(selected["value"] * COIN)
        required_sat = FUNDING_FEE_SAT + (WARMUP_SAMPLES + MEASURED_SAMPLES) * INCLUDED_CHAIN_TXS
        require(selected_sat > required_sat, "S_CHAINSTATE_MISMATCH", funding_value_sat=selected_sat, required_greater_than_sat=required_sat)

        funding_result = address_wallet.create_self_transfer(
            utxo_to_spend=selected,
            fee_rate=0,
            fee=Decimal(FUNDING_FEE_SAT) / COIN,
        )
        funding_tx = funding_result["tx"]
        require(len(funding_tx.vin) == 1 and len(funding_tx.vout) == 1, "S_WORKLOAD_MISMATCH", funding_inputs=len(funding_tx.vin), funding_outputs=len(funding_tx.vout))
        funding_tx.vout[0].scriptPubKey = CScript(raw_p2pk_wallet.get_output_script())
        address_wallet.sign_tx(funding_tx)
        input_sat = int(selected["value"] * COIN)
        output_sat = funding_tx.vout[0].nValue
        require(input_sat - output_sat == FUNDING_FEE_SAT, "S_WORKLOAD_MISMATCH", funding_fee_sat=input_sat - output_sat, expected_funding_fee_sat=FUNDING_FEE_SAT)
        seed = {
            "txid": funding_tx.txid_hex,
            "vout": 0,
            "value": Decimal(funding_tx.vout[0].nValue) / COIN,
        }

        template = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        require(template["previousblockhash"] == node.getbestblockhash(), "S_CHAINSTATE_MISMATCH", template_previous=template["previousblockhash"], tip=node.getbestblockhash())
        require(template["height"] == node.getblockcount() + 1, "S_CHAINSTATE_MISMATCH", template_height=template["height"], expected_height=node.getblockcount() + 1)
        coinbase = create_coinbase(height=template["height"], fees=FUNDING_FEE_SAT)
        funding_block = create_block(tmpl=template, coinbase=coinbase, txlist=[funding_tx])
        add_witness_commitment(funding_block)
        funding_block.solve()
        require(funding_block.is_valid(), "S_WORKLOAD_MISMATCH", funding_block_valid=False)
        return funding_block, seed

    def build_work_block(self, node, raw_p2pk_wallet, seed):
        mempool = node.getrawmempool()
        require(mempool == [], "S_CHAINSTATE_MISMATCH", mempool=mempool)
        template = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        current_tip = node.getbestblockhash()
        current_height = node.getblockcount()
        require(template["previousblockhash"] == current_tip, "S_CHAINSTATE_MISMATCH", template_previous=template["previousblockhash"], tip=current_tip)
        require(template["height"] == current_height + 1, "S_CHAINSTATE_MISMATCH", template_height=template["height"], expected_height=current_height + 1)

        expected_script = bytes(raw_p2pk_wallet.get_output_script())
        results = []
        current_seed = seed
        for index in range(GENERATED_CHAIN_TXS):
            result = raw_p2pk_wallet.create_self_transfer(
                fee_rate=0,
                fee=Decimal("0.00000001"),
                utxo_to_spend=current_seed,
            )
            transaction = result["tx"]
            txid_before_normalization = transaction.txid_hex
            require(len(transaction.vout) == 1, "S_WORKLOAD_MISMATCH", transaction_index=index, outputs=len(transaction.vout))
            transaction.vout[0].scriptPubKey = CScript(transaction.vout[0].scriptPubKey)
            require(transaction.txid_hex == txid_before_normalization, "S_WORKLOAD_MISMATCH", transaction_index=index, normalization_changed_txid=True)
            require(len(transaction.vin) == 1, "S_WORKLOAD_MISMATCH", transaction_index=index, inputs=len(transaction.vin))
            require(transaction.vin[0].prevout.hash == int(current_seed["txid"], 16), "S_WORKLOAD_MISMATCH", transaction_index=index, prevout_hash=f"{transaction.vin[0].prevout.hash:064x}", expected_prevout_hash=current_seed["txid"])
            require(transaction.vin[0].prevout.n == 0, "S_WORKLOAD_MISMATCH", transaction_index=index, prevout_n=transaction.vin[0].prevout.n)
            require(len(transaction.vin[0].scriptSig) == 73, "S_WORKLOAD_MISMATCH", transaction_index=index, script_sig_bytes=len(transaction.vin[0].scriptSig))
            require(transaction.wit.is_null(), "S_WORKLOAD_MISMATCH", transaction_index=index, witness_null=False)
            require(bytes(transaction.vout[0].scriptPubKey) == expected_script, "S_WORKLOAD_MISMATCH", transaction_index=index, output_script=bytes(transaction.vout[0].scriptPubKey).hex())
            require(transaction.get_vsize() == 168, "S_WORKLOAD_MISMATCH", transaction_index=index, vsize=transaction.get_vsize())
            input_value_sat = int(current_seed["value"] * COIN)
            require(input_value_sat - transaction.vout[0].nValue == CHAIN_TX_FEE_SAT, "S_WORKLOAD_MISMATCH", transaction_index=index, fee_sat=input_value_sat - transaction.vout[0].nValue)
            results.append(result)
            current_seed = result["new_utxo"]

        included_results = results[:INCLUDED_CHAIN_TXS]
        included_transactions = [result["tx"] for result in included_results]
        all_transactions = [result["tx"] for result in results]
        retained_coinbase = create_coinbase(height=template["height"], fees=INCLUDED_CHAIN_TXS * CHAIN_TX_FEE_SAT)
        overflow_coinbase = create_coinbase(height=template["height"], fees=GENERATED_CHAIN_TXS * CHAIN_TX_FEE_SAT)
        block = create_block(tmpl=template, coinbase=retained_coinbase, txlist=included_transactions)
        overflow_block = create_block(tmpl=template, coinbase=overflow_coinbase, txlist=all_transactions)

        weight = block.get_weight()
        overflow_weight = overflow_block.get_weight()
        serialized_bytes = len(block.serialize())
        require(weight == EXPECTED_BLOCK_WEIGHT, "S_WORKLOAD_MISMATCH", block_weight=weight, expected_block_weight=EXPECTED_BLOCK_WEIGHT)
        require(overflow_weight == EXPECTED_OVERFLOW_WEIGHT, "S_WORKLOAD_MISMATCH", overflow_weight=overflow_weight, expected_overflow_weight=EXPECTED_OVERFLOW_WEIGHT)
        require(serialized_bytes == EXPECTED_BLOCK_BYTES, "S_WORKLOAD_MISMATCH", serialized_bytes=serialized_bytes, expected_serialized_bytes=EXPECTED_BLOCK_BYTES)
        require(weight <= TARGET_WEIGHT, "S_WORKLOAD_MISMATCH", block_weight=weight, target_weight=TARGET_WEIGHT)
        require(overflow_weight > TARGET_WEIGHT, "S_WORKLOAD_MISMATCH", overflow_weight=overflow_weight, target_weight=TARGET_WEIGHT)
        require(weight <= MAX_BLOCK_WEIGHT, "S_WORKLOAD_MISMATCH", block_weight=weight, max_block_weight=MAX_BLOCK_WEIGHT)

        legacy_sigops = get_legacy_sigopcount_block(block)
        sigops_cost = legacy_sigops * WITNESS_SCALE_FACTOR
        require(legacy_sigops == EXPECTED_LEGACY_SIGOPS, "S_WORKLOAD_MISMATCH", legacy_sigops=legacy_sigops, expected_legacy_sigops=EXPECTED_LEGACY_SIGOPS)
        require(sigops_cost == EXPECTED_SIGOPS_COST, "S_WORKLOAD_MISMATCH", sigops_cost=sigops_cost, expected_sigops_cost=EXPECTED_SIGOPS_COST)
        require(sigops_cost <= MAX_BLOCK_SIGOPS_COST, "S_WORKLOAD_MISMATCH", sigops_cost=sigops_cost, max_sigops_cost=MAX_BLOCK_SIGOPS_COST)

        txids = [transaction.txid_hex for transaction in included_transactions]
        require(len(set(txids)) == INCLUDED_CHAIN_TXS, "S_WORKLOAD_MISMATCH", unique_txids=len(set(txids)), expected_unique_txids=INCLUDED_CHAIN_TXS)
        mempool_txids = set(node.getrawmempool())
        present_txids = sorted(txid for txid in txids if txid in mempool_txids)
        require(not present_txids, "S_WORKLOAD_MISMATCH", transactions_in_mempool=present_txids)
        require(all(transaction.wit.is_null() for transaction in included_transactions), "S_WORKLOAD_MISMATCH", included_witness_null=False)

        fingerprint_hasher = hashlib.sha256()
        for transaction in included_transactions:
            raw = transaction.serialize()
            fingerprint_hasher.update(len(raw).to_bytes(4, "little"))
            fingerprint_hasher.update(raw)
        fingerprint = fingerprint_hasher.hexdigest()

        block.solve()
        require(block.is_valid(), "S_WORKLOAD_MISMATCH", block_valid=False, height=template["height"])
        return {
            "block": block,
            "next_seed": included_results[-1]["new_utxo"],
            "tx_payload_sha256": fingerprint,
            "weight": weight,
            "serialized_bytes": serialized_bytes,
            "legacy_sigops": legacy_sigops,
            "sigops_cost": sigops_cost,
            "height": template["height"],
        }

    def _map_peer_id(self, peer):
        require(peer.is_connected, "S_PEER_DISCONNECTED", operation="map_peer_id")
        transport_socket = peer._transport.get_extra_info("socket") if peer._transport is not None else None
        require(transport_socket is not None, "S_PEER_ID", reason="missing_socket")
        socket_name = transport_socket.getsockname()
        expected_addr = f"{socket_name[0]}:{socket_name[1]}"
        expected_addrbind = f"{peer.dstaddr}:{peer.dstport}"
        matches = [
            info for info in self.nodes[0].getpeerinfo()
            if info["addr"] == expected_addr and info["addrbind"] == expected_addrbind
        ]
        require(len(matches) == 1, "S_PEER_ID", addr=expected_addr, addrbind=expected_addrbind, match_count=len(matches))
        require(matches[0]["subver"] == P2P_SUBVERSION, "S_PEER_ID", subver=matches[0]["subver"], expected_subver=P2P_SUBVERSION)
        require(type(matches[0]["id"]) is int, "S_PEER_ID", peer_id_type=type(matches[0]["id"]).__name__)
        return matches[0]["id"]

    @staticmethod
    def _validate_pong_marker(marker, nonce, peer_id):
        require(marker["nonce"] == nonce, "S_CODE_PLAN_MISMATCH", pong_nonce=marker["nonce"], expected_nonce=nonce)
        require(marker["peer"] == peer_id, "S_PEER_ID", marker_peer=marker["peer"], expected_peer=peer_id, nonce=nonce)
        require(marker["queue_ns"] == marker["queued_node_ns"] - marker["recv_node_ns"], "S_CLOCK_DISCONTINUITY", nonce=nonce, queue_ns=marker["queue_ns"])

    def _control_probe(self, role, nonce, peer_id, timing, marker):
        self._validate_pong_marker(marker, nonce, peer_id)
        sent_perf_ns, response_perf_ns = timing
        require(response_perf_ns >= sent_perf_ns, "S_CLOCK_DISCONTINUITY", role=role, sent_perf_ns=sent_perf_ns, response_perf_ns=response_perf_ns)
        require(
            marker["queued_node_ns"] >= marker["recv_node_ns"],
            "S_CLOCK_DISCONTINUITY",
            role=role,
            queued_node_ns=marker["queued_node_ns"],
            receive_node_ns=marker["recv_node_ns"],
        )
        return {
            "nonce": nonce,
            "node_queue_ns": marker["queue_ns"],
            "peer_id": peer_id,
            "python_response_perf_ns": response_perf_ns,
            "python_rtt_ns": response_perf_ns - sent_perf_ns,
            "python_send_perf_ns": sent_perf_ns,
            "queued_inside_pnb": None,
            "queued_node_ns": marker["queued_node_ns"],
            "queued_steady_ns": marker["queued_steady_ns"],
            "receive_node_ns": marker["recv_node_ns"],
            "received_inside_pnb": None,
            "role": role,
        }

    def _timed_probe(self, role, nonce, peer_id, timing, marker, pnb):
        self._validate_pong_marker(marker, nonce, peer_id)
        sent_perf_ns, response_perf_ns = timing
        require(response_perf_ns >= sent_perf_ns, "S_CLOCK_DISCONTINUITY", role=role, sent_perf_ns=sent_perf_ns, response_perf_ns=response_perf_ns)
        require(marker["queued_node_ns"] >= marker["recv_node_ns"], "S_CLOCK_DISCONTINUITY", role=role, queued_node_ns=marker["queued_node_ns"], receive_node_ns=marker["recv_node_ns"])
        received_inside = pnb["start_node_ns"] <= marker["recv_node_ns"] <= pnb["end_node_ns"]
        queued_inside = pnb["start_steady_ns"] <= marker["queued_steady_ns"] < pnb["end_steady_ns"]
        return {
            "nonce": nonce,
            "node_queue_ns": marker["queue_ns"],
            "peer_id": peer_id,
            "python_response_perf_ns": response_perf_ns,
            "python_rtt_ns": response_perf_ns - sent_perf_ns,
            "python_send_perf_ns": sent_perf_ns,
            "queued_inside_pnb": queued_inside,
            "queued_node_ns": marker["queued_node_ns"],
            "queued_steady_ns": marker["queued_steady_ns"],
            "receive_node_ns": marker["recv_node_ns"],
            "received_inside_pnb": received_inside,
            "role": role,
        }

    @staticmethod
    def _pnb_result(start_marker, end_marker):
        require(start_marker["hash"] == end_marker["hash"], "S_CODE_PLAN_MISMATCH", start_hash=start_marker["hash"], end_hash=end_marker["hash"])
        pnb = {
            "duration_ns": end_marker["duration_ns"],
            "end_node_ns": end_marker["node_ns"],
            "end_steady_ns": end_marker["steady_ns"],
            "start_node_ns": start_marker["node_ns"],
            "start_steady_ns": start_marker["steady_ns"],
        }
        node_span = pnb["end_node_ns"] - pnb["start_node_ns"]
        steady_span = pnb["end_steady_ns"] - pnb["start_steady_ns"]
        require(pnb["end_node_ns"] >= pnb["start_node_ns"], "S_CLOCK_DISCONTINUITY", node_span_ns=node_span)
        require(pnb["end_steady_ns"] >= pnb["start_steady_ns"], "S_CLOCK_DISCONTINUITY", steady_span_ns=steady_span)
        require(pnb["duration_ns"] > 0, "S_CLOCK_DISCONTINUITY", duration_ns=pnb["duration_ns"])
        require(pnb["duration_ns"] <= steady_span, "S_CLOCK_DISCONTINUITY", duration_ns=pnb["duration_ns"], steady_span_ns=steady_span)
        require(steady_span - pnb["duration_ns"] <= 10_000_000, "S_CLOCK_DISCONTINUITY", marker_overhead_ns=steady_span - pnb["duration_ns"])
        clock_allowance = max(5_000_000, steady_span // 1000)
        require(abs(node_span - steady_span) <= clock_allowance, "S_CLOCK_DISCONTINUITY", node_span_ns=node_span, steady_span_ns=steady_span, allowance_ns=clock_allowance)
        return pnb

    @staticmethod
    def _workload_result(work):
        return {
            "block_hash": work["block"].hash_hex,
            "height": work["height"],
            "legacy_sigops": work["legacy_sigops"],
            "non_coinbase_txs": INCLUDED_CHAIN_TXS,
            "serialized_bytes": work["serialized_bytes"],
            "sigops_cost": work["sigops_cost"],
            "total_fees_sat": INCLUDED_CHAIN_TXS * CHAIN_TX_FEE_SAT,
            "tx_payload_sha256": work["tx_payload_sha256"],
            "weight": work["weight"],
        }

    def _write_record(self, record):
        require(self.samples_file is not None and not self.samples_file.closed, "S_CODE_PLAN_MISMATCH", samples_file_open=False)
        self.samples_file.write(json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n")
        self.samples_file.flush()
        self.completed_records += 1

    def _collect_control_pair(self, index):
        checkpoint = self.marker_reader.sequence_checkpoint()
        unrelated_nonce = UNRELATED_CONTROL_NONCE + index
        source_nonce = SOURCE_CONTROL_NONCE + index
        self.peer_b.begin_ping(unrelated_nonce)
        self.peer_a.begin_ping(source_nonce)
        unrelated_timing = self.peer_b.finish_ping(BASE_TIMEOUT_SECONDS)
        source_timing = self.peer_a.finish_ping(BASE_TIMEOUT_SECONDS)
        unrelated_marker = self.marker_reader.wait_pong(unrelated_nonce, checkpoint)
        source_marker = self.marker_reader.wait_pong(source_nonce, checkpoint)
        unrelated = self._control_probe("unrelated", unrelated_nonce, self.peer_b_id, unrelated_timing, unrelated_marker)
        source = self._control_probe("source", source_nonce, self.peer_a_id, source_timing, source_marker)
        unrelated_record = {
            "schema_version": SCHEMA_VERSION,
            "record_type": "control",
            "index": index,
            "probe": unrelated,
        }
        source_record = {
            "schema_version": SCHEMA_VERSION,
            "record_type": "control",
            "index": index,
            "probe": source,
        }
        self._write_record(unrelated_record)
        self._write_record(source_record)
        self.control_records.extend((unrelated_record, source_record))

    def _collect_timed_block(self, record_type, index, work):
        block = work["block"]
        raw_block_message = self.peer_a.build_message(msg_block(block))
        self._announce_and_wait_for_request(self.peer_a, block)
        checkpoint = self.marker_reader.sequence_checkpoint()
        self.peer_a.send_raw_message(raw_block_message)
        start_marker = self.marker_reader.wait_pnb_start(block.hash_hex, checkpoint)

        unrelated_nonce = UNRELATED_CONTENDED_NONCE + index
        source_nonce = SOURCE_CONTENDED_NONCE + index
        self.peer_b.begin_ping(unrelated_nonce)
        self.peer_a.begin_ping(source_nonce)
        unrelated_timing = self.peer_b.finish_ping(BASE_TIMEOUT_SECONDS)
        source_timing = self.peer_a.finish_ping(BASE_TIMEOUT_SECONDS)
        unrelated_marker = self.marker_reader.wait_pong(unrelated_nonce, checkpoint)
        source_marker = self.marker_reader.wait_pong(source_nonce, checkpoint)
        end_marker = self.marker_reader.wait_pnb_end(block.hash_hex, checkpoint)

        self._wait_for_tip(block.hash_hex)
        self._require_chain_state(work["height"], block.hash_hex)
        require(self.peer_a.is_connected and self.peer_b.is_connected, "S_PEER_DISCONNECTED", operation="timed_block", block_hash=block.hash_hex)

        pnb = self._pnb_result(start_marker, end_marker)
        unrelated = self._timed_probe("unrelated", unrelated_nonce, self.peer_b_id, unrelated_timing, unrelated_marker, pnb)
        source = self._timed_probe("source", source_nonce, self.peer_a_id, source_timing, source_marker, pnb)
        require(source["received_inside_pnb"] and unrelated["received_inside_pnb"], "S_NO_OVERLAP", block_hash=block.hash_hex, source_received_inside_pnb=source["received_inside_pnb"], unrelated_received_inside_pnb=unrelated["received_inside_pnb"])
        if record_type == "warmup":
            require(pnb["duration_ns"] >= MIN_WARMUP_PNB_NS, "S_WORKLOAD_TOO_FAST", duration_ns=pnb["duration_ns"], minimum_ns=MIN_WARMUP_PNB_NS)

        record = {
            "schema_version": SCHEMA_VERSION,
            "record_type": record_type,
            "index": index,
            "pnb": pnb,
            "source": source,
            "unrelated": unrelated,
            "workload": self._workload_result(work),
        }
        self._write_record(record)
        return record

    def run_benchmark(self):
        self.started_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self._marker_parser_self_check()
        node = self.nodes[0]
        chain_info = node.getblockchaininfo()
        require(chain_info["blocks"] == 200, "S_CHAINSTATE_MISMATCH", height=chain_info["blocks"], expected_height=200)
        require(chain_info["initialblockdownload"] is False, "S_CHAINSTATE_MISMATCH", initialblockdownload=chain_info["initialblockdownload"])
        require(node.getrawmempool() == [], "S_CHAINSTATE_MISMATCH", mempool=node.getrawmempool())

        setup_peer = node.add_p2p_connection(BenchmarkPeer())
        address_wallet = MiniWallet(node)
        raw_p2pk_wallet = MiniWallet(node, mode=MiniWalletMode.RAW_P2PK)
        funding_block, seed = self._create_funding_block(node, address_wallet, raw_p2pk_wallet)
        require(funding_block.hashPrevBlock == int(node.getbestblockhash(), 16), "S_CHAINSTATE_MISMATCH", funding_previous=f"{funding_block.hashPrevBlock:064x}", tip=node.getbestblockhash())
        self._deliver_setup_block(setup_peer, funding_block)
        self._require_chain_state(201, funding_block.hash_hex)
        funding_txout = node.gettxout(seed["txid"], seed["vout"])
        require(funding_txout is not None, "S_CHAINSTATE_MISMATCH", funding_txid=seed["txid"], funding_vout=seed["vout"], unspent=False)
        require(
            funding_txout["value"] == seed["value"],
            "S_CHAINSTATE_MISMATCH",
            funding_value=str(funding_txout["value"]),
            expected_value=str(seed["value"]),
        )
        self.setup_funding_txid = seed["txid"]
        node.disconnect_p2ps()
        require(node.num_test_p2p_connections() == 0, "S_CHAINSTATE_MISMATCH", test_p2p_connections=node.num_test_p2p_connections())

        self.peer_a = node.add_p2p_connection(BenchmarkPeer())
        self.peer_b = node.add_p2p_connection(BenchmarkPeer())
        self.peer_a_id = self._map_peer_id(self.peer_a)
        self.peer_b_id = self._map_peer_id(self.peer_b)
        require(self.peer_a_id != self.peer_b_id, "S_PEER_ID", source_peer_id=self.peer_a_id, unrelated_peer_id=self.peer_b_id)
        self.marker_reader = MarkerReader(node.debug_log_path, BASE_TIMEOUT_SECONDS * self.options.timeout_factor)

        self.control_records = []
        self.trial_records = []
        for control_index in range(CONTROL_SAMPLES):
            self._collect_control_pair(control_index)

        warmup_work = self.build_work_block(node, raw_p2pk_wallet, seed)
        require(warmup_work["height"] == 202, "S_CHAINSTATE_MISMATCH", warmup_height=warmup_work["height"], expected_height=202)
        self.warmup_record = self._collect_timed_block("warmup", 0, warmup_work)
        seed = warmup_work["next_seed"]
        last_block_hash = warmup_work["block"].hash_hex

        for trial_index in range(1, MEASURED_SAMPLES + 1):
            work = self.build_work_block(node, raw_p2pk_wallet, seed)
            expected_height = 202 + trial_index
            require(work["height"] == expected_height, "S_CHAINSTATE_MISMATCH", trial_index=trial_index, height=work["height"], expected_height=expected_height)
            record = self._collect_timed_block("trial", trial_index, work)
            self.trial_records.append(record)
            seed = work["next_seed"]
            last_block_hash = work["block"].hash_hex

        self._require_chain_state(222, last_block_hash)
        require(self.peer_a.is_connected and self.peer_b.is_connected, "S_PEER_DISCONNECTED", operation="final_state")
        require(node.num_test_p2p_connections() == 2, "S_CHAINSTATE_MISMATCH", test_p2p_connections=node.num_test_p2p_connections(), expected_connections=2)
        self.marker_reader.assert_all_consumed()
        require(self.completed_records == 41, "S_CODE_PLAN_MISMATCH", completed_records=self.completed_records, expected_records=41)

        self.ended_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        summary = self._build_summary()
        comparison = None
        if self.options.variant == "async":
            self._validate_post_run_comparison(summary)
            comparison = self._build_comparison(summary)
        self._write_success_outputs(summary, comparison)

    @staticmethod
    def _control_metrics(records, role):
        probes = [record["probe"] for record in records if record["probe"]["role"] == role]
        require(len(probes) == CONTROL_SAMPLES, "S_CODE_PLAN_MISMATCH", control_role=role, sample_count=len(probes))
        return {
            "sample_count": len(probes),
            "node_queue_ns_p50": percentile([probe["node_queue_ns"] for probe in probes], 50),
            "node_queue_ns_p95": percentile([probe["node_queue_ns"] for probe in probes], 95),
            "python_rtt_ns_p50": percentile([probe["python_rtt_ns"] for probe in probes], 50),
            "python_rtt_ns_p95": percentile([probe["python_rtt_ns"] for probe in probes], 95),
        }

    def _trial_metrics(self, role):
        probes = [record[role] for record in self.trial_records]
        require(len(probes) == MEASURED_SAMPLES, "S_CODE_PLAN_MISMATCH", trial_role=role, sample_count=len(probes))
        receive_offsets = [
            record[role]["receive_node_ns"] - record["pnb"]["start_node_ns"]
            for record in self.trial_records
        ]
        return {
            "sample_count": len(probes),
            "node_queue_ns_p50": percentile([probe["node_queue_ns"] for probe in probes], 50),
            "node_queue_ns_p95": percentile([probe["node_queue_ns"] for probe in probes], 95),
            "python_rtt_ns_p50": percentile([probe["python_rtt_ns"] for probe in probes], 50),
            "python_rtt_ns_p95": percentile([probe["python_rtt_ns"] for probe in probes], 95),
            "queued_inside_pnb_count": sum(probe["queued_inside_pnb"] for probe in probes),
            "receive_offset_ns_p50": percentile(receive_offsets, 50),
            "receive_offset_ns_p95": percentile(receive_offsets, 95),
        }

    def _build_summary(self):
        require(len(self.trial_records) == MEASURED_SAMPLES, "S_CODE_PLAN_MISMATCH", trial_records=len(self.trial_records))
        workload_keys = (
            "weight",
            "serialized_bytes",
            "non_coinbase_txs",
            "legacy_sigops",
            "sigops_cost",
            "total_fees_sat",
        )
        common_workload = {}
        for key in workload_keys:
            values = {record["workload"][key] for record in self.trial_records}
            require(len(values) == 1, "S_WORKLOAD_MISMATCH", workload_key=key, values=sorted(values))
            common_workload[key] = values.pop()
        heights = [record["workload"]["height"] for record in self.trial_records]
        require(heights == list(range(203, 223)), "S_CHAINSTATE_MISMATCH", trial_heights=heights)

        fingerprints = [self.warmup_record["workload"]["tx_payload_sha256"]]
        fingerprints.extend(record["workload"]["tx_payload_sha256"] for record in self.trial_records)
        require(len(fingerprints) == 21 and all(HASH_RE.fullmatch(value) is not None for value in fingerprints), "S_WORKLOAD_MISMATCH", workload_fingerprints=fingerprints)
        cpu_count = os.cpu_count()
        require(type(cpu_count) is int and cpu_count > 0, "S_BUILD_PROVENANCE", cpu_count=cpu_count)

        pnb_durations = [record["pnb"]["duration_ns"] for record in self.trial_records]
        summary = {
            "schema_version": SCHEMA_VERSION,
            "benchmark": {
                "name": "p2p_async_pnb_benchmark",
                "variant": self.options.variant,
                "base_commit": BASE_COMMIT,
                "transport": "v1",
                "node_args": list(NODE_ARGS),
                "random_seed": 0,
                "port_seed": 16323,
                "constants": self._benchmark_constants(),
                "setup_funding_txid": self.setup_funding_txid,
                "workload_fingerprints": fingerprints,
            },
            "build": {
                "build_head": self.options.build_head,
                "prototype_commit": self.options.prototype_commit if self.options.variant == "async" else None,
                "binary_path": str(self.binary_path),
                "binary_sha256": sha256_file(self.binary_path),
                "harness_sha256": sha256_file(self.harness_path),
                "cmake_build_type": self.cmake_values["cmake_build_type"],
                "cmake_cxx_compiler": self.cmake_values["cmake_cxx_compiler"],
                "cmake_cxx_flags": self.cmake_values["cmake_cxx_flags"],
            },
            "environment": {
                "platform": platform.platform(),
                "machine": platform.machine(),
                "cpu_count": cpu_count,
                "python_version": platform.python_version(),
                "started_utc": self.started_utc,
                "ended_utc": self.ended_utc,
            },
            "controls": {
                "source": self._control_metrics(self.control_records, "source"),
                "unrelated": self._control_metrics(self.control_records, "unrelated"),
            },
            "warmup": {
                "pnb_duration_ns": self.warmup_record["pnb"]["duration_ns"],
                "source_queued_inside_pnb": self.warmup_record["source"]["queued_inside_pnb"],
                "unrelated_queued_inside_pnb": self.warmup_record["unrelated"]["queued_inside_pnb"],
                "tx_payload_sha256": self.warmup_record["workload"]["tx_payload_sha256"],
            },
            "trials": {
                "accepted_blocks": MEASURED_SAMPLES,
                "pnb": {
                    "sample_count": MEASURED_SAMPLES,
                    "duration_ns_p50": percentile(pnb_durations, 50),
                    "duration_ns_p95": percentile(pnb_durations, 95),
                },
                "source": self._trial_metrics("source"),
                "unrelated": self._trial_metrics("unrelated"),
                "workload": {
                    "height_first": heights[0],
                    "height_last": heights[-1],
                    **common_workload,
                },
            },
            "marker_counts": dict(self.marker_reader.counts),
        }
        return summary

    def _validate_post_run_comparison(self, summary):
        differing_keys = []
        comparisons = {
            "benchmark.setup_funding_txid": summary["benchmark"]["setup_funding_txid"],
            "benchmark.workload_fingerprints": summary["benchmark"]["workload_fingerprints"],
        }
        for dotted_key, async_value in comparisons.items():
            baseline_value, present = self._nested_value(self.baseline_summary, dotted_key)
            if not present or baseline_value != async_value:
                differing_keys.append(dotted_key)
        require(not differing_keys, "S_COMPARISON_MISMATCH", differing_keys=sorted(differing_keys))

    def _build_comparison(self, summary):
        baseline = self.baseline_summary
        baseline_source_early = baseline["trials"]["source"]["queued_inside_pnb_count"]
        async_source_early = summary["trials"]["source"]["queued_inside_pnb_count"]
        baseline_unrelated_early = baseline["trials"]["unrelated"]["queued_inside_pnb_count"]
        async_unrelated_early = summary["trials"]["unrelated"]["queued_inside_pnb_count"]
        baseline_queue_p50 = baseline["trials"]["unrelated"]["node_queue_ns_p50"]
        async_queue_p50 = summary["trials"]["unrelated"]["node_queue_ns_p50"]
        baseline_queue_p95 = baseline["trials"]["unrelated"]["node_queue_ns_p95"]
        async_queue_p95 = summary["trials"]["unrelated"]["node_queue_ns_p95"]

        if baseline_source_early != 0 or async_source_early != 0:
            status = "ORDERING_FAILURE"
        elif baseline_unrelated_early != 0:
            status = "BASELINE_NOT_SYNCHRONOUS"
        elif async_unrelated_early >= 18 and async_queue_p50 < baseline_queue_p50 and async_queue_p95 < baseline_queue_p95:
            status = "BENEFIT_DEMONSTRATED"
        else:
            status = "BENEFIT_NOT_DEMONSTRATED"

        baseline_rtt_p50 = baseline["trials"]["unrelated"]["python_rtt_ns_p50"]
        async_rtt_p50 = summary["trials"]["unrelated"]["python_rtt_ns_p50"]
        baseline_rtt_p95 = baseline["trials"]["unrelated"]["python_rtt_ns_p95"]
        async_rtt_p95 = summary["trials"]["unrelated"]["python_rtt_ns_p95"]
        baseline_pnb_p50 = baseline["trials"]["pnb"]["duration_ns_p50"]
        async_pnb_p50 = summary["trials"]["pnb"]["duration_ns_p50"]
        baseline_pnb_p95 = baseline["trials"]["pnb"]["duration_ns_p95"]
        async_pnb_p95 = summary["trials"]["pnb"]["duration_ns_p95"]
        require(baseline_pnb_p50 > 0 and baseline_pnb_p95 > 0, "S_COMPARISON_MISMATCH", differing_keys=["trials.pnb.duration"])
        warnings = []
        if async_pnb_p50 * 100 > baseline_pnb_p50 * 110 or async_pnb_p95 * 100 > baseline_pnb_p95 * 110:
            warnings.append("PNB_DURATION_REGRESSION_WARNING")
        warnings.sort()

        return {
            "schema_version": SCHEMA_VERSION,
            "status": status,
            "warnings": warnings,
            "baseline_build_head": baseline["build"]["build_head"],
            "async_build_head": summary["build"]["build_head"],
            "workload_fingerprints_match": True,
            "source": {
                "baseline_queued_inside_pnb_count": baseline_source_early,
                "async_queued_inside_pnb_count": async_source_early,
            },
            "unrelated": {
                "baseline_queued_inside_pnb_count": baseline_unrelated_early,
                "async_queued_inside_pnb_count": async_unrelated_early,
                "baseline_node_queue_ns_p50": baseline_queue_p50,
                "async_node_queue_ns_p50": async_queue_p50,
                "node_queue_ns_p50_delta": baseline_queue_p50 - async_queue_p50,
                "baseline_node_queue_ns_p95": baseline_queue_p95,
                "async_node_queue_ns_p95": async_queue_p95,
                "node_queue_ns_p95_delta": baseline_queue_p95 - async_queue_p95,
                "baseline_python_rtt_ns_p50": baseline_rtt_p50,
                "async_python_rtt_ns_p50": async_rtt_p50,
                "python_rtt_ns_p50_delta": baseline_rtt_p50 - async_rtt_p50,
                "baseline_python_rtt_ns_p95": baseline_rtt_p95,
                "async_python_rtt_ns_p95": async_rtt_p95,
                "python_rtt_ns_p95_delta": baseline_rtt_p95 - async_rtt_p95,
            },
            "pnb": {
                "baseline_duration_ns_p50": baseline_pnb_p50,
                "async_duration_ns_p50": async_pnb_p50,
                "duration_p50_ratio": format(Decimal(async_pnb_p50) / Decimal(baseline_pnb_p50), ".3f"),
                "baseline_duration_ns_p95": baseline_pnb_p95,
                "async_duration_ns_p95": async_pnb_p95,
                "duration_p95_ratio": format(Decimal(async_pnb_p95) / Decimal(baseline_pnb_p95), ".3f"),
            },
        }

    @staticmethod
    def _milliseconds(nanoseconds):
        return format(Decimal(nanoseconds) / Decimal(1_000_000), ".3f")

    def _summary_markdown(self, summary):
        pnb = summary["trials"]["pnb"]
        source = summary["trials"]["source"]
        unrelated = summary["trials"]["unrelated"]
        controls = summary["controls"]
        build = summary["build"]
        workload = summary["trials"]["workload"]
        prototype = build["prototype_commit"] if build["prototype_commit"] is not None else "null"
        fingerprint_status = "matches the baseline" if self.options.variant == "async" else "recorded for baseline comparison"
        return "\n".join([
            "| Variant | Samples | PNB p50/p95 ms | Source early | Unrelated early | Source queue p50/p95 ms | Unrelated queue p50/p95 ms | Unrelated RTT p50/p95 ms |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
            f"| {self.options.variant} | {MEASURED_SAMPLES} | {self._milliseconds(pnb['duration_ns_p50'])}/{self._milliseconds(pnb['duration_ns_p95'])} | {source['queued_inside_pnb_count']}/{MEASURED_SAMPLES} | {unrelated['queued_inside_pnb_count']}/{MEASURED_SAMPLES} | {self._milliseconds(source['node_queue_ns_p50'])}/{self._milliseconds(source['node_queue_ns_p95'])} | {self._milliseconds(unrelated['node_queue_ns_p50'])}/{self._milliseconds(unrelated['node_queue_ns_p95'])} | {self._milliseconds(unrelated['python_rtt_ns_p50'])}/{self._milliseconds(unrelated['python_rtt_ns_p95'])} |",
            "",
            f"Build commit: `{build['build_head']}`. Prototype commit: `{prototype}`. Binary SHA-256: `{build['binary_sha256']}`.",
            "",
            f"Workload: heights {workload['height_first']}-{workload['height_last']}, {workload['non_coinbase_txs']} non-coinbase transactions, weight {workload['weight']}, {workload['serialized_bytes']} serialized bytes, {workload['legacy_sigops']} legacy sigops, and {workload['total_fees_sat']} satoshis in fees. All 21 ordered transaction fingerprints were {fingerprint_status}.",
            "",
            f"Controls: source node queue p50/p95 {self._milliseconds(controls['source']['node_queue_ns_p50'])}/{self._milliseconds(controls['source']['node_queue_ns_p95'])} ms and RTT p50/p95 {self._milliseconds(controls['source']['python_rtt_ns_p50'])}/{self._milliseconds(controls['source']['python_rtt_ns_p95'])} ms; unrelated node queue p50/p95 {self._milliseconds(controls['unrelated']['node_queue_ns_p50'])}/{self._milliseconds(controls['unrelated']['node_queue_ns_p95'])} ms and RTT p50/p95 {self._milliseconds(controls['unrelated']['python_rtt_ns_p50'])}/{self._milliseconds(controls['unrelated']['python_rtt_ns_p95'])} ms.",
            "",
            "All 20 measured workload blocks were accepted.",
            "",
            "PNB duration is a regression guardrail, not the target benefit.",
            "",
        ])

    def _comparison_markdown(self, comparison):
        status_text = {
            "BENEFIT_DEMONSTRATED": "The async prototype serviced unrelated Peer B during PNB while preserving Peer A ordering.",
            "BENEFIT_NOT_DEMONSTRATED": "The run was valid, but the async prototype did not consistently service unrelated Peer B before PNB completed.",
            "ORDERING_FAILURE": "The prototype serviced a subsequent source-peer message before its block completed; the intended per-peer ordering was not preserved.",
            "BASELINE_NOT_SYNCHRONOUS": "The synchronous baseline serviced unrelated Peer B before PNB completed, so the required synchronous baseline was not demonstrated.",
        }[comparison["status"]]
        unrelated = comparison["unrelated"]
        pnb = comparison["pnb"]
        warning_text = ", ".join(comparison["warnings"]) if comparison["warnings"] else "none"
        return "\n".join([
            f"# Async PNB A/B comparison: {comparison['status']}",
            "",
            status_text,
            "",
            f"Source early counts (baseline/async): {comparison['source']['baseline_queued_inside_pnb_count']}/{comparison['source']['async_queued_inside_pnb_count']}.",
            f"Unrelated early counts (baseline/async): {unrelated['baseline_queued_inside_pnb_count']}/{unrelated['async_queued_inside_pnb_count']}.",
            f"Unrelated node queue p50/p95 ms (baseline): {self._milliseconds(unrelated['baseline_node_queue_ns_p50'])}/{self._milliseconds(unrelated['baseline_node_queue_ns_p95'])}.",
            f"Unrelated node queue p50/p95 ms (async): {self._milliseconds(unrelated['async_node_queue_ns_p50'])}/{self._milliseconds(unrelated['async_node_queue_ns_p95'])}.",
            f"Unrelated node queue p50/p95 deltas ms (baseline - async): {self._milliseconds(unrelated['node_queue_ns_p50_delta'])}/{self._milliseconds(unrelated['node_queue_ns_p95_delta'])}.",
            f"Unrelated RTT p50/p95 ms (baseline): {self._milliseconds(unrelated['baseline_python_rtt_ns_p50'])}/{self._milliseconds(unrelated['baseline_python_rtt_ns_p95'])}.",
            f"Unrelated RTT p50/p95 ms (async): {self._milliseconds(unrelated['async_python_rtt_ns_p50'])}/{self._milliseconds(unrelated['async_python_rtt_ns_p95'])}.",
            f"Unrelated RTT p50/p95 deltas ms (baseline - async): {self._milliseconds(unrelated['python_rtt_ns_p50_delta'])}/{self._milliseconds(unrelated['python_rtt_ns_p95_delta'])}.",
            f"PNB p50/p95 ms (baseline): {self._milliseconds(pnb['baseline_duration_ns_p50'])}/{self._milliseconds(pnb['baseline_duration_ns_p95'])}.",
            f"PNB p50/p95 ms (async): {self._milliseconds(pnb['async_duration_ns_p50'])}/{self._milliseconds(pnb['async_duration_ns_p95'])}.",
            f"PNB p50/p95 async/baseline ratios: {pnb['duration_p50_ratio']}/{pnb['duration_p95_ratio']}.",
            f"Warnings: {warning_text}.",
            "",
            "PNB duration is a regression guardrail, not evidence of faster block validation.",
            "",
        ])

    @staticmethod
    def _write_json(path, value):
        with path.open("x", encoding="utf-8", newline="\n") as output_file:
            json.dump(value, output_file, sort_keys=True, indent=2, allow_nan=False)
            output_file.write("\n")
            output_file.flush()

    @staticmethod
    def _write_text(path, value):
        with path.open("x", encoding="utf-8", newline="\n") as output_file:
            output_file.write(value)
            output_file.flush()

    def _write_success_outputs(self, summary, comparison):
        self._write_json(self.output_dir / "summary.json", summary)
        self._write_text(self.output_dir / "summary.md", self._summary_markdown(summary))
        if comparison is not None:
            self._write_json(self.output_dir / "comparison.json", comparison)
            self._write_text(self.output_dir / "comparison.md", self._comparison_markdown(comparison))

    def run_test(self):
        try:
            self._check_preflight()
            self.samples_file = (self.output_dir / "samples.jsonl").open("x", encoding="utf-8", newline="\n")
            self.run_benchmark()
            self.samples_file.flush()
            self.samples_file.close()
            self.samples_file = None
        except AssertionError as assertion:
            error = BenchmarkStop("S_FRAMEWORK_ASSERT", message=str(assertion))
            if self.samples_file is not None and not self.samples_file.closed:
                self.samples_file.flush()
                self.samples_file.close()
                self.samples_file = None
            if self.output_safe and not self.failure_written:
                self.write_failure(error)
            raise error from assertion
        except BenchmarkStop as error:
            if self.samples_file is not None and not self.samples_file.closed:
                self.samples_file.flush()
                self.samples_file.close()
                self.samples_file = None
            if self.output_safe and not self.failure_written:
                self.write_failure(error)
            raise


if __name__ == "__main__":
    AsyncPNBBenchmark(__file__).main()
