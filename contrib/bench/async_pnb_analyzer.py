#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Analyze a completed async-PNB collector directory offline."""

import argparse
import bisect
import csv
import hashlib
import json
import math
import os
import sys
from collections import Counter, defaultdict, deque
from pathlib import Path


COLLECTOR_FILES = {
    "manifest.json", "events.jsonl", "resources.csv", "rpc.jsonl", "summary.json"}
CONNECTION_ROLES = {
    0: "inbound", 1: "outbound-full-relay", 2: "manual", 3: "feeler",
    4: "block-relay-only", 5: "addr-fetch", 6: "private-broadcast"}
DELIVERY_ROUTES = {0: "unknown", 1: "full-block", 2: "compact-block", 3: "blocktxn"}
PERCENTILES = (50, 95, 99)
EVENT_NAMES = {
    1: "complete_message_ready", 2: "handler_start", 3: "handler_complete",
    4: "response_queued", 5: "job_submit", 6: "slot_submit",
    7: "worker_wake", 8: "pnb_start", 9: "pnb_end",
    10: "result_publication", 11: "busy_send_prefix_summary",
    12: "result_collection", 13: "continuation", 14: "test_gate_entered",
    15: "test_interface_registered", 16: "test_interface_unregistered",
    17: "test_shutdown_started", 18: "handler_prefix_complete",
    19: "handler_tail_complete", 20: "test_target_disconnected",
    21: "message_front_ready", 22: "receive_queue_state",
    23: "outbound_queued", 24: "socket_sent", 25: "outbound_dropped",
    26: "causal_link", 27: "peer_created", 28: "handshake_complete",
    29: "peer_finalized", 30: "discouragement", 31: "send_queue_state",
    32: "block_requested", 33: "block_request_removed", 34: "block_timeout",
}
RESOURCE_FIELDS = (
    "monotonic_ns", "wall_ns", "process_user_seconds", "process_system_seconds",
    "thread_msghand_seconds", "thread_pnb_seconds", "thread_network_seconds",
    "thread_validation_seconds", "thread_other_seconds", "rss_bytes", "thread_count",
    "voluntary_ctxt_switches", "nonvoluntary_ctxt_switches", "rchar", "wchar",
    "syscr", "syscw", "read_bytes", "write_bytes")
RESOURCE_FLOAT_FIELDS = {
    "process_user_seconds", "process_system_seconds", "thread_msghand_seconds",
    "thread_pnb_seconds", "thread_network_seconds", "thread_validation_seconds",
    "thread_other_seconds"}


class AnalysisError(RuntimeError):
    pass


def percentile(values, percent):
    """Linear interpolation at rank (n - 1) * percent / 100."""
    if not values:
        return None
    ordered = sorted(values)
    rank = (len(ordered) - 1) * percent / 100
    lower = math.floor(rank)
    upper = math.ceil(rank)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (rank - lower)


def distribution(values):
    return {
        "count": len(values),
        **{f"p{point}": percentile(values, point) for point in PERCENTILES},
        "max": max(values) if values else None,
    }


def read_json(path):
    try:
        with path.open(encoding="utf-8") as source:
            return json.load(source)
    except (OSError, json.JSONDecodeError) as error:
        raise AnalysisError(f"cannot read {path.name}: {error}") from error


def read_jsonl(path):
    result = []
    try:
        with path.open(encoding="utf-8") as source:
            for line_number, line in enumerate(source, 1):
                if not line.strip():
                    continue
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise AnalysisError(f"{path.name}:{line_number} is not an object")
                result.append(value)
    except (OSError, json.JSONDecodeError) as error:
        raise AnalysisError(f"cannot read {path.name}: {error}") from error
    return result


def read_resources(path):
    try:
        with path.open(encoding="utf-8", newline="") as source:
            reader = csv.DictReader(source)
            if tuple(reader.fieldnames or ()) != RESOURCE_FIELDS:
                raise AnalysisError("resources.csv header mismatch")
            result = []
            for row in reader:
                if None in row or any(value is None or value == "" for value in row.values()):
                    raise AnalysisError("resources.csv malformed row")
                result.append({
                    key: (float(value) if key in RESOURCE_FLOAT_FIELDS else int(value))
                    for key, value in row.items()})
            return result
    except (OSError, ValueError) as error:
        raise AnalysisError(f"cannot read resources.csv: {error}") from error


def file_facts(path, *, csv_header=False):
    digest = hashlib.sha256()
    lines = 0
    try:
        with path.open("rb") as source:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                lines += chunk.count(b"\n")
        return {
            "bytes": path.stat().st_size,
            "data_rows": max(0, lines - 1) if csv_header else lines,
            "lines": lines,
            "sha256": digest.hexdigest(),
        }
    except OSError as error:
        raise AnalysisError(f"cannot hash {path.name}: {error}") from error


def event_peer(event):
    values = event.get("values", [])
    code = event.get("event_code")
    index = 0
    if code in (5, 6, 11, 12, 13):
        index = 1
    elif code in (7, 8):
        index = 2
    elif code == 9:
        index = 5
    if index >= len(values):
        return None
    peer = values[index]
    return peer if isinstance(peer, int) and peer >= 0 else None


def event_route(event):
    values = event.get("values", [])
    index = {5: 3, 7: 3, 8: 3, 9: 6}.get(event.get("event_code"))
    if index is None or index >= len(values):
        return None
    return DELIVERY_ROUTES.get(values[index], f"unknown-{values[index]}")


def event_message_type(event):
    code = event.get("event_code")
    if code in (1, 2, 3, 4, 19, 21, 23, 24, 25):
        return event.get("text1", "unknown")
    return None


def prepare_rpc_states(rpc, max_age_ns):
    states = []
    saw_ibd = False
    transition_assigned = False
    for snapshot in sorted((item for item in rpc if "error" not in item),
                           key=lambda item: item["monotonic_ns"]):
        chain = snapshot.get("chain", {})
        ibd = chain.get("initialblockdownload")
        if not isinstance(ibd, bool):
            phase = "unclassified"
        elif ibd:
            phase = "ibd"
            saw_ibd = True
        elif saw_ibd and not transition_assigned:
            phase = "transition"
            transition_assigned = True
        else:
            phase = "post_ibd"
        states.append((snapshot["monotonic_ns"], phase, snapshot))
    times = [state[0] for state in states]

    def join(steady_ns):
        index = bisect.bisect_right(times, steady_ns) - 1
        if index < 0:
            return "unclassified", None
        age = steady_ns - states[index][0]
        if age < 0 or age > max_age_ns:
            return "unclassified", age
        return states[index][1], age

    return join


def phase_observation_intervals(rpc, start_ns, end_ns, max_age_ns,
                                mapping_uncertainty_ns=0):
    if end_ns <= start_ns:
        return []
    join = prepare_rpc_states(rpc, max_age_ns)
    points = {start_ns, end_ns}
    for row in rpc:
        if "error" in row or not isinstance(row.get("monotonic_ns"), int):
            continue
        sample = row["monotonic_ns"]
        for boundary in (sample, sample + max_age_ns):
            for point in (boundary - mapping_uncertainty_ns,
                          boundary + mapping_uncertainty_ns):
                if start_ns < point < end_ns:
                    points.add(point)
    ordered = sorted(points)
    intervals = []
    for left, right in zip(ordered, ordered[1:]):
        # Classification at an expiry boundary itself is inclusive (age ==
        # max), but that single instant has no interval width. An interior
        # point correctly classifies the following stale gap as unclassified.
        midpoint = left + (right - left) // 2
        low_phase, _low_age = join(midpoint - mapping_uncertainty_ns)
        high_phase, _high_age = join(midpoint + mapping_uncertainty_ns)
        phase = (low_phase if low_phase == high_phase and
                 low_phase != "unclassified" else "unclassified")
        intervals.append((phase, left, right))
    return intervals


def phase_observation_seconds(rpc, start_ns, end_ns, max_age_ns,
                              mapping_uncertainty_ns=0):
    durations = Counter()
    for phase, left, right in phase_observation_intervals(
            rpc, start_ns, end_ns, max_age_ns,
            mapping_uncertainty_ns=mapping_uncertainty_ns):
        durations[phase] += right - left
    return {name: durations[name] / 1e9 for name in
            ("ibd", "transition", "post_ibd", "unclassified")}


def annotate(events, rpc, max_age_seconds, mapping_uncertainty_ns=0):
    join = prepare_rpc_states(rpc, int(max_age_seconds * 1_000_000_000))
    peer_roles = {}
    for event in events:
        if event.get("event_code") == 27 and len(event.get("values", [])) >= 2:
            peer_roles[(event["process_epoch"], event["values"][0])] = CONNECTION_ROLES.get(
                event["values"][1], f"unknown-{event['values'][1]}")
    ages = []
    for event in events:
        mapped = event.get("mapped_monotonic_ns", event["steady_ns"])
        low_phase, _low_age = join(mapped - mapping_uncertainty_ns)
        high_phase, _high_age = join(mapped + mapping_uncertainty_ns)
        midpoint_phase, age = join(mapped)
        phase = (midpoint_phase if low_phase == high_phase == midpoint_phase and
                 midpoint_phase != "unclassified" else "unclassified")
        if phase == "unclassified":
            age = None
        event["_phase"] = phase
        event["_rpc_join_age_ns"] = age
        if age is not None:
            ages.append(age)
        peer = event_peer(event)
        event["_peer"] = peer
        event["_role"] = peer_roles.get((event["process_epoch"], peer), "unknown")
        event["_route"] = event_route(event)
        event["_message_type"] = event_message_type(event)
    return ages


def keyed_messages(events):
    complete, front, start, end = {}, {}, {}, {}
    duplicate_keys = []
    for event in events:
        code = event["event_code"]
        values = event["values"]
        if code not in (1, 2, 3, 21) or len(values) < 2:
            continue
        key = (event["process_epoch"], values[0], values[1])
        target = {1: complete, 2: start, 3: end, 21: front}[code]
        if key in target:
            duplicate_keys.append(key)
        else:
            target[key] = event
    return complete, front, start, end, duplicate_keys


def queue_metrics(events, code, start_ns, end_ns, peer_finalizations):
    by_peer = defaultdict(list)
    invalid_negative = 0
    for event in events:
        if event["event_code"] != code or len(event["values"]) < 4:
            continue
        values = event["values"]
        if values[1] < 0 or values[2] < 0:
            invalid_negative += 1
        by_peer[(event["process_epoch"], values[0])].append(event)
    byte_area = 0
    depth_area = 0
    max_bytes = 0
    max_depth = 0
    pause_transitions = 0
    pause_ns = 0
    open_pauses = 0
    post_finalization_samples = 0
    observed_samples = 0
    for peer_key, samples in by_peer.items():
        samples.sort(key=lambda event: event["steady_ns"])
        finalized_ns = peer_finalizations.get(peer_key)
        terminal_ns = min(end_ns, finalized_ns) if finalized_ns is not None else end_ns
        previous_pause = False
        for index, sample in enumerate(samples):
            values = sample["values"]
            if finalized_ns is not None and sample["steady_ns"] > finalized_ns:
                post_finalization_samples += 1
            if start_ns <= sample["steady_ns"] <= terminal_ns:
                observed_samples += 1
            following = (samples[index + 1]["steady_ns"]
                         if index + 1 < len(samples) else terminal_ns)
            following = min(following, terminal_ns)
            interval_start = max(start_ns, sample["steady_ns"])
            interval = max(0, following - interval_start)
            byte_area += values[1] * interval
            depth_area += values[2] * interval
            if interval or start_ns <= sample["steady_ns"] <= terminal_ns:
                max_bytes = max(max_bytes, values[1])
                max_depth = max(max_depth, values[2])
            paused = bool(values[3])
            if start_ns <= sample["steady_ns"] <= terminal_ns and paused != previous_pause:
                pause_transitions += 1
            if paused:
                pause_ns += interval
            previous_pause = paused
        active_samples = [sample for sample in samples if sample["steady_ns"] <= end_ns]
        if (active_samples and bool(active_samples[-1]["values"][3]) and
                finalized_ns is None):
            open_pauses += 1
    return {
        "samples": observed_samples,
        "retained_samples": sum(map(len, by_peer.values())),
        "byte_depth_area_byte_ns": byte_area,
        "depth_area_message_ns": depth_area,
        "max_bytes": max_bytes,
        "max_depth": max_depth,
        "pause_transitions": pause_transitions,
        "pause_duration_ns": pause_ns,
        "open_pause_intervals_at_epoch_end": open_pauses,
        "negative_counter_samples": invalid_negative,
        "post_finalization_samples": post_finalization_samples,
    }


def build_pnb_jobs(events, errors):
    stage_names = {
        5: "submit", 6: "slot_submit", 7: "worker_wake", 8: "start",
        9: "end", 10: "publication", 11: "busy_summary",
        12: "collection", 13: "continuation"}
    jobs = defaultdict(dict)
    lifecycle_frontier_sequence = defaultdict(int)
    for event in events:
        code = event["event_code"]
        values = event["values"]
        if code not in stage_names or not values:
            continue
        lifecycle_frontier_sequence[event["process_epoch"]] = max(
            lifecycle_frontier_sequence[event["process_epoch"]],
            event.get("sequence", 0))
        if values[0] <= 0:
            errors.append(
                f"zero PNB job ID at sequence {event.get('sequence')}")
        key = (event["process_epoch"], values[0])
        name = stage_names[code]
        if name in jobs[key]:
            errors.append(f"duplicate PNB {name} for epoch/job {key}")
        jobs[key][name] = event
    result = []
    for (epoch, job_id), parts in sorted(jobs.items()):
        labels_reconciled = True
        submit = parts.get("submit")
        async_mode = None
        if submit:
            raw_mode = submit["values"][2]
            if raw_mode not in (0, 1):
                errors.append(f"invalid PNB mode label for epoch/job {(epoch, job_id)}")
                labels_reconciled = False
            else:
                async_mode = bool(raw_mode)
        else:
            errors.append(f"PNB lifecycle does not start at submit for epoch/job {(epoch, job_id)}")
            labels_reconciled = False
        async_required = [
            "submit", "slot_submit", "worker_wake", "start", "end",
            "publication", "busy_summary", "collection", "continuation"]
        control_required = ["submit", "start", "end", "continuation"]
        required = async_required if async_mode else control_required
        async_only = {"slot_submit", "worker_wake", "publication",
                      "busy_summary", "collection"}
        if async_mode is False and (async_only & set(parts)):
            errors.append(f"control PNB has async-only stages for epoch/job {(epoch, job_id)}")
            labels_reconciled = False
        unexpected = set(parts) - set(required)
        if unexpected:
            errors.append(
                f"unexpected PNB lifecycle stages for epoch/job {(epoch, job_id)}: "
                f"{sorted(unexpected)}")
            labels_reconciled = False
        present_indices = [required.index(name) for name in required if name in parts]
        contiguous_prefix = bool(present_indices) and present_indices == list(
            range(0, max(present_indices) + 1))
        internal_gap = bool(present_indices) and not contiguous_prefix
        if internal_gap:
            errors.append(f"missing internal PNB lifecycle stage for epoch/job {(epoch, job_id)}")
        ordered = True
        previous = None
        for name in required:
            if name not in parts:
                continue
            current = parts[name]
            if previous and (current["sequence"] <= previous["sequence"] or
                             current["steady_ns"] < previous["steady_ns"]):
                ordered = False
                errors.append(f"impossible PNB lifecycle order for epoch/job {(epoch, job_id)}")
                break
            previous = current
        complete = all(name in parts for name in required)

        block_ids = {part.get("block_id") for part in parts.values()}
        if None in block_ids or len(block_ids) != 1:
            errors.append(f"mismatched PNB block labels for epoch/job {(epoch, job_id)}")
            labels_reconciled = False
        sources = set()
        for name, index in (("submit", 1), ("slot_submit", 1), ("worker_wake", 2),
                            ("start", 2), ("end", 5), ("busy_summary", 1),
                            ("collection", 1), ("continuation", 1)):
            if name in parts:
                source = parts[name]["values"][index]
                if source < 0:
                    errors.append(f"invalid PNB source label for epoch/job {(epoch, job_id)}")
                    labels_reconciled = False
                sources.add(source)
        if len(sources) != 1:
            errors.append(f"mismatched PNB source labels for epoch/job {(epoch, job_id)}")
            labels_reconciled = False
        routes = set()
        for name, index in (("submit", 3), ("worker_wake", 3),
                            ("start", 3), ("end", 6)):
            if name in parts:
                raw_route = parts[name]["values"][index]
                if raw_route not in (1, 2, 3):
                    errors.append(
                        f"invalid PNB route label for epoch/job {(epoch, job_id)}")
                    labels_reconciled = False
                routes.add(raw_route)
        if len(routes) != 1:
            errors.append(f"mismatched PNB route labels for epoch/job {(epoch, job_id)}")
            labels_reconciled = False
        expected_mode = 1 if async_mode else 0
        for name, index in (("start", 1), ("end", 4)):
            if name in parts and parts[name]["values"][index] != expected_mode:
                errors.append(f"mismatched PNB mode labels for epoch/job {(epoch, job_id)}")
                labels_reconciled = False
        if async_mode:
            for name, index in (("slot_submit", 3), ("worker_wake", 1),
                                ("publication", 3), ("busy_summary", 8),
                                ("collection", 4)):
                if name in parts and parts[name]["values"][index] != 1:
                    errors.append(f"mismatched PNB active-slot label for epoch/job {(epoch, job_id)}")
                    labels_reconciled = False
            slot = parts.get("slot_submit")
            if slot and (slot["values"][2] != 0 or slot.get("text1") != "accepted"):
                errors.append(f"invalid PNB submit status for epoch/job {(epoch, job_id)}")
                labels_reconciled = False
        results = set()
        for name, first, second in (("end", 2, 3), ("publication", 1, 2),
                                    ("collection", 2, 3), ("continuation", 2, 3)):
            if name in parts and len(parts[name]["values"]) > second:
                if (parts[name]["values"][first] not in (0, 1) or
                        parts[name]["values"][second] not in (0, 1)):
                    errors.append(
                        f"invalid PNB result label for epoch/job {(epoch, job_id)}")
                    labels_reconciled = False
                results.add((bool(parts[name]["values"][first]),
                             bool(parts[name]["values"][second])))
        if len(results) > 1 or any(new and not processed for processed, new in results):
            errors.append(f"mismatched PNB result labels for epoch/job {(epoch, job_id)}")
            labels_reconciled = False
        continuations = {parts[name].get("text1") for name in
                         ("submit", "collection", "continuation")
                         if name in parts}
        if len(continuations) > 1:
            errors.append(f"mismatched PNB continuation labels for epoch/job {(epoch, job_id)}")
            labels_reconciled = False
        if continuations and not continuations <= {"standard", "optimistic_compact"}:
            errors.append(f"invalid PNB continuation label for epoch/job {(epoch, job_id)}")
            labels_reconciled = False

        start = parts.get("start")
        end = parts.get("end")
        continuation = parts.get("continuation")
        submission_ibd = None
        submission_active_height = None
        if submit and len(submit["values"]) > 5:
            submission_ibd = bool(submit["values"][4])
            submission_active_height = submit["values"][5]
            if submit["values"][4] not in (0, 1):
                errors.append(
                    f"invalid PNB IBD label for epoch/job {(epoch, job_id)}")
                labels_reconciled = False
            if (submit["values"][5] < -1 or
                    submit["values"][6] not in (0, 1) or
                    submit["values"][7] not in (0, 1)):
                errors.append(f"invalid PNB submission labels for epoch/job {(epoch, job_id)}")
                labels_reconciled = False
        if start and submit and len(start["values"]) > 5:
            if (start["values"][4] != submit["values"][4] or
                    start["values"][5] != submit["values"][5]):
                errors.append(
                    f"mismatched PNB IBD/height labels for epoch/job {(epoch, job_id)}")
                labels_reconciled = False
        if start and end and end["values"][1] != end["steady_ns"] - start["steady_ns"]:
            errors.append(f"PNB duration mismatch for epoch/job {(epoch, job_id)}")
            labels_reconciled = False
        busy = parts.get("busy_summary")
        if busy:
            count, total, maximum, max_peer, max_start, max_end = busy["values"][2:8]
            valid_busy = count >= 0 and total >= 0 and maximum >= 0
            if count == 0:
                valid_busy &= (total, maximum, max_peer, max_start, max_end) == (0, 0, -1, 0, 0)
            else:
                valid_busy &= (max_peer >= 0 and max_start <= max_end and
                               maximum == max_end - max_start and total >= maximum)
            if not valid_busy:
                errors.append(f"invalid PNB busy-prefix summary for epoch/job {(epoch, job_id)}")
                labels_reconciled = False
        for name, index in (("collection", 5), ("continuation", 4)):
            if name in parts and parts[name]["values"][index] not in (0, 1):
                errors.append(f"invalid PNB source-live label for epoch/job {(epoch, job_id)}")
                labels_reconciled = False
        route = event_route(submit) if submit else None
        incomplete_at_boundary = (
            not complete and ordered and contiguous_prefix and labels_reconciled and
            max(part["sequence"] for part in parts.values()) ==
            lifecycle_frontier_sequence[epoch])
        if (not complete and ordered and contiguous_prefix and labels_reconciled and
                not incomplete_at_boundary):
            errors.append(
                f"incomplete PNB lifecycle precedes later PNB event for epoch/job "
                f"{(epoch, job_id)}")
        item = {
            "process_epoch": epoch,
            "job_id": job_id,
            "mode": "async" if async_mode else ("control" if async_mode is False else "unknown"),
            "source_peer": next(iter(sources)) if len(sources) == 1 else None,
            "delivery_route": (DELIVERY_ROUTES.get(next(iter(routes)),
                                                        f"unknown-{next(iter(routes))}")
                               if len(routes) == 1 else route),
            "submission_ibd": submission_ibd,
            "submission_active_height": submission_active_height,
            "phase": submit.get("_phase") if submit else "unclassified",
            "source_role": submit.get("_role", "unknown") if submit else "unknown",
            "block_id": next(iter(block_ids)) if len(block_ids) == 1 else None,
            "submit_ns": submit["steady_ns"] if submit else None,
            "submit_scope": submit.get("collection_scope") if submit else None,
            "start_ns": start["steady_ns"] if start else None,
            "start_sequence": start["sequence"] if start else None,
            "end_ns": end["steady_ns"] if end else None,
            "end_sequence": end["sequence"] if end else None,
            "publication_ns": parts["publication"]["steady_ns"]
                              if "publication" in parts else None,
            "slot_submit_ns": parts["slot_submit"]["steady_ns"]
                              if "slot_submit" in parts else None,
            "worker_wake_ns": parts["worker_wake"]["steady_ns"]
                              if "worker_wake" in parts else None,
            "busy_summary_ns": parts["busy_summary"]["steady_ns"]
                              if "busy_summary" in parts else None,
            "collection_ns": parts["collection"]["steady_ns"]
                             if "collection" in parts else None,
            "continuation_ns": continuation["steady_ns"] if continuation else None,
            "duration_ns": end["values"][1] if end else None,
            "process_new_block": next(iter(results))[0] if len(results) == 1 else None,
            "new_block": next(iter(results))[1] if len(results) == 1 else None,
            "continuation_kind": next(iter(continuations)) if len(continuations) == 1 else None,
            "lifecycle_stages": [name for name in required if name in parts],
            "labels_reconciled": labels_reconciled,
            "ordered_complete": complete and ordered and not internal_gap and labels_reconciled,
            "incomplete_at_collection_boundary": incomplete_at_boundary,
        }
        result.append(item)
    return result


def resource_metrics(resources, observation_seconds):
    if not resources:
        return {"samples": 0, "unavailable": True}
    first, last = resources[0], resources[-1]
    elapsed = max(0.0, (last["monotonic_ns"] - first["monotonic_ns"]) / 1e9)

    def delta(name):
        return last.get(name, 0) - first.get(name, 0)

    cpu_names = (
        "process_user_seconds", "process_system_seconds", "thread_msghand_seconds",
        "thread_pnb_seconds", "thread_network_seconds", "thread_validation_seconds",
        "thread_other_seconds")
    return {
        "samples": len(resources),
        "sample_elapsed_seconds": elapsed,
        "cpu_seconds_delta": {name: delta(name) for name in cpu_names},
        "cpu_cores_average": ((delta("process_user_seconds") +
                               delta("process_system_seconds")) / elapsed
                              if elapsed else None),
        "rss_bytes": distribution([row["rss_bytes"] for row in resources]),
        "io_delta": {name: delta(name) for name in
                     ("rchar", "wchar", "syscr", "syscw", "read_bytes", "write_bytes")},
        "context_switch_delta": {
            "voluntary": delta("voluntary_ctxt_switches"),
            "nonvoluntary": delta("nonvoluntary_ctxt_switches"),
        },
        "io_bytes_per_wall_second": {
            name: delta(name) / observation_seconds if observation_seconds else None
            for name in ("read_bytes", "write_bytes")
        },
    }


def network_metrics(rpc, observation_seconds):
    samples = [item for item in rpc if isinstance(item.get("network_totals"), dict)]
    if len(samples) < 2:
        return {"samples": len(samples), "unavailable": True}
    first, last = samples[0]["network_totals"], samples[-1]["network_totals"]
    received = last.get("totalbytesrecv", 0) - first.get("totalbytesrecv", 0)
    sent = last.get("totalbytessent", 0) - first.get("totalbytessent", 0)
    return {
        "samples": len(samples),
        "received_bytes_delta": received,
        "sent_bytes_delta": sent,
        "received_bytes_per_second": received / observation_seconds if observation_seconds else None,
        "sent_bytes_per_second": sent / observation_seconds if observation_seconds else None,
    }


def subset_summary(events, context_events=None, *, observation_seconds,
                   include_interval_work=False, pnb_count=0,
                   pnb_time_seconds=0.0):
    context = context_events if context_events is not None else events
    counts = Counter(event["event"] for event in events)
    payload_bytes = sum(event["values"][2] for event in events
                        if event["event_code"] == 1)
    wire_bytes = sum(event["values"][3] for event in events
                     if event["event_code"] == 1)
    complete, front, start, end, _duplicates = keyed_messages(context)
    selected_sequences = {event["sequence"] for event in events}
    selected_keys = {key for key, event in complete.items()
                     if event["sequence"] in selected_sequences}
    if include_interval_work:
        selected_keys.update(
            key for stages in (front, start, end)
            for key, event in stages.items()
            if event["sequence"] in selected_sequences and key in complete)

    outbound = {}
    causal = defaultdict(set)
    for event in context:
        values = event["values"]
        if event["event_code"] == 23 and len(values) >= 3:
            outbound_key = (event["process_epoch"], values[0], values[1])
            outbound.setdefault(outbound_key, event)
            if values[2]:
                causal[outbound_key].add(
                    (event["process_epoch"], values[0], values[2]))
        elif event["event_code"] == 26 and len(values) >= 3:
            causal[(event["process_epoch"], values[0], values[2])].add(
                (event["process_epoch"], values[0], values[1]))
    for outbound_key, inbound_keys in causal.items():
        if (include_interval_work and outbound_key in outbound and
                outbound[outbound_key]["sequence"] in selected_sequences):
            selected_keys.update(key for key in inbound_keys if key in complete)
    queue_to_front = []
    front_to_handler = []
    handler_durations = []
    for key in selected_keys:
        if key in front and front[key]["steady_ns"] >= complete[key]["steady_ns"]:
            queue_to_front.append(
                front[key]["steady_ns"] - complete[key]["steady_ns"])
        if key in start:
            front_ns = front.get(key, complete[key])["steady_ns"]
            if start[key]["steady_ns"] >= front_ns:
                front_to_handler.append(start[key]["steady_ns"] - front_ns)
        if (key in start and key in end and
                end[key]["steady_ns"] >= start[key]["steady_ns"]):
            handler_durations.append(
                end[key]["steady_ns"] - start[key]["steady_ns"])
    correlated_outbound = {
        key for key, inbound_keys in causal.items()
        if key in outbound and inbound_keys & selected_keys}
    ready_to_response = []
    front_to_response = []
    for outbound_key in correlated_outbound:
        queued_ns = outbound[outbound_key]["steady_ns"]
        for inbound_key in causal[outbound_key] & selected_keys:
            if queued_ns >= complete[inbound_key]["steady_ns"]:
                ready_to_response.append(
                    queued_ns - complete[inbound_key]["steady_ns"])
            if inbound_key in front and queued_ns >= front[inbound_key]["steady_ns"]:
                front_to_response.append(
                    queued_ns - front[inbound_key]["steady_ns"])
    socket = {}
    dropped = {}
    for event in context:
        values = event["values"]
        if event["event_code"] == 24 and len(values) >= 7:
            socket.setdefault(
                (event["process_epoch"], values[0], values[1]), event)
        elif event["event_code"] == 25 and len(values) >= 4:
            dropped.setdefault(
                (event["process_epoch"], values[0], values[1]), event)
    completed_outbound = correlated_outbound & set(socket)
    dropped_outbound = correlated_outbound & set(dropped)
    incomplete_outbound = correlated_outbound - completed_outbound - dropped_outbound
    queue_to_first = []
    queue_to_last = []
    for key in completed_outbound:
        first_ns = socket[key]["values"][3]
        last_ns = socket[key]["values"][4]
        queued_ns = outbound[key]["steady_ns"]
        if queued_ns <= first_ns <= last_ns:
            queue_to_first.append(first_ns - queued_ns)
            queue_to_last.append(last_ns - queued_ns)
    response_relationship = Counter()
    for key in correlated_outbound:
        relation = outbound[key].get("_pnb_source_relation")
        if relation in ("source_peer", "unrelated_peer"):
            response_relationship[f"response_queued_{relation}"] += 1
            if key in completed_outbound:
                response_relationship[f"completed_{relation}"] += 1
    for event in events:
        if event["event_code"] == 2 and event.get("_pnb_source_relation") in (
                "source_peer", "unrelated_peer"):
            response_relationship[
                f"handler_start_{event['_pnb_source_relation']}"] += 1
    return {
        "event_count": len(events),
        "observation_hours": observation_seconds / 3600,
        "complete_ready_count": counts["complete_message_ready"],
        "exact_front_count": counts["message_front_ready"],
        "handler_start_count": counts["handler_start"],
        "handler_complete_count": counts["handler_complete"],
        "response_queued_count": len(correlated_outbound),
        "socket_complete_count": len(completed_outbound),
        "outbound_drop_count": len(dropped_outbound),
        "outbound_incomplete_count": len(incomplete_outbound),
        "pnb_count": pnb_count,
        "pnb_count_basis": "measured_job_submit",
        "pnb_time_seconds": pnb_time_seconds,
        "pnb_time_basis": "clipped_busy_interval_overlap",
        "pnb_wall_fraction": pnb_time_seconds / observation_seconds if observation_seconds else None,
        "pnb_jobs_per_second": pnb_count / observation_seconds if observation_seconds else None,
        "payload_bytes": payload_bytes,
        "wire_bytes": wire_bytes,
        "queue_to_front_ns": distribution(queue_to_front),
        "front_to_handler_ns": distribution(front_to_handler),
        "handler_duration_ns": distribution(handler_durations),
        "complete_ready_to_response_queued_ns": distribution(ready_to_response),
        "front_ready_to_response_queued_ns": distribution(front_to_response),
        "queue_to_first_write_ns": distribution(queue_to_first),
        "queue_to_last_write_ns": distribution(queue_to_last),
        "pnb_source_relationship": dict(sorted(response_relationship.items())),
    }


def reconcile_collector(manifest, summary, events, resources, rpc, artifacts, errors):
    """Cross-check all retained rows, bounds, clocks, and finalized metadata."""
    actual_count = len(events)
    actual_first = events[0]["sequence"] if events else None
    actual_last = events[-1]["sequence"] if events else None
    actual_epochs = sorted({event.get("process_epoch") for event in events})
    actual_counts = dict(sorted(Counter(event.get("event") for event in events).items()))
    actual_bounds = [
        min((event["steady_ns"] for event in events), default=None),
        max((event["steady_ns"] for event in events), default=None),
    ]
    expected_summary = {
        "event_count": actual_count,
        "event_sequence_first": actual_first,
        "event_sequence_last": actual_last,
        "event_sequence_read_last": actual_last,
        "event_sequence_durable_last": actual_last,
        "consumer_ack": actual_last or 0,
        "event_counts": actual_counts,
        "event_steady_bounds_ns": actual_bounds,
    }
    for key, actual in expected_summary.items():
        if summary.get(key) != actual:
            errors.append(
                f"collector summary {key} mismatch: {summary.get(key)!r} != {actual!r}")
    summary_epoch = summary.get("process_epoch")
    if actual_epochs:
        if len(actual_epochs) != 1 or summary_epoch != actual_epochs[0]:
            errors.append("collector summary process epoch mismatch")
    elif summary_epoch is None:
        errors.append("collector summary process epoch is missing")
    if events and actual_first != 1:
        errors.append(f"collector event stream begins at {actual_first!r}, not sequence 1")
    cutoff = summary.get("collection_cutoff_sequence")
    if cutoff is not None and cutoff != (actual_last or 0):
        errors.append(f"collector cutoff mismatch: {cutoff!r} != {actual_last or 0!r}")
    producer_observed = summary.get("producer_sequence_observed")
    if (not isinstance(producer_observed, int) or producer_observed < (cutoff or 0)):
        errors.append("collector producer sequence bound mismatch")
    if not isinstance(summary.get("probe_status"), int) or summary.get("probe_status") & 3:
        errors.append("collector probe status is lossy or test-gated")
    stream = manifest.get("event_stream")
    if not isinstance(stream, dict):
        errors.append("collector manifest missing event_stream authority")
        return
    expected_manifest = {
        "process_epoch": actual_epochs[0] if len(actual_epochs) == 1 else summary_epoch,
        "count": actual_count,
        "sequence_first": actual_first,
        "sequence_last": actual_last,
        "durable_sequence": actual_last or 0,
        "event_counts": actual_counts,
    }
    for key, actual in expected_manifest.items():
        if stream.get(key) != actual:
            errors.append(
                f"collector manifest event_stream.{key} mismatch: "
                f"{stream.get(key)!r} != {actual!r}")
    expected_epochs = actual_epochs if actual_epochs else [summary_epoch]
    if manifest.get("process_epochs") != expected_epochs:
        errors.append("collector manifest process_epochs mismatch")
    for key in ("complete", "valid", "stop_reason"):
        if manifest.get(key) != summary.get(key):
            errors.append(f"collector manifest/summary {key} mismatch")
    for key in ("loss_count", "checksum_failures", "unstable_read_failures",
                "sequence_failures"):
        if summary.get(key) != 0:
            errors.append(f"collector summary {key} is nonzero")
    if summary.get("integrity_errors") != []:
        errors.append("collector summary contains integrity errors")

    if not isinstance(artifacts, dict):
        errors.append("actual collector artifact facts are unavailable")
    else:
        manifest_artifacts = manifest.get("artifacts")
        summary_artifacts = summary.get("artifact_integrity")
        if manifest_artifacts != artifacts:
            errors.append("collector manifest artifact hashes/bounds mismatch")
        expected_data = {name: artifacts.get(name) for name in
                         ("events.jsonl", "resources.csv", "rpc.jsonl")}
        if summary_artifacts != expected_data:
            errors.append("collector summary artifact hashes/bounds mismatch")
        row_expectations = {
            "events.jsonl": len(events),
            "resources.csv": len(resources),
            "rpc.jsonl": len(rpc),
        }
        for name, rows in row_expectations.items():
            fact = artifacts.get(name)
            if not isinstance(fact, dict) or fact.get("data_rows") != rows:
                errors.append(f"collector {name} retained row count mismatch")

    window = summary.get("collection_window")
    if not isinstance(window, dict) or manifest.get("collection_window") != window:
        errors.append("collector collection-window metadata mismatch")
        window = {}
    start_boundary = window.get("start")
    end_boundary = window.get("end")

    def validate_boundary(name, boundary):
        fields = (
            "producer_sequence", "collector_monotonic_before_ns",
            "collector_monotonic_after_ns", "collector_monotonic_midpoint_ns",
            "collector_wall_before_ns", "collector_wall_after_ns",
            "collector_wall_midpoint_ns", "capture_uncertainty_ns")
        if not isinstance(boundary, dict) or any(
                not isinstance(boundary.get(field), int) for field in fields):
            errors.append(f"malformed collection {name} boundary")
            return False
        mono_before = boundary["collector_monotonic_before_ns"]
        mono_after = boundary["collector_monotonic_after_ns"]
        wall_before = boundary["collector_wall_before_ns"]
        wall_after = boundary["collector_wall_after_ns"]
        if (mono_before <= 0 or wall_before <= 0 or mono_after < mono_before or
                wall_after < wall_before or boundary["producer_sequence"] < 0):
            errors.append(f"impossible collection {name} boundary")
        if boundary["collector_monotonic_midpoint_ns"] != (
                mono_before + (mono_after - mono_before) // 2):
            errors.append(f"collection {name} monotonic midpoint mismatch")
        if boundary["collector_wall_midpoint_ns"] != (
                wall_before + (wall_after - wall_before) // 2):
            errors.append(f"collection {name} wall midpoint mismatch")
        uncertainty = (mono_after - mono_before + wall_after - wall_before + 1) // 2
        if boundary["capture_uncertainty_ns"] != uncertainty:
            errors.append(f"collection {name} capture uncertainty mismatch")
        return True

    start_ok = validate_boundary("start", start_boundary)
    end_ok = validate_boundary("end", end_boundary)
    if start_ok and end_ok:
        start_mono = start_boundary["collector_monotonic_midpoint_ns"]
        end_mono = end_boundary["collector_monotonic_midpoint_ns"]
        start_wall = start_boundary["collector_wall_midpoint_ns"]
        end_wall = end_boundary["collector_wall_midpoint_ns"]
        duration_ns = end_mono - start_mono
        if duration_ns <= 0 or end_wall <= start_wall:
            errors.append("nonpositive collection clock interval")
        if window.get("duration_ns") != duration_ns:
            errors.append("collection monotonic duration mismatch")
        if window.get("duration_source") != "collector_python_monotonic_midpoints":
            errors.append("collection duration source mismatch")
        if manifest.get("clock_origin") != {
                "monotonic_ns": start_mono, "wall_ns": start_wall}:
            errors.append("collector start clock origin mismatch")
        if manifest.get("end_clock") != {
                "monotonic_ns": end_mono, "wall_ns": end_wall}:
            errors.append("collector cutoff clock mismatch")
    else:
        start_mono = end_mono = start_wall = end_wall = 0
        duration_ns = 0

    first_measured = window.get("sequence_first")
    last_measured = window.get("sequence_last")
    if (not isinstance(first_measured, int) or first_measured <= 0 or
            not isinstance(last_measured, int) or last_measured < 0):
        errors.append("invalid collection sequence window")
        first_measured, last_measured = 1, 0
    if window.get("pre_attach_sequence_last") != first_measured - 1:
        errors.append("pre-attach sequence boundary mismatch")
    if start_ok and start_boundary["producer_sequence"] != first_measured - 1:
        errors.append("start producer cutoff mismatch")
    if end_ok and end_boundary["producer_sequence"] != last_measured:
        errors.append("end producer cutoff mismatch")
    if last_measured != (actual_last or 0) or cutoff != last_measured:
        errors.append("measured sequence cutoff disagrees with retained stream")
    actual_scope = Counter()
    for event in events:
        expected_scope = (
            "pre_attach_backlog" if event["sequence"] < first_measured
            else "measured")
        if event.get("collection_scope") != expected_scope:
            errors.append(
                f"event collection scope mismatch at sequence {event['sequence']}")
        actual_scope[expected_scope] += 1
    actual_scope = dict(sorted(actual_scope.items()))
    if summary.get("event_scope_counts") != actual_scope:
        errors.append("collector event-scope counts mismatch")
    if window.get("pre_attach_backlog_event_count") != actual_scope.get(
            "pre_attach_backlog", 0):
        errors.append("collector backlog count mismatch")
    if window.get("measured_event_count") != actual_scope.get("measured", 0):
        errors.append("collector measured event count mismatch")

    mapping = summary.get("clock_mapping")
    cutoff_mapping = summary.get("cutoff_clock_mapping")
    if manifest.get("clock_mapping") != mapping:
        errors.append("manifest/summary start clock mapping mismatch")
    if manifest.get("cutoff_clock_mapping") != cutoff_mapping:
        errors.append("manifest/summary cutoff clock mapping mismatch")
    if not isinstance(mapping, dict) or not isinstance(cutoff_mapping, dict):
        errors.append("missing explicit clock mapping")
        mapping = {}
        cutoff_mapping = {}
    probe_wall = mapping.get("probe_creation_wall_ns")
    probe_steady = mapping.get("probe_creation_steady_ns")
    if not isinstance(probe_wall, int) or not isinstance(probe_steady, int) or (
            probe_wall <= 0 or probe_steady <= 0):
        errors.append("invalid probe clock origins")
    elif start_ok and end_ok:
        probe_delta = probe_wall - probe_steady
        collector_delta = start_wall - start_mono
        residual = collector_delta - probe_delta
        drift = (end_wall - start_wall) - (end_mono - start_mono)
        expected_mapping = {
            "collector_wall_ns": start_wall,
            "collector_monotonic_ns": start_mono,
            "probe_wall_minus_steady_ns": probe_delta,
            "collector_wall_minus_monotonic_ns": collector_delta,
            "steady_to_collector_monotonic_offset_ns": -residual,
            "steady_to_wall_offset_ns": probe_delta,
            "origin_residual_ns": residual,
            "capture_uncertainty_ns": start_boundary["capture_uncertainty_ns"],
            "cutoff_capture_uncertainty_ns": end_boundary["capture_uncertainty_ns"],
            "collection_wall_minus_monotonic_drift_ns": drift,
            "mapping_uncertainty_ns": (
                abs(residual) + start_boundary["capture_uncertainty_ns"] +
                abs(drift) + end_boundary["capture_uncertainty_ns"]),
            "compatibility": "wall_offset_bridge_with_reported_uncertainty",
            "method": "wall-offset bridge; residual may include pre-attach wall correction; no affine/drift claim",
        }
        for key, value in expected_mapping.items():
            if mapping.get(key) != value:
                errors.append(f"clock mapping {key} mismatch")
        end_collector_delta = end_wall - end_mono
        end_residual = end_collector_delta - probe_delta
        expected_cutoff_mapping = {
            "probe_creation_wall_ns": probe_wall,
            "probe_creation_steady_ns": probe_steady,
            "collector_wall_ns": end_wall,
            "collector_monotonic_ns": end_mono,
            "probe_wall_minus_steady_ns": probe_delta,
            "collector_wall_minus_monotonic_ns": end_collector_delta,
            "steady_to_collector_monotonic_offset_ns": -end_residual,
            "steady_to_wall_offset_ns": probe_delta,
            "origin_residual_ns": end_residual,
            "capture_uncertainty_ns": end_boundary["capture_uncertainty_ns"],
            "mapping_uncertainty_ns": (
                abs(end_residual) + end_boundary["capture_uncertainty_ns"]),
            "compatibility": "wall_offset_bridge_with_reported_uncertainty",
            "method": "wall-offset bridge; residual may include pre-attach wall correction; no affine/drift claim",
            "collection_wall_minus_monotonic_drift_ns": drift,
        }
        for key, value in expected_cutoff_mapping.items():
            if cutoff_mapping.get(key) != value:
                errors.append(f"cutoff clock mapping {key} mismatch")
        mapped_bounds = []
        offset = mapping.get("steady_to_collector_monotonic_offset_ns")
        wall_offset = mapping.get("steady_to_wall_offset_ns")
        uncertainty = mapping.get("mapping_uncertainty_ns")
        if all(isinstance(value, int) for value in (offset, wall_offset, uncertainty)):
            for event in events:
                mapped_mono = event["steady_ns"] + offset
                mapped_wall = event["steady_ns"] + wall_offset
                if event.get("mapped_monotonic_ns") != mapped_mono:
                    errors.append(f"mapped monotonic timestamp mismatch at {event['sequence']}")
                if event.get("mapped_wall_ns") != mapped_wall:
                    errors.append(f"mapped wall timestamp mismatch at {event['sequence']}")
                if event.get("collection_scope") == "measured":
                    mapped_bounds.append(mapped_mono)
                    if not (start_mono - uncertainty <= mapped_mono <= end_mono + uncertainty):
                        errors.append(f"measured event outside mapped clock bounds at {event['sequence']}")
        actual_mapped_bounds = [min(mapped_bounds), max(mapped_bounds)] if mapped_bounds else [None, None]
        if window.get("measured_event_mapped_monotonic_bounds_ns") != actual_mapped_bounds:
            errors.append("measured mapped event bounds mismatch")

    def validate_sample_rows(rows, name):
        previous_mono = None
        mono_values, wall_values = [], []
        for index, row in enumerate(rows):
            mono, wall = row.get("monotonic_ns"), row.get("wall_ns")
            if not isinstance(mono, int) or not isinstance(wall, int) or mono <= 0 or wall <= 0:
                errors.append(f"malformed {name} clock row {index}")
                continue
            if previous_mono is not None and mono <= previous_mono:
                errors.append(f"non-increasing {name} monotonic clock")
            previous_mono = mono
            mono_values.append(mono)
            wall_values.append(wall)
            if start_ok and end_ok and not (
                    start_boundary["collector_monotonic_before_ns"] <= mono <=
                    end_boundary["collector_monotonic_after_ns"]):
                errors.append(f"{name} row outside collection monotonic bounds")
            wall_uncertainty = (
                mapping.get("mapping_uncertainty_ns", 0)
                if isinstance(mapping.get("mapping_uncertainty_ns", 0), int) else 0)
            if start_ok and end_ok and not (
                    start_boundary["collector_wall_before_ns"] - wall_uncertainty <= wall <=
                    end_boundary["collector_wall_after_ns"] + wall_uncertainty):
                errors.append(f"{name} row outside collection wall bounds")
            if start_ok and end_ok:
                start_delta = (
                    start_boundary["collector_wall_midpoint_ns"] -
                    start_boundary["collector_monotonic_midpoint_ns"])
                end_delta = (
                    end_boundary["collector_wall_midpoint_ns"] -
                    end_boundary["collector_monotonic_midpoint_ns"])
                if not (min(start_delta, end_delta) - wall_uncertainty <= wall - mono <=
                        max(start_delta, end_delta) + wall_uncertainty):
                    errors.append(f"{name} row clock-domain residual mismatch")
        return ([min(mono_values), max(mono_values)] if mono_values else [None, None],
                [min(wall_values), max(wall_values)] if wall_values else [None, None])

    resource_mono, resource_wall = validate_sample_rows(resources, "resource")
    for row in resources:
        if any(not math.isfinite(row[field]) for field in RESOURCE_FLOAT_FIELDS):
            errors.append("nonfinite resource counter")
        if any(row[field] < 0 for field in RESOURCE_FIELDS if field not in (
                "monotonic_ns", "wall_ns") and field not in RESOURCE_FLOAT_FIELDS):
            errors.append("negative resource counter")
    if summary.get("resource_samples") != len(resources):
        errors.append("resource sample count mismatch")
    if summary.get("resource_monotonic_bounds_ns") != resource_mono:
        errors.append("resource monotonic bounds mismatch")
    if summary.get("resource_wall_bounds_ns") != resource_wall:
        errors.append("resource wall bounds mismatch")

    valid_rpc = 0
    failed_rpc = 0
    for index, row in enumerate(rpc):
        has_error = "error" in row
        has_chain = isinstance(row.get("chain"), dict)
        if has_error == has_chain:
            errors.append(f"RPC row {index} failure/success shape mismatch")
        if has_error:
            failed_rpc += 1
            if (set(row) != {"monotonic_ns", "wall_ns", "error"} or
                    not isinstance(row["error"], str) or not row["error"]):
                errors.append(f"RPC row {index} malformed error")
        else:
            valid_rpc += 1
            chain = row.get("chain", {})
            if (set(row) != {"monotonic_ns", "wall_ns", "chain", "warnings_present",
                             "network_totals", "network", "peers"} or
                    chain.get("chain") != manifest.get("expected_chain") or
                    not isinstance(chain.get("initialblockdownload"), bool) or
                    not isinstance(chain.get("blocks"), int) or
                    not isinstance(chain.get("headers"), int)):
                errors.append(f"RPC row {index} malformed chain snapshot")
    rpc_mono, rpc_wall = validate_sample_rows(rpc, "RPC")
    if summary.get("rpc_rows") != len(rpc):
        errors.append("RPC retained row count mismatch")
    if summary.get("rpc_samples") != valid_rpc:
        errors.append("RPC success count mismatch")
    if summary.get("rpc_failures") != failed_rpc:
        errors.append("RPC failure count mismatch")
    if summary.get("rpc_monotonic_bounds_ns") != rpc_mono:
        errors.append("RPC monotonic bounds mismatch")
    if summary.get("rpc_wall_bounds_ns") != rpc_wall:
        errors.append("RPC wall bounds mismatch")


def analyze(manifest, summary, events, resources, rpc, max_join_age, artifacts=None):
    integrity_errors = []
    previous = None
    structurally_valid = True
    for event in events:
        required = ("sequence", "process_epoch", "event", "event_code", "steady_ns", "values")
        if any(key not in event for key in required):
            integrity_errors.append("event missing required field")
            structurally_valid = False
            continue
        if EVENT_NAMES.get(event["event_code"]) != event["event"]:
            integrity_errors.append(
                f"event code/name mismatch at sequence {event['sequence']}")
        if (not isinstance(event["values"], list) or len(event["values"]) != 16 or
                any(not isinstance(value, int) for value in event["values"])):
            integrity_errors.append(
                f"invalid event values ABI at sequence {event['sequence']}")
            structurally_valid = False
        if previous is not None and event["sequence"] != previous + 1:
            integrity_errors.append(
                f"event sequence gap: {previous} to {event['sequence']}")
        previous = event["sequence"]
        forbidden = {"hash", "txid", "wtxid"} & set(event)
        if forbidden:
            integrity_errors.append(f"raw identifier keys present: {sorted(forbidden)}")
        if event["event_code"] == 4 and (
                len(event["values"]) < 3 or event["values"][2] != 0):
            integrity_errors.append(
                f"response_queued reserved field is nonzero at sequence {event['sequence']}")
        values = event.get("values", [])
        code = event.get("event_code")
        if code in (1, 2, 3, 4, 21) and len(values) > 1 and values[1] <= 0:
            integrity_errors.append(
                f"zero inbound causal ID at sequence {event.get('sequence')}")
        if code == 22 and len(values) > 5:
            reason, mutation_id = values[4], values[5]
            if reason not in (1, 2):
                integrity_errors.append(
                    f"unknown receive queue mutation reason at sequence "
                    f"{event.get('sequence')}")
            elif reason == 1 and mutation_id != 0:
                integrity_errors.append(
                    f"receive-append mutation has nonzero ID at sequence "
                    f"{event.get('sequence')}")
            elif reason == 2 and mutation_id <= 0:
                integrity_errors.append(
                    f"zero receive-pop causal ID at sequence {event.get('sequence')}")
        if code == 31 and len(values) > 5:
            reason, mutation_id = values[4], values[5]
            if reason not in (1, 2):
                integrity_errors.append(
                    f"unknown send queue mutation reason at sequence "
                    f"{event.get('sequence')}")
            elif reason == 1 and mutation_id <= 0:
                integrity_errors.append(
                    f"zero send-enqueue outbound ID at sequence "
                    f"{event.get('sequence')}")
            elif reason != 1 and mutation_id != 0:
                integrity_errors.append(
                    f"non-enqueue send mutation has nonzero ID at sequence "
                    f"{event.get('sequence')}")
        if code == 26 and len(values) > 2 and (values[1] <= 0 or values[2] <= 0):
            integrity_errors.append(
                f"zero causal relation ID at sequence {event.get('sequence')}")
        if code in range(5, 14) and values and values[0] <= 0:
            integrity_errors.append(
                f"zero PNB job ID at sequence {event.get('sequence')}")

    if structurally_valid:
        reconcile_collector(
            manifest, summary, events, resources, rpc, artifacts,
            integrity_errors)

    all_events = events
    raw_mapping_uncertainty = summary.get("clock_mapping", {}).get(
        "mapping_uncertainty_ns", 0)
    mapping_uncertainty_ns = (raw_mapping_uncertainty
                              if isinstance(raw_mapping_uncertainty, int) and
                              raw_mapping_uncertainty >= 0 else 0)
    join_ages = annotate(
        all_events, rpc, max_join_age,
        mapping_uncertainty_ns=mapping_uncertainty_ns)
    all_complete, all_front, all_starts, all_ends, duplicates = keyed_messages(all_events)
    if duplicates:
        integrity_errors.append(f"duplicate message lifecycle keys: {len(duplicates)}")
    for stage_name, stages in (("front", all_front), ("start", all_starts),
                               ("end", all_ends)):
        for key in stages:
            if key not in all_complete:
                integrity_errors.append(
                    f"orphan message {stage_name} without complete-ready for {key}")
    for key in all_complete:
        present = [True, key in all_front, key in all_starts, key in all_ends]
        last_present = max(index for index, value in enumerate(present) if value)
        if present[:last_present + 1] != [True] * (last_present + 1):
            integrity_errors.append(f"missing internal message lifecycle stage for {key}")
    max_progressed_id = defaultdict(int)
    max_started_id = defaultdict(int)
    for stages in (all_front, all_starts, all_ends):
        for epoch, peer, message_id in stages:
            max_progressed_id[(epoch, peer)] = max(
                max_progressed_id[(epoch, peer)], message_id)
    for epoch, peer, message_id in all_starts:
        max_started_id[(epoch, peer)] = max(
            max_started_id[(epoch, peer)], message_id)
    latest_handler_start_sequence = defaultdict(int)
    for (epoch, _peer, _message_id), event in all_starts.items():
        latest_handler_start_sequence[epoch] = max(
            latest_handler_start_sequence[epoch], event["sequence"])
    latest_finalization_sequence = defaultdict(int)
    for event in all_events:
        if event.get("event_code") == 29 and event.get("values"):
            latest_finalization_sequence[
                (event["process_epoch"], event["values"][0])] = max(
                    latest_finalization_sequence[
                        (event["process_epoch"], event["values"][0])],
                    event["sequence"])
    for key, ready in all_complete.items():
        epoch, peer, message_id = key
        if key not in all_front and max_progressed_id[(epoch, peer)] > message_id:
            integrity_errors.append(
                f"message without front stage precedes later same-peer progress for {key}")
        if (key in all_front and key not in all_starts and
                max_started_id[(epoch, peer)] > message_id):
            integrity_errors.append(
                f"front-only message precedes later same-peer handler for {key}")
        if key in all_starts and key not in all_ends:
            if (all_starts[key]["sequence"] <
                    latest_handler_start_sequence[epoch]):
                integrity_errors.append(
                    f"incomplete handler precedes later handler start for {key}")
            if (latest_finalization_sequence[(epoch, peer)] >
                    all_starts[key]["sequence"]):
                integrity_errors.append(
                    f"incomplete handler precedes peer finalization for {key}")
    window = summary.get("collection_window", {})
    mapping = summary.get("clock_mapping", {})
    observation_ns = window.get("duration_ns", 0)
    observation_seconds = observation_ns / 1e9 if isinstance(observation_ns, int) else 0
    offset = mapping.get("steady_to_collector_monotonic_offset_ns", 0)
    try:
        observation_start_mono = window["start"]["collector_monotonic_midpoint_ns"]
        observation_end_mono = window["end"]["collector_monotonic_midpoint_ns"]
        observation_start = observation_start_mono - offset
        observation_end = observation_end_mono - offset
    except (KeyError, TypeError):
        observation_start = min(
            (event["steady_ns"] for event in all_events), default=0)
        observation_end = max(
            (event["steady_ns"] for event in all_events), default=observation_start)
        observation_start_mono = observation_start + offset
        observation_end_mono = observation_end + offset
    events = [event for event in all_events
              if event.get("collection_scope") == "measured"]
    join_ages = [event["_rpc_join_age_ns"] for event in events
                 if event["_rpc_join_age_ns"] is not None]
    selected_message_keys = {
        key for key, event in all_complete.items()
        if event.get("collection_scope") == "measured"}
    complete = {key: all_complete[key] for key in selected_message_keys}
    front = {key: event for key, event in all_front.items()
             if key in selected_message_keys}
    starts = {key: event for key, event in all_starts.items()
              if key in selected_message_keys}
    ends = {key: event for key, event in all_ends.items()
            if key in selected_message_keys}

    queue_latency = []
    front_latency = []
    handler_latency = []
    ready_to_response = []
    front_to_response = []
    handler_outcomes = Counter()
    per_peer = defaultdict(list)
    no_service_intervals = []
    for key, ready in complete.items():
        if key in front:
            delta = front[key]["steady_ns"] - ready["steady_ns"]
            if delta < 0:
                integrity_errors.append(f"front precedes complete-ready for {key}")
            else:
                queue_latency.append(delta)
        if key in starts:
            front_time = front.get(key, ready)["steady_ns"]
            delta = starts[key]["steady_ns"] - front_time
            if delta < 0:
                integrity_errors.append(f"handler begins before front-ready for {key}")
            else:
                front_latency.append(delta)
                per_peer[key[1]].append(delta)
                no_service_intervals.append(delta)
        else:
            no_service_intervals.append(max(0, observation_end - front.get(key, ready)["steady_ns"]))
    for key, started in starts.items():
        if key not in ends:
            continue
        delta = ends[key]["steady_ns"] - started["steady_ns"]
        if delta < 0:
            integrity_errors.append(f"handler ends before begin for {key}")
        else:
            handler_latency.append(delta)
        handler_outcomes[str(ends[key]["values"][2])] += 1

    outbound = {}
    socket = {}
    dropped = {}
    causal_inbound = defaultdict(set)
    causal_outbound = defaultdict(set)
    causal_event_keys = set()
    legacy_responses = []
    for event in all_events:
        values = event["values"]
        if event["event_code"] == 23:
            if len(values) < 7:
                integrity_errors.append("short outbound_queued event")
                continue
            if values[1] == 0:
                integrity_errors.append("zero outbound ID in outbound_queued event")
            key = (event["process_epoch"], values[0], values[1])
            if key in outbound:
                integrity_errors.append(f"duplicate outbound key {key}")
                continue
            outbound[key] = event
            if values[2]:
                relation = (event["process_epoch"], values[0], values[2], values[1])
                if relation in causal_event_keys:
                    integrity_errors.append(f"duplicate causal key {relation}")
                causal_event_keys.add(relation)
                inbound_key = (event["process_epoch"], values[0], values[2])
                causal_inbound[inbound_key].add(key)
                causal_outbound[key].add(inbound_key)
        elif event["event_code"] == 24:
            if len(values) < 7:
                integrity_errors.append("short socket_sent event")
                continue
            if values[1] == 0:
                integrity_errors.append("zero outbound ID in socket_sent event")
            key = (event["process_epoch"], values[0], values[1])
            if key in socket:
                integrity_errors.append(f"duplicate socket key {key}")
                continue
            socket[key] = event
        elif event["event_code"] == 25:
            if len(values) < 4:
                integrity_errors.append("short outbound_dropped event")
                continue
            if values[1] == 0:
                integrity_errors.append("zero outbound ID in outbound_dropped event")
            key = (event["process_epoch"], values[0], values[1])
            if key in dropped:
                integrity_errors.append(f"duplicate drop key {key}")
                continue
            dropped[key] = event
        elif event["event_code"] == 26:
            if len(values) < 3:
                integrity_errors.append("short causal_link event")
                continue
            if values[2] == 0:
                integrity_errors.append("zero outbound ID in causal_link event")
            relation = (event["process_epoch"], values[0], values[1], values[2])
            if relation in causal_event_keys:
                integrity_errors.append(f"duplicate causal key {relation}")
                continue
            causal_event_keys.add(relation)
            inbound_key = relation[:3]
            outbound_key = (relation[0], relation[1], relation[3])
            causal_inbound[inbound_key].add(outbound_key)
            causal_outbound[outbound_key].add(inbound_key)
        elif event["event_code"] == 4:
            legacy_responses.append(event)

    for key in socket:
        if key not in outbound:
            integrity_errors.append(f"socket completion without outbound offer for {key}")
            continue
        queued, sent = outbound[key], socket[key]
        if sent["values"][2] != queued["values"][2]:
            integrity_errors.append(f"socket causal ID mismatch for {key}")
        if sent.get("text1", "") != queued.get("text1", ""):
            integrity_errors.append(f"socket message type mismatch for {key}")
        if sent["values"][6] != sent["values"][5]:
            integrity_errors.append(f"socket completed byte count mismatch for {key}")
    for key in dropped:
        if key not in outbound:
            integrity_errors.append(f"drop without outbound offer for {key}")
            continue
        queued, drop = outbound[key], dropped[key]
        if drop["values"][2] != queued["values"][2]:
            integrity_errors.append(f"drop causal ID mismatch for {key}")
        if drop.get("text1", "") != queued.get("text1", ""):
            integrity_errors.append(f"drop message type mismatch for {key}")
    for key in set(socket) & set(dropped):
        integrity_errors.append(f"outbound has both socket completion and drop for {key}")
    for inbound_key, outbound_keys in causal_inbound.items():
        if inbound_key not in all_complete:
            integrity_errors.append(f"causal link without inbound message for {inbound_key}")
        for outbound_key in outbound_keys:
            if outbound_key not in outbound:
                integrity_errors.append(f"causal link without outbound offer for {outbound_key}")

    receive_pop_keys = set()
    send_enqueue_keys = set()
    for event in all_events:
        values = event["values"]
        if event["event_code"] == 22 and values[4] == 2 and values[5] > 0:
            key = (event["process_epoch"], values[0], values[5])
            if key in receive_pop_keys:
                integrity_errors.append(f"duplicate receive-pop join for {key}")
                continue
            receive_pop_keys.add(key)
            if key not in all_complete:
                integrity_errors.append(
                    f"receive-pop mutation without inbound lifecycle for {key}")
            elif (key not in all_front or
                  event["sequence"] <= all_front[key]["sequence"] or
                  event["sequence"] <= all_complete[key]["sequence"]):
                integrity_errors.append(
                    f"impossible receive-pop lifecycle join for {key}")
        elif event["event_code"] == 31 and values[4] == 1 and values[5] > 0:
            key = (event["process_epoch"], values[0], values[5])
            if key in send_enqueue_keys:
                integrity_errors.append(f"duplicate send-enqueue join for {key}")
                continue
            send_enqueue_keys.add(key)
            if key not in outbound:
                integrity_errors.append(
                    f"send-enqueue mutation without outbound lifecycle for {key}")
            elif (event["sequence"] <= outbound[key]["sequence"] or
                  event["steady_ns"] != outbound[key]["steady_ns"]):
                integrity_errors.append(
                    f"impossible send-enqueue lifecycle join for {key}")
    for response in legacy_responses:
        values = response["values"]
        if len(values) < 10:
            integrity_errors.append("short legacy response_queued event")
            continue
        inbound_key = (response["process_epoch"], values[0], values[1])
        outbound_key = (response["process_epoch"], values[0], values[9])
        if values[9] == 0:
            integrity_errors.append("zero outbound ID in legacy response_queued event")
        if outbound_key not in outbound:
            integrity_errors.append(
                f"legacy response without outbound offer for {outbound_key}")
        if inbound_key not in causal_outbound.get(outbound_key, set()):
            integrity_errors.append(
                f"legacy response without canonical causal link for {inbound_key}")
        inbound = all_complete.get(inbound_key)
        queued = outbound.get(outbound_key)
        if inbound and response.get("text1", "") != inbound.get("text1", ""):
            integrity_errors.append(
                f"legacy response request type mismatch for {inbound_key}")
        if queued:
            if response.get("text2", "") != queued.get("text1", ""):
                integrity_errors.append(
                    f"legacy response type mismatch for {outbound_key}")
            if values[3] != queued["values"][3]:
                integrity_errors.append(
                    f"legacy response payload mismatch for {outbound_key}")
            if values[4:7] != queued["values"][4:7]:
                integrity_errors.append(
                    f"legacy response queue snapshot mismatch for {outbound_key}")
            if values[1] != queued["values"][2]:
                integrity_errors.append(
                    f"legacy response primary causal mismatch for {outbound_key}")

    # OUTBOUND_QUEUED inside the explicit measured sequence window is the
    # canonical offered population. Full-stream maps above remain the authority
    # for structural joins, including pre-attach lifecycle context.
    outbound = {key: event for key, event in outbound.items()
                if event.get("collection_scope") == "measured"}
    socket = {key: event for key, event in socket.items() if key in outbound}
    dropped = {key: event for key, event in dropped.items() if key in outbound}

    queue_to_first = []
    queue_to_last = []
    for key, queued in outbound.items():
        if key not in socket:
            continue
        sent = socket[key]
        first = sent["values"][3]
        last = sent["values"][4]
        if first < queued["steady_ns"] or last < first:
            integrity_errors.append(f"impossible outbound socket ordering for {key}")
            continue
        queue_to_first.append(first - queued["steady_ns"])
        queue_to_last.append(last - queued["steady_ns"])
    for outbound_key, inbound_keys in causal_outbound.items():
        queued = outbound.get(outbound_key)
        if not queued:
            continue
        for inbound_key in inbound_keys:
            ready = complete.get(inbound_key)
            if ready:
                delta = queued["steady_ns"] - ready["steady_ns"]
                if delta < 0:
                    integrity_errors.append(
                        f"response queued before complete-ready for {inbound_key}")
                else:
                    ready_to_response.append(delta)
            front_ready = front.get(inbound_key)
            if front_ready:
                delta = queued["steady_ns"] - front_ready["steady_ns"]
                if delta < 0:
                    integrity_errors.append(
                        f"response queued before front-ready for {inbound_key}")
                else:
                    front_to_response.append(delta)

    pnb_jobs = build_pnb_jobs(all_events, integrity_errors)
    observed_job_modes = {job["mode"] for job in pnb_jobs}
    expected_job_mode = {"candidate": "async", "control": "control"}.get(
        manifest.get("mode"))
    if pnb_jobs and (expected_job_mode is None or
                     observed_job_modes != {expected_job_mode}):
        integrity_errors.append(
            f"PNB manifest/job mode mismatch: manifest={manifest.get('mode')!r}, "
            f"observed={sorted(observed_job_modes)!r}")
    complete_pnb_jobs = [
        job for job in pnb_jobs
        if job["start_ns"] is not None and job["end_ns"] is not None and
        job["end_ns"] >= job["start_ns"] and job["ordered_complete"]]
    submitted_pnb_jobs = [job for job in pnb_jobs
                          if job["submit_scope"] == "measured"]
    completed_submitted_jobs = [job for job in complete_pnb_jobs
                                if job["submit_scope"] == "measured"]
    ordered_complete_jobs = sorted(
        complete_pnb_jobs,
        key=lambda job: (job["start_ns"], job["start_sequence"]))
    for previous_job, job in zip(ordered_complete_jobs, ordered_complete_jobs[1:]):
        if ((job["start_ns"], job["start_sequence"]) <
                (previous_job["end_ns"], previous_job["end_sequence"])):
            integrity_errors.append(
                "overlapping PNB intervals for epoch/jobs "
                f"{(previous_job['process_epoch'], previous_job['job_id'])} and "
                f"{(job['process_epoch'], job['job_id'])}")
    busy_pnb_intervals = []
    for job in pnb_jobs:
        if job["start_ns"] is None or not (
                job["ordered_complete"] or
                job["incomplete_at_collection_boundary"]):
            continue
        interval_start = max(job["start_ns"], observation_start)
        interval_end = min(
            job["end_ns"] if job["end_ns"] is not None else observation_end,
            observation_end)
        if interval_end > interval_start:
            busy_pnb_intervals.append((job, interval_start, interval_end))
    busy_pnb_intervals.sort(
        key=lambda item: (item[1], item[0]["start_sequence"]))
    for (previous_job, _previous_start, previous_end), (
            job, start_ns, _end_ns) in zip(
                busy_pnb_intervals, busy_pnb_intervals[1:]):
        if start_ns < previous_end:
            integrity_errors.append(
                "overlapping PNB busy intervals for epoch/jobs "
                f"{(previous_job['process_epoch'], previous_job['job_id'])} and "
                f"{(job['process_epoch'], job['job_id'])}")
    merged_intervals = []
    for job, interval_start, interval_end in busy_pnb_intervals:
        if merged_intervals and interval_start <= merged_intervals[-1][1]:
            merged_intervals[-1][1] = max(
                merged_intervals[-1][1], interval_end)
        else:
            merged_intervals.append([interval_start, interval_end])
    pnb_ns = sum(end - start for start, end in merged_intervals)

    def containing_pnb_jobs(event):
        position = (event["steady_ns"], event["sequence"])
        return [job for job, _start_ns, _end_ns in busy_pnb_intervals
                if (job["start_ns"], job["start_sequence"]) <= position and
                (job["end_ns"] is None or position <=
                 (job["end_ns"], job["end_sequence"]))]

    def count_source_relationship(prefix, event, jobs):
        if len(jobs) != 1 or jobs[0]["source_peer"] is None:
            return
        relation = ("source_peer" if event["values"][0] == jobs[0]["source_peer"]
                    else "unrelated_peer")
        during[f"{prefix}_{relation}"] += 1

    for event in events:
        jobs = containing_pnb_jobs(event)
        event["_pnb_route"] = (
            jobs[0]["delivery_route"] if len(jobs) == 1 else None)
        event["_pnb_source_relation"] = None
        if (len(jobs) == 1 and jobs[0]["source_peer"] is not None and
                event["event_code"] in (2, 23, 24, 25) and event["values"]):
            event["_pnb_source_relation"] = (
                "source_peer" if event["values"][0] == jobs[0]["source_peer"]
                else "unrelated_peer")

    useful_completed_keys = {
        key for key in outbound
        if causal_outbound.get(key) and key in socket and key not in dropped}
    during = Counter({
        "handler_start": 0,
        "response_queued": 0,
        "socket_sent": 0,
        "correlated_socket_sent": 0,
        "useful_correlated_completed_responses": 0,
        "handler_start_source_peer": 0,
        "handler_start_unrelated_peer": 0,
        "response_queued_source_peer": 0,
        "response_queued_unrelated_peer": 0,
        "useful_correlated_completed_responses_source_peer": 0,
        "useful_correlated_completed_responses_unrelated_peer": 0,
        "outbound_payload_bytes": 0,
        "outbound_wire_bytes": 0,
    })
    for event in events:
        jobs = containing_pnb_jobs(event)
        if jobs and event["event_code"] == 2:
            during["handler_start"] += 1
            count_source_relationship("handler_start", event, jobs)
    for key, queued in outbound.items():
        jobs = containing_pnb_jobs(queued)
        if causal_outbound.get(key) and jobs:
            during["response_queued"] += 1
            count_source_relationship("response_queued", queued, jobs)
            # Service throughput is attributed to the PNB interval in which the
            # response was queued. A large response may finish writing just
            # after the overlap ends, but it is still useful work caused during
            # that overlap once its eventual socket completion is observed.
            if key in useful_completed_keys:
                during["useful_correlated_completed_responses"] += 1
                count_source_relationship(
                    "useful_correlated_completed_responses", queued, jobs)
                during["outbound_payload_bytes"] += queued["values"][3]
                during["outbound_wire_bytes"] += socket[key]["values"][5]
    for sent in (event for event in events if event["event_code"] == 24):
        if containing_pnb_jobs(sent):
            during["socket_sent"] += 1
            values = sent["values"]
            key = ((sent["process_epoch"], values[0], values[1])
                   if len(values) >= 2 else None)
            if key is not None and causal_outbound.get(key):
                during["correlated_socket_sent"] += 1

    useful = [event for event in events if event["event_code"] == 3 and
              len(event["values"]) > 2 and event["values"][2] == 0]
    payload = sum(event["values"][2] for event in complete.values())
    wire = sum(event["values"][3] for event in complete.values())
    outbound_payload = sum(outbound[key]["values"][3] for key in useful_completed_keys)
    outbound_wire = sum(socket[key]["values"][5] for key in useful_completed_keys)
    pnb_seconds = pnb_ns / 1e9

    worst_peer = []
    for peer, values in per_peer.items():
        worst_peer.append({
            "peer": peer,
            "completion_count": len(values),
            "front_to_handler_p95_ns": percentile(values, 95),
            "front_to_handler_p99_ns": percentile(values, 99),
        })
    worst_peer.sort(key=lambda row: (-float(row["front_to_handler_p99_ns"] or 0), row["peer"]))

    lifecycle_counts = Counter(event["event"] for event in events if event["event_code"] in range(27, 31))
    handshake_latencies = [event["values"][2] for event in events if event["event_code"] == 28]
    finalizations = [event for event in events if event["event_code"] == 29]
    all_finalizations = [event for event in all_events if event["event_code"] == 29]
    peer_finalizations = {}
    for event in all_finalizations:
        if not event["values"]:
            integrity_errors.append("short peer_finalized event")
            continue
        key = (event["process_epoch"], event["values"][0])
        if key in peer_finalizations:
            integrity_errors.append(f"duplicate peer finalization for {key}")
        else:
            peer_finalizations[key] = event["steady_ns"]
    block_counts = Counter(event["event"] for event in events if event["event_code"] in (32, 33, 34))
    timeout_reasons = Counter(str(event["values"][1]) for event in events if event["event_code"] == 34)
    block_requests = defaultdict(deque)
    block_completion_ns = []
    block_removal_ns = []
    block_stall_ns = []
    unmatched_block_removals = 0
    for event in all_events:
        if event["event_code"] == 32 and event.get("block_id"):
            block_requests[(event["process_epoch"], event["values"][0],
                            event["block_id"])].append(event["steady_ns"])
        elif event["event_code"] == 33 and event.get("block_id"):
            key = (event["process_epoch"], event["values"][0], event["block_id"])
            reason = event["values"][2] if len(event["values"]) > 2 else None
            if reason not in (0, 1):
                integrity_errors.append(f"unknown block removal reason {reason!r} for {key}")
            if block_requests[key]:
                requested_ns = block_requests[key].popleft()
                if event["steady_ns"] < requested_ns:
                    integrity_errors.append(f"block removal precedes request for {key}")
                elif reason == 1 and event.get("collection_scope") == "measured":
                    block_completion_ns.append(event["steady_ns"] - requested_ns)
                elif reason == 0 and event.get("collection_scope") == "measured":
                    block_removal_ns.append(event["steady_ns"] - requested_ns)
            elif event.get("collection_scope") == "measured":
                unmatched_block_removals += 1
        elif event["event_code"] == 34 and event.get("block_id"):
            key = (event["process_epoch"], event["values"][0], event["block_id"])
            if (event.get("collection_scope") == "measured" and
                    block_requests[key] and event["steady_ns"] >= block_requests[key][0]):
                block_stall_ns.append(event["steady_ns"] - block_requests[key][0])

    receive_queue = queue_metrics(
        all_events, 22, observation_start, observation_end, peer_finalizations)
    send_queue = queue_metrics(
        all_events, 31, observation_start, observation_end, peer_finalizations)
    if receive_queue["negative_counter_samples"] or send_queue["negative_counter_samples"]:
        integrity_errors.append("negative queue counter observed")
    if (receive_queue["post_finalization_samples"] or
            send_queue["post_finalization_samples"]):
        integrity_errors.append("queue state observed after peer finalization")

    phases = ("ibd", "transition", "post_ibd", "unclassified")
    phase_intervals = phase_observation_intervals(
        rpc, observation_start_mono, observation_end_mono,
        int(max_join_age * 1_000_000_000),
        mapping_uncertainty_ns=mapping_uncertainty_ns)
    phase_duration_ns = Counter()
    for phase, left, right in phase_intervals:
        phase_duration_ns[phase] += right - left
    phase_seconds = {phase: phase_duration_ns[phase] / 1e9 for phase in phases}

    def measured_pnb_submissions(predicate):
        return sum(predicate(job) for job in submitted_pnb_jobs)

    def measured_pnb_time(predicate, phase=None):
        total_ns = 0
        for job, interval_start, interval_end in busy_pnb_intervals:
            if not predicate(job):
                continue
            if phase is None:
                total_ns += interval_end - interval_start
                continue
            mono_start = interval_start + offset
            mono_end = interval_end + offset
            for interval_phase, left, right in phase_intervals:
                if interval_phase == phase:
                    total_ns += max(0, min(mono_end, right) - max(mono_start, left))
        return total_ns / 1e9

    message_types = sorted({event["_message_type"] for event in events
                            if event["_message_type"]})
    connection_roles = sorted(
        {event["_role"] for event in events} |
        {job["source_role"] for job in submitted_pnb_jobs} |
        {job["source_role"] for job, _start, _end in busy_pnb_intervals})
    delivery_routes = sorted(
        {job["delivery_route"] for job in submitted_pnb_jobs
         if job["delivery_route"]} |
        {job["delivery_route"] for job, _start, _end in busy_pnb_intervals
         if job["delivery_route"]})
    process_epochs = sorted(
        {event["process_epoch"] for event in events} |
        {job["process_epoch"] for job in submitted_pnb_jobs} |
        {job["process_epoch"] for job, _start, _end in busy_pnb_intervals})
    breakdowns = {
        "phase": {phase: subset_summary(
                       [event for event in events if event["_phase"] == phase],
                       all_events, observation_seconds=phase_seconds[phase],
                       pnb_count=measured_pnb_submissions(
                           lambda job, phase=phase: job["phase"] == phase),
                       pnb_time_seconds=measured_pnb_time(
                           lambda _job: True, phase))
                  for phase in phases},
        "message_type": {name: subset_summary(
                              [event for event in events
                               if event["_message_type"] == name], all_events,
                              observation_seconds=observation_seconds,
                              pnb_count=0, pnb_time_seconds=0.0)
                         for name in message_types},
        "connection_role": {name: subset_summary(
                                 [event for event in events
                                  if event["_role"] == name], all_events,
                                 observation_seconds=observation_seconds,
                                 pnb_count=measured_pnb_submissions(
                                     lambda job, name=name:
                                     job["source_role"] == name),
                                 pnb_time_seconds=measured_pnb_time(
                                     lambda job, name=name:
                                     job["source_role"] == name))
                            for name in connection_roles},
        "pnb_delivery_route": {name: subset_summary(
                                    [event for event in events
                                     if event["_pnb_route"] == name], all_events,
                                    observation_seconds=observation_seconds,
                                    include_interval_work=True,
                                    pnb_count=measured_pnb_submissions(
                                        lambda job, name=name:
                                        job["delivery_route"] == name),
                                    pnb_time_seconds=measured_pnb_time(
                                        lambda job, name=name:
                                        job["delivery_route"] == name))
                               for name in delivery_routes},
        "process_epoch": {str(epoch): subset_summary(
                               [event for event in events
                                if event["process_epoch"] == epoch], all_events,
                               observation_seconds=observation_seconds,
                               pnb_count=measured_pnb_submissions(
                                   lambda job, epoch=epoch:
                                   job["process_epoch"] == epoch),
                               pnb_time_seconds=measured_pnb_time(
                                   lambda job, epoch=epoch:
                                   job["process_epoch"] == epoch))
                          for epoch in process_epochs},
    }

    return {
        "analysis_schema": 1,
        "input": {
            "collector_schema": manifest.get("collector_schema"),
            "probe_schema": manifest.get("probe_schema"),
            "mode": manifest.get("mode", "unknown"),
            "expected_chain": manifest.get("expected_chain"),
            "collector_valid": summary.get("valid"),
        },
        "interpretation": (
            "Observational measurement. Local socket completion is not remote receipt; "
            "before/after comparisons are not causal."),
        "percentile_method": "sort ascending; rank=(n-1)*p/100; linearly interpolate adjacent ranks",
        "rpc_join": {
            "method": "nearest preceding sample",
            "maximum_age_seconds": max_join_age,
            "joined_age_ns": distribution(join_ages),
            "unclassified_event_count": sum(event["_phase"] == "unclassified" for event in events),
            "phase_observation_seconds": phase_seconds,
        },
        "observation": {
            "seconds": observation_seconds,
            "hours": observation_seconds / 3600,
            "event_count": len(events),
            "retained_event_count": len(all_events),
            "pre_attach_backlog_event_count": len(all_events) - len(events),
            "sequence_first": window.get("sequence_first"),
            "sequence_last": window.get("sequence_last"),
            "duration_source": window.get("duration_source"),
            "clock_mapping_uncertainty_ns": mapping.get("mapping_uncertainty_ns"),
        },
        "pnb": {
            "count": len(submitted_pnb_jobs),
            "submitted_count": len(submitted_pnb_jobs),
            "completed_count": len(complete_pnb_jobs),
            "completed_submitted_count": len(completed_submitted_jobs),
            "busy_interval_count": len(busy_pnb_intervals),
            "time_seconds": pnb_seconds,
            "wall_fraction": pnb_seconds / observation_seconds if observation_seconds else None,
            "jobs_per_second": len(submitted_pnb_jobs) / observation_seconds if observation_seconds else None,
            "blocks_per_second": sum(bool(job["new_block"]) for job in completed_submitted_jobs) /
                                 observation_seconds if observation_seconds else None,
            "process_new_block_failures": sum(
                job["process_new_block"] is False for job in completed_submitted_jobs),
            "incomplete_at_collection_boundary": sum(
                job["incomplete_at_collection_boundary"] and
                job["submit_scope"] == "measured" for job in pnb_jobs),
            "pre_attach_jobs_excluded": sum(
                job["submit_scope"] == "pre_attach_backlog" for job in pnb_jobs),
            "pre_attach_active_at_measured_start": sum(
                job["submit_scope"] == "pre_attach_backlog" and
                job["start_ns"] is not None and
                (job["end_ns"] is None or job["end_ns"] >= observation_start)
                for job in pnb_jobs),
            "active_at_collection_cutoff": sum(
                job["submit_scope"] == "measured" and
                job["start_ns"] is not None and job["end_ns"] is None and
                job["incomplete_at_collection_boundary"]
                for job in pnb_jobs),
            "impossible_join_count": sum("PNB" in error for error in integrity_errors),
            "during_pnb_counts": dict(sorted(during.items())),
            "during_pnb_rates_per_second": {
                key: value / pnb_seconds if pnb_seconds else None
                for key, value in sorted(during.items())},
            "jobs": pnb_jobs,
        },
        "inbound": {
            "complete_ready_count": len(complete),
            "exact_front_count": len(front),
            "queue_to_front_ns": distribution(queue_latency),
            "front_to_handler_ns": distribution(front_latency),
            "handler_duration_ns": distribution(handler_latency),
            "complete_ready_to_response_queued_ns": distribution(ready_to_response),
            "front_ready_to_response_queued_ns": distribution(front_to_response),
            "handler_outcomes": dict(sorted(handler_outcomes.items())),
            "missing_front_at_boundary": sum(key not in front for key in complete),
            "missing_handler_start_at_boundary": sum(key not in starts for key in complete),
            "missing_handler_end_at_boundary": sum(key not in ends for key in complete),
            "useful_completed_messages": len(useful),
            "payload_bytes": payload,
            "wire_bytes": wire,
            "useful_messages_per_wall_second": len(useful) / observation_seconds if observation_seconds else None,
            "payload_bytes_per_wall_second": payload / observation_seconds if observation_seconds else None,
            "wire_bytes_per_wall_second": wire / observation_seconds if observation_seconds else None,
        },
        "service_throughput": {
            "useful_correlated_completed_responses": len(useful_completed_keys),
            "outbound_payload_bytes": outbound_payload,
            "outbound_wire_bytes": outbound_wire,
            "useful_correlated_completed_responses_per_wall_second": (
                len(useful_completed_keys) / observation_seconds
                if observation_seconds else None),
            "outbound_payload_bytes_per_wall_second": (
                outbound_payload / observation_seconds if observation_seconds else None),
            "outbound_wire_bytes_per_wall_second": (
                outbound_wire / observation_seconds if observation_seconds else None),
            "useful_correlated_completed_responses_per_pnb_second": (
                during["useful_correlated_completed_responses"] / pnb_seconds
                if pnb_seconds else None),
            "outbound_payload_bytes_per_pnb_second": (
                during["outbound_payload_bytes"] / pnb_seconds
                if pnb_seconds else None),
            "outbound_wire_bytes_per_pnb_second": (
                during["outbound_wire_bytes"] / pnb_seconds
                if pnb_seconds else None),
        },
        "outbound": {
            "offered": len(outbound),
            "correlated": sum(bool(causal_outbound.get(key)) for key in outbound),
            "completed": sum(key in socket for key in outbound),
            "incomplete": sum(key not in socket and key not in dropped for key in outbound),
            "dropped": len(dropped),
            "queue_to_first_write_ns": distribution(queue_to_first),
            "queue_to_last_write_ns": distribution(queue_to_last),
        },
        "queues": {
            "receive": receive_queue,
            "send": send_queue,
        },
        "fairness": {
            "per_peer": worst_peer,
            "worst_peer_p95_ns": max((row["front_to_handler_p95_ns"] or 0
                                      for row in worst_peer), default=None),
            "worst_peer_p99_ns": max((row["front_to_handler_p99_ns"] or 0
                                      for row in worst_peer), default=None),
            "max_front_ready_without_handler_service_ns": max(no_service_intervals, default=None),
        },
        "peer_lifecycle": {
            "counts": dict(sorted(lifecycle_counts.items())),
            "handshake_latency_ns": distribution(handshake_latencies),
            "disconnect_count": sum(bool(event["values"][3]) for event in finalizations),
            "discouragement_count": lifecycle_counts["discouragement"],
        },
        "block_download": {
            "counts": dict(sorted(block_counts.items())),
            "timeout_reasons": dict(sorted(timeout_reasons.items())),
            "observed_stall_intervals": block_counts["block_timeout"],
            "completed_removals": len(block_completion_ns),
            "noncompletion_removals": len(block_removal_ns),
            "unmatched_removals_at_collection_boundary": unmatched_block_removals,
            "requests_open_at_collection_boundary": sum(
                len(requests) for requests in block_requests.values()),
            "request_to_completion_ns": distribution(block_completion_ns),
            "request_to_noncompletion_removal_ns": distribution(block_removal_ns),
            "request_to_timeout_ns": distribution(block_stall_ns),
        },
        "resources": resource_metrics(resources, observation_seconds),
        "network": network_metrics(rpc, observation_seconds),
        "breakdowns": breakdowns,
        "integrity": {
            "collector": {
                key: summary.get(key) for key in
                ("valid", "loss_count", "checksum_failures", "unstable_read_failures",
                 "sequence_failures", "process_exit_state")},
            "analysis_errors": integrity_errors,
            "valid": not integrity_errors and bool(summary.get("valid")),
            "clock_mapping": mapping,
        },
        "observability": {
            "peer_response_receive": "not_observable",
            "true_peer_rtt": "not_observable",
            "remote_processing": "not_observable",
            "local_socket_complete": "observable_but_not_remote_receipt",
        },
    }


def markdown(report):
    integrity = report["integrity"]
    inbound = report["inbound"]
    outbound = report["outbound"]
    pnb = report["pnb"]
    return "\n".join([
        "# Async-PNB peer-service analysis",
        "",
        f"- Mode: `{report['input']['mode']}`",
        f"- Valid: `{str(integrity['valid']).lower()}`",
        f"- Observation: {report['observation']['hours']:.6f} hours",
        f"- Events: {report['observation']['event_count']}",
        f"- PNB jobs: {pnb['count']} ({pnb['time_seconds']:.6f} seconds)",
        f"- Complete/front/handler: {inbound['complete_ready_count']} / "
        f"{inbound['exact_front_count']} / {inbound['handler_duration_ns']['count']}",
        f"- Outbound offered/completed/dropped: {outbound['offered']} / "
        f"{outbound['completed']} / {outbound['dropped']}",
        "",
        "Percentiles use deterministic linear interpolation at rank `(n-1)*p/100`.",
        "",
        "This is observational measurement. Local socket completion is not remote receipt.",
        "Peer response receipt, true peer RTT, and remote processing are `not_observable`.",
        "",
    ])


def write_atomic(path, content):
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8") as output:
        output.write(content)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)


def run_self_tests():
    assert percentile([], 50) is None
    assert percentile([1], 99) == 1
    assert percentile([0, 10], 50) == 5
    assert percentile([0, 10, 20], 95) == 19
    rpc = [
        {"monotonic_ns": 10, "chain": {"initialblockdownload": True}},
        {"monotonic_ns": 20, "chain": {"initialblockdownload": False}},
        {"monotonic_ns": 30, "chain": {"initialblockdownload": False}},
    ]
    join = prepare_rpc_states(rpc, 100)
    assert join(15)[0] == "ibd"
    assert join(25)[0] == "transition"
    assert join(35)[0] == "post_ibd"
    assert join(9)[0] == "unclassified"
    assert distribution([0, 10])["p95"] == 9.5

    names = {
        1: "complete_message_ready", 2: "handler_start",
        3: "handler_complete", 4: "response_queued", 5: "job_submit",
        6: "slot_submit", 7: "worker_wake",
        8: "pnb_start", 9: "pnb_end", 10: "result_publication",
        11: "busy_send_prefix_summary",
        12: "result_collection", 13: "continuation",
        21: "message_front_ready", 22: "receive_queue_state",
        23: "outbound_queued", 24: "socket_sent",
        25: "outbound_dropped", 26: "causal_link",
        29: "peer_finalized", 31: "send_queue_state",
        32: "block_requested", 33: "block_request_removed",
    }
    epoch = 77

    def add(events, code, steady_ns, values=(), *, text1=None, text2=None,
            block_id=None):
        item = {
            "sequence": len(events) + 1,
            "process_epoch": epoch,
            "event": names[code],
            "event_code": code,
            "steady_ns": steady_ns,
            "values": list(values) + [0] * (16 - len(values)),
        }
        if text1 is not None:
            item["text1"] = text1
        if text2 is not None:
            item["text2"] = text2
        if block_id is not None:
            item["block_id"] = block_id
        events.append(item)
        return item

    def renumber(items):
        for sequence, item in enumerate(items, 1):
            item["sequence"] = sequence

    def fixture_fact(value, rows, *, lines=None):
        encoded = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        return {"bytes": len(encoded), "data_rows": rows,
                "lines": rows if lines is None else lines,
                "sha256": hashlib.sha256(encoded).hexdigest()}

    def fixture_artifacts(events, resources, rpc_rows, summary):
        return {
            "events.jsonl": fixture_fact(events, len(events)),
            "resources.csv": fixture_fact(
                resources, len(resources), lines=len(resources) + 1),
            "rpc.jsonl": fixture_fact(rpc_rows, len(rpc_rows)),
            "summary.json": fixture_fact(summary, 1, lines=1),
        }

    def collector_metadata(events, mode="candidate", *, resources=(), rpc_rows=(),
                           start_mono=None, end_mono=None, pre_attach_count=0):
        probe_steady = 1
        wall_offset = 1_000_000_000_000
        probe_wall = probe_steady + wall_offset
        start_mono = (min((item["steady_ns"] for item in events), default=1)
                      if start_mono is None else start_mono)
        end_mono = (max((item["steady_ns"] for item in events), default=start_mono + 1)
                    if end_mono is None else end_mono)
        assert 0 <= pre_attach_count <= len(events) and end_mono > start_mono > 0
        start_boundary = {
            "producer_sequence": pre_attach_count,
            "collector_monotonic_before_ns": start_mono,
            "collector_monotonic_after_ns": start_mono,
            "collector_monotonic_midpoint_ns": start_mono,
            "collector_wall_before_ns": start_mono + wall_offset,
            "collector_wall_after_ns": start_mono + wall_offset,
            "collector_wall_midpoint_ns": start_mono + wall_offset,
            "capture_uncertainty_ns": 0,
        }
        end_boundary = {
            "producer_sequence": len(events),
            "collector_monotonic_before_ns": end_mono,
            "collector_monotonic_after_ns": end_mono,
            "collector_monotonic_midpoint_ns": end_mono,
            "collector_wall_before_ns": end_mono + wall_offset,
            "collector_wall_after_ns": end_mono + wall_offset,
            "collector_wall_midpoint_ns": end_mono + wall_offset,
            "capture_uncertainty_ns": 0,
        }
        mapping = {
            "probe_creation_wall_ns": probe_wall,
            "probe_creation_steady_ns": probe_steady,
            "collector_wall_ns": start_mono + wall_offset,
            "collector_monotonic_ns": start_mono,
            "probe_wall_minus_steady_ns": wall_offset,
            "collector_wall_minus_monotonic_ns": wall_offset,
            "steady_to_collector_monotonic_offset_ns": 0,
            "steady_to_wall_offset_ns": wall_offset,
            "origin_residual_ns": 0,
            "capture_uncertainty_ns": 0,
            "mapping_uncertainty_ns": 0,
            "compatibility": "wall_offset_bridge_with_reported_uncertainty",
            "method": "wall-offset bridge; residual may include pre-attach wall correction; no affine/drift claim",
            "collection_wall_minus_monotonic_drift_ns": 0,
            "cutoff_capture_uncertainty_ns": 0,
        }
        cutoff_mapping = {
            **{key: value for key, value in mapping.items()
               if key not in ("cutoff_capture_uncertainty_ns", "mapping_uncertainty_ns")},
            "collector_wall_ns": end_mono + wall_offset,
            "collector_monotonic_ns": end_mono,
            "capture_uncertainty_ns": 0,
            "mapping_uncertainty_ns": 0,
        }
        for item in events:
            item["mapped_monotonic_ns"] = item["steady_ns"]
            item["mapped_wall_ns"] = item["steady_ns"] + wall_offset
            item["collection_scope"] = (
                "pre_attach_backlog" if item["sequence"] <= pre_attach_count
                else "measured")
        measured_times = [item["steady_ns"] for item in events
                          if item["collection_scope"] == "measured"]
        scope_counts = dict(sorted(Counter(
            item["collection_scope"] for item in events).items()))
        window = {
            "sequence_first": pre_attach_count + 1,
            "sequence_last": len(events),
            "pre_attach_sequence_last": pre_attach_count,
            "start": start_boundary,
            "end": end_boundary,
            "duration_ns": end_mono - start_mono,
            "duration_source": "collector_python_monotonic_midpoints",
            "pre_attach_backlog_event_count": pre_attach_count,
            "measured_event_count": len(events) - pre_attach_count,
            "measured_event_mapped_monotonic_bounds_ns": (
                [min(measured_times), max(measured_times)] if measured_times
                else [None, None]),
        }
        counts = dict(sorted(Counter(item["event"] for item in events).items()))
        first = events[0]["sequence"] if events else None
        last = events[-1]["sequence"] if events else None
        bounds = [
            min((item["steady_ns"] for item in events), default=None),
            max((item["steady_ns"] for item in events), default=None),
        ]
        resource_mono = [min((row["monotonic_ns"] for row in resources), default=None),
                         max((row["monotonic_ns"] for row in resources), default=None)]
        resource_wall = [min((row["wall_ns"] for row in resources), default=None),
                         max((row["wall_ns"] for row in resources), default=None)]
        rpc_mono = [min((row["monotonic_ns"] for row in rpc_rows), default=None),
                    max((row["monotonic_ns"] for row in rpc_rows), default=None)]
        rpc_wall = [min((row["wall_ns"] for row in rpc_rows), default=None),
                    max((row["wall_ns"] for row in rpc_rows), default=None)]
        preliminary_artifacts = {
            "events.jsonl": fixture_fact(events, len(events)),
            "resources.csv": fixture_fact(
                resources, len(resources), lines=len(resources) + 1),
            "rpc.jsonl": fixture_fact(rpc_rows, len(rpc_rows)),
        }
        summary = {
            "complete": True,
            "valid": True,
            "stop_reason": "duration_complete",
            "process_exit_state": "running_at_collection_end",
            "process_epoch": epoch,
            "event_counts": counts,
            "event_scope_counts": scope_counts,
            "event_count": len(events),
            "event_sequence_first": first,
            "event_sequence_last": last,
            "event_sequence_read_last": last,
            "event_sequence_durable_last": last,
            "collection_cutoff_sequence": last or 0,
            "producer_sequence_observed": last or 0,
            "probe_status": 0,
            "collection_window": window,
            "clock_mapping": mapping,
            "cutoff_clock_mapping": cutoff_mapping,
            "consumer_ack": last or 0,
            "loss_count": 0,
            "checksum_failures": 0,
            "unstable_read_failures": 0,
            "sequence_failures": 0,
            "integrity_errors": [],
            "event_steady_bounds_ns": bounds,
            "resource_samples": len(resources),
            "resource_monotonic_bounds_ns": resource_mono,
            "resource_wall_bounds_ns": resource_wall,
            "rpc_rows": len(rpc_rows),
            "rpc_samples": sum("error" not in row for row in rpc_rows),
            "rpc_failures": sum("error" in row for row in rpc_rows),
            "rpc_monotonic_bounds_ns": rpc_mono,
            "rpc_wall_bounds_ns": rpc_wall,
            "artifact_integrity": preliminary_artifacts,
        }
        artifacts = fixture_artifacts(events, resources, rpc_rows, summary)
        manifest = {
            "collector_schema": 1,
            "probe_schema": 4,
            "mode": mode,
            "expected_chain": "regtest",
            "clock_origin": {"monotonic_ns": start_mono,
                             "wall_ns": start_mono + wall_offset},
            "end_clock": {"monotonic_ns": end_mono,
                           "wall_ns": end_mono + wall_offset},
            "clock_mapping": mapping,
            "cutoff_clock_mapping": cutoff_mapping,
            "collection_window": window,
            "artifacts": artifacts,
            "complete": True,
            "valid": True,
            "stop_reason": "duration_complete",
            "process_epochs": [epoch],
            "event_stream": {
                "process_epoch": epoch,
                "count": len(events),
                "sequence_first": first,
                "sequence_last": last,
                "durable_sequence": last or 0,
                "event_counts": counts,
            },
        }
        return manifest, summary, artifacts

    rpc_fixture = [{
        "monotonic_ns": 100_000_000,
        "wall_ns": 1_000_100_000_000,
        "chain": {"chain": "regtest", "blocks": 100, "headers": 100,
                  "initialblockdownload": False},
        "warnings_present": False,
        "network_totals": {"totalbytesrecv": 0, "totalbytessent": 0,
                           "timemillis": 0},
        "network": {"networkactive": True, "connections": 0,
                    "connections_in": 0, "connections_out": 0},
        "peers": [],
    }]

    def fixture_report(events, mode="candidate", mutate_metadata=None, *,
                       resources=(), rpc_rows=None, mutate_rows=None,
                       start_mono=None, end_mono=None, pre_attach_count=0):
        cloned = json.loads(json.dumps(events))
        cloned_resources = json.loads(json.dumps(resources))
        cloned_rpc = json.loads(json.dumps(
            rpc_fixture if rpc_rows is None else rpc_rows))
        manifest, summary, artifacts = collector_metadata(
            cloned, mode, resources=cloned_resources, rpc_rows=cloned_rpc,
            start_mono=start_mono, end_mono=end_mono,
            pre_attach_count=pre_attach_count)
        if mutate_metadata:
            mutate_metadata(manifest, summary)
        if mutate_rows:
            mutate_rows(cloned, cloned_resources, cloned_rpc)
        artifacts = fixture_artifacts(
            cloned, cloned_resources, cloned_rpc, summary)
        return analyze(
            manifest, summary, cloned, cloned_resources, cloned_rpc,
            30.0, artifacts)

    valid = []
    add(valid, 1, 100_000_000, [7, 101, 10, 34], text1="ping")
    add(valid, 21, 110_000_000, [7, 101, 10, 1, 0], text1="ping")
    add(valid, 1, 120_000_000, [8, 103, 10, 34], text1="getdata")
    add(valid, 21, 130_000_000, [8, 103, 10, 1, 0], text1="getdata")
    add(valid, 22, 200_000_000, [90, 50, 1, 1, 1])
    # A socket-side send mutation uses the documented zero ID sentinel.
    add(valid, 31, 210_000_000, [91, 40, 1, 1, 2, 0])
    add(valid, 32, 220_000_000, [7, 100, 1], block_id="b000002")
    add(valid, 29, 300_000_000, [90, 0, 1, 1])
    add(valid, 29, 310_000_000, [91, 0, 1, 1])
    add(valid, 33, 320_000_000, [7, 100, 0, 0], block_id="b000002")
    add(valid, 32, 400_000_000, [7, 100, 1], block_id="b000002")
    add(valid, 33, 500_000_000, [7, 100, 1, 0], block_id="b000002")
    add(valid, 5, 600_000_000, [1, 7, 1, 1, 0, 100, 0, 0],
        text1="standard", block_id="b000001")
    add(valid, 6, 610_000_000, [1, 7, 0, 1],
        text1="accepted", block_id="b000001")
    add(valid, 7, 620_000_000, [1, 1, 7, 1], block_id="b000001")
    add(valid, 23, 700_000_000, [7, 203, 0, 8, 8, 1, 0], text1="ping")
    add(valid, 8, 1_000_000_000, [1, 1, 7, 1, 0, 100], block_id="b000001")
    add(valid, 2, 1_100_000_000, [8, 103], text1="getdata")
    add(valid, 3, 1_110_000_000, [8, 103, 0], text1="getdata")
    add(valid, 2, 1_120_000_000, [7, 101], text1="ping")
    add(valid, 3, 1_130_000_000, [7, 101, 0], text1="ping")
    add(valid, 23, 1_200_000_000, [7, 201, 101, 1000, 1000, 1, 0],
        text1="pong")
    add(valid, 4, 1_210_000_000,
        [7, 101, 0, 1000, 1000, 1, 0, 1, 1, 201],
        text1="ping", text2="pong")
    add(valid, 23, 1_300_000_000, [8, 202, 0, 2000, 2000, 1, 0],
        text1="block")
    add(valid, 26, 1_310_000_000, [8, 103, 202])
    add(valid, 24, 1_500_000_000,
        [8, 202, 0, 1_400_000_000, 1_500_000_000, 2050, 2050],
        text1="block")
    add(valid, 24, 1_600_000_000,
        [7, 203, 0, 1_550_000_000, 1_600_000_000, 32, 32],
        text1="ping")
    add(valid, 9, 2_000_000_000, [1, 1_000_000_000, 1, 1, 1, 7, 1],
        block_id="b000001")
    add(valid, 10, 2_010_000_000, [1, 1, 1, 1], block_id="b000001")
    add(valid, 11, 2_015_000_000, [1, 7, 0, 0, 0, -1, 0, 0, 1],
        block_id="b000001")
    add(valid, 12, 2_020_000_000, [1, 7, 1, 1, 1, 1],
        text1="standard", block_id="b000001")
    add(valid, 13, 2_030_000_000, [1, 7, 1, 1, 1],
        text1="standard", block_id="b000001")
    # This response was queued during PNB but completed after its interval.
    add(valid, 24, 2_100_000_000,
        [7, 201, 101, 2_050_000_000, 2_100_000_000, 1040, 1040],
        text1="pong")

    report = fixture_report(valid)
    assert report["integrity"]["valid"], report["integrity"]["analysis_errors"]
    assert report["pnb"]["count"] == 1
    assert report["pnb"]["jobs"][0]["ordered_complete"]
    assert report["pnb"]["jobs"][0]["submission_ibd"] is False
    assert report["pnb"]["jobs"][0]["submission_active_height"] == 100
    assert report["pnb"]["during_pnb_counts"]["response_queued"] == 2
    assert report["pnb"]["during_pnb_counts"]["socket_sent"] == 2
    assert report["pnb"]["during_pnb_counts"]["correlated_socket_sent"] == 1
    assert report["pnb"]["during_pnb_counts"]["handler_start_source_peer"] == 1
    assert report["pnb"]["during_pnb_counts"]["handler_start_unrelated_peer"] == 1
    assert report["pnb"]["during_pnb_counts"]["response_queued_source_peer"] == 1
    assert report["pnb"]["during_pnb_counts"]["response_queued_unrelated_peer"] == 1
    assert report["pnb"]["during_pnb_counts"]["useful_correlated_completed_responses"] == 2
    assert report["pnb"]["during_pnb_counts"]["outbound_payload_bytes"] == 3000
    assert report["pnb"]["during_pnb_counts"]["outbound_wire_bytes"] == 3090
    assert report["service_throughput"][
        "useful_correlated_completed_responses_per_pnb_second"] == 2
    assert report["service_throughput"]["outbound_payload_bytes_per_pnb_second"] == 3000
    assert report["service_throughput"]["outbound_wire_bytes_per_pnb_second"] == 3090
    assert report["service_throughput"][
        "useful_correlated_completed_responses_per_wall_second"] == 1
    assert report["inbound"]["complete_ready_to_response_queued_ns"]["count"] == 2
    assert report["inbound"]["front_ready_to_response_queued_ns"]["count"] == 2
    assert report["outbound"]["queue_to_last_write_ns"]["count"] == 3
    assert report["breakdowns"]["process_epoch"][str(epoch)][
        "response_queued_count"] == 2
    for message_type in ("ping", "getdata"):
        message = report["breakdowns"]["message_type"][message_type]
        assert message["queue_to_front_ns"]["count"] == 1
        assert message["front_to_handler_ns"]["count"] == 1
        assert message["complete_ready_to_response_queued_ns"]["count"] == 1
        assert message["front_ready_to_response_queued_ns"]["count"] == 1
        assert message["response_queued_count"] == 1
        assert message["socket_complete_count"] == 1
        assert message["outbound_drop_count"] == 0
        assert message["outbound_incomplete_count"] == 0
        assert message["queue_to_first_write_ns"]["count"] == 1
        assert message["queue_to_last_write_ns"]["count"] == 1
    route = report["breakdowns"]["pnb_delivery_route"]["full-block"]
    assert route["response_queued_count"] == 2
    assert route["socket_complete_count"] == 2
    assert route["queue_to_last_write_ns"]["count"] == 2
    assert route["pnb_source_relationship"] == {
        "completed_source_peer": 1,
        "completed_unrelated_peer": 1,
        "handler_start_source_peer": 1,
        "handler_start_unrelated_peer": 1,
        "response_queued_source_peer": 1,
        "response_queued_unrelated_peer": 1,
    }
    anchored = json.loads(json.dumps(valid))
    annotate(anchored, rpc_fixture, 30.0)
    for event in anchored:
        if (event["event_code"] in (1, 2, 3, 21) and
                event["values"][:2] == [7, 101]) or (
                event["event_code"] in (4, 23, 24) and
                event["values"][0] == 7 and
                (event["values"][1] == 101 or event["values"][1] == 201)):
            event["_phase"] = "transition"
    next(event for event in anchored
         if event["event_code"] == 1 and event["values"][:2] == [7, 101]
         )["_phase"] = "ibd"
    ibd_subset = subset_summary(
        [event for event in anchored if event["_phase"] == "ibd"], anchored,
        observation_seconds=2.0)
    transition_subset = subset_summary(
        [event for event in anchored if event["_phase"] == "transition"], anchored,
        observation_seconds=2.0)
    assert ibd_subset["complete_ready_count"] == 1
    assert ibd_subset["response_queued_count"] == 1
    assert transition_subset["complete_ready_count"] == 0
    assert transition_subset["response_queued_count"] == 0
    assert report["block_download"]["completed_removals"] == 1
    assert report["block_download"]["noncompletion_removals"] == 1
    assert report["block_download"]["requests_open_at_collection_boundary"] == 0
    assert report["queues"]["receive"]["byte_depth_area_byte_ns"] == 5_000_000_000
    assert report["queues"]["receive"]["pause_duration_ns"] == 100_000_000
    assert report["queues"]["receive"]["open_pause_intervals_at_epoch_end"] == 0
    assert report["queues"]["send"]["byte_depth_area_byte_ns"] == 4_000_000_000

    # Both complete control and complete async lifecycles are accepted, while
    # only a submit-starting contiguous prefix is a boundary truncation.
    control = []
    add(control, 5, 1, [2, 9, 0, 2], text1="optimistic_compact", block_id="b3")
    add(control, 8, 2, [2, 0, 9, 2], block_id="b3")
    add(control, 9, 3, [2, 1, 1, 0, 0, 9, 2], block_id="b3")
    add(control, 13, 4, [2, 9, 1, 0, 1],
        text1="optimistic_compact", block_id="b3")
    errors = []
    control_jobs = build_pnb_jobs(control, errors)
    assert not errors and control_jobs[0]["ordered_complete"]
    assert control_jobs[0]["mode"] == "control"
    bad_labels = json.loads(json.dumps(control))
    bad_labels[1]["values"][4] = 1
    bad_labels[2]["values"][1] = 2
    errors = []
    assert not build_pnb_jobs(bad_labels, errors)[0]["labels_reconciled"]
    assert any("IBD/height" in error for error in errors)
    assert any("duration mismatch" in error for error in errors)

    prefix = []
    add(prefix, 5, 1, [3, 9, 1, 1], text1="standard", block_id="b4")
    add(prefix, 6, 2, [3, 9, 0, 1], text1="accepted", block_id="b4")
    add(prefix, 7, 3, [3, 1, 9, 1], block_id="b4")
    add(prefix, 8, 4, [3, 1, 9, 1], block_id="b4")
    errors = []
    prefix_job = build_pnb_jobs(prefix, errors)[0]
    assert not errors and prefix_job["incomplete_at_collection_boundary"]

    # The single slot cannot accept a later job until the prior lifecycle has
    # reached collection/continuation, so later job activity disproves an
    # earlier apparent cutoff prefix.
    followed_prefix = json.loads(json.dumps(prefix))
    add(followed_prefix, 5, 5, [4, 9, 1, 1, 0, 100, 0, 0],
        text1="standard", block_id="b5")
    add(followed_prefix, 6, 6, [4, 9, 0, 1],
        text1="accepted", block_id="b5")
    add(followed_prefix, 7, 7, [4, 1, 9, 1], block_id="b5")
    add(followed_prefix, 8, 8, [4, 1, 9, 1, 0, 100], block_id="b5")
    add(followed_prefix, 9, 9, [4, 1, 1, 0, 1, 9, 1], block_id="b5")
    add(followed_prefix, 10, 10, [4, 1, 0, 1], block_id="b5")
    add(followed_prefix, 11, 11, [4, 9, 0, 0, 0, -1, 0, 0, 1],
        block_id="b5")
    add(followed_prefix, 12, 12, [4, 9, 1, 0, 1, 1],
        text1="standard", block_id="b5")
    add(followed_prefix, 13, 13, [4, 9, 1, 0, 1],
        text1="standard", block_id="b5")
    errors = []
    followed_jobs = build_pnb_jobs(followed_prefix, errors)
    assert errors
    assert any("precedes later PNB event" in error for error in errors)
    assert not next(job for job in followed_jobs if job["job_id"] == 3)[
        "incomplete_at_collection_boundary"]
    suffix = []
    add(suffix, 8, 1, [4, 1, 9, 1], block_id="b5")
    add(suffix, 9, 2, [4, 1, 1, 1, 1, 9, 1], block_id="b5")
    add(suffix, 10, 3, [4, 1, 1, 1], block_id="b5")
    add(suffix, 12, 4, [4, 9, 1, 1, 1], text1="standard", block_id="b5")
    add(suffix, 13, 5, [4, 9, 1, 1, 1], text1="standard", block_id="b5")
    errors = []
    suffix_job = build_pnb_jobs(suffix, errors)[0]
    assert errors and not suffix_job["incomplete_at_collection_boundary"]

    tampered = fixture_report(
        valid, mutate_metadata=lambda _manifest, summary:
        summary.__setitem__("event_count", summary["event_count"] + 1))
    assert not tampered["integrity"]["valid"]
    assert any("event_count mismatch" in error
               for error in tampered["integrity"]["analysis_errors"])
    wrong_mode = fixture_report(valid, mode="control")
    assert not wrong_mode["integrity"]["valid"]
    assert any("manifest/job mode mismatch" in error
               for error in wrong_mode["integrity"]["analysis_errors"])

    nonce = json.loads(json.dumps(valid))
    next(item for item in nonce if item["event_code"] == 4)["values"][2] = 42
    nonce_report = fixture_report(nonce)
    assert any("reserved field is nonzero" in error
               for error in nonce_report["integrity"]["analysis_errors"])

    legacy_bad = json.loads(json.dumps(valid))
    legacy = next(item for item in legacy_bad if item["event_code"] == 4)
    legacy["text1"] = "wrong-request"
    legacy["text2"] = "wrong-response"
    legacy["values"][3] += 1
    legacy["values"][4] += 1
    legacy_report = fixture_report(legacy_bad)
    legacy_errors = legacy_report["integrity"]["analysis_errors"]
    for expected in ("request type mismatch", "response type mismatch",
                     "payload mismatch", "queue snapshot mismatch"):
        assert any(expected in error for error in legacy_errors), expected

    zero_outbound = json.loads(json.dumps(valid))
    add(zero_outbound, 23, 2_200_000_000, [7, 0, 0, 1, 1, 1, 0],
        text1="ping")
    zero_report = fixture_report(zero_outbound)
    assert any("zero outbound ID" in error
               for error in zero_report["integrity"]["analysis_errors"])

    duplicates = json.loads(json.dumps(valid))
    original_outbound = next(item for item in duplicates
                             if item["event_code"] == 23 and item["values"][1] == 201)
    original_socket = next(item for item in duplicates
                           if item["event_code"] == 24 and item["values"][1] == 202)
    original_causal = next(item for item in duplicates if item["event_code"] == 26)
    for original in (original_outbound, original_socket, original_causal):
        copy = json.loads(json.dumps(original))
        copy["sequence"] = len(duplicates) + 1
        copy["steady_ns"] = 2_200_000_000 + len(duplicates)
        duplicates.append(copy)
    add(duplicates, 25, 2_300_000_000, [7, 201, 101, 1], text1="pong")
    add(duplicates, 25, 2_300_000_001, [7, 201, 101, 1], text1="pong")
    duplicate_report = fixture_report(duplicates)
    duplicate_errors = duplicate_report["integrity"]["analysis_errors"]
    for expected in ("duplicate outbound key", "duplicate socket key",
                     "duplicate causal key", "duplicate drop key",
                     "both socket completion and drop"):
        assert any(expected in error for error in duplicate_errors), expected

    malformed = json.loads(json.dumps(valid))
    bad_socket = next(item for item in malformed
                      if item["event_code"] == 24 and item["values"][1] == 202)
    bad_socket["values"][2] = 999
    bad_socket["values"][6] -= 1
    bad_socket["text1"] = "wrong"
    add(malformed, 2, 2_200_000_000, [66, 999], text1="ping")
    add(malformed, 23, 2_210_000_000, [66, 204, 0, 1, 1, 1, 0], text1="ping")
    add(malformed, 25, 2_220_000_000, [66, 204, 9, 1], text1="pong")
    malformed_report = fixture_report(malformed)
    malformed_errors = malformed_report["integrity"]["analysis_errors"]
    for expected in ("orphan message start", "socket causal ID mismatch",
                     "socket message type mismatch", "socket completed byte count mismatch",
                     "drop causal ID mismatch", "drop message type mismatch"):
        assert any(expected in error for error in malformed_errors), expected

    # HANDLER_START/COMPLETE is globally serialized by g_msgproc within an
    # epoch. A later start proves an omitted earlier completion was internal.
    missing_handler_end = json.loads(json.dumps(valid))
    missing_handler_end.remove(next(
        item for item in missing_handler_end
        if item["event_code"] == 3 and item["values"][:2] == [8, 103]))
    renumber(missing_handler_end)
    missing_handler_report = fixture_report(missing_handler_end)
    assert any("incomplete handler precedes later handler start" in error
               for error in missing_handler_report["integrity"]["analysis_errors"])

    # A front message may be discarded when its peer finalizes without ever
    # entering the handler; an in-flight handler may be the final collected
    # lifecycle prefix.
    finalized_queued = []
    add(finalized_queued, 1, 100_000_000, [40, 1, 10, 34], text1="ping")
    add(finalized_queued, 21, 101_000_000, [40, 1, 10, 1, 0], text1="ping")
    add(finalized_queued, 29, 102_000_000, [40, 0, 1, 1])
    finalized_queued_report = fixture_report(finalized_queued)
    assert finalized_queued_report["integrity"]["valid"], finalized_queued_report[
        "integrity"]["analysis_errors"]
    inflight_cutoff = []
    add(inflight_cutoff, 1, 100_000_000, [41, 1, 10, 34], text1="ping")
    add(inflight_cutoff, 21, 101_000_000, [41, 1, 10, 1, 0], text1="ping")
    add(inflight_cutoff, 22, 102_000_000, [41, 0, 0, 0, 2, 1])
    add(inflight_cutoff, 2, 103_000_000, [41, 1], text1="ping")
    inflight_cutoff_report = fixture_report(inflight_cutoff)
    assert inflight_cutoff_report["integrity"]["valid"], inflight_cutoff_report[
        "integrity"]["analysis_errors"]
    finalized_inflight = json.loads(json.dumps(inflight_cutoff))
    add(finalized_inflight, 29, 104_000_000, [41, 0, 1, 1])
    assert any("incomplete handler precedes peer finalization" in error
               for error in fixture_report(finalized_inflight)["integrity"][
                   "analysis_errors"])

    # Queue mutation IDs use exact producer-defined reasons and joins.
    queue_joins = []
    add(queue_joins, 1, 100_000_000, [50, 501, 10, 34], text1="ping")
    add(queue_joins, 21, 101_000_000, [50, 501, 10, 1, 0], text1="ping")
    add(queue_joins, 22, 102_000_000, [50, 10, 1, 0, 1, 0])
    add(queue_joins, 22, 103_000_000, [50, 0, 0, 0, 2, 501])
    add(queue_joins, 23, 120_000_000, [50, 601, 0, 10, 10, 1, 0], text1="pong")
    add(queue_joins, 31, 120_000_000, [50, 10, 1, 0, 1, 601])
    add(queue_joins, 31, 121_000_000, [50, 0, 0, 0, 2, 0])
    queue_joins_report = fixture_report(queue_joins)
    assert queue_joins_report["integrity"]["valid"], queue_joins_report[
        "integrity"]["analysis_errors"]

    queue_mutations = (
        (22, 1, 5, 501, "receive-append mutation has nonzero ID"),
        (22, 2, 5, 0, "zero receive-pop causal ID"),
        (22, 2, 5, 999, "receive-pop mutation without inbound lifecycle"),
        (31, 1, 5, 0, "zero send-enqueue outbound ID"),
        (31, 1, 5, 999, "send-enqueue mutation without outbound lifecycle"),
        (31, 2, 5, 601, "non-enqueue send mutation has nonzero ID"),
    )
    for code, reason, index, mutation_id, expected in queue_mutations:
        mutated = json.loads(json.dumps(queue_joins))
        target = next(item for item in mutated
                      if item["event_code"] == code and item["values"][4] == reason)
        target["values"][index] = mutation_id
        assert any(expected in error for error in
                   fixture_report(mutated)["integrity"]["analysis_errors"]), expected
    for code, reason, expected in (
            (22, 2, "duplicate receive-pop join"),
            (31, 1, "duplicate send-enqueue join")):
        duplicated = json.loads(json.dumps(queue_joins))
        original = next(item for item in duplicated
                        if item["event_code"] == code and item["values"][4] == reason)
        duplicated.insert(duplicated.index(original) + 1,
                          json.loads(json.dumps(original)))
        renumber(duplicated)
        assert any(expected in error for error in
                   fixture_report(duplicated)["integrity"]["analysis_errors"]), expected
    impossible_send_join = json.loads(json.dumps(queue_joins))
    next(item for item in impossible_send_join
         if item["event_code"] == 31 and item["values"][4] == 1)["steady_ns"] += 1
    assert any("impossible send-enqueue lifecycle join" in error for error in
               fixture_report(impossible_send_join)["integrity"]["analysis_errors"])

    overlap = json.loads(json.dumps(valid))
    add(overlap, 5, 1_400_000_000, [5, 7, 1, 1],
        text1="standard", block_id="b6")
    add(overlap, 6, 1_405_000_000, [5, 7, 0, 1],
        text1="accepted", block_id="b6")
    add(overlap, 7, 1_408_000_000, [5, 1, 7, 1], block_id="b6")
    add(overlap, 8, 1_410_000_000, [5, 1, 7, 1], block_id="b6")
    add(overlap, 9, 1_800_000_000, [5, 390_000_000, 1, 1, 1, 7, 1], block_id="b6")
    add(overlap, 10, 1_810_000_000, [5, 1, 1, 1], block_id="b6")
    add(overlap, 11, 1_815_000_000, [5, 7, 0, 0, 0, -1, 0, 0, 1],
        block_id="b6")
    add(overlap, 12, 1_820_000_000, [5, 7, 1, 1, 1],
        text1="standard", block_id="b6")
    add(overlap, 13, 1_830_000_000, [5, 7, 1, 1, 1],
        text1="standard", block_id="b6")
    overlap_report = fixture_report(overlap)
    assert any("overlapping PNB intervals" in error
               for error in overlap_report["integrity"]["analysis_errors"])

    # Async lifecycle validation includes every producer stage. These cases
    # specifically fail logic that only knew submit/start/end/publication/
    # collection/continuation.
    for missing_code in (5, 6, 7, 8, 9, 10, 11, 12):
        missing = json.loads(json.dumps(valid))
        missing.remove(next(item for item in missing if item["event_code"] == missing_code))
        renumber(missing)
        missing_report = fixture_report(missing)
        assert not missing_report["integrity"]["valid"], missing_code
        assert any("PNB" in error for error in
                   missing_report["integrity"]["analysis_errors"]), missing_code
    missing_continuation = json.loads(json.dumps(valid))
    missing_continuation.remove(next(
        item for item in missing_continuation if item["event_code"] == 13))
    renumber(missing_continuation)
    continuation_report = fixture_report(missing_continuation)
    assert continuation_report["integrity"]["valid"]
    assert continuation_report["pnb"]["incomplete_at_collection_boundary"] == 1

    for duplicate_code in range(5, 14):
        duplicate = json.loads(json.dumps(valid))
        original = next(item for item in duplicate
                        if item["event_code"] == duplicate_code)
        index = duplicate.index(original)
        duplicate.insert(index + 1, json.loads(json.dumps(original)))
        renumber(duplicate)
        duplicate_report = fixture_report(duplicate)
        assert any("duplicate PNB" in error for error in
                   duplicate_report["integrity"]["analysis_errors"]), duplicate_code

    reordered = json.loads(json.dumps(valid))
    first_index = next(index for index, item in enumerate(reordered)
                       if item["event_code"] == 6)
    second_index = next(index for index, item in enumerate(reordered)
                        if item["event_code"] == 7)
    reordered[first_index], reordered[second_index] = (
        reordered[second_index], reordered[first_index])
    renumber(reordered)
    reordered_report = fixture_report(reordered)
    assert any("lifecycle order" in error for error in
               reordered_report["integrity"]["analysis_errors"])

    lifecycle_corruptions = (
        (6, lambda item: (item["values"].__setitem__(2, 1),
                          item.__setitem__("text1", "full")), "submit status"),
        (7, lambda item: item["values"].__setitem__(2, 99), "source labels"),
        (7, lambda item: item["values"].__setitem__(3, 2), "route labels"),
        (10, lambda item: item["values"].__setitem__(2, 0), "result labels"),
        (11, lambda item: item["values"].__setitem__(2, 1), "busy-prefix"),
    )
    for code, mutate, expected in lifecycle_corruptions:
        corrupted = json.loads(json.dumps(valid))
        mutate(next(item for item in corrupted if item["event_code"] == code))
        corrupted_report = fixture_report(corrupted)
        assert any(expected in error for error in
                   corrupted_report["integrity"]["analysis_errors"]), (code, expected)
    blank_continuation = json.loads(json.dumps(valid))
    next(item for item in blank_continuation if item["event_code"] == 12)["text1"] = ""
    blank_report = fixture_report(blank_continuation)
    assert any("continuation label" in error for error in
               blank_report["integrity"]["analysis_errors"])
    wrong_hash = json.loads(json.dumps(valid))
    next(item for item in wrong_hash if item["event_code"] == 11)["block_id"] = "b999999"
    assert any("block labels" in error for error in
               fixture_report(wrong_hash)["integrity"]["analysis_errors"])
    cross_job = json.loads(json.dumps(valid))
    next(item for item in cross_job if item["event_code"] == 11)["values"][0] = 2
    assert not fixture_report(cross_job)["integrity"]["valid"]

    # Every mandatory join identifier fails closed at zero; RECEIVE_QUEUE_STATE
    # keeps its documented route-1 zero sentinel but route-2 pop requires an ID.
    for code in (1, 2, 3, 4, 21):
        zero = json.loads(json.dumps(valid))
        next(item for item in zero if item["event_code"] == code)["values"][1] = 0
        assert any("zero inbound causal ID" in error for error in
                   fixture_report(zero)["integrity"]["analysis_errors"]), code
    zero_pop = json.loads(json.dumps(valid))
    pop = next(item for item in zero_pop if item["event_code"] == 22)
    pop["values"][4:6] = [2, 0]
    assert any("zero receive-pop causal ID" in error for error in
               fixture_report(zero_pop)["integrity"]["analysis_errors"])
    for relation_index in (1, 2):
        zero_relation = json.loads(json.dumps(valid))
        next(item for item in zero_relation if item["event_code"] == 26
             )["values"][relation_index] = 0
        assert any("zero causal relation ID" in error for error in
                   fixture_report(zero_relation)["integrity"]["analysis_errors"])
    for code in range(5, 14):
        zero_job = json.loads(json.dumps(valid))
        next(item for item in zero_job if item["event_code"] == code)["values"][0] = 0
        assert any("zero PNB job ID" in error for error in
                   fixture_report(zero_job)["integrity"]["analysis_errors"]), code

    # Quiet boundaries, filtered rates, phase expiry, queue carry-in, and PNB
    # jobs crossing either collection edge all use the explicit global window.
    sparse = fixture_report(valid, start_mono=1, end_mono=10_000_000_001)
    assert sparse["observation"]["seconds"] == 10
    assert sparse["service_throughput"][
        "useful_correlated_completed_responses_per_wall_second"] == 0.2
    assert sparse["breakdowns"]["message_type"]["ping"][
        "observation_hours"] == 10 / 3600
    assert math.isclose(sum(sparse["rpc_join"]["phase_observation_seconds"].values()), 10)
    phase_gap = phase_observation_seconds(
        [{"monotonic_ns": 10, "chain": {"initialblockdownload": True}}],
        1, 101, 20)
    assert math.isclose(sum(phase_gap.values()), 100 / 1e9)
    assert math.isclose(phase_gap["ibd"], 20 / 1e9)
    assert math.isclose(phase_gap["unclassified"], 80 / 1e9)
    uncertain_phase_gap = phase_observation_seconds(
        [{"monotonic_ns": 10, "chain": {"initialblockdownload": True}}],
        1, 101, 20, mapping_uncertainty_ns=5)
    assert math.isclose(sum(uncertain_phase_gap.values()), 100 / 1e9)
    assert math.isclose(uncertain_phase_gap["ibd"], 10 / 1e9)
    assert math.isclose(uncertain_phase_gap["unclassified"], 90 / 1e9)
    uncertainty_events = [
        {"event_code": 30, "values": [7], "process_epoch": epoch,
         "steady_ns": 12, "mapped_monotonic_ns": 12},
        {"event_code": 30, "values": [7], "process_epoch": epoch,
         "steady_ns": 20, "mapped_monotonic_ns": 20},
        {"event_code": 30, "values": [7], "process_epoch": epoch,
         "steady_ns": 28, "mapped_monotonic_ns": 28},
    ]
    annotate(uncertainty_events,
             [{"monotonic_ns": 10,
               "chain": {"initialblockdownload": True}}],
             20 / 1e9, mapping_uncertainty_ns=5)
    assert [event["_phase"] for event in uncertainty_events] == [
        "unclassified", "ibd", "unclassified"]

    preattach = json.loads(json.dumps(valid))
    start_event = next(item for item in preattach if item["event_code"] == 8)
    preattach_report = fixture_report(
        preattach, pre_attach_count=start_event["sequence"],
        start_mono=1_050_000_000, end_mono=2_100_000_000)
    assert preattach_report["pnb"]["submitted_count"] == 0
    assert preattach_report["pnb"]["pre_attach_active_at_measured_start"] == 1
    assert preattach_report["pnb"]["busy_interval_count"] == 1
    assert preattach_report["pnb"]["time_seconds"] == 0.95
    for dimension, label in (("process_epoch", str(epoch)),
                             ("pnb_delivery_route", "full-block")):
        entry = preattach_report["breakdowns"][dimension][label]
        assert entry["pnb_count"] == 0
        assert entry["pnb_time_seconds"] == preattach_report["pnb"]["time_seconds"]

    phase_rpc = json.loads(json.dumps(rpc_fixture))
    phase_rpc[0]["chain"]["initialblockdownload"] = True
    phase_rpc.append({**json.loads(json.dumps(phase_rpc[0])),
                      "monotonic_ns": 1_500_000_000,
                      "wall_ns": 1_001_500_000_000,
                      "chain": {**phase_rpc[0]["chain"],
                                "initialblockdownload": False}})
    phase_crossing_report = fixture_report(valid, rpc_rows=phase_rpc)
    assert phase_crossing_report["integrity"]["valid"]
    phase_breakdown = phase_crossing_report["breakdowns"]["phase"]
    assert phase_breakdown["ibd"]["pnb_count"] == 1
    assert phase_breakdown["transition"]["pnb_count"] == 0
    assert phase_breakdown["ibd"]["pnb_time_seconds"] == 0.5
    assert phase_breakdown["transition"]["pnb_time_seconds"] == 0.5
    assert math.isclose(
        sum(entry["pnb_time_seconds"] for entry in phase_breakdown.values()),
        phase_crossing_report["pnb"]["time_seconds"])
    assert (sum(entry["pnb_count"] for entry in phase_breakdown.values()) ==
            phase_crossing_report["pnb"]["submitted_count"])

    active_cutoff = [item for item in json.loads(json.dumps(valid))
                     if item["event_code"] not in (9, 10, 11, 12, 13)]
    renumber(active_cutoff)
    active_report = fixture_report(active_cutoff)
    assert active_report["integrity"]["valid"]
    assert active_report["pnb"]["active_at_collection_cutoff"] == 1
    assert active_report["pnb"]["time_seconds"] == 1.1

    submit_cutoff = []
    add(submit_cutoff, 5, 100_000_000,
        [6, 70, 1, 3, 0, 100, 0, 0],
        text1="standard", block_id="b7")
    submit_cutoff_report = fixture_report(
        submit_cutoff, end_mono=101_000_000)
    assert submit_cutoff_report["integrity"]["valid"], submit_cutoff_report[
        "integrity"]["analysis_errors"]
    assert submit_cutoff_report["pnb"]["submitted_count"] == 1
    assert submit_cutoff_report["pnb"]["time_seconds"] == 0
    blocktxn_breakdown = submit_cutoff_report["breakdowns"][
        "pnb_delivery_route"]["blocktxn"]
    assert blocktxn_breakdown["pnb_count"] == 1
    assert blocktxn_breakdown["pnb_time_seconds"] == 0
    unknown_role_breakdown = submit_cutoff_report["breakdowns"][
        "connection_role"]["unknown"]
    assert unknown_role_breakdown["pnb_count"] == 1
    assert unknown_role_breakdown["pnb_time_seconds"] == 0

    tied = json.loads(json.dumps(valid))
    pnb_end = next(item for item in tied if item["event_code"] == 9)
    add(tied, 1, pnb_end["steady_ns"], [44, 444, 1, 25], text1="ping")
    add(tied, 21, pnb_end["steady_ns"], [44, 444, 1, 1, 0], text1="ping")
    add(tied, 2, pnb_end["steady_ns"], [44, 444], text1="ping")
    add(tied, 3, pnb_end["steady_ns"], [44, 444, 0], text1="ping")
    tied_report = fixture_report(tied)
    assert tied_report["pnb"]["during_pnb_counts"]["handler_start"] == 2

    queue_fixture = []
    add(queue_fixture, 22, 500_000_000, [92, 50, 1, 1, 1])
    add(queue_fixture, 29, 800_000_000, [92, 0, 1, 1])
    queue_report = fixture_report(
        queue_fixture, pre_attach_count=1,
        start_mono=600_000_000, end_mono=1_000_000_000)
    assert queue_report["queues"]["receive"]["byte_depth_area_byte_ns"] == 10_000_000_000
    assert queue_report["queues"]["receive"]["pause_duration_ns"] == 200_000_000
    assert queue_report["queues"]["receive"]["open_pause_intervals_at_epoch_end"] == 0

    resource_row = {field: 0 for field in RESOURCE_FIELDS}
    resource_row.update(monotonic_ns=200_000_000,
                        wall_ns=1_000_200_000_000,
                        rss_bytes=1024, thread_count=1)
    assert fixture_report(valid, resources=[resource_row])["integrity"]["valid"]
    deleted_resource = fixture_report(
        valid, resources=[resource_row],
        mutate_rows=lambda _events, rows, _rpc: rows.clear())
    assert any("resource" in error.lower() or "artifact" in error.lower()
               for error in deleted_resource["integrity"]["analysis_errors"])
    altered_rpc = fixture_report(
        valid, mutate_rows=lambda _events, _resources, rows:
        rows[0]["chain"].__setitem__("blocks", 101))
    assert any("artifact" in error.lower() for error in
               altered_rpc["integrity"]["analysis_errors"])
    malformed_rpc = fixture_report(
        valid, mutate_rows=lambda _events, _resources, rows:
        rows[0].__setitem__("error", "Injected"))
    assert any("failure/success shape" in error for error in
               malformed_rpc["integrity"]["analysis_errors"])
    truncated_events = fixture_report(
        valid, mutate_rows=lambda rows, _resources, _rpc: rows.pop())
    assert any("artifact" in error.lower() or "event_count" in error
               for error in truncated_events["integrity"]["analysis_errors"])

    def corrupt_clock(manifest, summary):
        summary["clock_mapping"]["steady_to_collector_monotonic_offset_ns"] += 1
        manifest["clock_mapping"]["steady_to_collector_monotonic_offset_ns"] += 1

    clock_report = fixture_report(valid, mutate_metadata=corrupt_clock)
    assert any("clock mapping" in error or "mapped monotonic" in error
               for error in clock_report["integrity"]["analysis_errors"])

    def corrupt_origin(manifest, summary):
        for metadata in (manifest, summary):
            metadata["clock_mapping"]["probe_creation_wall_ns"] = 0
            metadata["cutoff_clock_mapping"]["probe_creation_wall_ns"] = 0

    origin_report = fixture_report(valid, mutate_metadata=corrupt_origin)
    assert any("probe clock origins" in error for error in
               origin_report["integrity"]["analysis_errors"])
    artifact_report = fixture_report(
        valid, mutate_metadata=lambda _manifest, summary:
        summary["artifact_integrity"]["rpc.jsonl"].__setitem__("sha256", "0" * 64))
    assert any("artifact" in error.lower() for error in
               artifact_report["integrity"]["analysis_errors"])
    print("async_pnb_analyzer self-test: PASS")


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input")
    parser.add_argument("--output")
    parser.add_argument("--max-rpc-join-age", type=float, default=30.0)
    parser.add_argument("--allow-invalid", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return args
    if not args.input or not args.output:
        parser.error("--input and --output are required")
    if args.max_rpc_join_age <= 0:
        parser.error("--max-rpc-join-age must be positive")
    return args


def main():
    args = parse_args()
    if args.self_test:
        run_self_tests()
        return
    source = Path(args.input)
    output = Path(args.output)
    try:
        if not source.is_dir() or source.is_symlink():
            raise AnalysisError("--input must be a non-symlink collector directory")
        actual_files = {entry.name for entry in source.iterdir() if entry.is_file()}
        if actual_files != COLLECTOR_FILES:
            raise AnalysisError(
                f"collector directory file set mismatch: expected {sorted(COLLECTOR_FILES)}, "
                f"got {sorted(actual_files)}")
        if output.exists():
            raise AnalysisError("--output must not already exist")
        manifest = read_json(source / "manifest.json")
        summary = read_json(source / "summary.json")
        if not manifest.get("complete") or not summary.get("complete"):
            raise AnalysisError("collector directory is not complete")
        if not args.allow_invalid and (not manifest.get("valid") or not summary.get("valid")):
            raise AnalysisError("collector directory is invalid or lossy")
        events = read_jsonl(source / "events.jsonl")
        resources = read_resources(source / "resources.csv")
        rpc = read_jsonl(source / "rpc.jsonl")
        artifacts = {
            "events.jsonl": file_facts(source / "events.jsonl"),
            "resources.csv": file_facts(source / "resources.csv", csv_header=True),
            "rpc.jsonl": file_facts(source / "rpc.jsonl"),
            "summary.json": file_facts(source / "summary.json"),
        }
        report = analyze(
            manifest, summary, events, resources, rpc,
            args.max_rpc_join_age, artifacts)
        if not args.allow_invalid and not report["integrity"]["valid"]:
            raise AnalysisError(
                "analysis found invalid joins/order: " +
                "; ".join(report["integrity"]["analysis_errors"]))
        output.mkdir(mode=0o700)
        write_atomic(output / "analysis.json", json.dumps(
            report, indent=2, sort_keys=True) + "\n")
        write_atomic(output / "analysis.md", markdown(report))
    except AnalysisError as error:
        print(f"async_pnb_analyzer: {error}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
