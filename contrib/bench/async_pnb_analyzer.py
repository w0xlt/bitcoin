#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Analyze a completed async-PNB collector directory offline."""

import argparse
import bisect
import csv
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
            return [{key: float(value) for key, value in row.items()}
                    for row in csv.DictReader(source)]
    except (OSError, ValueError) as error:
        raise AnalysisError(f"cannot read resources.csv: {error}") from error


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


def annotate(events, rpc, max_age_seconds):
    join = prepare_rpc_states(rpc, int(max_age_seconds * 1_000_000_000))
    peer_roles = {}
    for event in events:
        if event.get("event_code") == 27 and len(event.get("values", [])) >= 2:
            peer_roles[(event["process_epoch"], event["values"][0])] = CONNECTION_ROLES.get(
                event["values"][1], f"unknown-{event['values'][1]}")
    ages = []
    for event in events:
        phase, age = join(event["steady_ns"])
        event["_phase"] = phase
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


def queue_metrics(events, code, end_ns, peer_finalizations):
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
    for peer_key, samples in by_peer.items():
        samples.sort(key=lambda event: event["steady_ns"])
        finalized_ns = peer_finalizations.get(peer_key)
        terminal_ns = min(end_ns, finalized_ns) if finalized_ns is not None else end_ns
        previous_pause = False
        for index, sample in enumerate(samples):
            values = sample["values"]
            if finalized_ns is not None and sample["steady_ns"] > finalized_ns:
                post_finalization_samples += 1
            following = (samples[index + 1]["steady_ns"]
                         if index + 1 < len(samples) else terminal_ns)
            following = min(following, terminal_ns)
            interval = max(0, following - sample["steady_ns"])
            byte_area += values[1] * interval
            depth_area += values[2] * interval
            max_bytes = max(max_bytes, values[1])
            max_depth = max(max_depth, values[2])
            paused = bool(values[3])
            if paused != previous_pause:
                pause_transitions += 1
            if paused:
                pause_ns += interval
            previous_pause = paused
        if (samples and bool(samples[-1]["values"][3]) and
                finalized_ns is None):
            open_pauses += 1
    return {
        "samples": sum(map(len, by_peer.values())),
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
    jobs = defaultdict(dict)
    for event in events:
        code = event["event_code"]
        values = event["values"]
        if code not in (5, 8, 9, 10, 12, 13) or not values:
            continue
        key = (event["process_epoch"], values[0])
        name = {5: "submit", 8: "start", 9: "end", 10: "publication",
                12: "collection", 13: "continuation"}[code]
        if name in jobs[key]:
            errors.append(f"duplicate PNB {name} for epoch/job {key}")
        jobs[key][name] = event
    result = []
    for (epoch, job_id), parts in sorted(jobs.items()):
        labels_reconciled = True
        submit = parts.get("submit")
        mode_flags = []
        for name, index in (("submit", 2), ("start", 1), ("end", 4),
                            ("publication", 3), ("collection", 4)):
            if name in parts and len(parts[name]["values"]) > index:
                raw_mode = parts[name]["values"][index]
                if raw_mode not in (0, 1):
                    errors.append(
                        f"invalid PNB mode label for epoch/job {(epoch, job_id)}")
                    labels_reconciled = False
                mode_flags.append(bool(raw_mode))
        if mode_flags and any(flag != mode_flags[0] for flag in mode_flags[1:]):
            errors.append(f"mismatched PNB mode labels for epoch/job {(epoch, job_id)}")
            labels_reconciled = False
        async_mode = bool(submit["values"][2]) if submit else (
            mode_flags[0] if mode_flags else None)
        required = (["submit", "start", "end", "publication", "collection", "continuation"]
                    if async_mode else ["submit", "start", "end", "continuation"])
        if async_mode is False and ({"publication", "collection"} & set(parts)):
            errors.append(f"control PNB has async-only stages for epoch/job {(epoch, job_id)}")
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

        block_ids = {part.get("block_id") for part in parts.values()
                     if part.get("block_id")}
        if len(block_ids) > 1:
            errors.append(f"mismatched PNB block labels for epoch/job {(epoch, job_id)}")
            labels_reconciled = False
        sources = set()
        for name, index in (("submit", 1), ("start", 2), ("end", 5),
                            ("collection", 1), ("continuation", 1)):
            if name in parts and len(parts[name]["values"]) > index:
                sources.add(parts[name]["values"][index])
        if len(sources) > 1:
            errors.append(f"mismatched PNB source labels for epoch/job {(epoch, job_id)}")
            labels_reconciled = False
        routes = set()
        for name, index in (("submit", 3), ("start", 3), ("end", 6)):
            if name in parts and len(parts[name]["values"]) > index:
                raw_route = parts[name]["values"][index]
                if raw_route not in DELIVERY_ROUTES:
                    errors.append(
                        f"invalid PNB route label for epoch/job {(epoch, job_id)}")
                    labels_reconciled = False
                routes.add(raw_route)
        if len(routes) > 1:
            errors.append(f"mismatched PNB route labels for epoch/job {(epoch, job_id)}")
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
        if len(results) > 1:
            errors.append(f"mismatched PNB result labels for epoch/job {(epoch, job_id)}")
            labels_reconciled = False
        continuations = {parts[name].get("text1") for name in
                         ("submit", "collection", "continuation")
                         if name in parts and parts[name].get("text1")}
        if len(continuations) > 1:
            errors.append(f"mismatched PNB continuation labels for epoch/job {(epoch, job_id)}")
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
        if start and submit and len(start["values"]) > 5:
            if (start["values"][4] != submit["values"][4] or
                    start["values"][5] != submit["values"][5]):
                errors.append(
                    f"mismatched PNB IBD/height labels for epoch/job {(epoch, job_id)}")
                labels_reconciled = False
        if start and end and end["values"][1] != end["steady_ns"] - start["steady_ns"]:
            errors.append(f"PNB duration mismatch for epoch/job {(epoch, job_id)}")
            labels_reconciled = False
        route = event_route(submit) if submit else None
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
            "block_id": next(iter(block_ids)) if len(block_ids) == 1 else None,
            "submit_ns": submit["steady_ns"] if submit else None,
            "start_ns": start["steady_ns"] if start else None,
            "start_sequence": start["sequence"] if start else None,
            "end_ns": end["steady_ns"] if end else None,
            "end_sequence": end["sequence"] if end else None,
            "publication_ns": parts["publication"]["steady_ns"]
                              if "publication" in parts else None,
            "collection_ns": parts["collection"]["steady_ns"]
                             if "collection" in parts else None,
            "continuation_ns": continuation["steady_ns"] if continuation else None,
            "duration_ns": end["values"][1] if end else None,
            "process_new_block": next(iter(results))[0] if len(results) == 1 else None,
            "new_block": next(iter(results))[1] if len(results) == 1 else None,
            "continuation_kind": next(iter(continuations)) if len(continuations) == 1 else None,
            "labels_reconciled": labels_reconciled,
            "ordered_complete": complete and ordered and not internal_gap and labels_reconciled,
            "incomplete_at_collection_boundary": (
                not complete and ordered and contiguous_prefix and labels_reconciled),
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


def subset_summary(events, context_events=None, *, include_interval_work=False):
    if not events:
        return {"event_count": 0, "observation_hours": 0}
    context = context_events if context_events is not None else events
    counts = Counter(event["event"] for event in events)
    span_seconds = (max(event["steady_ns"] for event in events) -
                    min(event["steady_ns"] for event in events)) / 1e9
    pnb_seconds = sum(event["values"][1] for event in events
                      if event["event_code"] == 9) / 1e9
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
        "observation_hours": span_seconds / 3600,
        "complete_ready_count": counts["complete_message_ready"],
        "exact_front_count": counts["message_front_ready"],
        "handler_start_count": counts["handler_start"],
        "handler_complete_count": counts["handler_complete"],
        "response_queued_count": len(correlated_outbound),
        "socket_complete_count": len(completed_outbound),
        "outbound_drop_count": len(dropped_outbound),
        "outbound_incomplete_count": len(incomplete_outbound),
        "pnb_count": counts["pnb_end"],
        "pnb_time_seconds": pnb_seconds,
        "pnb_wall_fraction": pnb_seconds / span_seconds if span_seconds else None,
        "pnb_jobs_per_second": counts["pnb_end"] / span_seconds if span_seconds else None,
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


def reconcile_collector(manifest, summary, events, errors):
    """Cross-check JSONL authority against both finalized metadata files."""
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


def analyze(manifest, summary, events, resources, rpc, max_join_age):
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

    if structurally_valid:
        reconcile_collector(manifest, summary, events, integrity_errors)

    join_ages = annotate(events, rpc, max_join_age)
    complete, front, starts, ends, duplicates = keyed_messages(events)
    if duplicates:
        integrity_errors.append(f"duplicate message lifecycle keys: {len(duplicates)}")
    for stage_name, stages in (("front", front), ("start", starts), ("end", ends)):
        for key in stages:
            if key not in complete:
                integrity_errors.append(
                    f"orphan message {stage_name} without complete-ready for {key}")
    for key in complete:
        present = [True, key in front, key in starts, key in ends]
        last_present = max(index for index, value in enumerate(present) if value)
        if present[:last_present + 1] != [True] * (last_present + 1):
            integrity_errors.append(f"missing internal message lifecycle stage for {key}")
    observation_start = min((event["steady_ns"] for event in events), default=0)
    observation_end = max((event["steady_ns"] for event in events), default=observation_start)
    observation_seconds = max(0, observation_end - observation_start) / 1e9

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
    for event in events:
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
        if inbound_key not in complete:
            integrity_errors.append(f"causal link without inbound message for {inbound_key}")
        for outbound_key in outbound_keys:
            if outbound_key not in outbound:
                integrity_errors.append(f"causal link without outbound offer for {outbound_key}")
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
        inbound = complete.get(inbound_key)
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

    pnb_jobs = build_pnb_jobs(events, integrity_errors)
    observed_job_modes = {job["mode"] for job in pnb_jobs}
    expected_job_mode = {"candidate": "async", "control": "control"}.get(
        manifest.get("mode"))
    if pnb_jobs and (expected_job_mode is None or
                     observed_job_modes != {expected_job_mode}):
        integrity_errors.append(
            f"PNB manifest/job mode mismatch: manifest={manifest.get('mode')!r}, "
            f"observed={sorted(observed_job_modes)!r}")
    bounded_pnb_jobs = [
        job for job in pnb_jobs
        if job["start_ns"] is not None and job["end_ns"] is not None and
        job["end_ns"] >= job["start_ns"]]
    bounded_pnb_jobs.sort(
        key=lambda job: (job["start_ns"], job["start_sequence"]))
    previous_end = None
    previous_job = None
    merged_intervals = []
    for job in bounded_pnb_jobs:
        start_position = (job["start_ns"], job["start_sequence"])
        end_position = (job["end_ns"], job["end_sequence"])
        if previous_end is not None and start_position < previous_end:
            integrity_errors.append(
                "overlapping PNB intervals for epoch/jobs "
                f"{(previous_job['process_epoch'], previous_job['job_id'])} and "
                f"{(job['process_epoch'], job['job_id'])}")
        if previous_end is None or end_position > previous_end:
            previous_end = end_position
            previous_job = job
        if merged_intervals and job["start_ns"] <= merged_intervals[-1][1]:
            merged_intervals[-1][1] = max(
                merged_intervals[-1][1], job["end_ns"])
        else:
            merged_intervals.append([job["start_ns"], job["end_ns"]])
    pnb_ns = sum(end - start for start, end in merged_intervals)

    def containing_pnb_jobs(event):
        position = (event["steady_ns"], event["sequence"])
        return [job for job in bounded_pnb_jobs
                if (job["start_ns"], job["start_sequence"]) <= position <=
                   (job["end_ns"], job["end_sequence"])]

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
    peer_finalizations = {}
    for event in finalizations:
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
    for event in events:
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
                elif reason == 1:
                    block_completion_ns.append(event["steady_ns"] - requested_ns)
                elif reason == 0:
                    block_removal_ns.append(event["steady_ns"] - requested_ns)
            else:
                unmatched_block_removals += 1
        elif event["event_code"] == 34 and event.get("block_id"):
            key = (event["process_epoch"], event["values"][0], event["block_id"])
            if block_requests[key] and event["steady_ns"] >= block_requests[key][0]:
                block_stall_ns.append(event["steady_ns"] - block_requests[key][0])

    receive_queue = queue_metrics(events, 22, observation_end, peer_finalizations)
    send_queue = queue_metrics(events, 31, observation_end, peer_finalizations)
    if receive_queue["negative_counter_samples"] or send_queue["negative_counter_samples"]:
        integrity_errors.append("negative queue counter observed")
    if (receive_queue["post_finalization_samples"] or
            send_queue["post_finalization_samples"]):
        integrity_errors.append("queue state observed after peer finalization")

    phases = ("ibd", "transition", "post_ibd", "unclassified")
    breakdowns = {
        "phase": {phase: subset_summary(
                       [event for event in events if event["_phase"] == phase], events)
                  for phase in phases},
        "message_type": {name: subset_summary(
                              [event for event in events
                               if event["_message_type"] == name], events)
                         for name in sorted({event["_message_type"] for event in events
                                             if event["_message_type"]})},
        "connection_role": {name: subset_summary(
                                 [event for event in events
                                  if event["_role"] == name], events)
                            for name in sorted({event["_role"] for event in events})},
        "pnb_delivery_route": {name: subset_summary(
                                    [event for event in events
                                     if event["_pnb_route"] == name], events,
                                    include_interval_work=True)
                               for name in sorted({job["delivery_route"]
                                                   for job in bounded_pnb_jobs
                                                   if job["delivery_route"]})},
        "process_epoch": {str(epoch): subset_summary(
                               [event for event in events
                                if event["process_epoch"] == epoch], events)
                          for epoch in sorted({event["process_epoch"] for event in events})},
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
        },
        "observation": {
            "seconds": observation_seconds,
            "hours": observation_seconds / 3600,
            "event_count": len(events),
        },
        "pnb": {
            "count": len(bounded_pnb_jobs),
            "time_seconds": pnb_seconds,
            "wall_fraction": pnb_seconds / observation_seconds if observation_seconds else None,
            "jobs_per_second": len(bounded_pnb_jobs) / observation_seconds if observation_seconds else None,
            "blocks_per_second": sum(bool(job["new_block"]) for job in pnb_jobs) /
                                 observation_seconds if observation_seconds else None,
            "process_new_block_failures": sum(
                job["process_new_block"] is False for job in pnb_jobs),
            "incomplete_at_collection_boundary": sum(
                job["incomplete_at_collection_boundary"] for job in pnb_jobs),
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
        8: "pnb_start", 9: "pnb_end", 10: "result_publication",
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

    def collector_metadata(events, mode="candidate"):
        counts = dict(sorted(Counter(item["event"] for item in events).items()))
        first = events[0]["sequence"] if events else None
        last = events[-1]["sequence"] if events else None
        bounds = [
            min((item["steady_ns"] for item in events), default=None),
            max((item["steady_ns"] for item in events), default=None),
        ]
        summary = {
            "complete": True,
            "valid": True,
            "stop_reason": "duration_complete",
            "process_exit_state": "running_at_collection_end",
            "process_epoch": epoch,
            "event_counts": counts,
            "event_count": len(events),
            "event_sequence_first": first,
            "event_sequence_last": last,
            "event_sequence_read_last": last,
            "event_sequence_durable_last": last,
            "collection_cutoff_sequence": last or 0,
            "consumer_ack": last or 0,
            "loss_count": 0,
            "checksum_failures": 0,
            "unstable_read_failures": 0,
            "sequence_failures": 0,
            "integrity_errors": [],
            "event_steady_bounds_ns": bounds,
        }
        manifest = {
            "collector_schema": 1,
            "probe_schema": 4,
            "mode": mode,
            "expected_chain": "regtest",
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
        return manifest, summary

    rpc_fixture = [{
        "monotonic_ns": 0,
        "chain": {"chain": "regtest", "initialblockdownload": False},
    }]

    def fixture_report(events, mode="candidate", mutate_metadata=None):
        cloned = json.loads(json.dumps(events))
        manifest, summary = collector_metadata(cloned, mode)
        if mutate_metadata:
            mutate_metadata(manifest, summary)
        return analyze(manifest, summary, cloned, [], rpc_fixture, 30.0)

    valid = []
    add(valid, 1, 100_000_000, [7, 101, 10, 34], text1="ping")
    add(valid, 21, 110_000_000, [7, 101, 10, 1, 0], text1="ping")
    add(valid, 1, 120_000_000, [8, 103, 10, 34], text1="getdata")
    add(valid, 21, 130_000_000, [8, 103, 10, 1, 0], text1="getdata")
    add(valid, 22, 200_000_000, [90, 50, 1, 1, 1])
    add(valid, 31, 210_000_000, [91, 40, 1, 1, 1])
    add(valid, 32, 220_000_000, [7, 100, 1], block_id="b000002")
    add(valid, 29, 300_000_000, [90, 0, 1, 1])
    add(valid, 29, 310_000_000, [91, 0, 1, 1])
    add(valid, 33, 320_000_000, [7, 100, 0, 0], block_id="b000002")
    add(valid, 32, 400_000_000, [7, 100, 1], block_id="b000002")
    add(valid, 33, 500_000_000, [7, 100, 1, 0], block_id="b000002")
    add(valid, 5, 600_000_000, [1, 7, 1, 1, 0, 100, 0, 0],
        text1="standard", block_id="b000001")
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
        [event for event in anchored if event["_phase"] == "ibd"], anchored)
    transition_subset = subset_summary(
        [event for event in anchored if event["_phase"] == "transition"], anchored)
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
    add(prefix, 8, 2, [3, 1, 9, 1], block_id="b4")
    errors = []
    prefix_job = build_pnb_jobs(prefix, errors)[0]
    assert not errors and prefix_job["incomplete_at_collection_boundary"]
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

    overlap = json.loads(json.dumps(valid))
    add(overlap, 5, 1_400_000_000, [5, 7, 1, 1],
        text1="standard", block_id="b6")
    add(overlap, 8, 1_410_000_000, [5, 1, 7, 1], block_id="b6")
    add(overlap, 9, 1_800_000_000, [5, 390_000_000, 1, 1, 1, 7, 1], block_id="b6")
    add(overlap, 10, 1_810_000_000, [5, 1, 1, 1], block_id="b6")
    add(overlap, 12, 1_820_000_000, [5, 7, 1, 1, 1],
        text1="standard", block_id="b6")
    add(overlap, 13, 1_830_000_000, [5, 7, 1, 1, 1],
        text1="standard", block_id="b6")
    overlap_report = fixture_report(overlap)
    assert any("overlapping PNB intervals" in error
               for error in overlap_report["integrity"]["analysis_errors"])
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
        report = analyze(manifest, summary, events, resources, rpc, args.max_rpc_join_age)
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
