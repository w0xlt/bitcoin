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
from collections import Counter, defaultdict
from pathlib import Path


COLLECTOR_FILES = {
    "manifest.json", "events.jsonl", "resources.csv", "rpc.jsonl", "summary.json"}
CONNECTION_ROLES = {
    0: "inbound", 1: "outbound-full-relay", 2: "manual", 3: "feeler",
    4: "block-relay-only", 5: "addr-fetch", 6: "private-broadcast"}
DELIVERY_ROUTES = {0: "unknown", 1: "full-block", 2: "compact-block", 3: "blocktxn"}
PERCENTILES = (50, 95, 99)


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


def queue_metrics(events, code, end_ns):
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
    for samples in by_peer.values():
        samples.sort(key=lambda event: event["steady_ns"])
        previous_pause = False
        for index, sample in enumerate(samples):
            values = sample["values"]
            following = samples[index + 1]["steady_ns"] if index + 1 < len(samples) else end_ns
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
        if samples and bool(samples[-1]["values"][3]):
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
    }


def interval_contains(intervals, timestamp):
    return any(start <= timestamp <= end for start, end in intervals)


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
            errors.append(f"duplicate {name} for epoch/job {key}")
        jobs[key][name] = event
    result = []
    for (epoch, job_id), parts in sorted(jobs.items()):
        submit = parts.get("submit")
        start = parts.get("start")
        end = parts.get("end")
        continuation = parts.get("continuation")
        complete = all((submit, start, end, continuation))
        ordered = complete and (
            submit["steady_ns"] <= start["steady_ns"] <= end["steady_ns"] <=
            continuation["steady_ns"])
        present_times = [
            (name, parts[name]["steady_ns"])
            for name in ("submit", "start", "end", "continuation") if name in parts]
        if any(present_times[index][1] > present_times[index + 1][1]
               for index in range(len(present_times) - 1)):
            errors.append(f"impossible PNB lifecycle order for epoch/job {(epoch, job_id)}")
        if ((start and not submit) or (end and not start) or
                (continuation and not end)):
            errors.append(f"missing PNB lifecycle prefix for epoch/job {(epoch, job_id)}")
        route = event_route(submit) if submit else None
        item = {
            "process_epoch": epoch,
            "job_id": job_id,
            "mode": ("async" if submit and submit["values"][2] else "control")
                    if submit else "unknown",
            "source_peer": submit["values"][1] if submit else None,
            "delivery_route": route,
            "phase": submit.get("_phase") if submit else "unclassified",
            "block_id": next((part.get("block_id") for part in parts.values()
                              if part.get("block_id")), None),
            "submit_ns": submit["steady_ns"] if submit else None,
            "start_ns": start["steady_ns"] if start else None,
            "end_ns": end["steady_ns"] if end else None,
            "continuation_ns": continuation["steady_ns"] if continuation else None,
            "duration_ns": end["values"][1] if end else None,
            "process_new_block": bool(end["values"][2]) if end else None,
            "new_block": bool(end["values"][3]) if end else None,
            "continuation_kind": continuation.get("text1") if continuation else None,
            "ordered_complete": ordered,
            "incomplete_at_collection_boundary": not complete,
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


def subset_summary(events):
    if not events:
        return {"event_count": 0, "observation_hours": 0}
    counts = Counter(event["event"] for event in events)
    span_seconds = (max(event["steady_ns"] for event in events) -
                    min(event["steady_ns"] for event in events)) / 1e9
    pnb_seconds = sum(event["values"][1] for event in events
                      if event["event_code"] == 9) / 1e9
    payload_bytes = sum(event["values"][2] for event in events
                        if event["event_code"] == 1)
    wire_bytes = sum(event["values"][3] for event in events
                     if event["event_code"] == 1)
    handler_durations = []
    complete, _front, start, end, _duplicates = keyed_messages(events)
    for key, started in start.items():
        if key in end and end[key]["steady_ns"] >= started["steady_ns"]:
            handler_durations.append(end[key]["steady_ns"] - started["steady_ns"])
    return {
        "event_count": len(events),
        "observation_hours": span_seconds / 3600,
        "complete_ready_count": counts["complete_message_ready"],
        "exact_front_count": counts["message_front_ready"],
        "handler_start_count": counts["handler_start"],
        "handler_complete_count": counts["handler_complete"],
        "response_queued_count": counts["response_queued"],
        "socket_complete_count": counts["socket_sent"],
        "pnb_count": counts["pnb_end"],
        "pnb_time_seconds": pnb_seconds,
        "pnb_wall_fraction": pnb_seconds / span_seconds if span_seconds else None,
        "pnb_jobs_per_second": counts["pnb_end"] / span_seconds if span_seconds else None,
        "payload_bytes": payload_bytes,
        "wire_bytes": wire_bytes,
        "handler_duration_ns": distribution(handler_durations),
    }


def analyze(manifest, summary, events, resources, rpc, max_join_age):
    integrity_errors = []
    previous = None
    for event in events:
        required = ("sequence", "process_epoch", "event", "event_code", "steady_ns", "values")
        if any(key not in event for key in required):
            integrity_errors.append("event missing required field")
            continue
        if previous is not None and event["sequence"] != previous + 1:
            integrity_errors.append(
                f"event sequence gap: {previous} to {event['sequence']}")
        previous = event["sequence"]
        forbidden = {"hash", "txid", "wtxid"} & set(event)
        if forbidden:
            integrity_errors.append(f"raw identifier keys present: {sorted(forbidden)}")

    join_ages = annotate(events, rpc, max_join_age)
    complete, front, starts, ends, duplicates = keyed_messages(events)
    if duplicates:
        integrity_errors.append(f"duplicate message lifecycle keys: {len(duplicates)}")
    observation_start = min((event["steady_ns"] for event in events), default=0)
    observation_end = max((event["steady_ns"] for event in events), default=observation_start)
    observation_seconds = max(0, observation_end - observation_start) / 1e9

    queue_latency = []
    front_latency = []
    handler_latency = []
    service_latency = []
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
    for event in events:
        values = event["values"]
        if event["event_code"] == 23:
            key = (event["process_epoch"], values[0], values[1])
            outbound[key] = event
            if values[2]:
                causal_inbound[(event["process_epoch"], values[0], values[2])].add(key)
        elif event["event_code"] == 24:
            socket[(event["process_epoch"], values[0], values[1])] = event
        elif event["event_code"] == 25:
            dropped[(event["process_epoch"], values[0], values[1])] = event
        elif event["event_code"] == 26:
            causal_inbound[(event["process_epoch"], values[0], values[1])].add(
                (event["process_epoch"], values[0], values[2]))

    for key in socket:
        if key not in outbound:
            integrity_errors.append(f"socket completion without outbound offer for {key}")
    for key in dropped:
        if key not in outbound:
            integrity_errors.append(f"drop without outbound offer for {key}")
    for inbound_key, outbound_keys in causal_inbound.items():
        if inbound_key not in complete:
            integrity_errors.append(f"causal link without inbound message for {inbound_key}")
        for outbound_key in outbound_keys:
            if outbound_key not in outbound:
                integrity_errors.append(f"causal link without outbound offer for {outbound_key}")

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
        causal = queued["values"][2]
        inbound_key = (key[0], key[1], causal)
        if causal and inbound_key in complete:
            service_latency.append(last - complete[inbound_key]["steady_ns"])

    pnb_jobs = build_pnb_jobs(events, integrity_errors)
    pnb_intervals = [(job["start_ns"], job["end_ns"]) for job in pnb_jobs
                     if job["start_ns"] is not None and job["end_ns"] is not None and
                     job["end_ns"] >= job["start_ns"]]
    pnb_ns = sum(end - start for start, end in pnb_intervals)
    during = Counter({
        "handler_start": 0, "response_queued": 0, "socket_sent": 0})
    for event in events:
        if interval_contains(pnb_intervals, event["steady_ns"]):
            if event["event_code"] in (2, 4, 24):
                during[event["event"]] += 1

    useful = [event for event in events if event["event_code"] == 3 and
              len(event["values"]) > 2 and event["values"][2] == 0]
    payload = sum(event["values"][2] for event in complete.values())
    wire = sum(event["values"][3] for event in complete.values())
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
    block_counts = Counter(event["event"] for event in events if event["event_code"] in (32, 33, 34))
    timeout_reasons = Counter(str(event["values"][1]) for event in events if event["event_code"] == 34)
    block_requests = {}
    block_completion_ns = []
    block_stall_ns = []
    for event in events:
        if event["event_code"] == 32 and event.get("block_id"):
            block_requests[(event["process_epoch"], event["values"][0],
                            event["block_id"])] = event["steady_ns"]
        elif event["event_code"] in (33, 34) and event.get("block_id"):
            key = (event["process_epoch"], event["values"][0], event["block_id"])
            if key in block_requests and event["steady_ns"] >= block_requests[key]:
                target = block_completion_ns if event["event_code"] == 33 else block_stall_ns
                target.append(event["steady_ns"] - block_requests[key])

    receive_queue = queue_metrics(events, 22, observation_end)
    send_queue = queue_metrics(events, 31, observation_end)
    if receive_queue["negative_counter_samples"] or send_queue["negative_counter_samples"]:
        integrity_errors.append("negative queue counter observed")

    phases = ("ibd", "transition", "post_ibd", "unclassified")
    breakdowns = {
        "phase": {phase: subset_summary([event for event in events if event["_phase"] == phase])
                  for phase in phases},
        "message_type": {name: subset_summary([event for event in events
                                               if event["_message_type"] == name])
                         for name in sorted({event["_message_type"] for event in events
                                             if event["_message_type"]})},
        "connection_role": {name: subset_summary([event for event in events
                                                  if event["_role"] == name])
                            for name in sorted({event["_role"] for event in events})},
        "pnb_delivery_route": {name: subset_summary([event for event in events
                                                     if event["_route"] == name])
                               for name in sorted({event["_route"] for event in events
                                                   if event["_route"]})},
        "process_epoch": {str(epoch): subset_summary([event for event in events
                                                      if event["process_epoch"] == epoch])
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
            "count": len(pnb_intervals),
            "time_seconds": pnb_seconds,
            "wall_fraction": pnb_seconds / observation_seconds if observation_seconds else None,
            "jobs_per_second": len(pnb_intervals) / observation_seconds if observation_seconds else None,
            "blocks_per_second": sum(bool(job["new_block"]) for job in pnb_jobs) /
                                 observation_seconds if observation_seconds else None,
            "process_new_block_failures": sum(
                job["process_new_block"] is False for job in pnb_jobs),
            "incomplete_at_collection_boundary": sum(
                job["incomplete_at_collection_boundary"] for job in pnb_jobs),
            "impossible_join_count": sum("PNB lifecycle" in error
                                         for error in integrity_errors),
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
            "ready_to_socket_complete_service_ns": distribution(service_latency),
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
            "useful_messages_per_pnb_second": len(useful) / pnb_seconds if pnb_seconds else None,
            "payload_bytes_per_pnb_second": payload / pnb_seconds if pnb_seconds else None,
            "wire_bytes_per_pnb_second": wire / pnb_seconds if pnb_seconds else None,
        },
        "outbound": {
            "offered": len(outbound),
            "correlated": sum(bool(event["values"][2]) for event in outbound.values()),
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
            "request_to_removal_ns": distribution(block_completion_ns),
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
        missing = COLLECTOR_FILES - {entry.name for entry in source.iterdir() if entry.is_file()}
        if missing:
            raise AnalysisError(f"collector directory is incomplete: missing {sorted(missing)}")
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
