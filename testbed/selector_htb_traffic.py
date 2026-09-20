#!/usr/bin/env python3
"""UDP sender/receiver for the isolated causal-selector HTB experiment."""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import math
import os
import select
import socket
import struct
import sys
import time
import zlib
from array import array
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

from experiments.selector_htb import (
    fit_frozen_selectors,
    load_selector_htb_config,
    nearest_rank,
    replay_trace,
)


MAGIC = b"CIQHTB01"
VERSION = 1
HEADER = struct.Struct("!8sBBBBIQQ")
CLASS_CODE = {"fast": 1, "suspicious": 2}
CLASS_NAME = {value: key for key, value in CLASS_CODE.items()}
LABEL_CODE = {"benign": 1, "attack": 2}
LABEL_NAME = {value: key for key, value in LABEL_CODE.items()}
PHASE_WARMUP = 1
PHASE_MEASUREMENT = 2
SO_RXQ_OVFL = getattr(socket, "SO_RXQ_OVFL", 40)


def require_testnet(address: str, subnet: str) -> None:
    parsed = ipaddress.ip_address(address)
    allowed = ipaddress.ip_network(subnet)
    if parsed.version != 4 or parsed not in allowed:
        raise ValueError(f"REFUSING address outside {allowed}: {address}")


def pin_cpu(cpu_id: int) -> list[int]:
    if cpu_id < 0:
        raise ValueError("cpu id must be nonnegative")
    os.sched_setaffinity(0, {cpu_id})
    actual = sorted(os.sched_getaffinity(0))
    if actual != [cpu_id]:
        raise RuntimeError(f"CPU affinity mismatch: {actual} != {[cpu_id]}")
    return actual


def udp_counters() -> dict[str, int]:
    rows = [
        line.split()
        for line in Path("/proc/net/snmp").read_text(encoding="utf-8").splitlines()
        if line.startswith("Udp:")
    ]
    if len(rows) != 2 or len(rows[0]) != len(rows[1]):
        raise RuntimeError("unexpected /proc/net/snmp UDP table")
    return {key: int(value) for key, value in zip(rows[0][1:], rows[1][1:])}


def counter_delta(before: dict[str, int], after: dict[str, int]) -> dict[str, int]:
    result = {key: after.get(key, 0) - before.get(key, 0) for key in sorted(set(before) | set(after))}
    if any(value < 0 for value in result.values()):
        raise RuntimeError("namespace-local UDP counter moved backwards")
    return result


def encode_uint64(values: Iterable[int]) -> dict[str, Any]:
    rows = list(values)
    if any(isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**64 for value in rows):
        raise ValueError("samples must be uint64 integers")
    words = array("Q", rows)
    if sys.byteorder != "little":
        words.byteswap()
    raw = words.tobytes()
    return {
        "encoding": "zlib_base64_uint64_le_v1",
        "sample_count": len(rows),
        "uncompressed_sha256": hashlib.sha256(raw).hexdigest(),
        "data_base64": base64.b64encode(zlib.compress(raw, 9)).decode("ascii"),
    }


def make_payload(
    size: int,
    traffic_class: str,
    true_label: str,
    phase: int,
    trace_index: int,
    planned_ns: int,
    sent_ns: int,
) -> bytes:
    if size < HEADER.size:
        raise ValueError("generated payload is smaller than the experiment header")
    header = HEADER.pack(
        MAGIC, VERSION, CLASS_CODE[traffic_class], LABEL_CODE[true_label], phase,
        trace_index, planned_ns, sent_ns,
    )
    return header + bytes(size - HEADER.size)


def parse_payload(payload: bytes) -> dict[str, Any] | None:
    if len(payload) < HEADER.size:
        return None
    magic, version, class_code, label_code, phase, index, planned_ns, sent_ns = HEADER.unpack_from(payload)
    if (
        magic != MAGIC
        or version != VERSION
        or class_code not in CLASS_NAME
        or label_code not in LABEL_NAME
        or phase not in (PHASE_WARMUP, PHASE_MEASUREMENT)
    ):
        return None
    return {
        "traffic_class": CLASS_NAME[class_code],
        "true_label": LABEL_NAME[label_code],
        "phase": phase,
        "trace_index": index,
        "planned_ns": planned_ns,
        "sent_ns": sent_ns,
    }


def await_start() -> int:
    line = sys.stdin.readline()
    if not line:
        raise RuntimeError("start barrier closed")
    payload = json.loads(line)
    if set(payload) != {"event", "start_monotonic_ns"} or payload["event"] != "start":
        raise RuntimeError("malformed start barrier")
    start = payload["start_monotonic_ns"]
    if isinstance(start, bool) or not isinstance(start, int) or start <= time.monotonic_ns():
        raise RuntimeError("start barrier is not a future monotonic timestamp")
    return start


def sleep_until(deadline_ns: int) -> None:
    while True:
        remaining = deadline_ns - time.monotonic_ns()
        if remaining <= 0:
            return
        if remaining > 150_000:
            time.sleep((remaining - 75_000) / 1_000_000_000)


def run_sender(args: argparse.Namespace) -> None:
    config = load_selector_htb_config(args.config)
    coupled, models, calibration = fit_frozen_selectors(config)
    replay, trace = replay_trace(
        config, coupled, models, args.seed, args.attack_scale, args.selector
    )
    require_testnet(args.destination_ip, str(config.network["allowed_subnet"]))
    affinity = pin_cpu(args.cpu_id)
    sockets: dict[str, socket.socket] = {}
    for traffic_class, port_key, tos_key in (
        ("fast", "fast_source_port", "fast_tos"),
        ("suspicious", "suspicious_source_port", "suspicious_tos"),
    ):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, args.socket_buffer_bytes)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, int(config.network[tos_key]))
        sock.bind((args.bind_ip, int(config.network[port_key])))
        sockets[traffic_class] = sock
    print(json.dumps({
        "event": "ready", "role": "sender", "cpu_affinity": affinity,
        "trace_sha256": trace["trace_sha256"], "packet_count": trace["packet_count"],
    }), flush=True)
    start_ns = await_start()
    warmup_ns = int(round(coupled.warmup_s * 1_000_000_000))
    maximum_late_ns = args.skip_if_late_ns
    sent_counts: dict[str, int] = defaultdict(int)
    sent_bytes: dict[str, int] = defaultdict(int)
    skipped_counts: dict[str, int] = defaultdict(int)
    lateness: list[int] = []
    first_send_ns: int | None = None
    last_send_ns: int | None = None
    try:
        for trace_index, event in enumerate(replay):
            planned_ns = start_ns + event.offset_ns
            sleep_until(planned_ns)
            actual_ns = time.monotonic_ns()
            late_ns = max(0, actual_ns - planned_ns)
            phase_name = "warmup" if event.offset_ns < warmup_ns else "measurement"
            key = f"{phase_name}:{event.true_label}:{event.traffic_class}"
            if late_ns > maximum_late_ns:
                skipped_counts[key] += 1
                continue
            phase = PHASE_WARMUP if phase_name == "warmup" else PHASE_MEASUREMENT
            payload = make_payload(
                event.size_bytes, event.traffic_class, event.true_label,
                phase, trace_index, planned_ns, actual_ns,
            )
            written = sockets[event.traffic_class].sendto(
                payload, (args.destination_ip, args.destination_port)
            )
            if written != len(payload):
                raise RuntimeError("partial UDP datagram send")
            sent_counts[key] += 1
            sent_bytes[key] += written
            lateness.append(late_ns)
            first_send_ns = actual_ns if first_send_ns is None else first_send_ns
            last_send_ns = actual_ns
    finally:
        for sock in sockets.values():
            sock.close()
    total_planned = len(replay)
    total_skipped = sum(skipped_counts.values())
    print(json.dumps({
        "event": "final", "role": "sender", "start_monotonic_ns": start_ns,
        "first_send_monotonic_ns": first_send_ns,
        "last_send_monotonic_ns": last_send_ns,
        "trace": trace, "calibration": calibration,
        "sent_packet_counts": dict(sorted(sent_counts.items())),
        "sent_payload_bytes": dict(sorted(sent_bytes.items())),
        "skipped_packet_counts": dict(sorted(skipped_counts.items())),
        "planned_packets": total_planned, "sent_packets": total_planned - total_skipped,
        "missed_schedule_fraction": total_skipped / total_planned if total_planned else 0.0,
        "send_lateness_p50_ns": nearest_rank(lateness, 0.50),
        "send_lateness_p99_ns": nearest_rank(lateness, 0.99),
        "send_lateness_max_ns": max(lateness) if lateness else None,
        "send_lateness_samples": encode_uint64(lateness),
    }, sort_keys=True), flush=True)


def run_receiver(args: argparse.Namespace) -> None:
    require_testnet(args.bind_ip, args.allowed_subnet)
    affinity = pin_cpu(args.cpu_id)
    before = udp_counters()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, args.socket_buffer_bytes)
    sock.setsockopt(socket.SOL_SOCKET, SO_RXQ_OVFL, 1)
    sock.bind((args.bind_ip, args.port))
    sock.setblocking(False)
    print(json.dumps({
        "event": "ready", "role": "receiver", "cpu_affinity": affinity,
        "actual_receive_buffer_bytes": sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF),
    }), flush=True)
    start_ns = await_start()
    end_ns = start_ns + int(round((args.duration_s + args.drain_s) * 1_000_000_000))
    counts: dict[str, int] = defaultdict(int)
    bytes_: dict[str, int] = defaultdict(int)
    latencies: dict[str, list[int]] = defaultdict(list)
    seen: set[int] = set()
    duplicate_packets = malformed_packets = wrong_peer_packets = 0
    overflow_total = 0
    while time.monotonic_ns() < end_ns:
        timeout = max(0.0, min(0.05, (end_ns - time.monotonic_ns()) / 1_000_000_000))
        ready, _, _ = select.select([sock], [], [], timeout)
        if not ready:
            continue
        data, ancillary, _, peer = sock.recvmsg(65535, 128)
        received_ns = time.monotonic_ns()
        if peer[0] != args.expected_peer_ip:
            wrong_peer_packets += 1
            continue
        for level, kind, payload in ancillary:
            if level == socket.SOL_SOCKET and kind == SO_RXQ_OVFL and len(payload) >= 4:
                overflow_total = max(overflow_total, struct.unpack("=I", payload[:4])[0])
        parsed = parse_payload(data)
        if parsed is None:
            malformed_packets += 1
            continue
        if parsed["trace_index"] in seen:
            duplicate_packets += 1
        seen.add(parsed["trace_index"])
        phase = "warmup" if parsed["phase"] == PHASE_WARMUP else "measurement"
        key = f"{phase}:{parsed['true_label']}:{parsed['traffic_class']}"
        counts[key] += 1
        bytes_[key] += len(data)
        if phase == "measurement":
            latencies[key].append(max(0, received_ns - parsed["sent_ns"]))
    sock.close()
    udp_delta = counter_delta(before, udp_counters())
    latency_summary = {
        key: {
            "sample_count": len(values),
            "p50_ns": nearest_rank(values, 0.50),
            "p99_ns": nearest_rank(values, 0.99),
            "max_ns": max(values) if values else None,
            "samples": encode_uint64(values),
        }
        for key, values in sorted(latencies.items())
    }
    print(json.dumps({
        "event": "final", "role": "receiver", "start_monotonic_ns": start_ns,
        "received_packet_counts": dict(sorted(counts.items())),
        "received_payload_bytes": dict(sorted(bytes_.items())),
        "latency_by_truth_and_class": latency_summary,
        "unique_trace_indices": len(seen), "duplicate_packets": duplicate_packets,
        "malformed_packets": malformed_packets, "wrong_peer_packets": wrong_peer_packets,
        "socket_rxq_overflow_drops": overflow_total, "udp_counter_delta": udp_delta,
    }, sort_keys=True), flush=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="role", required=True)
    sender = sub.add_parser("sender")
    sender.add_argument("--config", type=Path, required=True)
    sender.add_argument("--seed", type=int, required=True)
    sender.add_argument("--attack-scale", type=float, required=True)
    sender.add_argument("--selector", required=True)
    sender.add_argument("--bind-ip", required=True)
    sender.add_argument("--destination-ip", required=True)
    sender.add_argument("--destination-port", type=int, required=True)
    sender.add_argument("--cpu-id", type=int, required=True)
    sender.add_argument("--socket-buffer-bytes", type=int, default=16 * 1024 * 1024)
    sender.add_argument("--skip-if-late-ns", type=int, required=True)
    receiver = sub.add_parser("receiver")
    receiver.add_argument("--bind-ip", required=True)
    receiver.add_argument("--expected-peer-ip", required=True)
    receiver.add_argument("--allowed-subnet", required=True)
    receiver.add_argument("--port", type=int, required=True)
    receiver.add_argument("--duration-s", type=float, required=True)
    receiver.add_argument("--drain-s", type=float, required=True)
    receiver.add_argument("--cpu-id", type=int, required=True)
    receiver.add_argument("--socket-buffer-bytes", type=int, default=16 * 1024 * 1024)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.role == "sender":
        run_sender(args)
    else:
        run_receiver(args)


if __name__ == "__main__":
    main()
