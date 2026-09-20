#!/usr/bin/env python3
"""Phase-aware UDP traffic and echo RTT instrumentation for Study B.

The program never creates a namespace and refuses every address outside
RFC 5737 TEST-NET-2.  It is intended to be launched only by
``run_matched_scheduler.py`` through the isolated namespace anchors.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import math
import os
import resource
import select
import socket
import struct
import sys
import time
import zlib
from array import array
from fractions import Fraction
from pathlib import Path
from typing import Any


ALLOWED_SUBNET = ipaddress.ip_network("198.51.100.0/24")
MAGIC = b"MSHTB001"
VERSION = 1
CLASS_CODES = {"benign": 1, "suspicious": 2}
CLASS_NAMES = {value: key for key, value in CLASS_CODES.items()}
PHASE_WARMUP = 1
PHASE_MEASUREMENT = 2
HEADER = struct.Struct("!8sBBBBIQQ")
MAX_SEQUENCE = (1 << 32) - 1
FLAG_RTT_PROBE = 0x01
KNOWN_FLAGS = FLAG_RTT_PROBE
SO_RXQ_OVFL = getattr(socket, "SO_RXQ_OVFL", 40)
LATENESS_SAMPLE_ENCODING = "zlib_base64_uint64_le_v1"


def require_testnet(address: str) -> None:
    parsed = ipaddress.ip_address(address)
    if parsed.version != 4 or parsed not in ALLOWED_SUBNET:
        raise ValueError(f"REFUSING address outside {ALLOWED_SUBNET}: {address}")


def require_finite_nonnegative(value: float, name: str, *, positive: bool = False) -> None:
    if not math.isfinite(value) or value < 0 or (positive and value <= 0):
        raise ValueError(f"{name} must be finite and {'positive' if positive else 'nonnegative'}")


def pin_to_cpu(cpu_id: int) -> list[int]:
    if cpu_id < 0:
        raise ValueError("cpu-id must be nonnegative")
    os.sched_setaffinity(0, {cpu_id})
    resolved = sorted(os.sched_getaffinity(0))
    if resolved != [cpu_id]:
        raise RuntimeError(f"failed to pin process to CPU {cpu_id}: got {resolved}")
    return resolved


def process_usage() -> dict[str, Any]:
    usage = resource.getrusage(resource.RUSAGE_SELF)
    return {
        "process_time_s": time.process_time(),
        "user_cpu_s": usage.ru_utime,
        "system_cpu_s": usage.ru_stime,
        "voluntary_context_switches": usage.ru_nvcsw,
        "involuntary_context_switches": usage.ru_nivcsw,
        "max_rss_platform_units": usage.ru_maxrss,
    }


def udp_snmp_counters() -> dict[str, int]:
    """Read namespace-local UDP counters without shelling out."""

    lines = [
        line.split()
        for line in Path("/proc/net/snmp").read_text(encoding="utf-8").splitlines()
        if line.startswith("Udp:")
    ]
    if len(lines) != 2 or len(lines[0]) != len(lines[1]):
        raise RuntimeError("unexpected /proc/net/snmp UDP record")
    return {key: int(value) for key, value in zip(lines[0][1:], lines[1][1:])}


def udp_snmp_delta(before: dict[str, int], after: dict[str, int]) -> dict[str, int]:
    keys = sorted(set(before) | set(after))
    result = {key: after.get(key, 0) - before.get(key, 0) for key in keys}
    if any(value < 0 for value in result.values()):
        raise RuntimeError("UDP SNMP counter moved backwards")
    return result


def enable_rxq_overflow(sock: socket.socket) -> None:
    sock.setsockopt(socket.SOL_SOCKET, SO_RXQ_OVFL, 1)


def recv_datagram(sock: socket.socket) -> tuple[bytes, tuple[str, int], int | None]:
    data, ancillary, _flags, peer = sock.recvmsg(65535, 128)
    overflow: int | None = None
    for level, kind, payload in ancillary:
        if level == socket.SOL_SOCKET and kind == SO_RXQ_OVFL and len(payload) >= 4:
            overflow = struct.unpack("=I", payload[:4])[0]
    return data, peer, overflow


def await_shared_start(args: argparse.Namespace) -> tuple[int, int | None]:
    """Receive the runner's post-readiness shared future-start decision."""

    if args.start_monotonic_ns is not None:
        return args.start_monotonic_ns, None
    line = sys.stdin.readline()
    received_ns = time.monotonic_ns()
    if not line:
        raise RuntimeError("start barrier stdin closed before a start record")
    record = json.loads(line)
    if set(record) != {"event", "start_monotonic_ns"} or record["event"] != "start":
        raise RuntimeError("malformed start barrier record")
    start_ns = record["start_monotonic_ns"]
    if isinstance(start_ns, bool) or not isinstance(start_ns, int) or start_ns <= received_ns:
        raise RuntimeError("shared start is not a future monotonic timestamp")
    return start_ns, received_ns


def _schedule_offset_ns(seed: int, traffic_class: str, rate_pps: float) -> int:
    if rate_pps <= 0:
        return 0
    period_ns = max(1, int(1_000_000_000 / rate_pps))
    digest = hashlib.sha256(f"{seed}:{traffic_class}".encode("ascii")).digest()
    return int.from_bytes(digest[:8], "big") % period_ns


def _target_ns(start_ns: int, offset_ns: int, index: int, rate: Fraction) -> int:
    return start_ns + offset_ns + (index * 1_000_000_000 * rate.denominator) // rate.numerator


def planned_packet_count(duration_s: float, rate_pps: float, offset_ns: int) -> int:
    if rate_pps <= 0:
        return 0
    duration_ns = int(round(duration_s * 1_000_000_000))
    if offset_ns >= duration_ns:
        return 0
    rate = Fraction(str(rate_pps))
    remaining = duration_ns - 1 - offset_ns
    return (remaining * rate.numerator) // (1_000_000_000 * rate.denominator) + 1


def nearest_rank_percentile(values: list[int], percentile: float) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, math.ceil(percentile * len(ordered)))
    return ordered[rank - 1]


def encode_lateness_samples(values: list[int]) -> dict[str, Any]:
    """Losslessly retain every send-lateness sample in a compact raw field.

    The fixed-width representation makes the completed-tree verifier able to
    decode the original sample vector and independently recompute all reported
    lateness summaries, including the exact nearest-rank p99.  The vector is
    preserved in send order; compression is storage-only and is not a summary.
    """

    if any(
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value >= 1 << 64
        for value in values
    ):
        raise ValueError("lateness samples must be uint64 integers")
    words = array("Q", values)
    if sys.byteorder != "little":
        words.byteswap()
    raw = words.tobytes()
    compressed = zlib.compress(raw, level=9)
    return {
        "encoding": LATENESS_SAMPLE_ENCODING,
        "sample_count": len(values),
        "uncompressed_sha256": hashlib.sha256(raw).hexdigest(),
        "data_base64": base64.b64encode(compressed).decode("ascii"),
    }


def count_selected_indices(first_index: int, count: int, every_n: int) -> int:
    if count <= 0:
        return 0
    if first_index < 0 or every_n <= 0:
        raise ValueError("probe index/count inputs are invalid")
    last_index = first_index + count - 1
    return last_index // every_n - ((first_index - 1) // every_n)


def _sleep_until(deadline_ns: int) -> None:
    while True:
        remaining_ns = deadline_ns - time.monotonic_ns()
        if remaining_ns <= 0:
            return
        if remaining_ns > 150_000:
            time.sleep((remaining_ns - 75_000) / 1_000_000_000)


def _make_payload(
    size: int,
    class_code: int,
    phase: int,
    sequence: int,
    planned_ns: int,
    actual_send_ns: int,
    *,
    rtt_probe: bool = False,
) -> bytes:
    if size < HEADER.size:
        raise ValueError(f"payload size {size} is below header size {HEADER.size}")
    header = HEADER.pack(
        MAGIC,
        VERSION,
        class_code,
        phase,
        FLAG_RTT_PROBE if rtt_probe else 0,
        sequence,
        planned_ns,
        actual_send_ns,
    )
    return header + bytes(size - len(header))


def _parse_payload(data: bytes) -> dict[str, int | str] | None:
    if len(data) < HEADER.size:
        return None
    magic, version, class_code, phase, flags, sequence, planned_ns, sent_ns = HEADER.unpack_from(data)
    if (
        magic != MAGIC
        or version != VERSION
        or class_code not in CLASS_NAMES
        or phase not in (PHASE_WARMUP, PHASE_MEASUREMENT)
        or flags & ~KNOWN_FLAGS
        or (flags & FLAG_RTT_PROBE and class_code != CLASS_CODES["benign"])
    ):
        return None
    return {
        "class": CLASS_NAMES[class_code],
        "class_code": class_code,
        "phase": phase,
        "sequence": sequence,
        "planned_ns": planned_ns,
        "sent_ns": sent_ns,
        "rtt_probe": bool(flags & FLAG_RTT_PROBE),
    }


def run_receiver(args: argparse.Namespace) -> None:
    require_testnet(args.bind_ip)
    affinity = pin_to_cpu(args.cpu_id)
    udp_before = udp_snmp_counters()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, args.socket_buffer_bytes)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, args.socket_buffer_bytes)
    enable_rxq_overflow(sock)
    sock.bind((args.bind_ip, args.port))
    sock.setblocking(False)
    actual_buffers = {
        "receive_bytes": sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF),
        "send_bytes": sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF),
    }

    def empty_counts() -> dict[str, int]:
        return {
            "benign_packets": 0,
            "benign_bytes": 0,
            "suspicious_packets": 0,
            "suspicious_bytes": 0,
            "benign_rtt_probe_packets": 0,
        }

    counts_by_sender_phase = {
        "warmup": empty_counts(),
        "measurement": empty_counts(),
    }
    counts_by_arrival_window = {
        "before_start": empty_counts(),
        "warmup": empty_counts(),
        "measurement": empty_counts(),
        "drain": empty_counts(),
    }
    sender_phase_by_arrival_window = {
        sender_phase: {
            arrival_window: empty_counts()
            for arrival_window in counts_by_arrival_window
        }
        for sender_phase in counts_by_sender_phase
    }
    malformed_packets = 0
    wrong_size_packets = 0
    out_of_window_packets = 0
    benign_echo_attempts = 0
    benign_echo_failures = 0
    nonprobe_benign_packets_not_echoed = 0
    socket_rxq_overflow_drops = 0
    first_receive_ns: int | None = None
    last_receive_ns: int | None = None

    ready_ns = time.monotonic_ns()
    print(
        json.dumps(
            {
                "event": "ready",
                "role": "receiver",
                "bind_ip": args.bind_ip,
                "port": args.port,
                "monotonic_ns": ready_ns,
                "cpu_affinity": affinity,
            },
            sort_keys=True,
        ),
        flush=True,
    )

    start_ns, start_signal_received_ns = await_shared_start(args)
    warmup_end_ns = start_ns + int(round(args.warmup_s * 1e9))
    measurement_end_ns = warmup_end_ns + int(round(args.measurement_s * 1e9))
    end_ns = measurement_end_ns + int(round(args.drain_s * 1e9))

    while time.monotonic_ns() < end_ns:
        readable, _, _ = select.select([sock], [], [], 0.05)
        if not readable:
            continue
        for _ in range(1024):
            try:
                data, peer, overflow = recv_datagram(sock)
            except BlockingIOError:
                break
            if overflow is not None:
                socket_rxq_overflow_drops = max(socket_rxq_overflow_drops, overflow)
            received_ns = time.monotonic_ns()
            first_receive_ns = received_ns if first_receive_ns is None else first_receive_ns
            last_receive_ns = received_ns
            parsed = _parse_payload(data)
            if parsed is None:
                malformed_packets += 1
                continue
            if len(data) != args.packet_size:
                wrong_size_packets += 1
            sender_phase = (
                "warmup" if parsed["phase"] == PHASE_WARMUP else "measurement"
            )
            if received_ns < start_ns:
                arrival_window = "before_start"
            elif received_ns < warmup_end_ns:
                arrival_window = "warmup"
            elif received_ns < measurement_end_ns:
                arrival_window = "measurement"
            else:
                arrival_window = "drain"
            if arrival_window in {"before_start", "drain"}:
                out_of_window_packets += 1
            class_name = str(parsed["class"])
            for counter in (
                counts_by_sender_phase[sender_phase],
                counts_by_arrival_window[arrival_window],
                sender_phase_by_arrival_window[sender_phase][arrival_window],
            ):
                counter[f"{class_name}_packets"] += 1
                counter[f"{class_name}_bytes"] += len(data)
                if parsed["rtt_probe"]:
                    counter["benign_rtt_probe_packets"] += 1
            if class_name == "benign" and parsed["rtt_probe"]:
                benign_echo_attempts += 1
                try:
                    sock.sendto(data, peer)
                except (BlockingIOError, OSError):
                    benign_echo_failures += 1
            elif class_name == "benign":
                nonprobe_benign_packets_not_echoed += 1
    udp_after = udp_snmp_counters()
    sock.close()
    measurement_origin = sender_phase_by_arrival_window["measurement"]
    warmup_origin = sender_phase_by_arrival_window["warmup"]
    result = {
        "schema_version": "matched-scheduler-traffic-1.0",
        "role": "receiver",
        "final": True,
        "start_monotonic_ns": start_ns,
        "start_signal_received_monotonic_ns": start_signal_received_ns,
        "warmup_end_monotonic_ns": warmup_end_ns,
        "measurement_end_monotonic_ns": measurement_end_ns,
        "end_monotonic_ns": time.monotonic_ns(),
        "packet_size_bytes": args.packet_size,
        "primary_service_window": "receiver_arrival_[warmup_end,measurement_end)",
        "counts_by_arrival_window": counts_by_arrival_window,
        "counts_by_sender_phase": counts_by_sender_phase,
        "sender_phase_by_arrival_window": sender_phase_by_arrival_window,
        "measurement_origin_cohort": {
            "arrived_during_measurement": measurement_origin["measurement"],
            "arrived_during_drain": measurement_origin["drain"],
            "arrived_before_measurement_window": {
                key: measurement_origin["before_start"][key]
                + measurement_origin["warmup"][key]
                for key in measurement_origin["warmup"]
            },
        },
        "cross_boundary": {
            "warmup_origin_arrived_during_measurement": warmup_origin["measurement"],
            "measurement_origin_arrived_during_drain": measurement_origin["drain"],
        },
        "malformed_packets": malformed_packets,
        "wrong_size_packets": wrong_size_packets,
        "out_of_window_packets": out_of_window_packets,
        "benign_echo_attempts": benign_echo_attempts,
        "benign_echo_failures": benign_echo_failures,
        "echo_policy": "only_flagged_rtt_probes_are_echoed",
        "nonprobe_benign_packets_not_echoed": nonprobe_benign_packets_not_echoed,
        "socket_rxq_overflow_drops": socket_rxq_overflow_drops,
        "udp_snmp_before": udp_before,
        "udp_snmp_after": udp_after,
        "udp_snmp_delta": udp_snmp_delta(udp_before, udp_after),
        "first_receive_monotonic_ns": first_receive_ns,
        "last_receive_monotonic_ns": last_receive_ns,
        "requested_socket_buffer_bytes": args.socket_buffer_bytes,
        "actual_socket_buffers": actual_buffers,
        "cpu_affinity": affinity,
        "process_usage": process_usage(),
    }
    print(json.dumps(result, sort_keys=True, allow_nan=False), flush=True)


def run_sender(args: argparse.Namespace) -> None:
    require_testnet(args.bind_ip)
    require_testnet(args.target_ip)
    affinity = pin_to_cpu(args.cpu_id)
    udp_before = udp_snmp_counters()
    class_code = CLASS_CODES[args.traffic_class]
    tos = args.fast_tos if args.traffic_class == "benign" else args.suspicious_tos
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, tos)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, args.socket_buffer_bytes)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, args.socket_buffer_bytes)
    enable_rxq_overflow(sock)
    sock.bind((args.bind_ip, args.source_port))
    sock.setblocking(False)
    actual_buffers = {
        "receive_bytes": sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF),
        "send_bytes": sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF),
    }

    ready_ns = time.monotonic_ns()
    print(
        json.dumps(
            {
                "event": "ready",
                "role": "sender",
                "traffic_class": args.traffic_class,
                "bind_ip": args.bind_ip,
                "source_port": args.source_port,
                "monotonic_ns": ready_ns,
                "cpu_affinity": affinity,
                "rtt_probe_rate_pps": (
                    args.rtt_probe_rate_pps if args.traffic_class == "benign" else 0.0
                ),
            },
            sort_keys=True,
        ),
        flush=True,
    )
    start_ns, start_signal_received_ns = await_shared_start(args)
    warmup_end_ns = start_ns + int(round(args.warmup_s * 1e9))
    measurement_end_ns = warmup_end_ns + int(round(args.measurement_s * 1e9))
    drain_end_ns = measurement_end_ns + int(round(args.drain_s * 1e9))
    rate = Fraction(str(args.rate_pps)) if args.rate_pps > 0 else None
    offset_ns = _schedule_offset_ns(args.seed, args.traffic_class, args.rate_pps)
    planned_warmup = planned_packet_count(args.warmup_s, args.rate_pps, offset_ns)
    measurement_offset = max(0, offset_ns - int(round(args.warmup_s * 1e9)))
    # The continuous schedule crosses the phase boundary.  Compute the exact
    # total count and derive the measurement target by subtraction.
    planned_total = planned_packet_count(
        args.warmup_s + args.measurement_s, args.rate_pps, offset_ns
    )
    planned_measurement = max(0, planned_total - planned_warmup)
    _ = measurement_offset  # documents why the subtraction is intentional

    probe_every_n: int | None = None
    if args.traffic_class == "benign" and args.rate_pps > 0:
        if args.rtt_probe_rate_pps <= 0 or args.rtt_probe_rate_pps > args.rate_pps:
            raise ValueError("RTT probe rate must be positive and no greater than benign rate")
        ratio = args.rate_pps / args.rtt_probe_rate_pps
        if not math.isclose(ratio, round(ratio), abs_tol=1e-12):
            raise ValueError("benign rate must be an integer multiple of RTT probe rate")
        probe_every_n = int(round(ratio))
    planned_probes = {
        "warmup": (
            count_selected_indices(0, planned_warmup, probe_every_n)
            if probe_every_n is not None
            else 0
        ),
        "measurement": (
            count_selected_indices(planned_warmup, planned_measurement, probe_every_n)
            if probe_every_n is not None
            else 0
        ),
    }

    sent = {
        "warmup": {"packets": 0, "bytes": 0, "rtt_probe_packets": 0},
        "measurement": {"packets": 0, "bytes": 0, "rtt_probe_packets": 0},
    }
    send_errors = 0
    send_errors_by_phase = {"warmup": 0, "measurement": 0}
    missed_deadlines = {"warmup": 0, "measurement": 0}
    missed_probe_deadlines = {"warmup": 0, "measurement": 0}
    send_lateness_by_phase_ns: dict[str, list[int]] = {
        "warmup": [],
        "measurement": [],
    }
    measurement_rtt_ns: list[int] = []
    warmup_rtt_count = 0
    echo_malformed = 0
    echo_wrong_class = 0
    echo_duplicates = 0
    echo_nonprobe = 0
    socket_rxq_overflow_drops = 0
    outstanding: dict[int, tuple[int, int]] = {}
    acknowledged: set[int] = set()
    sequence = 0
    index = 0
    next_target = (
        _target_ns(start_ns, offset_ns, index, rate) if rate is not None else measurement_end_ns
    )
    target = (args.target_ip, args.target_port)

    def receive_echoes() -> None:
        nonlocal warmup_rtt_count, echo_malformed, echo_wrong_class
        nonlocal echo_duplicates, echo_nonprobe, socket_rxq_overflow_drops
        if args.traffic_class != "benign":
            return
        for _echo_index in range(2048):
            try:
                data, _peer, overflow = recv_datagram(sock)
            except BlockingIOError:
                return
            if overflow is not None:
                socket_rxq_overflow_drops = max(socket_rxq_overflow_drops, overflow)
            received_ns = time.monotonic_ns()
            parsed = _parse_payload(data)
            if parsed is None or len(data) != args.packet_size:
                echo_malformed += 1
                continue
            if parsed["class"] != "benign":
                echo_wrong_class += 1
                continue
            if not parsed["rtt_probe"]:
                echo_nonprobe += 1
                continue
            echo_sequence = int(parsed["sequence"])
            if echo_sequence in acknowledged:
                echo_duplicates += 1
                continue
            sent_record = outstanding.pop(echo_sequence, None)
            if sent_record is None:
                echo_malformed += 1
                continue
            acknowledged.add(echo_sequence)
            actual_send_ns, phase = sent_record
            rtt_ns = received_ns - actual_send_ns
            if rtt_ns < 0:
                echo_malformed += 1
            elif phase == PHASE_MEASUREMENT:
                measurement_rtt_ns.append(rtt_ns)
            else:
                warmup_rtt_count += 1

    while time.monotonic_ns() < measurement_end_ns:
        now_ns = time.monotonic_ns()
        sent_one_due_slot = False
        while rate is not None and next_target <= now_ns and next_target < measurement_end_ns:
            if sequence > MAX_SEQUENCE:
                raise RuntimeError("sequence number exhausted")
            phase = PHASE_WARMUP if next_target < warmup_end_ns else PHASE_MEASUREMENT
            phase_name = "warmup" if phase == PHASE_WARMUP else "measurement"
            subsequent_target = _target_ns(start_ns, offset_ns, index + 1, rate)
            is_probe = probe_every_n is not None and index % probe_every_n == 0
            # An expired slot is recorded and skipped.  Never emit a catch-up
            # burst: at most the newest due slot is attempted in this loop.
            if subsequent_target <= now_ns:
                missed_deadlines[phase_name] += 1
                if is_probe:
                    missed_probe_deadlines[phase_name] += 1
                sequence += 1
                index += 1
                next_target = subsequent_target
                continue
            actual_send_ns = time.monotonic_ns()
            payload = _make_payload(
                args.packet_size,
                class_code,
                phase,
                sequence,
                next_target,
                actual_send_ns,
                rtt_probe=is_probe,
            )
            try:
                written = sock.sendto(payload, target)
            except (BlockingIOError, OSError):
                send_errors += 1
                send_errors_by_phase[phase_name] += 1
            else:
                if written != args.packet_size:
                    send_errors += 1
                    send_errors_by_phase[phase_name] += 1
                else:
                    sent[phase_name]["packets"] += 1
                    sent[phase_name]["bytes"] += written
                    if is_probe:
                        sent[phase_name]["rtt_probe_packets"] += 1
                    send_lateness_by_phase_ns[phase_name].append(
                        max(0, actual_send_ns - next_target)
                    )
                    if is_probe:
                        outstanding[sequence] = (actual_send_ns, phase)
            sequence += 1
            index += 1
            sent_one_due_slot = True
            next_target = subsequent_target
            now_ns = time.monotonic_ns()
            break
        receive_echoes()
        if rate is None:
            time.sleep(min(0.01, max(0.0, (measurement_end_ns - now_ns) / 1e9)))
        elif next_target > now_ns:
            if args.traffic_class == "benign":
                select.select([sock], [], [], min(0.001, (next_target - now_ns) / 1e9))
            else:
                _sleep_until(next_target)
        elif sent_one_due_slot:
            # Yield after one due attempt so a delayed process cannot collapse
            # many logical arrivals into an artificial same-timestamp burst.
            time.sleep(0)

    # The outer clock check can cross measurement_end after the final send or
    # yield while scheduled targets remain unclassified. Account every
    # remaining target as missed so the declared schedule always satisfies
    # planned = sent + missed + send_errors. These slots are never transmitted
    # and therefore cannot create a catch-up burst.
    while rate is not None and index < planned_total:
        phase = PHASE_WARMUP if next_target < warmup_end_ns else PHASE_MEASUREMENT
        phase_name = "warmup" if phase == PHASE_WARMUP else "measurement"
        is_probe = probe_every_n is not None and index % probe_every_n == 0
        missed_deadlines[phase_name] += 1
        if is_probe:
            missed_probe_deadlines[phase_name] += 1
        sequence += 1
        index += 1
        next_target = _target_ns(start_ns, offset_ns, index, rate)

    while time.monotonic_ns() < drain_end_ns:
        receive_echoes()
        time.sleep(0.001)
    receive_echoes()
    udp_after = udp_snmp_counters()
    sock.close()
    all_lateness = (
        send_lateness_by_phase_ns["warmup"]
        + send_lateness_by_phase_ns["measurement"]
    )
    measurement_probe_sent = sent["measurement"]["rtt_probe_packets"]
    measurement_probe_received = len(measurement_rtt_ns)
    measurement_probe_unacked = sum(
        phase == PHASE_MEASUREMENT for _sent_ns, phase in outstanding.values()
    )
    result = {
        "schema_version": "matched-scheduler-traffic-1.0",
        "role": "sender",
        "traffic_class": args.traffic_class,
        "final": True,
        "seed": args.seed,
        "tos": tos,
        "source_port": args.source_port,
        "target_port": args.target_port,
        "start_monotonic_ns": start_ns,
        "start_signal_received_monotonic_ns": start_signal_received_ns,
        "warmup_end_monotonic_ns": warmup_end_ns,
        "measurement_end_monotonic_ns": measurement_end_ns,
        "end_monotonic_ns": time.monotonic_ns(),
        "target_rate_pps": args.rate_pps,
        "packet_size_bytes": args.packet_size,
        "schedule_offset_ns": offset_ns,
        "planned_packets": {
            "warmup": planned_warmup,
            "measurement": planned_measurement,
            "total": planned_total,
        },
        "missed_deadline_policy": "skip_expired_slot_never_catch_up",
        "missed_deadlines": {
            **missed_deadlines,
            "total": sum(missed_deadlines.values()),
            "rtt_probes": missed_probe_deadlines,
        },
        "sent": sent,
        "send_errors": send_errors,
        "send_errors_by_phase": send_errors_by_phase,
        "send_lateness_by_phase": {
            phase_name: {
                "sample_count": len(values),
                "mean_ns": sum(values) / len(values) if values else None,
                "max_ns": max(values) if values else None,
                "p99_ns": nearest_rank_percentile(values, 0.99),
            }
            for phase_name, values in send_lateness_by_phase_ns.items()
        },
        "send_lateness_samples_by_phase": {
            phase_name: encode_lateness_samples(values)
            for phase_name, values in send_lateness_by_phase_ns.items()
        },
        "send_lateness_sample_count": len(all_lateness),
        "send_lateness_mean_ns": (
            sum(all_lateness) / len(all_lateness)
            if all_lateness
            else None
        ),
        "send_lateness_max_ns": max(all_lateness) if all_lateness else None,
        "send_lateness_p99_ns": nearest_rank_percentile(all_lateness, 0.99),
        "measurement_rtt_ns": measurement_rtt_ns,
        "measurement_rtt_p99_ns": nearest_rank_percentile(measurement_rtt_ns, 0.99),
        "warmup_rtt_count": warmup_rtt_count,
        "echo_unacknowledged_packets": len(outstanding),
        "measurement_echo_unacknowledged_packets": measurement_probe_unacked,
        "measurement_echo_received_packets": measurement_probe_received,
        "rtt_probe_policy": "fixed_rate_flagged_subset_echo_only",
        "rtt_probes": {
            "target_rate_pps": (
                args.rtt_probe_rate_pps if args.traffic_class == "benign" else 0.0
            ),
            "selection_every_n_benign_packets": probe_every_n,
            "planned": planned_probes,
            "sent": {
                phase: sent[phase]["rtt_probe_packets"]
                for phase in ("warmup", "measurement")
            },
            "measurement_received": measurement_probe_received,
            "measurement_unacknowledged": measurement_probe_unacked,
            "measurement_loss_packets": max(
                0, measurement_probe_sent - measurement_probe_received
            ),
            "measurement_loss_fraction": (
                (measurement_probe_sent - measurement_probe_received)
                / measurement_probe_sent
                if measurement_probe_sent
                else None
            ),
            "measurement_conditional_rtt_p99_ns": nearest_rank_percentile(
                measurement_rtt_ns, 0.99
            ),
        },
        "echo_malformed": echo_malformed,
        "echo_wrong_class": echo_wrong_class,
        "echo_duplicates": echo_duplicates,
        "echo_nonprobe": echo_nonprobe,
        "rtt_loss_reason": None if measurement_rtt_ns else "no_valid_measurement_echo_received",
        "requested_socket_buffer_bytes": args.socket_buffer_bytes,
        "actual_socket_buffers": actual_buffers,
        "socket_rxq_overflow_drops": socket_rxq_overflow_drops,
        "udp_snmp_before": udp_before,
        "udp_snmp_after": udp_after,
        "udp_snmp_delta": udp_snmp_delta(udp_before, udp_after),
        "cpu_affinity": affinity,
        "process_usage": process_usage(),
    }
    print(json.dumps(result, sort_keys=True, allow_nan=False), flush=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="role", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--start-monotonic-ns",
        type=int,
        help="direct-test start; omitted in campaigns, which signal after readiness",
    )
    common.add_argument("--warmup-s", type=float, required=True)
    common.add_argument("--measurement-s", type=float, required=True)
    common.add_argument("--drain-s", type=float, required=True)
    common.add_argument("--packet-size", type=int, required=True)
    common.add_argument("--socket-buffer-bytes", type=int, required=True)
    common.add_argument("--cpu-id", type=int, required=True)

    receiver = subparsers.add_parser("receiver", parents=[common])
    receiver.add_argument("--bind-ip", required=True)
    receiver.add_argument("--port", type=int, required=True)

    sender = subparsers.add_parser("sender", parents=[common])
    sender.add_argument("--bind-ip", required=True)
    sender.add_argument("--target-ip", required=True)
    sender.add_argument("--source-port", type=int, required=True)
    sender.add_argument("--target-port", type=int, required=True)
    sender.add_argument("--traffic-class", choices=sorted(CLASS_CODES), required=True)
    sender.add_argument("--rate-pps", type=float, required=True)
    sender.add_argument("--rtt-probe-rate-pps", type=float, required=True)
    sender.add_argument("--seed", type=int, required=True)
    sender.add_argument("--fast-tos", type=int, required=True)
    sender.add_argument("--suspicious-tos", type=int, required=True)
    return parser


def validate_args(args: argparse.Namespace) -> None:
    require_finite_nonnegative(args.warmup_s, "warmup-s", positive=True)
    require_finite_nonnegative(args.measurement_s, "measurement-s", positive=True)
    require_finite_nonnegative(args.drain_s, "drain-s", positive=True)
    if (
        args.start_monotonic_ns is not None
        and args.start_monotonic_ns <= 0
    ) or args.packet_size < HEADER.size:
        raise ValueError("start-monotonic-ns and packet-size must be valid and positive")
    if args.socket_buffer_bytes <= 0:
        raise ValueError("socket-buffer-bytes must be positive")
    if args.role == "sender":
        require_finite_nonnegative(args.rate_pps, "rate-pps")
        require_finite_nonnegative(
            args.rtt_probe_rate_pps, "rtt-probe-rate-pps", positive=True
        )
        if not 0 <= args.fast_tos <= 255 or not 0 <= args.suspicious_tos <= 255:
            raise ValueError("TOS values must be bytes")


def main() -> None:
    args = build_parser().parse_args()
    try:
        validate_args(args)
        if args.role == "receiver":
            run_receiver(args)
        else:
            run_sender(args)
    except Exception as error:  # fail closed, with a machine-readable terminal record
        print(
            json.dumps(
                {
                    "schema_version": "matched-scheduler-traffic-1.0",
                    "role": args.role,
                    "final": True,
                    "error": f"{type(error).__name__}: {error}",
                },
                sort_keys=True,
            ),
            flush=True,
        )
        raise


if __name__ == "__main__":
    main()
