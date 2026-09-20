#!/usr/bin/env python3
"""traffic_gen.py -- benign and attack-family UDP traffic generator for the
isolated testbed. Must be run via nsenter into the anchor namespace created
by setup_netns.sh, exactly like every other testbed/ script; it does not
create or join namespaces itself.

Modes implement the traffic families frozen in
configs/confirmatory_v2.json's "traffic" block:
  benign              -- udp_constant_bit_rate, TOS 0x10 (FAST-marked)
  flood               -- high fixed aggregate rate, TOS 0x00 (QUAR-marked)
  low_and_slow        -- same rate/timing as benign but TOS 0x00
  burst_on_off        -- alternating burst_on_s/burst_off_s, TOS 0x00
  five_tuple_rotation -- rebinds source port every rotation_interval_s
  short_flow_explosion-- many 1-3 packet flows, new socket per flow

TOS marking is an explicit oracle label standing in for the XDP
classifier's redirect decision, which is not attached yet (no CAP_BPF --
see SERVER_ENVIRONMENT_REPORT.md). This is the same "oracle mode" pattern
already used elsewhere in this project as an explicitly labeled ceiling,
never presented as classifier output.

Safety: every target/bind address is checked against the TEST-NET-2 block
(198.51.100.0/24, RFC 5737, never validly routable) before any socket is
created. This is defense in depth on top of the namespace isolation itself
-- namespace isolation is what actually prevents reaching anything else,
this check just makes a mistake here loud instead of silently doing
something unintended.
"""

import argparse
import ipaddress
import json
import random
import socket
import sys
import time

ALLOWED_SUBNET = ipaddress.ip_network("198.51.100.0/24")

TOS_FAST = 0x10
TOS_QUARANTINE = 0x00

PACKET_SIZE_MIXED = {64: 0.3, 512: 0.4, 1500: 0.3}  # configs/confirmatory_v2.json


def require_allowed(ip_str: str, label: str) -> None:
    addr = ipaddress.ip_address(ip_str)
    if addr not in ALLOWED_SUBNET:
        sys.stderr.write(
            f"REFUSING: {label} address {ip_str} is outside the allowed "
            f"testbed subnet {ALLOWED_SUBNET} (RFC 5737 TEST-NET-2). "
            f"This generator only ever talks to addresses inside the "
            f"isolated veth pairs created by setup_netns.sh.\n"
        )
        sys.exit(1)


def pick_size(fixed: int | None) -> int:
    if fixed is not None:
        return fixed
    r = random.random()
    acc = 0.0
    for size, weight in PACKET_SIZE_MIXED.items():
        acc += weight
        if r <= acc:
            return size
    return 512


def make_socket(bind_ip: str, bind_port: int, tos: int) -> socket.socket:
    require_allowed(bind_ip, "bind")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, tos)
    s.bind((bind_ip, bind_port))
    return s


def run_server(args: argparse.Namespace) -> None:
    require_allowed(args.bind_ip, "bind")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((args.bind_ip, args.port))
    s.settimeout(0.5)
    deadline = time.monotonic() + args.duration_s if args.duration_s > 0 else None
    packets = 0
    total_bytes = 0
    # Delivered accounting split by the sender-embedded marker byte (see
    # send_burst): this is the receiver-side complement of the sender's TOS
    # mark, letting a single shared server separate "benign delivered" from
    # "attack delivered" (leakage) without needing IP_RECVTOS/ancillary-data
    # parsing. Both marks are oracle labels the traffic generator itself
    # assigns, not a live classifier decision -- see module docstring.
    benign_packets = 0
    benign_bytes = 0
    attack_packets = 0
    attack_bytes = 0
    last_report = time.monotonic()
    while deadline is None or time.monotonic() < deadline:
        try:
            data, addr = s.recvfrom(65535)
        except socket.timeout:
            pass
        else:
            packets += 1
            total_bytes += len(data)
            marker = data[0] if data else 0xFF
            if marker == TOS_FAST:
                benign_packets += 1
                benign_bytes += len(data)
            elif marker == TOS_QUARANTINE:
                attack_packets += 1
                attack_bytes += len(data)
        now = time.monotonic()
        if now - last_report >= 1.0:
            print(
                json.dumps(
                    {
                        "ts_ms": int(time.time() * 1000),
                        "role": "server",
                        "packets_total": packets,
                        "bytes_total": total_bytes,
                        "benign_packets": benign_packets,
                        "benign_bytes": benign_bytes,
                        "attack_packets": attack_packets,
                        "attack_bytes": attack_bytes,
                    }
                ),
                flush=True,
            )
            last_report = now
    print(
        json.dumps(
            {
                "ts_ms": int(time.time() * 1000),
                "role": "server",
                "final": True,
                "packets_total": packets,
                "bytes_total": total_bytes,
                "benign_packets": benign_packets,
                "benign_bytes": benign_bytes,
                "attack_packets": attack_packets,
                "attack_bytes": attack_bytes,
            }
        ),
        flush=True,
    )


def send_burst(sock: socket.socket, target: tuple, size: int, tos: int) -> int:
    # First byte carries the sender's oracle label (mirrors the IP TOS byte
    # used for tc classification) so a shared receiver can separate benign
    # from attack delivery -- see run_server. size is a floor, not exact:
    # the marker replaces byte 0 rather than adding to the requested size,
    # so wire size still matches the requested packet-size distribution.
    size = max(size, 1)
    payload = bytes([tos]) + bytes(size - 1)
    sock.sendto(payload, target)
    return size


def run_client(args: argparse.Namespace) -> None:
    require_allowed(args.target_ip, "target")
    require_allowed(args.bind_ip, "bind")
    target = (args.target_ip, args.port)
    tos = TOS_FAST if args.mode == "benign" else TOS_QUARANTINE

    packets_sent = 0
    bytes_sent = 0
    t_start = time.monotonic()
    deadline = t_start + args.duration_s

    def report(event: str = "") -> None:
        print(
            json.dumps(
                {
                    "ts_ms": int(time.time() * 1000),
                    "role": "client",
                    "mode": args.mode,
                    "tos": tos,
                    "packets_sent": packets_sent,
                    "bytes_sent": bytes_sent,
                    "event": event,
                }
            ),
            flush=True,
        )

    if args.mode in ("benign", "low_and_slow"):
        s = make_socket(args.bind_ip, 0, tos)
        interval = 1.0 / args.rate_pps if args.rate_pps > 0 else 0.01
        while time.monotonic() < deadline:
            size = pick_size(args.packet_size)
            bytes_sent += send_burst(s, target, size, tos)
            packets_sent += 1
            time.sleep(interval)
        s.close()

    elif args.mode == "flood":
        s = make_socket(args.bind_ip, 0, tos)
        interval = 1.0 / args.rate_pps if args.rate_pps > 0 else 0.0
        while time.monotonic() < deadline:
            size = pick_size(args.packet_size)
            bytes_sent += send_burst(s, target, size, tos)
            packets_sent += 1
            if interval > 0:
                time.sleep(interval)
        s.close()

    elif args.mode == "burst_on_off":
        s = make_socket(args.bind_ip, 0, tos)
        interval = 1.0 / args.rate_pps if args.rate_pps > 0 else 0.01
        on_s = args.burst_on_s
        off_s = args.burst_off_s
        while time.monotonic() < deadline:
            burst_end = min(time.monotonic() + on_s, deadline)
            while time.monotonic() < burst_end:
                size = pick_size(args.packet_size)
                bytes_sent += send_burst(s, target, size, tos)
                packets_sent += 1
                time.sleep(interval)
            report("burst_off_start")
            time.sleep(min(off_s, max(0.0, deadline - time.monotonic())))
        s.close()

    elif args.mode == "five_tuple_rotation":
        rotation_s = args.rotation_interval_s
        interval = 1.0 / args.rate_pps if args.rate_pps > 0 else 0.01
        while time.monotonic() < deadline:
            s = make_socket(args.bind_ip, 0, tos)
            rot_end = min(time.monotonic() + rotation_s, deadline)
            while time.monotonic() < rot_end:
                size = pick_size(args.packet_size)
                bytes_sent += send_burst(s, target, size, tos)
                packets_sent += 1
                time.sleep(interval)
            s.close()
            report("port_rotated")

    elif args.mode == "short_flow_explosion":
        lo, hi = args.short_flow_packets
        while time.monotonic() < deadline:
            s = make_socket(args.bind_ip, 0, tos)
            n = random.randint(lo, hi)
            for _ in range(n):
                size = pick_size(args.packet_size)
                bytes_sent += send_burst(s, target, size, tos)
                packets_sent += 1
            s.close()
            time.sleep(0.01)

    else:
        sys.stderr.write(f"unknown mode: {args.mode}\n")
        sys.exit(2)

    report("final")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="role", required=True)

    srv = sub.add_parser("server")
    srv.add_argument("--bind-ip", required=True)
    srv.add_argument("--port", type=int, required=True)
    srv.add_argument("--duration-s", type=float, default=10.0)

    cli = sub.add_parser("client")
    cli.add_argument("--bind-ip", required=True)
    cli.add_argument("--target-ip", required=True)
    cli.add_argument("--port", type=int, required=True)
    cli.add_argument(
        "--mode",
        required=True,
        choices=[
            "benign",
            "flood",
            "low_and_slow",
            "burst_on_off",
            "five_tuple_rotation",
            "short_flow_explosion",
        ],
    )
    cli.add_argument("--duration-s", type=float, default=10.0)
    cli.add_argument("--rate-pps", type=float, default=50.0)
    cli.add_argument("--packet-size", type=int, default=None, help="fixed size; omit for the frozen mixed distribution")
    cli.add_argument("--burst-on-s", type=float, default=5.0)
    cli.add_argument("--burst-off-s", type=float, default=5.0)
    cli.add_argument("--rotation-interval-s", type=float, default=2.0)
    cli.add_argument("--short-flow-packets", type=int, nargs=2, default=[1, 3])

    args = p.parse_args()
    if args.role == "server":
        run_server(args)
    else:
        run_client(args)


if __name__ == "__main__":
    main()
