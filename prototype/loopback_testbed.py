#!/usr/bin/env python3
"""Controlled user-space localhost testbed for capacity isolation.

This program is deliberately not XDP/eBPF, kernel forwarding, optical
hardware, or line-rate evidence.  It uses an oracle ground-truth label to
route application frames into finite user-space service domains and then
delivers admitted frames over real TCP or UDP sockets bound to 127.0.0.1.
"""

from __future__ import annotations

import argparse
import hashlib
import heapq
import json
import math
import os
import platform
import queue
import random
import socket
import statistics
import struct
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Any, Iterable, Sequence


SCHEMA_VERSION = "loopback-2.0"
STUDY_CONFIG_SCHEMA_VERSION = "loopback-study-config-1.0"
LOOPBACK_HOST = "127.0.0.1"
ORACLE_ROUTING_POLICY = "oracle_ground_truth_label"
FRAME_HEADER = struct.Struct("!IBBQQQI")
LENGTH_HEADER = struct.Struct("!I")
MAX_SEQUENCE = (1 << 32) - 1
UDP_MAX_APPLICATION_FRAME_BYTES = 65_507
TCP_MAX_APPLICATION_FRAME_BYTES = 65_535
LABEL_CODE = {"benign": 0, "attack": 1}
LABEL_NAME = {value: key for key, value in LABEL_CODE.items()}
ROUTE_CODE = {"shared": 0, "fast": 1, "quarantine": 2}
ROUTE_NAME = {value: key for key, value in ROUTE_CODE.items()}


@dataclass(frozen=True)
class PrototypeConfig:
    """One experimental condition and seed.

    Queue sizes are waiting-room capacities: the application frame currently
    in serialized service is not counted against ``*_buffer_packets``.  The
    defaults provide equal total configured resources in both modes:
    ``shared == fast + quarantine`` for capacity and waiting-room slots.
    """

    seed: int = 1009
    protocol: str = "udp"
    mode: str = "isolated"
    routing_policy: str = ORACLE_ROUTING_POLICY
    duration_s: float = 0.40
    measurement_start_s: float = 0.05
    benign_offered_pps: float = 160.0
    suspicious_offered_pps: float = 400.0
    shared_capacity_pps: float = 320.0
    fast_capacity_pps: float = 240.0
    quarantine_capacity_pps: float = 80.0
    shared_buffer_packets: int = 96
    fast_buffer_packets: int = 64
    quarantine_buffer_packets: int = 32
    quarantine_dwell_s: float = 0.025
    packet_size_bytes: int = 256
    drain_timeout_s: float = 4.0

    def validate(self) -> None:
        if not isinstance(self.seed, int) or isinstance(self.seed, bool):
            raise ValueError("seed must be an integer")
        if self.protocol not in {"udp", "tcp"}:
            raise ValueError("protocol must be udp or tcp")
        if self.mode not in {"shared", "isolated"}:
            raise ValueError("mode must be shared or isolated")
        if self.routing_policy != ORACLE_ROUTING_POLICY:
            raise ValueError(
                f"routing_policy must be {ORACLE_ROUTING_POLICY!r}; this testbed "
                "does not implement a learned classifier"
            )

        finite_fields = (
            "duration_s",
            "measurement_start_s",
            "benign_offered_pps",
            "suspicious_offered_pps",
            "shared_capacity_pps",
            "fast_capacity_pps",
            "quarantine_capacity_pps",
            "quarantine_dwell_s",
            "drain_timeout_s",
        )
        for name in finite_fields:
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"{name} must be a finite number")
            if not math.isfinite(float(value)):
                raise ValueError(f"{name} must be finite")

        if self.duration_s <= 0.0:
            raise ValueError("duration_s must be positive")
        if not 0.0 <= self.measurement_start_s < self.duration_s:
            raise ValueError("measurement_start_s must be inside the run")
        for name in ("benign_offered_pps", "suspicious_offered_pps"):
            if getattr(self, name) < 0.0:
                raise ValueError(f"{name} cannot be negative")
        for name in (
            "shared_capacity_pps",
            "fast_capacity_pps",
            "quarantine_capacity_pps",
        ):
            if getattr(self, name) <= 0.0:
                raise ValueError(f"{name} must be positive")
        if self.quarantine_dwell_s < 0.0:
            raise ValueError("quarantine_dwell_s cannot be negative")
        if self.drain_timeout_s <= 0.0:
            raise ValueError("drain_timeout_s must be positive")

        for name in (
            "shared_buffer_packets",
            "fast_buffer_packets",
            "quarantine_buffer_packets",
        ):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ValueError(f"{name} must be an integer of at least one")
        if (
            not isinstance(self.packet_size_bytes, int)
            or isinstance(self.packet_size_bytes, bool)
        ):
            raise ValueError("packet_size_bytes must be an integer")
        if self.packet_size_bytes < FRAME_HEADER.size:
            raise ValueError(
                f"packet_size_bytes must be at least {FRAME_HEADER.size}"
            )
        maximum = (
            UDP_MAX_APPLICATION_FRAME_BYTES
            if self.protocol == "udp"
            else TCP_MAX_APPLICATION_FRAME_BYTES
        )
        if self.packet_size_bytes > maximum:
            raise ValueError(
                f"packet_size_bytes exceeds the {self.protocol.upper()} testbed "
                f"limit of {maximum}"
            )


@dataclass(frozen=True)
class StudyConfig:
    """Complete, strict input for a multi-condition loopback study."""

    schema_version: str
    study_id: str
    study_role: str
    seeds: int
    seed_start: int
    protocols: tuple[str, ...]
    modes: tuple[str, ...]
    suspicious_offered_pps: tuple[float, ...]
    execution_order_seed: int
    routing_policy: str
    duration_s: float
    measurement_start_s: float
    benign_offered_pps: float
    shared_capacity_pps: float
    fast_capacity_pps: float
    quarantine_capacity_pps: float
    shared_buffer_packets: int
    fast_buffer_packets: int
    quarantine_buffer_packets: int
    quarantine_dwell_s: float
    packet_size_bytes: int
    drain_timeout_s: float

    @classmethod
    def from_mapping(cls, payload: Any) -> "StudyConfig":
        if not isinstance(payload, dict):
            raise ValueError("study config JSON root must be an object")
        expected = {field.name for field in fields(cls)}
        actual = set(payload)
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        if missing or unknown:
            details: list[str] = []
            if missing:
                details.append(f"missing keys: {', '.join(missing)}")
            if unknown:
                details.append(f"unknown keys: {', '.join(unknown)}")
            raise ValueError("invalid study config keys; " + "; ".join(details))

        normalized = dict(payload)
        for name in ("protocols", "modes", "suspicious_offered_pps"):
            value = normalized[name]
            if not isinstance(value, list):
                raise ValueError(f"{name} must be a JSON array")
            normalized[name] = tuple(value)
        try:
            config = cls(**normalized)
        except TypeError as exc:
            raise ValueError(f"invalid study config: {exc}") from exc
        config.validate()
        return config

    def validate(self) -> None:
        if self.schema_version != STUDY_CONFIG_SCHEMA_VERSION:
            raise ValueError(
                f"schema_version must be {STUDY_CONFIG_SCHEMA_VERSION!r}"
            )
        if not isinstance(self.study_id, str) or not self.study_id.strip():
            raise ValueError("study_id must be a non-empty string")
        if self.study_role not in {"authoritative", "quick_smoke"}:
            raise ValueError("study_role must be authoritative or quick_smoke")
        if not isinstance(self.seeds, int) or isinstance(self.seeds, bool):
            raise ValueError("seeds must be an integer")
        if self.seeds < 1:
            raise ValueError("seeds must be at least one")
        if not isinstance(self.seed_start, int) or isinstance(self.seed_start, bool):
            raise ValueError("seed_start must be an integer")
        if (
            not isinstance(self.execution_order_seed, int)
            or isinstance(self.execution_order_seed, bool)
        ):
            raise ValueError("execution_order_seed must be an integer")
        if not self.protocols or any(
            not isinstance(value, str) for value in self.protocols
        ):
            raise ValueError("protocols must contain strings")
        if not self.modes or any(not isinstance(value, str) for value in self.modes):
            raise ValueError("modes must contain strings")
        if not self.suspicious_offered_pps:
            raise ValueError("suspicious_offered_pps cannot be empty")
        for value in self.suspicious_offered_pps:
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                or value < 0
            ):
                raise ValueError(
                    "suspicious_offered_pps values must be finite and non-negative"
                )
        for name, values in (
            ("protocols", self.protocols),
            ("modes", self.modes),
            ("suspicious_offered_pps", self.suspicious_offered_pps),
        ):
            if len(set(values)) != len(values):
                raise ValueError(f"{name} cannot contain duplicates")

        for protocol in self.protocols:
            for mode in self.modes:
                for load in self.suspicious_offered_pps:
                    self.prototype_config(
                        seed=self.seed_start,
                        protocol=protocol,
                        mode=mode,
                        load=float(load),
                    ).validate()

        if self.study_role == "authoritative":
            if self.seeds < 30:
                raise ValueError("authoritative study requires at least 30 seeds")
            frozen: dict[str, Any] = {
                "seed_start": 1009,
                "protocols": ("udp", "tcp"),
                "modes": ("shared", "isolated"),
                "suspicious_offered_pps": (0, 160, 400, 800),
                "execution_order_seed": 1729,
                "routing_policy": ORACLE_ROUTING_POLICY,
                "duration_s": 1.2,
                "measurement_start_s": 0.2,
                "benign_offered_pps": 160.0,
                "shared_capacity_pps": 320.0,
                "fast_capacity_pps": 240.0,
                "quarantine_capacity_pps": 80.0,
                "shared_buffer_packets": 96,
                "fast_buffer_packets": 64,
                "quarantine_buffer_packets": 32,
                "quarantine_dwell_s": 0.025,
                "packet_size_bytes": 256,
                "drain_timeout_s": 4.0,
            }
            mismatches = [
                f"{name}={getattr(self, name)!r} (expected {expected!r})"
                for name, expected in frozen.items()
                if getattr(self, name) != expected
            ]
            if mismatches:
                raise ValueError(
                    "authoritative design is frozen; " + "; ".join(mismatches)
                )

    def prototype_config(
        self, seed: int, protocol: str, mode: str, load: float
    ) -> PrototypeConfig:
        return PrototypeConfig(
            seed=seed,
            protocol=protocol,
            mode=mode,
            routing_policy=self.routing_policy,
            duration_s=self.duration_s,
            measurement_start_s=self.measurement_start_s,
            benign_offered_pps=self.benign_offered_pps,
            suspicious_offered_pps=load,
            shared_capacity_pps=self.shared_capacity_pps,
            fast_capacity_pps=self.fast_capacity_pps,
            quarantine_capacity_pps=self.quarantine_capacity_pps,
            shared_buffer_packets=self.shared_buffer_packets,
            fast_buffer_packets=self.fast_buffer_packets,
            quarantine_buffer_packets=self.quarantine_buffer_packets,
            quarantine_dwell_s=self.quarantine_dwell_s,
            packet_size_bytes=self.packet_size_bytes,
            drain_timeout_s=self.drain_timeout_s,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class OfferedPacket:
    sequence: int
    label: str
    planned_offset_s: float
    target_ns: int
    ingress_ns: int
    size_bytes: int


def _json_default(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    raise TypeError(type(value).__name__)


def canonical_json_bytes(payload: Any) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
        default=_json_default,
    ).encode("utf-8")


def object_sha256(payload: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            payload,
            indent=2,
            sort_keys=True,
            allow_nan=False,
            default=_json_default,
        )
        + "\n",
        encoding="utf-8",
    )


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    duplicates: list[str] = []
    for key, value in pairs:
        if key in result:
            duplicates.append(key)
        result[key] = value
    if duplicates:
        raise ValueError(
            "duplicate JSON keys are forbidden: " + ", ".join(sorted(set(duplicates)))
        )
    return result


def _reject_nonfinite_json_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def _portable_source_path(path: Path) -> str:
    resolved = path.resolve()
    project_root = Path(__file__).resolve().parents[1]
    try:
        return resolved.relative_to(project_root).as_posix()
    except ValueError:
        return str(resolved)


def load_study_config(path: Path) -> tuple[StudyConfig, dict[str, Any]]:
    """Load a complete strict JSON config and return content-bound provenance."""

    if not path.exists():
        raise FileNotFoundError(f"study config does not exist: {path}")
    if not path.is_file():
        raise ValueError(f"study config path is not a file: {path}")
    try:
        payload = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_nonfinite_json_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid study config JSON: {exc}") from exc
    config = StudyConfig.from_mapping(payload)
    parsed = config.to_dict()
    provenance = {
        "source_mode": "committed_json_config",
        "path": _portable_source_path(path),
        "file_sha256": file_sha256(path),
        "parsed_config_sha256": object_sha256(parsed),
        "study_id": config.study_id,
        "study_role": config.study_role,
    }
    return config, provenance


def verify_study_config_unchanged(
    path: Path, input_configuration: dict[str, Any]
) -> None:
    """Fail if a file-backed study input changed after the initial load."""

    expected_hash = input_configuration.get("file_sha256")
    if expected_hash is None:
        return
    if not path.is_file():
        raise RuntimeError(f"study config disappeared during the run: {path}")
    observed_hash = file_sha256(path)
    if observed_hash != expected_hash:
        raise RuntimeError(
            "study config changed during the run: "
            f"expected {expected_hash}, observed {observed_hash}"
        )


def _quick_smoke_study_config(
    *,
    seeds: int,
    seed_start: int,
    protocols: Sequence[str],
    modes: Sequence[str],
    loads: Sequence[float],
    duration_s: float,
    measurement_start_s: float,
    dwell_s: float,
    order_seed: int,
) -> StudyConfig:
    defaults = PrototypeConfig()
    config = StudyConfig(
        schema_version=STUDY_CONFIG_SCHEMA_VERSION,
        study_id="cli-quick-smoke",
        study_role="quick_smoke",
        seeds=seeds,
        seed_start=seed_start,
        protocols=tuple(protocols),
        modes=tuple(modes),
        suspicious_offered_pps=tuple(loads),
        execution_order_seed=order_seed,
        routing_policy=defaults.routing_policy,
        duration_s=duration_s,
        measurement_start_s=measurement_start_s,
        benign_offered_pps=defaults.benign_offered_pps,
        shared_capacity_pps=defaults.shared_capacity_pps,
        fast_capacity_pps=defaults.fast_capacity_pps,
        quarantine_capacity_pps=defaults.quarantine_capacity_pps,
        shared_buffer_packets=defaults.shared_buffer_packets,
        fast_buffer_packets=defaults.fast_buffer_packets,
        quarantine_buffer_packets=defaults.quarantine_buffer_packets,
        quarantine_dwell_s=dwell_s,
        packet_size_bytes=defaults.packet_size_bytes,
        drain_timeout_s=defaults.drain_timeout_s,
    )
    config.validate()
    return config


def _probe_macos_architecture() -> dict[str, Any]:
    """Best-effort direct sysctl probe; never infer translation from names."""

    result: dict[str, Any] = {
        "macos_process_translated": None,
        "macos_arm64_capable": None,
        "macos_sysctl_probe_error": None,
    }
    if platform.system() != "Darwin":
        result["macos_sysctl_probe_error"] = "unavailable: host is not macOS"
        return result

    queries = {
        "macos_process_translated": "sysctl.proc_translated",
        "macos_arm64_capable": "hw.optional.arm64",
    }
    errors: list[str] = []
    for output_field, sysctl_name in queries.items():
        try:
            completed = subprocess.run(
                ["/usr/sbin/sysctl", "-n", sysctl_name],
                check=False,
                capture_output=True,
                text=True,
                timeout=2.0,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            errors.append(f"{sysctl_name}: {type(exc).__name__}: {exc}")
            continue
        value = completed.stdout.strip()
        if completed.returncode != 0:
            detail = completed.stderr.strip() or f"exit status {completed.returncode}"
            errors.append(f"{sysctl_name}: {detail}")
        elif value not in {"0", "1"}:
            errors.append(f"{sysctl_name}: unexpected value {value!r}")
        else:
            result[output_field] = value == "1"
    if errors:
        result["macos_sysctl_probe_error"] = "; ".join(errors)
    return result


def runtime_metadata() -> dict[str, Any]:
    kernel_uname = os.uname()
    python_process_machine = platform.machine()
    kernel_machine = kernel_uname.machine
    return {
        "system": kernel_uname.sysname,
        "kernel_release": kernel_uname.release,
        "kernel_version": kernel_uname.version,
        "kernel_machine": kernel_machine,
        "python_process_machine": python_process_machine,
        "architecture_mismatch_or_translation_possible": (
            kernel_machine != python_process_machine
        ),
        "python_process_processor": platform.processor(),
        "platform": platform.platform(),
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "python_compiler": platform.python_compiler(),
        "python_executable_name": Path(sys.executable).name,
        "socket_stack": "IPv4 loopback TCP/UDP via Python standard library",
        **_probe_macos_architecture(),
    }


def dependency_metadata() -> dict[str, Any]:
    return {
        "external_python_packages": [],
        "python_standard_library_modules": sorted(
            [
                "argparse",
                "dataclasses",
                "hashlib",
                "heapq",
                "json",
                "math",
                "os",
                "platform",
                "pathlib",
                "queue",
                "random",
                "socket",
                "statistics",
                "struct",
                "subprocess",
                "sys",
                "threading",
                "time",
                "typing",
            ]
        ),
        "python_version": platform.python_version(),
    }


def percentile(values: Sequence[float], probability: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    index = probability * (len(ordered) - 1)
    low = math.floor(index)
    high = math.ceil(index)
    if low == high:
        return ordered[low]
    weight = index - low
    return ordered[low] * (1.0 - weight) + ordered[high] * weight


def _safe_fraction(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def poisson_schedule(
    rng: random.Random, rate_pps: float, duration_s: float, label: str
) -> list[tuple[float, str]]:
    if rate_pps <= 0.0:
        return []
    result: list[tuple[float, str]] = []
    current = 0.0
    while True:
        current += rng.expovariate(rate_pps)
        if current >= duration_s:
            break
        result.append((current, label))
    return result


def offered_schedule(config: PrototypeConfig) -> list[tuple[float, str]]:
    """Return a deterministic offered schedule shared by paired modes."""

    config.validate()
    rng = random.Random(config.seed)
    events = poisson_schedule(
        rng, config.benign_offered_pps, config.duration_s, "benign"
    )
    events.extend(
        poisson_schedule(
            rng, config.suspicious_offered_pps, config.duration_s, "attack"
        )
    )
    events.sort(key=lambda item: (item[0], item[1]))
    if len(events) > MAX_SEQUENCE + 1:
        raise ValueError("offered schedule exceeds the 32-bit sequence space")
    return events


def _encode_frame(
    packet: OfferedPacket,
    route: str,
    service_ns: int,
    due_ns: int,
) -> bytes:
    if not 0 <= packet.sequence <= MAX_SEQUENCE:
        raise ValueError("sequence is outside the 32-bit frame field")
    if packet.label not in LABEL_CODE:
        raise ValueError(f"unknown label {packet.label!r}")
    if route not in ROUTE_CODE:
        raise ValueError(f"unknown route {route!r}")
    if packet.size_bytes < FRAME_HEADER.size:
        raise ValueError("frame size is shorter than its metadata header")
    if min(packet.ingress_ns, service_ns, due_ns) < 0:
        raise ValueError("frame timestamps must be non-negative")
    header = FRAME_HEADER.pack(
        packet.sequence,
        LABEL_CODE[packet.label],
        ROUTE_CODE[route],
        packet.ingress_ns,
        service_ns,
        due_ns,
        packet.size_bytes,
    )
    return header + bytes(packet.size_bytes - len(header))


def _decode_frame(frame: bytes, receive_ns: int) -> dict[str, Any]:
    if len(frame) < FRAME_HEADER.size:
        raise ValueError("short prototype frame")
    sequence, label_code, route_code, ingress_ns, service_ns, due_ns, size_bytes = (
        FRAME_HEADER.unpack_from(frame)
    )
    if size_bytes != len(frame):
        raise ValueError("prototype frame length mismatch")
    if label_code not in LABEL_NAME:
        raise ValueError(f"unknown label code {label_code}")
    if route_code not in ROUTE_NAME:
        raise ValueError(f"unknown route code {route_code}")
    return {
        "sequence": sequence,
        "label": LABEL_NAME[label_code],
        "route": ROUTE_NAME[route_code],
        "size_bytes": size_bytes,
        "ingress_ns": ingress_ns,
        "service_ns": service_ns,
        "due_ns": due_ns,
        "receive_ns": receive_ns,
    }


class LoopbackTransport:
    """One real TCP or UDP receiver/sender pair, restricted to loopback."""

    def __init__(self, protocol: str, channel: str) -> None:
        if protocol not in {"udp", "tcp"}:
            raise ValueError("protocol must be udp or tcp")
        if channel not in ROUTE_CODE:
            raise ValueError("unknown transport channel")
        self.protocol = protocol
        self.channel = channel
        self.records: list[dict[str, Any]] = []
        self.errors: list[str] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._server: socket.socket | None = None
        self._accepted: socket.socket | None = None
        self._sender: socket.socket | None = None

    def _record_error(self, message: str) -> None:
        with self._lock:
            self.errors.append(message)

    def start(self) -> None:
        if self.protocol == "udp":
            self._server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._server.bind((LOOPBACK_HOST, 0))
            host, port = self._server.getsockname()
            if host != LOOPBACK_HOST:
                raise RuntimeError("receiver escaped loopback")
            self._server.settimeout(0.05)
            self._sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sender.connect((LOOPBACK_HOST, port))
            self._thread = threading.Thread(
                target=self._udp_receive,
                name=f"prototype-udp-receiver-{self.channel}",
                daemon=True,
            )
            self._thread.start()
            return

        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((LOOPBACK_HOST, 0))
        self._server.listen(1)
        self._server.settimeout(1.0)
        host, port = self._server.getsockname()
        if host != LOOPBACK_HOST:
            raise RuntimeError("receiver escaped loopback")
        self._sender = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sender.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self._sender.connect((LOOPBACK_HOST, port))
        self._accepted, peer = self._server.accept()
        if peer[0] != LOOPBACK_HOST:
            raise RuntimeError("non-loopback TCP peer")
        self._accepted.settimeout(0.05)
        self._thread = threading.Thread(
            target=self._tcp_receive,
            name=f"prototype-tcp-receiver-{self.channel}",
            daemon=True,
        )
        self._thread.start()

    def _append_frame(self, frame: bytes) -> None:
        try:
            record = _decode_frame(frame, time.monotonic_ns())
            record["transport_channel"] = self.channel
            with self._lock:
                self.records.append(record)
        except Exception as exc:  # pragma: no cover - defensive receiver audit
            self._record_error(f"{type(exc).__name__}: {exc}")

    def _udp_receive(self) -> None:
        assert self._server is not None
        while not self._stop.is_set():
            try:
                frame, peer = self._server.recvfrom(UDP_MAX_APPLICATION_FRAME_BYTES)
            except socket.timeout:
                continue
            except OSError:
                break
            if peer[0] != LOOPBACK_HOST:
                self._record_error("discarded non-loopback UDP peer")
                continue
            self._append_frame(frame)

    def _recv_exact(self, connection: socket.socket, size: int) -> bytes | None:
        chunks: list[bytes] = []
        remaining = size
        while remaining and not self._stop.is_set():
            try:
                block = connection.recv(remaining)
            except socket.timeout:
                continue
            except OSError:
                return None
            if not block:
                return None
            chunks.append(block)
            remaining -= len(block)
        return b"".join(chunks) if remaining == 0 else None

    def _tcp_receive(self) -> None:
        assert self._accepted is not None
        while not self._stop.is_set():
            length_bytes = self._recv_exact(self._accepted, LENGTH_HEADER.size)
            if length_bytes is None:
                break
            (length,) = LENGTH_HEADER.unpack(length_bytes)
            if length < FRAME_HEADER.size or length > TCP_MAX_APPLICATION_FRAME_BYTES:
                self._record_error(f"invalid TCP frame length {length}")
                break
            frame = self._recv_exact(self._accepted, length)
            if frame is None:
                break
            self._append_frame(frame)

    def send(self, frame: bytes) -> None:
        assert self._sender is not None
        if self.protocol == "udp":
            sent = self._sender.send(frame)
            if sent != len(frame):
                raise RuntimeError("partial UDP send")
        else:
            self._sender.sendall(LENGTH_HEADER.pack(len(frame)) + frame)

    def record_count(self) -> int:
        with self._lock:
            return len(self.records)

    def snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(record) for record in self.records]

    def error_snapshot(self) -> list[str]:
        with self._lock:
            return list(self.errors)

    def close(self) -> None:
        # The trial waits for dispatch and receipt before this method.  This
        # grace period only lets a receiver leave its current syscall.
        deadline = time.monotonic() + 0.02
        while time.monotonic() < deadline:
            time.sleep(0.005)
        self._stop.set()
        for endpoint in (self._sender, self._accepted, self._server):
            if endpoint is not None:
                try:
                    endpoint.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                endpoint.close()
        if self._thread is not None:
            self._thread.join(timeout=0.5)


class DelayDispatcher:
    """Release serviced frames after dwell, separately for one route."""

    def __init__(self, route: str, transport: LoopbackTransport) -> None:
        if route != transport.channel:
            raise ValueError("dispatcher route must match its transport channel")
        self.route = route
        self.transport = transport
        self._condition = threading.Condition()
        self._heap: list[tuple[int, int, OfferedPacket, int]] = []
        self._counter = 0
        self._active_send = False
        self._stopping = False
        self.peak_dwell_heap_frames = 0
        self.send_errors: list[str] = []
        self.dispatch_records: list[dict[str, Any]] = []
        self._thread = threading.Thread(
            target=self._run,
            name=f"prototype-delay-dispatcher-{route}",
            daemon=True,
        )

    def start(self) -> None:
        self._thread.start()

    def schedule(
        self, packet: OfferedPacket, service_ns: int, dwell_s: float
    ) -> None:
        due_ns = service_ns + int(round(dwell_s * 1_000_000_000))
        with self._condition:
            self._counter += 1
            heapq.heappush(
                self._heap,
                (due_ns, self._counter, packet, service_ns),
            )
            self.peak_dwell_heap_frames = max(
                self.peak_dwell_heap_frames, len(self._heap)
            )
            self._condition.notify_all()

    def _run(self) -> None:
        while True:
            with self._condition:
                while not self._heap and not self._stopping:
                    self._condition.wait()
                if not self._heap and self._stopping:
                    return
                due_ns, _, packet, service_ns = self._heap[0]
                wait_s = (due_ns - time.monotonic_ns()) / 1_000_000_000
                if wait_s > 0.0:
                    self._condition.wait(timeout=wait_s)
                    continue
                heapq.heappop(self._heap)
                self._active_send = True

            send_start_ns = time.monotonic_ns()
            sent = False
            error: str | None = None
            try:
                self.transport.send(
                    _encode_frame(packet, self.route, service_ns, due_ns)
                )
                sent = True
            except Exception as exc:  # pragma: no cover - OS transport failure
                error = f"{type(exc).__name__}: {exc}"
            send_end_ns = time.monotonic_ns()
            record = {
                "sequence": packet.sequence,
                "route": self.route,
                "service_ns": service_ns,
                "due_ns": due_ns,
                "send_start_ns": send_start_ns,
                "send_end_ns": send_end_ns,
                "send_lateness_ms": (send_start_ns - due_ns) / 1_000_000,
                "send_duration_ms": (send_end_ns - send_start_ns) / 1_000_000,
                "sent": sent,
                "send_error": error,
            }
            with self._condition:
                self.dispatch_records.append(record)
                if error is not None:
                    self.send_errors.append(error)
                self._active_send = False
                self._condition.notify_all()

    def wait_empty(self, timeout_s: float) -> bool:
        deadline = time.monotonic() + timeout_s
        with self._condition:
            while self._heap or self._active_send:
                remaining = deadline - time.monotonic()
                if remaining <= 0.0:
                    return False
                self._condition.wait(timeout=remaining)
        return True

    def snapshot_records(self) -> list[dict[str, Any]]:
        with self._condition:
            return [dict(record) for record in self.dispatch_records]

    def error_snapshot(self) -> list[str]:
        with self._condition:
            return list(self.send_errors)

    def close(self) -> bool:
        with self._condition:
            self._stopping = True
            self._condition.notify_all()
        self._thread.join(timeout=1.0)
        return not self._thread.is_alive()


class ServiceWorker:
    """Waiting-only finite FIFO plus serialized service for one route."""

    def __init__(
        self,
        route: str,
        capacity_pps: float,
        buffer_packets: int,
        dwell_s: float,
        dispatcher: DelayDispatcher,
    ) -> None:
        if route != dispatcher.route:
            raise ValueError("service route must match dispatcher route")
        self.route = route
        self.capacity_pps = capacity_pps
        self.buffer_packets = buffer_packets
        self.dwell_s = dwell_s
        self.dispatcher = dispatcher
        self.queue: queue.Queue[OfferedPacket | None] = queue.Queue(
            maxsize=buffer_packets
        )
        self.accepted_sequences: list[int] = []
        self.admission_drop_sequences: list[int] = []
        self.service_records: list[dict[str, Any]] = []
        self._state_lock = threading.Lock()
        self._waiting_frames = 0
        self._in_service_frames = 0
        self.peak_waiting_frames = 0
        self.peak_resident_frames = 0
        self._thread = threading.Thread(
            target=self._run, name=f"prototype-service-{route}", daemon=True
        )

    def _update_peaks_locked(self) -> None:
        self.peak_waiting_frames = max(
            self.peak_waiting_frames, self._waiting_frames
        )
        self.peak_resident_frames = max(
            self.peak_resident_frames,
            self._waiting_frames + self._in_service_frames,
        )

    def start(self) -> None:
        self._thread.start()

    def admit(self, packet: OfferedPacket) -> bool:
        with self._state_lock:
            try:
                self.queue.put_nowait(packet)
            except queue.Full:
                self.admission_drop_sequences.append(packet.sequence)
                return False
            self._waiting_frames += 1
            self.accepted_sequences.append(packet.sequence)
            self._update_peaks_locked()
        return True

    def _run(self) -> None:
        interval_ns = int(math.ceil(1_000_000_000 / self.capacity_pps))
        previous_service_ns = 0
        while True:
            packet = self.queue.get()
            if packet is None:
                self.queue.task_done()
                return
            with self._state_lock:
                self._waiting_frames -= 1
                self._in_service_frames = 1
                self._update_peaks_locked()

            target_ns = max(time.monotonic_ns(), previous_service_ns) + interval_ns
            while True:
                remaining_ns = target_ns - time.monotonic_ns()
                if remaining_ns <= 0:
                    break
                time.sleep(remaining_ns / 1_000_000_000)
            service_ns = time.monotonic_ns()
            previous_service_ns = service_ns
            self.service_records.append(
                {
                    "sequence": packet.sequence,
                    "label": packet.label,
                    "route": self.route,
                    "service_ns": service_ns,
                }
            )
            self.dispatcher.schedule(packet, service_ns, self.dwell_s)
            with self._state_lock:
                self._in_service_frames = 0
            self.queue.task_done()

    def finish(self, timeout_s: float) -> bool:
        deadline = time.monotonic() + timeout_s
        while self.queue.unfinished_tasks and time.monotonic() < deadline:
            time.sleep(0.005)
        drained = self.queue.unfinished_tasks == 0
        try:
            self.queue.put_nowait(None)
        except queue.Full:  # pragma: no cover - only possible after timeout
            return False
        self._thread.join(timeout=max(0.1, deadline - time.monotonic()))
        return drained and not self._thread.is_alive()

    def occupancy_summary(self) -> dict[str, Any]:
        with self._state_lock:
            return {
                "waiting_buffer_capacity_frames": self.buffer_packets,
                "buffer_semantics": "waiting-only; in-service and dwell excluded",
                "peak_waiting_frames": self.peak_waiting_frames,
                "peak_resident_frames_waiting_plus_in_service": (
                    self.peak_resident_frames
                ),
                "final_waiting_frames": self._waiting_frames,
                "final_in_service_frames": self._in_service_frames,
            }


def _records_by_unique_sequence(
    records: Sequence[dict[str, Any]],
) -> tuple[dict[int, dict[str, Any]], list[int]]:
    by_sequence: dict[int, dict[str, Any]] = {}
    duplicates: list[int] = []
    for record in records:
        sequence = int(record["sequence"])
        if sequence in by_sequence:
            duplicates.append(sequence)
        else:
            by_sequence[sequence] = record
    return by_sequence, sorted(set(duplicates))


def _latency_summary(records: Sequence[dict[str, Any]]) -> dict[str, Any]:
    values = [
        (record["receive_ns"] - record["ingress_ns"]) / 1_000_000
        for record in records
    ]
    return {
        "sample_count": len(values),
        "p50": percentile(values, 0.50),
        "p95": percentile(values, 0.95),
        "p99": percentile(values, 0.99),
        "mean": statistics.fmean(values) if values else None,
    }


def _measurement_block(
    offered_records: Sequence[dict[str, Any]],
    received_records: Sequence[dict[str, Any]],
    departure_records: Sequence[dict[str, Any]],
    measurement_duration_s: float,
) -> dict[str, Any]:
    offered_sequences = {int(record["sequence"]) for record in offered_records}
    admitted_sequences = {
        int(record["sequence"])
        for record in offered_records
        if record["admitted"]
    }
    delivered_sequences = {
        int(record["sequence"])
        for record in received_records
        if int(record["sequence"]) in offered_sequences
    }
    admission_drops = len(offered_sequences - admitted_sequences)
    delivery_failures = len(admitted_sequences - delivered_sequences)
    end_to_end_losses = admission_drops + delivery_failures
    departure_bytes = sum(int(record["size_bytes"]) for record in departure_records)
    return {
        "ingress_cohort": {
            "selection_clock": "actual_monotonic_ingress_ns",
            "offered_application_frames": len(offered_sequences),
            "offered_application_payload_bytes": sum(
                int(record["size_bytes"]) for record in offered_records
            ),
            "admitted_application_frames": len(admitted_sequences),
            "admission_drop_frames": admission_drops,
            "admission_drop_fraction": _safe_fraction(
                admission_drops, len(offered_sequences)
            ),
            "delivered_application_frames": len(delivered_sequences),
            "delivery_failure_frames": delivery_failures,
            "delivery_failure_fraction_of_admitted": _safe_fraction(
                delivery_failures, len(admitted_sequences)
            ),
            "end_to_end_loss_frames": end_to_end_losses,
            "end_to_end_loss_fraction": _safe_fraction(
                end_to_end_losses, len(offered_sequences)
            ),
            "latency_ms": _latency_summary(received_records),
        },
        "departure_window": {
            "selection_clock": "actual_monotonic_receive_ns",
            "delivered_application_frames": len(departure_records),
            "delivered_application_payload_bytes": departure_bytes,
            "application_frame_rate_fps": (
                len(departure_records) / measurement_duration_s
            ),
            "application_payload_Bps": departure_bytes / measurement_duration_s,
        },
    }


def _condition_identity(config: PrototypeConfig) -> dict[str, Any]:
    identity = asdict(config)
    identity.pop("seed")
    return identity


def _resource_accounting(config: PrototypeConfig) -> dict[str, Any]:
    isolated_capacity = (
        config.fast_capacity_pps + config.quarantine_capacity_pps
    )
    isolated_buffer = (
        config.fast_buffer_packets + config.quarantine_buffer_packets
    )
    return {
        "capacity_pps": {
            "shared": config.shared_capacity_pps,
            "isolated_fast_plus_quarantine": isolated_capacity,
            "equal_total": math.isclose(
                config.shared_capacity_pps,
                isolated_capacity,
                rel_tol=1e-12,
                abs_tol=1e-12,
            ),
        },
        "waiting_buffer_frames": {
            "shared": config.shared_buffer_packets,
            "isolated_fast_plus_quarantine": isolated_buffer,
            "equal_total": config.shared_buffer_packets == isolated_buffer,
        },
        "buffer_semantics": (
            "configured slots count waiting frames only; the one frame in "
            "service and frames in post-service dwell are recorded separately"
        ),
        "dwell_heap_capacity": (
            "unbounded application heap; excluded from matched waiting-slot "
            "totals, with peak occupancy reported per route"
        ),
    }


def _integrity_audit(
    offered_records: Sequence[dict[str, Any]],
    workers: dict[str, ServiceWorker],
    dispatch_records: Sequence[dict[str, Any]],
    received_records: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    offered_by_sequence, offered_duplicates = _records_by_unique_sequence(
        offered_records
    )
    received_by_sequence, received_duplicates = _records_by_unique_sequence(
        received_records
    )
    dispatch_by_sequence, dispatch_duplicates = _records_by_unique_sequence(
        dispatch_records
    )
    service_records = [
        record for worker in workers.values() for record in worker.service_records
    ]
    service_by_sequence, service_duplicates = _records_by_unique_sequence(
        service_records
    )

    accepted = [
        sequence
        for worker in workers.values()
        for sequence in worker.accepted_sequences
    ]
    admission_dropped = [
        sequence
        for worker in workers.values()
        for sequence in worker.admission_drop_sequences
    ]
    offered_set = set(offered_by_sequence)
    accepted_set = set(accepted)
    dropped_set = set(admission_dropped)
    received_set = set(received_by_sequence)
    service_set = set(service_by_sequence)
    dispatch_set = set(dispatch_by_sequence)

    partition_errors: list[str] = []
    if offered_duplicates:
        partition_errors.append("duplicate offered sequence IDs")
    if len(accepted) != len(accepted_set):
        partition_errors.append("duplicate accepted sequence IDs")
    if len(admission_dropped) != len(dropped_set):
        partition_errors.append("duplicate admission-drop sequence IDs")
    if accepted_set & dropped_set:
        partition_errors.append("accepted and admission-drop sets overlap")
    if accepted_set | dropped_set != offered_set:
        partition_errors.append("accepted/drop sets do not partition offered set")
    if service_set != accepted_set:
        partition_errors.append("service set differs from accepted set")
    if service_duplicates:
        partition_errors.append("duplicate service sequence IDs")
    if dispatch_set != service_set:
        partition_errors.append("dispatch set differs from service set")
    if dispatch_duplicates:
        partition_errors.append("duplicate dispatch sequence IDs")
    if received_set - accepted_set:
        partition_errors.append("received set contains non-admitted frames")
    if received_duplicates:
        partition_errors.append("duplicate received sequence IDs")

    metadata_mismatches: list[dict[str, Any]] = []
    fields = ("label", "route", "size_bytes", "ingress_ns")
    for sequence, received in received_by_sequence.items():
        offered = offered_by_sequence.get(sequence)
        service = service_by_sequence.get(sequence)
        dispatch = dispatch_by_sequence.get(sequence)
        if offered is None or service is None or dispatch is None:
            metadata_mismatches.append(
                {"sequence": sequence, "field": "record_linkage"}
            )
            continue
        for field in fields:
            if received[field] != offered[field]:
                metadata_mismatches.append(
                    {"sequence": sequence, "field": field}
                )
        if received["service_ns"] != service["service_ns"]:
            metadata_mismatches.append(
                {"sequence": sequence, "field": "service_ns"}
            )
        if received["due_ns"] != dispatch["due_ns"]:
            metadata_mismatches.append(
                {"sequence": sequence, "field": "due_ns"}
            )
        if received["transport_channel"] != received["route"]:
            metadata_mismatches.append(
                {"sequence": sequence, "field": "transport_channel"}
            )
        if not (
            received["ingress_ns"]
            <= received["service_ns"]
            <= received["due_ns"]
            <= dispatch["send_start_ns"]
            <= received["receive_ns"]
        ):
            metadata_mismatches.append(
                {"sequence": sequence, "field": "timestamp_order"}
            )

    delivery_failure_sequences = sorted(accepted_set - received_set)
    return {
        "offered_sequence_is_contiguous_from_zero": (
            sorted(offered_set) == list(range(len(offered_set)))
        ),
        "offered_sequence_duplicates": offered_duplicates,
        "received_sequence_duplicates": received_duplicates,
        "service_sequence_duplicates": service_duplicates,
        "dispatch_sequence_duplicates": dispatch_duplicates,
        "partition_errors": partition_errors,
        "metadata_mismatches": metadata_mismatches,
        "unexpected_received_sequences": sorted(received_set - accepted_set),
        "delivery_failure_sequences": delivery_failure_sequences,
        "sequence_partition_valid": not partition_errors,
        "exact_received_metadata_valid": not metadata_mismatches,
        "received_sequences_unique": not received_duplicates,
        "exact_sequence_integrity_valid": (
            not partition_errors
            and not offered_duplicates
            and not service_duplicates
            and not dispatch_duplicates
            and not received_duplicates
            and sorted(offered_set) == list(range(len(offered_set)))
        ),
    }


def run_trial(
    config: PrototypeConfig,
    raw_path: Path | None = None,
) -> dict[str, Any]:
    """Execute one live loopback trial and return a v2 summary."""

    config.validate()
    schedule = offered_schedule(config)
    route_names = ["shared"] if config.mode == "shared" else ["fast", "quarantine"]

    # Isolated routes intentionally receive distinct sockets and distinct dwell
    # dispatchers; only the process and host loopback stack are shared.
    transports = {
        route: LoopbackTransport(config.protocol, route) for route in route_names
    }
    for transport in transports.values():
        transport.start()
    dispatchers = {
        route: DelayDispatcher(route, transports[route]) for route in route_names
    }
    for dispatcher in dispatchers.values():
        dispatcher.start()

    if config.mode == "shared":
        workers = {
            "shared": ServiceWorker(
                "shared",
                config.shared_capacity_pps,
                config.shared_buffer_packets,
                0.0,
                dispatchers["shared"],
            )
        }
    else:
        workers = {
            "fast": ServiceWorker(
                "fast",
                config.fast_capacity_pps,
                config.fast_buffer_packets,
                0.0,
                dispatchers["fast"],
            ),
            "quarantine": ServiceWorker(
                "quarantine",
                config.quarantine_capacity_pps,
                config.quarantine_buffer_packets,
                config.quarantine_dwell_s,
                dispatchers["quarantine"],
            ),
        }
    for worker in workers.values():
        worker.start()

    process_cpu_start = time.process_time()
    start_ns = time.monotonic_ns() + 20_000_000
    offered_records: list[dict[str, Any]] = []
    for sequence, (planned_offset_s, label) in enumerate(schedule):
        target_ns = start_ns + int(round(planned_offset_s * 1_000_000_000))
        while True:
            remaining_ns = target_ns - time.monotonic_ns()
            if remaining_ns <= 0:
                break
            time.sleep(remaining_ns / 1_000_000_000)
        ingress_ns = time.monotonic_ns()
        packet = OfferedPacket(
            sequence=sequence,
            label=label,
            planned_offset_s=planned_offset_s,
            target_ns=target_ns,
            ingress_ns=ingress_ns,
            size_bytes=config.packet_size_bytes,
        )
        route = (
            "shared"
            if config.mode == "shared"
            else "fast"
            if label == "benign"
            else "quarantine"
        )
        admitted = workers[route].admit(packet)
        offered_records.append(
            {
                "sequence": sequence,
                "label": label,
                "route": route,
                "routing_policy": config.routing_policy,
                "size_bytes": config.packet_size_bytes,
                "planned_offset_s": planned_offset_s,
                "target_ns": target_ns,
                "ingress_ns": ingress_ns,
                "ingress_offset_s": (ingress_ns - start_ns) / 1_000_000_000,
                "scheduling_slippage_ms": (ingress_ns - target_ns) / 1_000_000,
                "admitted": admitted,
                "admission_drop": not admitted,
            }
        )

    worker_drain_results = {
        route: worker.finish(config.drain_timeout_s)
        for route, worker in workers.items()
    }
    dispatcher_drain_results = {
        route: dispatcher.wait_empty(config.drain_timeout_s)
        for route, dispatcher in dispatchers.items()
    }
    expected_received = sum(
        len(worker.accepted_sequences) for worker in workers.values()
    )
    receive_deadline = time.monotonic() + config.drain_timeout_s
    while (
        sum(transport.record_count() for transport in transports.values())
        < expected_received
        and time.monotonic() < receive_deadline
    ):
        time.sleep(0.005)
    dispatcher_close_results = {
        route: dispatcher.close() for route, dispatcher in dispatchers.items()
    }
    process_cpu_s = time.process_time() - process_cpu_start
    for transport in transports.values():
        transport.close()

    received_records = [
        record for transport in transports.values() for record in transport.snapshot()
    ]
    received_by_sequence, _ = _records_by_unique_sequence(received_records)
    dispatch_records = [
        record
        for dispatcher in dispatchers.values()
        for record in dispatcher.snapshot_records()
    ]
    dispatch_by_sequence, _ = _records_by_unique_sequence(dispatch_records)
    service_records = [
        record for worker in workers.values() for record in worker.service_records
    ]
    service_by_sequence, _ = _records_by_unique_sequence(service_records)

    measurement_start_ns = start_ns + int(
        round(config.measurement_start_s * 1_000_000_000)
    )
    measurement_end_ns = start_ns + int(round(config.duration_s * 1_000_000_000))
    measurement_duration_s = config.duration_s - config.measurement_start_s

    # Reliability and latency use the actual-ingress cohort.  Throughput uses
    # a separate departure window and can therefore include warm-up arrivals.
    ingress_cohort = [
        record
        for record in offered_records
        if measurement_start_ns <= record["ingress_ns"] < measurement_end_ns
    ]
    ingress_cohort_sequences = {
        int(record["sequence"]) for record in ingress_cohort
    }
    ingress_cohort_received = [
        record
        for record in received_records
        if int(record["sequence"]) in ingress_cohort_sequences
    ]
    departure_window = [
        record
        for record in received_records
        if measurement_start_ns <= record["receive_ns"] < measurement_end_ns
    ]

    metrics_by_label: dict[str, Any] = {}
    for label in ("benign", "attack"):
        metrics_by_label[label] = _measurement_block(
            [record for record in ingress_cohort if record["label"] == label],
            [
                record
                for record in ingress_cohort_received
                if record["label"] == label
            ],
            [record for record in departure_window if record["label"] == label],
            measurement_duration_s,
        )

    service_domains: dict[str, Any] = {}
    for route, worker in workers.items():
        measured_services = [
            record["service_ns"]
            for record in worker.service_records
            if record["sequence"] in ingress_cohort_sequences
        ]
        spacings_ms = [
            (later - earlier) / 1_000_000
            for earlier, later in zip(measured_services, measured_services[1:])
        ]
        service_domains[route] = {
            "capacity_pps": worker.capacity_pps,
            "minimum_observed_spacing_ms": (
                min(spacings_ms) if spacings_ms else None
            ),
            "configured_minimum_spacing_ms": 1000.0 / worker.capacity_pps,
            "ingress_cohort_service_count": len(measured_services),
            **worker.occupancy_summary(),
        }

    dispatcher_domains: dict[str, Any] = {}
    for route, dispatcher in dispatchers.items():
        records = dispatcher.snapshot_records()
        lateness = [record["send_lateness_ms"] for record in records]
        durations = [record["send_duration_ms"] for record in records]
        dispatcher_domains[route] = {
            "separate_loopback_transport": True,
            "peak_dwell_heap_frames": dispatcher.peak_dwell_heap_frames,
            "scheduled_frames": len(records),
            "sent_frames": sum(bool(record["sent"]) for record in records),
            "send_failure_frames": sum(not record["sent"] for record in records),
            "send_lateness_ms": {
                "sample_count": len(lateness),
                "p50": percentile(lateness, 0.50),
                "p95": percentile(lateness, 0.95),
                "p99": percentile(lateness, 0.99),
                "max": max(lateness) if lateness else None,
            },
            "send_duration_ms": {
                "sample_count": len(durations),
                "p50": percentile(durations, 0.50),
                "p95": percentile(durations, 0.95),
                "p99": percentile(durations, 0.99),
                "max": max(durations) if durations else None,
            },
        }

    slippage = [record["scheduling_slippage_ms"] for record in ingress_cohort]
    transport_errors = {
        route: transport.error_snapshot() for route, transport in transports.items()
    }
    dispatcher_send_errors = {
        route: dispatcher.error_snapshot()
        for route, dispatcher in dispatchers.items()
    }
    integrity = _integrity_audit(
        offered_records, workers, dispatch_records, received_records
    )
    delivery_failure_count = len(integrity["delivery_failure_sequences"])
    runtime = runtime_metadata()
    dependency = dependency_metadata()
    config_payload = asdict(config)
    condition_identity = _condition_identity(config)

    summary: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "claim_boundary": (
            "unprivileged user-space oracle-routed localhost TCP/UDP testbed; "
            "not XDP/eBPF, kernel forwarding, optical hardware, physical-link, "
            "or line-rate evidence"
        ),
        "routing": {
            "policy": config.routing_policy,
            "oracle": True,
            "decision_input": "ground-truth synthetic benign/attack label",
            "learned_classifier_present": False,
            "isolated_mapping": {
                "benign": "fast",
                "attack": "quarantine",
            },
        },
        "host_runtime": runtime,
        "host_runtime_sha256": object_sha256(runtime),
        "dependencies": dependency,
        "dependencies_sha256": object_sha256(dependency),
        "config": config_payload,
        "config_sha256": object_sha256(config_payload),
        "condition_identity": condition_identity,
        "condition_identity_sha256": object_sha256(condition_identity),
        "resource_accounting": _resource_accounting(config),
        "transport_topology": {
            "protocol": config.protocol,
            "bind_host": LOOPBACK_HOST,
            "channel_count": len(transports),
            "channels": sorted(transports),
            "isolated_routes_use_distinct_transport_and_dispatcher": (
                config.mode == "isolated" and len(transports) == 2
            ),
        },
        "offered_schedule_sha256": object_sha256(schedule),
        "expected_received_application_frames": expected_received,
        "actual_received_application_frames": len(received_records),
        "transport_errors_by_channel": transport_errors,
        "dispatcher_send_errors_by_channel": dispatcher_send_errors,
        "worker_drained_by_route": worker_drain_results,
        "dispatcher_drained_by_route": dispatcher_drain_results,
        "dispatcher_closed_by_route": dispatcher_close_results,
        "integrity": integrity,
        "valid_for_publication_aggregation": (
            all(worker_drain_results.values())
            and all(dispatcher_drain_results.values())
            and all(dispatcher_close_results.values())
            and not any(transport_errors.values())
            and not any(dispatcher_send_errors.values())
            and integrity["exact_sequence_integrity_valid"]
            and integrity["exact_received_metadata_valid"]
            and delivery_failure_count == 0
        ),
        "measurement": {
            "window_definition": {
                "start_offset_s": config.measurement_start_s,
                "end_offset_s": config.duration_s,
                "duration_s": measurement_duration_s,
                "ingress_cohort_uses_actual_ingress_not_planned_schedule": True,
                "departure_throughput_is_a_separate_receive_time_window": True,
            },
            "all": _measurement_block(
                ingress_cohort,
                ingress_cohort_received,
                departure_window,
                measurement_duration_s,
            ),
            "by_label": metrics_by_label,
            "service_domains": service_domains,
            "delay_dispatchers": dispatcher_domains,
            "scheduling_slippage_ms": {
                "sample_count": len(slippage),
                "p50": percentile(slippage, 0.50),
                "p95": percentile(slippage, 0.95),
                "p99": percentile(slippage, 0.99),
                "max": max(slippage) if slippage else None,
            },
            "process_cpu_s": process_cpu_s,
        },
    }

    if raw_path is not None:
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        with raw_path.open("w", encoding="utf-8") as handle:
            for offered in offered_records:
                sequence = int(offered["sequence"])
                combined = dict(offered)
                service = service_by_sequence.get(sequence)
                dispatch = dispatch_by_sequence.get(sequence)
                received = received_by_sequence.get(sequence)
                combined.update(
                    {
                        "in_actual_ingress_cohort": (
                            measurement_start_ns
                            <= offered["ingress_ns"]
                            < measurement_end_ns
                        ),
                        "service_ns": service["service_ns"] if service else None,
                        "due_ns": dispatch["due_ns"] if dispatch else None,
                        "send_start_ns": (
                            dispatch["send_start_ns"] if dispatch else None
                        ),
                        "send_end_ns": dispatch["send_end_ns"] if dispatch else None,
                        "send_lateness_ms": (
                            dispatch["send_lateness_ms"] if dispatch else None
                        ),
                        "send_error": dispatch["send_error"] if dispatch else None,
                        "received": received is not None,
                        "delivery_failure": bool(
                            offered["admitted"] and received is None
                        ),
                        "receive_ns": received["receive_ns"] if received else None,
                        "in_departure_window": bool(
                            received is not None
                            and measurement_start_ns
                            <= received["receive_ns"]
                            < measurement_end_ns
                        ),
                        "latency_ms": (
                            (received["receive_ns"] - offered["ingress_ns"])
                            / 1_000_000
                            if received
                            else None
                        ),
                    }
                )
                handle.write(
                    json.dumps(combined, sort_keys=True, allow_nan=False) + "\n"
                )
        summary["raw_event_log"] = f"raw/{raw_path.name}"
        summary["raw_event_log_sha256"] = file_sha256(raw_path)
    return summary


def _bootstrap_mean_ci(
    sample: Sequence[float], seed_material: str, resamples: int = 5_000
) -> dict[str, Any]:
    if not sample:
        return {
            "lower": None,
            "upper": None,
            "confidence_level": 0.95,
            "resamples": resamples,
            "method": "seed-level nonparametric percentile bootstrap of mean",
        }
    if len(sample) == 1:
        lower = upper = float(sample[0])
    else:
        seed = int(hashlib.sha256(seed_material.encode("utf-8")).hexdigest()[:16], 16)
        rng = random.Random(seed)
        estimates = [
            statistics.fmean(sample[rng.randrange(len(sample))] for _ in sample)
            for _ in range(resamples)
        ]
        lower = percentile(estimates, 0.025)
        upper = percentile(estimates, 0.975)
    return {
        "lower": lower,
        "upper": upper,
        "confidence_level": 0.95,
        "resamples": resamples,
        "method": "seed-level nonparametric percentile bootstrap of mean",
    }


def aggregate_trials(trials: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate one condition across unique seeds with bootstrap CIs."""

    rows = list(trials)
    if not rows:
        raise ValueError("no trials to aggregate")
    if any(row.get("schema_version") != SCHEMA_VERSION for row in rows):
        raise ValueError("all trials must use the loopback v2 schema")
    if any(not row.get("valid_for_publication_aggregation", False) for row in rows):
        raise ValueError("invalid trial cannot enter publication aggregation")
    condition_hashes = {row["condition_identity_sha256"] for row in rows}
    if len(condition_hashes) != 1:
        raise ValueError("trials from different condition identities cannot mix")
    seeds = [int(row["config"]["seed"]) for row in rows]
    if len(seeds) != len(set(seeds)):
        raise ValueError("publication aggregation requires unique seed IDs")

    condition_hash = next(iter(condition_hashes))

    def values(path: tuple[str, ...]) -> list[float]:
        result: list[float] = []
        for row in rows:
            value: Any = row
            for key in path:
                value = value[key]
            if value is not None:
                result.append(float(value))
        return result

    metric_paths = (
        (
            "application_frame_rate_fps",
            ("departure_window", "application_frame_rate_fps"),
            "frames/s",
        ),
        (
            "application_payload_Bps",
            ("departure_window", "application_payload_Bps"),
            "bytes/s",
        ),
        (
            "admission_drop_fraction",
            ("ingress_cohort", "admission_drop_fraction"),
            "fraction",
        ),
        (
            "delivery_failure_fraction_of_admitted",
            ("ingress_cohort", "delivery_failure_fraction_of_admitted"),
            "fraction",
        ),
        (
            "end_to_end_loss_fraction",
            ("ingress_cohort", "end_to_end_loss_fraction"),
            "fraction",
        ),
        (
            "p50_latency_ms",
            ("ingress_cohort", "latency_ms", "p50"),
            "ms",
        ),
        (
            "p95_latency_ms",
            ("ingress_cohort", "latency_ms", "p95"),
            "ms",
        ),
        (
            "p99_latency_ms",
            ("ingress_cohort", "latency_ms", "p99"),
            "ms",
        ),
    )
    metrics: dict[str, Any] = {}
    for label in ("benign", "attack"):
        prefix = ("measurement", "by_label", label)
        metrics[label] = {}
        for name, suffix, unit in metric_paths:
            sample = values(prefix + suffix)
            metrics[label][name] = {
                "unit": unit,
                "sample_count": len(sample),
                "mean": statistics.fmean(sample) if sample else None,
                "bootstrap_95_ci": _bootstrap_mean_ci(
                    sample, f"{condition_hash}:{label}:{name}"
                ),
            }
    return {
        "schema_version": SCHEMA_VERSION,
        "aggregation_method": (
            "arithmetic mean across unique seed-level trials with deterministic "
            "95% nonparametric percentile bootstrap confidence intervals"
        ),
        "trial_count": len(rows),
        "valid_trial_count": len(rows),
        "seed_sample_count": len(seeds),
        "seed_ids": sorted(seeds),
        "condition_identity": rows[0]["condition_identity"],
        "condition_identity_sha256": condition_hash,
        "claim_boundary": rows[0]["claim_boundary"],
        "metrics": metrics,
    }


def build_trial_plan(
    protocols: Sequence[str],
    modes: Sequence[str],
    loads: Sequence[float],
    seeds: int,
    seed_start: int,
    duration_s: float,
    measurement_start_s: float,
    dwell_s: float,
    order_seed: int,
) -> list[dict[str, Any]]:
    """Backward-compatible quick-smoke plan constructor.

    Publication runs must use :func:`load_study_config` and
    :func:`build_study_trial_plan` so every field is supplied by one hashed
    input file.
    """

    study = _quick_smoke_study_config(
        seeds=seeds,
        seed_start=seed_start,
        protocols=protocols,
        modes=modes,
        loads=loads,
        duration_s=duration_s,
        measurement_start_s=measurement_start_s,
        dwell_s=dwell_s,
        order_seed=order_seed,
    )
    return build_study_trial_plan(study)


def build_study_trial_plan(study: StudyConfig) -> list[dict[str, Any]]:
    """Create the exact deterministic paired plan defined by ``study``."""

    study.validate()
    blocks = [
        (study.seed_start + seed_index, protocol, float(load))
        for seed_index in range(study.seeds)
        for protocol in study.protocols
        for load in study.suspicious_offered_pps
    ]
    rng = random.Random(study.execution_order_seed)
    rng.shuffle(blocks)
    plan: list[dict[str, Any]] = []
    for seed, protocol, load in blocks:
        block_modes = list(study.modes)
        rng.shuffle(block_modes)
        block_id = f"{protocol}_load_{load:g}_seed_{seed}"
        for within_block_order, mode in enumerate(block_modes):
            config = study.prototype_config(
                seed=seed,
                protocol=protocol,
                mode=mode,
                load=load,
            )
            config.validate()
            plan.append(
                {
                    "execution_ordinal": len(plan),
                    "paired_block_id": block_id,
                    "within_block_order": within_block_order,
                    "config": config,
                    "config_sha256": object_sha256(asdict(config)),
                }
            )
    return plan


def build_execution_plan_payload(
    study: StudyConfig,
    plan: Sequence[dict[str, Any]],
    input_configuration: dict[str, Any],
) -> dict[str, Any]:
    """Bind the exact study input and its source hash into the plan."""

    study.validate()
    parsed_hash = object_sha256(study.to_dict())
    if input_configuration.get("parsed_config_sha256") != parsed_hash:
        raise ValueError("input config provenance does not match parsed study config")
    expected_trials = (
        study.seeds
        * len(study.protocols)
        * len(study.modes)
        * len(study.suspicious_offered_pps)
    )
    if len(plan) != expected_trials:
        raise ValueError(
            f"plan has {len(plan)} trials but study config requires {expected_trials}"
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "study_id": study.study_id,
        "study_role": study.study_role,
        "authoritative_design": study.study_role == "authoritative",
        "study_config": study.to_dict(),
        "study_config_sha256": parsed_hash,
        "input_configuration": dict(input_configuration),
        "order_seed": study.execution_order_seed,
        "design": (
            "randomized block order; requested modes randomized within each "
            "seed/protocol/load block and executed adjacently"
        ),
        "trials": [
            {
                **{key: value for key, value in item.items() if key != "config"},
                "config": asdict(item["config"]),
            }
            for item in plan
        ],
    }


def build_configuration_provenance(
    execution_plan_path: Path,
    execution_plan_payload: dict[str, Any],
    plan: Sequence[dict[str, Any]],
    input_configuration: dict[str, Any],
) -> dict[str, Any]:
    """Construct manifest provenance and verify input-to-plan hash plumbing."""

    if execution_plan_payload.get("input_configuration") != input_configuration:
        raise ValueError("execution plan input provenance differs from manifest input")
    declared_study_hash = execution_plan_payload.get("study_config_sha256")
    actual_study_hash = object_sha256(execution_plan_payload.get("study_config"))
    if declared_study_hash != actual_study_hash:
        raise ValueError("execution plan study config hash mismatch")
    input_parsed_hash = input_configuration.get("parsed_config_sha256")
    if declared_study_hash != input_parsed_hash:
        raise ValueError("execution plan is not bound to the input config hash")
    provenance = {
        "input_configuration": dict(input_configuration),
        "execution_plan_file_sha256": file_sha256(execution_plan_path),
        "execution_plan_study_config_sha256": declared_study_hash,
        "ordered_trial_config_sha256": [item["config_sha256"] for item in plan],
        "input_config_hash_matches_execution_plan": True,
    }
    provenance["configuration_set_sha256"] = object_sha256(provenance)
    return provenance


def _source_provenance() -> dict[str, Any]:
    project_root = Path(__file__).resolve().parents[1]
    candidates = [
        Path(__file__).resolve(),
        project_root / "prototype" / "README.md",
        project_root / "tests" / "test_loopback_testbed.py",
        project_root / "configs" / "loopback_testbed.json",
    ]
    files = {
        str(path.relative_to(project_root)): file_sha256(path)
        for path in candidates
        if path.exists()
    }
    return {"files": files, "source_set_sha256": object_sha256(files)}


def _prepare_output_dir(output_dir: Path) -> None:
    """Create an output directory, refusing any stale or ambiguous contents."""

    if output_dir.exists():
        if not output_dir.is_dir():
            raise ValueError(f"output path is not a directory: {output_dir}")
        if next(output_dir.iterdir(), None) is not None:
            raise FileExistsError(
                f"output directory must be empty to prevent stale-file "
                f"contamination: {output_dir}"
            )
        return
    output_dir.mkdir(parents=True, exist_ok=False)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--config",
        type=Path,
        help=(
            "complete strict JSON study config; cannot be combined with "
            "quick-smoke design flags"
        ),
    )
    parser.add_argument("--seeds", type=int)
    parser.add_argument("--seed-start", type=int)
    parser.add_argument("--protocols")
    parser.add_argument("--modes")
    parser.add_argument("--loads")
    parser.add_argument("--duration", type=float)
    parser.add_argument("--measurement-start", type=float)
    parser.add_argument("--dwell", type=float)
    parser.add_argument(
        "--order-seed",
        type=int,
        help="deterministic randomization seed for paired execution blocks",
    )
    args = parser.parse_args()

    quick_flag_names = (
        "seeds",
        "seed_start",
        "protocols",
        "modes",
        "loads",
        "duration",
        "measurement_start",
        "dwell",
        "order_seed",
    )
    supplied_quick_flags = [
        name for name in quick_flag_names if getattr(args, name) is not None
    ]
    if args.config is not None:
        if supplied_quick_flags:
            parser.error(
                "--config cannot be combined with quick-smoke flags: "
                + ", ".join(f"--{name.replace('_', '-')}" for name in supplied_quick_flags)
            )
        try:
            study, input_configuration = load_study_config(args.config)
        except (FileNotFoundError, ValueError) as exc:
            parser.error(str(exc))
    else:
        protocols_text = args.protocols if args.protocols is not None else "udp,tcp"
        modes_text = args.modes if args.modes is not None else "shared,isolated"
        loads_text = args.loads if args.loads is not None else "400"
        try:
            protocols = [
                value.strip() for value in protocols_text.split(",") if value.strip()
            ]
            modes = [
                value.strip() for value in modes_text.split(",") if value.strip()
            ]
            loads = [
                float(value) for value in loads_text.split(",") if value.strip()
            ]
            study = _quick_smoke_study_config(
                seeds=args.seeds if args.seeds is not None else 1,
                seed_start=args.seed_start if args.seed_start is not None else 1009,
                protocols=protocols,
                modes=modes,
                loads=loads,
                duration_s=args.duration if args.duration is not None else 0.40,
                measurement_start_s=(
                    args.measurement_start
                    if args.measurement_start is not None
                    else 0.05
                ),
                dwell_s=args.dwell if args.dwell is not None else 0.025,
                order_seed=args.order_seed if args.order_seed is not None else 1729,
            )
        except ValueError as exc:
            parser.error(str(exc))
        input_configuration = {
            "source_mode": "cli_quick_smoke",
            "path": None,
            "file_sha256": None,
            "parsed_config_sha256": object_sha256(study.to_dict()),
            "study_id": study.study_id,
            "study_role": study.study_role,
        }

    plan = build_study_trial_plan(study)
    plan_payload = build_execution_plan_payload(
        study, plan, input_configuration
    )

    # Refuse stale files before writing the plan or opening any live socket.
    _prepare_output_dir(args.output_dir)
    execution_plan_path = args.output_dir / "execution_plan.json"
    write_json(execution_plan_path, plan_payload)

    grouped: dict[tuple[str, str, float], list[dict[str, Any]]] = {}
    trials: list[dict[str, Any]] = []
    for item in plan:
        config: PrototypeConfig = item["config"]
        load = config.suspicious_offered_pps
        stem = f"{config.protocol}_{config.mode}_load_{load:g}_seed_{config.seed}"
        raw_path = args.output_dir / "raw" / f"{stem}.jsonl"
        summary = run_trial(config, raw_path)
        summary["execution"] = {
            "execution_ordinal": item["execution_ordinal"],
            "paired_block_id": item["paired_block_id"],
            "within_block_order": item["within_block_order"],
            "order_seed": study.execution_order_seed,
            "study_id": study.study_id,
            "study_role": study.study_role,
            "study_config_sha256": object_sha256(study.to_dict()),
            "input_config_file_sha256": input_configuration["file_sha256"],
        }
        write_json(args.output_dir / "raw" / f"{stem}.summary.json", summary)
        grouped.setdefault((config.protocol, config.mode, load), []).append(summary)
        trials.append(summary)

    aggregate_files: dict[str, str] = {}
    for (protocol, mode, load), group in sorted(grouped.items()):
        path = args.output_dir / f"{protocol}_{mode}_load_{load:g}.json"
        write_json(path, aggregate_trials(group))
        aggregate_files[str(path.relative_to(args.output_dir))] = file_sha256(path)

    source = _source_provenance()
    dependencies = dependency_metadata()
    runtime = runtime_metadata()
    if args.config is not None:
        verify_study_config_unchanged(args.config, input_configuration)
    configuration = build_configuration_provenance(
        execution_plan_path,
        plan_payload,
        plan,
        input_configuration,
    )
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "study_id": study.study_id,
        "study_role": study.study_role,
        "authoritative_design": study.study_role == "authoritative",
        "trial_count": len(trials),
        "valid_trial_count": sum(
            bool(trial["valid_for_publication_aggregation"]) for trial in trials
        ),
        "claim_boundary": trials[0]["claim_boundary"] if trials else None,
        "provenance": {
            "source": source,
            "configuration": configuration,
            "dependencies": {
                "metadata": dependencies,
                "sha256": object_sha256(dependencies),
            },
            "host_runtime": {
                "metadata": runtime,
                "sha256": object_sha256(runtime),
            },
        },
        "aggregate_files": aggregate_files,
        "files": {
            str(path.relative_to(args.output_dir)): file_sha256(path)
            for path in sorted(args.output_dir.rglob("*.json*"))
            if path.name != "manifest.json"
        },
    }
    write_json(args.output_dir / "manifest.json", manifest)
    print(f"completed {len(trials)} live loopback trials")
    print(f"study={study.study_id} role={study.study_role}")
    print(f"manifest={args.output_dir / 'manifest.json'}")


if __name__ == "__main__":
    main()
