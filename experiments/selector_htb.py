#!/usr/bin/env python3
"""Frozen inputs for causal selector replay through a real Linux HTB qdisc.

The experiment deliberately separates two claims.  Selector decisions are
computed in userspace from the first 20 IATs using the existing training and
calibration split.  Packet service is then measured on a real, rootless veth
and Linux HTB path.  This is not XDP/eBPF execution and does not measure the
cost of computing a decision in a packet-forwarding hook.
"""

from __future__ import annotations

import hashlib
import json
import math
import random
from dataclasses import asdict, dataclass, fields, replace
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from experiments.coupled_simulation import (
    CoupledConfig,
    FlowTrace,
    PacketEvent,
    SelectorDecision,
    fit_selectors,
    generate_flows,
    load_config as load_coupled_config,
    packet_events,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCHEDULERS = ("fixed", "borrowing")


@dataclass(frozen=True)
class SelectorHtbConfig:
    schema_version: str
    study_id: str
    evidence_boundary: str
    base_coupled_config: str
    selectors: tuple[str, ...]
    attack_scales: tuple[float, ...]
    heldout_seeds: tuple[int, ...]
    heldout_flows_per_family: int
    execution_order_seed: int
    bootstrap_seed: int
    bootstrap_replicates: int
    network: Mapping[str, Any]
    service: Mapping[str, Any]
    timing: Mapping[str, Any]
    validity: Mapping[str, Any]

    def __post_init__(self) -> None:
        if self.schema_version != "selector-htb-config-1.0":
            raise ValueError("unsupported selector-HTB configuration schema")
        if self.evidence_boundary != (
            "single-host-rootless-veth-userspace-causal-selector-replay-"
            "real-linux-htb-no-xdp"
        ):
            raise ValueError("the evidence boundary must remain explicit")
        if not self.selectors or set(self.selectors) - {"multifeature", "oracle"}:
            raise ValueError("only the frozen multifeature and maturity-matched oracle are valid")
        if len(self.selectors) != len(set(self.selectors)):
            raise ValueError("selectors must be unique")
        if len(self.heldout_seeds) < 30 or len(self.heldout_seeds) != len(set(self.heldout_seeds)):
            raise ValueError("at least 30 unique held-out seeds are required")
        if not self.attack_scales or any(
            isinstance(value, bool) or not math.isfinite(value) or value <= 0
            for value in self.attack_scales
        ):
            raise ValueError("attack scales must be finite and positive")
        if self.heldout_flows_per_family < 1:
            raise ValueError("heldout_flows_per_family must be positive")
        if self.bootstrap_replicates < 1:
            raise ValueError("bootstrap_replicates must be positive")
        required_network = {
            "allowed_subnet", "server_ip", "client_ip", "prefix_length",
            "server_interface", "client_interface", "mtu", "receiver_port",
            "fast_source_port", "suspicious_source_port", "fast_tos", "suspicious_tos",
        }
        required_service = {
            "total_Bps", "fast_reserved_fraction", "buffer_time_s",
            "root_burst_bytes", "child_burst_bytes", "r2q",
        }
        required_timing = {
            "drain_s", "start_lead_s", "ready_timeout_s",
            "process_timeout_slack_s", "cooldown_between_arms_s",
        }
        required_validity = {
            "maximum_missed_schedule_fraction", "maximum_send_lateness_p99_ns",
            "require_zero_malformed_packets", "require_zero_udp_receive_errors",
            "maximum_within_pair_sent_count_relative_difference",
        }
        for supplied, expected, label in (
            (set(self.network), required_network, "network"),
            (set(self.service), required_service, "service"),
            (set(self.timing), required_timing, "timing"),
            (set(self.validity), required_validity, "validity"),
        ):
            if supplied != expected:
                raise ValueError(f"{label} keys mismatch: {sorted(supplied ^ expected)}")
        total = float(self.service["total_Bps"])
        fraction = float(self.service["fast_reserved_fraction"])
        if not math.isfinite(total) or total <= 0 or not 0 < fraction < 1:
            raise ValueError("service rate must be positive and reservation fraction inside (0,1)")
        if int(self.network["fast_tos"]) == int(self.network["suspicious_tos"]):
            raise ValueError("FAST and suspicious TOS values must differ")
        if int(self.network["mtu"]) < 1528:
            raise ValueError("veth MTU must prevent fragmentation of 1,500-byte UDP payloads")

    @property
    def base_config_path(self) -> Path:
        path = (PROJECT_ROOT / self.base_coupled_config).resolve()
        if PROJECT_ROOT.resolve() not in path.parents:
            raise ValueError("base coupled configuration must remain within the project")
        return path

    @property
    def fast_reserved_Bps(self) -> int:
        return int(round(float(self.service["total_Bps"]) * float(self.service["fast_reserved_fraction"])))

    @property
    def suspicious_reserved_Bps(self) -> int:
        return int(self.service["total_Bps"]) - self.fast_reserved_Bps


@dataclass(frozen=True)
class ReplayEvent:
    offset_ns: int
    flow_id: str
    packet_index: int
    size_bytes: int
    true_label: str
    family: str
    traffic_class: str
    provisional: bool


def canonical_sha256(payload: Any) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    ).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_new_json(path: Path, payload: Any) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True, allow_nan=False)
        handle.write("\n")


def load_selector_htb_config(path: Path) -> SelectorHtbConfig:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise TypeError("selector-HTB configuration must be a JSON object")
    expected = {field.name for field in fields(SelectorHtbConfig)}
    if set(payload) != expected:
        raise ValueError(
            f"configuration keys must exactly match; missing={sorted(expected - set(payload))}, "
            f"unknown={sorted(set(payload) - expected)}"
        )
    for name in ("selectors", "attack_scales", "heldout_seeds"):
        if not isinstance(payload[name], list):
            raise TypeError(f"{name} must be a JSON array")
        payload[name] = tuple(payload[name])
    return SelectorHtbConfig(**payload)


def fit_frozen_selectors(
    config: SelectorHtbConfig,
) -> tuple[CoupledConfig, dict[str, Any], dict[str, Any]]:
    """Fit with training/calibration data only and return requested models."""

    coupled = load_coupled_config(config.base_config_path)
    if set(config.heldout_seeds) - set(coupled.heldout_seeds):
        raise ValueError("selector-HTB seeds must be a subset of the frozen held-out split")
    forbidden = set(config.heldout_seeds) & (
        set(coupled.train_seeds) | set(coupled.calibration_seeds)
    )
    if forbidden:
        raise ValueError(f"held-out leakage detected: {sorted(forbidden)}")
    training = [
        flow
        for seed in coupled.train_seeds
        for flow in generate_flows(seed, "train", coupled, 1.0)
    ]
    calibration = [
        flow
        for seed in coupled.calibration_seeds
        for flow in generate_flows(seed, "calibration", coupled, 1.0)
    ]
    all_models, report = fit_selectors(training, calibration, coupled)
    models = {name: all_models[name] for name in config.selectors}
    report = {
        **report,
        "requested_models": list(config.selectors),
        "heldout_data_used_for_fit_or_calibration": False,
        "model_parameters": {name: asdict(model) for name, model in models.items()},
    }
    return coupled, models, report


def heldout_flows(
    config: SelectorHtbConfig,
    coupled: CoupledConfig,
    seed: int,
    attack_scale: float,
) -> list[FlowTrace]:
    if seed not in config.heldout_seeds:
        raise ValueError("seed is not in the frozen held-out split")
    if attack_scale not in config.attack_scales:
        raise ValueError("attack scale is not frozen in the selector-HTB configuration")
    replay_config = replace(coupled, flows_per_family=config.heldout_flows_per_family)
    return generate_flows(seed, "heldout", replay_config, attack_scale)


def build_replay_events(
    flows: Sequence[FlowTrace],
    events: Sequence[PacketEvent],
    decisions: Mapping[str, SelectorDecision],
    window_iats: int,
) -> list[ReplayEvent]:
    flow_ids = {flow.flow_id for flow in flows}
    if set(decisions) != flow_ids:
        raise ValueError("one and only one selector decision is required per flow")
    replay: list[ReplayEvent] = []
    for event in events:
        decision = decisions[event.flow_id]
        provisional = event.packet_index < window_iats or not decision.mature
        suspicious = decision.predicted_attack and not provisional
        replay.append(
            ReplayEvent(
                offset_ns=int(round(event.time_s * 1_000_000_000)),
                flow_id=event.flow_id,
                packet_index=event.packet_index,
                size_bytes=event.size_bytes,
                true_label=event.true_label,
                family=event.family,
                traffic_class="suspicious" if suspicious else "fast",
                provisional=provisional,
            )
        )
    return replay


def replay_trace(
    config: SelectorHtbConfig,
    coupled: CoupledConfig,
    models: Mapping[str, Any],
    seed: int,
    attack_scale: float,
    selector: str,
) -> tuple[list[ReplayEvent], dict[str, Any]]:
    if selector not in models:
        raise ValueError("selector is not fitted/frozen")
    flows = heldout_flows(config, coupled, seed, attack_scale)
    events = packet_events(flows, coupled.duration_s)
    decisions = {flow.flow_id: models[selector].decide(flow) for flow in flows}
    replay = build_replay_events(flows, events, decisions, coupled.window_iats)
    mature = [decision for decision in decisions.values() if decision.mature]
    flow_lookup = {flow.flow_id: flow for flow in flows}
    confusion = {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "immature": len(flows) - len(mature)}
    for decision in mature:
        attack = flow_lookup[decision.flow_id].true_label == "attack"
        if attack and decision.predicted_attack:
            confusion["tp"] += 1
        elif attack:
            confusion["fn"] += 1
        elif decision.predicted_attack:
            confusion["fp"] += 1
        else:
            confusion["tn"] += 1
    counts: dict[str, int] = {}
    bytes_: dict[str, int] = {}
    for item in replay:
        key = f"{item.true_label}_{item.traffic_class}"
        counts[key] = counts.get(key, 0) + 1
        bytes_[key] = bytes_.get(key, 0) + item.size_bytes
    digest_payload = [
        [
            item.offset_ns, item.flow_id, item.packet_index, item.size_bytes,
            item.true_label, item.family, item.traffic_class, item.provisional,
        ]
        for item in replay
    ]
    metadata = {
        "seed": seed,
        "attack_scale": attack_scale,
        "selector": selector,
        "flow_count": len(flows),
        "packet_count": len(replay),
        "payload_bytes": sum(item.size_bytes for item in replay),
        "packet_counts_by_truth_and_class": counts,
        "payload_bytes_by_truth_and_class": bytes_,
        "mature_flow_confusion": confusion,
        "trace_sha256": canonical_sha256(digest_payload),
        "maturity_rule": (
            f"packet indices 0..{coupled.window_iats - 1} are provisional FAST; "
            f"index {coupled.window_iats} and later use the decision when mature"
        ),
    }
    return replay, metadata


def build_execution_plan(config: SelectorHtbConfig) -> dict[str, Any]:
    pairs = [
        {
            "pair_id": f"seed{seed}_scale{scale:g}_{selector}",
            "seed": seed,
            "attack_scale": scale,
            "selector": selector,
        }
        for seed in config.heldout_seeds
        for scale in config.attack_scales
        for selector in config.selectors
    ]
    rng = random.Random(config.execution_order_seed)
    rng.shuffle(pairs)
    trials: list[dict[str, Any]] = []
    for pair_ordinal, pair in enumerate(pairs, start=1):
        arm_order = list(SCHEDULERS)
        rng.shuffle(arm_order)
        for arm_ordinal, scheduler in enumerate(arm_order, start=1):
            trials.append(
                {
                    **pair,
                    "pair_ordinal": pair_ordinal,
                    "arm_ordinal": arm_ordinal,
                    "scheduler": scheduler,
                    "trial_id": f"{pair['pair_id']}_{scheduler}",
                }
            )
    plan = {
        "schema_version": "selector-htb-plan-1.0",
        "execution_order_seed": config.execution_order_seed,
        "pair_count": len(pairs),
        "trial_count": len(trials),
        "trials": trials,
    }
    plan["plan_sha256"] = canonical_sha256(plan)
    return plan


def nearest_rank(values: Iterable[int], quantile: float) -> int | None:
    rows = sorted(values)
    if not rows:
        return None
    if not 0 < quantile <= 1:
        raise ValueError("quantile must be in (0,1]")
    return rows[max(0, math.ceil(quantile * len(rows)) - 1)]


def tc_spec(config: SelectorHtbConfig, scheduler: str) -> dict[str, Any]:
    if scheduler not in SCHEDULERS:
        raise ValueError(f"unknown scheduler {scheduler}")
    total = int(config.service["total_Bps"])
    fast = config.fast_reserved_Bps
    suspicious = config.suspicious_reserved_Bps
    buffer_time = float(config.service["buffer_time_s"])
    ceiling = total if scheduler == "borrowing" else None
    return {
        "scheduler": scheduler,
        "total_Bps": total,
        "root_burst_bytes": int(config.service["root_burst_bytes"]),
        "child_burst_bytes": int(config.service["child_burst_bytes"]),
        "r2q": int(config.service["r2q"]),
        "classes": {
            "fast": {
                "classid": "1:10", "rate_Bps": fast,
                "ceil_Bps": ceiling or fast,
                "buffer_bytes": int(round(fast * buffer_time)),
                "tos": int(config.network["fast_tos"]),
            },
            "suspicious": {
                "classid": "1:20", "rate_Bps": suspicious,
                "ceil_Bps": ceiling or suspicious,
                "buffer_bytes": int(round(suspicious * buffer_time)),
                "tos": int(config.network["suspicious_tos"]),
            },
        },
    }


def tc_commands(config: SelectorHtbConfig, scheduler: str, tc_binary: str) -> list[list[str]]:
    spec = tc_spec(config, scheduler)
    interface = str(config.network["client_interface"])
    total = spec["total_Bps"]
    root_burst = spec["root_burst_bytes"]
    child_burst = spec["child_burst_bytes"]
    result = [
        [tc_binary, "qdisc", "del", "dev", interface, "root"],
        [tc_binary, "qdisc", "add", "dev", interface, "root", "handle", "1:",
         "htb", "default", "20", "r2q", str(spec["r2q"]), "direct_qlen", "0"],
        [tc_binary, "class", "add", "dev", interface, "parent", "1:", "classid", "1:1",
         "htb", "rate", f"{total}Bps", "ceil", f"{total}Bps",
         "burst", f"{root_burst}b", "cburst", f"{root_burst}b"],
    ]
    for name in ("fast", "suspicious"):
        row = spec["classes"][name]
        result.extend(
            [
                [tc_binary, "class", "add", "dev", interface, "parent", "1:1",
                 "classid", row["classid"], "htb", "rate", f"{row['rate_Bps']}Bps",
                 "ceil", f"{row['ceil_Bps']}Bps", "burst", f"{child_burst}b",
                 "cburst", f"{child_burst}b", "prio", "0"],
                [tc_binary, "qdisc", "add", "dev", interface, "parent", row["classid"],
                 "handle", "10:" if name == "fast" else "20:", "bfifo", "limit",
                 str(row["buffer_bytes"])],
            ]
        )
    result.extend(
        [
            [tc_binary, "filter", "add", "dev", interface, "protocol", "ip", "parent", "1:",
             "prio", "1", "u32", "match", "ip", "tos",
             f"0x{spec['classes']['fast']['tos']:02x}", "0xff", "flowid", "1:10"],
            [tc_binary, "filter", "add", "dev", interface, "protocol", "ip", "parent", "1:",
             "prio", "2", "u32", "match", "ip", "tos",
             f"0x{spec['classes']['suspicious']['tos']:02x}", "0xff", "flowid", "1:20"],
        ]
    )
    return result
