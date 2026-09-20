#!/usr/bin/env python3
"""Run paired causal-selector traces through a disposable real HTB path."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import platform
import select
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable

from experiments.selector_htb import (
    PROJECT_ROOT,
    build_execution_plan,
    file_sha256,
    fit_frozen_selectors,
    load_selector_htb_config,
    replay_trace,
    tc_commands,
    tc_spec,
    write_new_json,
)


TRAFFIC_MODULE = "testbed.selector_htb_traffic"
SOURCE_FILES = (
    "configs/selector_htb.json",
    "configs/coupled_simulation.json",
    "experiments/selector_htb.py",
    "experiments/selector_htb_analysis.py",
    "experiments/coupled_simulation.py",
    "protocols/SELECTOR_HTB_PROTOCOL.md",
    "testbed/selector_htb_traffic.py",
    "testbed/run_selector_htb.py",
    "testbed/run_selector_htb_isolated.sh",
    "requirements.txt",
)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def run(
    command: list[str], *, check: bool = True, timeout: float = 30.0,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command, cwd=PROJECT_ROOT, text=True, capture_output=True, timeout=timeout
    )
    if check and completed.returncode != 0:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {command!r}\n"
            f"stdout={completed.stdout[-4000:]}\nstderr={completed.stderr[-4000:]}"
        )
    return completed


def client_command(client_pid: int, command: list[str]) -> list[str]:
    return ["nsenter", "--target", str(client_pid), "--net", "--", *command]


def namespace_json(command: list[str]) -> list[dict[str, Any]]:
    completed = run(command)
    value = json.loads(completed.stdout)
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise RuntimeError(f"namespace command did not return a JSON list: {command!r}")
    return value


def interface_names(command: Callable[[list[str]], list[str]]) -> list[str]:
    return sorted(str(row["ifname"]) for row in namespace_json(command(["ip", "-j", "link", "show"])))


def assert_outer_isolation() -> None:
    expected_host = os.environ.get("CIQ_HOST_NETNS_ID")
    actual = os.readlink("/proc/self/ns/net")
    if not expected_host:
        raise RuntimeError("CIQ_HOST_NETNS_ID is absent; use run_selector_htb_isolated.sh")
    if actual == expected_host:
        raise RuntimeError("REFUSING to run in the host network namespace")
    if interface_names(lambda inner: inner) != ["lo"]:
        raise RuntimeError("new outer namespace did not begin with loopback only")
    if namespace_json(["ip", "-j", "route", "show", "default"]):
        raise RuntimeError("new outer namespace unexpectedly has a default route")


def start_client_anchor() -> tuple[subprocess.Popen[str], int]:
    process = subprocess.Popen(
        ["unshare", "--net", "--fork", "bash", "-c", "echo $$; exec sleep infinity"],
        cwd=PROJECT_ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        start_new_session=True,
    )
    if process.stdout is None:
        raise RuntimeError("client anchor stdout is unavailable")
    ready, _, _ = select.select([process.stdout], [], [], 5.0)
    if not ready:
        raise RuntimeError("client namespace anchor did not report its PID")
    line = process.stdout.readline().strip()
    if not line.isdigit():
        raise RuntimeError(f"client namespace anchor emitted an invalid PID: {line!r}")
    child_pid = int(line)
    if not Path(f"/proc/{child_pid}/ns/net").exists():
        raise RuntimeError("client namespace anchor disappeared")
    return process, child_pid


def stop_anchor(process: subprocess.Popen[str], child_pid: int) -> None:
    try:
        os.kill(child_pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=3)


def configure_topology(config: Any, client_pid: int) -> dict[str, Any]:
    network = config.network
    server_iface = str(network["server_interface"])
    client_iface = str(network["client_interface"])
    server_ip = str(network["server_ip"])
    client_ip = str(network["client_ip"])
    prefix = int(network["prefix_length"])
    server = lambda inner: inner
    client = lambda inner: client_command(client_pid, inner)
    for wrap in (server, client):
        run(wrap(["sysctl", "-qw", "net.ipv6.conf.all.disable_ipv6=1"]))
        run(wrap(["sysctl", "-qw", "net.ipv6.conf.default.disable_ipv6=1"]))
    run(["ip", "link", "add", server_iface, "type", "veth", "peer", "name", client_iface])
    run(["ip", "link", "set", client_iface, "netns", str(client_pid)])
    for wrap, iface, address in (
        (server, server_iface, server_ip), (client, client_iface, client_ip),
    ):
        run(wrap(["ip", "link", "set", "dev", iface, "mtu", str(network["mtu"])]))
        run(wrap(["ip", "addr", "add", f"{address}/{prefix}", "dev", iface]))
        run(wrap(["ip", "addr", "replace", "127.0.0.1/8", "dev", "lo"]))
        run(wrap(["ip", "link", "set", "lo", "up"]))
        run(wrap(["ip", "link", "set", iface, "up"]))

    def mac(wrap: Callable[[list[str]], list[str]], iface: str) -> str:
        rows = namespace_json(wrap(["ip", "-j", "link", "show", "dev", iface]))
        if len(rows) != 1 or not rows[0].get("address"):
            raise RuntimeError("could not determine veth address")
        return str(rows[0]["address"]).lower()

    server_mac = mac(server, server_iface)
    client_mac = mac(client, client_iface)
    run(["ip", "neigh", "replace", client_ip, "lladdr", client_mac,
         "nud", "permanent", "dev", server_iface])
    run(client(["ip", "neigh", "replace", server_ip, "lladdr", server_mac,
                "nud", "permanent", "dev", client_iface]))
    expected = {"server": ["lo", server_iface], "client": ["lo", client_iface]}
    actual = {"server": interface_names(server), "client": interface_names(client)}
    if any(sorted(expected[role]) != actual[role] for role in expected):
        raise RuntimeError(f"interface allowlist mismatch: {actual!r}")
    routes = {
        "server": namespace_json(["ip", "-j", "route", "show", "default"]),
        "client": namespace_json(client(["ip", "-j", "route", "show", "default"])),
    }
    if routes["server"] or routes["client"]:
        raise RuntimeError("default route is forbidden in either namespace")
    links = {
        "server": namespace_json(["ip", "-j", "link", "show", "dev", server_iface]),
        "client": namespace_json(client(["ip", "-j", "link", "show", "dev", client_iface])),
    }
    if any(rows[0].get("mtu") != int(network["mtu"]) for rows in links.values()):
        raise RuntimeError(f"veth MTU mismatch: {links!r}")
    return {
        "captured_utc": utc_now(), "server_interfaces": actual["server"],
        "client_interfaces": actual["client"], "default_routes": routes,
        "server_netns": os.readlink("/proc/self/ns/net"),
        "client_netns": os.readlink(f"/proc/{client_pid}/ns/net"),
        "server_mac": server_mac, "client_mac": client_mac, "links": links,
    }


def apply_tc(config: Any, scheduler: str, tc_binary: str, client_pid: int) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for index, command in enumerate(tc_commands(config, scheduler, tc_binary)):
        completed = run(client_command(client_pid, command), check=False)
        missing_root = index == 0 and completed.returncode != 0
        record = {
            "argv": command, "returncode": completed.returncode,
            "allowed_initial_root_absence": missing_root,
            "stdout": completed.stdout, "stderr": completed.stderr,
        }
        records.append(record)
        if completed.returncode != 0 and not missing_root:
            raise RuntimeError(f"tc configuration failed: {record!r}")
    return records


def tc_snapshot(config: Any, tc_binary: str, client_pid: int) -> dict[str, Any]:
    interface = str(config.network["client_interface"])
    result: dict[str, Any] = {"captured_monotonic_ns": time.monotonic_ns(), "records": {}}
    for category in ("qdisc", "class", "filter"):
        command = [tc_binary, "-s", "-d", "-j", category, "show", "dev", interface]
        completed = run(client_command(client_pid, command))
        payload = json.loads(completed.stdout)
        if not isinstance(payload, list):
            raise RuntimeError(f"tc {category} output is not a JSON list")
        result["records"][category] = payload
    return result


def validate_tc(snapshot: dict[str, Any], spec: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    qdiscs = {str(row.get("handle")): row for row in snapshot["records"]["qdisc"]}
    classes = {str(row.get("handle")): row for row in snapshot["records"]["class"]}
    expected_qdiscs = {"1:": "htb", "10:": "bfifo", "20:": "bfifo"}
    if {key: row.get("kind") for key, row in qdiscs.items()} != expected_qdiscs:
        errors.append("qdisc_handle_or_kind_mismatch")
    expected_classes = {
        "1:1": {"rate": spec["total_Bps"], "ceil": spec["total_Bps"], "parent": None},
        "1:10": {**spec["classes"]["fast"], "parent": "1:1"},
        "1:20": {**spec["classes"]["suspicious"], "parent": "1:1"},
    }
    if set(classes) != set(expected_classes):
        errors.append("class_handle_set_mismatch")
    for classid, expected in expected_classes.items():
        observed = classes.get(classid, {})
        if observed.get("class") != "htb":
            errors.append(f"{classid}:kind")
            continue
        if observed.get("rate") != expected.get("rate", expected.get("rate_Bps")):
            errors.append(f"{classid}:rate")
        if observed.get("ceil") != expected.get("ceil", expected.get("ceil_Bps")):
            errors.append(f"{classid}:ceil")
        if classid != "1:1" and observed.get("parent") != "1:1":
            errors.append(f"{classid}:parent")
        if classid != "1:1" and observed.get("prio") != 0:
            errors.append(f"{classid}:priority")
    for handle, name in (("10:", "fast"), ("20:", "suspicious")):
        observed = qdiscs.get(handle, {})
        if observed.get("options", {}).get("limit") != spec["classes"][name]["buffer_bytes"]:
            errors.append(f"{handle}:buffer")
    rules = {
        row.get("options", {}).get("flowid"): row
        for row in snapshot["records"]["filter"]
        if row.get("options", {}).get("flowid")
    }
    if set(rules) != {"1:10", "1:20"}:
        errors.append("filter_flowid_set_mismatch")
    expected_matches = {
        "1:10": f"{int(spec['classes']['fast']['tos']):02x}0000".lstrip("0") or "0",
        "1:20": f"{int(spec['classes']['suspicious']['tos']):02x}0000".lstrip("0") or "0",
    }
    for flowid, expected_value in expected_matches.items():
        match = rules.get(flowid, {}).get("options", {}).get("match", {})
        if match.get("mask") != "ff0000" or match.get("value") != expected_value:
            errors.append(f"{flowid}:tos_filter")
    return errors


def packet_conservation(
    sender: dict[str, Any], receiver: dict[str, Any], tc_after: dict[str, Any]
) -> dict[str, Any]:
    sender_by_class = {
        name: sum(
            count for key, count in sender["sent_packet_counts"].items()
            if key.endswith(f":{name}")
        )
        for name in ("fast", "suspicious")
    }
    receiver_by_class = {
        name: sum(
            count for key, count in receiver["received_packet_counts"].items()
            if key.endswith(f":{name}")
        )
        for name in ("fast", "suspicious")
    }
    qdiscs = {str(row.get("handle")): row for row in tc_after["records"]["qdisc"]}
    rules = {
        row.get("options", {}).get("flowid"): row
        for row in tc_after["records"]["filter"]
        if row.get("options", {}).get("flowid")
    }
    details: dict[str, Any] = {}
    errors: list[str] = []
    for name, handle, flowid in (("fast", "10:", "1:10"), ("suspicious", "20:", "1:20")):
        leaf = qdiscs.get(handle, {})
        filtered = rules.get(flowid, {}).get("options", {}).get("success")
        transmitted = leaf.get("packets")
        dropped = leaf.get("drops")
        row = {
            "sender_packets": sender_by_class[name], "filter_success": filtered,
            "leaf_transmitted_packets": transmitted, "leaf_dropped_packets": dropped,
            "receiver_packets": receiver_by_class[name],
        }
        details[name] = row
        if filtered != sender_by_class[name]:
            errors.append(f"{name}:sender_to_filter")
        if not isinstance(transmitted, int) or not isinstance(dropped, int) or (
            transmitted + dropped != sender_by_class[name]
        ):
            errors.append(f"{name}:leaf_conservation")
        if transmitted != receiver_by_class[name]:
            errors.append(f"{name}:leaf_to_receiver")
    return {"by_class": details, "errors": errors, "exact": not errors}


def read_ready(process: subprocess.Popen[str], role: str, timeout: float) -> dict[str, Any]:
    if process.stdout is None:
        raise RuntimeError(f"{role} stdout is unavailable")
    ready, _, _ = select.select([process.stdout], [], [], timeout)
    if not ready:
        raise RuntimeError(f"timeout waiting for {role} readiness")
    line = process.stdout.readline()
    if not line:
        stderr = process.stderr.read() if process.stderr else ""
        raise RuntimeError(f"{role} exited before readiness: {stderr[-4000:]}")
    payload = json.loads(line)
    if payload.get("event") != "ready" or payload.get("role") != role:
        raise RuntimeError(f"malformed {role} readiness: {payload!r}")
    return payload


def final_record(output: str, role: str) -> dict[str, Any]:
    rows = [json.loads(line) for line in output.splitlines() if line.strip()]
    matches = [row for row in rows if row.get("event") == "final" and row.get("role") == role]
    if len(matches) != 1:
        raise RuntimeError(f"expected one {role} final record, got {len(matches)}")
    return matches[0]


def run_trial(
    config: Any,
    coupled: Any,
    models: dict[str, Any],
    trial: dict[str, Any],
    tc_binary: str,
    client_pid: int,
    cpu_ids: tuple[int, int],
) -> dict[str, Any]:
    replay, expected_trace = replay_trace(
        config, coupled, models, trial["seed"], trial["attack_scale"], trial["selector"]
    )
    del replay
    tc_apply = apply_tc(config, trial["scheduler"], tc_binary, client_pid)
    tc_before = tc_snapshot(config, tc_binary, client_pid)
    tc_validation_before = validate_tc(tc_before, tc_spec(config, trial["scheduler"]))
    if tc_validation_before:
        raise RuntimeError(f"live tc state does not match request: {tc_validation_before}")
    python = sys.executable
    network = config.network
    timing = config.timing
    receiver_command = [
        python, "-m", TRAFFIC_MODULE, "receiver",
        "--bind-ip", str(network["server_ip"]),
        "--expected-peer-ip", str(network["client_ip"]),
        "--allowed-subnet", str(network["allowed_subnet"]),
        "--port", str(network["receiver_port"]),
        "--duration-s", str(coupled.duration_s),
        "--drain-s", str(timing["drain_s"]),
        "--cpu-id", str(cpu_ids[0]),
    ]
    sender_inner = [
        python, "-m", TRAFFIC_MODULE, "sender", "--config", str(args_path(config)),
        "--seed", str(trial["seed"]), "--attack-scale", str(trial["attack_scale"]),
        "--selector", trial["selector"], "--bind-ip", str(network["client_ip"]),
        "--destination-ip", str(network["server_ip"]),
        "--destination-port", str(network["receiver_port"]),
        "--cpu-id", str(cpu_ids[1]),
        "--skip-if-late-ns", str(config.validity["maximum_send_lateness_p99_ns"]),
    ]
    sender_command = client_command(client_pid, sender_inner)
    processes: list[subprocess.Popen[str]] = []
    try:
        receiver = subprocess.Popen(
            receiver_command, cwd=PROJECT_ROOT, text=True, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        processes.append(receiver)
        sender = subprocess.Popen(
            sender_command, cwd=PROJECT_ROOT, text=True, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        processes.append(sender)
        ready_timeout = float(timing["ready_timeout_s"])
        receiver_ready = read_ready(receiver, "receiver", ready_timeout)
        sender_ready = read_ready(sender, "sender", ready_timeout)
        if sender_ready["trace_sha256"] != expected_trace["trace_sha256"]:
            raise RuntimeError("sender trace differs from runner-generated trace")
        start_ns = time.monotonic_ns() + int(round(float(timing["start_lead_s"]) * 1e9))
        barrier = json.dumps({"event": "start", "start_monotonic_ns": start_ns}) + "\n"
        for process in (receiver, sender):
            if process.stdin is None:
                raise RuntimeError("traffic process stdin is unavailable")
            process.stdin.write(barrier)
            process.stdin.flush()
            process.stdin.close()
            process.stdin = None
        timeout = coupled.duration_s + float(timing["drain_s"]) + float(timing["process_timeout_slack_s"])
        sender_out, sender_err = sender.communicate(timeout=timeout)
        receiver_out, receiver_err = receiver.communicate(timeout=timeout)
        if sender.returncode != 0 or receiver.returncode != 0:
            raise RuntimeError(
                f"traffic process failure sender={sender.returncode} receiver={receiver.returncode}; "
                f"sender_stderr={sender_err[-4000:]}; receiver_stderr={receiver_err[-4000:]}"
            )
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
    tc_after = tc_snapshot(config, tc_binary, client_pid)
    sender_final = final_record(sender_out, "sender")
    receiver_final = final_record(receiver_out, "receiver")
    if sender_final["trace"]["trace_sha256"] != expected_trace["trace_sha256"]:
        raise RuntimeError("completed sender trace differs from runner-generated trace")
    tc_validation_after = validate_tc(tc_after, tc_spec(config, trial["scheduler"]))
    conservation = packet_conservation(sender_final, receiver_final, tc_after)
    validity_reasons: list[str] = []
    validity = config.validity
    if sender_final["missed_schedule_fraction"] > float(validity["maximum_missed_schedule_fraction"]):
        validity_reasons.append("missed_schedule_fraction")
    if (sender_final["send_lateness_p99_ns"] or 0) > int(validity["maximum_send_lateness_p99_ns"]):
        validity_reasons.append("send_lateness_p99")
    if validity["require_zero_malformed_packets"] and receiver_final["malformed_packets"] != 0:
        validity_reasons.append("malformed_packets")
    if tc_validation_after:
        validity_reasons.append("live_tc_mismatch")
    if not conservation["exact"]:
        validity_reasons.append("packet_conservation")
    udp = receiver_final["udp_counter_delta"]
    if validity["require_zero_udp_receive_errors"] and (
        udp.get("InErrors", 0) != 0 or udp.get("RcvbufErrors", 0) != 0
        or receiver_final["socket_rxq_overflow_drops"] != 0
    ):
        validity_reasons.append("udp_receive_errors")
    return {
        "schema_version": "selector-htb-trial-1.0", "completed_utc": utc_now(),
        "trial": trial, "tc_requested": tc_spec(config, trial["scheduler"]),
        "tc_apply": tc_apply, "tc_before": tc_before, "tc_after": tc_after,
        "tc_validation": {"before": tc_validation_before, "after": tc_validation_after},
        "packet_conservation": conservation,
        "receiver_ready": receiver_ready, "sender_ready": sender_ready,
        "sender": sender_final, "receiver": receiver_final,
        "stderr": {"sender": sender_err, "receiver": receiver_err},
        "valid": not validity_reasons, "invalid_reasons": validity_reasons,
    }


_CONFIG_PATH: Path | None = None


def args_path(_config: Any) -> Path:
    if _CONFIG_PATH is None:
        raise RuntimeError("internal configuration path is unset")
    return _CONFIG_PATH


def choose_cpu_ids() -> tuple[int, int]:
    available = sorted(os.sched_getaffinity(0))
    if len(available) < 2:
        raise RuntimeError("at least two available logical CPUs are required")
    preferred = [4, 6]
    selected = [cpu for cpu in preferred if cpu in available]
    for cpu in available:
        if cpu not in selected:
            selected.append(cpu)
        if len(selected) == 2:
            break
    return selected[0], selected[1]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--tc", required=True)
    parser.add_argument("--profile", choices=("smoke", "authoritative"), required=True)
    return parser.parse_args()


def main() -> None:
    global _CONFIG_PATH
    args = parse_args()
    _CONFIG_PATH = args.config.resolve()
    assert_outer_isolation()
    if args.output_dir.exists():
        raise FileExistsError(f"output directory already exists: {args.output_dir}")
    args.output_dir.mkdir(parents=True)
    raw_dir = args.output_dir / "raw"
    raw_dir.mkdir()
    config = load_selector_htb_config(_CONFIG_PATH)
    coupled, models, calibration = fit_frozen_selectors(config)
    plan = build_execution_plan(config)
    if args.profile == "smoke":
        trials = [
            {
                "pair_id": "smoke_seed1009_scale1_multifeature",
                "seed": 1009, "attack_scale": 1.0, "selector": "multifeature",
                "pair_ordinal": 1, "arm_ordinal": index,
                "scheduler": scheduler,
                "trial_id": f"smoke_seed1009_scale1_multifeature_{scheduler}",
            }
            for index, scheduler in enumerate(("fixed", "borrowing"), start=1)
        ]
    else:
        trials = plan["trials"]
    write_new_json(args.output_dir / "plan.json", {**plan, "executed_profile": args.profile, "executed_trials": trials})
    write_new_json(args.output_dir / "calibration.json", calibration)
    write_new_json(args.output_dir / "environment.json", {
        "started_utc": utc_now(), "profile": args.profile,
        "python": platform.python_version(), "kernel": platform.release(),
        "machine": platform.machine(), "cpu_ids": choose_cpu_ids(),
        "source_files": {
            relative: file_sha256(PROJECT_ROOT / relative) for relative in SOURCE_FILES
        },
        "config_sha256": file_sha256(_CONFIG_PATH),
        "tc_binary": args.tc, "tc_sha256": file_sha256(Path(args.tc)),
        "evidence_boundary": config.evidence_boundary,
    })
    anchor: subprocess.Popen[str] | None = None
    client_pid = -1
    records: list[dict[str, Any]] = []
    try:
        anchor, client_pid = start_client_anchor()
        write_new_json(args.output_dir / "topology.json", configure_topology(config, client_pid))
        cpu_ids = choose_cpu_ids()
        for ordinal, trial in enumerate(trials, start=1):
            print(f"[{ordinal}/{len(trials)}] {trial['trial_id']}", flush=True)
            record = run_trial(config, coupled, models, trial, args.tc, client_pid, cpu_ids)
            write_new_json(raw_dir / f"{trial['trial_id']}.json", record)
            records.append(record)
            if ordinal < len(trials):
                time.sleep(float(config.timing["cooldown_between_arms_s"]))
    finally:
        if anchor is not None:
            stop_anchor(anchor, client_pid)
    pair_sent: dict[str, list[int]] = {}
    for record in records:
        pair_sent.setdefault(record["trial"]["pair_id"], []).append(record["sender"]["sent_packets"])
    pair_errors = {
        pair: {
            "sent_counts": values,
            "absolute_difference": max(values) - min(values),
            "relative_difference": (
                (max(values) - min(values)) / max(values) if max(values) else 0.0
            ),
        }
        for pair, values in pair_sent.items()
        if len(values) != 2 or (
            (max(values) - min(values)) / max(values) if max(values) else 0.0
        ) > float(config.validity["maximum_within_pair_sent_count_relative_difference"])
    }
    summary = {
        "schema_version": "selector-htb-campaign-1.0", "completed_utc": utc_now(),
        "profile": args.profile, "planned_trial_count": len(trials),
        "completed_trial_count": len(records),
        "valid_trial_count": sum(record["valid"] for record in records),
        "invalid_trial_count": sum(not record["valid"] for record in records),
        "within_pair_sent_count_errors": pair_errors,
        "mechanical_pass": len(records) == len(trials)
        and all(record["valid"] for record in records) and not pair_errors,
    }
    write_new_json(args.output_dir / "summary.json", summary)
    print(json.dumps(summary, sort_keys=True), flush=True)
    if not summary["mechanical_pass"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
