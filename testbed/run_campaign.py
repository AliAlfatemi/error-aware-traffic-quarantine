#!/usr/bin/env python3
"""run_campaign.py -- runs many trials of concurrent benign+attack traffic
against each requested baseline, inside the isolated two-namespace testbed
created by setup_netns.sh, and writes one raw JSON record per trial.

This is a REDUCED-SCALE PILOT campaign, not the fully frozen
CONFIRMATORY_PROTOCOL_V2.md study (which specifies 30 repetitions, 60s
measurement windows, and the full traffic-family/offered-load sweep). It
exists to get real, measured, oracle-routed tc/HTB mechanism data into the
manuscript now, while the XDP classifier remains unattached (no CAP_BPF --
see SERVER_ENVIRONMENT_REPORT.md). Every output file and manuscript
sentence built from this data must say "pilot" / "reduced-scale" /
"oracle-routed testbed", never "confirmatory".

Must be run on the host that owns the server/client anchor PIDs (i.e. on
the selected execution host itself, not proxied through another remote shell), because it uses
nsenter directly and needs precise process lifecycle control that a chain
of separate SSH invocations cannot reliably provide (see
COMPLETE_EXPERIMENT_LOG_V2.md for the background-process bugs that
motivated writing this in Python instead of bash).

Usage:
  python3 run_campaign.py --server-pid P --client-pid P \
      --baselines B0,B3,B5,B6 --reps 10 \
      --warmup-s 1 --measure-s 8 \
      --benign-rate-pps 200 --attack-rate-pps 3000 --attack-packet-size 1500 \
      --output-dir results_v2/pilot_campaign
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

TESTBED_DIR = Path(__file__).resolve().parent


def nsenter_server_cmd(server_pid: str, inner: list[str]) -> list[str]:
    return ["nsenter", "--target", server_pid, "--net", "--user", "--preserve-credentials", "--"] + inner


def nsenter_client_cmd(server_pid: str, client_pid: str, inner: list[str]) -> list[str]:
    # Double nsenter: the client netns is nested under the server anchor's
    # user namespace (see setup_netns.sh) -- a single `nsenter --net` from
    # the host lacks the capability to join it directly.
    return [
        "nsenter", "--target", server_pid, "--net", "--user", "--preserve-credentials", "--",
        "nsenter", "--target", client_pid, "--net", "--",
    ] + inner


def run_baseline_apply(server_pid: str, client_pid: str, baseline: str) -> None:
    r = subprocess.run(
        ["bash", str(TESTBED_DIR / "apply_htb_baseline.sh"), server_pid, client_pid, baseline],
        capture_output=True, text=True, timeout=20,
    )
    if r.returncode != 0:
        raise RuntimeError(f"apply_htb_baseline.sh {baseline} failed: {r.stdout[-2000:]}\n{r.stderr[-2000:]}")


def kill_group(proc: subprocess.Popen, grace_s: float = 1.0) -> None:
    if proc.poll() is not None:
        return
    try:
        proc.send_signal(signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        proc.wait(timeout=grace_s)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        proc.wait(timeout=grace_s)


def last_json_line(text: str) -> dict:
    for line in reversed(text.strip().splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
    return {}


def run_trial(args, baseline: str, rep: int) -> dict:
    server_pid, client_pid = args.server_pid, args.client_pid
    port = 9100 + (rep % 50)  # rotate ports across reps to avoid TIME_WAIT collisions
    total_duration = args.warmup_s + args.measure_s + 1.0  # +1s drain

    run_baseline_apply(server_pid, client_pid, baseline)

    controller_proc = None
    if baseline == "B6":
        controller_proc = subprocess.Popen(
            ["bash", str(TESTBED_DIR / "sbeq_budget_controller.sh"), server_pid, client_pid,
             "--iterations", "0", "--poll-interval-ms", "50"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )

    server_proc = subprocess.Popen(
        nsenter_server_cmd(server_pid, [
            "python3", str(TESTBED_DIR / "traffic_gen.py"), "server",
            "--bind-ip", "198.51.100.9", "--port", str(port),
            "--duration-s", str(total_duration + 5),
        ]),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    time.sleep(0.3)

    benign_proc = subprocess.Popen(
        nsenter_client_cmd(server_pid, client_pid, [
            "python3", str(TESTBED_DIR / "traffic_gen.py"), "client",
            "--bind-ip", "198.51.100.10", "--target-ip", "198.51.100.9", "--port", str(port),
            "--mode", "benign", "--duration-s", str(args.measure_s),
            "--rate-pps", str(args.benign_rate_pps),
        ]),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    attack_proc = subprocess.Popen(
        nsenter_client_cmd(server_pid, client_pid, [
            "python3", str(TESTBED_DIR / "traffic_gen.py"), "client",
            "--bind-ip", "198.51.100.10", "--target-ip", "198.51.100.9", "--port", str(port),
            "--mode", "flood", "--duration-s", str(args.measure_s),
            "--rate-pps", str(args.attack_rate_pps), "--packet-size", str(args.attack_packet_size),
        ]),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )

    benign_out, _ = benign_proc.communicate(timeout=args.measure_s + 10)
    attack_out, _ = attack_proc.communicate(timeout=args.measure_s + 10)
    time.sleep(1.0)  # drain

    kill_group(server_proc)
    server_out = server_proc.stdout.read() if server_proc.stdout else ""

    controller_stats = {"revoke_events": 0, "restore_events": 0}
    if controller_proc is not None:
        kill_group(controller_proc, grace_s=2.0)
        ctrl_out = controller_proc.stdout.read() if controller_proc.stdout else ""
        controller_stats["revoke_events"] = ctrl_out.count("budget_exceeded_revoke")
        controller_stats["restore_events"] = ctrl_out.count("window_rollover_restore")

    benign_final = last_json_line(benign_out)
    attack_final = last_json_line(attack_out)
    server_final = last_json_line(server_out)

    return {
        "baseline": baseline,
        "rep": rep,
        "port": port,
        "warmup_s": args.warmup_s,
        "measure_s": args.measure_s,
        "benign_rate_pps": args.benign_rate_pps,
        "attack_rate_pps": args.attack_rate_pps,
        "attack_packet_size": args.attack_packet_size,
        "benign_sent_packets": benign_final.get("packets_sent", 0),
        "benign_sent_bytes": benign_final.get("bytes_sent", 0),
        "attack_sent_packets": attack_final.get("packets_sent", 0),
        "attack_sent_bytes": attack_final.get("bytes_sent", 0),
        "benign_delivered_packets": server_final.get("benign_packets", 0),
        "benign_delivered_bytes": server_final.get("benign_bytes", 0),
        "attack_delivered_packets": server_final.get("attack_packets", 0),
        "attack_delivered_bytes": server_final.get("attack_bytes", 0),
        "controller_revoke_events": controller_stats["revoke_events"],
        "controller_restore_events": controller_stats["restore_events"],
        "ts_unix": time.time(),
    }


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--server-pid", required=True)
    p.add_argument("--client-pid", required=True)
    p.add_argument("--baselines", required=True, help="comma-separated, e.g. B0,B3,B5,B6")
    p.add_argument("--reps", type=int, default=10)
    p.add_argument("--warmup-s", type=float, default=1.0)
    p.add_argument("--measure-s", type=float, default=8.0)
    p.add_argument("--benign-rate-pps", type=float, default=200.0)
    p.add_argument("--attack-rate-pps", type=float, default=3000.0)
    p.add_argument("--attack-packet-size", type=int, default=1500)
    p.add_argument("--output-dir", required=True)
    p.add_argument("--seed-offset", type=int, default=0, help="added to rep index in trial ids, for resuming/extending a campaign without id collisions")
    args = p.parse_args()

    baselines = args.baselines.split(",")
    out_dir = Path(args.output_dir)
    raw_dir = out_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    manifest = {
        "schema_version": "pilot-campaign-1.0",
        "study_label": "reduced_scale_pilot_not_confirmatory",
        "server_pid": args.server_pid,
        "client_pid": args.client_pid,
        "baselines": baselines,
        "reps_per_baseline": args.reps,
        "started_unix": time.time(),
        "trial_ids": [],
    }

    total = len(baselines) * args.reps
    done = 0
    for baseline in baselines:
        for rep in range(args.seed_offset, args.seed_offset + args.reps):
            trial_id = f"{baseline}_{rep:03d}"
            print(f"[{done+1}/{total}] running {trial_id}...", file=sys.stderr, flush=True)
            try:
                record = run_trial(args, baseline, rep)
            except Exception as e:  # noqa: BLE001 -- record failure, keep campaign going
                record = {"baseline": baseline, "rep": rep, "error": str(e), "ts_unix": time.time()}
                print(f"  FAILED: {e}", file=sys.stderr, flush=True)
            out_path = raw_dir / f"{trial_id}.json"
            out_path.write_text(json.dumps(record, indent=2))
            manifest["trial_ids"].append(trial_id)
            done += 1
            print(f"  ok: benign_delivered={record.get('benign_delivered_bytes','?')}B "
                  f"attack_delivered={record.get('attack_delivered_bytes','?')}B "
                  f"revokes={record.get('controller_revoke_events','?')}", file=sys.stderr, flush=True)

    manifest["finished_unix"] = time.time()
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"campaign complete: {done} trials written to {raw_dir}", file=sys.stderr)


if __name__ == "__main__":
    main()
