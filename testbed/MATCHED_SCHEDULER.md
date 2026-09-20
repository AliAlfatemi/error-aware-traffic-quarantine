# Matched rootless HTB scheduler diagnostic

This guide is self-contained for Study B. It covers only the prospective,
single-host rootless-veth comparison of B3 fixed child ceilings against B5
work-conserving borrowing. It does not run or depend on the historical pilot.
Study B is governed by `STUDY_B_EXECUTION_AMENDMENT.md`, which incorporates
the byte-identical base `EXPERIMENTAL_PROTOCOL_FINAL.md` at its recorded
SHA-256 and corrects only the raw sysfs CPU-core identifiers before any Study B
arm ran. The base file continues to govern the already completed Study A.

## Evidence boundary

The study uses two disposable network namespaces and exactly one veth pair.
Only RFC 5737 TEST-NET-2 addresses are assigned; IPv6 is disabled; no default
route exists; permanent peer-neighbor entries prevent ARP from entering the
measured qdisc counters. The classifier is an oracle IPv4 TOS classifier. This
is a scheduler diagnostic, not an XDP, public-network, multi-host, or
physical-wire experiment.

The frozen root service is 8,000,000 B/s. The primary illustrative SLO policy
reserves 70% for FAST and 30% for suspicious service; it was not optimized
against outcomes. The primary borrowing-active load is 7,500 benign pps and
800 suspicious pps. The 5,000/5,000-pps both-saturated condition is a negative
control because neither class leaves borrowable service idle. Reservation
sensitivity at 50/50, 70/30, and 85/15 is descriptive only.

A UDP payload is 1,200 bytes. On the frozen veth egress path, `tc` counts
1,242 bytes per such departure. That qdisc/SKB unit is neither the 1,228-byte
IPv4/UDP datagram unit nor an unmeasured physical-wire byte count.

Goodput and suspicious service use receiver arrivals in
`[warmup_end, measurement_end)`. The raw record separately retains sender
phase cohorts delivered during the drain and all cross-boundary counts. RTT is
conditional on delivered, deterministically flagged 100-pps benign probes;
only those probes are echoed, and probe loss is reported separately.
Every send-lateness sample is retained losslessly as an authenticated compact
uint64 vector, so the read-only verifier recomputes phase and overall count,
mean, maximum, and exact nearest-rank p99 rather than trusting summaries.

## Requirements

- Linux with `python3`, `ip`, `tc`, `unshare`, `nsenter`, `bash`, and user
  namespaces enabled.
- The invoking account must be able to create an unprivileged user/network
  namespace. Host root and `sudo` are not used.
- Logical CPUs 4, 6, and 8 must be available. Their raw sysfs package-local
  `core_id` values must be 1, 4, and 2 respectively, all on package 0 and NUMA
  node 0, with pairwise-disjoint thread-sibling sets, exactly as frozen in
  `configs/matched_scheduler.json`.
- Run from the repository root. Every output directory must be absent or empty.

## Static checks and plan

```bash
python3 -m unittest tests.test_matched_scheduler tests.test_matched_scheduler_verifier
python3 testbed/run_matched_scheduler.py \
  --profile authoritative \
  --plan-only > /tmp/matched_scheduler_plan.json
```

The authoritative plan must contain 80 pairs and 160 arms. Within each stratum,
first-arm order is constrained to 15/15 for 30 pairs, 5/5 for 10 pairs, and an
alternating 3/2 or 2/3 for five-pair strata.

## Non-evidentiary smoke

```bash
python3 testbed/run_matched_scheduler.py \
  --profile smoke \
  --manage-namespaces \
  --output-dir /tmp/matched_scheduler_smoke_non_evidentiary

python3 -m experiments.matched_scheduler_analysis \
  --input-dir /tmp/matched_scheduler_smoke_non_evidentiary

python3 -m experiments.matched_scheduler_analysis \
  --input-dir /tmp/matched_scheduler_smoke_non_evidentiary \
  --verify-completed \
  --allow-failed-study
```

The smoke profile is engineering-only, rate-scaled, short, and explicitly
non-evidentiary. Never cite its endpoint values. Inspect it, then remove that
exact temporary directory; it is not retained or released.

## Authoritative campaign

Run this only after the protocol prose and `protocol_sha256` have received the
final pre-outcome freeze and all focused tests and smoke checks pass:

```bash
python3 testbed/run_matched_scheduler.py \
  --profile authoritative \
  --manage-namespaces \
  --output-dir results_additional/matched_scheduler

python3 -m experiments.matched_scheduler_analysis \
  --input-dir results_additional/matched_scheduler

python3 -m experiments.matched_scheduler_analysis \
  --input-dir results_additional/matched_scheduler \
  --verify-completed
```

The runner always attempts identity-checked teardown and writes the campaign
manifests before returning failure. For the authoritative profile, any invalid
arm, missing arm, within-pair fidelity failure, setup failure, teardown failure,
or campaign exception causes a nonzero exit. Analysis is transactional. The
public verifier is read-only: it re-hashes the complete tree and independently
recomputes validity, endpoint rows, paired effects, bootstrap intervals, sign
tests, Holm adjustment, sensitivity summaries, plan equivalence, and the final
`study_B_pass` decision.

Persisted diagnostics redact the invoking project root, account home, and host
name. A final byte-level privacy gate records only relative file/token labels
and prevents a leaking campaign from passing.

Expected immutable campaign files are `config.json`, `protocol.md`,
`execution_plan.json`, `source_hashes.json`, `environment.json`, `setup.json`,
`teardown.json`, `campaign_manifest.json`, `campaign_inventory.json`, and one
JSON record per planned arm under `raw/`. Analysis adds an `analysis/` tree and
the final nested tree manifest; consult verifier output for the final content
fingerprint.
