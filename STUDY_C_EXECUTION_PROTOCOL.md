# Study C execution protocol

Frozen: 2026-09-13, before any Study C arm or endpoint observation.

Status: prospectively frozen for this campaign, but not independently
preregistered.

Study-C semantic design SHA-256: 76b5060c593ecc05878b7e8ab219d2891f83d3935d564a45d0a8c8ac0a673484

## Purpose and evidence boundary

Study C is a new matched rootless Linux HTB campaign. It does not replace,
repair, pool with, or promote any arm from the failed frozen Study B. Study B
remains an immutable negative execution record.

The question is: under one veth bottleneck and fixed oracle TOS class marks,
what is the effect of allowing unused reserved capacity to be borrowed? The
comparator is a two-class HTB tree whose child ceilings equal their reserved
rates. The treatment has the same tree, filters, rates, buffers, bursts,
quanta, priorities, traffic, processes, sockets, and instrumentation, but both
child ceilings equal the root capacity. The only intended static difference
within a pair is the two child ceiling values.

This is a single-host scheduler diagnostic. It is not evidence of a learned
online selector, XDP attachment, NIC behavior, physical-wire rate, line rate,
multi-host isolation, or deployment efficacy.

## Lineage and disclosed changes

The design inherits the estimands, traffic regimes, HTB configuration,
randomization, validity gates, statistics, and no-replacement policy from
`EXPERIMENTAL_PROTOCOL_FINAL.md` at SHA-256
`fc52ec677d93bc2406c1759d42c3d45908d035bddc6f16180d7b9e7d1fd07cf8`.

Study C makes only these prospective execution changes:

1. It binds CPU topology to the measured frozen-compute-host sysfs mapping
   rather than the earlier host mapping.
2. It classifies every scheduled slot that remains when the sender crosses the
   measurement-end clock as missed. Such slots are never sent. This closes the
   known `planned = sent + missed + send_errors + 1` accounting defect without
   changing the offered schedule, endpoints, thresholds, or catch-up policy.
3. It uses a new create-only source snapshot and output tree. No Study B result
   is copied into Study C.

The changes were selected from execution diagnostics, not endpoint effects.
Two pre-outcome, non-evidentiary smoke attempts stopped before the first arm.
The first used untouched Study B source and rejected the old-host CPU mapping.
The second used Study C draft metadata derived from `lscpu`; the runtime gate
showed that the raw sysfs core identifiers differ from those labels and that a
literal internal hostname violated the privacy scan. Both attempts tore down
successfully and are retained separately. Neither exposed an endpoint or
informed the design, traffic, estimands, or thresholds.

## Frozen host and CPU assignment

The authoritative campaign runs on the frozen host recorded privately in the
runtime environment. Logical CPUs 4, 6, and 8 are fixed for receiver, benign
sender, and suspicious sender, respectively.

| Role | Logical CPU | Package | Raw sysfs core ID | NUMA node |
|---|---:|---:|---:|---:|
| Receiver | 4 | 0 | 2 | 0 |
| Benign sender | 6 | 0 | 5 | 0 |
| Suspicious sender | 8 | 0 | 3 | 0 |

The three assignments are distinct physical cores. The live runner must reject
the campaign before any arm if the mapping differs.

## Frozen design

The root HTB capacity is 8,000,000 qdisc/SKB B/s. The primary allocation is
5,600,000 B/s FAST and 2,400,000 B/s suspicious. Each leaf's `bfifo` limit is
20 ms of its reserved rate. The packet payload is 1,200 bytes; application
payload and qdisc/SKB counters remain separate.

The standard paired strata are:

| Regime | Benign packet/s | Suspicious packet/s | Pairs |
|---|---:|---:|---:|
| No attack | 7,500 | 0 | 10 |
| Low total | 2,500 | 800 | 10 |
| Borrowable overload | 7,500 | 800 | 30 |
| Both saturated | 5,000 | 5,000 | 10 |

Five additional primary-load pairs use a 60-second measurement. Reservation
sensitivity uses five pairs each at 50/50, 70/30, and 85/15. The complete plan
therefore contains 80 pairs and 160 arms. Pair order and within-pair arm order
are deterministic and randomized from the frozen configuration.

## Endpoints and validity

The three primary treatment-minus-comparator endpoints are benign payload
goodput, benign conditional RTT p99, and suspicious-class payload service.
Primary effects use 30 paired borrowable-overload blocks, a deterministic
10,000-replicate paired percentile bootstrap, an exact paired sign test, and
Holm correction across the three endpoints. The practical thresholds remain
80,000 B/s for rate endpoints and 5 ms for p99.

All frozen schedule, readiness, CPU-background, counter-reconciliation,
socket-overflow, topology, queue-tree, and within-pair fidelity gates remain in
force. Every planned arm must be recorded and every primary pair must be valid
for a mechanical pass. Invalid arms and pairs remain in the result tree. There
is no endpoint-directed replacement, rerun, optional stopping, or threshold
change.

## Publication rule

The completed-tree verifier must independently recompute source hashes,
inventory closure, raw validity, pair validity, endpoints, statistics, and the
final fingerprint. A mechanically failed campaign remains reportable only as a
failed diagnostic and cannot support scheduler-effect inference.
