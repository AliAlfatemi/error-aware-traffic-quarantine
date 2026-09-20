# Final bounded experimental protocol

Frozen: 2026-08-08, before execution of either analysis defined below.

Status: prospectively frozen for this revision, but **not independently
preregistered**. This document supersedes the earlier confirmatory protocol,
which remains recoverable from Git and the read-only baseline snapshot but is
excluded from the release. The earlier design is not executable as a
confirmatory protocol because its privilege assumptions, primary-load
definition, buffer fields, thresholds, and precision rationale do not match
the available system or final configuration.

Protocol SHA-256 is recorded in the new result manifests before analysis.
Any change after a result is observed must be appended to the amendment log
and downgrades the affected result to exploratory.

## 1. Scientific decision and evidence boundary

The revision follows the mandatory fallback: an error-aware accounting and
experimental-identifiability study. It does not attempt to establish a
deployed DDoS defense.

The authorized Linux host has sufficient CPU and memory and supports rootless
user/network namespaces, veth, and `tc`. However, the account has no sudo,
Docker-daemon access, `CAP_BPF`, or `CAP_NET_ADMIN` in the initial user
namespace; `kernel.unprivileged_bpf_disabled=2`. Therefore an XDP program
cannot be verifier-loaded or attached. The existing XDP ELF remains
compile-only evidence.

New work is limited to:

1. descriptive sensitivity of RT-IoT2022 results to exact learned-input
   grouping; and
2. a single-host, rootless Linux veth/HTB scheduler diagnostic with
   maturity-matched oracle class marks.

Neither analysis supplies capture-level generalization, online ingress
classification, XDP steering, physical-link performance, or line-rate
evidence.

## 2. Study A — RT-IoT2022 exact-input-group sensitivity

### 2.1 Purpose

Quantify how the reported completed-flow classifiers and timing comparators
change across repeated partitions that prevent an identical compact
learned-input tuple from crossing train, calibration, and test. These tuples
are deduplication groups only. They are **not** capture, device, session,
source, or time identities. Atomic compact-tuple assignment proves exact-input
separation for the compact logistic and reference random forest. It does not
prove equality separation for the lower-dimensional projections used by the
hand-built timing comparators.

### 2.2 Frozen inputs and model family

- Dataset: the official UCI RT-IoT2022 table verified by the hashes in
  `data/public/rt_iot2022/PROVENANCE.md`.
- Learned-input columns and label normalization: exactly those used by
  `experiments/public_rt_iot2022.py`.
- Models: the existing compact logistic and reference random-forest learned
  models, plus the rate-only, dispersion-only, and timing-OR calibrated
  hand-built comparators, with the same preprocessing and calibration-only
  threshold rules. No feature or model is selected using a test partition.
- Split unit: hash/equality group of the exact learned-input tuple.
- Split seeds: the fixed 30-element list in
  `configs/public_group_sensitivity.json`.
- Target row fractions are fixed in that configuration. A group is assigned
  atomically, so realized row fractions may differ and must be reported.

### 2.3 Outputs

For every split and model, retain:

- row, exact-group, benign-family, and attack-family counts by partition;
- proof that no exact compact learned-input group crosses partitions for the
  two learned models, plus explicit cross-partition equality-overlap counts for
  each timing comparator's lower-dimensional projection;
- confusion counts and flow-row precision, recall, specificity, FPR, FNR,
  and F1;
- macro recall over attack families and macro FPR over benign families;
- equal-exact-group-weighted accuracy, recall, and FPR;
- largest test-group identity hash and row share; and
- dominant-test-group removal sensitivity.

Across 30 splits, report the empirical median, range, and percentile interval
of each descriptive metric. These intervals describe split sensitivity only;
they are not sampling intervals for a deployment population. No row-level
p-values are permitted. In addition, within each split and metric variant,
run a deterministic 2,000-replicate IID exact-group cluster bootstrap using
one shared resampled-group multiplicity vector across selectors. Report
2.5th--97.5th percentile intervals using NumPy's `linear` percentile method
for row recall and FPR. Present-family macro intervals are emitted only when
every included family has at least ten exact groups; otherwise they are
explicitly undefined. Retain both replicate-level and interval-level CSV
records. These are within-release exact-group-resampling sensitivity
intervals, not capture-level or population confidence intervals.

### 2.4 Failure rules

The stage fails closed on a source-hash mismatch, missing value not handled by
the frozen preprocessing, non-finite output, duplicate JSON key, group leakage,
an empty required binary class, stale output directory, or a manifest/file-hash
mismatch. A rare family absent from one partition is retained as a zero count
with an undefined/null family metric and an explicit absent-family list; its
seed is never replaced. Failed splits remain listed with reasons and are not
silently replaced.

## 3. Study B — matched rootless Linux scheduler diagnostic

Study-B semantic design SHA-256: cb7a929f447fcdfa2cb614ffe997a21f4cdd5aa9dd98e2d9cd9b010a20e225b1

### 3.1 Question, treatment, and estimands

Under one rootless veth bottleneck and fixed oracle class marks, what is the
effect of allowing unused reserved capacity to be borrowed? The treatment is
a work-conserving HTB reservation in which both child ceilings equal the root
capacity. The comparator is the same two-class HTB tree with each child
ceiling equal to its reservation.

The paired treatment-minus-comparator estimands are:

1. benign application-payload goodput (B/s), using packets whose receiver
   arrival time is in `[warmup_end, measurement_end)`;
2. benign conditional RTT p99 (ms), using successfully echoed flagged probes
   sent during measurement; and
3. suspicious-class application-payload service (B/s), using the same receiver
   arrival window.

Probe delivery/loss is always reported beside conditional p99; unacknowledged
probes are not converted into low latency. The third endpoint is not called
protected-service attack leakage because both oracle-marked classes terminate
at the diagnostic receiver.

### 3.2 Exact factor matching

The following must be identical within a pair:

| Factor | Frozen match |
|---|---|
| Host, kernel, namespace anchors | Same live process identities and namespaces |
| Interface topology | One shared veth pair, exact addresses and route |
| Queue tree | HTB root with `direct_qlen 0`, two children, two `bfifo` leaves, two TOS filters |
| Total service | 8,000,000 qdisc/SKB B/s root rate and ceiling |
| Reservations | Primary FAST 5,600,000 B/s; suspicious 2,400,000 B/s |
| Buffer semantics | Tail-drop `bfifo`; 20 ms of each child's reserved rate |
| HTB parameters | Same rates, bursts, cbursts, quanta, priorities, and link layer |
| Packet schedule | Same seed, payload, rates, skipped-slot rule, and start time |
| Classification | Sender-supplied oracle TOS; no learned selector or maturation |
| Processes/sockets | Same receiver plus benign and suspicious UDP senders |
| CPU placement | Receiver 4, benign sender 6, suspicious sender 8 |
| Timing/cohort | Same warm-up, receiver-arrival measurement window, and drain |
| Instrumentation | Same process, UDP, namespace, and four-snapshot `tc -s -j` records |

The only intended static difference is the FAST and suspicious child `ceil`:
the reservation in the fixed arm and 8,000,000 B/s in the work-conserving
arm. Any other material requested or emitted `tc` difference invalidates the
pair.

### 3.3 Byte domains and load regimes

Each UDP application payload is 1,200 bytes. The corresponding IPv4/UDP
datagram is 1,228 bytes. Pre-authoritative live `tc` probing on the frozen
veth path established a separate 1,242-byte qdisc/SKB accounting unit per
successfully sent packet. This is not a physical-wire size; physical-wire
bytes are unmeasured. Payload and qdisc counters are retained separately.

| Regime | Benign packet/s | Suspicious packet/s | Role | Pairs |
|---|---:|---:|---|---:|
| `no_attack` | 7,500 | 0 | Secondary utilization/cost | 10 |
| `low_total` | 2,500 | 800 | Secondary underload | 10 |
| `borrowable_overload` | 7,500 | 800 | **Primary** | 30 |
| `both_saturated` | 5,000 | 5,000 | Negative control | 10 |

The primary schedule offers 9.96 MB/s of application payload and
$8{,}300\times1{,}242=10.3086$ MB/s in the frozen qdisc/SKB accounting unit,
both above the 8 MB/s root. Benign demand exceeds every evaluated FAST
reservation. Suspicious demand is 0.9936 MB/s in qdisc units, below even the
smallest 1.2 MB/s suspicious reservation, so unused suspicious reservation is
available to borrow. In `both_saturated`, both children have unmet demand;
that condition is retained as a borrowing-inactive negative control.

### 3.4 Blocks, durations, reservation policy, and order

- Standard arms use 5 s warm-up, 20 s receiver-arrival measurement, and 2 s
  drain. A descriptive duration check uses five paired primary-load blocks
  with a 60 s measurement; no 300 s arm is claimed.
- The primary 70/30 FAST/suspicious allocation is a transparent illustrative
  SLO policy: 5,600,000/2,400,000 B/s. It was not optimized or tuned against
  outcomes.
- Descriptive reservation sensitivity uses five primary-load pairs at each of
  50/50 (4,000,000/4,000,000 B/s), 70/30, and 85/15
  (6,800,000/1,200,000 B/s). Leaf limits are exactly 20 ms of reservation:
  80,000/80,000, 112,000/48,000, and 136,000/24,000 bytes.
- Pair sequence is deterministically randomized. Arms remain adjacent and use
  the same traffic seed. Arm order is constrained to 15/15 for the 30-pair
  primary stratum, 5/5 in each 10-pair stratum, and alternating 3/2 versus 2/3
  across five-pair strata.
- No endpoint-directed replacement, optional stopping, or order change is
  permitted.

The authoritative plan is 80 pairs (160 arms): 60 standard, five duration,
and 15 reservation-sensitivity pairs. Expected wall time is about 90--105
minutes including gates and overhead, plus any wait for an eligible quiet
window.

Thirty primary blocks follow the requested floor. No comparable variance
estimate exists for a prospective power calculation, so inference is
precision-based: interval widths and all raw paired effects are reported. The
study does not infer adequate power from $N=30$.

### 3.5 Statistics and practical thresholds

For the three primary endpoints, retain paired effects, a 10,000-replicate
fixed-seed paired percentile bootstrap interval, an exact two-sided paired sign
test, and Holm correction over the three-endpoint family at $\alpha=0.05$.
The frozen practical thresholds are 80,000 B/s (1% of root service) for each
rate endpoint and 5 ms for conditional RTT p99. Statistical detectability does
not override these thresholds. No-attack, low-total, both-saturated, duration,
reservation-ratio, probe-loss, CPU, and qdisc-counter analyses are descriptive.

### 3.6 Readiness, schedule fidelity, and CPU control

The receiver and both senders first bind their sockets, pin to their frozen
CPUs, and emit machine-readable readiness records. Only after all three are
ready is one shared future start selected; each process must have at least
0.25 s lead. Expired constant-rate slots are skipped and never emitted as a
catch-up burst. For each warm-up and measurement phase,
`planned = sent + missed + errors`; no more than 1% of slots may be missed,
send-lateness p99 must be at most 2 ms, and phase-snapshot start lateness must
be at most 50 ms. Within a pair, successful sent counts may differ by at most
0.5% and send-lateness p99 by at most 1 ms.

Exactly 100 evenly spaced benign packets/s are flagged as RTT probes in the
authoritative schedule; only flagged probes are echoed. Planned, sent,
received, unacknowledged, and lost probe counts are retained. Conditional
nearest-rank p99 is valid only with at least 500 successfully delivered
measurement probes and zero malformed, wrong-class, duplicate, or non-probe
echo errors.

Before each arm, `/proc/stat` is sampled for one second separately on logical
CPUs 4, 6, and 8. An arm is invalid if any assigned CPU exceeds 20% busy.
Whole-host aggregate load is descriptive and is not an exclusion trigger. The
three IDs map to distinct physical cores 4/6/8 on socket 0 and NUMA node 0,
with no SMT sibling overlap; they were selected from pre-outcome background
control and remain fixed.

### 3.7 Namespace, queue, and counter gates

Before and after every arm, the runner requires stable PID/start-tick/UID/user-
namespace/network-namespace identities. The server namespace contains only
`lo` and `sbeq0-shared`, with `127.0.0.1/8` and `198.51.100.9/30`; the client
contains only `lo` and `sbeq0-shrpeer`, with `127.0.0.1/8` and
`198.51.100.10/30`. Each has only the connected `198.51.100.8/30` main route,
no default, disabled IPv6, and a permanent peer neighbor installed before
`tc` to exclude ARP from measurement.

At arm start, measurement start, measurement end, and arm end, normalized
`tc` JSON must show exactly the frozen root, three classes, two `bfifo` leaves,
and two u32 TOS filters, including parents/handles, rates/ceilings,
root `direct_qlen 0`, 91,392-byte common bursts/cbursts, quanta, priorities, link-layer fields,
buffer limits, filter protocol/priority/header/table/rules, and counters. Pair
analysis proves that normalized B3/B5 static state differs only in the two
child ceilings.

Every valid arm requires nonnegative, monotone root/class/leaf packet, byte,
drop, and backlog records. Measurement-window root departures must reconcile
with receiver arrivals within the frozen absolute tolerance; whole-arm
departures plus drops must reconcile with successful sends, and the observed
departure byte/packet ratio must equal the frozen 1,242-byte qdisc unit. UDP
`InErrors`, `RcvbufErrors`, and `SO_RXQ_OVFL` must remain zero. Sender-phase
by receiver-arrival-window matrices, measurement-origin packets delivered in
drain, and all cross-boundary cohorts remain separate from the primary arrival
window.

### 3.8 Failure, publication, and verification rules

An unexpected process exit, non-finite value, missing field, hash/source drift,
topology or `tc` mismatch, schedule/readiness/CPU/counter/probe gate failure,
missing arm, or invalid arm invalidates its pair. Every record and reason is
retained; no arm is silently discarded or rerun. An authoritative campaign
with any invalid or missing arm/pair writes its complete manifests and exits
nonzero.

Analysis validates all raw records before transactionally publishing an
`analysis/` directory and final inventory. The read-only completed-tree
verifier rehashes the exact config, protocol, canonical source set, campaign,
raw, analysis, and final trees. It independently recomputes arm and pair
validity, receiver-arrival endpoints, exact paired-effect CSV bytes, bootstrap
intervals, sign tests, Holm adjustment, descriptive summaries, and the binary
`study_B_pass`; a hash-valid failed study cannot be packaged as accepted
evidence.

## 4. Existing evidence retained unchanged

The six-stage v1 result tree remains immutable under fingerprint
`5c11bf7286423dc45782ea6b0a9345665308d2dd4abb77abcd689cc791023485`.
Its negative results, same-selector effects, buffer confound, provisional
exposure, public-data dependence, and localhost limitations remain visible.

The prior `results_v2/pilot_campaign/` is rejected as confirmatory evidence:
it is unpaired, sequential, unsaturated, unseeded, lacks a real warm-up and
required telemetry, and predates a material controller correction. It may be
retained outside submission packages as historical bring-up provenance only.

## 5. Claims permitted after execution

If both new studies pass their mechanical gates, the manuscript may claim
only:

- descriptive sensitivity to exact-input grouping in one completed-flow
  dataset; and
- a causal effect of HTB borrowing versus fixed ceilings in the specifically
  matched, rootless, oracle-labeled single-host diagnostic.

It may not infer online detection, XDP feasibility/performance, capture-level
generalization, physical isolation, multi-host behavior, or deployable DDoS
protection.

## 6. Amendment log

- 2026-08-08, before any authoritative Study A output existed: Section 2.2 was
  clarified to enumerate all five selectors already named by the frozen
  configuration. The compact logistic model had been inadvertently omitted
  from the prose phrase "timing-rule and random-forest families"; no feature,
  split, outcome, or analysis rule changed.
- 2026-08-08, before any authoritative Study A output existed: Sections
  2.1--2.3 were narrowed to distinguish exact compact-tuple separation for the
  two learned models from projection overlap in the three calibrated timing
  comparators. The output audit now reports that overlap; partitions and
  estimands are unchanged.
- 2026-08-08, before any authoritative Study A output existed: Section 2.4 was
  corrected so rare-family absence is retained as a zero count and null metric,
  not treated as a failed split. This prevents outcome-dependent seed
  replacement while preserving binary-class fail-closed behavior.
- 2026-08-08, before any authoritative Study A output existed: Section 2.3
  added the requested exact-group cluster-bootstrap sensitivity. The method,
  replicate count, shared selector resamples, percentile method, and minimum
  family support rule were frozen before execution. The intervals are
  explicitly not capture or population intervals.
- 2026-08-08, before any authoritative Study B output existed: Sections
  3.2--3.5 added the requested 50/50, 70/30, and 85/15 reservation sensitivity,
  recomputed 20-ms leaf buffers, the non-optimized 70/30 policy rationale, and
  the payload/qdisc/wire accounting distinction. The primary 70/30 estimand,
  endpoints, thresholds, and block count did not change.
- 2026-08-08, before any authoritative Study B output existed: the planned
  5,000/5,000-packet/s primary schedule was found mechanically incapable of
  identifying borrowing because both children were reservation-saturated.
  The primary was corrected prospectively to 7,500/800 packet/s, which leaves
  suspicious reservation idle while benign demand exceeds its reservation;
  5,000/5,000 was retained as a 10-pair negative control. This changed the
  complete plan from the superseded 70-pair draft to 80 pairs. No endpoint
  observation informed the correction.
- 2026-08-08, before any authoritative Study B output existed: live
  configuration preflight established a common 91,392-byte HTB burst/cburst
  emitted consistently across every frozen rate and a 1,242-byte veth
  qdisc/SKB accounting unit per 1,200-byte payload packet. These are mechanical
  unit/configuration facts, not performance outcomes or physical-wire claims.
- 2026-08-08, before any authoritative Study B output existed: the background
  exclusion was corrected from a whole-host aggregate to the three assigned
  logical CPUs individually, with frozen distinct-core IDs 4/6/8. Whole-host
  load remains descriptive. CPU selection used pre-outcome load/topology only.
- 2026-08-08, before any authoritative Study B output existed: Sections
  3.1 and 3.6--3.8 froze receiver-arrival service windows, separate drain and
  cross-boundary cohorts, flagged sparse RTT probes, all-process readiness,
  skipped expired slots, timing fidelity, exact namespace and four-snapshot
  `tc` topology, UDP/qdisc conservation, nonzero-on-invalid execution,
  transactional analysis, and full read-only statistical recomputation. A
  non-evidentiary engineering smoke used while implementing these gates is not
  a result and cannot be promoted.
- 2026-08-08, before any authoritative Study B output existed: the canonical
  Study-B semantic-design digest was added independently of the full protocol
  hash so a stale prose/config pair fails even when an old protocol hash still
  matches. No authoritative output directory had been created.
