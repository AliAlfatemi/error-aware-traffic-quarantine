# Cross-host loopback replication protocol

Frozen: 2026-09-13 before execution on the two additional compute hosts.

Status: prospectively frozen for the two new hosts, not independently
preregistered. The earlier `node003_full` reproduction was inspected before
this protocol and is therefore a disclosed retrospective anchor, not a third
prospective replicate.

## Question and claim boundary

Repeat the exact 480-trial oracle-routed localhost TCP/UDP experiment on two
additional cluster hosts to determine whether the direction of the reported
reservation/containment effects persists and how much the numeric effect
magnitudes vary by host.

This is a descriptive host-replication check. Hosts are not sampled from a
deployment population, `n_hosts=3` is too small for host-level inference, and
results remain user-space localhost evidence rather than XDP, kernel
forwarding, NIC, physical-link, or production evidence.

## Frozen source and environment

- Git revision: `08a72cdd60770ad31327d9dd0acc8f73382c361b`
- `prototype/loopback_testbed.py` SHA-256:
  `dc0d542056f0ceb605df498cf8e7b2be12857044da8d807c08c311af8283170c`
- `configs/loopback_testbed.json` SHA-256:
  `f090a5e29aae3c705f37568dea977ba5e19d747229d50061a6d803106b614139`
- `experiments/statistical_analysis.py` SHA-256:
  `b2014f52cb5238e4650a4384569f490f5681283d8518580c9c264c140a5a701c`
- `requirements.txt` SHA-256:
  `31d8fea3606445927748f3b372d574788396ac486c74e4f08742de177020b725`
- Shared isolated runtime: CPython 3.13.9 with the exact requirements above.

The two new executions use create-only output directories. No failed or
invalid trial is replaced, and no output from one host is copied into another
host's result tree.

## Frozen design

Each host executes the committed configuration without alteration: 30 paired
seeds for each combination of UDP/TCP, shared/isolated mode, and suspicious
offered load 0/160/400/800 frames/s, for 480 trials per host.

For each new host, the existing statistical-analysis implementation is used
without code changes and with only input/output paths adjusted. The two
loopback Holm families remain:

1. oracle benign protection: 24 hypotheses;
2. oracle attack containment: 6 hypotheses.

The primary descriptive checks are fixed before the new runs:

- at 800 suspicious frames/s, report isolated-minus-shared benign frame rate,
  benign p99 latency, benign loss, and attack frame rate for TCP and UDP;
- at zero suspicious input, report the isolated-minus-shared benign p99
  latency cost for TCP and UDP;
- report per-host paired means, 95% paired-seed bootstrap intervals, exact
  sign tests, and within-family Holm decisions exactly as implemented;
- compare the sign of every primary effect across hosts and report the range
  of host-specific means; do not pool seed records across hosts;
- call an effect directionally replicated only when all three hosts have the
  same sign. Statistical significance is reported per host and is not a
  requirement for the descriptive directional label.

## Disclosed prior observation

Before freezing this protocol, the completed `node003_full` reproduction was
known to show the expected overload benefit and idle latency cost, with
host-specific magnitudes differing from the manuscript's earlier host. This
motivated the cross-host check. No threshold or configuration is selected
from the new `node001` or `node002` outcomes.
