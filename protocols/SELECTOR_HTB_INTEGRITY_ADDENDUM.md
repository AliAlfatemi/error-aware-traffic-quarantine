# Selector → HTB Integrity Addendum

Recorded 2026-09-13 after the authoritative campaign had begun and before its
analysis. At the time of this addendum, 16 of 360 raw arm files existed.

This addendum changes no workload, seed, attack scale, selector, scheduler,
packet rule, endpoint, validity threshold, hypothesis, direction, or statistical
method. The running raw-data process and its frozen source files are not
modified or restarted.

Before the already-frozen analysis is allowed to run, an additional semantic
sealer must verify the complete raw inventory, exact plan membership, per-arm
validity records, per-class conservation, live-tc checks, paired trace hashes,
paired sender fidelity, campaign summary, and the current hashes of every
source file captured in `environment.json`. It then writes one create-only
SHA-256 manifest over the complete campaign input tree. Failure blocks analysis.

This safeguard was added because the original campaign summary did not itself
contain a closed-file-set manifest. It narrows the opportunity for undetected
post-run alteration and does not create an outcome-dependent analytic choice.
