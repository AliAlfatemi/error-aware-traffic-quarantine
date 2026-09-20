# Protocol registry

This registry distinguishes active evidence protocols from immutable historical
records. Uppercase compatibility filenames are preserved when a completed
result manifest or protocol hash binds the exact path or bytes.

| Protocol record | Status | Scientific role |
|---|---|---|
| [`EXPERIMENTAL_PROTOCOL_FINAL.md`](../EXPERIMENTAL_PROTOCOL_FINAL.md) | Frozen 2026-08-08 | Base protocol for the RT-IoT2022 exact-group sensitivity and matched-scheduler lineage |
| [`STUDY_B_EXECUTION_AMENDMENT.md`](../STUDY_B_EXECUTION_AMENDMENT.md) | Historical failed-study record | Documents the prospectively frozen Study B topology correction and non-promotable engineering attempts |
| [`STUDY_C_EXECUTION_PROTOCOL.md`](../STUDY_C_EXECUTION_PROTOCOL.md) | Frozen 2026-09-13; completed campaign | Governs the replacement matched rootless Linux HTB campaign without promoting or pooling failed Study B output |
| [`CROSS_HOST_LOOPBACK_PROTOCOL.md`](CROSS_HOST_LOOPBACK_PROTOCOL.md) | Frozen before the two additional hosts | Governs the descriptive three-host localhost direction check |
| [`SELECTOR_HTB_PROTOCOL.md`](SELECTOR_HTB_PROTOCOL.md) | Frozen before the authoritative campaign | Governs userspace causal selector replay through real Linux HTB |
| [`SELECTOR_HTB_INTEGRITY_ADDENDUM.md`](SELECTOR_HTB_INTEGRITY_ADDENDUM.md) | Disclosed post-start, pre-analysis integrity control | Requires semantic verification and a create-only closed-file seal before selector-to-HTB analysis |

## Compatibility filenames

`EXPERIMENTAL_PROTOCOL_FINAL.md` is an evidence-bound historical pathname.
Here, “FINAL” means the protocol was frozen on its recorded date before the
specified analyses; it does not mean that every later study shares that file
or that the repository is free to rename it. The Study C configuration, the
exact-group sensitivity configuration, generated manifests, and tests all bind
that exact path and SHA-256 digest.

Likewise, `testbed/MATCHED_SCHEDULER.md` and the output key `study_B_pass` are
retained compatibility identifiers in the completed Study C source schema.
The current reader guide is
[`docs/STUDY_C_REPRODUCIBILITY.md`](../docs/STUDY_C_REPRODUCIBILITY.md), which
states their interpretation and verifies the successful campaign's exact
source manifest.

## Interpretation rule

Protocols and amendments are retained even when an execution failed. A failed
study is a negative execution record, not evidence for an endpoint claim, and
is never pooled with a successful replacement campaign. Retention makes the
design history auditable and prevents retrospective rewriting.

The repository makes no verified XDP/eBPF execution claim. Compile-only or
unverified XDP development material is intentionally excluded from the public
artifact.
