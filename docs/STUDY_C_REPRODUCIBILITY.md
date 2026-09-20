# Study C reproducibility guide

Study C is the completed matched rootless Linux HTB experiment governed by
[`STUDY_C_EXECUTION_PROTOCOL.md`](../STUDY_C_EXECUTION_PROTOCOL.md). It compares
fixed child ceilings (B3) with work-conserving borrowing (B5) while holding the
traffic, reservations, buffers, filters, processes, and instrumentation fixed.
The IPv4 TOS marks are oracle labels, so the experiment identifies scheduler
behavior rather than selector accuracy.

## Frozen execution source

The completed campaign recorded a twelve-file source inventory before any arm
ran. The exact paths, sizes, and SHA-256 digests are committed in
[`provenance/study_c_source_manifest.json`](../provenance/study_c_source_manifest.json).
The test suite verifies those bytes on every push.

Several compatibility names in that immutable source predate Study C:

- `testbed/MATCHED_SCHEDULER.md` is the Study B execution-era guide retained
  because the completed Study C campaign hashes that file;
- the stored analysis field `study_B_pass` is a legacy schema key whose value
  is recomputed as the mechanical pass decision for the campaign identified by
  `study_id`; and
- some comments in the isolation helper use the older generic setup-script
  name.

These names do not change the Study C configuration, protocol, endpoints, or
result interpretation. Do not edit the twelve frozen files merely to modernize
their wording: doing so would correctly make the completed-tree verifier reject
the source as drifted.

## Portable checks

Installation and unit tests are described in the repository README. The
deterministic authoritative plan can be inspected without network privileges:

```bash
python testbed/run_matched_scheduler.py \
  --profile authoritative \
  --plan-only > /tmp/ciq-study-c-plan.json
```

The plan contains 80 adjacent randomized pairs and 160 arms. This command does
not create namespaces or result files.

## Live execution boundary

Live execution requires Linux, unprivileged user/network namespaces, `ip`,
`tc`, `unshare`, and `nsenter`. The frozen configuration also requires logical
CPUs 4, 6, and 8 to map to raw sysfs core IDs 2, 5, and 3 on package 0 and NUMA
node 0, with disjoint sibling sets. The runner fails before traffic if that
topology or any isolation gate differs. This host binding is deliberate and
must not be weakened to make another machine pass.

A smoke run is engineering-only:

```bash
python testbed/run_matched_scheduler.py \
  --profile smoke \
  --manage-namespaces \
  --output-dir outputs/matched-scheduler-smoke

python -m experiments.matched_scheduler_analysis \
  --input-dir outputs/matched-scheduler-smoke

python -m experiments.matched_scheduler_analysis \
  --input-dir outputs/matched-scheduler-smoke \
  --verify-completed \
  --allow-failed-study
```

Smoke endpoints are non-evidentiary and must not be cited. The authoritative
campaign was executed once under its prospectively frozen protocol. A later
execution is a reproduction and must use a new create-only result tree; it
must never replace, extend, or be pooled into the completed campaign.

## Read-only verification of released evidence

After obtaining the completed `study_c_compute_a` result tree from the release
archive, verify it without modifying any file:

```bash
python -m experiments.matched_scheduler_analysis \
  --input-dir /path/to/study_c_compute_a \
  --verify-completed
```

The verifier authenticates the closed file inventories, source/config/protocol
hashes, raw arm validity, pair fidelity, endpoint reconstruction, paired
bootstrap intervals, exact sign tests, Holm adjustment, and final content
fingerprint. A hash-valid failed campaign can be inspected only by explicitly
adding `--allow-failed-study`; it cannot support a scheduler-effect claim.
