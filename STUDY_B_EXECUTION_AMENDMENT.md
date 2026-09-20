# Study B execution amendment

Frozen: 2026-08-09, before any authoritative Study B arm and before any valid
arm under this final design.

Status: prospectively frozen for Study B, but **not independently
preregistered**. This amendment incorporates
`EXPERIMENTAL_PROTOCOL_FINAL.md` at SHA-256
`fc52ec677d93bc2406c1759d42c3d45908d035bddc6f16180d7b9e7d1fd07cf8`
and supersedes only its Study B CPU-topology identification described below.
If the two documents conflict on that identification, this amendment controls.
All other Study B design, execution, validity, and analysis provisions in the
base protocol remain unchanged.

This amendment does not govern or modify Study A. Study A remains bound to the
byte-identical `EXPERIMENTAL_PROTOCOL_FINAL.md` attachment and its recorded
SHA-256.

Study-B semantic design SHA-256: 25a22a06505567fbb5d1201a22ae623f11ed141ce372dfc52d70d43a9c6464ef

## CPU-topology correction

The logical CPU assignments remain exactly receiver 4, benign sender 6, and
suspicious sender 8. All three remain on physical package 0 and NUMA node 0.
The authoritative runtime gate reads the raw package-local values from
`/sys/devices/system/cpu/cpuN/topology/core_id`; it does not compare against
the differently presented core labels from `lscpu -e`.

The corrected frozen mapping is:

| Role | Logical CPU | Raw sysfs `physical_package_id` | Raw sysfs `core_id` | NUMA node | Observed `thread_siblings_list` |
|---|---:|---:|---:|---:|---:|
| Receiver | 4 | 0 | 1 | 0 | 4 |
| Benign sender | 6 | 0 | 4 | 0 | 6 |
| Suspicious sender | 8 | 0 | 2 | 0 | 8 |

Thus the three `(physical_package_id, core_id)` pairs are distinct and their
thread-sibling sets are pairwise disjoint. The CPU choice itself did not
change. It was made from pre-authoritative background control and topology,
not from endpoint outcomes, and remains fixed for the entire campaign.

## Pre-outcome engineering-smoke record

Three non-evidentiary engineering attempts preceded this correction:

1. An earlier smoke under a superseded, pre-final design recorded 14 of 14
   planned arms. All 14 arms were invalid, yielding zero valid pairs out of
   seven. That design still used the superseded whole-host aggregate CPU
   exclusion and pre-correction HTB burst rounding. Its completed-tree content
   fingerprint is
   `76d0f474884471709da3cdf369d1d10b651934a5ebf2c81ce8d2dd7aa50f2ceb`.
   Endpoint records from this run were not used to choose endpoints, outcomes,
   thresholds, traffic, topology, or any other final-design element. The run
   is non-promotable and cannot supply a valid pair or scientific result.
2. A later attempt stopped during namespace setup while obtaining the veth
   MAC address. Zero of 16 smoke arms ran. Identity-checked partial cleanup
   removed the namespace anchors and restored the host-interface inventory to
   its exact pre-setup SHA-256,
   `6e5e21f27619f6565572e8c468a21b555775036bb170bbdfe9cc492fc02b00b2`.
3. The final pre-amendment attempt completed namespace setup and then stopped
   during system metadata validation at `receiver.core_id: 1 != 4`. Zero of 16
   smoke arms ran. Exact teardown removed the namespace anchors and restored
   the same pre-setup host-interface inventory SHA-256.

All three attempts remain immutable, non-evidentiary engineering records. They
cannot be promoted, combined with, or substituted for either a fresh smoke or
the authoritative campaign. No endpoint value from them informed this
amendment or selected any element of the final design.

The superseded Study B semantic-design digest was
`cb7a929f447fcdfa2cb614ffe997a21f4cdd5aa9dd98e2d9cd9b010a20e225b1`.
Apart from the raw sysfs `core_id` correction and the protocol-file binding
needed to record it, the 80-pair/160-arm plan, traffic schedules, HTB settings,
estimands, validity gates, and statistical procedures are unchanged.
