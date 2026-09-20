# Manuscript-to-artifact map

This map identifies the code and evidence boundary behind each manuscript
claim. It is intentionally explicit about what each stage cannot establish.

| Evidence stage | Primary implementation | Frozen input or protocol | Verification boundary |
|---|---|---|---|
| Timing-only historical baseline | `experiments/timing_baseline.py` | `configs/timing_baseline.json` | Synthetic timing behavior; no kernel or deployment claim |
| Coupled accounting simulation | `experiments/coupled_simulation.py` | `configs/coupled_simulation.json` | Selector, queue, buffer, and dwell mechanisms under deterministic simulation |
| RT-IoT2022 completed-flow evaluation | `experiments/public_rt_iot2022.py` | `configs/public_rt_iot2022.json`; `data/public/rt_iot2022/PROVENANCE.md` | Duplicate-input-safe completed-flow analysis; no packet-level or capture-held-out claim |
| Thirty-split exact-group sensitivity | `experiments/public_group_sensitivity.py` | `configs/public_group_sensitivity.json`; `EXPERIMENTAL_PROTOCOL_FINAL.md` | Descriptive split and exact-group sensitivity; not population inference |
| Localhost TCP/UDP mechanism study | `prototype/loopback_testbed.py` | `configs/loopback_testbed.json` | User-space localhost sockets; no forwarding-hook or physical-link claim |
| Cross-host localhost replication | `experiments/cross_host_loopback_summary.py` | `protocols/CROSS_HOST_LOOPBACK_PROTOCOL.md` | Three-host descriptive direction check; no host-population inference |
| Matched Linux HTB Study C | `testbed/run_matched_scheduler.py`; `experiments/matched_scheduler_analysis.py` | `configs/matched_scheduler.json`; `STUDY_C_EXECUTION_PROTOCOL.md` | Single-host rootless-veth oracle scheduler causality; no learned selector or XDP claim |
| Selector-to-HTB coupling | `testbed/run_selector_htb.py`; `experiments/seal_selector_htb_campaign.py`; `experiments/selector_htb_analysis.py` | `configs/selector_htb.json`; `protocols/SELECTOR_HTB_PROTOCOL.md`; integrity addendum | Userspace causal selector replay through real HTB; no XDP compute-cost or line-rate claim |
| Statistical synthesis | `experiments/statistical_analysis.py` | `configs/statistical_analysis.json` | Paired effects, fixed multiplicity families, and deterministic manifests |
| State/failure ablations | `experiments/synthetic_ablations.py` | `configs/synthetic_ablations.json` | Synthetic state-capacity and restart-policy effects only |

The computational stages can be orchestrated with
`run_reproducible_experiments.py`. Live network experiments are deliberately
separate because they require Linux namespace capabilities and frozen host
preconditions.

## Evidence distribution

The repository includes the small immutable RT-IoT2022 derived snapshot needed
by the exact-group stage. Licensed source data, full live-campaign trees, and
the manuscript are excluded from Git. Full evidence should be distributed as a
versioned release asset or DOI-backed archive with its recorded tree manifests
unchanged. Compact public lineage records for Study C and the selector-to-HTB
campaign are retained under `provenance/` and verified by the test suite.
