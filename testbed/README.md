# Linux testbed entry points

The maintained public testbed has two experiment paths:

1. `run_matched_scheduler.py` executes the frozen Study C oracle scheduler
   comparison. Use [`docs/STUDY_C_REPRODUCIBILITY.md`](../docs/STUDY_C_REPRODUCIBILITY.md)
   as the reader-facing guide.
2. `run_selector_htb_isolated.sh` and `run_selector_htb.py` execute the
   causal selector-to-HTB campaign governed by
   [`protocols/SELECTOR_HTB_PROTOCOL.md`](../protocols/SELECTOR_HTB_PROTOCOL.md).

`MATCHED_SCHEDULER.md` is retained byte-for-byte because it belongs to the
completed Study C source-hash inventory. Its Study B wording is historical and
it is not the current reader guide. The compatibility details and exact frozen
manifest are documented in the Study C guide.

All live scripts are restricted to disposable rootless network namespaces and
RFC 5737 TEST-NET addresses. They are research instruments, not deployment or
third-party traffic-testing tools.
