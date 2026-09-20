# Error-Aware Traffic Quarantine

Research software accompanying **“Error-Aware Accounting for Traffic
Quarantine: Identifying Selector, Scheduler, and Buffer Confounds.”**

The code evaluates how selector errors, scheduling policy, and buffer
allocation affect traffic-quarantine measurements. It contains deterministic
simulation, completed-flow analysis of RT-IoT2022, paired statistical analysis,
a controlled localhost TCP/UDP prototype, and isolated Linux HTB experiments.

## Scope

This is research software, not a production DDoS-mitigation appliance.

The evaluated code paths cover discrete-event simulation, completed-flow data,
an unprivileged user-space localhost prototype, and rootless Linux experiments
with real HTB qdiscs on disposable veth pairs. They do not establish XDP/eBPF
execution, physical-link or NIC behavior, line-rate throughput, or production
efficacy.

## Installation

Use CPython 3.13.3 and the pinned dependencies:

```bash
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Dataset

The licensed RT-IoT2022 source data are not committed. Download the official
UCI archive and verify both published SHA-256 digests with:

```bash
python data/public/rt_iot2022/download.py
```

See [`data/public/rt_iot2022/PROVENANCE.md`](data/public/rt_iot2022/PROVENANCE.md)
for the source, license, hashes, and analysis boundary.

## Tests

After installing the dataset:

```bash
python -m unittest discover -s tests -v
```

The default suite contains 176 tests. Two live localhost socket tests are
intentionally skipped unless explicitly enabled:

```bash
RUN_LIVE_LOOPBACK_TESTS=1 \
python -m unittest tests.test_loopback_testbed.LiveLoopbackTests -v
```

## Run the coupled simulation

Every output directory must be new or empty:

```bash
python -m experiments.coupled_simulation \
  --config configs/coupled_simulation.json \
  --output-dir outputs/coupled-simulation
```

## Run the exact-group public-data sensitivity

This pre-specified analysis repeats the RT-IoT2022 evaluation over 30 fixed
exact-input-group splits. It requires the verified dataset and the committed
frozen public-stage evidence snapshot under `results/public_rt_iot2022/`.

```bash
python -m experiments.public_group_sensitivity \
  --config configs/public_group_sensitivity.json \
  --output-dir results_additional/public_group_sensitivity \
  --acknowledge-final-protocol-frozen
```

Verify an existing completed stage without modifying it:

```bash
python -m experiments.public_group_sensitivity \
  --output-dir results_additional/public_group_sensitivity \
  --verify-completed
```

## Run the matched HTB scheduler experiment

This causal diagnostic compares strict child ceilings with work-conserving
borrowing on the same rootless-veth Linux testbed. Its IPv4 TOS classifier is
an oracle, so this study isolates scheduler behavior rather than selector
accuracy. Read [`testbed/MATCHED_SCHEDULER.md`](testbed/MATCHED_SCHEDULER.md)
and the frozen Study B/C protocols before execution.

```bash
python testbed/run_matched_scheduler.py \
  --profile smoke \
  --manage-namespaces \
  --output-dir outputs/matched-scheduler-smoke

python -m experiments.matched_scheduler_analysis \
  --input-dir outputs/matched-scheduler-smoke \
  --allow-failed-study
```

The smoke profile is engineering-only and must not be cited. The authoritative
campaign has frozen CPU-topology and timing requirements; follow the testbed
guide exactly rather than changing its configuration.

## Run the causal-selector HTB experiment

The live Linux experiment connects the frozen 20-IAT selector to a real HTB
qdisc inside disposable rootless network namespaces. It requires Linux,
unprivileged user namespaces, `ip`, `nsenter`, `unshare`, and a `tc` executable.
Read [`protocols/SELECTOR_HTB_PROTOCOL.md`](protocols/SELECTOR_HTB_PROTOCOL.md)
for the design and evidence boundary. Run the engineering smoke profile before
an authoritative campaign:

```bash
CIQ_PYTHON="$PWD/.venv/bin/python" \
bash testbed/run_selector_htb_isolated.sh \
  --config configs/selector_htb.json \
  --output-dir outputs/selector-htb-smoke \
  --tc /usr/sbin/tc \
  --profile smoke
```

The authoritative profile uses the same command with a new output directory
and `--profile authoritative`. Analyze a mechanically passing campaign with:

```bash
python -m experiments.selector_htb_analysis \
  --input-dir outputs/selector-htb-authoritative \
  --config configs/selector_htb.json \
  --output-dir outputs/selector-htb-analysis
```

## Run the computational pipeline

This runs the timing, public-data, coupled-simulation, and synthetic-ablation
stages. It never overwrites an existing output tree.

```bash
python run_reproducible_experiments.py reproduce-computational \
  --output-root outputs/computational \
  --confirm-expensive
```

Use `--help` on the entry point or any module for its complete CLI.

## Repository layout

- `experiments/` — simulation, public-data, and statistical-analysis code
- `prototype/` — controlled IPv4 localhost TCP/UDP demonstrator
- `testbed/` — rootless isolated-network runners and traffic instrumentation
- `protocols/` — frozen experiment questions, boundaries, and analysis plans
- `configs/` — versioned experiment configurations
- `data/` — verified public-dataset downloader and provenance
- `tests/` — unit, integrity, and invariant tests

## Data, results, and paper

The licensed source dataset, full generated campaign trees, manuscript, and
internal revision records are not Git files. The repository does include the
small immutable `results/public_rt_iot2022/` evidence snapshot required to bind
and reproduce the exact-group sensitivity stage. Larger frozen evidence and
the manuscript should be distributed separately as versioned release assets or
through a DOI-backed research archive.

## Safe use

RT-IoT2022 contains completed-flow aggregates rather than packet timestamps;
it cannot validate online packet maturation or packet-level diversion. Run
network experiments only on systems and traffic that you own or are explicitly
authorized to test.

## Citation and license

Use [`CITATION.cff`](CITATION.cff) for citation metadata. No separate software
license grant currently applies to the original project source. See
[`LICENSES_AND_DATA.md`](LICENSES_AND_DATA.md) before reuse or redistribution.
