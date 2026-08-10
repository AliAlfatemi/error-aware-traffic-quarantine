# Error-Aware Traffic Quarantine

Research software accompanying **“Error-Aware Accounting for Traffic
Quarantine: Identifying Selector, Scheduler, and Buffer Confounds.”**

The code evaluates how selector errors, scheduling policy, and buffer
allocation affect traffic-quarantine measurements. It contains deterministic
simulation, completed-flow analysis of RT-IoT2022, paired statistical analysis,
and a controlled localhost TCP/UDP prototype.

## Scope

This is research software, not a production DDoS-mitigation appliance.

The evaluated code paths cover discrete-event simulation, completed-flow data,
and an unprivileged user-space localhost prototype. They do not establish
kernel forwarding, XDP/eBPF execution, physical-link behavior, line-rate
throughput, or production efficacy.

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

The default suite contains 97 tests. Two live localhost socket tests are
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
- `configs/` — versioned experiment configurations
- `data/` — verified public-dataset downloader and provenance
- `tests/` — unit, integrity, and invariant tests

## Data, results, and paper

This repository intentionally contains code only. Licensed source data,
generated result trees, the manuscript, and internal revision records are not
Git files. Frozen evidence and the manuscript should be distributed separately
as versioned release assets or through a DOI-backed research archive.

## Safe use

RT-IoT2022 contains completed-flow aggregates rather than packet timestamps;
it cannot validate online packet maturation or packet-level diversion. Run
network experiments only on systems and traffic that you own or are explicitly
authorized to test.

## Citation and license

Use [`CITATION.cff`](CITATION.cff) for citation metadata. No separate software
license grant currently applies to the original project source. See
[`LICENSES_AND_DATA.md`](LICENSES_AND_DATA.md) before reuse or redistribution.
