# RT-IoT2022 provenance, license, and analysis boundary

- Official dataset page: https://archive.ics.uci.edu/dataset/942/rt-iot2022
- Official download: https://archive.ics.uci.edu/static/public/942/rt-iot2022.zip
- Dataset DOI: https://doi.org/10.24432/C5P338
- Creator citation: B. S. Sharmila and Rohini Nagapadma, “RT-IoT2022,” UCI
  Machine Learning Repository, 2023.
- Associated article: B. S. Sharmila and R. Nagapadma, “Quantized autoencoder
  (QAE) intrusion detection system for anomaly detection in
  resource-constrained IoT devices using RT-IoT2022 dataset,” *Cybersecurity*,
  2023, DOI 10.1186/s42400-023-00178-5.
- License: Creative Commons Attribution 4.0 International (CC BY 4.0).
  Redistribution and adaptation are permitted with attribution. Official
  license link: https://creativecommons.org/licenses/by/4.0/
- Downloaded from the official UCI URL: 2026-08-04.

## Immutable source hashes

- `original/rt-iot2022.zip`:
  `bcaa24d62abbb1215be576d5cf9c02dfcb0bb7c4c2f5a00e03055afaa1ed109e`
- `original/RT_IOT2022` (the single CSV member extracted without modification):
  `956956c09c1764584fa08acd0f6876475626bcedcd6a6b1f8c492c2e9a2089ea`

The analysis validates both hashes before reading the data and never overwrites
either source file. The effective analysis configuration is the separate,
immutable input `configs/public_rt_iot2022.json`; generated manifests bind the
source files, configuration, generator, requirements file, and runtime package
versions by hash or exact version.

## As-distributed audit

The CSV has 123,117 rows and 85 columns, including `Attack_type` and an unnamed
integer column. Inspection shows that the unnamed integer restarts within
classes, so the analysis renames it `class_local_row_id`. It is not treated as
a global event order, capture identifier, session identifier, or timestamp.

The three labels treated as normal are exactly the normal labels present in the
distributed file: `MQTT_Publish` (4,146), `Thing_Speak` (8,108), and
`Wipro_bulb` (253). The remaining nine labels are treated as attacks. Some
descriptive prose associated with the dataset mentions Amazon Alexa, but no
Amazon-Alexa label occurs in this CSV; the analysis follows the file rather
than inventing or relabeling records.

There are no missing or infinite numeric values. There are 5,202 later rows
that exactly duplicate an earlier full source-feature vector when both the
class-local row identifier and label are excluded (5,195 when the label is
retained). More importantly, reduced model inputs repeat much more often:
104,934 rows repeat an earlier 12-feature reference input and 104,940 repeat an
earlier five-feature compact input.

Identical inputs sometimes carry conflicting labels, and no such row is
deleted:

| Input identity | Family-conflict groups / involved rows | Binary-conflict groups / involved rows |
|---|---:|---:|
| Full source features except index and label | 6 / 128 | 4 / 107 |
| 12-feature reference input | 84 / 8,023 | 9 / 2,136 |
| Five-feature compact input | 85 / 8,250 | 9 / 2,154 |

“Involved rows” means all rows belonging to a conflicting group, not merely
rows after the first. These conflicts place a data-imposed ceiling on any
deterministic classifier that receives only the corresponding input.

## Global split and leakage boundary

One hash-bucket split is assigned before fitting or threshold calibration. The
global grouping relation connects rows that are identical under either learned
model input. Because the five compact features are a subset of the 12 reference
features, equality of the five-feature tuple is the coarser relation and fully
defines these connected groups. Consequently, zero identical five-feature and
zero identical 12-feature learned inputs cross train, calibration, or test.
The 60/20/20 hash-bucket ranges yield 94,213 train rows, 16,089 calibration
rows, and 12,815 test rows; this imbalance in realized row counts is retained
rather than repaired after observing labels. Train contains 86,794 attack and
7,419 benign rows across all 12 families; calibration contains 13,586 attack
and 2,503 benign rows across 11 families (no `NMAP_FIN_SCAN` row lands there);
test contains 10,230 attack and 2,585 benign rows across all 12 families.

The repeated-input concentration is severe. The largest compact-input group
has 25,894 rows. The largest group within train is those 25,894 rows (27.48% of
train); the largest calibration group has 9,690 rows (60.23% of calibration);
and the largest test group has 5,200 rows (40.58% of test). These groups are
kept intact to prevent identical-input leakage, so the group-safe hash split is
not row-balanced and effective independent sample size is much smaller than
the row count. This concentration must be considered when interpreting both
calibration transfer and test metrics.

This split is only duplicate-input-safe. The distributed file has contiguous
class blocks and supplies no capture, device, session, or time grouping key.
The hash buckets therefore do **not** establish temporal independence,
capture-to-capture independence, device independence, or independence of
rows from the same acquisition environment. No source-order sensitivity result
is represented as a temporal or capture holdout.

## Dispersion degeneracy

`flow_iat.std` is exactly zero in 105,520 of 123,117 rows (85.71%). Every one
of those rows has only one or two total packets: 14,809 have one packet and
90,711 have two. Conversely, no nonzero-dispersion row has at most two packets.
Thus the dispersion-only comparator is largely a flow-length degeneracy check
on this artifact; it is not evidence that a mature online IAT window separates
traffic.

Threshold records use the explicit strict rule `score > threshold`. Scores tied
at the boundary are not flagged. This makes tied zeros unambiguous and avoids
the earlier use of a subnormal `nextafter(0)` sentinel that could be displayed
as rounded zero.

## Metric and claim limits

The file contains precomputed CICFlowMeter-style bidirectional completed-flow
aggregates. Its IAT fields are microsecond-scale flow statistics; it does not
contain packet timestamps or the individual IAT sequence. It cannot validate
an exact 20-IAT online feature, 21-packet maturation, packet redirect, queue
isolation, kernel execution, or XDP execution.

Wilson intervals in the generated summary are labeled descriptive conditional
row intervals. They do not account for capture or group dependence because the
necessary grouping key is absent. Macro-family results are unweighted means of
per-family row rates. Packet and payload totals are used only for retrospective
whole-flow mass associations: they are not operational packet diversion,
goodput, or pre-classification leakage measurements.

Accordingly, results are an in-dataset check of selectors on completed-flow
features under a duplicate-input-safe hash split. They are not an independent
deployment, packet-level, capture-held-out, kernel, or optical validation.
