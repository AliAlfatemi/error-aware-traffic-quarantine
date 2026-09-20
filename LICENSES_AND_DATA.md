# Licenses and data

## Project source

No separate software license has been granted for the original project source.
Copyright remains with the authors. Public visibility on GitHub does not by
itself grant permission to copy, modify, or redistribute the source.

The exact Python dependencies are listed in `requirements.txt`; each remains
under its upstream license.

## RT-IoT2022

The public-data evaluation uses RT-IoT2022 by B. S. Sharmila and Rohini
Nagapadma, published by the UCI Machine Learning Repository in 2023.

- Official record: <https://archive.ics.uci.edu/dataset/942/rt-iot2022>
- Dataset DOI: <https://doi.org/10.24432/C5P338>
- UCI license: Creative Commons Attribution 4.0 International,
  <https://creativecommons.org/licenses/by/4.0/>

The source dataset is not committed to this repository. The tracked
`results/public_rt_iot2022/` snapshot contains derived split assignments,
labels, weights, predictions, and summary metadata needed to authenticate the
public-data stage; it does not contain the 85 original feature columns. These
derived records retain the dataset's CC BY 4.0 attribution requirement.

Install and verify the official source bytes with:

```bash
python data/public/rt_iot2022/download.py
```

The downloader accepts no mirror, verifies the official archive and extracted
table SHA-256 hashes, requires the exact single archive member, and refuses to
overwrite a partial or invalid installation. Full provenance and limitations
are in `data/public/rt_iot2022/PROVENANCE.md`.
