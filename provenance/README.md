# Provenance records

This directory contains compact, non-sensitive bindings to completed live
campaigns. Full raw campaign trees are distributed separately because they are
larger evidence packages with their own closed-file manifests.

## Study C

[`study_c_source_manifest.json`](study_c_source_manifest.json) is the exact
twelve-file `source_hashes.json` payload recorded by the successful Study C
campaign before execution. Each entry fixes the repository-relative path,
byte size, and SHA-256 digest. The release-hygiene tests recompute all twelve
records from the checkout.

## Selector-to-HTB

[`selector_htb_seal_record.json`](selector_htb_seal_record.json) records the
SHA-256 digest and compact integrity fields of the authoritative campaign's
create-only seal. It also records the source hashes reverified by the sealer,
the sealer's own hash, and the integrity-addendum hash. The full seal contains
365 input-file hashes covering 360 raw arms and five static campaign files.

These records contain no account names, hostnames, private paths, packet
captures, or credentials. They establish lineage and integrity; they are not a
substitute for the full evidence archive.
