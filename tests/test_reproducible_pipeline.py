from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from experiments import reproducible_pipeline as pipeline


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )


def _write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def _hash(path: Path) -> str:
    return pipeline.file_sha256(path)


def _canonical(path: Path) -> str:
    return pipeline.canonical_json_sha256(pipeline.load_json_strict(path))


class ArtifactFixture:
    """Small, structurally faithful instance of all six manifest schemas."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.results = root / "results"
        self.results.mkdir(parents=True)
        self._project_inputs()
        self.records: dict[str, dict[str, object]] = {}
        self._timing()
        self._public()
        self._coupled()
        self._ablations()
        self._loopback()
        self._statistics()

    def _project_inputs(self) -> None:
        for name in (
            "experiments/reproducible_pipeline.py",
            "run_reproducible_experiments.py",
            "experiments/timing_baseline.py",
            "experiments/public_rt_iot2022.py",
            "experiments/coupled_simulation.py",
            "experiments/synthetic_ablations.py",
            "experiments/statistical_analysis.py",
            "prototype/loopback_testbed.py",
        ):
            _write_text(self.root / name, f"# fixture {name}\n")
        _write_text(self.root / "requirements.txt", "")
        configs = {
            "timing_baseline": {"schema_version": "timing-baseline-1.0", "x": 1},
            "public_rt_iot2022": {"schema_version": "public-rt-iot2022-2.0", "x": 2},
            "coupled_simulation": {"schema_version": "coupled-1.1", "x": 3},
            "synthetic_ablations": {
                "schema_version": "synthetic-ablations-1.0",
                "x": 4,
            },
            "loopback_testbed": {"schema_version": "loopback-2.0", "x": 5},
            "statistical_analysis": {
                "schema_version": "statistical-analysis-1.0",
                "coupled": {"input_dir": "results/coupled_simulation"},
                "loopback": {"input_dir": "results/loopback_testbed"},
            },
        }
        for name, value in configs.items():
            _write_json(self.root / "configs" / f"{name}.json", value)
        _write_text(self.root / "data/public/source.csv", "label,value\nnormal,1\n")

    def _output_manifest(
        self,
        directory: str,
        summary: object | None,
        manifest: dict[str, object],
        files_key: str,
        extra_files: dict[str, object] | None = None,
    ) -> dict[str, object]:
        output = self.results / directory
        output.mkdir(parents=True)
        generated: dict[str, str] = {}
        if summary is not None:
            _write_json(output / "summary.json", summary)
            generated["summary.json"] = _hash(output / "summary.json")
        for name, value in (extra_files or {}).items():
            if isinstance(value, str):
                _write_text(output / name, value)
            else:
                _write_json(output / name, value)
            generated[name] = _hash(output / name)
        manifest[files_key] = generated
        _write_json(output / "manifest.json", manifest)
        return {
            "manifest_path": f"results/{directory}/manifest.json",
            "manifest_sha256": _hash(output / "manifest.json"),
            "schema_version": manifest["schema_version"],
            "declared_file_count": len(generated),
            "declared_files_fingerprint_sha256": pipeline.canonical_json_sha256(
                generated
            ),
        }

    def _timing(self) -> None:
        config = self.root / "configs/timing_baseline.json"
        source = self.root / "experiments/timing_baseline.py"
        requirements = self.root / "requirements.txt"
        runtime = {"python": "fixture"}
        summary = {
            "artifact_role": "historical negative timing-only baseline",
            "claim_scope": "synthetic context only",
            "classification": {
                "test_seed_count": 30,
                "decision_after_packets": 21,
                "aggregate_confusion": {"tp": 1, "fp": 2, "tn": 3, "fn": 4},
                "aggregate_metrics": {
                    "precision": {"estimate": 0.3},
                    "recall_tpr": {"estimate": 0.2},
                    "false_positive_rate": {"estimate": 0.1},
                    "f1": {"estimate": 0.24},
                },
            },
        }
        manifest = {
            "schema_version": "timing-baseline-1.0",
            "deterministic": True,
            "artifact_role": "context",
            "inputs": {
                "generator": {
                    "artifact_path": "experiments/timing_baseline.py",
                    "sha256": _hash(source),
                },
                "immutable_config": {
                    "artifact_path": "configs/timing_baseline.json",
                    "sha256": _hash(config),
                    "effective_config_sha256": _canonical(config),
                },
                "requirements": {
                    "artifact_path": "requirements.txt",
                    "sha256": _hash(requirements),
                },
                "runtime": {
                    "record": runtime,
                    "sha256": pipeline.canonical_json_sha256(runtime),
                },
            },
        }
        self.records["timing_baseline_v1"] = self._output_manifest(
            "timing_baseline_v1", summary, manifest, "generated_files"
        )

    def _public(self) -> None:
        config = self.root / "configs/public_rt_iot2022.json"
        source = self.root / "experiments/public_rt_iot2022.py"
        requirements = self.root / "requirements.txt"
        dataset = self.root / "data/public/source.csv"
        summary = {
            "claim_boundary": "completed-flow descriptive rows only",
            "dataset_audit": {
                "source": {"license": "fixture"},
                "rows_retained": 1,
                "split_counts": {"train": 1, "calibration": 0, "test": 0},
                "learned_input_overlap_audits": {},
                "global_grouping": {},
                "dispersion_feature_degeneracy": {},
            },
            "selectors": {
                "timing_or": {
                    "metrics": {
                        "precision": {"estimate": 0.7},
                        "recall_tpr": {"estimate": 0.6},
                        "false_positive_rate": {"estimate": 0.05},
                        "f1": 0.65,
                        "balanced_accuracy": 0.75,
                        "average_precision": 0.8,
                        "roc_auc": 0.85,
                    },
                    "macro_family_averages": {},
                    "retrospective_whole_flow_mass_association": {},
                }
            },
        }
        manifest = {
            "schema_version": "public-rt-iot2022-2.0",
            "reproducibility_inputs": {
                "generator": {
                    "artifact_path": "experiments/public_rt_iot2022.py",
                    "sha256": _hash(source),
                },
                "immutable_config": {
                    "artifact_path": "configs/public_rt_iot2022.json",
                    "sha256": _hash(config),
                    "effective_config_sha256": _canonical(config),
                },
                "requirements": {
                    "artifact_path": "requirements.txt",
                    "sha256": _hash(requirements),
                },
                "runtime": {"python": "fixture"},
                "determinism_scope": "fixture scope",
            },
            "source_files": {"data/public/source.csv": _hash(dataset)},
        }
        self.records["public_rt_iot2022"] = self._output_manifest(
            "public_rt_iot2022", summary, manifest, "generated_files"
        )

    def _coupled(self) -> None:
        config = self.root / "configs/coupled_simulation.json"
        source = self.root / "experiments/coupled_simulation.py"
        requirements = self.root / "requirements.txt"
        runtime = {"python": "fixture"}
        dependencies = {"numpy": "fixture"}
        summary = {
            "split_integrity": {"heldout_seed_count": 30},
            "limitations": ["synthetic only"],
            "classification": {
                "multifeature": {
                    "flow_rates": {"recall": 0.5, "fpr": 0.01},
                    "mature_packet_rates": {"recall": 0.7, "fpr": 0.02},
                    "mature_byte_rates": {"recall": 0.8, "fpr": 0.03},
                }
            },
            "coupled_evaluation": {
                "groups": [
                    {
                        "sweep_name": "attack_scale_12",
                        "defense": "capacity_isolated_quarantine",
                        "selector": "multifeature",
                        "seed_count": 30,
                        "metrics": {
                            name: {"mean": float(index + 1)}
                            for index, name in enumerate(
                                (
                                    "offered_load_to_matched_capacity",
                                    "benign_goodput_Bps",
                                    "benign_latency_p99_s",
                                    "benign_protected_byte_loss_fraction",
                                    "attack_leakage_Bps",
                                )
                            )
                        },
                    }
                ]
            },
        }
        provenance = {
            "source_sha256": _hash(source),
            "input_config_artifact": {
                "path_as_invoked": "configs/coupled_simulation.json",
                "sha256": _hash(config),
            },
            "config_canonical_sha256": _canonical(config),
            "requirements_artifact": {
                "path": "requirements.txt",
                "sha256": _hash(requirements),
            },
            "runtime": runtime,
            "runtime_fingerprint_sha256": pipeline.canonical_json_sha256(runtime),
            "dependencies": dependencies,
            "dependency_fingerprint_sha256": pipeline.canonical_json_sha256(
                dependencies
            ),
        }
        manifest = {
            "schema_version": "coupled-1.1",
            "deterministic": True,
            "input_provenance": provenance,
        }
        self.records["coupled_simulation"] = self._output_manifest(
            "coupled_simulation", summary, manifest, "files"
        )

    def _ablations(self) -> None:
        config = self.root / "configs/synthetic_ablations.json"
        coupled_config = self.root / "configs/coupled_simulation.json"
        source = self.root / "experiments/synthetic_ablations.py"
        coupled_source = self.root / "experiments/coupled_simulation.py"
        requirements = self.root / "requirements.txt"
        runtime = {"python": "fixture"}
        dependencies = {"numpy": "fixture"}

        def section(identity: dict[str, object], metrics: tuple[str, ...]) -> dict[str, object]:
            return {
                "groups": [
                    {
                        **identity,
                        "metrics": {
                            name: {"mean": float(index)}
                            for index, name in enumerate(metrics)
                        },
                    }
                ]
            }

        summary = {
            "run_scope": "authoritative_heldout",
            "limitations": ["synthetic only"],
            "observation_window_sensitivity": section(
                {"window_iats": 20, "selector": "multifeature", "seed_count": 30},
                (
                    "flow_recall",
                    "flow_fpr",
                    "flow_f1",
                    "decision_delay_mean_s",
                    "provisional_attack_packet_fraction",
                    "logical_state_payload_bytes_per_entry",
                ),
            ),
            "state_cardinality_scaling": section(
                {"target_concurrent_flows": 4096, "seed_count": 30},
                (
                    "peak_occupancy_entries",
                    "peak_logical_state_payload_bytes",
                    "state_evictions",
                    "state_progress_packets_lost",
                    "eligible_flow_maturation_fraction",
                ),
            ),
            "detector_failure_recovery": section(
                {"scenario": "fail_closed", "seed_count": 30},
                (
                    "benign_goodput_Bps",
                    "attack_leakage_Bps",
                    "failure_window_attack_fast_packets",
                    "failure_window_benign_quarantine_packets",
                    "reacquisition_attack_fast_packets",
                    "reacquisition_benign_quarantine_packets",
                    "recovery_delay_mean_s",
                    "recovery_delay_p95_s",
                ),
            ),
        }
        source_map = {
            "experiments/coupled_simulation.py": _hash(coupled_source),
            "experiments/synthetic_ablations.py": _hash(source),
        }
        input_map = {
            "configs/coupled_simulation.json": _hash(coupled_config),
            "configs/synthetic_ablations.json": _hash(config),
            "requirements.txt": _hash(requirements),
        }
        manifest = {
            "schema_version": "synthetic-ablations-1.0",
            "authoritative": True,
            "input_provenance": {
                "source_sha256": source_map,
                "input_file_sha256": input_map,
                "ablation_config_canonical_sha256": _canonical(config),
                "coupled_config_canonical_sha256": _canonical(coupled_config),
                "runtime": runtime,
                "runtime_fingerprint_sha256": pipeline.canonical_json_sha256(runtime),
                "dependencies": dependencies,
                "dependency_fingerprint_sha256": pipeline.canonical_json_sha256(
                    dependencies
                ),
            },
        }
        self.records["synthetic_ablations"] = self._output_manifest(
            "synthetic_ablations", summary, manifest, "files"
        )

    def _loopback(self) -> None:
        config = self.root / "configs/loopback_testbed.json"
        source = self.root / "prototype/loopback_testbed.py"
        runtime = {"python": "fixture", "socket_stack": "fixture"}
        dependencies = {"external_python_packages": []}
        source_map = {
            "configs/loopback_testbed.json": _hash(config),
            "prototype/loopback_testbed.py": _hash(source),
        }
        aggregate = {
            "schema_version": "loopback-2.0",
            "condition_identity": {
                "protocol": "udp",
                "mode": "isolated",
                "suspicious_offered_pps": 800.0,
            },
            "seed_sample_count": 30,
            "metrics": {
                label: {
                    metric: {"mean": float(index + 1)}
                    for index, metric in enumerate(
                        (
                            "application_frame_rate_fps",
                            "application_payload_Bps",
                            "end_to_end_loss_fraction",
                            "p99_latency_ms",
                        )
                    )
                }
                for label in ("benign", "attack")
            },
        }
        manifest = {
            "schema_version": "loopback-2.0",
            "study_id": "fixture",
            "authoritative_design": True,
            "trial_count": 30,
            "valid_trial_count": 30,
            "claim_boundary": "user-space oracle localhost only",
            "provenance": {
                "source": {
                    "files": source_map,
                    "source_set_sha256": pipeline.canonical_json_sha256(source_map),
                },
                "configuration": {
                    "input_configuration": {
                        "path": "configs/loopback_testbed.json",
                        "file_sha256": _hash(config),
                        "parsed_config_sha256": _canonical(config),
                    }
                },
                "host_runtime": {
                    "metadata": runtime,
                    "sha256": pipeline.canonical_json_sha256(runtime),
                },
                "dependencies": {
                    "metadata": dependencies,
                    "sha256": pipeline.canonical_json_sha256(dependencies),
                },
            },
        }
        record = self._output_manifest(
            "loopback_testbed",
            None,
            manifest,
            "files",
            {"udp_isolated_load_800.json": aggregate},
        )
        output_manifest = pipeline.load_json_strict(
            self.results / "loopback_testbed/manifest.json"
        )
        output_manifest["aggregate_files"] = {
            "udp_isolated_load_800.json": output_manifest["files"][
                "udp_isolated_load_800.json"
            ]
        }
        _write_json(self.results / "loopback_testbed/manifest.json", output_manifest)
        record["manifest_sha256"] = _hash(
            self.results / "loopback_testbed/manifest.json"
        )
        self.records["loopback_testbed"] = record

    def _statistics(self) -> None:
        config = self.root / "configs/statistical_analysis.json"
        source = self.root / "experiments/statistical_analysis.py"
        requirements = self.root / "requirements.txt"
        runtime = {"python": "fixture"}
        dependencies = {"numpy": "fixture"}
        result = {
            "hypothesis_id": "fixture|metric=x",
            "condition": {"load": 1},
            "metric": {"id": "x", "unit": "units", "better": "higher"},
            "pair_count": 30,
            "effect_native": {"mean": {"estimate": 1.0, "ci": [0.5, 1.5]}},
            "nonparametric_test": {
                "p_value_holm": 0.01,
                "statistically_significant_after_holm": True,
            },
            "practical_significance": {
                "classification_from_mean_native_effect": "beneficial"
            },
            "relative_effect": {
                "available": True,
                "oriented_benefit_percent": {
                    "mean": {"estimate": 10.0, "ci": [5.0, 15.0]}
                },
            },
        }
        summary = {
            "analysis_plan": {"paired_test": "exact sign test"},
            "public_dataset_scope": {
                "included_in_paired_hypothesis_tests": False
            },
            "limitations": ["finite seeds"],
            "comparison_families": [
                {
                    "family_id": "fixture_family",
                    "study": "fixture",
                    "holm_scope": "fixture family",
                    "hypothesis_count": 1,
                    "results": [result],
                }
            ],
        }
        upstream: dict[str, object] = {}
        for name in ("coupled_simulation", "loopback_testbed"):
            record = self.records[name]
            upstream[name] = {
                "manifest_path": record["manifest_path"],
                "manifest_sha256": record["manifest_sha256"],
                "schema_version": record["schema_version"],
                "verified_file_count": record["declared_file_count"],
                "verified_files_fingerprint_sha256": record[
                    "declared_files_fingerprint_sha256"
                ],
            }
        manifest = {
            "schema_version": "statistical-analysis-1.0",
            "deterministic_given_bound_inputs_and_runtime": True,
            "provenance": {
                "source_artifact": {
                    "path": "experiments/statistical_analysis.py",
                    "sha256": _hash(source),
                },
                "config_artifact": {
                    "path": "configs/statistical_analysis.json",
                    "sha256": _hash(config),
                    "canonical_sha256": _canonical(config),
                },
                "requirements_artifact": {
                    "path": "requirements.txt",
                    "sha256": _hash(requirements),
                },
                "runtime": runtime,
                "runtime_fingerprint_sha256": pipeline.canonical_json_sha256(runtime),
                "dependencies": dependencies,
                "dependency_fingerprint_sha256": pipeline.canonical_json_sha256(
                    dependencies
                ),
                "input_manifests": upstream,
            },
        }
        self.records["statistical_analysis"] = self._output_manifest(
            "statistical_analysis", summary, manifest, "files"
        )


class StrictJsonTests(unittest.TestCase):
    def test_rejects_duplicate_keys_and_nonfinite_numbers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            duplicate = root / "duplicate.json"
            duplicate.write_text('{"x": 1, "x": 2}\n', encoding="utf-8")
            with self.assertRaisesRegex(pipeline.VerificationError, "duplicate"):
                pipeline.load_json_strict(duplicate)
            nonfinite = root / "nonfinite.json"
            nonfinite.write_text('{"x": 1e999}\n', encoding="utf-8")
            with self.assertRaisesRegex(pipeline.VerificationError, "non-finite"):
                pipeline.load_json_strict(nonfinite)

    def test_writer_is_deterministic_and_refuses_nonfinite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "value.json"
            pipeline.write_json_strict(path, {"b": 2, "a": 1})
            first = path.read_bytes()
            pipeline.write_json_strict(path, {"a": 1, "b": 2})
            self.assertEqual(first, path.read_bytes())
            with self.assertRaises(pipeline.VerificationError):
                pipeline.write_json_strict(path, {"bad": float("nan")})


class ManifestOrchestrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.fixture = ArtifactFixture(self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_all_six_schemas_verify_and_outputs_are_byte_deterministic(self) -> None:
        summary, manifest = pipeline.build_top_level_artifacts(
            self.fixture.results,
            project_root=self.root,
            require_statistics=True,
        )
        self.assertEqual(
            summary["verified_stage_order"], list(pipeline.AUTHORITATIVE_STAGE_NAMES)
        )
        self.assertEqual(summary["artifact_scope"], "complete_authoritative_evaluation")
        self.assertEqual(
            summary["combined_fingerprint_sha256"],
            manifest["combined_fingerprint_sha256"],
        )
        self.assertEqual(
            pipeline.file_sha256(self.fixture.results / "summary.json"),
            manifest["files"]["summary.json"],
        )
        self.assertEqual(
            summary["key_results"]["loopback_testbed"]["trial_count"], 30
        )
        first_summary = (self.fixture.results / "summary.json").read_bytes()
        first_manifest = (self.fixture.results / "manifest.json").read_bytes()
        pipeline.build_top_level_artifacts(
            self.fixture.results,
            project_root=self.root,
            require_statistics=True,
        )
        self.assertEqual(first_summary, (self.fixture.results / "summary.json").read_bytes())
        self.assertEqual(first_manifest, (self.fixture.results / "manifest.json").read_bytes())

    def test_tampered_generated_file_is_rejected(self) -> None:
        path = self.fixture.results / "coupled_simulation/summary.json"
        path.write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(pipeline.VerificationError, "hash mismatch"):
            pipeline.build_top_level_artifacts(
                self.fixture.results, project_root=self.root
            )

    def test_undeclared_stage_file_is_rejected(self) -> None:
        _write_text(
            self.fixture.results / "coupled_simulation/undeclared.txt",
            "not bound by the stage manifest\n",
        )
        with self.assertRaisesRegex(
            pipeline.VerificationError, "declared-file set mismatch"
        ):
            pipeline.build_top_level_artifacts(
                self.fixture.results, project_root=self.root
            )

    def test_manifest_path_escape_is_rejected(self) -> None:
        manifest_path = self.fixture.results / "timing_baseline_v1/manifest.json"
        manifest = pipeline.load_json_strict(manifest_path)
        manifest["generated_files"]["../escape.json"] = "0" * 64
        _write_json(manifest_path, manifest)
        with self.assertRaisesRegex(pipeline.VerificationError, "escapes"):
            pipeline.build_top_level_artifacts(
                self.fixture.results, project_root=self.root
            )

    def test_stale_statistical_upstream_binding_is_rejected(self) -> None:
        path = self.fixture.results / "statistical_analysis/manifest.json"
        manifest = pipeline.load_json_strict(path)
        manifest["provenance"]["input_manifests"]["coupled_simulation"][
            "manifest_sha256"
        ] = "0" * 64
        _write_json(path, manifest)
        with self.assertRaisesRegex(pipeline.VerificationError, "upstream binding"):
            pipeline.build_top_level_artifacts(
                self.fixture.results,
                project_root=self.root,
                require_statistics=True,
            )

    def test_optional_statistics_is_verified_when_present(self) -> None:
        summary, _ = pipeline.build_top_level_artifacts(
            self.fixture.results, project_root=self.root
        )
        self.assertIn("statistical_analysis", summary["verified_stage_order"])

    def test_published_verification_is_read_only(self) -> None:
        pipeline.build_top_level_artifacts(
            self.fixture.results,
            project_root=self.root,
            require_statistics=True,
        )
        before = {
            name: (self.fixture.results / name).read_bytes()
            for name in ("summary.json", "manifest.json")
        }
        pipeline.verify_published_top_level(
            self.fixture.results,
            project_root=self.root,
            require_statistics=True,
        )
        after = {
            name: (self.fixture.results / name).read_bytes()
            for name in ("summary.json", "manifest.json")
        }
        self.assertEqual(before, after)


class ExecutionSafetyTests(unittest.TestCase):
    def test_empty_cli_invocation_only_calls_verifier(self) -> None:
        fake_summary = {
            "verification_status": "passed",
            "artifact_scope": "fixture",
            "combined_fingerprint_sha256": "0" * 64,
        }
        with mock.patch.object(
            pipeline, "verify_published_top_level", return_value=(fake_summary, {})
        ) as verifier, mock.patch.object(pipeline, "reproduce") as reproduce:
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(pipeline.main([]), 0)
        verifier.assert_called_once()
        reproduce.assert_not_called()
        self.assertIn("artifact_scope=fixture", output.getvalue())

    def test_reproduction_refuses_to_start_without_acknowledgement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "new-run"
            with mock.patch.object(pipeline, "_run") as runner:
                with self.assertRaisesRegex(
                    pipeline.VerificationError, "--confirm-expensive"
                ):
                    pipeline.reproduce(
                        output,
                        include_live_loopback=False,
                        confirm_expensive=False,
                        confirm_live_loopback=False,
                        project_root=root,
                    )
            runner.assert_not_called()
            self.assertFalse(output.exists())

    def test_live_reproduction_requires_separate_acknowledgement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.object(pipeline, "_run") as runner:
                with self.assertRaisesRegex(
                    pipeline.VerificationError, "--confirm-live-loopback"
                ):
                    pipeline.reproduce(
                        root / "new-run",
                        include_live_loopback=True,
                        confirm_expensive=True,
                        confirm_live_loopback=False,
                        project_root=root,
                    )
            runner.assert_not_called()

    def test_live_command_is_absent_from_computational_plan(self) -> None:
        commands = pipeline._reproduction_commands(
            pipeline.PROJECT_ROOT / "results/reproductions/fixture",
            pipeline.PROJECT_ROOT,
            include_live_loopback=False,
        )
        rendered = "\n".join(" ".join(command) for command in commands)
        self.assertNotIn("prototype.loopback_testbed", rendered)
        self.assertEqual(len(commands), 4)

    def test_full_reproduction_statistical_command_has_one_output_flag(self) -> None:
        fake_summary = {
            "verification_status": "passed",
            "artifact_scope": "fixture",
            "combined_fingerprint_sha256": "0" * 64,
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_json(
                root / "configs/statistical_analysis.json",
                {
                    "coupled": {"input_dir": "results/coupled_simulation"},
                    "loopback": {"input_dir": "results/loopback_testbed"},
                },
            )
            with mock.patch.object(pipeline, "_run") as runner, mock.patch.object(
                pipeline,
                "build_top_level_artifacts",
                return_value=(fake_summary, {}),
            ):
                pipeline.reproduce(
                    root / "reproduction",
                    include_live_loopback=True,
                    confirm_expensive=True,
                    confirm_live_loopback=True,
                    project_root=root,
                )
            statistical = runner.call_args_list[-1].args[0]
            self.assertEqual(statistical.count("--output-dir"), 1)
            self.assertIn("reproduction/statistical_analysis", statistical)


if __name__ == "__main__":
    unittest.main()
