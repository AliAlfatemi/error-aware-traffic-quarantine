from __future__ import annotations

import json
import math
import unittest
from dataclasses import FrozenInstanceError, asdict, replace
from pathlib import Path

import numpy as np

from experiments.coupled_simulation import (
    CoupledConfig,
    FlowTrace,
    PacketEvent,
    SelectorDecision,
    SelectorModel,
    SweepPoint,
    _FiniteByteQueue,
    build_sweep_points,
    canonical_json_sha256,
    classification_accounting,
    decisions_for_flows,
    defense_plan,
    fit_selectors,
    flow_to_dict,
    generate_flows,
    load_config,
    packet_events,
    runtime_provenance,
    simulate_defense,
)


def make_flow(
    flow_id: str,
    family: str,
    packet_count: int,
    iat_s: float,
    size_bytes: int,
    *,
    start_time_s: float = 0.0,
    protocol: str | None = None,
) -> FlowTrace:
    iats = tuple(iat_s for _ in range(packet_count - 1))
    offsets = tuple(float(value) for value in np.concatenate(([0.0], np.cumsum(iats))))
    benign = family.startswith("benign_")
    return FlowTrace(
        flow_id=flow_id,
        split="unit",
        seed=7,
        family=family,
        true_label="benign" if benign else "attack",
        protocol=protocol or ("TCP-like" if benign else "UDP-like"),
        start_time_s=start_time_s,
        iats_s=iats,
        arrival_offsets_s=offsets,
        packet_sizes_bytes=tuple(size_bytes for _ in range(packet_count)),
    )


class SplitAndRawTraceTests(unittest.TestCase):
    def test_committed_config_is_complete_and_matches_defaults(self) -> None:
        path = Path(__file__).resolve().parents[1] / "configs" / "coupled_simulation.json"
        loaded = load_config(path)
        self.assertEqual(loaded, CoupledConfig())
        provenance = runtime_provenance(loaded, path)
        self.assertEqual(len(provenance["input_config_artifact"]["sha256"]), 64)
        self.assertEqual(provenance["requirements_artifact"]["path"], "requirements.txt")
        self.assertEqual(len(provenance["requirements_artifact"]["sha256"]), 64)

    def test_default_split_has_thirty_disjoint_heldout_seeds(self) -> None:
        config = CoupledConfig()
        self.assertGreaterEqual(len(config.heldout_seeds), 30)
        self.assertFalse(set(config.train_seeds) & set(config.calibration_seeds))
        self.assertFalse(set(config.train_seeds) & set(config.heldout_seeds))
        self.assertFalse(set(config.calibration_seeds) & set(config.heldout_seeds))
        self.assertEqual(config.maturity_packets, 21)
        self.assertEqual(config.provisional_packets_before_decision, 20)
        self.assertEqual(
            config.shared_capacity_Bps,
            config.fast_capacity_Bps + config.quarantine_capacity_Bps,
        )
        self.assertEqual(
            config.shared_buffer_bytes,
            config.fast_buffer_bytes + config.quarantine_buffer_bytes,
        )
        with self.assertRaises(FrozenInstanceError):
            config.window_iats = 10  # type: ignore[misc]
        with self.assertRaises(ValueError):
            replace(config, shared_capacity_Bps=config.shared_capacity_Bps + 1.0)
        with self.assertRaises(ValueError):
            replace(config, duration_s=math.nan)
        with self.assertRaises(TypeError):
            replace(config, train_seeds=list(config.train_seeds))  # type: ignore[arg-type]

    def test_config_source_dependency_and_runtime_fingerprints_are_finite_and_stable(self) -> None:
        config = CoupledConfig()
        first = runtime_provenance(config)
        second = runtime_provenance(config)
        self.assertEqual(first, second)
        self.assertEqual(first["config_canonical_sha256"], canonical_json_sha256(asdict(config)))
        for name in (
            "config_canonical_sha256", "source_sha256",
            "dependency_fingerprint_sha256", "runtime_fingerprint_sha256",
            "combined_input_fingerprint_sha256",
        ):
            self.assertEqual(len(first[name]), 64)
        json.dumps(first, allow_nan=False)

    def test_raw_iats_sizes_protocol_and_offsets_survive_json_exactly(self) -> None:
        flow = make_flow("raw", "attack_jitter", 27, 0.003125, 777)
        encoded = json.dumps(flow_to_dict(flow), sort_keys=True)
        decoded = json.loads(encoded)
        self.assertEqual(decoded["iats_s"], list(flow.iats_s))
        self.assertEqual(decoded["arrival_offsets_s"], list(flow.arrival_offsets_s))
        self.assertEqual(decoded["packet_sizes_bytes"], list(flow.packet_sizes_bytes))
        self.assertEqual(decoded["protocol"], flow.protocol)
        self.assertEqual(decoded["true_label"], flow.true_label)
        self.assertEqual(decoded["family"], flow.family)

    def test_generation_is_deterministic_and_retains_all_packet_arrays(self) -> None:
        config = replace(CoupledConfig(), flows_per_family=1)
        first = generate_flows(4242, "heldout", config, 1.0)
        second = generate_flows(4242, "heldout", config, 1.0)
        self.assertEqual(first, second)
        for flow in first:
            self.assertEqual(len(flow.iats_s) + 1, len(flow.arrival_offsets_s))
            self.assertEqual(len(flow.arrival_offsets_s), len(flow.packet_sizes_bytes))


class QueueInvariantTests(unittest.TestCase):
    def test_service_completion_is_independent_of_post_service_dwell(self) -> None:
        event = PacketEvent(0.0, "f", 0, 1000, "attack", "attack_volumetric", "UDP-like")
        no_dwell = _FiniteByteQueue(10_000.0, 10_000)
        long_dwell = _FiniteByteQueue(10_000.0, 10_000)
        accepted_a, completion_a, release_a = no_dwell.offer(event, 0.0)
        accepted_b, completion_b, release_b = long_dwell.offer(event, 3.0)
        self.assertTrue(accepted_a and accepted_b)
        self.assertEqual(completion_a, completion_b)
        self.assertAlmostEqual(release_b - release_a, 3.0)
        self.assertEqual(no_dwell.accounting()["accepted_bytes"], long_dwell.accounting()["accepted_bytes"])

    def test_packet_and_byte_conservation_in_coupled_isolated_run(self) -> None:
        config = replace(CoupledConfig(), duration_s=3.0, warmup_s=0.0)
        flows = [
            make_flow("b", "benign_paced", 30, 0.020, 900),
            make_flow("a", "attack_volumetric", 70, 0.003, 1200),
        ]
        events = packet_events(flows, config.duration_s)
        oracle = SelectorModel("oracle", config.window_iats)
        decisions = decisions_for_flows(flows, {"oracle": oracle})["oracle"]
        sweep = SweepPoint("unit", 1.0, 30_000.0, 15_000, 0.5)
        result = simulate_defense(
            flows, events, decisions, config, sweep,
            "capacity_isolated_quarantine", "oracle",
        )
        metrics = result["metrics"]
        self.assertEqual(
            metrics["protected_packets"] + metrics["quarantine_packets"] + metrics["dropped_packets"],
            metrics["offered_packets"],
        )
        self.assertEqual(
            metrics["protected_bytes"] + metrics["quarantine_bytes"] + metrics["dropped_bytes"],
            metrics["offered_bytes"],
        )
        shared = simulate_defense(
            flows, events, None, config, sweep, "shared_fifo", None
        )
        self.assertEqual(
            shared["queue_accounting"]["shared"]["capacity_Bps"],
            config.fast_capacity_Bps + sweep.quarantine_capacity_Bps,
        )
        self.assertEqual(
            shared["queue_accounting"]["shared"]["buffer_bytes"],
            config.fast_buffer_bytes + sweep.quarantine_buffer_bytes,
        )


class ClassificationAccountingTests(unittest.TestCase):
    def test_volume_weighted_false_negative_rate_differs_from_flow_rate(self) -> None:
        config = CoupledConfig()
        large_missed = make_flow("large", "attack_volumetric", 101, 0.005, 1500)
        small_detected = make_flow("small", "attack_low_rate", 21, 0.010, 100)
        flows = [large_missed, small_detected]
        events = packet_events(flows, config.duration_s)
        decisions = {
            "large": SelectorDecision("unit", "large", True, False, 20, 0.1, 0.0, "forced miss"),
            "small": SelectorDecision("unit", "small", True, True, 20, 0.2, 1.0, "forced hit"),
        }
        report = classification_accounting(flows, events, decisions, config.window_iats)
        self.assertEqual(report["flow_rates"]["fnr"], 0.5)
        self.assertGreater(report["mature_packet_rates"]["fnr"], 0.95)
        self.assertGreater(report["mature_byte_rates"]["fnr"], report["mature_packet_rates"]["fnr"])
        formula = report["load_accounting"]["packet"]
        self.assertAlmostEqual(formula["attack_fast_fraction_formula"], formula["attack_fast_fraction_observed"])

    def test_first_twenty_packets_are_provisional_fast_and_twenty_first_is_mature(self) -> None:
        config = replace(
            CoupledConfig(), duration_s=2.0, warmup_s=0.0,
            shared_capacity_Bps=20_000_000.0, shared_buffer_bytes=2_000_000,
            fast_capacity_Bps=10_000_000.0, fast_buffer_bytes=1_000_000,
            quarantine_capacity_Bps=10_000_000.0, quarantine_buffer_bytes=1_000_000,
        )
        attack = make_flow("attack", "attack_volumetric", 25, 0.010, 500)
        flows = [attack]
        events = packet_events(flows, config.duration_s)
        oracle = SelectorModel("oracle", config.window_iats)
        decisions = decisions_for_flows(flows, {"oracle": oracle})["oracle"]
        sweep = SweepPoint("unit", 1.0, config.quarantine_capacity_Bps, config.quarantine_buffer_bytes, 0.0)
        result = simulate_defense(
            flows, events, decisions, config, sweep,
            "capacity_isolated_quarantine", "oracle",
        )
        metrics = result["metrics"]
        self.assertEqual(metrics["provisional_attack_fast_packets"], 20)
        self.assertEqual(metrics["provisional_attack_delivered_packets"], 20)
        self.assertEqual(metrics["protected_packets"], 20)
        self.assertEqual(metrics["quarantine_packets"], 5)


class CoupledDefenseTests(unittest.TestCase):
    def test_isolated_fast_path_beats_shared_fifo_with_oracle_under_attack(self) -> None:
        config = replace(
            CoupledConfig(), duration_s=2.0, warmup_s=0.0,
            shared_capacity_Bps=90_000.0, shared_buffer_bytes=12_000,
            aggregate_limiter_capacity_Bps=70_000.0,
            fast_capacity_Bps=70_000.0, fast_buffer_bytes=8_000,
            quarantine_capacity_Bps=20_000.0, quarantine_buffer_bytes=4_000,
            fast_delay_s=0.0, quarantine_delay_s=0.0,
        )
        benign = make_flow("z-benign", "benign_paced", 70, 0.020, 1000)
        attack = make_flow("a-attack", "attack_volumetric", 220, 0.001, 1500)
        flows = [benign, attack]
        events = packet_events(flows, config.duration_s)
        oracle = SelectorModel("oracle", config.window_iats)
        decisions = decisions_for_flows(flows, {"oracle": oracle})["oracle"]
        sweep = SweepPoint("high", 1.0, config.quarantine_capacity_Bps, config.quarantine_buffer_bytes, 0.0)
        shared = simulate_defense(flows, events, None, config, sweep, "shared_fifo", None)
        isolated = simulate_defense(
            flows, events, decisions, config, sweep,
            "capacity_isolated_quarantine", "oracle",
        )
        self.assertGreater(
            isolated["metrics"]["benign_goodput_Bps"],
            shared["metrics"]["benign_goodput_Bps"],
        )
        self.assertLess(
            isolated["metrics"]["attack_leakage_Bps"],
            shared["metrics"]["attack_leakage_Bps"],
        )
        self.assertTrue(shared["resource_equivalence"]["capacity_equal"])
        self.assertTrue(shared["resource_equivalence"]["buffer_equal"])
        self.assertEqual(
            shared["resource_equivalence"]["shared_physical_capacity_Bps"],
            isolated["resource_equivalence"]["isolated_fast_plus_quarantine_capacity_Bps"],
        )

    def test_detector_free_protocol_priority_differs_from_oracle_isolation(self) -> None:
        config = replace(
            CoupledConfig(), duration_s=2.0, warmup_s=0.0,
            shared_capacity_Bps=100_000.0, shared_buffer_bytes=20_000,
            aggregate_limiter_capacity_Bps=80_000.0,
            fast_capacity_Bps=80_000.0, fast_buffer_bytes=15_000,
            quarantine_capacity_Bps=20_000.0, quarantine_buffer_bytes=5_000,
            fast_delay_s=0.0, quarantine_delay_s=0.0,
        )
        benign_low_priority = make_flow(
            "b-low", "benign_paced", 100, 0.012, 1000, protocol="UDP-like"
        )
        attack_high_priority = make_flow(
            "a-high", "attack_volumetric", 600, 0.0015, 1200, protocol="TCP-like"
        )
        flows = [benign_low_priority, attack_high_priority]
        events = packet_events(flows, config.duration_s)
        sweep = SweepPoint(
            "unit", 1.0, config.quarantine_capacity_Bps,
            config.quarantine_buffer_bytes, 0.0,
        )
        priority = simulate_defense(
            flows, events, None, config, sweep, "static_protocol_priority", None
        )
        decisions = decisions_for_flows(
            flows, {"oracle": SelectorModel("oracle", config.window_iats)}
        )["oracle"]
        isolated = simulate_defense(
            flows, events, decisions, config, sweep,
            "capacity_isolated_quarantine", "oracle",
        )
        self.assertIsNone(priority["selector"])
        self.assertEqual(
            priority["queue_accounting"]["priority_shared"]["discipline"],
            "non-preemptive work-conserving strict priority",
        )
        self.assertGreater(
            isolated["metrics"]["benign_goodput_Bps"],
            priority["metrics"]["benign_goodput_Bps"],
        )
        self.assertLess(
            isolated["metrics"]["attack_leakage_Bps"],
            priority["metrics"]["attack_leakage_Bps"],
        )

    def test_default_attack_sweep_spans_below_capacity_to_clear_overload(self) -> None:
        config = CoupledConfig()
        capacity = config.fast_capacity_Bps + config.quarantine_capacity_Bps
        ratios = []
        for scale in (min(config.attack_scale_sweep), max(config.attack_scale_sweep)):
            events = packet_events(generate_flows(1009, "heldout", config, scale), config.duration_s)
            ratios.append(sum(event.size_bytes for event in events) / config.duration_s / capacity)
        self.assertLess(ratios[0], 1.0)
        self.assertGreaterEqual(ratios[1], 1.5)

    def test_sweep_plan_varies_attack_cq_kq_and_dq_one_factor_at_a_time(self) -> None:
        config = CoupledConfig()
        points = build_sweep_points(config)
        self.assertGreater(len({point.attack_scale for point in points}), 1)
        self.assertGreater(len({point.quarantine_capacity_Bps for point in points}), 1)
        self.assertGreater(len({point.quarantine_buffer_bytes for point in points}), 1)
        self.assertGreater(len({point.quarantine_delay_s for point in points}), 1)
        plan = defense_plan()
        self.assertIn(("static_protocol_priority", None), plan)
        self.assertNotIn(("oracle_reserved_after_maturity", "oracle"), plan)

    def test_selector_fit_is_deterministic_and_uses_only_supplied_splits(self) -> None:
        config = replace(CoupledConfig(), flows_per_family=1)
        training = generate_flows(config.train_seeds[0], "train", config)
        calibration = generate_flows(config.calibration_seeds[0], "calibration", config)
        first, first_report = fit_selectors(training, calibration, config)
        second, second_report = fit_selectors(training, calibration, config)
        self.assertEqual(first, second)
        self.assertEqual(first_report, second_report)
        self.assertEqual(set(first), {"rate_only", "variance_only", "current_or_timing", "multifeature", "oracle"})
        self.assertTrue(first_report["thresholds_selected_without_heldout_data"])
        payload = {
            "models": {name: asdict(model) for name, model in first.items()},
            "calibration": first_report,
        }
        encoded = json.dumps(payload, sort_keys=True, allow_nan=False)
        self.assertNotIn("Infinity", encoded)
        self.assertNotIn("NaN", encoded)

        def assert_finite(value: object) -> None:
            if isinstance(value, float):
                self.assertTrue(math.isfinite(value))
            elif isinstance(value, dict):
                for nested in value.values():
                    assert_finite(nested)
            elif isinstance(value, (list, tuple)):
                for nested in value:
                    assert_finite(nested)

        assert_finite(payload)


if __name__ == "__main__":
    unittest.main()
