from __future__ import annotations

import json
import unittest
from pathlib import Path

from experiments.selector_htb import (
    build_execution_plan,
    build_replay_events,
    fit_frozen_selectors,
    heldout_flows,
    load_selector_htb_config,
    replay_trace,
    tc_commands,
    tc_spec,
)
from experiments.coupled_simulation import packet_events


ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "configs" / "selector_htb.json"


class SelectorHtbInputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = load_selector_htb_config(CONFIG_PATH)
        cls.coupled, cls.models, cls.report = fit_frozen_selectors(cls.config)

    def test_config_is_complete_and_split_is_leak_free(self) -> None:
        self.assertEqual(len(self.config.heldout_seeds), 30)
        self.assertFalse(self.report["heldout_data_used_for_fit_or_calibration"])
        self.assertEqual(set(self.models), {"multifeature", "oracle"})
        json.dumps(self.report, allow_nan=False)

    def test_execution_plan_is_deterministic_and_paired(self) -> None:
        first = build_execution_plan(self.config)
        second = build_execution_plan(self.config)
        self.assertEqual(first, second)
        self.assertEqual(first["pair_count"], 180)
        self.assertEqual(first["trial_count"], 360)
        by_pair: dict[str, list[str]] = {}
        for trial in first["trials"]:
            by_pair.setdefault(trial["pair_id"], []).append(trial["scheduler"])
        self.assertTrue(all(sorted(arms) == ["borrowing", "fixed"] for arms in by_pair.values()))

    def test_first_twenty_packets_are_fast_then_mature_decision_applies(self) -> None:
        flows = heldout_flows(self.config, self.coupled, 1009, 1.0)
        flow = next(
            item for item in flows
            if item.true_label == "attack"
            and len(item.iats_s) >= self.coupled.window_iats
            and self.models["oracle"].decide(item).predicted_attack
        )
        events = packet_events([flow], self.coupled.duration_s)
        decision = self.models["oracle"].decide(flow)
        replay = build_replay_events(
            [flow], events, {flow.flow_id: decision}, self.coupled.window_iats
        )
        self.assertTrue(all(item.traffic_class == "fast" for item in replay[:20]))
        if len(replay) > 20:
            self.assertEqual(replay[20].packet_index, 20)
            self.assertEqual(replay[20].traffic_class, "suspicious")
            self.assertFalse(replay[20].provisional)

    def test_replay_trace_is_deterministic(self) -> None:
        _, first = replay_trace(
            self.config, self.coupled, self.models, 1013, 4.0, "multifeature"
        )
        _, second = replay_trace(
            self.config, self.coupled, self.models, 1013, 4.0, "multifeature"
        )
        self.assertEqual(first, second)
        self.assertEqual(len(first["trace_sha256"]), 64)
        self.assertGreater(first["packet_count"], 10_000)

    def test_scheduler_arms_change_only_child_ceilings(self) -> None:
        fixed = tc_spec(self.config, "fixed")
        borrowing = tc_spec(self.config, "borrowing")
        normalized = json.loads(json.dumps(borrowing))
        normalized["scheduler"] = "fixed"
        for name in ("fast", "suspicious"):
            normalized["classes"][name]["ceil_Bps"] = normalized["classes"][name]["rate_Bps"]
        self.assertEqual(fixed, normalized)
        commands = tc_commands(self.config, "borrowing", "/safe/tc")
        self.assertTrue(all(command[0] == "/safe/tc" for command in commands))
        self.assertEqual(len(commands), 9)
        self.assertEqual(
            [
                command[command.index("prio") + 1]
                for command in commands
                if len(command) > 1 and command[1] == "class" and "prio" in command
            ],
            ["0", "0"],
        )


if __name__ == "__main__":
    unittest.main()
