from __future__ import annotations

import unittest

from experiments.cross_host_loopback_summary import directional_label


class CrossHostLoopbackSummaryTests(unittest.TestCase):
    def test_direction_requires_all_three_hosts(self) -> None:
        self.assertEqual(
            directional_label([1.0, 2.0, 3.0]), "directionally_replicated_positive"
        )
        self.assertEqual(
            directional_label([-1.0, -2.0, -3.0]), "directionally_replicated_negative"
        )
        self.assertEqual(directional_label([1.0, -2.0, 3.0]), "direction_not_replicated")
        self.assertEqual(directional_label([0.0, 0.0, 0.0]), "all_zero")


if __name__ == "__main__":
    unittest.main()
