from __future__ import annotations

import unittest

from experiments.selector_htb_analysis import (
    bootstrap_mean_ci,
    decode_uint64,
    exact_two_sided_sign_test,
    holm,
)
from testbed.selector_htb_traffic import encode_uint64


class SelectorHtbAnalysisTests(unittest.TestCase):
    def test_lossless_uint64_round_trip(self) -> None:
        values = [0, 1, 2**32, 2**63, 2**64 - 1]
        self.assertEqual(decode_uint64(encode_uint64(values)), values)

    def test_exact_sign_test(self) -> None:
        result = exact_two_sided_sign_test([1.0] * 30)
        self.assertEqual(result["positive"], 30)
        self.assertAlmostEqual(result["p_value"], 2 / 2**30)
        self.assertEqual(exact_two_sided_sign_test([0.0, 0.0])["p_value"], 1.0)

    def test_bootstrap_is_deterministic(self) -> None:
        first = bootstrap_mean_ci([1.0, 2.0, 3.0], 200, 77)
        second = bootstrap_mean_ci([1.0, 2.0, 3.0], 200, 77)
        self.assertEqual(first, second)

    def test_holm_is_monotone_in_sorted_order(self) -> None:
        result = holm({"a": 0.001, "b": 0.02, "c": 0.04})
        self.assertAlmostEqual(result["a"]["holm_adjusted_p"], 0.003)
        self.assertAlmostEqual(result["b"]["holm_adjusted_p"], 0.04)
        self.assertAlmostEqual(result["c"]["holm_adjusted_p"], 0.04)


if __name__ == "__main__":
    unittest.main()
