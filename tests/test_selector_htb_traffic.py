from __future__ import annotations

import unittest

from testbed.selector_htb_traffic import HEADER, make_payload, parse_payload


class SelectorHtbTrafficTests(unittest.TestCase):
    def test_payload_round_trip_and_exact_size(self) -> None:
        payload = make_payload(777, "suspicious", "attack", 2, 123, 456, 789)
        self.assertEqual(len(payload), 777)
        self.assertEqual(
            parse_payload(payload),
            {
                "traffic_class": "suspicious", "true_label": "attack", "phase": 2,
                "trace_index": 123, "planned_ns": 456, "sent_ns": 789,
            },
        )

    def test_rejects_short_or_bad_magic(self) -> None:
        self.assertIsNone(parse_payload(bytes(HEADER.size - 1)))
        payload = bytearray(make_payload(64, "fast", "benign", 1, 0, 1, 2))
        payload[0] ^= 1
        self.assertIsNone(parse_payload(bytes(payload)))


if __name__ == "__main__":
    unittest.main()
