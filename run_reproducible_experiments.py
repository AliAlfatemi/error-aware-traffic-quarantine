#!/usr/bin/env python3
"""Safe entry point for explicitly reproducing or verifying experiments.

This code-only repository does not bundle authoritative result trees, so an
empty invocation prints help. Every verification or reproduction action must
be selected explicitly.
"""

import sys

from experiments.reproducible_pipeline import cli


if __name__ == "__main__":
    raise SystemExit(cli(["--help"]) if len(sys.argv) == 1 else cli())
