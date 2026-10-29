"""Command-line entry point for prepared manual generic patches."""

import argparse
import json
import subprocess
import sys
from contextlib import redirect_stdout
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="taosc-llm",
        description=(
            "Build fixed and BinRadar-selectable binaries from prepared Taosc "
            "metadata and one manual generic guard. This does not verify the repair."
        ),
    )
    parser.add_argument(
        "--config", "-c", type=Path, required=True, metavar="config.env",
        help="prepared config.env file containing the BINARY basename",
    )
    parser.add_argument(
        "--workdir", "-w", type=Path, required=True, metavar="DIRECTORY",
        help="existing directory containing BINARY.orig and patch addresses",
    )
    parser.add_argument(
        "--predicate", required=True, metavar="EXPRESSION",
        help="BinRadar generic expression; true jumps to patch-destination",
    )
    args = parser.parse_args(argv)

    try:
        # Keep help independent of BinRadar/native dependencies and reserve stdout
        # for the single result, including when imported helpers print diagnostics.
        with redirect_stdout(sys.stderr):
            from .builder import generate_patch

            result = generate_patch(args.config, args.workdir, args.predicate)
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"taosc-llm: {error}", file=sys.stderr)
        return 1

    print(json.dumps(result))
    return 0
