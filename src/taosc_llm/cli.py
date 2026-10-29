"""Prepared generic guards: explicit manual or isolated Pi synthesis mode."""

import argparse
import json
import subprocess
import sys
from contextlib import redirect_stdout
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments[:1] == ["recover-quota"]:
        recovery = argparse.ArgumentParser(prog="taosc-llm recover-quota")
        recovery.add_argument("--confirm-provider-settled", action="store_true", required=True,
                              help="assert all prior remote requests have completed; never a timeout bypass")
        recovery.parse_args(arguments[1:])
        try:
            from .admission import recover_reservations
            print(json.dumps({"cleared_reservations": recover_reservations(confirm_provider_settled=True)}))
            return 0
        except (ValueError, OSError, RuntimeError) as error:
            print(f"taosc-llm: {error}", file=sys.stderr)
            return 1

    parser = argparse.ArgumentParser(
        prog="taosc-llm",
        description="Build a manual or Pi-proposed generic guard from prepared metadata; not a repair verifier.",
    )
    parser.add_argument("--config", "-c", type=Path, required=True, metavar="config.env")
    parser.add_argument("--workdir", "-w", type=Path, required=True, metavar="DIRECTORY")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--predicate", metavar="EXPRESSION", help="manual nonzero-to-jump generic guard")
    mode.add_argument("--provider-env", type=Path, metavar="FILE", help="explicit provider file; enables Pi synthesis")
    parser.add_argument("--context", type=Path, help="caller-prepared development evidence JSON (not raw BinRadar captures)")
    parser.add_argument("--pi-sdk-root", type=Path, help="explicit pinned npm project; Guix supplies an installed default")
    parser.add_argument("--base-url", help="explicit nonsecret override; no routing fallback")
    parser.add_argument("--model", help="exact model ID override within the selected profile")
    parser.add_argument("--max-in-flight", type=int, help="provider cap; this Ollama account permits 1..3")
    parser.add_argument("--workers", type=int, help="finite positive local worker capacity")
    parser.add_argument("--isolate-native", action="store_true", help="also isolate native commands in manual mode; always enabled for Pi")
    args = parser.parse_args(arguments)
    if args.provider_env is not None and args.context is None:
        parser.error("--provider-env requires --context")
    if args.predicate is not None and any(value is not None for value in (
            args.context, args.pi_sdk_root, args.base_url, args.model, args.max_in_flight, args.workers)):
        parser.error("provider/context options require --provider-env")
    try:
        # Help remains independent of SDK/auth/native dependency discovery.
        with redirect_stdout(sys.stderr):
            if args.predicate is not None:
                from .builder import generate_patch
                if args.isolate_native:
                    from .native import build_command
                    result = generate_patch(args.config, args.workdir, args.predicate, native_runner=build_command)
                else:
                    result = generate_patch(args.config, args.workdir, args.predicate)
            else:
                from .synthesis import generate_with_pi
                result = generate_with_pi(args.config, args.workdir, args.context, args.provider_env,
                                          sdk_root=args.pi_sdk_root, base_url=args.base_url,
                                          model=args.model, max_in_flight=args.max_in_flight, workers=args.workers)
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"taosc-llm: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("taosc-llm: cancelled; unresolved requests remain quarantined", file=sys.stderr)
        return 130
    print(json.dumps(result))
    return 0 if result["status"] in ("built", "abstained") else 1
