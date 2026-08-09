import argparse
import json
import sys

from .core import Scanner, build_native


def main() -> None:
    parser = argparse.ArgumentParser(description="Streaming C guardrail scanner")
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build")
    build.add_argument("--cc", default="cc")
    check = commands.add_parser("scan")
    check.add_argument("--json", action="store_true", dest="json_mode")
    arguments = parser.parse_args()
    if arguments.command == "build":
        sys.stdout.write(str(build_native(arguments.cc)) + "\n")
        return
    with Scanner(arguments.json_mode) as scanner:
        while chunk := sys.stdin.buffer.read(4096):
            scanner.feed(chunk)
        flags = scanner.finish()
    sys.stdout.write(
        json.dumps(
            {
                "flags": flags,
                "secret": bool(flags & 1),
                "injection": bool(flags & 2),
                "json_structure": bool(flags & 12),
            }
        )
        + "\n"
    )
    raise SystemExit(1 if flags else 0)
