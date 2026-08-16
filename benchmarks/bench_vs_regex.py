"""Report measured end-to-end latency; baselines intentionally cover different checks."""

import json
import platform
import re
import statistics
import time
from pathlib import Path

from guardrail_py.core import Scanner


def main() -> None:
    secret = re.compile(rb"(?:sk-|ghp_|AKIA)[A-Za-z0-9_-]{17,}")
    injection = re.compile(
        rb"ignore (?:all )?previous instructions|reveal your system prompt", re.I
    )
    rows = []
    for size in (128, 1024, 8192):
        payload = json.dumps({"status": "nominal " * (size // 8)}).encode()
        timings = {"c_stream_us": [], "python_regex_json_us": []}
        with Scanner(True) as scanner:
            for _ in range(200):
                # Reuse the loaded ABI; allocation is included, shared-library loading is excluded.
                start = time.perf_counter_ns()
                context = scanner._library.gr_create(True)
                scanner._library.gr_feed(context, payload, len(payload))
                scanner._library.gr_finish(context)
                scanner._library.gr_destroy(context)
                timings["c_stream_us"].append((time.perf_counter_ns() - start) / 1000)
                start = time.perf_counter_ns()
                secret.search(payload)
                injection.search(payload)
                json.loads(payload)
                timings["python_regex_json_us"].append((time.perf_counter_ns() - start) / 1000)
        rows.append(
            {
                "bytes": len(payload),
                **{key: statistics.median(values) for key, values in timings.items()},
            }
        )
    destination = Path("benchmarks/results.json")
    destination.write_text(
        json.dumps(
            {
                "platform": platform.platform(),
                "python": platform.python_version(),
                "iterations": 200,
                "measurements": rows,
            },
            indent=2,
        )
        + "\n"
    )
    for row in rows:
        print(
            f"{row['bytes']:6d} bytes  C {row['c_stream_us']:.2f} us  Python {row['python_regex_json_us']:.2f} us"
        )


if __name__ == "__main__":
    main()
