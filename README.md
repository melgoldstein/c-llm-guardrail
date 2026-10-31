# c-llm-guardrail

[Portfolio: melgoldstein.com](https://melgoldstein.com/)

Bounded-memory C99 checks for LLM output streams, with a Python `ctypes` interface.
Detect secret-like tokens, known injection signatures and JSON bracket mismatches
without buffering the complete response. MIT licensed; Python 3.11+.

## Quickstart (30 Seconds)

Requires Python and a C99 compiler, with a virtual environment active:

```bash
git clone https://github.com/melgoldstein/c-llm-guardrail.git
cd c-llm-guardrail
python -m pip install -e '.[dev]'
guardrail build --cc gcc
echo '{"status":"nominal"}' | guardrail scan --json
python -m pytest -q
```

Windows uses the same CLI with GCC on PATH, or its full path passed to `--cc`.
Native builds are explicit; importing never invokes a compiler. C sources are included
in the wheel. Set `GUARDRAIL_LIBRARY` for a custom library location. On Linux, `make`
also builds the standalone shared library under `build/`.

## Stream API

```python
from guardrail_py import Scanner

with Scanner(json_mode=True) as scanner:
    scanner.feed(b'{"answer":"ignore previous ')
    scanner.feed(b'instructions"}')
    flags = scanner.finish()
    assert flags & 2
```

Each scanner owns an independent C context. Flags are sticky across chunks. Use one
owner per stream; `finish()` detects unfinished strings and unclosed brackets. Context
exit releases and clears native state. The [C ABI](include/guardrail.h) is also public.

| Bit | Meaning |
| ---: | --- |
| 1 | Prefix/entropy heuristic matched a secret-like ASCII token |
| 2 | A configured case-insensitive injection signature completed |
| 4 | Mismatched bracket, unfinished string or unclosed structure |
| 8 | JSON nesting exceeded 256 levels |

CLI output is JSON; exit status is 1 on findings and 0 on a clean scan. The C core
uses only the standard C/math libraries. Python has no third-party runtime dependencies.

## Benchmark comparison

Measured medians over 200 iterations on Windows x64:

| Input bytes | C stream checks, us | Python regex + JSON, us |
| ---: | ---: | ---: |
| 142 | 1.80 | 4.10 |
| 1,038 | 5.90 | 20.20 |
| 8,206 | 37.50 | 142.40 |

Reproduce: `python benchmarks/bench_vs_regex.py`. [Raw results](benchmarks/results.json)
record platform and iterations. C timing includes allocation, feed, finish and ctypes
calls, excluding shared-library loading. Python runs compiled secret/injection regexes
and `json.loads`. Coverage differs: Python validates full JSON grammar while C checks
bracket/string structure and also evaluates token entropy. This is a latency reference,
not a feature-equivalence or detection-quality benchmark. Larger inputs take longer.

ASCII classification reduced the initial 8 KB C median from about 435 us to 38 us on
this host. Compiler, CPU and workload affect results.

## Detection contract

Prefix candidates include `sk-`, `ghp_` and `AKIA` combined with Shannon entropy checks.
Generic mixed letter/digit tokens of at least 32 characters are checked separately.
Candidate storage and the JSON nesting stack are each capped at 256 entries. Entropy
checks occur at fixed token lengths and boundaries, keeping state independent of input size.

Injection matching covers five literal signatures in `src/scanner.c`, not arbitrary
paraphrases. Entropy may flag legitimate identifiers or miss low-entropy secrets.
Bracket balance does not validate commas, values, Unicode or full JSON grammar; run a
full parser on completed JSON. Findings are inputs to an application's policy layer.

Tests cover split secrets/signatures, quoted brackets, embedded NUL, long tokens,
nesting and lifecycle errors. CI tests Python 3.11/3.12, builds distributions and checks
the installed CLI outside the checkout. See [CONTRIBUTING.md](CONTRIBUTING.md).
