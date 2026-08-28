# Development

Install `python -m pip install -e '.[dev]'` in a virtual environment.
Run `python -m pytest`, `python -m ruff check .`, and `python -m build` before submitting a change.
For the C toolkit, build the native library first with `guardrail build --cc gcc`.
Include a regression case for behavior changes and rerun benchmarks when changing hot paths.
Report benchmark hardware, input size, iteration count and validation coverage.
