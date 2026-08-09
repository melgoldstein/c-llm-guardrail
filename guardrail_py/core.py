"""Owned streaming contexts for the guardrail C ABI."""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from pathlib import Path

SECRET, INJECTION, JSON_ERROR, DEPTH_ERROR = 1, 2, 4, 8


def library_path() -> Path:
    suffix = ".dll" if sys.platform == "win32" else ".dylib" if sys.platform == "darwin" else ".so"
    return Path(
        os.environ.get(
            "GUARDRAIL_LIBRARY", str(Path.home() / ".cache/c-llm-guardrail" / f"guardrail{suffix}")
        )
    )


def build_native(compiler: str = "cc") -> Path:
    native = Path(__file__).parent / "native"
    destination = library_path()
    destination.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            compiler,
            "-O3",
            "-std=c99",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-shared",
            "-fPIC",
            str(native / "scanner.c"),
            "-I",
            str(native),
            "-lm",
            "-o",
            str(destination),
        ],
        check=True,
    )
    return destination


class Scanner:
    """One independent stream; close explicitly or use a context manager."""

    def __init__(self, json_mode: bool = False) -> None:
        self._library = ctypes.CDLL(str(library_path()))
        self._library.gr_create.argtypes = [ctypes.c_int]
        self._library.gr_create.restype = ctypes.c_void_p
        self._library.gr_feed.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]
        self._library.gr_feed.restype = ctypes.c_uint
        self._library.gr_finish.argtypes = [ctypes.c_void_p]
        self._library.gr_finish.restype = ctypes.c_uint
        self._library.gr_destroy.argtypes = [ctypes.c_void_p]
        self._library.gr_destroy.restype = None
        self._context = self._library.gr_create(json_mode)
        self._finished = False
        if not self._context:
            raise MemoryError("Cannot allocate guardrail context")

    def feed(self, chunk: bytes) -> int:
        if not self._context or self._finished:
            raise RuntimeError("Stream is closed or finalized")
        return int(self._library.gr_feed(self._context, chunk, len(chunk)))

    def finish(self) -> int:
        if not self._context:
            raise RuntimeError("Stream is closed")
        self._finished = True
        return int(self._library.gr_finish(self._context))

    def close(self) -> None:
        if self._context:
            self._library.gr_destroy(self._context)
            self._context = None

    def __enter__(self) -> Scanner:
        return self

    def __exit__(self, *exception: object) -> None:
        self.close()


def scan(payload: bytes, json_mode: bool = False) -> int:
    with Scanner(json_mode) as scanner:
        scanner.feed(payload)
        return scanner.finish()
