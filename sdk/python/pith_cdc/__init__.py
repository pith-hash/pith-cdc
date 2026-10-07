# SPDX-License-Identifier: MIT
# Copyright (c) 2026 pith-hash
"""pith-cdc SDK: FastCDC content-defined chunking through ctypes.

The single Rust core (the ``pith-cdc`` cdylib built by
``cargo build --release``) is loaded at runtime; this package carries
no third-party dependency — ``ctypes`` is the standard library.

Discovery order (the suite's cdylib convention):

1. ``PITH_CDYLIB`` — an explicit cdylib *file* path;
2. ``PITH_CDYLIB_DIR`` — a *directory* scanned for the cdylib names
   (the CD pipeline points this at ``target/release``);
3. the package directory itself (the built wheel ships the cdylib as
   package data);
4. ``<repo root>/target/release`` — the repository working-tree layout,
   so a source checkout runs against a local cargo build with no
   configuration.

The FFI surface is one chunking operation plus one free:
``pith_cdc_chunk`` runs the FastCDC scan over a byte slice and hands
back a flat ``(offset, length, hash)`` triple buffer (24 bytes per
chunk), and ``pith_cdc_free`` releases the handed-out buffer.
"""

from __future__ import annotations

import ctypes
import os
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "Chunk",
    "FfiError",
    "LibraryNotFoundError",
    "find_cdylib",
    "chunk",
    "LEVEL_0",
    "LEVEL_1",
    "LEVEL_2",
    "LEVEL_3",
    "STATUS_OK",
    "STATUS_INVALID",
    "STATUS_REJECTED",
]

#: Status: success.
STATUS_OK = 0
#: Status: a caller argument is invalid (a null pointer, or a level
#: code the ABI does not define — only 0..=3 exist).
STATUS_INVALID = -1
#: Status: the core chunker refused the parameters (a size outside its
#: range, or a ``min <= avg <= max`` violation).
STATUS_REJECTED = -2

#: Normalization-level wire code: level 0, no normalization.
LEVEL_0 = 0
#: Normalization-level wire code: level 1.
LEVEL_1 = 1
#: Normalization-level wire code: level 2, the crate default.
LEVEL_2 = 2
#: Normalization-level wire code: level 3.
LEVEL_3 = 3

#: Every cdylib file name cargo may drop into the build directory, per
#: platform (windows / linux / macOS).
CDYLIB_NAMES = ("pith_cdc.dll", "libpith_cdc.so", "libpith_cdc.dylib")


@dataclass(frozen=True)
class Chunk:
    """One content-defined chunk: a ``(offset, length)`` span plus the
    Gear fingerprint value at the cut point (the ``hash`` — a rolling
    fingerprint, not a digest)."""

    #: Byte offset of the chunk start within the source.
    offset: int
    #: Chunk length in bytes.
    length: int
    #: Gear fingerprint as of the end of the chunk.
    hash: int


class LibraryNotFoundError(OSError):
    """No cdylib was found through the discovery chain."""


class FfiError(Exception):
    """A non-zero status code came back from the cdylib."""

    def __init__(self, op: str, status: int) -> None:
        kind = {
            STATUS_INVALID: "invalid argument",
            STATUS_REJECTED: "parameters rejected",
        }.get(status, "unknown failure")
        super().__init__(f"{op} failed: {kind} (status {status})")
        #: The raw status code the FFI returned.
        self.status = status


def find_cdylib() -> Path:
    """Locates the cdylib through the suite's discovery chain."""
    explicit = os.environ.get("PITH_CDYLIB")
    if explicit:
        p = Path(explicit)
        if p.is_file():
            return p
    env_dir = os.environ.get("PITH_CDYLIB_DIR")
    candidates: list[Path] = []
    if env_dir:
        env_dir_path = Path(env_dir)
        candidates.append(env_dir_path)
        if not env_dir_path.is_absolute():
            # CD and local runs invoke tools from the repository root or
            # from sdk/<lang>; resolve the env value against both.
            candidates.append(Path.cwd() / env_dir_path)
            candidates.append(Path(__file__).resolve().parents[3] / env_dir_path)
    candidates.append(Path(__file__).resolve().parent)  # packaged wheel
    candidates.append(Path(__file__).resolve().parents[3] / "target" / "release")
    for directory in candidates:
        for name in CDYLIB_NAMES:
            p = directory / name
            if p.is_file():
                return p
    raise LibraryNotFoundError(
        "no pith-cdc cdylib found (searched PITH_CDYLIB, PITH_CDYLIB_DIR, "
        "the package directory and <repo>/target/release); "
        "run `cargo build --release` first"
    )


_lib: ctypes.CDLL | None = None


def _load() -> ctypes.CDLL:
    global _lib
    if _lib is None:
        lib = ctypes.CDLL(str(find_cdylib()))
        lib.pith_cdc_chunk.argtypes = [
            ctypes.c_void_p,  # data
            ctypes.c_size_t,  # len
            ctypes.c_size_t,  # min_size
            ctypes.c_size_t,  # avg_size
            ctypes.c_size_t,  # max_size
            ctypes.c_uint32,  # level
            ctypes.POINTER(ctypes.c_void_p),  # out buffer
            ctypes.POINTER(ctypes.c_size_t),  # out length (bytes)
        ]
        lib.pith_cdc_chunk.restype = ctypes.c_int32
        lib.pith_cdc_free.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        lib.pith_cdc_free.restype = None
        _lib = lib
    return _lib


def chunk(
    data: bytes,
    min_size: int,
    avg_size: int,
    max_size: int,
    level: int = LEVEL_2,
) -> list[Chunk]:
    """Chunks ``data`` with FastCDC and returns the chunk boundaries.

    ``min_size``/``avg_size``/``max_size`` are validated by the Rust
    core (the spec's defaults are 2048/8192/32768); ``level`` is one of
    the ``LEVEL_*`` wire codes (the default is :data:`LEVEL_2`, the
    paper's sweet spot).

    Raises :class:`FfiError` with ``status == STATUS_REJECTED`` for
    out-of-range or misordered sizes and ``status ==
    STATUS_INVALID`` for an unknown level code — never a crash; an
    empty input simply returns ``[]``.
    """
    # ctypes hands an empty bytes object as a valid buffer, but pass a
    # real NULL for it so the (null, 0) contract is exercised exactly
    # like the Go binding does.
    buf = data if len(data) else None
    out = ctypes.c_void_p()
    out_len = ctypes.c_size_t()
    status = _load().pith_cdc_chunk(
        buf, len(data), min_size, avg_size, max_size, level,
        ctypes.byref(out), ctypes.byref(out_len),
    )
    if status != STATUS_OK:
        raise FfiError("pith_cdc_chunk", status)
    try:
        count = out_len.value // 24
        words = (ctypes.c_uint64 * (count * 3)).from_address(out.value)
        return [
            Chunk(offset=words[i * 3], length=words[i * 3 + 1], hash=words[i * 3 + 2])
            for i in range(count)
        ]
    finally:
        _load().pith_cdc_free(out, out_len.value)
