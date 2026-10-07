# SPDX-License-Identifier: MIT
# Copyright (c) 2026 pith-hash
"""Hex-exact conformance: the committed reference vectors through ctypes.

Every vector in the repository-root ``reference.json`` is replayed
through the cdylib and compared exactly — the chunk count, every
``(offset, length)`` boundary and every fingerprint formatted
``%016x`` — after each input is regenerated deterministically from its
recorded recipe (SplitMix64 stream, degenerate fills, sawtooth). The
same vectors the Rust ``gen-reference verify`` gate and the Node/Go
SDKs check.
"""

from __future__ import annotations

import ctypes
import json
from pathlib import Path

import pytest

from pith_cdc import FfiError, chunk, find_cdylib

REPO_ROOT = Path(__file__).resolve().parents[3]
MASK64 = (1 << 64) - 1

#: The reference vector's first chunk, pinned literally (rust-derived):
#: this test fails loudly even if reference.json were regenerated
#: wrongly.
PINNED_VECTOR = "splitmix64-1mib-2k8k32k-l2"
PINNED_SEED = 0x5EED5EED5EED5EED
PINNED_FIRST_CHUNK = (0, 2386, 0xDEAD20B04C882E33)


def splitmix64_bytes(seed: int, length: int) -> bytes:
    """Regenerates the corpus's ``splitmix64`` recipe: little-endian
    words, the last partial word carrying the low bytes."""
    out = bytearray()
    state = seed
    while len(out) < length:
        state = (state + 0x9E3779B97F4A7C15) & MASK64
        z = state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK64
        out += ((z ^ (z >> 31)) & MASK64).to_bytes(8, "little")
    return bytes(out[:length])


def build_input(kind: str, seed: int, length: int) -> bytes:
    """Mirrors ``tools/gen-reference`` ``build_input`` exactly."""
    if kind == "splitmix64":
        return splitmix64_bytes(seed, length)
    if kind == "zeros":
        return bytes(length)
    if kind == "fill-ff":
        return b"\xff" * length
    if kind == "sawtooth":
        return bytes((i * 7 + 13) % 256 for i in range(length))
    raise ValueError(f"unknown corpus kind {kind!r}")


def vectors() -> list[dict]:
    return json.loads((REPO_ROOT / "reference.json").read_text(encoding="utf-8"))["vectors"]


def test_cdylib_is_discoverable() -> None:
    path = find_cdylib()
    assert path.is_file(), path


@pytest.mark.parametrize("vector", vectors(), ids=lambda v: v["name"])
def test_reference_vector_is_reproduced_hex_exact(vector: dict) -> None:
    data = build_input(
        vector["input"]["kind"],
        int(vector["input"]["seed_hex"], 16),
        vector["input"]["length"],
    )
    params = vector["params"]
    got = chunk(
        data, params["min_size"], params["avg_size"], params["max_size"], params["level"]
    )
    recorded = vector["chunks"]
    assert len(got) == len(recorded), vector["name"]
    for i, (chunk_, want) in enumerate(zip(got, recorded)):
        assert chunk_.offset == want[0], f"{vector['name']} chunk {i} offset"
        assert chunk_.length == want[1], f"{vector['name']} chunk {i} length"
        assert format(chunk_.hash, "016x") == want[2], f"{vector['name']} chunk {i} hash"


def test_pinned_first_chunk_matches_a_rust_derived_value() -> None:
    # splitmix64-1mib-2k8k32k-l2's first chunk, pinned in the committed
    # reference.json and re-derived by the Rust unit tests; this test
    # fails loudly even if reference.json were regenerated wrongly.
    for vector in vectors():
        if vector["name"] == PINNED_VECTOR:
            params = vector["params"]
            data = splitmix64_bytes(PINNED_SEED, vector["input"]["length"])
            got = chunk(
                data, params["min_size"], params["avg_size"], params["max_size"],
                params["level"],
            )
            first = got[0]
            assert (first.offset, first.length, first.hash) == PINNED_FIRST_CHUNK
            return
    raise AssertionError(f"{PINNED_VECTOR} missing from reference.json")


def test_below_range_min_size_is_rejected() -> None:
    with pytest.raises(FfiError) as err:
        chunk(b"\x00" * 4096, 32, 8192, 32768)
    assert err.value.status == -2


def test_unknown_level_code_is_invalid() -> None:
    with pytest.raises(FfiError) as err:
        chunk(b"\x00" * 4096, 2048, 8192, 32768, level=9)
    assert err.value.status == -1


def test_avg_below_min_is_rejected() -> None:
    with pytest.raises(FfiError) as err:
        chunk(b"\x00" * 4096, 8192, 2048, 32768)
    assert err.value.status == -2


def test_null_data_pointer_is_invalid() -> None:
    # A null data pointer with a non-zero length is a caller bug; call
    # the raw symbol exactly like the C contract says.
    lib = ctypes.CDLL(str(find_cdylib()))
    out = ctypes.c_void_p()
    out_len = ctypes.c_size_t()
    status = lib.pith_cdc_chunk(
        None, 16, 2048, 8192, 32768, 2, ctypes.byref(out), ctypes.byref(out_len)
    )
    assert status == -1


def test_empty_input_yields_zero_chunks() -> None:
    assert chunk(b"", 2048, 8192, 32768) == []
