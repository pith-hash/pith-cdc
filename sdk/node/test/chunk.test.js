// SPDX-License-Identifier: MIT
// Copyright (c) 2026 pith-hash
"use strict";

// Hex-exact conformance: the committed reference vectors through koffi.
// Every vector in the repository-root reference.json is replayed through
// the cdylib and compared exactly — the chunk count, every (offset,
// length) boundary and every fingerprint formatted %016x — after each
// input is regenerated deterministically from its recorded recipe. The
// same vectors the Rust gen-reference verify gate and the Python/Go SDKs
// check.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const { FfiError, chunk, findCdylib, koffiChunkRaw } = require("../index.js");

const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");

const VECTORS = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "reference.json"), "utf8")).vectors;

/** Regenerates the corpus's splitmix64 recipe: little-endian words,
 * the last partial word carrying the low bytes. */
function splitmix64Bytes(seed, length) {
  const out = Buffer.alloc(length);
  let state = seed;
  for (let pos = 0n; pos < BigInt(length); ) {
    state = (state + 0x9e3779b97f4a7c15n) & 0xffffffffffffffffn;
    let z = state;
    z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & 0xffffffffffffffffn;
    z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & 0xffffffffffffffffn;
    z ^= z >> 31n;
    const word = Buffer.alloc(8);
    word.writeBigUInt64LE(z);
    const take = Math.min(8, length - Number(pos));
    word.copy(out, Number(pos), 0, take);
    pos += 8n;
  }
  return out;
}

/** Mirrors tools/gen-reference build_input exactly. */
function buildInput(kind, seed, length) {
  if (kind === "splitmix64") return splitmix64Bytes(BigInt(`0x${seed}`), length);
  if (kind === "zeros") return Buffer.alloc(length);
  if (kind === "fill-ff") return Buffer.alloc(length, 0xff);
  if (kind === "sawtooth") {
    const out = Buffer.alloc(length);
    for (let i = 0; i < length; i++) out[i] = (i * 7 + 13) % 256;
    return out;
  }
  throw new Error(`unknown corpus kind ${kind}`);
}

test("cdylib is discoverable", () => {
  assert.ok(fs.statSync(findCdylib()).isFile());
});

for (const vector of VECTORS) {
  test(`reference vector ${vector.name} is reproduced hex-exact`, () => {
    const data = buildInput(vector.input.kind, vector.input.seed_hex, vector.input.length);
    const p = vector.params;
    const got = chunk(data, p.min_size, p.avg_size, p.max_size, p.level);
    assert.equal(got.length, vector.chunks.length, vector.name);
    for (let i = 0; i < got.length; i++) {
      assert.equal(got[i].offset, BigInt(vector.chunks[i][0]), `${vector.name} chunk ${i} offset`);
      assert.equal(got[i].length, BigInt(vector.chunks[i][1]), `${vector.name} chunk ${i} length`);
      assert.equal(got[i].hash.toString(16).padStart(16, "0"), vector.chunks[i][2], `${vector.name} chunk ${i} hash`);
    }
  });
}

test("pinned first chunk matches a rust-derived value", () => {
  // splitmix64-1mib-2k8k32k-l2's first chunk, pinned in the committed
  // reference.json and re-derived by the Rust unit tests; this test
  // fails loudly even if reference.json were regenerated wrongly.
  const vector = VECTORS.find((v) => v.name === "splitmix64-1mib-2k8k32k-l2");
  assert.ok(vector, "pinned vector missing from reference.json");
  const data = splitmix64Bytes(0x5eed5eed5eed5eedn, vector.input.length);
  const got = chunk(data, vector.params.min_size, vector.params.avg_size, vector.params.max_size, vector.params.level);
  assert.equal(got[0].offset, 0n);
  assert.equal(got[0].length, 2386n);
  assert.equal(got[0].hash.toString(16).padStart(16, "0"), "dead20b04c882e33");
});

test("below-range min_size is rejected", () => {
  assert.throws(() => chunk(Buffer.alloc(4096), 32, 8192, 32768), (err) => {
    assert.ok(err instanceof FfiError);
    assert.equal(err.status, -2);
    return true;
  });
});

test("unknown level code is invalid", () => {
  assert.throws(() => chunk(Buffer.alloc(4096), 2048, 8192, 32768, 9), (err) => {
    assert.ok(err instanceof FfiError);
    assert.equal(err.status, -1);
    return true;
  });
});

test("avg below min is rejected", () => {
  assert.throws(() => chunk(Buffer.alloc(4096), 8192, 2048, 32768), (err) => {
    assert.ok(err instanceof FfiError);
    assert.equal(err.status, -2);
    return true;
  });
});

test("null data pointer with a non-zero length is invalid", () => {
  // Call the raw symbol the way the C contract says: a null data
  // pointer with a non-zero length is a caller bug, status -1.
  assert.throws(() => koffiChunkRaw(null, 16, 2048, 8192, 32768, 2), (err) => {
    assert.ok(err instanceof FfiError);
    assert.equal(err.status, -1);
    return true;
  });
});

test("empty input yields zero chunks", () => {
  assert.deepEqual(chunk(Buffer.alloc(0), 2048, 8192, 32768), []);
});
