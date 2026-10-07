// SPDX-License-Identifier: MIT
// Copyright (c) 2026 pith-hash
"use strict";

/**
 * pith-cdc SDK: FastCDC content-defined chunking through koffi.
 *
 * The single Rust core (the `pith-cdc` cdylib built by
 * `cargo build --release`) is loaded at runtime; koffi is the only
 * runtime dependency.
 *
 * Discovery order (the suite's cdylib convention):
 *
 *  1. `PITH_CDYLIB` — an explicit cdylib *file* path;
 *  2. `PITH_CDYLIB_DIR` — a *directory* scanned for the cdylib names
 *     (the CD pipeline points this at `target/release`);
 *  3. `prebuilds/` — the packaged npm layout the CD publish job
 *     assembles, flat and per `<os-arch>` (e.g. `linux-x64`);
 *  4. `<repo root>/target/release` — the repository working-tree
 *     layout, so a source checkout runs against a local cargo build
 *     with no configuration.
 *
 * The FFI surface is one chunking operation plus one free:
 * `pith_cdc_chunk` runs the FastCDC scan over a byte slice and hands
 * back a flat `(offset, length, hash)` triple buffer (24 bytes per
 * chunk), and `pith_cdc_free` releases the handed-out buffer.
 */

const koffi = require("koffi");
const fs = require("node:fs");
const path = require("node:path");

const STATUS_OK = 0;
const STATUS_INVALID = -1;
const STATUS_REJECTED = -2;

/** Normalization-level wire codes (the ABI defines 0..=3 only). */
const LEVEL_0 = 0;
const LEVEL_1 = 1;
/** Level 2: the paper's sweet spot and the crate default. */
const LEVEL_2 = 2;
const LEVEL_3 = 3;

/** Every cdylib file name cargo may drop into the build directory, per platform. */
const CDYLIB_NAMES = ["pith_cdc.dll", "libpith_cdc.so", "libpith_cdc.dylib"];

const PKG_ROOT = path.join(__dirname);
const REPO_ROOT = path.resolve(__dirname, "..", "..");

/** FfiError: a non-zero status code came back from the cdylib. */
class FfiError extends Error {
  /**
   * @param {string} op the FFI operation name
   * @param {number} status the raw status code
   */
  constructor(op, status) {
    const kind = { [STATUS_INVALID]: "invalid argument", [STATUS_REJECTED]: "parameters rejected" }[status] ?? "unknown failure";
    super(`${op} failed: ${kind} (status ${status})`);
    this.name = "FfiError";
    /** The raw status code the FFI returned. */
    this.status = status;
  }
}

/**
 * Locates the cdylib through the suite's discovery chain.
 * @returns {string} an absolute path to the cdylib file
 * @throws {Error} when nothing is found
 */
function findCdylib() {
  const explicit = process.env.PITH_CDYLIB;
  if (explicit && fs.statSync(explicit, { throwIfNoEntry: false })?.isFile()) {
    return path.resolve(explicit);
  }
  /** @type {string[]} */
  const dirs = [];
  const envDir = process.env.PITH_CDYLIB_DIR;
  if (envDir) {
    dirs.push(envDir);
    if (!path.isAbsolute(envDir)) {
      dirs.push(path.join(REPO_ROOT, envDir));
    }
  }
  const osArch = `${process.platform}-${process.arch}`;
  dirs.push(path.join(PKG_ROOT, "prebuilds", osArch));
  dirs.push(path.join(PKG_ROOT, "prebuilds"));
  dirs.push(path.join(REPO_ROOT, "target", "release"));
  for (const dir of dirs) {
    for (const name of CDYLIB_NAMES) {
      const p = path.join(dir, name);
      if (fs.statSync(p, { throwIfNoEntry: false })?.isFile()) return p;
    }
  }
  throw new Error(
    "no pith-cdc cdylib found (searched PITH_CDYLIB, PITH_CDYLIB_DIR, prebuilds/ and <repo>/target/release); " +
      "run `cargo build --release` first",
  );
}

let cached = undefined;

/**
 * Loads the cdylib and binds the exported symbols (lazily, once).
 * @returns {{chunk: Function, free: Function}}
 */
function loadLibrary() {
  if (cached) return cached;
  const lib = koffi.load(findCdylib());
  const chunk = lib.func("pith_cdc_chunk", "int32_t", [
    "const uint8_t *",
    "size_t",
    "size_t",
    "size_t",
    "size_t",
    "uint32_t",
    koffi.out(koffi.pointer("void *")),
    koffi.out(koffi.pointer("size_t")),
  ]);
  const free = lib.func("void pith_cdc_free(void *ptr, size_t len)");
  cached = { chunk, free };
  return cached;
}

/**
 * Calls the raw FFI with an explicit data pointer — the path the
 * null-pointer refusal tests need, which the Buffer-typed `chunk()`
 * cannot express.
 *
 * @param {Pointer | null} dataPtr a `const uint8_t *` (or null when
 *   `len` is 0)
 * @param {number} len source length in bytes
 * @param {number} minSize sub-minimum cut-point skip distance
 * @param {number} avgSize target average chunk size
 * @param {number} maxSize hard cap on a chunk's length
 * @param {number} level normalization level wire code
 * @returns {{offset: bigint, length: bigint, hash: bigint}[]}
 * @throws {FfiError} on any non-zero status
 */
function koffiChunkRaw(dataPtr, len, minSize, avgSize, maxSize, level) {
  const { chunk: chunkFn, free } = loadLibrary();
  const out = [null];
  const outLen = [0];
  const status = chunkFn(dataPtr, len, minSize, avgSize, maxSize, level, out, outLen);
  if (status !== STATUS_OK) {
    throw new FfiError("pith_cdc_chunk", status);
  }
  try {
    // koffi.decode hands back a Uint8Array view over the external
    // buffer; copy the values out (as BigInts) before the cdylib
    // buffer is freed.
    const raw = koffi.decode(out[0], "uint8_t", Number(outLen[0]));
    const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
    const count = raw.byteLength / 24;
    const chunks = new Array(count);
    for (let i = 0; i < count; i++) {
      chunks[i] = {
        offset: view.getBigUint64(i * 24, true),
        length: view.getBigUint64(i * 24 + 8, true),
        hash: view.getBigUint64(i * 24 + 16, true),
      };
    }
    return chunks;
  } finally {
    free(out[0], Number(outLen[0]));
  }
}

/**
 * Chunks `data` with FastCDC and returns the chunk boundaries. The
 * handed-out cdylib buffer is copied out and released before returning.
 *
 * @param {Buffer} data the source bytes (an empty buffer is legal and
 *   yields `[]`)
 * @param {number} minSize sub-minimum cut-point skip distance (64 B..=1 MiB)
 * @param {number} avgSize target average chunk size (256 B..=4 MiB)
 * @param {number} maxSize hard cap on a chunk's length (1 KiB..=16 MiB)
 * @param {number} [level=2] normalization level wire code (0..=3)
 * @returns {{offset: bigint, length: bigint, hash: bigint}[]}
 * @throws {FfiError} with `status === -2` for rejected parameters and
 *   `status === -1` for an unknown level code
 */
function chunk(data, minSize, avgSize, maxSize, level = LEVEL_2) {
  if (!Buffer.isBuffer(data)) {
    throw new TypeError("data must be a Buffer");
  }
  return koffiChunkRaw(data, data.length, minSize, avgSize, maxSize, level);
}

module.exports = {
  STATUS_OK,
  STATUS_INVALID,
  STATUS_REJECTED,
  LEVEL_0,
  LEVEL_1,
  LEVEL_2,
  LEVEL_3,
  CDYLIB_NAMES,
  FfiError,
  findCdylib,
  chunk,
  koffiChunkRaw,
};
