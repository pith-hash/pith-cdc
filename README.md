<p align="center">
  <img src="https://pith-cdc.n24q02m.com/logo.svg" alt="pith-cdc" width="120">
</p>

<h1 align="center">pith-cdc</h1>

<p align="center">
  <strong>FastCDC content-defined chunking with a 16-level gear mask table (zero-dep Rust)</strong>
</p>

<p align="center">
  <a href="https://github.com/pith-hash/pith-cdc/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/pith-hash/pith-cdc/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/pith-hash/pith-cdc/actions/workflows/cd.yml"><img alt="CD" src="https://github.com/pith-hash/pith-cdc/actions/workflows/cd.yml/badge.svg"></a>
  <a href="https://github.com/pith-hash/pith-cdc/releases/latest"><img alt="Latest release" src="https://img.shields.io/github/v/release/pith-hash/pith-cdc?display_name=tag&sort=semver"></a>
  <a href="https://github.com/n24q02m/better-semantic-release"><img alt="semantic-release" src="https://img.shields.io/badge/semantic--release-e10079?logo=semantic-release&logoColor=white"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/github/license/pith-hash/pith-cdc"></a>
</p>

<p align="center">
  <a href="#install">Install</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#the-pith-suite-contract">Suite contract</a>
</p>

<!-- BEGIN: AUTO-GENERATED-CROSS-PROMO -->
<!-- END: AUTO-GENERATED-CROSS-PROMO -->

## The pith suite contract

pith-cdc is part of the **pith** suite (pith-hash). Every suite repository
follows the same rules; CI enforces them mechanically:

- **Naming**: a library is always `pith-<domain>` (`pith-image`, `pith-audio`,
  `pith-zip`, ...). The curator/repository of repositories is the bare
  `pith-hash`. Never invent a second naming scheme inside the suite.
- **Version pinning**: cross-library dependencies pin `~0.1` (e.g.
  `pith-image = { version = "~0.1", path = "../pith-image" }`). The whole suite
  moves together inside 0.1.x; breaking changes require a suite-wide version
  bump, never a silent minor drift.
- **Zero third-party dependencies**: every crate depends only on other
  `pith-*` crates plus `std`. `scripts/check-zero-deps.py` (run in CI) fails
  the build on any other crate, for normal, build and dev dependencies alike.
- **No unsafe**: every crate root carries `#![forbid(unsafe_code)]`.
- **Hex-exact vectors**: `reference.json` at the repo root is the
  cross-language source of truth. The `gen-reference` binary regenerates it;
  CI verifies the committed copy is current (`gen-reference verify`), and CD
  ships the regenerated file with every SDK artifact. Python, Node and Go SDKs
  MUST test against the same bytes.

## Repository layout

```
src/               the pith-cdc library (FastCDC chunker, Gear, Buzhash64)
tests/             behavioural, table-pin, stateful and reference-vector tests
tools/gen-reference  the vector generator binary (bin name: gen-reference)
reference.json     hex-exact chunking vectors (canonical copy: tests/reference.json)
```

## Install

Rust (the core library):

```bash
cargo add pith-cdc
```

Python / Node / Go SDKs are published from the same cdylib on every release;
see the release assets or the package registries for the matching version.

## Quick start

```rust
use pith_cdc::FastCdc;

let data = std::fs::read("backup.img")?;

// Spec defaults: min 2 KiB, avg 8 KiB, max 32 KiB, normalization level 2.
for chunk in FastCdc::new(&data, 2048, 8192, 32768)? {
    println!("chunk at {} ({} bytes, fingerprint {:016x})",
             chunk.offset, chunk.length, chunk.hash);
}
```

Boundaries are content-defined: insertions shift only nearby cut points,
and identical regions cut identically, so unchanged blocks deduplicate
across versions. `chunk(&data, min, avg, max)?` returns the boundaries
as plain `(offset, length)` pairs.

## Vectors

`tools/gen-reference` regenerates `reference.json` (root copy) and
`tests/reference.json` (canonical copy) from a fixed input corpus of 11
vectors: SplitMix64 streams at normalization levels 0–3, degenerate
all-zero and all-`0xff` fills, a sawtooth pattern, fixed-size edge
parameters and sub-minimum/empty inputs. `gen-reference verify`
byte-compares both committed copies; CI runs it on every push.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © pith-hash
