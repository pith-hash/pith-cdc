//! Generates and verifies the pith-cdc reference chunking vectors.
//!
//! `tests/reference.json` is the committed corpus of content-defined
//! chunking vectors: fixed deterministic inputs (SplitMix64 streams,
//! degenerate fills, a sawtooth pattern) chunked at a fixed matrix of
//! `(min, avg, max, level)` parameters, each chunk recorded as
//! `[offset, length, "fingerprint-hex"]`. `gen` rewrites the file (plus the
//! root `reference.json` copy the CD workflow ships with SDK artifacts);
//! `verify` recomputes every vector and byte-compares the committed copies.
//!
//! The corpus inputs are built from the same recipes the conformance test
//! uses (`tests/reference.rs`), so a disagreement between generator and
//! test is itself a loud failure.

use pith_cdc::{FastCdc, Normalization};
use pith_digest::SplitMix64;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// One frozen chunking vector: a deterministic input, chunking parameters
/// and the exact chunks the crate must produce.
struct Vector {
    name: &'static str,
    kind: &'static str,
    seed: u64,
    length: usize,
    min_size: usize,
    avg_size: usize,
    max_size: usize,
    level: u32,
    chunks: Vec<(usize, usize, u64)>,
}

/// One frozen corpus entry before chunking: input recipe plus parameters.
struct VectorSpec {
    name: &'static str,
    kind: &'static str,
    seed: u64,
    length: usize,
    min_size: usize,
    avg_size: usize,
    max_size: usize,
    level: u32,
}

/// The fixed input corpus and parameter matrix, in file order.
fn vector_specs() -> [VectorSpec; 11] {
    [
        VectorSpec {
            name: "splitmix64-1mib-2k8k32k-l2",
            kind: "splitmix64",
            seed: 0x5eed_5eed_5eed_5eed,
            length: 1 << 20,
            min_size: 2048,
            avg_size: 8192,
            max_size: 32768,
            level: 2,
        },
        VectorSpec {
            name: "splitmix64-1mib-2k8k32k-l0",
            kind: "splitmix64",
            seed: 0x5eed_5eed_5eed_5eed,
            length: 1 << 20,
            min_size: 2048,
            avg_size: 8192,
            max_size: 32768,
            level: 0,
        },
        VectorSpec {
            name: "splitmix64-1mib-2k8k32k-l1",
            kind: "splitmix64",
            seed: 0x5eed_5eed_5eed_5eed,
            length: 1 << 20,
            min_size: 2048,
            avg_size: 8192,
            max_size: 32768,
            level: 1,
        },
        VectorSpec {
            name: "splitmix64-1mib-2k8k32k-l3",
            kind: "splitmix64",
            seed: 0x5eed_5eed_5eed_5eed,
            length: 1 << 20,
            min_size: 2048,
            avg_size: 8192,
            max_size: 32768,
            level: 3,
        },
        VectorSpec {
            name: "splitmix64-256kib-8k16k64k-l2",
            kind: "splitmix64",
            seed: 0,
            length: 256 * 1024,
            min_size: 8192,
            avg_size: 16384,
            max_size: 65536,
            level: 2,
        },
        VectorSpec {
            name: "zeros-256kib-2k8k32k-l2",
            kind: "zeros",
            seed: 0,
            length: 256 * 1024,
            min_size: 2048,
            avg_size: 8192,
            max_size: 32768,
            level: 2,
        },
        VectorSpec {
            name: "fill-ff-64kib-64b256b1k-l0",
            kind: "fill-ff",
            seed: 0,
            length: 64 * 1024,
            min_size: 64,
            avg_size: 256,
            max_size: 1024,
            level: 0,
        },
        VectorSpec {
            name: "sawtooth-128kib-1k4k16k-l3",
            kind: "sawtooth",
            seed: 0,
            length: 128 * 1024,
            min_size: 1024,
            avg_size: 4096,
            max_size: 16384,
            level: 3,
        },
        VectorSpec {
            name: "splitmix64-1kib-submin-l2",
            kind: "splitmix64",
            seed: 9,
            length: 1024,
            min_size: 2048,
            avg_size: 8192,
            max_size: 32768,
            level: 2,
        },
        VectorSpec {
            name: "empty-2k8k32k-l2",
            kind: "splitmix64",
            seed: 0,
            length: 0,
            min_size: 2048,
            avg_size: 8192,
            max_size: 32768,
            level: 2,
        },
        VectorSpec {
            name: "splitmix64-64kib-fixed2k-l2",
            kind: "splitmix64",
            seed: 0x0123_4567_89ab_cdef,
            length: 64 * 1024,
            min_size: 2048,
            avg_size: 2048,
            max_size: 2048,
            level: 2,
        },
    ]
}

/// Builds the deterministic input bytes for a corpus kind.
///
/// Mirrored by `tests/reference.rs`; the two recipes must stay identical or
/// the conformance test fails loudly.
fn build_input(kind: &str, seed: u64, length: usize) -> Vec<u8> {
    match kind {
        "splitmix64" => {
            let mut rng = SplitMix64::new(seed);
            let mut out = vec![0u8; length];
            rng.fill_bytes(&mut out);
            out
        }
        "zeros" => vec![0u8; length],
        "fill-ff" => vec![0xffu8; length],
        "sawtooth" => (0..length).map(|i| ((i * 7 + 13) % 256) as u8).collect(),
        other => panic!("unknown corpus kind {other:?}"),
    }
}

/// Computes every vector: input bytes, then chunks as
/// `(offset, length, fingerprint)`.
fn vectors() -> Vec<Vector> {
    vector_specs()
        .into_iter()
        .map(|spec| {
            let VectorSpec {
                name,
                kind,
                seed,
                length,
                min_size,
                avg_size,
                max_size,
                level,
            } = spec;
            let data = build_input(kind, seed, length);
            let normalization = match level {
                0 => Normalization::Level0,
                1 => Normalization::Level1,
                2 => Normalization::Level2,
                3 => Normalization::Level3,
                other => panic!("unknown normalization level {other}"),
            };
            let chunks = FastCdc::with_level(&data, min_size, avg_size, max_size, normalization)
                .expect("corpus parameters must be valid")
                .map(|c| (c.offset, c.length, c.hash))
                .collect();
            Vector {
                name,
                kind,
                seed,
                length,
                min_size,
                avg_size,
                max_size,
                level,
                chunks,
            }
        })
        .collect()
}

/// Serializes the whole corpus as pretty-printed JSON, deterministically
/// (fixed order, fixed formatting, lowercase hex fingerprints).
fn render(vectors: &[Vector]) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str("  \"schema\": \"pith-cdc.reference.v1\",\n");
    out.push_str("  \"algorithm\": \"FastCDC (Xia et al., USENIX ATC 2016): Gear rolling fingerprint, zero-padded fp & mask == 0 judgment, normalized chunking\",\n");
    out.push_str("  \"vectors\": [\n");
    for (vi, v) in vectors.iter().enumerate() {
        out.push_str("    {\n");
        out.push_str(&format!("      \"name\": \"{}\",\n", v.name));
        out.push_str(&format!(
            "      \"input\": {{ \"kind\": \"{}\", \"seed_hex\": \"{:016x}\", \"length\": {} }},\n",
            v.kind, v.seed, v.length
        ));
        out.push_str(&format!(
            "      \"params\": {{ \"min_size\": {}, \"avg_size\": {}, \"max_size\": {}, \"level\": {} }},\n",
            v.min_size, v.avg_size, v.max_size, v.level
        ));
        out.push_str("      \"chunks\": [\n");
        for (ci, &(offset, length, hash)) in v.chunks.iter().enumerate() {
            let comma = if ci + 1 == v.chunks.len() { "" } else { "," };
            out.push_str(&format!(
                "        [{offset}, {length}, \"{hash:016x}\"]{comma}\n"
            ));
        }
        out.push_str("      ]\n");
        let comma = if vi + 1 == vectors.len() { "" } else { "," };
        out.push_str(&format!("    }}{comma}\n"));
    }
    out.push_str("  ]\n");
    out.push_str("}\n");
    out
}

/// Writes the canonical `tests/reference.json` and the root `reference.json`
/// copy the CD workflow ships with the SDK artifacts.
fn write_outputs(root: &Path, document: &str) -> std::io::Result<Vec<PathBuf>> {
    let tests_copy = root.join("tests").join("reference.json");
    let root_copy = root.join("reference.json");
    fs::create_dir_all(tests_copy.parent().expect("tests parent"))?;
    fs::write(&tests_copy, document)?;
    fs::write(&root_copy, document)?;
    Ok(vec![tests_copy, root_copy])
}

/// Recomputes every vector and byte-compares both committed copies.
fn verify_outputs(root: &Path, document: &str) -> Result<(), String> {
    let expected = document.as_bytes();
    for path in [
        root.join("tests").join("reference.json"),
        root.join("reference.json"),
    ] {
        let actual = fs::read(&path).map_err(|e| {
            format!(
                "{} is unreadable: {e}; run `gen-reference gen`",
                path.display()
            )
        })?;
        if actual != expected {
            return Err(format!(
                "{} is stale or hand-edited ({} bytes vs {} expected); \
                 run `gen-reference gen` and commit the result",
                path.display(),
                actual.len(),
                expected.len()
            ));
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let mode = args.next().unwrap_or_default();
    let root = PathBuf::from(args.next().unwrap_or_else(|| ".".into()));
    run(&mode, &root)
}

/// Runs one generator mode against `root`; separated from [`main`] so the
/// dispatch itself is unit-testable.
fn run(mode: &str, root: &Path) -> ExitCode {
    let vectors = vectors();
    let document = render(&vectors);
    let count = vectors.len();
    match mode {
        "gen" => match write_outputs(root, &document) {
            Ok(paths) => {
                for path in paths {
                    println!("wrote {} ({} bytes)", path.display(), document.len());
                }
                println!("{count} vectors");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("gen failed: {e}");
                ExitCode::FAILURE
            }
        },
        "verify" => match verify_outputs(root, &document) {
            Ok(()) => {
                println!(
                    "reference vectors are current: {count} vectors, {} bytes in both copies",
                    document.len()
                );
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("VERIFY FAILED: {e}");
                ExitCode::FAILURE
            }
        },
        other => {
            eprintln!("unknown mode {other:?}; usage: gen-reference <gen|verify> [repo-root]");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("pith-cdc-genref-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("temp root");
        dir
    }

    #[test]
    fn every_vector_tiles_its_input() {
        for v in vectors() {
            let mut end = 0usize;
            for &(offset, length, _) in &v.chunks {
                assert_eq!(offset, end, "vector {} is not contiguous", v.name);
                end += length;
            }
            assert_eq!(end, v.length, "vector {} does not tile its input", v.name);
        }
    }

    #[test]
    fn corpus_has_the_frozen_entry_count() {
        assert_eq!(vectors().len(), 11);
        let names: Vec<&str> = vectors().iter().map(|v| v.name).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(names.len(), sorted.len(), "corpus names must be unique");
    }

    #[test]
    fn pathological_fill_produces_max_length_chunks() {
        let zeros = vectors()
            .into_iter()
            .find(|v| v.name == "zeros-256kib-2k8k32k-l2")
            .expect("zeros vector");
        for &(offset, length, _) in zeros.chunks.iter().take(zeros.chunks.len() - 1) {
            assert_eq!(
                length, 32768,
                "all-zero data must fall back to max at {offset}"
            );
        }
        let fixed = vectors()
            .into_iter()
            .find(|v| v.name == "splitmix64-64kib-fixed2k-l2")
            .expect("fixed vector");
        assert!(fixed.chunks.iter().all(|&(_, length, _)| length == 2048));
    }

    #[test]
    fn sub_min_and_empty_inputs_have_degenerate_vectors() {
        let tiny = vectors()
            .into_iter()
            .find(|v| v.name == "splitmix64-1kib-submin-l2")
            .expect("tiny vector");
        assert_eq!(tiny.chunks, vec![(0, 1024, 0)]);
        let empty = vectors()
            .into_iter()
            .find(|v| v.name == "empty-2k8k32k-l2")
            .expect("empty vector");
        assert!(empty.chunks.is_empty());
    }

    #[test]
    fn render_is_deterministic_and_shaped_like_json() {
        let a = render(&vectors());
        let b = render(&vectors());
        assert_eq!(a, b);
        assert!(a.starts_with("{\n  \"schema\": \"pith-cdc.reference.v1\""));
        assert!(a.ends_with("}\n"));
    }

    #[test]
    fn write_then_verify_round_trips() {
        let root = temp_root("roundtrip");
        let document = render(&vectors());
        let paths = write_outputs(&root, &document).expect("write");
        assert_eq!(paths.len(), 2);
        verify_outputs(&root, &document).expect("freshly written copies must verify");
        fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn verify_rejects_tampered_and_missing_copies() {
        let root = temp_root("tamper");
        let document = render(&vectors());
        write_outputs(&root, &document).expect("write");

        let tests_copy = root.join("tests").join("reference.json");
        let mut tampered = document.clone();
        tampered.push(' ');
        fs::write(&tests_copy, tampered).expect("tamper");
        assert!(verify_outputs(&root, &document).is_err());

        fs::remove_file(&tests_copy).expect("remove");
        assert!(verify_outputs(&root, &document).is_err());
        fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn input_kinds_are_reproducible() {
        assert_eq!(build_input("zeros", 0, 300), vec![0u8; 300]);
        assert_eq!(build_input("fill-ff", 0, 300), vec![0xffu8; 300]);
        let saw = build_input("sawtooth", 0, 513);
        assert_eq!(saw[0], 13);
        assert_eq!(saw[1], 20);
        assert_eq!(saw[512], ((512 * 7 + 13) % 256) as u8);
        assert_eq!(
            build_input("splitmix64", 7, 256),
            build_input("splitmix64", 7, 256)
        );
        assert_ne!(
            build_input("splitmix64", 7, 256),
            build_input("splitmix64", 8, 256)
        );
    }

    #[test]
    #[should_panic(expected = "unknown corpus kind")]
    fn unknown_input_kind_panics() {
        build_input("fibonacci", 0, 8);
    }

    #[test]
    fn run_gen_then_verify_succeeds() {
        let root = temp_root("run-dispatch");
        assert_eq!(run("gen", &root), ExitCode::SUCCESS);
        assert_eq!(run("verify", &root), ExitCode::SUCCESS);
        fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn run_verify_fails_on_tampered_copy() {
        let root = temp_root("run-tamper");
        assert_eq!(run("gen", &root), ExitCode::SUCCESS);
        let tests_copy = root.join("tests").join("reference.json");
        let mut tampered = fs::read_to_string(&tests_copy).expect("read");
        tampered.replace_range(0..1, "0");
        tampered.insert(0, '9');
        fs::write(&tests_copy, tampered).expect("tamper");
        assert_eq!(run("verify", &root), ExitCode::FAILURE);
        fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn run_gen_fails_when_root_is_a_file() {
        let mut guard = std::env::temp_dir();
        guard.push(format!("pith-cdc-genref-file-{}", std::process::id()));
        let _ = fs::remove_file(&guard);
        fs::write(&guard, b"not a directory").expect("root file");
        assert_eq!(run("gen", &guard), ExitCode::FAILURE);
        fs::remove_file(&guard).expect("cleanup");
    }

    #[test]
    fn run_rejects_unknown_and_missing_modes() {
        let root = temp_root("run-badmode");
        assert_eq!(run("regenerate", &root), ExitCode::from(2));
        assert_eq!(run("", &root), ExitCode::from(2));
        fs::remove_dir_all(&root).expect("cleanup");
    }
}
