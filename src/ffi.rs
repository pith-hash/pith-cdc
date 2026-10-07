//! The C ABI surface of `pith-cdc`: the entry points the Python
//! (ctypes), Node (koffi) and Go (cgo) SDKs bind through.
//!
//! The suite's FFI convention, defined by this module and mirrored by
//! every `pith-*` cdylib:
//!
//! * one flat set of `#[unsafe(no_mangle)] pub unsafe extern "C"`
//!   functions — raw pointers plus lengths and scalars, no structs
//!   across the boundary;
//! * every function returns a status code (see the constants below),
//!   never a `Result`, never a panic: every input that could make the
//!   core panic is pre-validated here, and the core's own rejections
//!   come back as a status;
//! * [`pith_cdc_chunk`] allocates and hands ownership to the caller,
//!   released with [`pith_cdc_free`] by passing back the same byte
//!   length;
//! * the `unsafe` allowance is confined to this module; every core
//!   module stays unsafe-free behind the crate-root `#![deny]`.
//!
//! Normalization levels cross the boundary as their wire codes
//! [`PITH_LEVEL_0`]..[`PITH_LEVEL_3`] — the [`Normalization`] variant
//! numbers. Chunks are handed out as a flat `u64` buffer of
//! `(offset, length, hash)` triples: 24 bytes per chunk, so the
//! handed-out byte length is always a multiple of 24. An empty input
//! is a legal vector (the corpus commits one) and yields `PITH_OK`
//! with a zero-length buffer.

#![allow(unsafe_code)]

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::Chunk;
use crate::FastCdc;
use crate::masks::Normalization;

/// Status: success.
pub const PITH_OK: i32 = 0;
/// Status: a caller argument is invalid — a null pointer, or a
/// normalization-level code the ABI does not define.
pub const PITH_E_INVALID: i32 = -1;
/// Status: the core chunker refused the parameters (a
/// [`Params::validate`](crate::Params::validate) bound failed: a size
/// outside its range or a `min <= avg <= max` violation).
pub const PITH_E_REJECTED: i32 = -2;

/// Normalization-level wire code: level 0, no normalization (the
/// widest chunk-size spread).
pub const PITH_LEVEL_0: u32 = 0;
/// Normalization-level wire code: level 1.
pub const PITH_LEVEL_1: u32 = 1;
/// Normalization-level wire code: level 2, the paper's sweet spot and
/// the crate default.
pub const PITH_LEVEL_2: u32 = 2;
/// Normalization-level wire code: level 3, approaching fixed-size
/// chunking.
pub const PITH_LEVEL_3: u32 = 3;

/// Chunks `data` with FastCDC and hands the caller a flat buffer of
/// `(offset, length, hash)` triples.
///
/// `data` points at `len` bytes of the source (a null pointer with
/// `len == 0` is a legal empty input). `min_size`, `avg_size`,
/// `max_size` and `level` are the chunking parameters, `level` one of
/// the `PITH_LEVEL_*` wire codes. On success the function allocates a
/// buffer, writes its address through `out` and its byte length
/// through `out_len` (always a multiple of 24), and returns
/// [`PITH_OK`]; the caller owns the buffer and must release it with
/// [`pith_cdc_free`], passing back the same pointer *and* length.
///
/// Unknown level codes are [`PITH_E_INVALID`] (a caller bug — the ABI
/// defines only 0..=3); parameter values the core's validation refuses
/// are [`PITH_E_REJECTED`].
///
/// # Safety
///
/// `data` must point to `len` readable bytes; `out` to one writable
/// pointer; `out_len` to one writable `usize`. All must stay valid for
/// the duration of the call; the function retains nothing.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pith_cdc_chunk(
    data: *const u8,
    len: usize,
    min_size: usize,
    avg_size: usize,
    max_size: usize,
    level: u32,
    out: *mut *mut u64,
    out_len: *mut usize,
) -> i32 {
    if (data.is_null() && len != 0) || out.is_null() || out_len.is_null() {
        return PITH_E_INVALID;
    }
    // `from_raw_parts` demands a non-null, aligned data pointer even
    // for a zero-length slice, and some SDKs hand a null pointer for
    // an empty source — which is a legal vector here.
    let bytes: &[u8] = if len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(data, len) }
    };
    match chunk_triples(bytes, min_size, avg_size, max_size, level) {
        Ok(triples) => {
            let byte_len = triples.len() * core::mem::size_of::<u64>();
            // Hand the exact-length buffer to the caller; `pith_cdc_free`
            // reconstructs the boxed slice from the same byte length.
            let ptr = Box::into_raw(triples.into_boxed_slice());
            unsafe {
                *out = ptr.cast::<u64>();
                *out_len = byte_len;
            }
            PITH_OK
        }
        Err(status) => status,
    }
}

/// Releases a buffer handed out by [`pith_cdc_chunk`].
///
/// # Safety
///
/// `ptr` must be a pointer returned by [`pith_cdc_chunk`] with the
/// `out_len` value that came back with it, and must not have been
/// released (or otherwise freed) before. Null is accepted and ignored,
/// so callers can free unconditionally on the error path.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pith_cdc_free(ptr: *mut u64, len: usize) {
    if ptr.is_null() {
        return;
    }
    // The buffer is a boxed `[u64]` slice; the caller hands back the
    // byte length that came with it, so the element count is exact.
    let slice = unsafe { core::slice::from_raw_parts_mut(ptr, len / core::mem::size_of::<u64>()) };
    drop(unsafe { Box::from_raw(slice) });
}

/// The safe core of [`pith_cdc_chunk`]: validate the wire parameters,
/// chunk the input and flatten the chunks to `(offset, length, hash)`
/// triples.
///
/// An unknown level wire code is [`PITH_E_INVALID`] (the caller sent a
/// value the ABI does not define); a [`Params::validate`](crate::Params)
/// failure is [`PITH_E_REJECTED`] (well-formed wire values the core
/// refuses). Both checks return before any chunking runs, so no panic
/// — the mask-table indexing included — is reachable through this
/// boundary.
fn chunk_triples(
    bytes: &[u8],
    min_size: usize,
    avg_size: usize,
    max_size: usize,
    level: u32,
) -> Result<Vec<u64>, i32> {
    let normalization = match level {
        PITH_LEVEL_0 => Normalization::Level0,
        PITH_LEVEL_1 => Normalization::Level1,
        PITH_LEVEL_2 => Normalization::Level2,
        PITH_LEVEL_3 => Normalization::Level3,
        _ => return Err(PITH_E_INVALID),
    };
    let chunker = FastCdc::with_level(bytes, min_size, avg_size, max_size, normalization)
        .map_err(|_| PITH_E_REJECTED)?;
    // Validated `min_size` is at least 64, so this is a tight bound on
    // the chunk count (the last chunk may be short, hence the +1).
    let mut triples = Vec::with_capacity(3 * (bytes.len() / min_size + 1));
    for Chunk {
        hash,
        offset,
        length,
    } in chunker
    {
        triples.push(offset as u64);
        triples.push(length as u64);
        triples.push(hash);
    }
    Ok(triples)
}

#[cfg(test)]
mod tests {
    use super::{
        PITH_E_INVALID, PITH_E_REJECTED, PITH_LEVEL_0, PITH_LEVEL_1, PITH_LEVEL_2, PITH_LEVEL_3,
        PITH_OK, chunk_triples, pith_cdc_chunk, pith_cdc_free,
    };

    /// Regenerates the corpus's `splitmix64` input recipe
    /// (`tools/gen-reference`): little-endian words, last partial word
    /// = low bytes. An independent reimplementation, like the SDK
    /// harnesses — if it disagreed with `pith_digest::SplitMix64`, the
    /// pins below would fail loudly.
    fn splitmix64_bytes(seed: u64, length: usize) -> Vec<u8> {
        let mut state = seed;
        let mut next = move || {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        };
        let mut out = Vec::with_capacity(length);
        while out.len() < length {
            let word = next().to_le_bytes();
            let take = (length - out.len()).min(8);
            out.extend_from_slice(&word[..take]);
        }
        out
    }

    /// Runs the raw FFI over `bytes` and copies the flat triples out
    /// before releasing the handed-out buffer.
    fn ffi_chunks(
        bytes: &[u8],
        min: usize,
        avg: usize,
        max: usize,
        level: u32,
    ) -> Result<Vec<u64>, i32> {
        let mut out: *mut u64 = core::ptr::null_mut();
        let mut out_len: usize = 0;
        let status = unsafe {
            pith_cdc_chunk(
                bytes.as_ptr(),
                bytes.len(),
                min,
                avg,
                max,
                level,
                &mut out,
                &mut out_len,
            )
        };
        if status != PITH_OK {
            return Err(status);
        }
        let handed = unsafe { core::slice::from_raw_parts(out, out_len / 8) };
        let triples = handed.to_vec();
        assert_eq!(out_len, triples.len() * 8);
        assert_eq!(out_len % 24, 0, "the byte length is always triple-sized");
        unsafe { pith_cdc_free(out, out_len) };
        Ok(triples)
    }

    /// The pinned reference vectors, replayed through the raw FFI.
    ///
    /// The committed `reference.json` (byte-verified by
    /// `gen-reference verify` and `tests/reference.rs`) records for the
    /// `splitmix64-1mib-2k8k32k-l*` family — seed `5eed5eed5eed5eed`,
    /// 1 MiB, params 2048/8192/32768 — these chunk counts and first
    /// chunks. Levels 0–2 share the same first cut; level 3's strict
    /// mask pushes it further out. The level-2 pin is re-derived
    /// literally here so the FFI cannot drift from the corpus silently.
    #[test]
    fn ffi_reproduces_the_pinned_reference_vectors() {
        let data = splitmix64_bytes(0x5eed_5eed_5eed_5eed, 1 << 20);
        // (level wire code, committed chunk count, committed first chunk).
        let pinned: [(u32, usize, [u64; 3]); 4] = [
            (PITH_LEVEL_0, 107, [0, 2386, 0xdead_20b0_4c88_2e33]),
            (PITH_LEVEL_1, 109, [0, 2386, 0xdead_20b0_4c88_2e33]),
            (PITH_LEVEL_2, 107, [0, 2386, 0xdead_20b0_4c88_2e33]),
            (PITH_LEVEL_3, 115, [0, 10653, 0x10fd_a6bc_9c84_b4f0]),
        ];
        for (level, count, first) in pinned {
            let triples =
                ffi_chunks(&data, 2048, 8192, 32768, level).expect("pinned vector status");
            assert_eq!(triples.len() / 3, count, "level {level} chunk count");
            // Chunks tile the input exactly, in order.
            let mut expected_offset = 0u64;
            for triple in triples.chunks_exact(3) {
                assert_eq!(triple[0], expected_offset, "level {level} tiling");
                expected_offset += triple[1];
            }
            assert_eq!(expected_offset, data.len() as u64);
            assert_eq!(&triples[..3], &first, "level {level} first chunk");
        }
        // The level-2 last chunk, pinned exactly as the corpus and the
        // three SDK harnesses pin it.
        let l2 = ffi_chunks(&data, 2048, 8192, 32768, PITH_LEVEL_2).expect("status");
        assert_eq!(&l2[l2.len() - 3..], &[1047070, 1506, 0x0000_0000_0000_0000]);
    }

    /// Sub-minimum input: shorter than `min_size`, so the whole input
    /// is one chunk with a zero fingerprint (no byte is ever judged).
    #[test]
    fn ffi_reproduces_the_subminimum_vector() {
        let data = splitmix64_bytes(9, 1024);
        let triples = ffi_chunks(&data, 2048, 8192, 32768, PITH_LEVEL_2).expect("status");
        assert_eq!(&triples[..], &[0, 1024, 0]);
    }

    /// The degenerate all-zeros corpus entry: the judgment never fires
    /// on the constant input, so the scanner falls back to `max_size`
    /// chunks (8 × 32 KiB for 256 KiB).
    #[test]
    fn ffi_reproduces_the_zeros_vector() {
        let data = vec![0u8; 256 * 1024];
        let triples = ffi_chunks(&data, 2048, 8192, 32768, PITH_LEVEL_2).expect("status");
        assert_eq!(triples.len() / 3, 8);
        for triple in triples.chunks_exact(3) {
            assert_eq!(triple[1], 32768);
        }
    }

    /// Null pointers and unknown level codes are
    /// [`PITH_E_INVALID`]; parameter values the core refuses are
    /// [`PITH_E_REJECTED`]; none of it panics. A null data pointer
    /// with a zero length stays legal.
    #[test]
    fn ffi_refusals() {
        let data = [7u8; 4096];
        let mut out: *mut u64 = core::ptr::null_mut();
        let mut out_len: usize = 0;

        // Null data with a non-zero length.
        let null_data = unsafe {
            pith_cdc_chunk(
                core::ptr::null(),
                16,
                2048,
                8192,
                32768,
                PITH_LEVEL_2,
                &mut out,
                &mut out_len,
            )
        };
        assert_eq!(null_data, PITH_E_INVALID);

        // Null out / out_len slots.
        let null_out = unsafe {
            pith_cdc_chunk(
                data.as_ptr(),
                data.len(),
                2048,
                8192,
                32768,
                PITH_LEVEL_2,
                core::ptr::null_mut(),
                &mut out_len,
            )
        };
        assert_eq!(null_out, PITH_E_INVALID);
        let null_out_len = unsafe {
            pith_cdc_chunk(
                data.as_ptr(),
                data.len(),
                2048,
                8192,
                32768,
                PITH_LEVEL_2,
                &mut out,
                core::ptr::null_mut(),
            )
        };
        assert_eq!(null_out_len, PITH_E_INVALID);

        // Unknown level wire code.
        let unknown_level = unsafe {
            pith_cdc_chunk(
                data.as_ptr(),
                data.len(),
                2048,
                8192,
                32768,
                9,
                &mut out,
                &mut out_len,
            )
        };
        assert_eq!(unknown_level, PITH_E_INVALID);

        // A null data pointer with a zero length is a legal empty input.
        let empty_ok = unsafe {
            pith_cdc_chunk(
                core::ptr::null(),
                0,
                2048,
                8192,
                32768,
                PITH_LEVEL_2,
                &mut out,
                &mut out_len,
            )
        };
        assert_eq!(empty_ok, PITH_OK);
        assert_eq!(out_len, 0);
        unsafe { pith_cdc_free(out, out_len) };

        // Validation refusals: below-range min, avg < min, below-range
        // avg, below-range max, avg > max — all PITH_E_REJECTED.
        for (min, avg, max) in [
            (32, 8192, 32768),   // min below 64
            (8192, 2048, 32768), // avg < min
            (2048, 128, 32768),  // avg below 256
            (2048, 8192, 512),   // max below 1 KiB
            (2048, 8192, 4096),  // max < avg
        ] {
            let refused = unsafe {
                pith_cdc_chunk(
                    data.as_ptr(),
                    data.len(),
                    min,
                    avg,
                    max,
                    PITH_LEVEL_2,
                    &mut out,
                    &mut out_len,
                )
            };
            assert_eq!(refused, PITH_E_REJECTED, "params {min}/{avg}/{max}");
        }

        // The same refusals, observed through the test helper's error
        // path (the FFI status surfaces as Err instead of a panic).
        assert_eq!(
            ffi_chunks(&data, 32, 8192, 32768, PITH_LEVEL_2),
            Err(PITH_E_REJECTED)
        );
        assert_eq!(ffi_chunks(&data, 2048, 8192, 32768, 9), Err(PITH_E_INVALID));

        // Freeing a null pointer is a no-op.
        unsafe { pith_cdc_free(core::ptr::null_mut(), 0) };
    }

    /// The safe core agrees with the raw FFI and carries the same
    /// refusal statuses.
    #[test]
    fn safe_core_matches_ffi() {
        let data = splitmix64_bytes(0x0123_4567_89ab_cdef, 64 * 1024);
        let via_core =
            chunk_triples(&data, 2048, 2048, 2048, PITH_LEVEL_2).expect("fixed-size vector");
        let via_ffi = ffi_chunks(&data, 2048, 2048, 2048, PITH_LEVEL_2).expect("status");
        assert_eq!(via_core, via_ffi);
        // 64 KiB at a fixed 2048: exactly 32 chunks of 2048 (the fixed
        // `max_size` pins every length).
        assert_eq!(via_core.len() / 3, 32);
        for triple in via_core.chunks_exact(3) {
            assert_eq!(triple[1], 2048);
        }
        assert_eq!(
            chunk_triples(&data, 32, 8192, 32768, PITH_LEVEL_2),
            Err(PITH_E_REJECTED)
        );
        assert_eq!(
            chunk_triples(&data, 2048, 8192, 32768, 9),
            Err(PITH_E_INVALID)
        );
    }
}
