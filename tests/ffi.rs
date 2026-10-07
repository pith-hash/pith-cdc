//! C-ABI conformance: the `pith_cdc_chunk` / `pith_cdc_free` surface a
//! foreign caller binds (the Python, Node and Go SDKs).
//!
//! The in-crate unit tests in `src/ffi.rs` cover the branches; this test
//! calls the exported symbols the way the SDKs do — from a separate
//! crate, through the `extern "C"` boundary — and pins the committed
//! `reference.json` vector the SDK harnesses pin, so the C surface and
//! the corpus stay in lock-step on every commit.

use pith_cdc::ffi::{
    PITH_E_INVALID, PITH_E_REJECTED, PITH_LEVEL_2, PITH_OK, pith_cdc_chunk, pith_cdc_free,
};
use pith_digest::SplitMix64;

/// Runs the raw FFI over `bytes` and copies the flat
/// `(offset, length, hash)` triples out before releasing the buffer.
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
    assert_eq!(out_len % 24, 0, "the byte length is always triple-sized");
    let handed = unsafe { core::slice::from_raw_parts(out, out_len / 8) };
    let triples = handed.to_vec();
    unsafe { pith_cdc_free(out, out_len) };
    Ok(triples)
}

/// `reference.json` vector `splitmix64-1mib-2k8k32k-l2`, replayed
/// through the C ABI: 107 chunks tiling the 1 MiB input, the first
/// triple `(0, 2386, dead20b04c882e33)` and the last chunk pinned
/// exactly as the SDK harnesses pin them.
#[test]
fn ffi_matches_the_pinned_reference_vector() {
    let data = {
        let mut rng = SplitMix64::new(0x5eed_5eed_5eed_5eed);
        let mut out = vec![0u8; 1 << 20];
        rng.fill_bytes(&mut out);
        out
    };
    let triples = ffi_chunks(&data, 2048, 8192, 32768, PITH_LEVEL_2).expect("status");
    assert_eq!(triples.len() / 3, 107);
    assert_eq!(&triples[..3], &[0, 2386, 0xdead_20b0_4c88_2e33]);
    assert_eq!(&triples[triples.len() - 3..], &[1047070, 1506, 0]);
    let mut offset = 0u64;
    for triple in triples.chunks_exact(3) {
        assert_eq!(triple[0], offset, "chunks tile the input exactly");
        offset += triple[1];
    }
    assert_eq!(offset, data.len() as u64);
}

/// An empty source is a legal vector: `PITH_OK` with zero chunks —
/// handed in both as a real pointer and as the null pointer some SDKs
/// pass for an empty slice. Freeing a null pointer is a no-op.
#[test]
fn ffi_accepts_the_empty_input() {
    let empty = ffi_chunks(&[], 2048, 8192, 32768, PITH_LEVEL_2).expect("status");
    assert!(empty.is_empty());

    let mut out: *mut u64 = core::ptr::null_mut();
    let mut out_len: usize = 0;
    let status = unsafe {
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
    assert_eq!(status, PITH_OK);
    assert_eq!(out_len, 0);
    unsafe { pith_cdc_free(out, out_len) };
    unsafe { pith_cdc_free(core::ptr::null_mut(), 0) };
}

/// Every refusal path: statuses, never a crash. Null pointers and
/// unknown level codes are `PITH_E_INVALID`; parameter values the core
/// refuses are `PITH_E_REJECTED`.
#[test]
fn ffi_refuses_bad_arguments() {
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

    // Null out slots.
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

    // Unknown level wire code (the ABI defines 0..=3 only).
    assert_eq!(ffi_chunks(&data, 2048, 8192, 32768, 9), Err(PITH_E_INVALID));

    // Below-range min_size, avg < min, max < avg.
    for (min, avg, max) in [(32, 8192, 32768), (8192, 2048, 32768), (2048, 8192, 4096)] {
        assert_eq!(
            ffi_chunks(&data, min, avg, max, PITH_LEVEL_2),
            Err(PITH_E_REJECTED),
            "params {min}/{avg}/{max}"
        );
    }
}
