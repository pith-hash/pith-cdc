//! Lifecycle tests for the stateful public API the behavioural tests touch
//! only indirectly: the [`Gear`] wrapper, the [`Buzhash64`] window bookkeeping
//! accessors, and the validated-`Params` accessor on a running chunker.

use pith_cdc::{BUZHASH_WINDOW, Buzhash64, FastCdc, GEAR, Gear, Normalization};

#[test]
fn gear_wrapper_matches_the_manual_fold() {
    let mut gear = Gear::new();
    assert_eq!(gear.fingerprint(), 0, "empty window fingerprints to zero");

    let data: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
    let mut manual = 0u64;
    for (step, &byte) in data.iter().enumerate() {
        assert_eq!(
            gear.push(byte),
            manual.wrapping_shl(1).wrapping_add(GEAR[byte as usize]),
            "push return at step {step}"
        );
        manual = manual.wrapping_shl(1).wrapping_add(GEAR[byte as usize]);
        assert_eq!(gear.fingerprint(), manual, "fingerprint at step {step}");
    }

    gear.reset();
    assert_eq!(gear.fingerprint(), 0, "reset clears the fingerprint");
    assert_eq!(
        Gear::default().fingerprint(),
        0,
        "default is the empty window"
    );
}

#[test]
fn buzhash_window_bookkeeping_tracks_pushes() {
    let mut h = Buzhash64::new();
    assert!(h.is_empty());
    assert!(!h.is_full());
    assert_eq!(h.len(), 0);

    for step in 1..BUZHASH_WINDOW {
        h.push(step as u8);
        assert_eq!(h.len(), step);
        assert!(!h.is_empty());
        assert!(!h.is_full(), "window must not report full at {step}");
    }
    h.push(0xff);
    assert_eq!(h.len(), BUZHASH_WINDOW);
    assert!(h.is_full());

    // Once full the length saturates; pushes keep evicting instead.
    h.push(0x42);
    assert_eq!(h.len(), BUZHASH_WINDOW);
    assert!(h.is_full());
}

#[test]
fn buzhash_default_and_reset_return_to_the_empty_window() {
    let mut fresh = Buzhash64::default();
    assert!(fresh.is_empty());
    assert_eq!(fresh.fingerprint(), 0);

    fresh.update(b"deterministic window contents");
    let populated = fresh.fingerprint();
    assert_ne!(populated, 0);

    fresh.reset();
    assert!(fresh.is_empty());
    assert_eq!(fresh.fingerprint(), 0);
    fresh.update(b"deterministic window contents");
    let mut reference = Buzhash64::new();
    reference.update(b"deterministic window contents");
    assert_eq!(
        fresh.fingerprint(),
        reference.fingerprint(),
        "reset restarts identically"
    );
}

#[test]
fn chunker_params_accessor_reports_the_validated_configuration() {
    let data = [0u8; 4096];
    let chunker = FastCdc::new(&data, 2048, 8192, 32768).expect("valid parameters");
    let params = chunker.params();
    assert_eq!(params.min_size, 2048);
    assert_eq!(params.avg_size, 8192);
    assert_eq!(params.max_size, 32768);
    assert_eq!(
        params.level,
        Normalization::Level2,
        "new() defaults to level 2"
    );

    let leveled = FastCdc::with_level(&data, 64, 256, 1024, Normalization::Level3)
        .expect("valid parameters")
        .params();
    assert_eq!(leveled.min_size, 64);
    assert_eq!(leveled.avg_size, 256);
    assert_eq!(leveled.max_size, 1024);
    assert_eq!(leveled.level, Normalization::Level3);
}
