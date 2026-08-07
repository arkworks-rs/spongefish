//! A tiny, dependency-free timing harness.
//!
//! Deliberately *not* criterion: `spongefish` is a `no_std` cryptography crate
//! whose dependency set is gated by a `cargo deny` policy this harness must not
//! perturb, and criterion would add ~30 transitive dev-dependencies. What is
//! needed here is a stable, low-variance A/B number, which a warmed-up
//! median-of-batches loop provides.

use std::{
    hint::black_box,
    time::{Duration, Instant},
};

/// Time `f` and report nanoseconds per iteration.
///
/// `f` is called `batch` times per sample; the reported figure is the median
/// over `SAMPLES` samples, which rejects scheduler noise far better than a mean.
// The elapsed-nanosecond and batch counts are converted to `f64` only to print
// a per-iteration average. Both are far below 2^53 for any sample this harness
// takes (a sample is ~500us, and the batch is capped at 2^24), so the precision
// loss the lint warns about cannot reach the digits being reported.
#[allow(clippy::cast_precision_loss)]
pub fn bench<F: FnMut()>(name: &str, mut f: F) {
    const SAMPLES: usize = 41;
    const MIN_SAMPLE: Duration = Duration::from_micros(500);

    // Warm up, and simultaneously size the batch so one sample takes >= 500us.
    let mut batch = 1usize;
    loop {
        let start = Instant::now();
        for _ in 0..batch {
            f();
        }
        if start.elapsed() >= MIN_SAMPLE || batch >= 1 << 24 {
            break;
        }
        batch *= 2;
    }

    let mut samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let start = Instant::now();
        for _ in 0..batch {
            f();
        }
        samples.push(start.elapsed().as_nanos() as f64 / batch as f64);
    }
    samples.sort_by(f64::total_cmp);
    let median = samples[SAMPLES / 2];
    // Spread between the 25th and 75th percentile, as a sanity check that the
    // measurement is stable enough to compare across runs.
    let spread = (samples[SAMPLES * 3 / 4] - samples[SAMPLES / 4]) / median * 100.0;

    println!("{name:<52} {median:>12.2} ns/iter  (iqr {spread:>5.1}%)");
}

/// Keep a value alive across the optimizer.
pub fn sink<T>(value: T) {
    black_box(value);
}
