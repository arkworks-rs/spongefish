#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(target_endian = "big")]
compile_error!(
    r#"
This crate doesn't support big-endian targets.
"#
);

#[cfg(feature = "blake3")]
pub mod blake3;
#[cfg(feature = "keccak")]
pub mod keccak;
mod protocol;

pub use protocol::PowTranscriptExt;

/// Search a prepared proof-of-work strategy for its least accepted nonce.
///
/// Construction belongs to each strategy; the grinder only selects execution.
/// `grind` is always sequential, even with the `parallel` feature enabled.
///
/// ```
/// # #[cfg(feature = "blake3")]
/// # {
/// use spongefish_pow::{blake3::Blake3PoW, PoWGrinder};
/// let mut grinder = PoWGrinder::new(Blake3PoW::new([7; 32], 8));
/// let nonce = grinder.grind().unwrap();
/// assert!(grinder.verify(nonce));
/// # }
/// ```
pub struct PoWGrinder<S: PowStrategy> {
    strategy: S,
}

impl<S: PowStrategy> PoWGrinder<S> {
    /// Construct a grinder from a prepared strategy.
    pub const fn new(strategy: S) -> Self {
        Self { strategy }
    }

    /// Find the least accepted nonce sequentially, or `None` on exhaustion.
    pub fn grind(&mut self) -> Option<u64> {
        self.strategy.solve()
    }

    /// Find the same least nonce using owned strategy clones on Rayon workers.
    ///
    /// Only the strategy is transferred; no `Sync` bound is required. Clones
    /// are made on the calling thread before dispatch.
    #[cfg(feature = "parallel")]
    pub fn grind_parallel(&mut self) -> Option<u64>
    where
        S: Send,
    {
        self.strategy.solve_parallel()
    }

    /// Verify the nonce is in range and satisfies the prepared strategy.
    #[must_use = "unchecked proof of work verification"]
    pub fn verify(&mut self, nonce: u64) -> bool {
        nonce <= self.strategy.last_nonce() && self.strategy.check(nonce)
    }
}

/// Convenience functions accepting the same prepared strategies as [`PoWGrinder`].
pub mod convenience {
    use crate::{PoWGrinder, PowStrategy};

    /// Find the least accepted nonce sequentially.
    pub fn grind_pow(strategy: impl PowStrategy) -> Option<u64> {
        PoWGrinder::new(strategy).grind()
    }

    /// Check a nonce against a prepared strategy, including its range bound.
    #[must_use = "unchecked proof of work verification"]
    pub fn verify_pow(strategy: impl PowStrategy, nonce: u64) -> bool {
        PoWGrinder::new(strategy).verify(nonce)
    }
}

/// A prepared nonce predicate, independent of its seed or duplex sponge evaluator.
///
/// `check` and every clone must describe the same stable predicate. Mutable
/// hash scratch space is allowed, but acceptance must not depend on query order.
/// Override the search methods to provide optimized implementations, preserving
/// the least-nonce result and [`Self::last_nonce`] bound.
pub trait PowStrategy: Clone {
    /// Whether this nonce satisfies the prepared problem.
    #[must_use = "unchecked proof of work verification"]
    fn check(&mut self, nonce: u64) -> bool;

    /// The inclusive end of the nonce search space, starting at zero.
    fn last_nonce(&self) -> u64 {
        u64::MAX
    }

    /// Find the least accepted nonce sequentially, or `None` on exhaustion.
    fn solve(&mut self) -> Option<u64> {
        (0..=self.last_nonce()).find(|&nonce| self.check(nonce))
    }

    /// Find the same least nonce using independent owned clones.
    #[cfg(feature = "parallel")]
    fn solve_parallel(&mut self) -> Option<u64>
    where
        Self: Send,
    {
        search_parallel(self, 1, |strategy, nonce| {
            strategy.check(nonce).then_some(nonce)
        })
    }
}

// Each checker returns the least accepted nonce in a positive-width batch.
#[cfg(feature = "parallel")]
fn search_parallel<S, F>(strategy: &mut S, width: u64, check_batch: F) -> Option<u64>
where
    S: PowStrategy + Send,
    F: Fn(&mut S, u64) -> Option<u64> + Sync,
{
    use std::sync::atomic::{AtomicU64, Ordering};

    use rayon::prelude::*;

    let least = AtomicU64::new(u64::MAX);
    let jobs = rayon::current_num_threads();
    let limit = strategy.last_nonce();
    let strategies: Vec<_> = (0..jobs).map(|_| strategy.clone()).collect();
    strategies
        .into_par_iter()
        .enumerate()
        .for_each(|(index, mut strategy)| {
            // Batch indices avoid overflowing width * jobs or the starting nonce.
            for batch in (index as u64..=limit / width).step_by(jobs) {
                let start = batch * width;
                // MAX doubles as a sentinel and is checked after joining.
                if start >= least.load(Ordering::Relaxed) {
                    break;
                }
                if let Some(nonce) = check_batch(&mut strategy, start).filter(|&n| n <= limit) {
                    least.fetch_min(nonce, Ordering::Relaxed);
                    break;
                }
            }
        });
    let nonce = least.into_inner();
    if nonce != u64::MAX || (limit == u64::MAX && strategy.check(nonce)) {
        Some(nonce)
    } else {
        None
    }
}

// Inclusive target avoids representing 2^64 at zero difficulty.
#[cfg(any(feature = "blake3", feature = "keccak"))]
pub(crate) const fn difficulty_target(bits: u32) -> u64 {
    assert!(bits < 60, "bits must be smaller than 60");
    u64::MAX >> bits
}

#[cfg(test)]
mod tests {
    use super::{PoWGrinder, PowStrategy};

    #[derive(Clone)]
    struct Bounded {
        limit: u64,
        accepted: Option<u64>,
    }

    impl PowStrategy for Bounded {
        fn check(&mut self, nonce: u64) -> bool {
            self.accepted == Some(nonce)
        }

        fn last_nonce(&self) -> u64 {
            self.limit
        }
    }

    #[cfg(all(feature = "parallel", not(target_arch = "wasm32")))]
    #[test]
    fn parallel_batches_handle_large_widths_and_partial_tails() {
        for workers in [1, 3, 4] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(workers)
                .build()
                .unwrap();
            for (limit, width) in [(8, 4), (u64::MAX, u64::MAX - 1), (u64::MAX, u64::MAX)] {
                for accepted in [
                    None,
                    Some(0),
                    Some(3),
                    Some(4),
                    Some(7),
                    Some(8),
                    Some(9),
                    Some(u64::MAX - 1),
                    Some(u64::MAX),
                ] {
                    let mut strategy = Bounded { limit, accepted };
                    let result = pool.install(|| {
                        super::search_parallel(&mut strategy, width, |strategy, start| {
                            strategy
                                .accepted
                                .filter(|&n| n >= start && n - start < width)
                        })
                    });
                    assert_eq!(result, accepted.filter(|&nonce| nonce <= limit));
                }
            }
        }
    }

    #[test]
    fn sequential_strategy_needs_neither_send_nor_sync() {
        #[derive(Clone)]
        struct LocalOnly(std::rc::Rc<Bounded>);
        impl PowStrategy for LocalOnly {
            fn check(&mut self, nonce: u64) -> bool {
                self.0.accepted == Some(nonce)
            }
            fn last_nonce(&self) -> u64 {
                self.0.limit
            }
        }
        let problem = LocalOnly(std::rc::Rc::new(Bounded {
            limit: 8,
            accepted: Some(5),
        }));
        let mut grinder = PoWGrinder::new(problem);
        assert_eq!(grinder.grind(), Some(5));
        assert!(grinder.verify(5));
    }

    #[test]
    fn search_returns_the_least_of_multiple_hits() {
        #[derive(Clone)]
        struct Several {
            first: core::cell::Cell<u64>,
        }
        impl PowStrategy for Several {
            fn check(&mut self, nonce: u64) -> bool {
                let first = self.first.get();
                nonce >= first && (nonce - first).is_multiple_of(3)
            }
            fn last_nonce(&self) -> u64 {
                17
            }
        }
        for first in [0, 1, 2, 7, 17] {
            let mut grinder = PoWGrinder::new(Several {
                first: first.into(),
            });
            assert_eq!(grinder.grind(), Some(first));
            #[cfg(all(feature = "parallel", not(target_arch = "wasm32")))]
            for workers in [1, 3, 4] {
                let pool = rayon::ThreadPoolBuilder::new()
                    .num_threads(workers)
                    .build()
                    .unwrap();
                assert_eq!(pool.install(|| grinder.grind_parallel()), Some(first));
            }
        }
    }

    #[test]
    fn search_and_verification_respect_the_inclusive_nonce_limit() {
        for accepted in [None, Some(0), Some(1), Some(8), Some(9), Some(u64::MAX)] {
            let problem = Bounded { limit: 8, accepted };
            let expected = accepted.filter(|&nonce| nonce <= 8);
            let mut grinder = PoWGrinder::new(problem);
            assert_eq!(grinder.grind(), expected);
            assert!(!grinder.verify(9));
            assert!(!grinder.verify(u64::MAX));
            #[cfg(all(feature = "parallel", not(target_arch = "wasm32")))]
            for workers in [1, 3, 4] {
                let pool = rayon::ThreadPoolBuilder::new()
                    .num_threads(workers)
                    .build()
                    .unwrap();
                assert_eq!(pool.install(|| grinder.grind_parallel()), expected);
            }
        }
    }
}
