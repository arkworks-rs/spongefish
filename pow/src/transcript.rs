//! Verifier messages with grinding.

use spongefish::{
    DuplexSpongeInit, DuplexSpongeInterface, Encoding, FromNarg, FromUniform, ProverState,
    Transcript, VerificationError, Witness,
};

/// The configuration for a proof of work.
///
/// A [`PowStrategy`] contains the parameters for the proof of work.
/// Parameters and acceptance must remain equivalent across calls and clones.
///
/// # Security
///
/// When work is requested, the grinding is expected to amplify soundness for
/// the **current round**. In particular, trait implementors must be wary of preprocessing
/// attacks that might occur when seeding the PoW with a fixed seed, or creating inadvertly
/// a new round.
///
/// Failed nonce checks must use [`Transcript::check`] to permanently reject the
/// verifier.
///
/// The difficulty, placement and solution codec must be
/// fixed by the protocol and properly accounted for in the session identifier.
///
/// The helper absorbs the nonce before deriving `challenge_len()` verifier bytes.
pub trait PowStrategy: Clone {
    /// The canonical, self-delimiting nonce codec. Integers use fixed-width encoding.
    ///
    /// Conversion to and from `u64` must round-trip every permitted nonce.
    type Nonce: From<u64> + Into<u64> + Encoding + FromNarg;

    /// Whether to exchange a nonce and derive check bytes.
    ///
    /// Returning `false` skips all work and immediately derives the protected message.
    fn enabled(&self) -> bool {
        true
    }

    /// The inclusive nonce bound, starting at zero.
    fn last_nonce(&self) -> u64 {
        u64::MAX
    }

    /// Number of verifier bytes derived after each candidate nonce.
    ///
    /// This must be positive when work is enabled and fixed by the protocol.
    fn challenge_len(&self) -> usize;

    /// Test the nonce and its verifier bytes without changing the puzzle.
    /// Acceptance must not depend on evaluation order.
    /// `challenge` must contain exactly [`Self::challenge_len`] bytes.
    ///
    /// For seeded PoW these bytes are the seed, derived anew for every nonce.
    /// This predicate must enforce the protocol's difficulty; it cannot establish
    /// a soundness claim by itself.
    fn accepts(&self, nonce: u64, challenge: &[u8]) -> bool;

    /// Return the least accepted nonce in `0..=last_nonce()`, or `None` on exhaustion.
    ///
    /// Synchronous and potentially blocking. Implementations must not panic for
    /// valid strategy parameters and a non-panicking evaluator.
    /// `evaluate` must fill its output with verifier bytes after the encoded nonce;
    /// calls and clones must agree. It must not advance the live transcript.
    fn solve<E: Fn(&[u8], &mut [u8]) + Clone>(self, evaluate: E) -> Option<u64> {
        let mut challenge = vec![0; self.challenge_len()];
        (0..=self.last_nonce()).find(|&nonce| {
            evaluate(Self::Nonce::from(nonce).encode().as_ref(), &mut challenge);
            self.accepts(nonce, &challenge)
        })
    }

    /// Return the same least nonce as [`Self::solve`], or `None` on exhaustion.
    ///
    /// Synchronous and potentially blocking.
    /// Default implementations use Rayon with `parallel`
    /// and otherwise calls [`Self::solve`].
    /// Parallelism may reduce elapsed time but can evaluate extra candidates;
    /// speedup is not guaranteed.
    /// Only strategy and evaluator state require `Send`, without `Sync`.
    /// Overrides must not panic for valid parameters and a non-panicking evaluator.
    /// Callback panics propagate; Rayon may panic if pool initialization fails.
    fn solve_parallel<E>(self, evaluate: E) -> Option<u64>
    where
        Self: Send,
        E: Fn(&[u8], &mut [u8]) + Clone + Send,
    {
        #[cfg(feature = "parallel")]
        {
            let challenge = vec![0; self.challenge_len()];
            let nonces = 0..=self.last_nonce();
            search_parallel(
                (self, evaluate, challenge),
                nonces,
                |(config, evaluate, challenge), nonce| {
                    evaluate(Self::Nonce::from(nonce).encode().as_ref(), challenge);
                    config.accepts(nonce, challenge)
                },
            )
        }
        #[cfg(not(feature = "parallel"))]
        {
            self.solve(evaluate)
        }
    }
}

/// Obtain verifier messages protected by a configured proof-of-work protocol.
///
/// Available both inside generic [`Argument::run`](spongefish::Argument::run)
/// implementations and directly on prover and verifier states. The helper owns
/// nonce exchange, binding and verification; callers never supply a seed.
///
/// ```
/// use spongefish::{Transcript, VerificationError};
/// use spongefish_pow::{PowStrategy, PowTranscriptExt};
///
/// fn round<T: Transcript>(
///     transcript: &mut T,
///     config: impl PowStrategy,
/// ) -> Result<u64, VerificationError> {
///     transcript.verifier_message_pow(config)
/// }
/// ```
pub trait PowTranscriptExt: Transcript {
    /// Search sequentially, exchange the nonce, check it and return the protected message.
    fn verifier_message_pow<T: FromUniform>(
        &mut self,
        config: impl PowStrategy,
    ) -> Result<T, VerificationError> {
        if config.enabled() && config.challenge_len() == 0 {
            self.check(|| false)?;
            return Err(VerificationError);
        }
        let nonce = if config.enabled() {
            self.prover_only(|| {
                let evaluate = self
                    .verifier_message_oracle()
                    .into_known()
                    .ok_or(VerificationError)?;
                config.clone().solve(evaluate).ok_or(VerificationError)
            })
            .transpose()?
        } else {
            Witness::unknown()
        };
        finish(self, &config, nonce)
    }
}

impl<T: Transcript + ?Sized> PowTranscriptExt for T {}

/// Search in parallel on a concrete prover and return the protected verifier message.
///
/// Uses the same nonce exchange, check and protected message as
/// [`PowTranscriptExt::verifier_message_pow`]. The verifier uses that ordinary
/// helper and never searches.
///
/// Only the public sponge and configuration need `Send`; the live prover and
/// private RNG stay on the calling thread and need neither `Send` nor `Sync`.
/// This function is synchronous and may block. It is available without Rayon:
/// the default solver falls back to sequential search unless `parallel` is enabled.
/// Configurations may override [`PowStrategy::solve_parallel`] for another backend.
pub fn verifier_message_pow_parallel<T: FromUniform>(
    prover: &mut ProverState<
        impl DuplexSpongeInterface<U = u8> + Send,
        impl DuplexSpongeInit<U = u8>,
    >,
    config: impl PowStrategy + Send,
) -> Result<T, VerificationError> {
    if !config.enabled() {
        return finish(prover, &config, Witness::unknown());
    }
    if config.challenge_len() == 0 {
        prover.check(|| false)?;
        return Err(VerificationError);
    }
    let replay = config.clone();
    let nonce = config
        .solve_parallel(prover.verifier_message_oracle())
        .ok_or(VerificationError)?;
    finish(prover, &replay, Witness::known(nonce))
}

fn finish<T: FromUniform, C: PowStrategy>(
    transcript: &mut (impl Transcript + ?Sized),
    config: &C,
    nonce: Witness<u64>,
) -> Result<T, VerificationError> {
    if config.enabled() {
        let value: u64 = transcript.prover_message(nonce.map(C::Nonce::from))?.into();
        let in_range = value <= config.last_nonce();
        if nonce.map(|_| in_range).into_known() == Some(false) {
            return Err(VerificationError);
        }
        transcript.check(|| in_range)?;
        let challenge: Vec<u8> = (0..config.challenge_len())
            .map(|_| transcript.verifier_message())
            .collect();
        let accepted = config.accepts(value, &challenge);
        // ProverState::check may skip predicates in release builds. Reject a
        // disagreement between snapshot search and live replay in either build.
        if nonce.map(|_| accepted).into_known() == Some(false) {
            return Err(VerificationError);
        }
        transcript.check(|| accepted)?;
    } else {
        transcript.check(|| true)?;
    }
    Ok(transcript.verifier_message())
}

// Search an ordered range with independent owned state per Rayon job.
#[cfg(feature = "parallel")]
fn search_parallel<S: Clone + Send>(
    state: S,
    nonces: core::ops::RangeInclusive<u64>,
    check: fn(&mut S, u64) -> bool,
) -> Option<u64> {
    use rayon::prelude::*;

    nonces
        .into_par_iter()
        .map_with(state, |state, nonce| check(state, nonce).then_some(nonce))
        .find_first(Option::is_some)
        .flatten()
}

#[cfg(test)]
mod tests {
    use spongefish::{
        instantiations::TurboShake128, DuplexSpongeInit, DuplexSpongeInterface, Narg, ProverState,
        VerifierState,
    };

    use super::{verifier_message_pow_parallel, PowStrategy, PowTranscriptExt};

    // A small seeded puzzle for testing the shared driver, not a shipped construction.
    #[derive(Clone)]
    struct Seeded(bool);

    fn hash_accepts(seed: &[u8], nonce: u64) -> bool {
        let mut hash = TurboShake128::init(&[19; 32]);
        hash.absorb(seed).absorb(&nonce.to_le_bytes());
        let mut result = [0; 1];
        hash.squeeze(&mut result);
        result[0].trailing_zeros() >= 3
    }

    impl PowStrategy for Seeded {
        type Nonce = u64;

        fn enabled(&self) -> bool {
            self.0
        }
        fn last_nonce(&self) -> u64 {
            511
        }
        fn challenge_len(&self) -> usize {
            32
        }
        fn accepts(&self, nonce: u64, seed: &[u8]) -> bool {
            hash_accepts(seed, nonce)
        }
    }

    #[test]
    fn seeded_round_binds_each_counter_before_its_seed_and_checks_before_challenge() {
        let session = Narg::derive_session_id(b"pow/nonce-first-seeded/v1");
        for enabled in [false, true] {
            let mut before = TurboShake128::init(session.as_bytes());
            before.absorb(&0u32.to_le_bytes()).absorb(&[42]);
            let candidate = |nonce: u64| {
                let mut after = before.clone();
                after.absorb(&nonce.to_le_bytes());
                let mut seed = [0; 32];
                after.squeeze(&mut seed);
                (hash_accepts(&seed, nonce), after)
            };
            let (proof, mut after) = if enabled {
                (0..=511)
                    .find_map(|nonce| {
                        let (accepted, after) = candidate(nonce);
                        accepted.then_some((nonce.to_le_bytes().to_vec(), after))
                    })
                    .unwrap()
            } else {
                (vec![], before.clone())
            };
            let challenge = u64::from_le_bytes(after.squeeze_array());
            let following = u64::from_le_bytes(after.squeeze_array());
            for parallel in [false, true] {
                let mut prover =
                    ProverState::<TurboShake128>::new_with_seed(&session, &0u32, [7; 32]);
                prover.public_message(&42u8);
                let result = if parallel {
                    verifier_message_pow_parallel::<u64>(&mut prover, Seeded(enabled))
                } else {
                    prover.verifier_message_pow::<u64>(Seeded(enabled))
                };
                assert_eq!(result.unwrap(), challenge);
                assert_eq!(prover.verifier_message::<u64>(), following);
                assert_eq!(prover.into_narg_string(), proof);
                let mut verifier = VerifierState::<TurboShake128>::new(&session, &0u32, &proof);
                verifier.public_message(&42u8);
                let result = verifier.verifier_message_pow::<u64>(Seeded(enabled));
                assert_eq!(result.unwrap(), challenge);
                assert_eq!(verifier.verifier_message::<u64>(), following);
                verifier.check_eof().unwrap();
            }
            if enabled {
                let bad = (0..=511).find(|&n| !candidate(n).0).unwrap().to_le_bytes();
                let out_of_range = 512u64.to_le_bytes();
                for proof in [&bad[..], &out_of_range[..], &bad[..7]] {
                    let mut verifier = VerifierState::<TurboShake128>::new(&session, &0u32, proof);
                    verifier.public_message(&42u8);
                    assert!(verifier.verifier_message_pow::<u64>(Seeded(true)).is_err());
                    assert!(verifier.verifier_message_pow::<u64>(Seeded(false)).is_err());
                    assert!(verifier.check_eof().is_err());
                }
            }
        }
    }

    #[derive(Clone)]
    struct Problem {
        limit: u64,
        accepted: &'static [u64],
    }

    impl PowStrategy for Problem {
        type Nonce = u64;

        fn challenge_len(&self) -> usize {
            1
        }

        fn accepts(&self, nonce: u64, _challenge: &[u8]) -> bool {
            self.accepted.contains(&nonce)
        }

        fn last_nonce(&self) -> u64 {
            self.limit
        }
    }

    fn evaluate(_candidate: &[u8], output: &mut [u8]) {
        output.fill(0);
    }

    #[test]
    fn search_respects_nonce_order_and_bounds() {
        const CASES: &[(u64, &[u64])] = &[
            (0, &[]),
            (0, &[0]),
            (0, &[1]),
            (8, &[]),
            (8, &[0, 4, 8]),
            (8, &[7, 1, 4]),
            (8, &[8]),
            (8, &[9, u64::MAX]),
        ];
        for &(limit, accepted) in CASES {
            let problem = Problem { limit, accepted };
            let expected = accepted.iter().copied().filter(|&n| n <= limit).min();
            assert_eq!(problem.clone().solve(evaluate), expected);
            #[cfg(not(feature = "parallel"))]
            assert_eq!(problem.clone().solve_parallel(evaluate), expected);
            #[cfg(all(feature = "parallel", not(target_arch = "wasm32")))]
            for workers in [1, 3, 4] {
                let pool = rayon::ThreadPoolBuilder::new()
                    .num_threads(workers)
                    .build()
                    .unwrap();
                assert_eq!(
                    pool.install(|| problem.clone().solve_parallel(evaluate)),
                    expected
                );
            }
        }
    }

    #[cfg(all(feature = "parallel", not(target_arch = "wasm32")))]
    #[test]
    fn parallel_search_handles_empty_ranges_and_u64_max() {
        const HITS: &[&[u64]] = &[
            &[],
            &[0],
            &[8],
            &[9],
            &[u64::MAX - 8],
            &[u64::MAX - 1, u64::MAX],
            &[u64::MAX],
        ];
        for workers in [1, 3, 4] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(workers)
                .build()
                .unwrap();
            for nonces in [
                0..=8,
                u64::MAX - 8..=u64::MAX,
                core::ops::RangeInclusive::new(1, 0),
            ] {
                for &accepted in HITS {
                    let problem = Problem {
                        limit: *nonces.end(),
                        accepted,
                    };
                    let expected = accepted
                        .iter()
                        .copied()
                        .filter(|n| nonces.contains(n))
                        .min();
                    assert_eq!(
                        pool.install(|| super::search_parallel(
                            problem,
                            nonces.clone(),
                            |problem, nonce| problem.accepts(nonce, &[0])
                        )),
                        expected
                    );
                }
            }
        }
    }
}
