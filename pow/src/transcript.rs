//! Proof-of-work-protected verifier messages for [`spongefish`] transcripts.
//!
//! This module wires the standalone [`PoWGrinder`][crate::PoWGrinder] into the
//! Fiat--Shamir transcript through an extension trait, [`DecodingPow`],
//! implemented for both [`ProverState`] and [`VerifierState`].
//!
//! [`DecodingPow::verifier_message_pow`] parallels
//! [`ProverState::verifier_message`]/[`VerifierState::verifier_message`], but
//! inserts a grinding step before squeezing the returned challenge:
//!
//! 1. a fixed-length challenge is squeezed from the current transcript state;
//! 2. the prover grinds a nonce of the requested difficulty with a
//!    [`PowStrategy`] and commits it to the transcript;
//! 3. the verifier reads the nonce and rejects unless it satisfies the
//!    proof-of-work predicate;
//! 4. the verifier message of type `T` is squeezed from the (now nonce-bound)
//!    state and returned.
//!
//! Because a fresh challenge `T` is only produced after a valid nonce has been
//! absorbed, a cheating prover who wants to retry the challenge must redo the
//! grind for every attempt, which is exactly the soundness amplification a
//! Fiat--Shamir proof-of-work step buys.
//!
//! Proof-of-work is inherently byte-oriented, so the extension is available
//! only for byte sponges (`H::U = u8`).
//!
//! # Example
//!
//! ```
//! use spongefish::{Decoding, ProverState, VerifierState};
//! use spongefish_pow::{blake3::Blake3PoW, DecodingPow};
//!
//! let bits = 8.0;
//! let domain = spongefish::domain_separator!("examples"; "verifier_message_pow")
//!     .instance(&0u32);
//!
//! // Prover: grind and emit the challenge.
//! let mut prover: ProverState = domain.std_prover();
//! let challenge: u32 = prover.verifier_message_pow::<u32, Blake3PoW>(bits);
//! let proof = prover.narg_string().to_vec();
//!
//! // Verifier: re-derive the challenge, checking the proof-of-work.
//! let mut verifier: VerifierState = domain.std_verifier(&proof);
//! let replay: u32 = verifier
//!     .verifier_message_pow::<u32, Blake3PoW>(bits)
//!     .expect("valid proof-of-work");
//! assert_eq!(challenge, replay);
//! ```

use rand::{CryptoRng, RngCore};
use spongefish::{
    Decoding, DuplexSpongeInterface, ProverState, VerificationError, VerificationResult,
    VerifierState,
};

use crate::{PoWGrinder, PowStrategy};

/// Length in bytes of the challenge squeezed for the proof-of-work grind.
const POW_CHALLENGE_BYTES: usize = 32;

/// Extension trait adding a proof-of-work-protected verifier message to a
/// Fiat--Shamir transcript.
///
/// Implemented for [`ProverState`] (where the grind is performed and the
/// returned value is infallible) and [`VerifierState`] (where the nonce is
/// checked and the return type is a [`VerificationResult`]). The differing
/// return types are captured by the [`Output`][`DecodingPow::Output`]
/// associated type.
pub trait DecodingPow {
    /// The result of [`verifier_message_pow`][`DecodingPow::verifier_message_pow`].
    ///
    /// `T` for the prover (the grind never fails to produce a transcript) and
    /// [`VerificationResult<T>`] for the verifier (the nonce may be invalid).
    type Output<T>;

    /// Squeeze a verifier message `T`, gated behind a proof-of-work grind of
    /// difficulty `bits` (the binary logarithm of the expected work) using the
    /// [`PowStrategy`] `S`.
    fn verifier_message_pow<T, S>(&mut self, bits: f64) -> Self::Output<T>
    where
        T: Decoding<[u8]>,
        S: PowStrategy;
}

impl<H, R> DecodingPow for ProverState<H, R>
where
    H: DuplexSpongeInterface<U = u8>,
    R: RngCore + CryptoRng,
{
    type Output<T> = T;

    fn verifier_message_pow<T, S>(&mut self, bits: f64) -> T
    where
        T: Decoding<[u8]>,
        S: PowStrategy,
    {
        // 1. Derive the grinding challenge from the current transcript state.
        let challenge: [u8; POW_CHALLENGE_BYTES] = self.verifier_message();
        // 2. Grind a nonce meeting the requested difficulty.
        let solution = PoWGrinder::<S>::new(challenge, bits)
            .grind()
            .expect("proof-of-work grinding exhausted the nonce space (difficulty too high)");
        // 3. Commit the nonce to the transcript: absorbed into the sponge and
        //    written to the NARG string so the verifier can replay it.
        self.prover_message(&solution.nonce.to_le_bytes());
        // 4. Squeeze the verifier message that the grind protects.
        self.verifier_message()
    }
}

impl<H> DecodingPow for VerifierState<'_, H>
where
    H: DuplexSpongeInterface<U = u8>,
{
    type Output<T> = VerificationResult<T>;

    fn verifier_message_pow<T, S>(&mut self, bits: f64) -> VerificationResult<T>
    where
        T: Decoding<[u8]>,
        S: PowStrategy,
    {
        // 1. Re-derive the same grinding challenge.
        let challenge: [u8; POW_CHALLENGE_BYTES] = self.verifier_message();
        // 2. Read the prover's nonce (also absorbs it, matching the prover).
        let nonce = u64::from_le_bytes(self.prover_message::<[u8; 8]>()?);
        // 3. Reject unless the nonce satisfies the proof-of-work predicate.
        if !PoWGrinder::<S>::new(challenge, bits).verify(nonce) {
            return Err(VerificationError);
        }
        // 4. Squeeze the protected verifier message.
        Ok(self.verifier_message())
    }
}

#[cfg(all(test, feature = "blake3"))]
mod tests {
    use spongefish::{ProverState, VerifierState};

    use super::DecodingPow;
    use crate::blake3::Blake3PoW;

    const BITS: f64 = 8.0;

    fn prove() -> (u64, Vec<u8>) {
        let domain = spongefish::domain_separator!("pow tests"; "round trip").instance(&0u32);
        let mut prover: ProverState = domain.std_prover();
        let challenge: u64 = prover.verifier_message_pow::<u64, Blake3PoW>(BITS);
        (challenge, prover.narg_string().to_vec())
    }

    #[test]
    fn verifier_message_pow_round_trip() {
        let (challenge, proof) = prove();
        let domain = spongefish::domain_separator!("pow tests"; "round trip").instance(&0u32);
        let mut verifier: VerifierState = domain.std_verifier(&proof);
        let replay: u64 = verifier
            .verifier_message_pow::<u64, Blake3PoW>(BITS)
            .expect("valid proof-of-work");
        assert_eq!(challenge, replay);
        assert!(verifier.check_eof().is_ok());
    }

    #[test]
    fn tampered_nonce_is_rejected() {
        let (_challenge, mut proof) = prove();
        // The nonce is the only thing in the NARG string (8 LE bytes); corrupt it.
        for byte in &mut proof {
            *byte ^= 0xff;
        }
        let domain = spongefish::domain_separator!("pow tests"; "round trip").instance(&0u32);
        let mut verifier: VerifierState = domain.std_verifier(&proof);
        assert!(verifier
            .verifier_message_pow::<u64, Blake3PoW>(BITS)
            .is_err());
    }

    #[test]
    fn higher_difficulty_at_verification_is_rejected() {
        let (_challenge, proof) = prove();
        let domain = spongefish::domain_separator!("pow tests"; "round trip").instance(&0u32);
        let mut verifier: VerifierState = domain.std_verifier(&proof);
        // A nonce ground for `BITS` will (almost surely) not satisfy a strictly
        // harder predicate.
        assert!(verifier
            .verifier_message_pow::<u64, Blake3PoW>(BITS + 16.0)
            .is_err());
    }
}
