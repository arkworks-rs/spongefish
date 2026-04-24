//! Sponge-backed `ProverChannel` / `VerifierChannel` adapters.

extern crate alloc;

use alloc::vec::Vec;

use ia_core::{Deserialize, ProverChannel, VerifierChannel};
use crate::{
    Decoding, DomainSeparator, DuplexSpongeInterface, Encoding, NargDeserialize, NargSerialize,
    ProverState, StdHash, VerificationResult, VerifierState,
};

use super::params::{Keccak, SpongeInfo};

/// Construct spongefish prover/verifier states from the same public inputs that define the
/// Fiat–Shamir transcript (protocol id, session id, instance bytes).
///
/// For SHAKE128 (`StdHash`) we use spongefish `std_prover` / `std_verifier`: the 64-byte tag from
/// [`DomainSeparator::derive`] is passed to `StdHash::from_protocol_id`, then the instance is absorbed.
///
/// For Keccak duplex, we use [`DomainSeparator::to_prover`] / [`DomainSeparator::to_verifier`]:
/// the same derived tag and instance are absorbed as `public_message`s.
pub trait TranscriptSponge: DuplexSpongeInterface<U = u8> + Sized {
    fn prover_state<I: Encoding>(
        self,
        protocol_id: [u8; 64],
        session: [u8; 64],
        instance: &I,
    ) -> ProverState<Self>;

    fn verifier_state<'a, I: Encoding>(
        self,
        protocol_id: [u8; 64],
        session: [u8; 64],
        instance: &I,
        narg_string: &'a [u8],
    ) -> VerifierState<'a, Self>;
}

impl TranscriptSponge for Keccak {
    fn prover_state<I: Encoding>(
        self,
        protocol_id: [u8; 64],
        session: [u8; 64],
        instance: &I,
    ) -> ProverState<Self> {
        let domsep = DomainSeparator::derive(
            protocol_id.as_ref(),
            Keccak::SPONGE_INFO,
            session.as_ref(),
        )
        .instance(instance);
        domsep.to_prover(self)
    }

    fn verifier_state<'a, I: Encoding>(
        self,
        protocol_id: [u8; 64],
        session: [u8; 64],
        instance: &I,
        narg_string: &'a [u8],
    ) -> VerifierState<'a, Self> {
        let domsep = DomainSeparator::derive(
            protocol_id.as_ref(),
            Keccak::SPONGE_INFO,
            session.as_ref(),
        )
        .instance(instance);
        domsep.to_verifier(self, narg_string)
    }
}

impl TranscriptSponge for StdHash {
    fn prover_state<I: Encoding>(
        self,
        protocol_id: [u8; 64],
        session: [u8; 64],
        instance: &I,
    ) -> ProverState<Self> {
        // IMPORTANT: ignore `self` and use spongefish `std_prover` initialization semantics.
        let domsep = DomainSeparator::derive(
            protocol_id.as_ref(),
            <StdHash as SpongeInfo>::SPONGE_INFO,
            session.as_ref(),
        )
        .instance(instance);
        domsep.std_prover()
    }

    fn verifier_state<'a, I: Encoding>(
        self,
        protocol_id: [u8; 64],
        session: [u8; 64],
        instance: &I,
        narg_string: &'a [u8],
    ) -> VerifierState<'a, Self> {
        // IMPORTANT: ignore `self` and use spongefish `std_verifier` initialization semantics.
        let domsep = DomainSeparator::derive(
            protocol_id.as_ref(),
            <StdHash as SpongeInfo>::SPONGE_INFO,
            session.as_ref(),
        )
        .instance(instance);
        domsep.std_verifier(narg_string)
    }
}

/// Wraps `spongefish::ProverState` as an ia-core `ProverChannel`.
///
/// Generic over the duplex sponge `H` used for the Fiat–Shamir transcript.
/// Defaults to [`Keccak`] (Argus standard); use [`crate::params::StdHash`] for
/// compatibility with spongefish `std_prover` / `std_verifier` (SHAKE128 XOF).
pub struct SpongeProver<H: DuplexSpongeInterface = Keccak> {
    pub state: ProverState<H>,
}

impl<H: DuplexSpongeInterface> SpongeProver<H> {
    pub fn new(state: ProverState<H>) -> Self {
        Self { state }
    }

    pub fn narg_string(&self) -> &[u8] {
        self.state.narg_string()
    }

    /// Absorb a **public** message into the transcript (Fiat–Shamir) without appending to the NARG string.
    ///
    /// Matches spongefish `ProverState::public_message` (e.g. σ-proofs batchable commitments).
    pub fn public_message<T: Encoding<[H::U]> + ?Sized>(&mut self, msg: &T) {
        self.state.public_message(msg);
    }

    /// Squeeze a verifier challenge from the duplex sponge.
    pub fn verifier_message<VM: Decoding<[H::U]>>(&mut self) -> VM {
        self.state.verifier_message()
    }
}

impl<H: DuplexSpongeInterface> ProverChannel<H::U> for SpongeProver<H> {
    fn send_prover_message<PM: Encoding<[H::U]> + NargSerialize>(&mut self, msg: &PM) {
        self.state.prover_message(msg);
    }

    fn read_verifier_message<VM: Decoding<[H::U]>>(&mut self) -> VM {
        self.state.verifier_message()
    }
}

/// Wraps `spongefish::VerifierState` as an ia-core `VerifierChannel`.
pub struct SpongeVerifier<'a, H: DuplexSpongeInterface = Keccak> {
    pub state: VerifierState<'a, H>,
}

impl<'a, H: DuplexSpongeInterface> SpongeVerifier<'a, H> {
    pub fn new(state: VerifierState<'a, H>) -> Self {
        Self { state }
    }

    /// Absorb a public message without consuming the NARG cursor.
    pub fn public_message<T: Encoding<[H::U]> + ?Sized>(&mut self, msg: &T) {
        self.state.public_message(msg);
    }

    /// Read an ordered list of prover messages from the NARG string and absorb each one.
    pub fn prover_messages_vec<T: Encoding<[H::U]> + NargDeserialize>(
        &mut self,
        len: usize,
    ) -> VerificationResult<Vec<T>> {
        self.state.prover_messages_vec(len)
    }

    /// Squeeze a verifier challenge.
    pub fn verifier_message<VM: Decoding<[H::U]>>(&mut self) -> VM {
        self.state.verifier_message()
    }

    pub fn check_eof(self) -> VerificationResult<()> {
        self.state.check_eof()
    }
}

impl<'a, H: DuplexSpongeInterface> VerifierChannel<H::U> for SpongeVerifier<'a, H> {
    fn read_prover_message<PM: Encoding<[H::U]> + Deserialize>(
        &mut self,
    ) -> ia_core::VerificationResult<PM> {
        self.state
            .prover_message()
            .map_err(|_| ia_core::VerificationError)
    }

    fn send_verifier_message<VM: Decoding<[H::U]>>(&mut self) -> VM {
        self.state.verifier_message()
    }
}
