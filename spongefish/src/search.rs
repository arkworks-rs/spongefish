//! Prover-side search over candidate prover messages.

use crate::DuplexSpongeInterface;

/// Evaluate the transcript on a candidate prover message without sending it.
///
/// A probe answers one question: "if the prover sent `candidate` now, what
/// would the next verifier message bytes be?". It is how a prover grinds a
/// message against a predicate on the challenge that follows it, such as a
/// proof of work over the transcript sponge itself.
///
/// Obtain one with [`Transcript::prover_search`][crate::Transcript::prover_search].
///
/// A probe is [`Sync`], so a search may run on several threads at once.
pub trait Probe: Sync {
    /// Write into `out` the bytes that the transcript would squeeze right
    /// after absorbing `candidate`.
    ///
    /// The transcript itself is unchanged.
    fn probe(&self, candidate: &[u8], out: &mut [u8]);
}

/// A snapshot of the prover's public-coin sponge, used to search for a
/// prover message.
///
/// Built by [`ProverState::message_search`][crate::ProverState::message_search].
///
/// # Security
///
/// The snapshot holds a copy of the public sponge state and nothing else. It
/// does not hold the private RNG and cannot write to the NARG string. It can
/// evaluate many hypothetical continuations of the transcript at the point it
/// was taken, which is its purpose, but it cannot restore or advance the live
/// [`ProverState`][crate::ProverState]. A snapshot kept across later messages
/// still answers for the earlier point. Its outputs depend only on public
/// data, which the verifier recomputes anyway.
#[derive(Clone)]
pub struct MessageSearch<H> {
    sponge: H,
}

impl<H> MessageSearch<H> {
    pub(crate) const fn new(sponge: H) -> Self {
        Self { sponge }
    }
}

impl<H: DuplexSpongeInterface<U = u8> + Sync> Probe for MessageSearch<H> {
    fn probe(&self, candidate: &[u8], out: &mut [u8]) {
        let mut sponge = self.sponge.clone();
        sponge.absorb(candidate);
        sponge.squeeze(out);
    }
}
