use alloc::vec::Vec;
use core::marker::PhantomData;

#[cfg(feature = "turboshake128")]
use crate::DefaultHash;
use crate::{
    Decoding, DuplexSpongeInit, DuplexSpongeInterface, Encoding, NargDeserialize, ProverState,
    VerificationError, VerifierState,
};

/// A witness value.
///
/// Denoted a value which the verifier may not have.
///
/// ```compile_fail,E0308
/// # use spongefish::{Transcript, Witness};
/// fn check<T: Transcript>(transcript: &mut T, witness: Witness<u64>)
///     -> Result<(), VerificationError>
/// {
///     transcript.check(|| witness.map(|w| w == 0)) // `Witness<bool>`, not `bool`
/// }
/// ```
///
/// Control flow may not depend on a value marked [`Witness`].
///
/// ```compile_fail,E0308
/// # use spongefish::{Transcript, Witness};
/// fn run<T: Transcript>(transcript: &mut T, witness: Witness<u64>)
///     -> Result<(), VerificationError>
/// {
///     if witness.map(|w| w > 5) { // `Witness<bool>`, not `bool`
///         transcript.prover_message(Witness::known(1u64))?;
///     }
///     Ok(())
/// }
/// ```
#[derive(Clone, Copy, Default)]
pub struct Witness<T>(Option<T>);

impl<T> core::fmt::Debug for Witness<T> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("Witness(..)")
    }
}

impl<T> Witness<T> {
    /// The prover's view.
    pub const fn known(value: T) -> Self {
        Self(Some(value))
    }

    /// The verifier's view. Carries no `T`, so nothing downstream can read one.
    pub const fn unknown() -> Self {
        Self(None)
    }

    /// Compute with the value if there is one.
    ///
    /// The closure must be pure; see the type-level warning above.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Witness<U> {
        Witness(self.0.map(f))
    }

    /// Combine two, known only when both are.
    pub fn zip<U>(self, other: Witness<U>) -> Witness<(T, U)> {
        Witness(self.0.zip(other.0))
    }

    #[must_use]
    pub const fn as_ref(&self) -> Witness<&T> {
        Witness(self.0.as_ref())
    }

    pub const fn as_mut(&mut self) -> Witness<&mut T> {
        Witness(self.0.as_mut())
    }
}

impl<T> From<T> for Witness<T> {
    fn from(value: T) -> Self {
        Self(Some(value))
    }
}

/// The interactive protocol transcript.
pub trait Transcript {
    /// A prover message: the prover sends the value, the verifier reads one.
    ///
    /// It takes a [`Witness<T>`] and returns a plain `T`, declassifying a secret value into
    /// one that can be used by the verifier.
    fn prover_message<T>(&mut self, value: Witness<T>) -> Result<T, VerificationError>
    where
        T: Encoding + NargDeserialize;

    /// A verifier message. Both sides derive it the same way, so it is
    /// infallible and known to both.
    fn verifier_message<T: Decoding<[u8]>>(&mut self) -> T;

    /// A value both parties hold: absorbed, not carried by the proof.
    fn public_message<T: Encoding + ?Sized>(&mut self, value: &T);

    /// The prover's private randomness. Unknown on the verifier, which is what
    /// makes the rest of the body typecheck on both sides.
    fn sample<T: Decoding<[u8]>>(&mut self) -> Witness<T>;

    /// `n` samples from the prover's private randomness. Unknown on the
    /// verifier, without allocating a placeholder vector there.
    fn sample_vec<T: Decoding<[u8]>>(&mut self, n: usize) -> Witness<Vec<T>>;

    /// A verification equation.
    ///
    /// The closure `holds` is called also by the prover in `debug` builds.
    fn check(&self, holds: impl FnOnce() -> bool) -> Result<(), VerificationError>;
}

/// The interactive argument.
///
/// # Why there is no `self`
///
/// An implementor of this trait should not carry any state outside of the instance
/// or the section identifier. Additionally, the type should be
/// zero-sized, so that a field is a clear compile error:
///
/// ```compile_fail,E0080
/// # use spongefish::{Argument, Transcript, Witness};
/// struct IP {
///     generator: u64,   // reaches neither the sponge nor the session id
/// }
///
/// impl Argument for IP {
///     type Instance = u64;
///     type Witness = u64;
///     type Output = ();
///     fn run<T: Transcript>(
///         _transcript: &mut T,
///         _instance: &u64,
///         _witness: Witness<&u64>,
///     )
///         -> Result<(), VerificationError> { Ok(()) }
/// }
///
/// const _: () = <IP as Argument>::NO_STATE;
/// ```
pub trait Argument: Sized {
    /// Asserts that the implementor carries no data.
    ///
    /// Checked by [`FiatShamir::prove`] and [`FiatShamir::verify`]. Not part of
    /// the public API; do not override it.
    #[doc(hidden)]
    const NO_STATE: () = assert!(
        core::mem::size_of::<Self>() == 0,
        "an Argument must be zero-sized. Values must be explicitly part of \
         `Instance`, and `Witness`. Protocol parameters can be const generics",
    );

    /// The statement. Everything public lives here, because this is what gets
    /// absorbed — a public value outside it is the weak Fiat-Shamir bug.
    type Instance: Encoding;
    /// The prover's private input.
    type Witness;
    /// What both parties compute by the end.
    type Output;

    /// Generic over the side, which is the whole trick: `prove` instantiates it
    /// with a known witness, `verify` with an unknown one, and there is one
    /// body.
    fn run<T: Transcript>(
        transcript: &mut T,
        instance: &Self::Instance,
        witness: Witness<&Self::Witness>,
    ) -> Result<Self::Output, VerificationError>;
}

#[inline]
fn assert_argument_has_no_state<A: Argument>() {
    assert!(
        core::mem::size_of::<A>() == 0,
        "an Argument must be zero-sized"
    );
}

// --- the DSFS transformation ---------------------------------------------------------

impl<H: DuplexSpongeInterface<U = u8>, R: DuplexSpongeInit<U = u8>> Transcript
    for ProverState<H, R>
{
    fn prover_message<T>(&mut self, value: Witness<T>) -> Result<T, VerificationError>
    where
        T: Encoding + NargDeserialize,
    {
        // `Witness::unknown()` here means the caller ran the prover without a
        // witness. Nothing to send.
        let Witness(value) = value;
        let value = value.ok_or(VerificationError)?;
        Self::prover_message(self, &value);
        Ok(value)
    }

    fn verifier_message<T: Decoding<[u8]>>(&mut self) -> T {
        Self::verifier_message(self)
    }

    fn public_message<T: Encoding + ?Sized>(&mut self, value: &T) {
        Self::public_message(self, value);
    }

    fn sample<T: Decoding<[u8]>>(&mut self) -> Witness<T> {
        Witness::known(self.rng().sample())
    }

    fn sample_vec<T: Decoding<[u8]>>(&mut self, n: usize) -> Witness<Vec<T>> {
        Witness::known(self.rng().sample_vec(n))
    }

    fn check(&self, holds: impl FnOnce() -> bool) -> Result<(), VerificationError> {
        // Short-circuits, so a release build never calls `holds` and the
        // equation is dead code.
        if cfg!(debug_assertions) && !holds() {
            return Err(VerificationError);
        }
        Ok(())
    }
}

impl<H: DuplexSpongeInterface<U = u8>> Transcript for VerifierState<'_, H> {
    fn prover_message<T>(&mut self, _value: Witness<T>) -> Result<T, VerificationError>
    where
        T: Encoding + NargDeserialize,
    {
        // The argument is `unknown` and is dropped; the message comes off the
        // wire. Absorbing the bytes read rather than a re-encoding of what was
        // parsed is what keeps a non-canonical codec from admitting a second
        // accepting proof.
        Self::prover_message_as(self, T::deserialize_from_narg)
    }

    fn verifier_message<T: Decoding<[u8]>>(&mut self) -> T {
        Self::verifier_message(self)
    }

    fn public_message<T: Encoding + ?Sized>(&mut self, value: &T) {
        Self::public_message(self, value);
    }

    fn sample<T: Decoding<[u8]>>(&mut self) -> Witness<T> {
        Witness::unknown()
    }

    fn sample_vec<T: Decoding<[u8]>>(&mut self, _n: usize) -> Witness<Vec<T>> {
        Witness::unknown()
    }

    fn check(&self, holds: impl FnOnce() -> bool) -> Result<(), VerificationError> {
        if holds() {
            Ok(())
        } else {
            Err(VerificationError)
        }
    }
}

// --- entry points ----------------------------------------------------------

/// The Fiat-Shamir transformation, at a chosen duplex sponge.
///
/// This is a type rather than two free functions so that the sponge can be
/// named once and defaulted: Rust allows no default on a function's generic
/// parameters, and — less obviously — a struct's default is not applied in
/// expression position either, so `FiatShamir::prove(..)` would still ask you
/// to infer `H`. The alias [`Narg`] is what closes that gap.
///
/// Use [`Narg::prove`] for the draft's default suite, or
/// `FiatShamir::<Keccak>::prove(..)` for another.
#[cfg(feature = "turboshake128")]
pub struct FiatShamir<H = DefaultHash>(PhantomData<H>);

/// The transformation at a sponge you name. Without the `turboshake128`
/// feature there is no default suite to fall back on.
#[cfg(not(feature = "turboshake128"))]
pub struct FiatShamir<H>(PhantomData<H>);

/// The transformation at [`DefaultHash`], the TurboSHAKE128 suite of the draft.
///
/// A type alias fixes the parameter, so `Narg::prove(..)` needs no turbofish.
#[cfg(feature = "turboshake128")]
pub type Narg = FiatShamir<DefaultHash>;

impl<H: DuplexSpongeInit<U = u8>> FiatShamir<H> {
    /// Run `argument` as the non-interactive prover.
    ///
    /// Returns the NARG string and whatever terminal value the dialogue
    /// produced — for a sumcheck, the folded evaluation that a surrounding
    /// construction has to tie to reality.
    /// Seeding the prover's private RNG is what needs `getrandom`; the
    /// verifier has no randomness and so needs neither feature.
    #[cfg(all(feature = "turboshake128", feature = "getrandom"))]
    pub fn prove<A: Argument>(
        session_id: &crate::SessionId,
        instance: &A::Instance,
        witness: &A::Witness,
    ) -> Result<(alloc::vec::Vec<u8>, A::Output), VerificationError> {
        assert_argument_has_no_state::<A>();
        let () = A::NO_STATE;
        let mut transcript = ProverState::<H>::new(session_id, instance);
        let output = A::run(&mut transcript, instance, Witness::known(witness))?;
        Ok((transcript.into_narg_string(), output))
    }

    /// Run `argument` as the non-interactive verifier.
    ///
    /// The end-of-input check is here and not optional: trailing bytes make a
    /// proof malleable.
    pub fn verify<A: Argument>(
        session_id: &crate::SessionId,
        instance: &A::Instance,
        narg_string: &[u8],
    ) -> Result<A::Output, VerificationError> {
        assert_argument_has_no_state::<A>();
        let () = A::NO_STATE;
        let mut transcript = VerifierState::<H>::new(session_id, instance, narg_string);
        let output = A::run(&mut transcript, instance, Witness::unknown())?;
        transcript.check_eof()?;
        Ok(output)
    }
}
