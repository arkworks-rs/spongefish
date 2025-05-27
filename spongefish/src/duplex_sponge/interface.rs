use super::Unit;

/// A [`DuplexInterface`] is an abstract interface for absorbing and squeezing data.
/// The type parameter `U` represents basic unit that the sponge works with.
///
/// We require [`DuplexInterface`] implementations to have a [`std::default::Default`] implementation, that initializes
/// to zero the hash function state, and a [`zeroize::Zeroize`] implementation for secure deletion.
///
/// **HAZARD**: Don't implement this trait unless you know what you are doing.
/// Consider using the sponges already provided by this library.
pub trait DuplexSpongeInterface<U = u8>: Default + Clone + zeroize::Zeroize
where
    U: Unit,
{
    /// Initializes a new sponge, setting up the state.
    fn new(iv: [u8; 32]) -> Self;

    /// Absorbs new elements in the sponge.
    fn absorb(&mut self, input: &[U]) -> &mut Self;

    /// Squeezes out new elements.
    fn squeeze(&mut self, output: &mut [U]) -> &mut Self;

    /// Ratcheting.
    ///
    /// This operations makes sure that different elements are processed in different blocks.
    /// Right now, this is done by:
    /// - permuting the state.
    /// - zero rate elements.
    /// This has the effect that state holds no information about the elements absorbed so far.
    /// The resulting state is compressed.
    fn ratchet(&mut self) -> &mut Self;
}
