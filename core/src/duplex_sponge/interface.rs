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
    fn new() -> Self;

    /// Absorbs new elements in the sponge.
    fn absorb(&mut self, input: &[U]) -> &mut Self;

    /// Squeezes out new elements.
    fn squeeze(&mut self, output: &mut [U]) -> &mut Self;

    /// Pad the current block.
    ///
    /// If the underlying hash is processing absorbs in blocks, this function will fill it
    /// so that future absorbs can rely on the full "rate" of the underlying hash.
    fn pad_block(&mut self) -> &mut Self;
}
