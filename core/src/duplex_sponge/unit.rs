/// Basic units over which a sponge operates.
///
/// The only requirement of Units is that they have fixed size, can be copied, and possess a "zero" element.
pub trait Unit: Clone + Sized {
    /// The zero element.
    const ZERO: Self;
}

impl Unit for u8 {
    const ZERO: Self = 0;
}
