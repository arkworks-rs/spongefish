use std::io;

/// Basic units over which a sponge operates.
///
/// We require the units to have a precise size in memory, to be cloneable,
/// and that we can zeroize them.
pub trait Unit: Clone + Sized + zeroize::Zeroize {
    /// Write a bunch of units in the wire.
    fn write(bunch: &[Self], w: &mut impl io::Write) -> Result<(), io::Error>;
    /// Read a bunch of units from the wire
    fn read(r: &mut impl io::Read, bunch: &mut [Self]) -> Result<(), io::Error>;
}

impl Unit for u8 {
    fn write(bunch: &[Self], w: &mut impl io::Write) -> Result<(), io::Error> {
        w.write_all(bunch)
    }

    fn read(r: &mut impl io::Read, bunch: &mut [Self]) -> Result<(), io::Error> {
        r.read_exact(bunch)
    }
}
