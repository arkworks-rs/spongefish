use crate::ProofError;


/// Basic units over which a sponge operates.
///
/// We require the units to have a precise size in memory, to be cloneable.
pub trait Unit: ReadBytes + Clone + Sized {
    /// The zero element.
    const ZERO: Self;
}

pub trait ReadBytes: Sized {
    /// Read a bunch of units from the wire.
    fn read(bunch: &mut [Self], buf: &mut [u8]) -> Result<usize, ProofError>;
}

#[cfg(feature = "std")]
impl<U> ReadBytes for U
where
    for<'a> &'a [U]: std::io::Read,
{
    fn read(units: &mut [U], buf: &mut [u8]) -> Result<usize, ProofError> {
        use std::io::Read;
        (units as &[U]).read(buf).map_err(From::from)
    }
}

#[cfg(feature = "std")]
impl From<std::io::Error> for ProofError {
    fn from(_value: std::io::Error) -> Self {
        todo!()
    }
}


#[cfg(not(feature = "std"))]
impl ReadBytes for u8 {
    fn read(units: &mut [u8], buf: &mut [u8]) -> Result<usize, ProofError> {
        let len = units.len().min(buf.len());
        buf[..len].copy_from_slice(&units[..len]);
        Ok(len)
    }
}

impl Unit for u8 {
    const ZERO: Self = 0;
}
