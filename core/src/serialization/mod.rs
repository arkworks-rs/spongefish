use crate::ProofError;


/// Trait for de-serialization of prover messages from the proof string.
pub trait ReadBytes: Sized {
    fn read(dst: &mut [Self], src: &mut [u8]) -> Result<usize, ProofError>;
}

/// Trait for serialization of prover messages into the proof string.
pub trait WriteBytes: Sized {
    fn write(dst: &mut [u8], src: &mut [Self]) -> Result<usize, ProofError>;
}

#[cfg(feature = "std")]
impl<T> ReadBytes for T
where
    for<'a> &'a [T]: std::io::Read,
{
    fn read(dst: &mut [T], src: &mut [u8]) -> Result<usize, ProofError> {
        use std::io::Read;
        (dst as &[T]).read(src).map_err(From::from)
    }
}


#[cfg(not(feature = "std"))]
impl ReadBytes for u8 {
    fn read(dst: &mut [u8], src: &mut [u8]) -> Result<usize, ProofError> {
        let len = dst.len().min(src.len());
        dst[..len].copy_from_slice(&src[..len]);
        Ok(len)
    }
}

#[cfg(feature = "std")]
impl From<std::io::Error> for ProofError {
    fn from(_value: std::io::Error) -> Self {
        todo!()
    }
}

