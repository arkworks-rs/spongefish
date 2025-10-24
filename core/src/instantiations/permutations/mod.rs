#[cfg(feature = "ascon")]
mod ascon;
#[cfg(feature = "keccak")]
mod keccak;

#[cfg(feature = "ascon")]
pub use ascon::Ascon12;
#[cfg(feature = "keccak")]
pub use keccak::KeccakF1600;
