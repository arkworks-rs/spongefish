use core::fmt::Arguments;

/// Proposed alternative domain separator
// pub mod pattern;

// pub mod safe;

// pub use safe::*;
// /// SAFE API.
// pub mod sho;

// /// Traits for domain separator
// pub mod traits;

// use crate::{
//     alloc::string::ToString,
//     duplex_sponge::DuplexSpongeInterface,
//     StdHash,
// };
use crate::{DuplexSpongeInterface, StdHash};

#[allow(dead_code)]
const SESSION_FALLBACK_LABEL: &str = env!("CARGO_PKG_NAME");

// impl From<&str> for DomainSeparatorMismatch {
//     fn from(s: &str) -> Self {
//         s.to_string().into()
//     }
// }

// impl From<alloc::string::String> for DomainSeparatorMismatch {
//     fn from(s: alloc::string::String) -> Self {
//         Self(s)
//     }
// }

// #[cfg(feature = "std")]
// extern crate std;
// #[cfg(feature = "std")]
// impl From<std::io::Error> for DomainSeparatorMismatch {
//     fn from(value: std::io::Error) -> Self {
//         Self(value.to_string())
//     }
// }

// /// Signals a domain separator is inconsistent with the description provided.
// #[derive(Debug, Clone)]
// pub struct DomainSeparatorMismatch(alloc::string::String);

#[allow(dead_code)]
#[inline]
pub const fn protocol_id(input: &str) -> [u8; 64] {
    let bytes = input.as_bytes();
    let mut output = [0u8; 64];
    let mut idx = 0;
    while idx < bytes.len() && idx < 32 {
        output[idx] = bytes[idx];
        idx += 1;
    }
    output
}

#[allow(dead_code)]
#[inline]
pub(crate) fn session_id(args: Arguments) -> [u8; 64] {
    let mut sponge = StdHash::default();

    if let Some(message) = args.as_str() {
        absorb_session_input(&mut sponge, message);
    } else {
        let formatted = alloc::fmt::format(args);
        absorb_session_input(&mut sponge, &formatted);
    }

    sponge.squeeze_array::<64>()
}

#[allow(dead_code)]
fn absorb_session_input(sponge: &mut StdHash, message: &str) {
    if message.is_empty() {
        sponge.absorb(SESSION_FALLBACK_LABEL.as_bytes());
    } else {
        sponge.absorb(message.as_bytes());
    }
}
