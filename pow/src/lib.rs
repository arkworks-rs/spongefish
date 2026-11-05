#![cfg_attr(docsrs, feature(doc_cfg))]

mod transcript;

pub use transcript::{verifier_message_pow_parallel, PowStrategy, PowTranscriptExt};
