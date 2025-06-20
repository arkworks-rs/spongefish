use crate::{
    codecs::unit::Pattern as _,
    pattern::{Label, Length, Pattern as _, PatternState},
};

/// Traits for patterns that handle byte arrays in a transcript.
pub trait Pattern {
    fn public_bytes(&mut self, label: Label, size: usize);
    fn message_bytes(&mut self, label: Label, size: usize);
    fn challenge_bytes(&mut self, label: Label, size: usize);
}

/// Implementation where `Unit = u8`
impl Pattern for PatternState<u8> {
    fn public_bytes(&mut self, label: Label, size: usize) {
        self.begin_public::<u8>(label, Length::Fixed(size));
        self.public_units("units", size);
        self.end_public::<u8>(label, Length::Fixed(size))
    }

    fn message_bytes(&mut self, label: Label, size: usize) {
        self.begin_message::<u8>(label, Length::Fixed(size));
        self.message_units("units", size);
        self.end_message::<u8>(label, Length::Fixed(size))
    }

    fn challenge_bytes(&mut self, label: Label, size: usize) {
        self.begin_challenge::<u8>(label, Length::Fixed(size));
        self.challenge_units("units", size);
        self.end_challenge::<u8>(label, Length::Fixed(size))
    }
}
