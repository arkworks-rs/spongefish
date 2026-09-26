//! The byte encoding of an instance and of a witness: the statement as a
//! string, for a proof system in any language to read.
//!
//! Both encodings are versioned, little-endian, and prefix-free, so an
//! instance can also be absorbed into a transcript as it is. Every list is
//! preceded by its `u32` length and every wire is a `u32` index. Values of
//! the unit type `T` are written with their spongefish [`Encoding`], and the
//! header records their width so that a reader need not know `T`.
//!
//! ```text
//! instance  "SFRI" u8:1 u32:width u32:unit_len u32:label_len label
//!           u32:vars_count
//!           u32:n_public  { u32:var  T:value }*
//!           u32:n_queries { u32:var*width (input) u32:var*width (output) }*
//!           u32:n_equations { u32:n_terms { u32:var T:weight }* T:image }*
//! witness   "SFRW" u8:1 u32:width u32:unit_len
//!           u32:n_steps { T*width (input) T*width (output) }*
//! ```

use alloc::{format, string::String, vec::Vec};

use spongefish::{
    derive_session_id, DefaultHash, DuplexSpongeInit, DuplexSpongeInterface, Encoding, FromNarg,
    NargReader, Unit, VerificationError,
};

use crate::{
    allocator::FieldVar,
    error::InvalidRelation,
    expr::{Sum, Weighted},
    permutation::{LinearEquation, PermutationInstance, PermutationWitness, QueryAnswerPair},
};

/// The four bytes every encoded instance starts with.
pub const INSTANCE_MAGIC: [u8; 4] = *b"SFRI";
/// The four bytes every encoded witness starts with.
pub const WITNESS_MAGIC: [u8; 4] = *b"SFRW";
/// The encoding version this crate writes and reads.
pub const VERSION: u8 = 1;

/// The tag [`PermutationInstance::digest`] derives its session identifier from.
pub const DIGEST_TAG: &[u8] = b"spongefish-circuit/instance/v1";

/// The width, in bytes, of one encoded unit.
fn unit_len<T: Unit + Encoding>() -> usize {
    T::ZERO.encode().as_ref().len()
}

fn put_u32(out: &mut Vec<u8>, value: usize) {
    let value = u32::try_from(value).expect("relation sizes fit in u32");
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_unit<T: Encoding>(out: &mut Vec<u8>, value: &T, unit_len: usize) {
    let encoded = value.encode();
    assert_eq!(
        encoded.as_ref().len(),
        unit_len,
        "units must have a fixed-width encoding"
    );
    out.extend_from_slice(encoded.as_ref());
}

fn put_vars<const W: usize>(out: &mut Vec<u8>, vars: &[FieldVar; W]) {
    for var in vars {
        put_u32(out, var.index());
    }
}

fn malformed(what: &str) -> InvalidRelation {
    InvalidRelation::new(format!("malformed encoding: {what}"))
}

fn read_u32(reader: &mut NargReader<'_>, what: &str) -> Result<usize, InvalidRelation> {
    reader
        .read::<u32>()
        .map(|value| value as usize)
        .map_err(|VerificationError| malformed(what))
}

fn read_var(reader: &mut NargReader<'_>) -> Result<FieldVar, InvalidRelation> {
    let index = read_u32(reader, "wire index")?;
    FieldVar::try_from_index(index).ok_or_else(|| malformed("wire index out of range"))
}

fn read_vars<const W: usize>(
    reader: &mut NargReader<'_>,
) -> Result<[FieldVar; W], InvalidRelation> {
    let mut vars = [FieldVar::ZERO; W];
    for var in &mut vars {
        *var = read_var(reader)?;
    }
    Ok(vars)
}

fn read_unit<T: FromNarg>(reader: &mut NargReader<'_>) -> Result<T, InvalidRelation> {
    reader
        .read::<T>()
        .map_err(|VerificationError| malformed("unit value"))
}

/// Read and check a header, returning the label for an instance.
fn read_header<T: Unit + Encoding>(
    reader: &mut NargReader<'_>,
    magic: [u8; 4],
    width: usize,
    with_label: bool,
) -> Result<String, InvalidRelation> {
    let found: [u8; 4] = reader
        .take_array()
        .map_err(|VerificationError| malformed("magic"))?;
    if found != magic {
        return Err(malformed("wrong magic"));
    }
    let version: [u8; 1] = reader
        .take_array()
        .map_err(|VerificationError| malformed("version"))?;
    if version[0] != VERSION {
        return Err(malformed("unsupported version"));
    }
    if read_u32(reader, "width")? != width {
        return Err(malformed("width does not match the type"));
    }
    if read_u32(reader, "unit length")? != unit_len::<T>() {
        return Err(malformed("unit length does not match the type"));
    }
    if !with_label {
        return Ok(String::new());
    }
    let label_len = read_u32(reader, "label length")?;
    let label = reader
        .take(label_len)
        .map_err(|VerificationError| malformed("label"))?;
    String::from_utf8(label.to_vec()).map_err(|_| malformed("label is not UTF-8"))
}

impl<T: Unit + Encoding + FromNarg + PartialEq, const WIDTH: usize> PermutationInstance<T, WIDTH> {
    /// The canonical byte encoding of this instance.
    pub fn to_bytes(&self) -> Vec<u8> {
        let unit_len = unit_len::<T>();
        let mut out = Vec::new();
        out.extend_from_slice(&INSTANCE_MAGIC);
        out.push(VERSION);
        put_u32(&mut out, WIDTH);
        put_u32(&mut out, unit_len);
        put_u32(&mut out, self.label.len());
        out.extend_from_slice(self.label.as_bytes());
        put_u32(&mut out, self.vars_count);
        put_u32(&mut out, self.public_values.len());
        for (var, value) in &self.public_values {
            put_u32(&mut out, var.index());
            put_unit(&mut out, value, unit_len);
        }
        put_u32(&mut out, self.queries.len());
        for query in &self.queries {
            put_vars(&mut out, &query.input);
            put_vars(&mut out, &query.output);
        }
        put_u32(&mut out, self.equations.len());
        for equation in &self.equations {
            put_u32(&mut out, equation.terms.terms().len());
            for term in equation.terms.terms() {
                put_u32(&mut out, term.var.index());
                put_unit(&mut out, &term.weight, unit_len);
            }
            put_unit(&mut out, &equation.image, unit_len);
        }
        out
    }

    /// Parse [`Self::to_bytes`], running the same checks as
    /// [`PermutationRelation::compile`][crate::PermutationRelation::compile].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, InvalidRelation> {
        let mut reader = NargReader::new(bytes);
        let instance = Self::read(&mut reader)?;
        if !reader.is_empty() {
            return Err(malformed("trailing bytes"));
        }
        Ok(instance)
    }

    fn read(reader: &mut NargReader<'_>) -> Result<Self, InvalidRelation> {
        let label = read_header::<T>(reader, INSTANCE_MAGIC, WIDTH, true)?;
        let vars_count = read_u32(reader, "variable count")?;
        let n_public = read_u32(reader, "public count")?;
        let mut public_values = Vec::new();
        for _ in 0..n_public {
            let var = read_var(reader)?;
            let value = read_unit::<T>(reader)?;
            public_values.push((var, value));
        }
        let n_queries = read_u32(reader, "query count")?;
        let mut queries = Vec::new();
        for _ in 0..n_queries {
            let input = read_vars::<WIDTH>(reader)?;
            let output = read_vars::<WIDTH>(reader)?;
            queries.push(QueryAnswerPair::new(input, output));
        }
        let n_equations = read_u32(reader, "equation count")?;
        let mut equations = Vec::new();
        for _ in 0..n_equations {
            let n_terms = read_u32(reader, "term count")?;
            let mut terms = Vec::new();
            for _ in 0..n_terms {
                let var = read_var(reader)?;
                let weight = read_unit::<T>(reader)?;
                terms.push(Weighted { var, weight });
            }
            let image = read_unit::<T>(reader)?;
            equations.push(LinearEquation::new(
                terms.into_iter().collect::<Sum<T>>(),
                image,
            ));
        }
        let public_sorted = public_values
            .windows(2)
            .all(|pair| pair[0].0.index() < pair[1].0.index());
        if !public_sorted {
            return Err(malformed("public wires must be strictly increasing"));
        }
        Self::validated(label, vars_count, public_values, queries, equations)
    }

    /// The 32-byte digest of [`Self::to_bytes`], for binding the statement
    /// into a transcript.
    pub fn digest(&self) -> [u8; 32] {
        let session_id = derive_session_id::<DefaultHash>(DIGEST_TAG);
        let mut sponge = DefaultHash::init(session_id.as_bytes());
        sponge.absorb(&self.to_bytes());
        let mut out = [0u8; 32];
        sponge.squeeze(&mut out);
        out
    }
}

impl<T: Unit + Encoding + FromNarg + PartialEq, const WIDTH: usize> Encoding
    for PermutationInstance<T, WIDTH>
{
    fn encode(&self) -> impl AsRef<[u8]> {
        self.to_bytes()
    }
}

impl<T: Unit + Encoding + FromNarg + PartialEq, const WIDTH: usize> FromNarg
    for PermutationInstance<T, WIDTH>
{
    fn from_narg(reader: &mut NargReader<'_>) -> Result<Self, VerificationError> {
        Self::read(reader).map_err(|_| VerificationError)
    }
}

impl<T: Unit + Encoding + FromNarg, const WIDTH: usize> PermutationWitness<T, WIDTH> {
    /// The canonical byte encoding of this witness.
    pub fn to_bytes(&self) -> Vec<u8> {
        let unit_len = unit_len::<T>();
        let mut out = Vec::new();
        out.extend_from_slice(&WITNESS_MAGIC);
        out.push(VERSION);
        put_u32(&mut out, WIDTH);
        put_u32(&mut out, unit_len);
        put_u32(&mut out, self.trace.len());
        for step in &self.trace {
            for value in step.input.iter().chain(&step.output) {
                put_unit(&mut out, value, unit_len);
            }
        }
        out
    }

    /// Parse [`Self::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, InvalidRelation> {
        let mut reader = NargReader::new(bytes);
        read_header::<T>(&mut reader, WITNESS_MAGIC, WIDTH, false)?;
        let n_steps = read_u32(&mut reader, "step count")?;
        let mut trace = Vec::new();
        for _ in 0..n_steps {
            let mut input = core::array::from_fn(|_| T::ZERO);
            let mut output = core::array::from_fn(|_| T::ZERO);
            for value in input.iter_mut().chain(&mut output) {
                *value = read_unit::<T>(&mut reader)?;
            }
            trace.push(QueryAnswerPair::new(input, output));
        }
        if !reader.is_empty() {
            return Err(malformed("trailing bytes"));
        }
        Ok(Self { trace })
    }
}
