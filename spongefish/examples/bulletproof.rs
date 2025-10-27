//! This is the example of a zk proof that is relatively complex,
//! with non-constant rounds, where the implementor wanted to get the job
//! done without caring too much about which hash function to be used.
//!
//! Bulletproofs allow to prove that a vector commitment has the following form
//!
//! $$
//! C = \langle a, G \rangle + \langle b, H \rangle + \langle a, b \rangle U
//! $$

use ark_ec::{AffineRepr, CurveGroup, PrimeGroup, VariableBaseMSM};
use ark_ff::Field;
// use ark_std::log2;
use rand::rngs::OsRng;
use spongefish::{
    codecs::{Decoding, Encoding},
    io::{NargDeserialize, NargSerialize},
    ProverState, VerificationError, VerificationResult, VerifierState,
};

fn prove<'a, G>(
    prover_state: &'a mut ProverState,
    generators: (&[G::Affine], &[G::Affine], &G::Affine),
    statement: &G, // the actual inner-product of the witness is not really needed
    witness: (&[G::ScalarField], &[G::ScalarField]),
) -> VerificationResult<&'a [u8]>
where
    G: CurveGroup + NargSerialize + Encoding<[u8]>,
    G::ScalarField: NargSerialize + Encoding<[u8]> + Decoding<[u8]>,
{
    assert_eq!(witness.0.len(), witness.1.len());

    if witness.0.len() == 1 {
        assert_eq!(generators.0.len(), 1);

        prover_state.prover_message(&[witness.0[0], witness.1[0]]);
        return Ok(prover_state.narg_string());
    }

    let n = witness.0.len() / 2;
    let (a_left, a_right) = witness.0.split_at(n);
    let (b_left, b_right) = witness.1.split_at(n);
    let (g_left, g_right) = generators.0.split_at(n);
    let (h_left, h_right) = generators.1.split_at(n);
    let u = *generators.2;

    let left = u * dot_prod(a_left, b_right)
        + G::msm_unchecked(g_right, a_left)
        + G::msm_unchecked(h_left, b_right);

    let right = u * dot_prod(a_right, b_left)
        + G::msm_unchecked(g_left, a_right)
        + G::msm_unchecked(h_right, b_left);

    prover_state.prover_message(&[left, right]);
    let x: G::ScalarField = prover_state.verifier_message();
    let x_inv = x.inverse().expect("You just won the lottery!");

    let new_g = fold_generators(g_left, g_right, &x_inv, &x);
    let new_h = fold_generators(h_left, h_right, &x, &x_inv);
    let new_generators = (&new_g[..], &new_h[..], generators.2);

    let new_a = fold(a_left, a_right, &x, &x_inv);
    let new_b = fold(b_left, b_right, &x_inv, &x);
    let new_witness = (&new_a[..], &new_b[..]);

    let new_statement = *statement + left * x.square() + right * x_inv.square();

    let bulletproof = prove(prover_state, new_generators, &new_statement, new_witness)?;
    Ok(bulletproof)
}

fn verify<G>(
    verifier_state: &mut VerifierState,
    generators: (&[G::Affine], &[G::Affine], &G::Affine),
    mut n: usize,
    statement: &G,
) -> VerificationResult<()>
where
    G: CurveGroup + Encoding<[u8]> + NargDeserialize,
    G::ScalarField: Decoding<[u8]> + Encoding<[u8]> + NargDeserialize,
{
    let mut g = generators.0.to_vec();
    let mut h = generators.1.to_vec();
    let u = *generators.2;
    let mut statement = *statement;

    while n != 1 {
        let [left, right]: [G; 2] = verifier_state.prover_messages()?;
        n /= 2;
        let (g_left, g_right) = g.split_at(n);
        let (h_left, h_right) = h.split_at(n);
        let x: G::ScalarField = verifier_state.verifier_message();
        let x_inv = x.inverse().expect("You just won the lottery!");

        g = fold_generators(g_left, g_right, &x_inv, &x);
        h = fold_generators(h_left, h_right, &x, &x_inv);
        statement = statement + left * x.square() + right * x_inv.square();
    }
    let [a, b]: [G::ScalarField; 2] = verifier_state.prover_messages()?;

    let c = a * b;
    if (g[0] * a + h[0] * b + u * c - statement).is_zero() {
        Ok(())
    } else {
        *VerificationError
    }
}

fn fold_generators<A: AffineRepr>(
    a: &[A],
    b: &[A],
    x: &A::ScalarField,
    y: &A::ScalarField,
) -> Vec<A> {
    a.iter()
        .zip(b.iter())
        .map(|(&a, &b)| (a * x + b * y).into_affine())
        .collect()
}

/// Computes the inner prouct of vectors `a` and `b`.
///
/// Useless once https://github.com/arkworks-rs/algebra/pull/665 gets merged.
fn dot_prod<F: Field>(a: &[F], b: &[F]) -> F {
    a.iter().zip(b.iter()).map(|(&a, &b)| a * b).sum()
}

/// Folds together `(a, b)` using challenges `x` and `y`.
fn fold<F: Field>(a: &[F], b: &[F], x: &F, y: &F) -> Vec<F> {
    a.iter()
        .zip(b.iter())
        .map(|(&a, &b)| a * x + b * y)
        .collect()
}

fn main() {
    use ark_curve25519::EdwardsProjective as G;
    use ark_std::UniformRand;

    type F = <G as PrimeGroup>::ScalarField;
    type GAffine = <G as CurveGroup>::Affine;

    // the vector size
    let size = 8;
    // the testing vectors
    let a = (0..size).map(|x| F::from(x as u32)).collect::<Vec<_>>();
    let b = (0..size)
        .map(|x| F::from(x as u32 + 42))
        .collect::<Vec<_>>();
    let ab = dot_prod(&a, &b);
    // the generators to be used for respectively a, b, ip
    let g = (0..a.len())
        .map(|_| GAffine::rand(&mut OsRng))
        .collect::<Vec<_>>();
    let h = (0..b.len())
        .map(|_| GAffine::rand(&mut OsRng))
        .collect::<Vec<_>>();
    let u = GAffine::rand(&mut OsRng);

    let generators = (&g[..], &h[..], &u);
    let statement = G::msm_unchecked(&g, &a) + G::msm_unchecked(&h, &b) + u * ab;
    let witness = (&a[..], &b[..]);

    let protocol_id = [0u8; 64];
    let session_id = [0u8; 32];
    let mut prover_state = ProverState::new(protocol_id, session_id);
    prover_state.public_message(&statement);
    let narg_string =
        prove(&mut prover_state, generators, &statement, witness).expect("Error proving");
    println!(
        "Here's a bulletproof for {} elements:\n{}",
        size,
        hex::encode(narg_string)
    );

    let mut verifier_state = VerifierState::new(protocol_id, session_id, narg_string);
    verifier_state.public_message(&statement);
    verify(&mut verifier_state, generators, size, &statement).expect("Invalid proof");
}
