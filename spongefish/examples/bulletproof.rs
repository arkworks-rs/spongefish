//! # Example: bulletproofs via curve25519-dalek.
//!
//! Bulletproofs allow to prove that a vector commitment has the following form
//!
//! $$
//! C = \langle a, G \rangle + \langle b, H \rangle + \langle a, b \rangle U
//! $$

use curve25519_dalek::{traits::MultiscalarMul, RistrettoPoint, Scalar};
use spongefish::{ProverState, VerificationResult, VerifierState};

struct SchnorrProof;

impl SchnorrProof {
    fn protocol_id() -> [u8; 64] {
        spongefish::protocol_id!("schnorr proofs for testing")
    }

    pub fn prove<'a>(
        prover_state: &'a mut ProverState,
        generators: (&[RistrettoPoint], &[RistrettoPoint], &RistrettoPoint),
        statement: &RistrettoPoint, // the actual inner-product of the witness is not really needed
        witness: (&[Scalar], &[Scalar]),
    ) -> VerificationResult<&'a [u8]> {
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
            + RistrettoPoint::multiscalar_mul(a_left, g_right)
            + RistrettoPoint::multiscalar_mul(b_right, h_left);

        let right = u * dot_prod(a_right, b_left)
            + RistrettoPoint::multiscalar_mul(a_right, g_left)
            + RistrettoPoint::multiscalar_mul(b_left, h_right);

        prover_state.prover_message(&[left, right]);
        let x: Scalar = prover_state.verifier_message();
        let x_inv = x.invert();

        let new_g = fold_generators(g_left, g_right, &x_inv, &x);
        let new_h = fold_generators(h_left, h_right, &x, &x_inv);
        let new_generators = (&new_g[..], &new_h[..], generators.2);

        let new_a = self.fold(a_left, a_right, &x, &x_inv);
        let new_b = self.fold(b_left, b_right, &x_inv, &x);
        let new_witness = (&new_a[..], &new_b[..]);

        let new_statement = *statement + left * x * x + right * x_inv * x_inv;

        self.prove(prover_state, new_generators, &new_statement, new_witness)
    }

    pub fn verify(
        verifier_state: &mut VerifierState,
        generators: (&[RistrettoPoint], &[RistrettoPoint], &RistrettoPoint),
        mut n: usize,
        instance: &RistrettoPoint,
    ) -> VerificationResult<()> {
        let mut g = generators.0.to_vec();
        let mut h = generators.1.to_vec();
        let u = *generators.2;
        let mut statement = *instance;

        while n != 1 {
            let [left, right] = verifier_state.prover_messages::<RistrettoPoint, 2>()?;
            n /= 2;
            let (g_left, g_right) = g.split_at(n);
            let (h_left, h_right) = h.split_at(n);
            let x: Scalar = verifier_state.verifier_message();
            let x_inv = x.invert();

            g = self.fold_generators(g_left, g_right, &x_inv, &x);
            h = self.fold_generators(h_left, h_right, &x, &x_inv);
            statement = statement + left * x * x + right * x_inv * x_inv;
        }
        let [a, b]: [Scalar; 2] = verifier_state.prover_messages()?;

        let c = a * b;
        verifier_state.finish(g[0] * a + h[0] * b + u * c == statement)
    }

    fn fold_generators(
        a: &[RistrettoPoint],
        b: &[RistrettoPoint],
        x: &Scalar,
        y: &Scalar,
    ) -> Vec<RistrettoPoint> {
        a.iter()
            .zip(b.iter())
            .map(|(&a, &b)| a * x + b * y)
            .collect()
    }

    /// Folds together `(a, b)` using challenges `x` and `y`.
    fn fold(a: &[Scalar], b: &[Scalar], x: &Scalar, y: &Scalar) -> Vec<Scalar> {
        a.iter()
            .zip(b.iter())
            .map(|(&a, &b)| a * x + b * y)
            .collect()
    }
}

/// Computes the inner prouct of vectors `a` and `b`.
///
/// Useless once https://github.com/arkworks-rs/algebra/pull/665 gets merged.
fn dot_prod(a: &[Scalar], b: &[Scalar]) -> Scalar {
    a.iter().zip(b.iter()).map(|(&a, &b)| a * b).sum()
}


fn main() {
    let mut rng = rand::thread_rng();
    // the vector size
    let size = 8;
    // the testing vectors
    let a = (0..size)
        .map(|x| Scalar::from(x as u32))
        .collect::<Vec<_>>();
    let b = (0..size)
        .map(|x| Scalar::from(x as u32 + 42))
        .collect::<Vec<_>>();
    let ab = dot_prod(&a, &b);
    // the generators to be used for respectively a, b, ip
    let g = (0..a.len())
        .map(|_| RistrettoPoint::random(&mut rng))
        .collect::<Vec<_>>();
    let h = (0..b.len())
        .map(|_| RistrettoPoint::random(&mut rng))
        .collect::<Vec<_>>();
    let u = RistrettoPoint::random(&mut rng);

    let generators = (&g[..], &h[..], &u);
    let statement =
        RistrettoPoint::multiscalar_mul(&a, &g) + RistrettoPoint::multiscalar_mul(&b, &h) + u * ab;
    let witness = (&a[..], &b[..]);

    let mut prover_state =
        ProverState::new(SchnorrProof::protocol_id(), spongefish::session_id!("test"));
    prover_state.public_message(&statement);
    let narg_string =
        self.prove(&mut prover_state, generators, &statement, witness).expect("Error proving");
    println!(
        "Here's a bulletproof for {} elements:\n{}",
        size,
        hex::encode(narg_string)
    );

    let mut verifier_state = VerifierState::new(&protocol_id, &session_id, narg_string);
    verifier_state.public_message(&statement);
    BulletProof::verify(&mut verifier_state, generators, size, &statement).expect("Invalid proof");
}
