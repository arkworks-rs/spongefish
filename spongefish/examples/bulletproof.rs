//! # Example: bulletproofs via curve25519-dalek.
//!
//! Bulletproofs allow to prove that a vector commitment has the following form
//!
//! $$
//! C = \langle a, G \rangle + \langle b, H \rangle + \langle a, b \rangle U
//! $$

use curve25519_dalek::{traits::MultiscalarMul, RistrettoPoint, Scalar};
use spongefish::{
    session_id, DomainSeparator, Encoding, ProverState, VerificationError, VerificationResult,
    VerifierState,
};

struct BulletProof;

/// xxx. Instance are prefix-free
#[derive(Encoding, Clone)]
struct Instance {
    len: usize,
    lhs_generators: Vec<RistrettoPoint>,
    rhs_generators: Vec<RistrettoPoint>,
    iner_product_generator: RistrettoPoint,
    ip_commitment: RistrettoPoint,
}

impl Instance {
    fn new() -> Self {
        let i = Instance {};
    }
}

impl BulletProof {
    fn protocol_id() -> [u8; 64] {
        spongefish::protocol_id!("bulletproofs ipa over ristretto255 with blake128")
    }

    pub fn prove<'a>(
        prover_state: &'a mut ProverState,
        instance: &Instance,
        witness: (&[Scalar], &[Scalar]),
    ) -> &'a [u8] {
        assert_eq!(witness.0.len(), witness.1.len());

        if witness.0.len() == 1 {
            assert_eq!(instance.lhs_generators.len(), instance.rhs_generators.len());
            assert_eq!(instance.lhs_generators.len(), witness.0.len());

            prover_state.prover_messages(&[witness.0[0], witness.1[0]]);
            return prover_state.narg_string();
        }

        let n = witness.0.len() / 2;
        let (a_left, a_right) = witness.0.split_at(n);
        let (b_left, b_right) = witness.1.split_at(n);
        let (g_left, g_right) = instance.lhs_generators.split_at(n);
        let (h_left, h_right) = instance.rhs_generators.split_at(n);
        let u = instance.iner_product_generator;

        let left = u * dot_prod(a_left, b_right)
            + RistrettoPoint::multiscalar_mul(a_left, g_right)
            + RistrettoPoint::multiscalar_mul(b_right, h_left);

        let right = u * dot_prod(a_right, b_left)
            + RistrettoPoint::multiscalar_mul(a_right, g_left)
            + RistrettoPoint::multiscalar_mul(b_left, h_right);

        prover_state.prover_message(&[left, right]);
        let x: Scalar = prover_state.verifier_message();
        let x_inv = x.invert();

        let new_g = Self::fold_generators(g_left, g_right, &x_inv, &x);
        let new_h = Self::fold_generators(h_left, h_right, &x, &x_inv);
        let new_inner_product = left * x * x + right * x_inv * x_inv + instance.ip_commitment;

        let new_a = Self::fold(a_left, a_right, &x, &x_inv);
        let new_b = Self::fold(b_left, b_right, &x_inv, &x);
        let new_witness = (&new_a[..], &new_b[..]);

        let instance = &Instance {
            ip_commitment: new_inner_product,
            lhs_generators: new_g,
            rhs_generators: new_h,
            iner_product_generator: instance.iner_product_generator,
        };
        Self::prove(prover_state, &instance, new_witness)
    }

    pub fn verify(
        mut verifier_state: VerifierState,
        instance: &Instance,
    ) -> VerificationResult<()> {
        let mut g = instance.lhs_generators.to_vec();
        let mut h = instance.rhs_generators.to_vec();
        let u = instance.iner_product_generator;
        assert_eq!(instance.lhs_generators.len(), instance.rhs_generators.len());
        let mut n = instance.lhs_generators.len();
        let mut inner_product = instance.ip_commitment;

        while n != 1 {
            let [left, right] = verifier_state.prover_messages::<RistrettoPoint, 2>()?;
            n /= 2;
            let (g_left, g_right) = g.split_at(n);
            let (h_left, h_right) = h.split_at(n);
            let x: Scalar = verifier_state.verifier_message();
            let x_inv = x.invert();

            g = Self::fold_generators(g_left, g_right, &x_inv, &x);
            h = Self::fold_generators(h_left, h_right, &x, &x_inv);
            inner_product = inner_product + left * x * x + right * x_inv * x_inv;
        }
        let [a, b]: [Scalar; 2] = verifier_state.prover_messages()?;

        let c = a * b;
        let relation_holds = g[0] * a + h[0] * b + u * c == instance.ip_commitment;
        if !relation_holds {
            Err(VerificationError)
        }
        verifier_state.check_eof()
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

    let instance = Instance {
        ip_commitment: RistrettoPoint::multiscalar_mul(&a, &g)
            + RistrettoPoint::multiscalar_mul(&b, &h)
            + u * ab,
        lhs_generators: g,
        rhs_generators: h,
        iner_product_generator: u,
    };
    let witness = (&a[..], &b[..]);

    let domain_separator =
        spongefish::domain_separator!("bulletproofs"; session = "spongefish examples")
            .instance(&instance);
    let mut prover_state = domain_separator.std_prover();
    let narg_string = BulletProof::prove(&mut prover_state, &instance, witness);
    println!(
        "Here's a bulletproof for {} elements:\n{}",
        size,
        hex::encode(narg_string)
    );

    let verifier_state = domain_separator.std_verifier(narg_string);
    BulletProof::verify(verifier_state, &instance).expect("Invalid proof")
}
