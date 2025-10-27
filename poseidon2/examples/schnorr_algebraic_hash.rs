/// Schnorr signature example using Poseidon hash over BLS12-381.
///
/// This example demonstrates using the Poseidon algebraic hash function
/// (which implements DuplexSpongeInterface) for Schnorr signatures.
use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{Field, PrimeField, Zero};
use ark_std::UniformRand;
use spongefish::DuplexSpongeInterface;
use spongefish_poseidon::bls12_381::Poseidonx5_255_3;

/// Generate a key pair (secret key, public key)
fn keygen() -> (Fr, G1Affine) {
    let mut rng = ark_std::test_rng();
    let sk = Fr::rand(&mut rng);
    let pk = (G1Projective::generator() * sk).into();
    (sk, pk)
}

/// Create a Schnorr signature/proof using Poseidon hash
fn prove<H>(hash: &mut H, sk: &Fr, pk: &G1Affine) -> (G1Affine, Fr)
where
    H: DuplexSpongeInterface<U = Fr>,
{
    let mut rng = ark_std::test_rng();

    // Generate random nonce
    let k = Fr::rand(&mut rng);
    let r_point: G1Affine = (G1Projective::generator() * k).into();

    // Hash the commitment point coordinates
    // We'll absorb the x and y coordinates as field elements
    hash.absorb(&[r_point.x, r_point.y]);

    // Add public key to the hash
    hash.absorb(&[pk.x, pk.y]);

    // Squeeze challenge
    let mut challenge = [Fr::zero()];
    hash.squeeze(&mut challenge);
    let c = challenge[0];

    // Compute response s = k + c * sk
    let s = k + c * sk;

    (r_point, s)
}

/// Verify a Schnorr signature using Poseidon hash
fn verify<H>(hash: &mut H, pk: &G1Affine, signature: (G1Affine, Fr)) -> bool
where
    H: DuplexSpongeInterface<U = Fr>,
{
    let (r_point, s) = signature;

    // Recreate challenge using same hash process
    hash.absorb(&[r_point.x, r_point.y]);
    hash.absorb(&[pk.x, pk.y]);

    let mut challenge = [Fr::zero()];
    hash.squeeze(&mut challenge);
    let c = challenge[0];

    // Verify equation: s*G = r + c*pk
    let lhs = G1Projective::generator() * s;
    let rhs: G1Projective = r_point.into();
    let pk_proj: G1Projective = (*pk).into();
    let rhs = rhs + (pk_proj * c);

    lhs == rhs
}

fn main() {
    println!("Schnorr Signature Example using Poseidon Hash");
    println!("=============================================\n");

    // Generate keys
    let (sk, pk) = keygen();
    println!("Generated key pair");
    println!("  Secret key: {:?}", sk);
    println!("  Public key x: {:?}", pk.x);
    println!("  Public key y: {:?}", pk.y);

    // Create a Poseidon hash instance for proving
    let mut prover_hash = Poseidonx5_255_3::new();

    // Create signature
    let signature = prove(&mut prover_hash, &sk, &pk);
    println!("\nCreated signature:");
    println!("  R.x: {:?}", signature.0.x);
    println!("  R.y: {:?}", signature.0.y);
    println!("  s: {:?}", signature.1);

    // Create a fresh Poseidon hash instance for verification
    let mut verifier_hash = Poseidonx5_255_3::new();

    // Verify signature
    let is_valid = verify(&mut verifier_hash, &pk, signature);
    println!("\nSignature valid: {}", is_valid);

    // Try to verify with a different public key (should fail)
    let (_, wrong_pk) = keygen();
    let mut wrong_verifier_hash = Poseidonx5_255_3::new();
    let is_valid_wrong = verify(&mut wrong_verifier_hash, &wrong_pk, signature);
    println!("Signature valid for wrong public key: {}", is_valid_wrong);

    println!("\nExample completed successfully!");
}
