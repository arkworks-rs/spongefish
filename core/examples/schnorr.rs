/// Example: simple Schnorr proofs in <100 LOC
use ark_ec::{CurveGroup, PrimeGroup};
use ark_std::UniformRand;
use rand::rngs::OsRng;
use spongefish::{Encoding, Decoding, NargDeserialize, ProverState, VerifierState, VerificationError, VerificationResult};

/// Here the proving algorithm takes as input a [`ProverState`], and an instance-witness pair.
///
/// The [`ProverState`] actually depends on a duplex sponge interface (over any field) and a random number generator.
/// By default, it relies on [`spongefish::DefaultHash`] (which is over [`u8`] and [`rand::rngs::StdRng`]).
///
/// The prover messages are group element (denoted [G][`ark_ec::CurveGroup`]) and elements in the scalar field ([G::ScalarField][ark_ff::Field]).
/// Both are required to implement [`Encoding`], which for bytes also tells us how to serialize them.
/// The verifier messages are scalars, and thus required to implement [`Decoding`].
#[allow(non_snake_case)]
fn prove<'a, G>(
    prover_state: &'a mut ProverState,
    P: G,    // the secret key
    x: G::ScalarField,
) -> &'a [u8]
where
    G: CurveGroup + Encoding<[u8]>,
    G::ScalarField: Encoding<[u8]> + Decoding<[u8]>
{
    // `ProverState` types implement a cryptographically-secure random number generator that is tied to the protocol transcript
    // and that can be accessed via the `rng()` function.
    let k = G::ScalarField::rand(prover_state.rng());
    let K = P * k;

    // Add a sequence of points to the protocol transcript.
    // An error is returned in case of failed serialization, or inconsistencies with the domain separator provided (see below).
    prover_state.prover_message(&K);

    // Fetch a challenge from the current transcript state.
    let c = prover_state.verifier_message::<G::ScalarField>();

    let r = k + c * x;
    // Add a sequence of scalar elements to the protocol transcript.
    prover_state.prover_message(&r);

    // Output the current protocol transcript as a sequence of bytes.
    prover_state.narg_string()
}

/// The verify algorithm takes as input
/// - the verifier state `VerifierState`, that has access to a random oracle `H` and can deserialize/squeeze elements from the group `G`.
/// - the secret key `witness`
/// It returns a zero-knowledge proof of knowledge of `witness` as a sequence of bytes.
#[allow(non_snake_case)]
fn verify<G>(
    verifier_state: &mut VerifierState,
    P: G,
    X: G,
) -> VerificationResult<()>
where
    G: CurveGroup + Encoding + NargDeserialize,
    G::ScalarField: Encoding + NargDeserialize + Decoding
{
    let K = verifier_state.prover_message::<G>()?;
    let c = verifier_state.verifier_message::<G::ScalarField>();
    let r = verifier_state.prover_message::<G::ScalarField>()?;

    if P * r == K + X * c {
        Ok(())
    } else {
        *VerificationError
    }
}

fn main() {
    type G = ark_curve25519::EdwardsProjective;
    type F = ark_curve25519::Fr;

    // Set up the elements to prove
    let generator = G::generator();
    let sk = F::rand(&mut OsRng);
    let pk = generator * sk;

    let protocol_id = [0u8; 32];
    let session_id = [0u8; 32];
    // Create the prover transcript, add the statement to it, and then invoke the prover.
    let mut prover_state = ProverState::new(protocol_id, session_id);
    prover_state.public_message(&[generator, pk]);
    let narg_string = prove(&mut prover_state, generator, sk);

    // Print out the hex-encoded schnorr proof.
    println!("Here's a Schnorr signature:\n{}", hex::encode(narg_string));

    // Verify the proof: create the verifier transcript, add the statement to it, and invoke the verifier.
    let mut verifier_state = VerifierState::new(protocol_id, session_id, narg_string);
    verifier_state.public_message(&[generator, pk]);
    verify(&mut verifier_state, generator, pk).expect("Verification failed");
}
