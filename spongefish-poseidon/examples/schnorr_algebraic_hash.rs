/// This code is pretty much the same as the one in `schnorr.rs`,
/// except for minor changes in order to work with algebraic hashes
/// over the scalar field of BLS12-381.
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::PrimeField;
use ark_std::UniformRand;
use spongefish::codecs::arkworks_algebra::*;

/// Extend the IO pattern with the Schnorr protocol.
trait SchnorrDomainSeparator<G: CurveGroup> {
    /// Adds the entire Schnorr protocol to the IO pattern (statement and proof).
    fn add_schnorr_domsep(self) -> Self;
}

impl<G, H, U> SchnorrDomainSeparator<G> for DomainSeparator<H, U>
where
    G: CurveGroup,
    U: Unit,
    H: DuplexSpongeInterface<U>,
    DomainSeparator<H, U>: GroupDomainSeparator<G> + ByteDomainSeparator,
{
    fn add_schnorr_domsep(self) -> Self {
        self.add_points(1, "generator (P)")
            .add_points(1, "public key (X)")
            .ratchet()
            .add_points(1, "commitment (K)")
            .challenge_bytes(16, "challenge (c)")
            .add_points(1, "response (r)")
    }
}

/// The key generation algorithm otuputs
/// a secret key `sk` in $\mathbb{Z}_p$
/// and its respective public key `pk` in $\mathbb{G}$.
fn keygen<G: CurveGroup>() -> (G::ScalarField, G) {
    let sk = G::ScalarField::rand(&mut spongefish::DefaultRng::default());
    let pk = G::generator() * sk;
    (sk, pk)
}

/// The prove algorithm takes as input
/// - the prover state `ProverState`, that has access to a random oracle `H` and can absorb/squeeze elements from the group `G`.
/// - The generator `P` in the group.
/// - the secret key $x \in \mathbb{Z}_p$
///
/// It returns a zero-knowledge proof of knowledge of `x` as a sequence of bytes.
#[allow(non_snake_case)]
fn prove<G, H, U>(
    // the hash function `H` works over bytes.
    // Algebraic hashes over a particular domain can be denoted with an additional type argument implementing `spongefish::Unit`.
    prover_state: &mut ProverState<H, U>,
    // the generator
    P: G,
    // the secret key
    x: G::ScalarField,
) -> ProofResult<&[u8]>
where
    U: Unit,
    G::BaseField: PrimeField,
    H: DuplexSpongeInterface<U>,
    G: CurveGroup,
    ProverState<H, U>: GroupToUnitSerialize<G> + FieldToUnitSerialize<G::BaseField> + UnitToBytes,
{
    // `ProverState` types implement a cryptographically-secure random number generator that is tied to the protocol transcript
    // and that can be accessed via the `rng()` function.
    let k = G::ScalarField::rand(prover_state.rng());
    let K = P * k;

    // Add a sequence of points to the protocol transcript.
    // An error is returned in case of failed serialization, or inconsistencies with the IO pattern provided (see below).
    prover_state.add_points(&[K])?;

    // Fetch a challenge from the current transcript state.
    let c_bytes = prover_state.challenge_bytes::<16>()?;
    let c = G::ScalarField::from_le_bytes_mod_order(&c_bytes);

    let r = k + c * x;
    let r_q = swap_field::<G::ScalarField, G::BaseField>(r)?;
    // Add a sequence of scalar elements to the protocol transcript.
    prover_state.add_scalars(&[r_q])?;

    // Output the current protocol transcript as a sequence of bytes.
    Ok(prover_state.narg_string())
}

/// The verify algorithm takes as input
/// - the verifier state `VerifierState`, that has access to a random oracle `H` and can deserialize/squeeze elements from the group `G`.
/// - the secret key `witness`
///
/// It returns a zero-knowledge proof of knowledge of `witness` as a sequence of bytes.
#[allow(non_snake_case)]
fn verify<'a, G, H, U>(
    // `ArkGroupMelin` contains the veirifier state, including the messages currently read. In addition, it is aware of the group `G`
    // from which it can serialize/deserialize elements.
    verifier_state: &mut VerifierState<'a, H, U>,
    // The group generator `P``
    P: G,
    // The public key `X`
    X: G,
) -> ProofResult<()>
where
    U: Unit,
    G::BaseField: PrimeField,
    G: CurveGroup,
    H: DuplexSpongeInterface<U>,
    VerifierState<'a, H, U>:
        GroupToUnitDeserialize<G> + FieldToUnitDeserialize<G::BaseField> + UnitToBytes,
{
    // Read the protocol from the transcript:
    let [K] = verifier_state.next_points()?;
    let c_bytes = verifier_state.challenge_bytes::<16>()?;
    let c = G::ScalarField::from_le_bytes_mod_order(&c_bytes);
    // Map the response to the field of the hash function to be absorbed easily.
    let [r_q] = verifier_state.next_scalars()?;
    let r = swap_field::<G::BaseField, G::ScalarField>(r_q)?;

    if P * r == K + X * c {
        Ok(())
    } else {
        Err(ProofError::InvalidProof)
    }

    // from here, another proof can be verified using the same prover state, and proofs can be composed.
}

#[allow(non_snake_case)]
fn main() {
    // Choose the group:
    type G = ark_bls12_381::G1Projective;

    // Set the hash function (commented out other valid choices):
    // type H = spongefish::hash::Keccak;
    type H = spongefish::duplex_sponge::legacy::DigestBridge<blake2::Blake2s256>;
    // type H = spongefish::hash::legacy::DigestBridge<sha2::Sha256>;
    // type H = spongefish_poseidon::PoseidonHash;

    // Unit type where the hash function works over.
    type U = u8;
    // type U = ark_bls12_381::Fq;

    // Set up the IO for the protocol transcript with domain separator "spongefish::examples::schnorr"
    let domain_separator = DomainSeparator::<H, U>::new("spongefish::examples::schnorr");
    let domain_separator = SchnorrDomainSeparator::<G>::add_schnorr_domsep(domain_separator);

    // Set up the elements to prove
    let P = G::generator();
    let (x, X) = keygen();

    // Create the prover transcript, add the statement to it, and then invoke the prover.
    let mut prover_state = domain_separator.to_prover_state();
    prover_state.public_points(&[P, X]).unwrap();
    prover_state.ratchet().unwrap();
    let proof = prove(&mut prover_state, P, x).expect("Invalid proof");

    // Print out the hex-encoded schnorr proof.
    println!("Here's a Schnorr signature:\n{}", hex::encode(proof));

    // Verify the proof: create the verifier transcript, add the statement to it, and invoke the verifier.
    let mut verifier_state = VerifierState::<H, U>::new(&domain_separator, proof);
    verifier_state.public_points(&[P, X]).unwrap();
    verifier_state.ratchet().unwrap();
    verify(&mut verifier_state, P, X).expect("Invalid proof");
}
