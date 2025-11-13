/// Example: simple Schnorr proofs in <100 LOC
use ark_ec::{CurveGroup, PrimeGroup};
use ark_std::UniformRand;
use rand::rngs::OsRng;
use spongefish::{
    protocol_id, Codec, DomainSeparator, Encoding, NargDeserialize, NargSerialize, ProverState,
    VerificationError, VerificationResult, VerifierState,
};

struct Schnorr;

impl Schnorr {
    pub fn protocol_id() -> [u8; 64] {
        protocol_id(core::format_args!("schnorr proof"))
    }

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
        instance: &[G; 2],
        x: G::ScalarField,
    ) -> &'a [u8]
    where
        G: CurveGroup + NargSerialize + Encoding + Clone,
        G::ScalarField: Codec,
    {
        // `ProverState` types implement a cryptographically-secure random number generator.
        let k = G::ScalarField::rand(prover_state.rng());
        let K = instance[0].clone() * k;

        prover_state.prover_message(&K);
        let c = prover_state.verifier_message::<G::ScalarField>();

        let r = k + c * x;
        prover_state.prover_message(&r);

        prover_state.narg_string()
    }

    /// The verify algorithm takes as input
    /// - the verifier state `VerifierState`, that has access to a random oracle `H` and can deserialize/squeeze elements from the group `G`.
    /// - the secret key `witness`
    /// It returns a zero-knowledge proof of knowledge of `witness` as a sequence of bytes.
    #[allow(non_snake_case)]
    fn verify<G>(mut verifier_state: VerifierState, P: G, X: G) -> VerificationResult<()>
    where
        G: CurveGroup + NargDeserialize + Encoding,
        G::ScalarField: Codec,
    {
        let K = verifier_state.prover_message::<G>()?;
        let c = verifier_state.verifier_message::<G::ScalarField>();
        let r = verifier_state.prover_message::<G::ScalarField>()?;

        let relation_holds = P * r == K + X * c;
        if !relation_holds {
            return Err(VerificationError);
        }
        verifier_state.check_eof()?;
        Ok(())
    }
}

fn main() {
    type G = ark_curve25519::EdwardsProjective;
    type F = ark_curve25519::Fr;

    // Set up the elements to prove
    let generator = G::generator();
    let sk = F::rand(&mut OsRng);
    let pk = generator * sk;
    let instance = [generator, pk];

    let domain_sep = DomainSeparator::new(Schnorr::protocol_id())
        .session(spongefish::session!("spongefish examples"))
        .instance(&instance);

    // Prove the relation sk * G::generator() = pk
    let mut prover_state = domain_sep.std_prover();
    let narg_string = Schnorr::prove(&mut prover_state, &instance, sk);

    // Print out the hex-encoded schnorr proof.
    println!("Here's a Schnorr signature:\n{}", hex::encode(narg_string));

    // Verify the proof: create the verifier transcript, add the statement to it, and invoke the verifier.
    let verifier_state = domain_sep.std_verifier(narg_string);
    Schnorr::verify(verifier_state, instance[0].clone(), instance[1].clone())
        .expect("Verification failed");
}
