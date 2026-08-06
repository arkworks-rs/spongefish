/// Example: simple Schnorr proofs in <100 LOC
use ark_ec::{CurveGroup, PrimeGroup};
use ark_std::UniformRand;
use spongefish::{
    Codec, Encoding, NargDeserialize, NargSerialize, PrivateRng, ProverState, VerificationError,
    VerificationResult, VerifierState,
};

struct Schnorr;

/// Adapts [`PrivateRng`] to arkworks' rand 0.8 trait.
struct ArkRng<'a>(&'a mut PrivateRng);

impl ark_std::rand::RngCore for ArkRng<'_> {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.0.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.0.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), ark_std::rand::Error> {
        self.0.fill_bytes(dest);
        Ok(())
    }
}

impl Schnorr {
    /// Here the proving algorithm takes as input a [`ProverState`], and an instance-witness pair.
    ///
    /// The prover messages are group elements (denoted [G][`ark_ec::CurveGroup`]) and elements in
    /// the scalar field ([G::ScalarField][ark_ff::Field]).
    /// Both are required to implement [`Encoding`], which for bytes also tells us how to serialize them.
    /// The verifier messages are scalars, and thus required to implement [`Decoding`][spongefish::Decoding].
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
        // `ProverState` carries a cryptographically-secure private RNG; `sample`
        // draws a uniformly-distributed scalar through its `Decoding` codec.
        let k = prover_state.rng().sample::<G::ScalarField>();
        let K = instance[0] * k;

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

    // The session identifier binds the proof to the protocol and application context.
    let session_id =
        spongefish::derive_session_id::<spongefish::StdHash>(b"spongefish examples/schnorr proof");

    // Set up the elements to prove
    let generator = G::generator();
    let mut rng = PrivateRng::from_os_entropy();
    let sk = F::rand(&mut ArkRng(&mut rng));
    let pk = generator * sk;
    let instance = [generator, pk];

    // Prove the relation sk * G::generator() = pk
    let mut prover_state = ProverState::new(&session_id, &instance);
    let narg_string = Schnorr::prove(&mut prover_state, &instance, sk);

    // Print out the hex-encoded schnorr proof.
    println!("Here's a Schnorr signature:\n{}", hex::encode(narg_string));

    // Verify the proof: create the verifier transcript, add the statement to it, and invoke the verifier.
    let verifier_state = VerifierState::new(&session_id, &instance, narg_string);
    Schnorr::verify(verifier_state, instance[0], instance[1]).expect("Verification failed");
}
