//! NARG security bounds combining IA/IR metadata with sponge parameters.

extern crate alloc;

use ia_core::{ProtocolSecurity, SecurityProfile};

use super::params::{SpongeParams, STD_SPONGE_PARAMS};

/// Final NARG security profile after applying DSFS to an IA/IR.
#[derive(Debug, Clone)]
pub struct NargSecurity {
    pub ia: SecurityProfile,
    pub sponge: SpongeParams,
}

/// NARG security for a protocol under the standard sponge.
pub fn security<P: ProtocolSecurity>(p: &P) -> NargSecurity {
    NargSecurity::for_protocol(p)
}

/// NARG security for an interactive reduction under the standard sponge.
pub fn reduction_security<P: ProtocolSecurity>(p: &P) -> NargSecurity {
    NargSecurity::for_protocol(p)
}

impl NargSecurity {
    /// Security for a protocol under the standard sponge.
    pub fn for_protocol<P: ProtocolSecurity>(p: &P) -> Self {
        Self { ia: p.security(), sponge: STD_SPONGE_PARAMS }
    }

    /// Security for a protocol under a custom sponge configuration.
    pub fn for_protocol_with<P: ProtocolSecurity>(p: &P, sponge: SpongeParams) -> Self {
        Self { ia: p.security(), sponge }
    }

    /// Security for an IA under the standard sponge.
    pub fn for_ia<IA: ProtocolSecurity>(ia: &IA) -> Self {
        Self { ia: ia.security(), sponge: STD_SPONGE_PARAMS }
    }

    /// Security for an IR under the standard sponge.
    pub fn for_reduction<IR: ProtocolSecurity>(ir: &IR) -> Self {
        Self { ia: ir.security(), sponge: STD_SPONGE_PARAMS }
    }

    /// Security for an IA under a custom sponge configuration.
    pub fn for_ia_with<IA: ProtocolSecurity>(ia: &IA, sponge: SpongeParams) -> Self {
        Self { ia: ia.security(), sponge }
    }

    /// Security for an IR under a custom sponge configuration.
    pub fn for_reduction_with<IR: ProtocolSecurity>(ir: &IR, sponge: SpongeParams) -> Self {
        Self { ia: ir.security(), sponge }
    }

    /// Theorem 6.1: `eps_narg(t) <= eps_sr_ip(t) + 25*t^2/|Sigma|^c`.
    ///
    /// SR soundness is derived from the per-round RBR errors.
    pub fn soundness_error(&self, t: u64) -> f64 {
        let t_f = t as f64;
        self.ia.sr_soundness_error(t)
            + 25.0 * t_f * t_f / self.sponge_sigma_to(self.sponge.capacity)
    }

    /// Theorem 6.2: `kappa_narg(t) <= kappa_sr_ip(t) + 25*t^2/|Sigma|^c`.
    pub fn knowledge_soundness_error(&self, t: u64) -> f64 {
        let t_f = t as f64;
        self.ia.sr_knowledge_soundness_error(t)
            + 25.0 * t_f * t_f / self.sponge_sigma_to(self.sponge.capacity)
    }

    /// Theorem 7.1: `z_narg(t) <= z_ip(t) + t/|Sigma|^min(delta,c) + t*sum_i ceil(lV(i)/r)/|Sigma|^(r+c)`.
    pub fn zk_error(&self, t: u64) -> f64 {
        let t_f = t as f64;
        let min_delta_c = self.sponge.delta.min(self.sponge.capacity);
        let challenge_blocks: u64 = self
            .ia
            .verifier_challenge_lengths
            .iter()
            .map(|&l_vi| (l_vi as u64).div_ceil(self.sponge.rate))
            .sum();

        self.ia.hvzk_error.evaluate(t)
            + t_f / self.sponge_sigma_to(min_delta_c)
            + t_f * challenge_blocks as f64
                / self.sponge_sigma_to(self.sponge.rate + self.sponge.capacity)
    }

    pub fn soundness_bits(&self, t: u64) -> f64 {
        -self.soundness_error(t).log2()
    }

    pub fn knowledge_soundness_bits(&self, t: u64) -> f64 {
        -self.knowledge_soundness_error(t).log2()
    }

    pub fn zk_bits(&self, t: u64) -> f64 {
        -self.zk_error(t).log2()
    }

    fn sponge_sigma_to(&self, exponent: u64) -> f64 {
        self.sponge.alphabet_size.powf(exponent as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::NargSecurity;
    use super::super::params::SpongeParams;
    use ia_core::{SecurityErrorBound, SecurityProfile};

    /// Helper: build a profile with uniform per-round RBR error.
    fn profile_with_rbr(
        rbr_per_round: fn(u64) -> f64,
        num_rounds: usize,
        knowledge_soundness: fn(u64) -> f64,
        hvzk: fn(u64) -> f64,
        challenge_lengths: alloc::vec::Vec<usize>,
    ) -> SecurityProfile {
        SecurityProfile {
            plain_soundness_error: SecurityErrorBound::zero(),
            rbr_soundness_errors: (0..num_rounds)
                .map(|_| SecurityErrorBound::new(rbr_per_round))
                .collect(),
            rbr_knowledge_soundness_errors: (0..num_rounds)
                .map(|_| SecurityErrorBound::new(knowledge_soundness))
                .collect(),
            hvzk_error: SecurityErrorBound::new(hvzk),
            verifier_challenge_lengths: challenge_lengths,
        }
    }

    #[test]
    fn theorem1_bounds_are_applied() {
        let sec = NargSecurity {
            ia: profile_with_rbr(
                |_t| 0.005, // 2 rounds * 0.005 = 0.01 SR soundness
                2,
                |_t| 0.02,
                |_t| 0.03,
                alloc::vec![5, 7],
            ),
            sponge: SpongeParams {
                alphabet_size: 2.0,
                capacity: 4,
                rate: 3,
                delta: 2,
            },
        };

        let t = 2_u64;
        let additive = 25.0 * (t as f64) * (t as f64) / 2_f64.powf(4.0);
        // SR soundness (CY24 Thm 31.2.1 tighter form): t*max + sum = 2*0.005 + 0.01 = 0.02
        assert!((sec.soundness_error(t) - (0.02 + additive)).abs() < 1e-12);
        // SR knowledge (CY24 Thm 31.3.1 tighter form): 2 rounds of 0.02 each
        // t*max + sum = 2*0.02 + (0.02+0.02) = 0.04 + 0.04 = 0.08
        assert!((sec.knowledge_soundness_error(t) - (0.08 + additive)).abs() < 1e-12);
    }

    #[test]
    fn theorem1_with_t_dependent_ia_error() {
        fn ia_rbr_soundness(t: u64) -> f64 {
            (t as f64) / 1_000_000.0
        }

        let sec = NargSecurity {
            // 1 round with RBR error = t/1M, so SR soundness = t/1M
            ia: profile_with_rbr(ia_rbr_soundness, 1, |_| 0.0, |_| 0.0, alloc::vec![1]),
            sponge: SpongeParams {
                alphabet_size: 256.0,
                capacity: 2,
                rate: 2,
                delta: 1,
            },
        };

        let t = 100_u64;
        // 1 round, rbr(100) = 100/1M. SR = t*max + sum = 100*(100/1M) + 100/1M = 10100/1M
        let expected_ia = 10100.0 / 1_000_000.0;
        let expected_sponge = 25.0 * 100.0 * 100.0 / 256.0_f64.powf(2.0);
        assert!((sec.soundness_error(t) - (expected_ia + expected_sponge)).abs() < 1e-12);
    }

    #[test]
    fn theorem2_bound_is_applied() {
        let sec = NargSecurity {
            ia: profile_with_rbr(|_| 0.0, 2, |_| 0.0, |_t| 0.125, alloc::vec![5, 7]),
            sponge: SpongeParams {
                alphabet_size: 2.0,
                capacity: 4,
                rate: 3,
                delta: 2,
            },
        };

        let t = 2_u64;
        // ceil(5/3) + ceil(7/3) = 2 + 3 = 5.
        let expected = 0.125 + 2.0 / 2_f64.powf(2.0) + 2.0 * 5.0 / 2_f64.powf(7.0);
        assert!((sec.zk_error(t) - expected).abs() < 1e-12);
    }

    #[test]
    fn security_error_bound_composes_additively() {
        let a = SecurityErrorBound::new(|t| t as f64);
        let b = SecurityErrorBound::new(|t| 2.0 * t as f64);
        let c = a.compose(&b);
        assert!((c.evaluate(10) - 30.0).abs() < 1e-12);
    }

    #[test]
    fn sr_soundness_derived_from_rbr() {
        let profile = SecurityProfile {
            plain_soundness_error: SecurityErrorBound::zero(),
            rbr_soundness_errors: alloc::vec![
                SecurityErrorBound::new(|_| 0.01),
                SecurityErrorBound::new(|_| 0.02),
                SecurityErrorBound::new(|_| 0.03),
            ],
            rbr_knowledge_soundness_errors: alloc::vec![],
            hvzk_error: SecurityErrorBound::zero(),
            verifier_challenge_lengths: alloc::vec![1, 1, 1],
        };
        // At t=0: SR = 0 * max + sum = 0.01 + 0.02 + 0.03 = 0.06
        assert!((profile.sr_soundness_error(0) - 0.06).abs() < 1e-12);
        // At t=10: SR = 10 * 0.03 + 0.06 = 0.36
        assert!((profile.sr_soundness_error(10) - 0.36).abs() < 1e-12);
    }

    #[test]
    fn rbr_composition_derives_correct_sr() {
        let p1 = SecurityProfile {
            plain_soundness_error: SecurityErrorBound::new(|_| 0.01),
            rbr_soundness_errors: alloc::vec![
                SecurityErrorBound::new(|_| 0.005),
                SecurityErrorBound::new(|_| 0.005),
            ],
            rbr_knowledge_soundness_errors: alloc::vec![
                SecurityErrorBound::new(|_| 0.005),
                SecurityErrorBound::new(|_| 0.005),
            ],
            hvzk_error: SecurityErrorBound::zero(),
            verifier_challenge_lengths: alloc::vec![1, 1],
        };
        let p2 = SecurityProfile {
            plain_soundness_error: SecurityErrorBound::new(|_| 0.02),
            rbr_soundness_errors: alloc::vec![SecurityErrorBound::new(|_| 0.02)],
            rbr_knowledge_soundness_errors: alloc::vec![SecurityErrorBound::new(|_| 0.02)],
            hvzk_error: SecurityErrorBound::zero(),
            verifier_challenge_lengths: alloc::vec![1],
        };
        let composed = p1.compose(&p2);

        // RBR vectors concatenated
        assert_eq!(composed.rbr_soundness_errors.len(), 3);
        assert_eq!(composed.num_rounds(), 3);

        // At t=0: SR soundness = 0 * max + sum = 0.005 + 0.005 + 0.02 = 0.03
        assert!((composed.sr_soundness_error(0) - 0.03).abs() < 1e-12);
        // At t=5: SR soundness = 5 * 0.02 + 0.03 = 0.13
        assert!((composed.sr_soundness_error(5) - 0.13).abs() < 1e-12);

        // RBR knowledge vectors also concatenated (same values)
        assert_eq!(composed.rbr_knowledge_soundness_errors.len(), 3);
        // At t=0: SR knowledge = 0 * max + sum = 0.03
        assert!((composed.sr_knowledge_soundness_error(0) - 0.03).abs() < 1e-12);
        // At t=5: SR knowledge = 5 * 0.02 + 0.03 = 0.13
        assert!((composed.sr_knowledge_soundness_error(5) - 0.13).abs() < 1e-12);

        // Plain soundness composed via union bound: 0.01 + 0.02 = 0.03
        assert!((composed.plain_soundness_error.evaluate(0) - 0.03).abs() < 1e-12);
    }
}
