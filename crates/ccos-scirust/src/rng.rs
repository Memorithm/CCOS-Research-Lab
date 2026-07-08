//! Deterministic, dependency-free PRNG (SplitMix64) plus a Gaussian sampler.
//!
//! Used to generate reproducible random projections and synthetic activations
//! for the measurement prototype and tests. Deterministic seeding keeps every
//! reported number reproducible.

pub struct Rng {
    state: u64,
}

impl Rng {
    #[inline]
    pub fn new(seed: u64) -> Self {
        // Avoid the degenerate all-zero state.
        Rng {
            state: seed ^ 0x9E37_79B9_7F4A_7C15,
        }
    }

    /// SplitMix64 — fast, well-distributed 64-bit output.
    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform `f32` in `[0, 1)`.
    #[inline]
    pub fn next_unit(&mut self) -> f32 {
        // 24 random bits -> [0, 1).
        ((self.next_u64() >> 40) as f32) * (1.0 / (1u64 << 24) as f32)
    }

    /// Standard normal `N(0, 1)` via Box–Muller.
    #[inline]
    pub fn next_gaussian(&mut self) -> f32 {
        let u1 = self.next_unit().max(1.0e-7);
        let u2 = self.next_unit();
        let r = (-2.0 * u1.ln()).sqrt();
        r * (2.0 * std::f32::consts::PI * u2).cos()
    }

    /// Fill a slice with `N(0, 1)` samples.
    pub fn fill_gaussian(&mut self, out: &mut [f32]) {
        for v in out.iter_mut() {
            *v = self.next_gaussian();
        }
    }
}
