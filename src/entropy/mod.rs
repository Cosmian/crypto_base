use rand::{RngCore as _, SeedableRng};
use rand_core::{CryptoRng, RngCore};
use rand_hc::Hc128Rng;

#[derive(Debug)]
pub struct CsRng {
    rng: Hc128Rng,
}

impl CsRng {
    #[must_use]
    pub fn new() -> Self {
        Self {
            rng: Hc128Rng::from_entropy(),
        }
    }

    /// Generate an vector of random bytes
    pub fn generate_random_bytes(&mut self, len: usize) -> Vec<u8> {
        let mut bytes = vec![0_u8; len];
        self.rng.fill_bytes(&mut bytes);
        bytes
    }
}

impl Default for CsRng {
    fn default() -> Self {
        Self::new()
    }
}

impl RngCore for CsRng {
    fn next_u32(&mut self) -> u32 {
        self.rng.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.rng.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.rng.try_fill_bytes(dest).map_err(rand_core::Error::new)
    }
}
impl CryptoRng for CsRng {}

#[must_use]
pub fn new_uid() -> [u8; 32] {
    let mut rng = CsRng::new();
    let mut v = [0_u8; 32];
    rng.fill_bytes(&mut v);
    v
}

/// PRNG for bytes array
pub fn gen_bytes(output: &mut [u8]) -> anyhow::Result<()> {
    let mut rng = CsRng::new();
    anyhow::ensure!(
        !output.is_empty(),
        "Entropy generation failed: output empty!"
    );

    rng.fill_bytes(output);
    Ok(())
}
