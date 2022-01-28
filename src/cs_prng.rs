use num_bigint::{BigInt, BigUint};
use rand::{Rng, RngCore, SeedableRng};
use rand_distr::StandardNormal;
use rand_hc::Hc128Rng;

/// A Cryptographically secure pseudo-random number generator
/// based on HC128 that generates `BigUint` on a uniform distribution
pub struct Uniform {
    rng: Hc128Rng,
}

impl Uniform {
    /// Instantiate a new cryptographically secure pseudo-random number
    /// generator
    // based on HC128
    #[must_use]
    pub fn new() -> Uniform {
        Uniform {
            rng: Hc128Rng::from_entropy(),
        }
    }

    /// Generate a Big Unsigned Integer
    /// of length at most `bits` from an Uniform distribution
    pub fn big_uint(&mut self, bits: usize) -> BigUint {
        let full_bytes = bits / 8;
        let rem = bits - full_bytes * 8;
        let num_bytes = full_bytes + (rem > 0) as usize;
        let mask: u8 = std::u8::MAX >> ((8 - rem) % 8);
        let mut bytes = vec![0_u8; num_bytes];
        self.rng.fill_bytes(&mut bytes);
        // apply mask
        bytes[0] &= mask;
        BigUint::from_bytes_be(&bytes)
    }

    /// Generate a Big Unsigned Integer
    /// strictly lower than the passed value `q`
    ///
    /// Note: the generation is not constant time but the timing
    /// does not reveal anything about the returned value
    pub fn big_uint_below(&mut self, q: &BigUint) -> BigUint {
        let bits = q.bits() as usize;
        loop {
            let r = self.big_uint(bits);
            if &r < q {
                return r;
            }
        }
    }
}

impl Default for Uniform {
    fn default() -> Self {
        Uniform {
            rng: Hc128Rng::from_entropy(),
        }
    }
}

// split the 127 bits of an i28 on 8 sigmas
// (probability of values outside this range is negligible)
const SIGMA_128: i128 = std::i128::MAX >> 3;
const SIGMA_128_F64: f64 = SIGMA_128 as f64;

/// A Cryptographically secure pseudo-random number generator
/// based on HC128 that generates `BigInt` on a normal/Gaussian distribution
pub struct Normal {
    rng: Hc128Rng,
    mean: BigInt,
    std_dev: BigInt,
}

impl Normal {
    /// Instantiate a new cryptographically secure pseudo-random number
    /// generator
    // based on ChaCha20
    #[must_use]
    pub fn new(mean: &BigInt, std_dev: &BigUint) -> Normal {
        Normal {
            rng: Hc128Rng::from_entropy(),
            mean: mean.clone(),
            std_dev: std_dev.clone().into(),
        }
    }

    /// Generate a Big (signed) Integer
    /// from a Normal distribution
    pub fn big_int(&mut self) -> BigInt {
        let f: f64 = self.rng.sample(StandardNormal);
        let scale = (SIGMA_128_F64 * f) as i128;
        // this HAS to be slow
        (&self.std_dev * scale) / SIGMA_128 + &self.mean
    }

    /// Generate a Big Unsigned Integer modulo q
    /// from a Normal distribution
    pub fn big_uint(&mut self, q: &BigUint) -> BigUint {
        let q_int: BigInt = q.clone().into();
        // this HAS to be VERY slow
        let i = self.big_int();
        let ui: BigInt = (&i % &q_int + &q_int) % &q_int;
        ui.to_biguint().expect("Something is very wrong here")
    }
}

#[cfg(test)]
mod tests {

    use num_bigint::{BigInt, BigUint};
    use num_traits::Pow;
    use retry_panic::retry_panic;

    use super::{Normal, Uniform};

    #[test]
    fn test_big_int() {
        let n = 1_u64 << 63;
        let p = 1_u64 << 32;
        let v: u64 = 1_u64 << 63;
        let mut k = BigUint::from(n);
        k *= p;
        k *= v;
        assert_eq!(
            k.to_u32_digits(),
            vec![0, 0, 0, 0, 0b_0100_0000_0000_0000_0000_0000_0000_0000]
        );
    }

    #[test]
    fn test_random_big_int() {
        let bits = 100_u64;
        let max_val = Pow::pow(&BigUint::from(2_u32), bits);
        let mut rng = Uniform::new();
        for _i in 0..1_000_000 {
            let v = rng.big_uint(bits as usize);
            // println!(
            //     "bits: {}, v: {},  max-v: {}",
            //     v.bits(),
            //     &v.clone(),
            //     max_val.clone() - v.clone()
            // );
            assert!(v < max_val);
            assert!(v.bits() <= bits);
        }
    }

    #[test]
    fn test_random_big_int_below() {
        let bits = 256_usize;
        let mut rng = Uniform::new();
        let q = rng.big_uint(bits);
        for _i in 0..10000 {
            let v = rng.big_uint_below(&q);
            assert!(v < q);
        }
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn test_normal_big_int() {
        let mean = BigInt::from(0_u32);
        let std_dev = Uniform::new().big_uint(256);
        let mut rng = Normal::new(&mean, &std_dev);
        let one_std_dev: BigInt = std_dev.clone().into();
        let two_std_dev: BigInt = &one_std_dev * 2;
        let three_std_dev: BigInt = &one_std_dev * 3;
        let mut counter_1 = 0_usize;
        let mut counter_2 = 0_usize;
        let mut counter_3 = 0_usize;
        const FACTOR: usize = 5;
        for _i in 0..FACTOR * 100_000_usize {
            let v = &rng.big_int();
            if v > &-(&one_std_dev) && v < &one_std_dev {
                counter_1 += 1;
                counter_2 += 1;
                counter_3 += 1;
            } else if v > &-&two_std_dev && v < &two_std_dev {
                counter_2 += 1;
                counter_3 += 1;
            } else if v > &-&three_std_dev && v < &three_std_dev {
                counter_3 += 1;
            }
        }
        // println!("σ: [{} bits] {}", std_dev.bits(), &std_dev);
        // println!(
        //     "<σ: {} <2σ: {} <3σ: {}",
        //     counter_1 / FACTOR,
        //     counter_2 / FACTOR,
        //     counter_3 / FACTOR
        // );

        // three sigma rule
        assert!(counter_1 > 68070 * FACTOR && counter_1 < 68470 * FACTOR);
        assert!(counter_2 > 95250 * FACTOR && counter_2 < 95650 * FACTOR);
        assert!(counter_3 > 99530 * FACTOR && counter_3 < 99930 * FACTOR);
    }

    #[retry_panic]
    #[test]
    fn test_normal_big_uint_mod_q() {
        let mean = BigInt::from(0_u32);
        let std_dev = Uniform::new().big_uint(100);
        let q = BigUint::from((1_u128 << 127) - 1);
        let mut rng = Normal::new(&mean, &std_dev);
        let two_std_dev: BigUint = &std_dev * 2_u32;
        let three_std_dev: BigUint = &std_dev * 3_u32;
        let mut counter_1 = 0_usize;
        let mut counter_2 = 0_usize;
        let mut counter_3 = 0_usize;
        const FACTOR: usize = 3;
        for _i in 0..FACTOR * 100_000_usize {
            let v = &rng.big_uint(&q);
            assert!(v < &q, "the value should be less than the modulo");
            if v < &std_dev || v > &(&q - &std_dev) {
                counter_1 += 1;
                counter_2 += 1;
                counter_3 += 1;
            } else if v < &two_std_dev || v > &(&q - &two_std_dev) {
                counter_2 += 1;
                counter_3 += 1;
            } else if v < &three_std_dev || v > &(&q - &three_std_dev) {
                counter_3 += 1;
            }
        }
        // println!("σ: [{} bits] {}", std_dev.bits(), &std_dev);
        // println!(
        //     "<σ: {} <2σ: {} <3σ: {}",
        //     counter_1 / FACTOR,
        //     counter_2 / FACTOR,
        //     counter_3 / FACTOR
        // );

        // three sigma rule
        assert!(counter_1 > 68070 * FACTOR && counter_1 < 68470 * FACTOR);
        assert!(counter_2 > 95250 * FACTOR && counter_2 < 95650 * FACTOR);
        assert!(counter_3 > 99530 * FACTOR && counter_3 < 99930 * FACTOR);
    }
}
