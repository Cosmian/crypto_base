use aes::cipher::{generic_array::GenericArray, BlockEncrypt, NewBlockCipher};
// use aesni::stream_cipher::{NewStreamCipher, StreamCipher};
use aes::Aes256;

/// Using AES 256 as a hash function.
/// Implements the scheme of  S. Matyas, C. Meyer and J. Oseas
/// Hᵢ = E(Hᵢ₋₁, Xᵢ)^Xᵢ^Hᵢ₋₁ where the AES
/// encryption of plaintext X with key K will is denoted with E(K, X)
/// see https://www.esat.kuleuven.be/cosic/publications/article-48.pdf
/// Since the block size is 16 and we need to encrypt 32 bytes (top get a 256
/// bit hash) we use AES in counter mode to encrypt two blocks of 16 bytes
pub struct AesMmo {
    hash: [u8; 32],
    block: [u8; 32],
    block_offset: usize,
}

/// This is the routine implementing: Hᵢ = E(Hᵢ₋₁, Xᵢ)^Xᵢ^Hᵢ₋
/// The block must be 32 byte long
#[inline]
fn hash_block(block: &[u8; 32], hash: &mut [u8; 32]) {
    let mut b = [0_u8; 32];
    b.copy_from_slice(block);
    // since AES blocks are only 16 bytes long, we split the data to hash in 2
    let mut block_16 = GenericArray::clone_from_slice(&block[0..16]);
    // first 16 block
    let cipher = Aes256::new(GenericArray::from_slice(hash));
    cipher.encrypt_block(&mut block_16);
    for i in 0..16 {
        // calculate the new hash according to MMO
        hash[i] = block_16[i] ^ block[i] ^ hash[i + 16];
        // put last 16 bytes of input in block
        block_16[i] = block[i + 16];
    }
    // second 16 byte block - the "key" is now made of Hᵢ₋₁||Hᵢ₋₂
    let cipher = Aes256::new(GenericArray::from_slice(hash));
    cipher.encrypt_block(&mut block_16);
    for i in 16..32 {
        hash[i] = block_16[i - 16] ^ block[i] ^ hash[i - 16];
    }
}

impl AesMmo {
    /// Tests whether the AES native interface is available on this machine
    ///
    /// The BRC constrained PRF will NOT run if it is not available
    #[must_use]
    pub fn is_available() -> bool {
        crate::brc_c_prf_hi::aes_ni_available()
    }

    #[must_use]
    pub fn new(seed: &[u8; 32]) -> AesMmo {
        AesMmo {
            hash: *seed,
            block: [0_u8; 32],
            block_offset: 0,
        }
    }

    /// Digest data, updating the internal state.
    /// This method can be called repeatedly for use with streaming messages.
    pub fn update(&mut self, data: &[u8]) {
        let data_len = data.len();
        let mut data_offset = 0_usize;

        loop {
            let data_left = data_len - data_offset;
            let data_to_copy = if data_left >= 32 - self.block_offset {
                32 - self.block_offset
            } else {
                data_left
            };
            self.block[self.block_offset..self.block_offset + data_to_copy]
                .copy_from_slice(&data[data_offset..data_offset + data_to_copy]);
            data_offset += data_to_copy;
            self.block_offset += data_to_copy;
            if self.block_offset < 32 {
                return
            }
            hash_block(&self.block, &mut self.hash);
            // reset block
            self.block_offset = 0;
            self.block.copy_from_slice(&[0_u8; 32]);
        }
    }

    /// Retrieve result and consume hasher instance.
    #[must_use]
    pub fn finalize(&self) -> [u8; 32] {
        let mut hash = [0_u8; 32];
        hash.copy_from_slice(&self.hash);
        if self.block_offset > 0 {
            hash_block(&self.block, &mut hash);
        }
        hash
    }

    /// Convenience function to compute hash of the data.
    /// It will handle hasher creation, data feeding and finalization.
    #[must_use]
    pub fn digest(seed: &[u8; 32], data: &[u8]) -> [u8; 32] {
        let mut hasher = AesMmo::new(seed);
        hasher.update(data);
        hasher.finalize()
    }

    /// Convenience function to compute 2 hashes of the data.
    /// It will handle hasher creation, data feeding and finalization.
    #[must_use]
    pub fn digest2(seed: &[u8; 32], data: &[u8]) -> ([u8; 32], [u8; 32]) {
        let mut hasher = AesMmo::new(seed);
        hasher.update(data);
        let first_hash = hasher.finalize();
        let mut second_hash = first_hash;
        hash_block(&first_hash, &mut second_hash);
        assert_ne!(first_hash, second_hash);
        (first_hash, second_hash)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::time::Instant;

    use rand::{prelude::*, RngCore, SeedableRng};
    use rand_hc::Hc128Rng;

    use super::{super::sodium_bindings, AesMmo};

    pub(crate) fn blake2b(seed: &[u8; 32], data: &[u8]) -> [u8; 32] {
        let mut h = [0_u8; 32];
        unsafe {
            sodium_bindings::crypto_generichash_blake2b(
                h.as_mut_ptr(),
                32,
                data.as_ptr(),
                data.len() as u64,
                seed.as_ptr(),
                32,
            )
        };
        h
    }

    #[test]
    fn test_small_hash() {
        let mut cs_rng = Hc128Rng::from_entropy();
        let mut seed = [0_u8; 32];
        cs_rng.fill_bytes(&mut seed);
        //test two data of less than 256 nits has differently
        let h2 = AesMmo::digest(&seed, b"this is a second value");
        let h1 = AesMmo::digest(&seed, b"this is a first value");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_stable_hashing() {
        let mut cs_rng = Hc128Rng::from_entropy();
        let mut rng = rand::thread_rng();
        for _i in 0..1000 {
            // prepare random data of random length
            let data_len = rng.gen_range(48..12000);
            let mut data = vec![0_u8; data_len];
            cs_rng.fill_bytes(&mut data);
            // generate the seed
            let mut seed = [0_u8; 32];
            cs_rng.fill_bytes(&mut seed);
            // the data should have a 32 byte length
            let h1 = AesMmo::digest(&seed, &data);
            assert_eq!(32, h1.len());
            // when hashed twice with the same seed, results should be identical
            let h2 = AesMmo::digest(&seed, &data);
            assert_eq!(h1, h2);
            // when hashed in parts, the result should be identical
            let v1 = data[0..32].to_vec();
            let v2 = data[32..48].to_vec();
            let v3 = data[48..].to_vec();
            let mut hasher_2 = AesMmo::new(&seed);
            hasher_2.update(&v1);
            hasher_2.update(&v2);
            hasher_2.update(&v3);
            assert_eq!(h1, hasher_2.finalize());
            // two different seeds -> 2 different values (with very high probability)
            let mut seed3 = [0_u8; 32];
            cs_rng.fill_bytes(&mut seed3);
            let h3 = AesMmo::digest(&seed3, &data);
            debug_assert_ne!(h1, h3);
        }
    }

    #[test]
    #[ignore = "too slow for CI"]
    #[allow(unused_must_use)]
    fn bench_hash() {
        let mut cs_rng = Hc128Rng::from_entropy();

        // generate the seed
        let mut seed = [0_u8; 32];
        cs_rng.fill_bytes(&mut seed);

        for l in 1..17_u64 {
            // generate random data
            let data_len = 16 * l;
            let mut data = vec![0_u8; data_len as usize];
            cs_rng.fill_bytes(&mut data);

            let rounds = 500_000_u128;
            let mut nanos_aes = 0_u128;
            let mut nanos_sha256 = 0_u128;
            let mut nanos_blake = 0_u128;
            for _i in 0..rounds {
                let now = Instant::now();
                AesMmo::digest(&seed, &data);
                nanos_aes += now.elapsed().as_nanos();
                // compare with sha256 from sodium bindings
                let mut h = [0_u8; 32];
                let now = Instant::now();
                unsafe {
                    sodium_bindings::crypto_hash_sha256(h.as_mut_ptr(), data.as_ptr(), data_len)
                };
                nanos_sha256 += now.elapsed().as_nanos();
                // Blake2b
                let now = Instant::now();
                blake2b(&seed, &data);
                nanos_blake += now.elapsed().as_nanos();
            }
            println!(
                "Average over {} rounds of {} data bytes: nano per hash aes: {}; sha256 {}; \
                 blake: {}",
                rounds,
                16 * l,
                nanos_aes / rounds,
                nanos_sha256 / rounds,
                nanos_blake / rounds,
            )
        }
    }
}
