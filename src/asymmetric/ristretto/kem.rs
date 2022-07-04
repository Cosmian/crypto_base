use crate::{
    asymmetric::{ristretto::X25519Crypto, AsymmetricCrypto, KeyPair},
    hybrid_crypto::Kem,
    kdf::hkdf_256,
    CryptoBaseError, KeyTrait,
};
use rand_core::{CryptoRng, RngCore};
use std::convert::TryFrom;

const HKDF_INFO: &[u8; 21] = b"ecies-ristretto-25519";

impl Kem for X25519Crypto {
    type PublicKey = <<Self as AsymmetricCrypto>::KeyPair as KeyPair>::PublicKey;
    type PrivateKey = <<Self as AsymmetricCrypto>::KeyPair as KeyPair>::PrivateKey;

    type Keys = <Self as AsymmetricCrypto>::KeyPair;

    const ENCAPSULATION_SIZE: usize = Self::PublicKey::LENGTH;

    fn description() -> String {
        todo!()
    }

    fn key_gen<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Result<Self::Keys, CryptoBaseError> {
        Ok(Self::Keys::new(rng))
    }

    fn encaps<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        pk: &Self::PublicKey,
        sym_key_length: usize,
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoBaseError> {
        let ephemeral_keypair = self.key_gen(rng)?;

        // encapsulation
        let encapsulation = ephemeral_keypair.public_key().to_bytes();

        // shared secret
        let shared_secret = (pk * ephemeral_keypair.private_key()).to_bytes();

        // generate secret key
        let mut b = Vec::with_capacity(Self::PublicKey::LENGTH + Self::PrivateKey::LENGTH);
        b.extend(shared_secret);
        b.extend_from_slice(&encapsulation);
        let secret_key = hkdf_256(&b, sym_key_length, HKDF_INFO)?;
        Ok((secret_key, encapsulation))
    }

    fn decaps(
        &self,
        sk: &Self::PrivateKey,
        encapsulation: &[u8],
        sym_key_length: usize,
    ) -> Result<Vec<u8>, CryptoBaseError> {
        // case CheckMod = 1: the ciphertext should map to valid public key
        // compute the shared secret
        let h = Self::PublicKey::try_from(encapsulation)? * sk;

        // TODO: check `h` is not null -> implement `is_zero`
        let shared_secret = h.to_bytes();

        // generate secret key
        let mut b = [0u8; Self::PublicKey::LENGTH + Self::PrivateKey::LENGTH];
        b[..Self::PublicKey::LENGTH].clone_from_slice(&shared_secret);
        b[Self::PublicKey::LENGTH..].clone_from_slice(encapsulation);
        hkdf_256(&b, sym_key_length, HKDF_INFO)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        asymmetric::{ristretto::X25519Crypto, AsymmetricCrypto, KeyPair},
        entropy::CsRng,
        hybrid_crypto::Kem,
    };

    #[test]
    fn test_kem_x25519() {
        let mut rng = CsRng::new();
        let kem = X25519Crypto::new();
        let key_pair = kem.key_gen(&mut rng).expect("KeyGen failed");
        let (secret_key, encapsulation) = kem
            .encaps(&mut rng, key_pair.public_key(), 32)
            .expect("X25519 encaps failed");
        let res = kem
            .decaps(key_pair.private_key(), &encapsulation, 32)
            .expect("X25519 decaps failed");
        if secret_key != res {
            panic!("Wrong decapsulation!");
        }
    }
}
