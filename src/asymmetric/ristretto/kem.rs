use crate::{
    asymmetric::{ristretto::X25519Crypto, AsymmetricCrypto, KeyPair},
    hybrid_crypto::Kem,
    kdf, CryptoBaseError, KeyTrait,
};
use rand_core::{CryptoRng, RngCore};
use std::convert::TryFrom;

const HKDF_INFO: &[u8; 21] = b"ecies-ristretto-25519";

impl Kem for X25519Crypto {
    type KeyPair = <Self as AsymmetricCrypto>::KeyPair;

    const ENCAPSULATION_SIZE: usize = <Self::KeyPair as KeyPair>::PublicKey::LENGTH;

    fn description() -> String {
        todo!()
    }

    fn key_gen<R: RngCore + CryptoRng>(rng: &mut R) -> Self::KeyPair {
        Self::KeyPair::new(rng)
    }

    fn encaps<R: RngCore + CryptoRng>(
        rng: &mut R,
        pk: &<Self::KeyPair as KeyPair>::PublicKey,
        secret_key_length: usize,
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoBaseError> {
        let ephemeral_keypair = Self::key_gen(rng);

        // encapsulation
        let encapsulation = ephemeral_keypair.public_key().to_bytes();

        // shared secret
        let shared_secret = (pk * ephemeral_keypair.private_key()).to_bytes();

        // generate secret key
        let mut b = Vec::with_capacity(
            <Self::KeyPair as KeyPair>::PublicKey::LENGTH
                + <Self::KeyPair as KeyPair>::PrivateKey::LENGTH,
        );
        b.extend(shared_secret);
        b.extend_from_slice(&encapsulation);
        let secret_key = kdf::hkdf_256(&b, secret_key_length, HKDF_INFO)?;
        Ok((secret_key, encapsulation))
    }

    fn decaps(
        sk: &<Self::KeyPair as KeyPair>::PrivateKey,
        encapsulation: &[u8],
        secret_key_length: usize,
    ) -> Result<Vec<u8>, CryptoBaseError> {
        // case CheckMod = 1: the ciphertext should map to valid public key
        // compute the shared secret
        let h = <Self::KeyPair as KeyPair>::PublicKey::try_from(encapsulation)? * sk;

        // TODO: check `h` is not null -> implement `is_zero`
        let shared_secret = h.to_bytes();

        // generate secret key
        let mut b = [0u8; <Self::KeyPair as KeyPair>::PublicKey::LENGTH
            + <Self::KeyPair as KeyPair>::PrivateKey::LENGTH];
        b[..<Self::KeyPair as KeyPair>::PublicKey::LENGTH].clone_from_slice(&shared_secret);
        b[<Self::KeyPair as KeyPair>::PublicKey::LENGTH..].clone_from_slice(encapsulation);
        kdf::hkdf_256(&b, secret_key_length, HKDF_INFO)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        asymmetric::{ristretto::X25519Crypto, KeyPair},
        entropy::CsRng,
        hybrid_crypto::Kem,
    };

    #[test]
    fn test_kem() {
        let mut rng = CsRng::new();
        let key_pair = X25519Crypto::key_gen(&mut rng);
        let (secret_key, encapsulation) = X25519Crypto::encaps(&mut rng, key_pair.public_key(), 32)
            .expect("X25519 encaps failed");
        let res = X25519Crypto::decaps(key_pair.private_key(), &encapsulation, 32)
            .expect("X25519 decaps failed");
        if secret_key != res {
            panic!("Wrong decapsulation!");
        }
    }
}
