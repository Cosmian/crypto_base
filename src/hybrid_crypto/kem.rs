use crate::{
    asymmetric::{
        ristretto::{X25519Crypto, X25519PrivateKey, X25519PublicKey},
        AsymmetricCrypto, KeyPair,
    },
    hybrid_crypto::{Error, Kem},
    kdf,
    symmetric_crypto::{aes_256_gcm_pure::Aes256GcmCrypto, Nonce, SymmetricCrypto},
    Key,
};
use std::convert::TryFrom;

const HKDF_INFO: &[u8; 21] = b"ecies-ristretto-25519";

pub struct ElGammalKemAesX25519 {
    x25519_scheme: X25519Crypto,
}

impl Kem<X25519Crypto> for ElGammalKemAesX25519 {
    type CipherText = Vec<u8>;
    type SecretKey = Vec<u8>;

    fn new() -> Self {
        ElGammalKemAesX25519 {
            x25519_scheme: X25519Crypto::new(),
        }
    }

    fn description(&self) -> String {
        todo!()
    }

    fn key_gen(&self) -> <X25519Crypto as AsymmetricCrypto>::KeyPair {
        <X25519Crypto as AsymmetricCrypto>::KeyPair::new(&self.x25519_scheme.rng)
    }

    fn encaps(
        &self,
        pk: &<<X25519Crypto as AsymmetricCrypto>::KeyPair as KeyPair>::PublicKey,
    ) -> Result<(Self::CipherText, Self::SecretKey), Error> {
        let ephemeral_keypair = self.key_gen();

        // KEM ciphertext
        let C0 = ephemeral_keypair.public_key().as_bytes();

        // shared secret
        let PEH = (pk * ephemeral_keypair.private_key()).as_bytes();

        // generate symmetric key
        let mut b = [0u8; X25519PublicKey::LENGTH + X25519PrivateKey::LENGTH];
        b[..X25519PublicKey::LENGTH].clone_from_slice(&PEH);
        b[X25519PublicKey::LENGTH..].clone_from_slice(&C0);
        let K = kdf::hkdf_256(
            &b,
            <Aes256GcmCrypto as SymmetricCrypto>::Key::LENGTH
                + <Aes256GcmCrypto as SymmetricCrypto>::Nonce::LENGTH,
            HKDF_INFO,
        )?;
        Ok((C0, K))
    }

    fn decaps(
        &self,
        sk: &<<X25519Crypto as AsymmetricCrypto>::KeyPair as KeyPair>::PrivateKey,
        C0: &Self::CipherText,
    ) -> Result<Self::SecretKey, Error> {
        // case CheckMod = 1: the ciphertext should map to valid public key
        // compute the shared secret
        let h = <X25519PublicKey>::try_from(C0.as_slice())? * sk;

        // TODO: check it is not null -> implement `is_zero`
        let mut b = [0u8; X25519PublicKey::LENGTH + X25519PrivateKey::LENGTH];
        b[..X25519PublicKey::LENGTH].clone_from_slice(&h.as_bytes());
        b[X25519PublicKey::LENGTH..].clone_from_slice(C0);

        kdf::hkdf_256(
            &b,
            <Aes256GcmCrypto as SymmetricCrypto>::Key::LENGTH
                + <Aes256GcmCrypto as SymmetricCrypto>::Nonce::LENGTH,
            HKDF_INFO,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[test]
    fn test_kem() -> Result<()> {
        let kem = ElGammalKemAesX25519::new();
        let key_pair = kem.key_gen();
        let (C0, K) = kem
            .encaps(key_pair.public_key())
            .map_err(|err| anyhow::eyre!("{:?}", err))?;
        let res = kem
            .decaps(key_pair.private_key(), &C0)
            .map_err(|err| anyhow::eyre!("{:?}", err))?;
        anyhow::ensure!(K == res, "Wrong decapsulation!");
        Ok(())
    }
}
