use crate::{
    asymmetric::{ristretto::X25519Crypto, KeyPair},
    hybrid_crypto::{Error, Kem},
    kdf, Key,
};
use rand_core::{CryptoRng, RngCore};
use std::{convert::TryFrom, sync::Mutex};

const HKDF_INFO: &[u8; 21] = b"ecies-ristretto-25519";

impl Kem for X25519Crypto {
    const KEY_LENGTH: usize = 256;
    type Encapsulation = Vec<u8>;
    type SecretKey = Vec<u8>;

    fn description() -> String {
        todo!()
    }

    fn key_gen<R: RngCore + CryptoRng>(rng: &Mutex<R>) -> Self::KeyPair {
        Self::KeyPair::new(rng)
    }

    fn encaps<R: RngCore + CryptoRng>(
        rng: &Mutex<R>,
        pk: &<Self::KeyPair as KeyPair>::PublicKey,
    ) -> Result<(Self::Encapsulation, Self::SecretKey), Error> {
        let ephemeral_keypair = Self::key_gen(rng);

        // encapsulation
        let E = ephemeral_keypair.public_key().as_bytes();

        // shared secret
        let PEH = (pk * ephemeral_keypair.private_key()).as_bytes();

        // generate secret key
        let mut b = [0u8; <Self::KeyPair as KeyPair>::PublicKey::LENGTH
            + <Self::KeyPair as KeyPair>::PrivateKey::LENGTH];
        b[..<Self::KeyPair as KeyPair>::PublicKey::LENGTH].clone_from_slice(&PEH);
        b[<Self::KeyPair as KeyPair>::PublicKey::LENGTH..].clone_from_slice(&E);
        let K = kdf::hkdf_256(&b, Self::KEY_LENGTH, HKDF_INFO)?;
        Ok((K, E))
    }

    fn decaps(
        sk: &<Self::KeyPair as KeyPair>::PrivateKey,
        E: &Self::Encapsulation,
    ) -> Result<Self::SecretKey, Error> {
        // case CheckMod = 1: the ciphertext should map to valid public key
        // compute the shared secret
        let h = <Self::KeyPair as KeyPair>::PublicKey::try_from(E.as_slice())? * sk;

        // TODO: check `h` is not null -> implement `is_zero`
        let PEH = h.as_bytes();

        // generate secret key
        let mut b = [0u8; <Self::KeyPair as KeyPair>::PublicKey::LENGTH
            + <Self::KeyPair as KeyPair>::PrivateKey::LENGTH];
        b[..<Self::KeyPair as KeyPair>::PublicKey::LENGTH].clone_from_slice(&PEH);
        b[<Self::KeyPair as KeyPair>::PublicKey::LENGTH..].clone_from_slice(E);
        kdf::hkdf_256(&b, Self::KEY_LENGTH, HKDF_INFO)
    }
}

#[cfg(test)]
mod tests {
    use crate::entropy::CsRng;

    use super::*;
    use anyhow::Result;

    #[test]
    fn test_kem() -> Result<()> {
        let rng = Mutex::new(CsRng::new());
        let key_pair = X25519Crypto::key_gen(&rng);
        let (K, E) = X25519Crypto::encaps(&rng, key_pair.public_key())
            .map_err(|err| anyhow::eyre!("{:?}", err))?;
        let res = X25519Crypto::decaps(key_pair.private_key(), &E)
            .map_err(|err| anyhow::eyre!("{:?}", err))?;
        anyhow::ensure!(K == res, "Wrong decapsulation!");
        Ok(())
    }
}
