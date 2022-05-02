use crate::{
    hybrid_crypto::Dem,
    symmetric_crypto::{aes_256_gcm_pure::Aes256GcmCrypto, Nonce, SymmetricCrypto},
    Error, Key,
};
use rand_core::{CryptoRng, RngCore};
use std::{convert::TryFrom, sync::Mutex};

impl Dem for Aes256GcmCrypto {
    fn encaps<R: RngCore + CryptoRng>(
        rng: &Mutex<R>,
        K: &[u8],
        L: &[u8],
        m: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if K.len() < Self::Key::LENGTH {
            return Err(Error::SizeError {
                given: K.len(),
                expected: Self::Key::LENGTH,
            });
        }
        // AES GCM includes an authentification method
        // there is no need for parsing a MAC key
        let key = Self::Key::try_from(&K[..Self::Key::LENGTH])?;
        let nonce = Self::Nonce::new(rng);
        let mut c = Self::encrypt(&key, m, &nonce, Some(L))
            .map_err(|err| Error::EncryptionError { err })?;
        let mut res: Vec<u8> = nonce.into();
        res.append(&mut c);
        Ok(res)
    }

    fn decaps(K: &[u8], L: &[u8], c: &[u8]) -> Result<Vec<u8>, Error> {
        if K.len() < Self::Key::LENGTH {
            return Err(Error::SizeError {
                given: K.len(),
                expected: Self::Key::LENGTH,
            });
        }
        // AES GCM includes an authentification method
        // there is no need for parsing a MAC key
        let key = Self::Key::try_from(&K[..Self::Key::LENGTH])?;
        let nonce = Self::Nonce::try_from(&c[..Self::Nonce::LENGTH])?;
        Self::decrypt(&key, &c[Self::Nonce::LENGTH..], &nonce, Some(L))
            .map_err(|err| Error::EncryptionError { err })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        asymmetric::{ristretto::X25519Crypto, KeyPair},
        entropy::CsRng,
        hybrid_crypto::Kem,
    };
    use anyhow::Result;
    use std::sync::Mutex;

    #[test]
    fn test_dem() -> Result<()> {
        let m = b"my secret message";
        let L = b"public tag";
        let rng = Mutex::new(CsRng::new());
        let key_pair = X25519Crypto::key_gen(&rng);
        let (_, K) = X25519Crypto::encaps(&rng, key_pair.public_key())
            .map_err(|err| anyhow::eyre!("{:?}", err))?;
        let c = Aes256GcmCrypto::encaps(&rng, &K, L, m)?;
        let res = Aes256GcmCrypto::decaps(&K, L, &c)?;
        anyhow::ensure!(res == m, "Decryption error");
        Ok(())
    }
}
