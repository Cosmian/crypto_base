use std::convert::TryFrom;

use rand_core::{CryptoRng, RngCore};

use crate::{
    hybrid_crypto::Dem,
    symmetric_crypto::{aes_256_gcm_pure::Aes256GcmCrypto, nonce::NonceTrait, SymmetricCrypto},
    Error, KeyTrait,
};

impl Dem for Aes256GcmCrypto {
    fn encaps<R: RngCore + CryptoRng>(
        rng: &mut R,
        K: &[u8],
        L: &[u8],
        D: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if K.len() < Self::Key::LENGTH {
            return Err(Error::SizeError {
                given: K.len(),
                expected: Self::Key::LENGTH,
            });
        }
        // AES GCM includes an authentication method
        // there is no need for parsing a MAC key
        let key = Self::Key::try_from(&K[..Self::Key::LENGTH])?;
        let nonce = Self::Nonce::new(rng);
        let mut c = Self::encrypt(&key, D, &nonce, Some(L))
            .map_err(|err| Error::EncryptionError(err.to_string()))?;
        // allocate correct byte number
        let mut res: Vec<u8> = Vec::with_capacity(D.len() + Self::ENCAPSULATION_OVERHEAD);
        res.append(&mut nonce.into());
        res.append(&mut c);
        Ok(res)
    }

    fn decaps(K: &[u8], L: &[u8], E: &[u8]) -> Result<Vec<u8>, Error> {
        if K.len() < Self::Key::LENGTH {
            return Err(Error::SizeError {
                given: K.len(),
                expected: Self::Key::LENGTH,
            });
        }

        if E.len() < Self::Nonce::LENGTH {
            return Err(Error::SizeError {
                given: K.len(),
                expected: Self::Nonce::LENGTH,
            });
        }

        // AES GCM includes an authentication method
        // there is no need for parsing a MAC key
        let key = Self::Key::try_from(&K[..Self::Key::LENGTH])?;
        let nonce = Self::Nonce::try_from(&E[..Self::Nonce::LENGTH])?;
        Self::decrypt(&key, &E[Self::Nonce::LENGTH..], &nonce, Some(L))
            .map_err(|err| Error::EncryptionError(err.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use super::*;
    use crate::{
        asymmetric::{ristretto::X25519Crypto, KeyPair},
        entropy::CsRng,
        hybrid_crypto::Kem,
    };

    #[test]
    fn test_dem() -> Result<()> {
        let m = b"my secret message";
        let L = b"public tag";
        let mut rng = CsRng::new();
        let key_pair = X25519Crypto::key_gen(&mut rng);
        let (K, _) = X25519Crypto::encaps(&mut rng, key_pair.public_key())
            .map_err(|err| anyhow::eyre!("{:?}", err))?;
        let c = Aes256GcmCrypto::encaps(&mut rng, &K, L, m)?;
        let res = Aes256GcmCrypto::decaps(&K, L, &c)?;
        anyhow::ensure!(res == m, "Decryption error");
        Ok(())
    }

    #[test]
    fn test_encapsulation_overhead() -> Result<()> {
        let m = b"my secret message";
        let L = b"public tag";
        let mut rng = CsRng::new();
        let key_pair = X25519Crypto::key_gen(&mut rng);
        let (K, _) = X25519Crypto::encaps(&mut rng, key_pair.public_key())
            .map_err(|err| anyhow::eyre!("{:?}", err))?;
        let c = Aes256GcmCrypto::encaps(&mut rng, &K, L, m)?;
        anyhow::ensure!(
            c.len() == m.len() + Aes256GcmCrypto::ENCAPSULATION_OVERHEAD,
            "Wrong encapsulation overhead"
        );
        Ok(())
    }
}
