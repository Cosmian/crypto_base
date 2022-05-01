use crate::{
    hybrid_crypto::Dem,
    symmetric_crypto::{aes_256_gcm_pure::Aes256GcmCrypto, Nonce, SymmetricCrypto},
    Error, Key,
};
use log::error;
use rand_core::{CryptoRng, RngCore};
use std::{
    convert::TryFrom,
    ops::{Deref, DerefMut},
    sync::Mutex,
};

pub struct DemAes(Aes256GcmCrypto);

impl Deref for DemAes {
    type Target = Aes256GcmCrypto;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for DemAes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Dem<Aes256GcmCrypto> for DemAes {
    const KEY_LENGTH: usize = <Aes256GcmCrypto as SymmetricCrypto>::Key::LENGTH;

    fn encrypt<R: RngCore + CryptoRng>(
        rng: &Mutex<R>,
        K: &[u8],
        L: &[u8],
        m: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if K.len() < Self::KEY_LENGTH {
            return Err(Error::SizeError {
                given: K.len(),
                expected: Self::KEY_LENGTH,
            });
        }
        let k1 = K[..<Aes256GcmCrypto as SymmetricCrypto>::Key::LENGTH].to_vec();
        let key = <Aes256GcmCrypto as SymmetricCrypto>::Key::try_from(k1)?;
        let nonce = <Aes256GcmCrypto as SymmetricCrypto>::Nonce::new(rng);
        // this encryption method comprises the MAC tag
        let mut c = Aes256GcmCrypto::encrypt(&key, m, &nonce, Some(L)).map_err(|err| {
            error!("{:?}", err);
            Error::EncryptionError
        })?;
        let mut res: Vec<u8> = nonce.into();
        res.append(&mut c);
        Ok(res)
    }

    fn decrypt(K: &[u8], L: &[u8], c: &[u8]) -> Result<Vec<u8>, Error> {
        if K.len() < Self::KEY_LENGTH {
            return Err(Error::SizeError {
                given: K.len(),
                expected: Self::KEY_LENGTH,
            });
        }
        let k1 = K[..<Aes256GcmCrypto as SymmetricCrypto>::Key::LENGTH].to_vec();
        let key = <Aes256GcmCrypto as SymmetricCrypto>::Key::try_from(k1)?;
        let nonce = <Aes256GcmCrypto as SymmetricCrypto>::Nonce::try_from(
            c[..<Aes256GcmCrypto as SymmetricCrypto>::Nonce::LENGTH].to_vec(),
        )?;
        // this encryption method comprises the authentification tag
        Aes256GcmCrypto::decrypt(
            &key,
            &c[<Aes256GcmCrypto as SymmetricCrypto>::Nonce::LENGTH..],
            &nonce,
            Some(L),
        )
        .map_err(|err| {
            error!("{:?}", err);
            Error::EncryptionError
        })
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
        let c = DemAes::encrypt(&rng, &K, L, m)?;
        let res = DemAes::decrypt(&K, L, &c)?;
        anyhow::ensure!(res == m, "Decryption error");
        Ok(())
    }
}
