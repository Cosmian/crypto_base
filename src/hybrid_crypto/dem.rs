use crate::{
    hybrid_crypto::Dem,
    symmetric_crypto::{aes_256_gcm_pure::Aes256GcmCrypto, Nonce, SymmetricCrypto},
    Error,
};
use log::error;
use std::{convert::TryFrom, ops::Deref};

pub struct DemAes(Aes256GcmCrypto);

impl Deref for DemAes {
    type Target = Aes256GcmCrypto;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Dem<Aes256GcmCrypto> for DemAes {
    const KEY_LENGTH: usize =
        <<Aes256GcmCrypto as crate::symmetric_crypto::SymmetricCrypto>::Key as crate::Key>::LENGTH;

    fn new() -> Self {
        Self(Aes256GcmCrypto::new())
    }

    fn encrypt(&self, K: &[u8], L: &[u8], m: &[u8]) -> Result<Vec<u8>, crate::Error> {
        if K.len() < Self::KEY_LENGTH {
            return Err(Error::SizeError {
                given: K.len(),
                expected: Self::KEY_LENGTH,
            });
        }
        let k1 = K[..<<Aes256GcmCrypto as crate::symmetric_crypto::SymmetricCrypto>::Key as crate::Key>::LENGTH].to_vec();
        let key = <<Aes256GcmCrypto as SymmetricCrypto>::Key>::try_from(k1)?;
        let nonce = self.generate_nonce();
        // this encryption method comprises the MAC tag
        let mut c = self
            .deref()
            .encrypt(&key, m, &nonce, Some(L))
            .map_err(|err| {
                error!("{:?}", err);
                Error::EncryptionError
            })?;
        let mut res: Vec<u8> = nonce.into();
        res.append(&mut c);
        Ok(res)
    }

    fn decrypt(&self, K: &[u8], L: &[u8], c: &[u8]) -> Result<Vec<u8>, crate::Error> {
        if K.len() < Self::KEY_LENGTH {
            return Err(Error::SizeError {
                given: K.len(),
                expected: Self::KEY_LENGTH,
            });
        }
        let k1 = K[..<<Aes256GcmCrypto as crate::symmetric_crypto::SymmetricCrypto>::Key as crate::Key>::LENGTH].to_vec();
        let key = <<Aes256GcmCrypto as SymmetricCrypto>::Key>::try_from(k1)?;
        let nonce = <<Aes256GcmCrypto as SymmetricCrypto>::Nonce as Nonce>::try_from(
            c[..<<Aes256GcmCrypto as SymmetricCrypto>::Nonce as Nonce>::LENGTH].to_vec(),
        )?;
        // this encryption method comprises the authentification tag
        self.deref()
            .decrypt(
                &key,
                &c[<<Aes256GcmCrypto as SymmetricCrypto>::Nonce as Nonce>::LENGTH..],
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
        asymmetric::KeyPair,
        hybrid_crypto::{kem::ElGammalKemAesX25519, Kem},
    };
    use anyhow::Result;

    #[test]
    fn test_dem() -> Result<()> {
        let m = b"my secret message";
        let L = b"public tag";
        let kem = ElGammalKemAesX25519::new();
        let key_pair = kem.key_gen().map_err(|err| anyhow::eyre!("{:?}", err))?;
        let (_, K) = kem
            .encaps(key_pair.public_key())
            .map_err(|err| anyhow::eyre!("{:?}", err))?;
        let dem = DemAes::new();
        let c = dem.encrypt(&K, L, m)?;
        let res = dem.decrypt(&K, L, &c)?;
        anyhow::ensure!(res == m, "Decryption error");
        Ok(())
    }
}
