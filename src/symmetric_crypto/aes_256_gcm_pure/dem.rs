use crate::{
    hybrid_crypto::Dem,
    symmetric_crypto::{aes_256_gcm_pure::Aes256GcmCrypto, nonce::NonceTrait, SymmetricCrypto},
    CryptoBaseError, KeyTrait,
};
use rand_core::{CryptoRng, RngCore};
use std::convert::TryFrom;

impl Dem for Aes256GcmCrypto {
    fn encaps<R: RngCore + CryptoRng>(
        rng: &mut R,
        secret_key: &[u8],
        additional_data: Option<&[u8]>,
        message: &[u8],
    ) -> Result<Vec<u8>, CryptoBaseError> {
        if secret_key.len() < Self::Key::LENGTH {
            return Err(CryptoBaseError::SizeError {
                given: secret_key.len(),
                expected: Self::Key::LENGTH,
            });
        }
        // AES GCM includes an authentication method
        // there is no need for parsing a MAC key
        let key = Self::Key::try_from(&secret_key[..Self::Key::LENGTH])?;
        let nonce = Self::Nonce::new(rng);
        let mut c = Self::encrypt(&key, message, &nonce, additional_data)
            .map_err(|err| CryptoBaseError::EncryptionError(err.to_string()))?;
        // allocate correct byte number
        let mut res: Vec<u8> = Vec::with_capacity(message.len() + Self::ENCRYPTION_OVERHEAD);
        res.append(&mut nonce.into());
        res.append(&mut c);
        Ok(res)
    }

    fn decaps(
        secret_key: &[u8],
        additional_data: Option<&[u8]>,
        encapsulation: &[u8],
    ) -> Result<Vec<u8>, CryptoBaseError> {
        if secret_key.len() < Self::Key::LENGTH {
            return Err(CryptoBaseError::SizeError {
                given: secret_key.len(),
                expected: Self::Key::LENGTH,
            });
        }
        // AES GCM includes an authentication method
        // there is no need for parsing a MAC key
        let key = Self::Key::try_from(&secret_key[..Self::Key::LENGTH])?;
        let nonce = Self::Nonce::try_from(&encapsulation[..Self::Nonce::LENGTH])?;
        Self::decrypt(
            &key,
            &encapsulation[Self::Nonce::LENGTH..],
            &nonce,
            additional_data,
        )
        .map_err(|err| CryptoBaseError::EncryptionError(err.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        asymmetric::{ristretto::X25519Crypto, AsymmetricCrypto, KeyPair},
        entropy::CsRng,
        hybrid_crypto::{Dem, Kem},
        symmetric_crypto::{aes_256_gcm_pure::Aes256GcmCrypto, SymmetricCrypto},
        CryptoBaseError, KeyTrait,
    };

    #[test]
    fn test_dem() -> Result<(), CryptoBaseError> {
        let m = b"my secret message";
        let additional_data = Some(b"public tag".as_slice());
        let mut rng = CsRng::new();
        let kem = X25519Crypto::new();
        let key_pair = kem.key_gen(&mut rng)?;
        let (secret_key, _) = kem.encaps(
            &mut rng,
            key_pair.public_key(),
            <Aes256GcmCrypto as SymmetricCrypto>::Key::LENGTH,
        )?;
        let c = Aes256GcmCrypto::encaps(&mut rng, &secret_key, additional_data, m)?;
        let res = Aes256GcmCrypto::decaps(&secret_key, additional_data, &c)?;
        if res != m {
            return Err(CryptoBaseError::DecryptionError(
                "Decaps failed".to_string(),
            ));
        }
        Ok(())
    }
}
