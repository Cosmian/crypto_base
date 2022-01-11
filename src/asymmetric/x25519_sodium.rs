#![allow(clippy::cast_possible_truncation)]

use std::{
    convert::{AsMut, TryFrom, TryInto},
    fmt::Display,
    vec::Vec,
};

/// This module provide asymetric cryptography for
/// the encryption of the symmetric key
use super::{AsymmetricCrypto, KeyPair};
use crate::{
    sodium_bindings,
    symmetric_crypto::{Key, SymmetricCrypto},
};

pub const PRIVATE_KEY_LENGTH: usize = sodium_bindings::crypto_box_SECRETKEYBYTES as usize;
pub const PUBLIC_KEY_LENGTH: usize = sodium_bindings::crypto_box_PUBLICKEYBYTES as usize;
pub const SEAL_LENGTH: usize = sodium_bindings::crypto_box_SEALBYTES as usize;

pub type X25519PrivateKey = [u8; PRIVATE_KEY_LENGTH];

#[derive(Clone, PartialEq, Debug)]
pub struct X25519PublicKey {
    pub v: [u8; PUBLIC_KEY_LENGTH],
}

impl TryFrom<&[u8]> for X25519PublicKey {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        let len = value.len();
        let bytes: [u8; PUBLIC_KEY_LENGTH] = value.try_into().map_err(|_| {
            anyhow::anyhow!(
                "Invalid key of length: {}, expected length: {}",
                len,
                PUBLIC_KEY_LENGTH
            )
        })?;
        Ok(X25519PublicKey { v: bytes })
    }
}

impl Display for X25519PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.v))
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct X25519KeyPair {
    private_key: X25519PrivateKey,
    public_key: X25519PublicKey,
}

impl KeyPair for X25519KeyPair {
    type PrivateKey = X25519PrivateKey;
    type PublicKey = X25519PublicKey;

    fn public_key(&self) -> &Self::PublicKey {
        &self.public_key
    }

    fn private_key(&self) -> &Self::PrivateKey {
        &self.private_key
    }
}

impl TryFrom<&[u8]> for X25519KeyPair {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        let len = value.len();
        if len != PRIVATE_KEY_LENGTH + PUBLIC_KEY_LENGTH {
            anyhow::bail!(
                "Invalid key pair of length: {}, expected length: {}",
                len,
                PRIVATE_KEY_LENGTH + PUBLIC_KEY_LENGTH
            );
        }
        let public_key_bytes: [u8; PUBLIC_KEY_LENGTH] = value[..PUBLIC_KEY_LENGTH]
            .try_into()
            .map_err(|e| anyhow::anyhow!("Invalid public key: {:?}", e))?;
        let private_key_bytes: [u8; PRIVATE_KEY_LENGTH] = value[PUBLIC_KEY_LENGTH as usize..]
            .try_into()
            .map_err(|e| anyhow::anyhow!("Invalid private key: {:?}", e))?;
        Ok(X25519KeyPair {
            private_key: private_key_bytes,
            public_key: X25519PublicKey {
                v: public_key_bytes,
            },
        })
    }
}

impl Display for X25519KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}{}",
            hex::encode(self.public_key.v),
            hex::encode(self.private_key)
        )
    }
}

#[derive(Debug, PartialEq)]
pub struct X25519Crypto;

impl AsymmetricCrypto for X25519Crypto {
    type KeyPair = X25519KeyPair;
    type KeygenParam = ();

    #[must_use]
    fn new() -> Self {
        unsafe {
            sodium_bindings::sodium_init();
        };
        Self {}
    }

    fn new_attrs(_attrs: &[u32]) -> Self {
        X25519Crypto::new()
    }

    fn description(&self) -> String {
        format!(
            "X25519 (private key bits: {}, seal bits: {})",
            PRIVATE_KEY_LENGTH * 8,
            SEAL_LENGTH * 8,
        )
    }

    fn generate_key_pair(&self, _: Self::KeygenParam) -> anyhow::Result<Self::KeyPair> {
        let mut key_pair = X25519KeyPair {
            private_key: [0_u8; PRIVATE_KEY_LENGTH],
            public_key: X25519PublicKey {
                v: [0_u8; PUBLIC_KEY_LENGTH],
            },
        };

        let res = unsafe {
            sodium_bindings::crypto_box_keypair(
                key_pair.public_key.v.as_mut().as_mut_ptr(),
                key_pair.private_key.as_mut().as_mut_ptr(),
            )
        };
        anyhow::ensure!(res == 0, "generation of random key pair failed");
        Ok(key_pair)
    }

    fn generate_symmetric_key<S: SymmetricCrypto>(
        &self,
        public_key: &<Self::KeyPair as KeyPair>::PublicKey,
    ) -> anyhow::Result<(S::Key, Vec<u8>)> {
        let mut bytes: Vec<u8> = vec![0; S::Key::LENGTH];
        unsafe {
            sodium_bindings::randombytes_buf(
                bytes.as_mut_ptr().cast::<std::ffi::c_void>(),
                bytes.len() as u64,
            );
        }
        let key = S::generate_key_from_rnd(&bytes)?;
        let bytes = self.encrypt(public_key, &key.clone().into())?;
        Ok((key, bytes))
    }

    fn decrypt_symmetric_key<S: SymmetricCrypto>(
        &self,
        private_key: &<Self::KeyPair as KeyPair>::PrivateKey,
        data: &[u8],
    ) -> anyhow::Result<S::Key> {
        S::Key::parse(self.decrypt(private_key, data)?)
    }

    fn generate_random_bytes(&self, len: usize) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![0; len];
        unsafe {
            sodium_bindings::randombytes_buf(
                bytes.as_mut_ptr().cast::<std::ffi::c_void>(),
                bytes.len() as u64,
            );
        }
        bytes
    }

    fn encrypted_message_length(&self, clear_text_message_length: usize) -> usize {
        clear_text_message_length + SEAL_LENGTH
    }

    fn encrypt(
        &self,
        public_key: &<Self::KeyPair as KeyPair>::PublicKey,
        data: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        if data.is_empty() {
            return Ok(vec![])
        }
        let enc_len = self.encrypted_message_length(data.len());
        let mut result = vec![0_u8; enc_len];
        let res = unsafe {
            sodium_bindings::crypto_box_seal(
                result.as_mut_ptr(),
                data.as_ptr(),
                data.len() as u64,
                public_key.v.as_ptr(),
            )
        };
        anyhow::ensure!(res == 0, "encryption failed");
        Ok(result)
    }

    fn clear_text_message_length(encrypted_message_length: usize) -> usize {
        if encrypted_message_length < SEAL_LENGTH {
            0_usize
        } else {
            encrypted_message_length - SEAL_LENGTH
        }
    }

    fn decrypt(
        &self,
        private_key: &<Self::KeyPair as KeyPair>::PrivateKey,
        data: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let ct_len = X25519Crypto::clear_text_message_length(data.len());
        if ct_len == 0 {
            return Ok(vec![])
        }
        let mut result = vec![0_u8; ct_len];
        let res = unsafe {
            sodium_bindings::crypto_box_seal_open(
                result.as_mut_ptr(),
                data.as_ptr(),
                data.len() as u64,
                key_pair.public_key.v.as_ptr(),
                key_pair.private_key.as_ptr(),
            )
        };
        anyhow::ensure!(res == 0, "decryption failed");
        Ok(result)
    }
}

#[cfg(test)]
mod test {
    use std::convert::TryFrom;

    use super::{AsymmetricCrypto, KeyPair};
    use crate::{
        abe::{bilinear_map::bls12_381::Bls12_381, gpsw::abe::Gpsw},
        asymmetric::{abe::AbeCrypto, x25519_sodium},
        entropy::new_uid,
        hybrid_crypto::Header,
        symmetric_crypto::{aes_256_gcm_sodium, xchacha20},
    };

    #[test]
    fn test_generate_key_pair() {
        let crypto = super::X25519Crypto::new();
        let key_pair_1 = crypto.generate_key_pair(()).unwrap();
        assert_ne!([0_u8; super::PRIVATE_KEY_LENGTH], key_pair_1.private_key);
        assert_ne!([0_u8; super::PUBLIC_KEY_LENGTH], key_pair_1.public_key.v);
        assert_eq!(
            super::PRIVATE_KEY_LENGTH as usize,
            key_pair_1.private_key.len()
        );
        assert_eq!(
            super::PUBLIC_KEY_LENGTH as usize,
            key_pair_1.public_key.v.len()
        );
        let key_pair_2 = crypto.generate_key_pair(()).unwrap();
        assert_ne!(key_pair_2.private_key, key_pair_1.private_key);
        assert_ne!(key_pair_2.public_key.v, key_pair_1.public_key.v);
    }

    #[test]
    fn test_parse_key_pair() {
        let crypto = super::X25519Crypto::new();
        let key_pair = crypto.generate_key_pair(()).unwrap();
        let hex = format!("{}", key_pair);
        let recovered =
            super::X25519KeyPair::try_from(hex::decode(hex).unwrap().as_slice()).unwrap();
        assert_eq!(key_pair, recovered);
    }

    #[test]
    fn test_parse_public_key() {
        let crypto = super::X25519Crypto::new();
        let key_pair = crypto.generate_key_pair(()).unwrap();
        let hex = format!("{}", key_pair.public_key());
        let recovered =
            super::X25519PublicKey::try_from(hex::decode(hex).unwrap().as_slice()).unwrap();
        assert_eq!(key_pair.public_key(), &recovered);
    }

    #[test]
    fn test_encryption_decryption() {
        let crypto = super::X25519Crypto::new();
        let random_msg = crypto.generate_random_bytes(4096);
        assert_ne!(vec![0_u8; 4096], random_msg);
        let key_pair: super::X25519KeyPair = crypto.generate_key_pair(()).unwrap();
        let enc_bytes = crypto.encrypt(&key_pair.public_key, &random_msg).unwrap();
        assert_eq!(
            4096_usize + super::SEAL_LENGTH,
            crypto.encrypted_message_length(random_msg.len())
        );
        assert_eq!(
            4096_usize,
            super::X25519Crypto::clear_text_message_length(enc_bytes.len())
        );
        let clear_text = crypto.decrypt(&key_pair.private_key, &enc_bytes).unwrap();
        assert_eq!(random_msg, clear_text);
    }

    #[test]
    fn test_aes_header() {
        let uid = new_uid();
        let asymmetric = x25519_sodium::X25519Crypto::new();
        let key_pair = asymmetric.generate_key_pair(()).unwrap();
        let symmetric_key = asymmetric
            .generate_symmetric_key::<aes_256_gcm_sodium::Aes256GcmCrypto>(key_pair.public_key())
            .unwrap();
        let header =
            Header::<x25519_sodium::X25519Crypto, aes_256_gcm_sodium::Aes256GcmCrypto>::new(
                uid,
                symmetric_key.0,
            );
        let bytes = header.to_bytes(symmetric_key.1).unwrap();
        let recovered =
            Header::<x25519_sodium::X25519Crypto, aes_256_gcm_sodium::Aes256GcmCrypto>::from_encrypted_bytes(
                &bytes,
                &asymmetric,
                &key_pair,
            )
            .unwrap();
        assert_eq!(header, recovered);
    }

    #[test]
    fn test_chacha_header() {
        let uid = new_uid();
        let asymmetric = x25519_sodium::X25519Crypto::new();
        let key_pair = asymmetric.generate_key_pair(()).unwrap();
        let symmetric_key = asymmetric
            .generate_symmetric_key::<xchacha20::XChacha20Crypto>(key_pair.public_key())
            .unwrap();
        let header = Header::<x25519_sodium::X25519Crypto, xchacha20::XChacha20Crypto>::new(
            uid,
            symmetric_key.0,
        );
        let bytes = header.to_bytes(symmetric_key.1).unwrap();
        let recovered =
            Header::<x25519_sodium::X25519Crypto, xchacha20::XChacha20Crypto>::from_encrypted_bytes(
                &bytes,
                &asymmetric,
                &key_pair,
            )
            .unwrap();
        assert_eq!(header, recovered);
    }

    #[test]
    fn test_abe_chacha_header() {
        let uid = new_uid();
        let asymmetric = AbeCrypto::<Gpsw<Bls12_381>>::new_attrs(&[1, 2, 3, 4]);
        let param = (1000, "1 & (4 | (2 & 3))".to_owned());
        let key_pair = asymmetric.generate_key_pair(param).unwrap();
        let symmetric_key = asymmetric
            .generate_symmetric_key::<xchacha20::XChacha20Crypto>(key_pair.public_key())
            .unwrap();
        let header = Header::<AbeCrypto<Gpsw<Bls12_381>>, xchacha20::XChacha20Crypto>::new(
            uid,
            symmetric_key.0,
        );
        let bytes = header.to_bytes(symmetric_key.1).unwrap();
        let recovered =
            Header::<AbeCrypto<Gpsw<Bls12_381>>, xchacha20::XChacha20Crypto>::from_encrypted_bytes(
                &bytes,
                &asymmetric,
                &key_pair,
            )
            .unwrap();
        assert_eq!(header, recovered);
    }
}
