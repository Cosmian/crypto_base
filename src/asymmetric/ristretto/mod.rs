pub mod kem;

use crate::{
    asymmetric::{AsymmetricCrypto, KeyPair},
    CryptoBaseError,
};
use cosmian_crypto_core::{entropy::CsRng, reexport::generic_array::typenum::Unsigned, KeyTrait};
use rand::{CryptoRng, RngCore};
use std::{convert::TryFrom, fmt::Display, ops::DerefMut, sync::Mutex};

pub use cosmian_crypto_core::asymmetric_crypto::{X25519PrivateKey, X25519PublicKey};

/// Asymmetric pricate and public key pair based on the X25519 curve.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct X25519KeyPair {
    private_key: X25519PrivateKey,
    public_key: X25519PublicKey,
}

impl X25519KeyPair {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let private_key = X25519PrivateKey::new(rng);
        let public_key = X25519PublicKey::from(&private_key);
        Self {
            private_key,
            public_key,
        }
    }
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
    type Error = CryptoBaseError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let len = <<Self as KeyPair>::PrivateKey as KeyTrait>::Length::to_usize()
            + <<Self as KeyPair>::PublicKey as KeyTrait>::Length::to_usize();
        if len != bytes.len() {
            return Err(Self::Error::SizeError {
                given: bytes.len(),
                expected: len,
            });
        }
        let private_key = <Self as KeyPair>::PrivateKey::try_from(
            &bytes[..<<Self as KeyPair>::PrivateKey as KeyTrait>::Length::to_usize()],
        )?;
        let public_key = <Self as KeyPair>::PublicKey::try_from(
            &bytes[<<Self as KeyPair>::PrivateKey as KeyTrait>::Length::to_usize()..],
        )?;
        Ok(Self {
            private_key,
            public_key,
        })
    }
}

impl Display for X25519KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}", self.private_key(), self.public_key())
    }
}

pub struct X25519Crypto {
    pub(crate) rng: Mutex<CsRng>,
}

impl Default for X25519Crypto {
    fn default() -> Self {
        Self::new()
    }
}

impl Display for X25519Crypto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.description())
    }
}

impl PartialEq for X25519Crypto {
    fn eq(&self, other: &Self) -> bool {
        self.description() == other.description()
    }
}

impl AsymmetricCrypto for X25519Crypto {
    type KeyPair = X25519KeyPair;

    fn new() -> Self {
        Self {
            rng: Mutex::new(CsRng::new()),
        }
    }

    fn description(&self) -> String {
        todo!()
    }

    fn generate_key_pair(&self) -> Self::KeyPair {
        Self::KeyPair::new(self.rng.lock().expect("Mutex lock failed").deref_mut())
    }
}

#[cfg(test)]
mod test {
    use super::{AsymmetricCrypto, KeyPair, X25519PrivateKey, X25519PublicKey};
    use cosmian_crypto_core::{
        reexport::generic_array::{typenum::Unsigned, GenericArray},
        KeyTrait,
    };
    use std::convert::TryFrom;

    #[test]
    fn test_generate_key_pair() {
        let crypto = super::X25519Crypto::new();
        let key_pair_1 = crypto.generate_key_pair();
        assert_ne!(
            &GenericArray::<u8, <X25519PrivateKey as KeyTrait>::Length>::default(),
            &key_pair_1.private_key().to_bytes(),
        );
        assert_ne!(
            &GenericArray::<u8, <X25519PublicKey as KeyTrait>::Length>::default(),
            &key_pair_1.public_key().to_bytes(),
        );
        assert_eq!(
            <X25519PrivateKey as KeyTrait>::Length::to_usize(),
            key_pair_1.private_key.to_bytes().len()
        );
        assert_eq!(
            <X25519PublicKey as KeyTrait>::Length::to_usize(),
            key_pair_1.public_key.to_bytes().len()
        );
        let key_pair_2 = crypto.generate_key_pair();
        assert_ne!(key_pair_2.private_key, key_pair_1.private_key);
        assert_ne!(key_pair_2.public_key, key_pair_1.public_key);
    }

    #[test]
    fn test_parse_key_pair() {
        let crypto = super::X25519Crypto::new();
        let key_pair = crypto.generate_key_pair();
        let hex = format!("{}", key_pair);
        let recovered =
            super::X25519KeyPair::try_from(hex::decode(hex).unwrap().as_slice()).unwrap();
        assert_eq!(key_pair, recovered);
    }
}
