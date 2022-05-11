use crate::{
    symmetric_crypto::{Nonce as _, SymmetricCrypto},
    Error, KeyTrait,
};
use rand_core::{CryptoRng, RngCore};
use std::{
    cmp::min,
    convert::{TryFrom, TryInto},
    fmt::Display,
    ops::DerefMut,
    sync::Mutex,
    vec::Vec,
};

#[derive(Debug, Clone, PartialEq)]
pub struct Key<const KEY_LENGTH: usize>(pub [u8; KEY_LENGTH]);

impl<const KEY_LENGTH: usize> KeyTrait for Key<KEY_LENGTH> {
    /// Generate a new symmetric random `Key`
    fn new<R: RngCore + CryptoRng>(rng: &Mutex<R>) -> Self {
        let mut key = Self([0_u8; KEY_LENGTH]);
        rng.lock()
            .expect("Could not get a hold on the mutex")
            .deref_mut()
            .fill_bytes(&mut key.0);
        key
    }

    fn as_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl<const KEY_LENGTH: usize> From<Key<KEY_LENGTH>> for Vec<u8> {
    fn from(k: Key<KEY_LENGTH>) -> Vec<u8> {
        k.0.to_vec()
    }
}

impl<const KEY_LENGTH: usize> TryFrom<Vec<u8>> for Key<KEY_LENGTH> {
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl<'a, const KEY_LENGTH: usize> TryFrom<&'a [u8]> for Key<KEY_LENGTH> {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let b: [u8; KEY_LENGTH] = bytes.try_into().map_err(|_| Error::SizeError {
            given: bytes.len(),
            expected: KEY_LENGTH,
        })?;
        Ok(Self(b))
    }
}

impl<const KEY_LENGTH: usize> From<Key<KEY_LENGTH>> for [u8; KEY_LENGTH] {
    fn from(k: Key<KEY_LENGTH>) -> [u8; KEY_LENGTH] {
        k.0
    }
}

impl<const KEY_LENGTH: usize> Display for Key<KEY_LENGTH> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}
