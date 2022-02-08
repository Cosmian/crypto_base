use std::{
    cmp::min,
    convert::{TryFrom, TryInto},
    fmt::Display,
    sync::Mutex,
    vec::Vec,
};

use aes_gcm::Aes256Gcm; // Or `Aes128Gcm`
use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, NewAead, Payload},
    AeadInPlace,
};
use rand::{RngCore, SeedableRng};
use rand_hc::Hc128Rng;

use super::SymmetricCrypto;

// This implements AES 256 GCM, using a pure rust interface
// It will use the AES native interface on the CPU if available

pub const KEY_LENGTH: usize = 32;
pub const NONCE_LENGTH: usize = 12;
pub const MAC_LENGTH: usize = 16;

#[derive(Debug, Clone, PartialEq)]
pub struct Key(pub [u8; KEY_LENGTH]);

impl super::Key for Key {
    const LENGTH: usize = KEY_LENGTH;

    fn try_from(bytes: Vec<u8>) -> anyhow::Result<Self> {
        bytes.try_into()
    }

    fn try_from_slice(bytes: &[u8]) -> anyhow::Result<Self> {
        bytes.try_into()
    }

    fn as_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl Key {
    #[must_use]
    pub fn as_array(&self) -> [u8; 32] {
        self.0
    }
}

impl TryFrom<Vec<u8>> for Key {
    type Error = anyhow::Error;

    fn try_from(value: Vec<u8>) -> std::result::Result<Self, Self::Error> {
        value.as_slice().try_into()
    }
}

impl TryFrom<&[u8]> for Key {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        let len = value.len();
        let b: [u8; KEY_LENGTH] = value.try_into().map_err(|_| {
            anyhow::anyhow!(
                "Invalid key of length: {}, expected length: {}",
                len,
                KEY_LENGTH
            )
        })?;
        Ok(Self(b))
    }
}

impl From<Key> for Vec<u8> {
    fn from(k: Key) -> Vec<u8> {
        k.0.to_vec()
    }
}

impl Display for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Nonce(pub [u8; NONCE_LENGTH]);

impl super::Nonce for Nonce {
    const LENGTH: usize = NONCE_LENGTH;

    fn try_from(bytes: Vec<u8>) -> anyhow::Result<Self> {
        bytes.try_into()
    }

    fn try_from_slice(bytes: &[u8]) -> anyhow::Result<Self> {
        bytes.try_into()
    }

    fn increment(&self, increment: usize) -> Self {
        let mut vec = self.0.to_vec();
        vec.extend_from_slice(&[0_u8; 128 - Self::LENGTH]);
        let mut v = u128::from_le_bytes(
            vec.try_into()
                .expect("This should never happen: nonce is 96 bit < 128 bits"),
        );
        v += increment as u128;
        Nonce(
            v.to_be_bytes()[0..Self::LENGTH]
                .try_into()
                .expect("This should never happen: nonce is 96 bit < 128 bits"),
        )
    }

    fn xor(&self, b2: &[u8]) -> Self {
        let mut n = self.0;
        for i in 0..min(b2.len(), NONCE_LENGTH) {
            n[i] ^= b2[i];
        }
        Nonce(n)
    }

    fn as_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl TryFrom<Vec<u8>> for Nonce {
    type Error = anyhow::Error;

    fn try_from(value: Vec<u8>) -> std::result::Result<Self, Self::Error> {
        value.as_slice().try_into()
    }
}

impl TryFrom<&[u8]> for Nonce {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        let len = value.len();

        let b: [u8; NONCE_LENGTH] = value.try_into().map_err(|_| {
            anyhow::anyhow!(
                "Invalid nonce of length: {}, expected length: {}",
                len,
                NONCE_LENGTH
            )
        })?;
        Ok(Self(b))
    }
}

impl From<Nonce> for Vec<u8> {
    fn from(n: Nonce) -> Vec<u8> {
        n.0.to_vec()
    }
}

impl From<Key> for [u8; KEY_LENGTH] {
    fn from(k: Key) -> [u8; KEY_LENGTH] {
        k.0
    }
}

impl Display for Nonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

pub struct Aes256GcmCrypto {
    rng: Mutex<CsRng>,
}

impl Display for Aes256GcmCrypto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", Aes256GcmCrypto::description())
    }
}

impl PartialEq for Aes256GcmCrypto {
    // `rng` is a random generator so you obviously can't
    // compare with other `rng` instance
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Default for Aes256GcmCrypto {
    fn default() -> Self {
        Self::new()
    }
}

impl SymmetricCrypto for Aes256GcmCrypto {
    type Key = Key;
    type Nonce = Nonce;

    const MAC_LENGTH: usize = MAC_LENGTH;

    #[must_use]
    fn new() -> Self {
        Aes256GcmCrypto {
            rng: Mutex::new(CsRng::new()),
        }
    }

    fn description() -> String {
        format!(
            "AES 256 GCM pure Rust (key bits: {}, nonce bits: {}, tag bits: {})",
            KEY_LENGTH * 8,
            NONCE_LENGTH * 8,
            MAC_LENGTH * 8
        )
    }

    fn generate_random_bytes(&self, len: usize) -> Vec<u8> {
        self.rng
            .lock()
            .expect("a mutex lock failed")
            .generate_random_bytes(len)
    }

    fn generate_key_from_rnd(rnd_bytes: &[u8]) -> anyhow::Result<Self::Key> {
        Self::Key::try_from(rnd_bytes)
    }

    fn generate_key(&self) -> Self::Key {
        self.rng.lock().expect("a mutex lock failed").generate_key()
    }

    fn generate_nonce(&self) -> Self::Nonce {
        self.rng
            .lock()
            .expect("a mutex lock failed")
            .generate_nonce()
    }

    fn encrypt(
        &self,
        key: &Self::Key,
        bytes: &[u8],
        nonce: &Self::Nonce,
        additional_data: Option<&[u8]>,
    ) -> anyhow::Result<Vec<u8>> {
        encrypt_combined(key, bytes, nonce, additional_data)
    }

    fn decrypt(
        &self,
        key: &Self::Key,
        bytes: &[u8],
        nonce: &Self::Nonce,
        additional_data: Option<&[u8]>,
    ) -> anyhow::Result<Vec<u8>> {
        decrypt_combined(key, bytes, nonce, additional_data)
    }
}

/// A cryptographically secure RNG for use with AES 256
/// Using this struct avoids having to
/// gather entropy every time which is slow when
/// generating Nonces
pub struct CsRng {
    rng: Hc128Rng,
}

impl CsRng {
    #[must_use]
    pub fn new() -> Self {
        Self {
            rng: Hc128Rng::from_entropy(),
        }
    }

    /// Generate an vector of random bytes
    pub fn generate_random_bytes(&mut self, len: usize) -> Vec<u8> {
        let mut bytes = vec![0_u8; len];
        self.rng.fill_bytes(&mut bytes);
        bytes
    }

    /// Fill `dest ` with random bytes
    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.rng.fill_bytes(dest);
    }

    /// Generate a fresh nonce
    pub fn generate_nonce(&mut self) -> Nonce {
        let mut nonce = Nonce([0_u8; NONCE_LENGTH]);
        self.rng.fill_bytes(&mut nonce.0);
        nonce
    }

    /// Generate a new symmetric random `Key`
    pub fn generate_key(&mut self) -> Key {
        let mut key = Key([0_u8; KEY_LENGTH]);
        self.rng.fill_bytes(&mut key.0);
        key
    }
}

impl Default for CsRng {
    fn default() -> Self {
        CsRng::new()
    }
}

/// Encrypts a message using a secret key and a public nonce in combined mode:
/// the encrypted message, as well as a tag authenticating both the confidential
/// message and non-confidential data, are put into the encrypted result.
///
/// The total length of the encrypted data is the message length + `MAC_LENGTH`
pub fn encrypt_combined(
    key: &Key,
    bytes: &[u8],
    nonce: &Nonce,
    additional_data: Option<&[u8]>,
) -> anyhow::Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key.0));
    let payload = if let Some(aad) = additional_data {
        Payload { msg: bytes, aad }
    } else {
        Payload::from(bytes)
    };
    cipher
        .encrypt(GenericArray::from_slice(&nonce.0), payload)
        .map_err(|e| anyhow::anyhow!(e))
}

/// Encrypts a message in place using a secret key and a public nonce in detached mode:
/// The a tag authenticating both the confidential
/// message and non-confidential data, are returned separately
///
/// The tag length is `MAC_LENGTH`
pub fn encrypt_in_place_detached(
    key: &Key,
    bytes: &mut [u8],
    nonce: &Nonce,
    additional_data: Option<&[u8]>,
) -> anyhow::Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key.0));
    let additional_data = additional_data.unwrap_or_default();
    cipher
        .encrypt_in_place_detached(GenericArray::from_slice(&nonce.0), additional_data, bytes)
        .map_err(|e| anyhow::anyhow!(e))
        .map(|t| t.to_vec())
}

/// Decrypts a message in combined mode: the MAC is appended to the cipher text
///
/// The provided additional data must match those provided during encryption for
/// the MAC to verify.
///
/// Decryption will never be performed, even partially, before verification.
pub fn decrypt_combined(
    key: &Key,
    bytes: &[u8],
    nonce: &Nonce,
    additional_data: Option<&[u8]>,
) -> anyhow::Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key.0));
    let payload = if let Some(aad) = additional_data {
        Payload { msg: bytes, aad }
    } else {
        Payload::from(bytes)
    };
    cipher
        .decrypt(GenericArray::from_slice(&nonce.0), payload)
        .map_err(|e| anyhow::anyhow!(e))
}

/// Decrypts a message in pace in detached mode.
/// The bytes should not contain the authentication tag.
///
/// The provided additional data must match those provided during encryption for
/// the MAC to verify.
///
/// Decryption will never be performed, even partially, before verification.
pub fn decrypt_in_place_detached(
    key: &Key,
    bytes: &mut [u8],
    tag: &[u8],
    nonce: &Nonce,
    additional_data: Option<&[u8]>,
) -> anyhow::Result<()> {
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key.0));
    let additional_data = additional_data.unwrap_or_default();
    cipher
        .decrypt_in_place_detached(
            GenericArray::from_slice(&nonce.0),
            additional_data,
            bytes,
            GenericArray::from_slice(tag),
        )
        .map_err(|e| anyhow::anyhow!(e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key() {
        let mut cs_rng = CsRng::default();
        let key_1 = cs_rng.generate_key();
        assert_eq!(KEY_LENGTH, key_1.0.len());
        let key_2 = cs_rng.generate_key();
        assert_eq!(KEY_LENGTH, key_2.0.len());
        assert_ne!(key_1, key_2);
    }

    #[test]
    fn test_nonce() {
        let mut cs_rng = CsRng::default();
        let nonce_1 = cs_rng.generate_nonce();
        assert_eq!(NONCE_LENGTH, nonce_1.0.len());
        let nonce_2 = cs_rng.generate_nonce();
        assert_eq!(NONCE_LENGTH, nonce_2.0.len());
        assert_ne!(nonce_1, nonce_2);
    }

    #[test]
    fn test_random_bytes() {
        let mut cs_rng = CsRng::default();
        let size: usize = 1024;
        let random_bytes_1 = cs_rng.generate_random_bytes(size);
        assert_eq!(size, random_bytes_1.len());
        let random_bytes_2 = cs_rng.generate_random_bytes(size);
        assert_eq!(size, random_bytes_1.len());
        assert_ne!(random_bytes_1, random_bytes_2);
    }

    #[test]
    fn test_encryption_decryption_combined() -> anyhow::Result<()> {
        let mut cs_rng = CsRng::default();
        let key = cs_rng.generate_key();
        let bytes = cs_rng.generate_random_bytes(8192);
        let iv = cs_rng.generate_nonce();
        // no additional data
        let encrypted_result = encrypt_combined(&key, &bytes, &iv, None)?;
        assert_ne!(encrypted_result, bytes);
        assert_eq!(bytes.len() + MAC_LENGTH, encrypted_result.len());
        let recovered = decrypt_combined(&key, encrypted_result.as_slice(), &iv, None)?;
        assert_eq!(bytes, recovered);
        // additional data
        let ad = cs_rng.generate_random_bytes(42);
        let encrypted_result = encrypt_combined(&key, &bytes, &iv, Some(&ad))?;
        assert_ne!(encrypted_result, bytes);
        assert_eq!(bytes.len() + MAC_LENGTH, encrypted_result.len());
        let recovered = decrypt_combined(&key, encrypted_result.as_slice(), &iv, Some(&ad))?;
        assert_eq!(bytes, recovered);
        Ok(())
    }

    #[test]
    fn test_encryption_decryption_detached() -> anyhow::Result<()> {
        let mut cs_rng = CsRng::default();
        let key = cs_rng.generate_key();
        let bytes = cs_rng.generate_random_bytes(8192);
        let iv = cs_rng.generate_nonce();
        // no additional data
        let mut data = bytes.clone();
        let tag = encrypt_in_place_detached(&key, &mut data, &iv, None)?;
        assert_ne!(bytes, data);
        assert_eq!(bytes.len(), data.len());
        assert_eq!(MAC_LENGTH, tag.len());
        decrypt_in_place_detached(&key, &mut data, &tag, &iv, None)?;
        assert_eq!(bytes, data);
        // // additional data
        let ad = cs_rng.generate_random_bytes(42);
        let mut data = bytes.clone();
        let tag = encrypt_in_place_detached(&key, &mut data, &iv, Some(&ad))?;
        assert_ne!(bytes, data);
        assert_eq!(bytes.len(), data.len());
        assert_eq!(MAC_LENGTH, tag.len());
        decrypt_in_place_detached(&key, &mut data, &tag, &iv, Some(&ad))?;
        assert_eq!(bytes, data);
        Ok(())
    }
}
