pub mod ristretto;

use std::{convert::TryFrom, fmt::Display, vec::Vec};

use crate::symmetric_crypto::SymmetricCrypto;

pub trait KeyPair: TryFrom<&'static [u8]> + Clone + Display + PartialEq {
    type PublicKey: TryFrom<&'static [u8]> + Clone + Display + PartialEq;
    type PrivateKey;
    fn public_key(&self) -> &Self::PublicKey;
    fn private_key(&self) -> &Self::PrivateKey;
}

pub trait AsymmetricCrypto: Send + Sync {
    type KeyPair: KeyPair;
    type KeygenParam;

    /// Instantiate the asymmetric scheme
    fn new() -> Self;

    /// The plain English description of the scheme
    fn description(&self) -> String;

    /// Generate a key pair
    fn generate_key_pair(&self, param: Self::KeygenParam) -> anyhow::Result<Self::KeyPair>;

    /// Generate a symmetric key which is appropriate for asymmetric encryption
    /// in the case of an hybrid encryption scheme
    fn generate_symmetric_key<S: SymmetricCrypto>(&self) -> anyhow::Result<S::Key>;

    /// Encrypt a symmetric key used in an hybrid encryption case.
    /// In most cases, this is the same as the encrypt method
    fn encrypt_symmetric_key<S: SymmetricCrypto>(
        &self,
        public_key: &<Self::KeyPair as KeyPair>::PublicKey,
        symmetric_key: &S::Key,
    ) -> anyhow::Result<Vec<u8>>;

    /// Decrypt a symmetric key used in an hybrid encryption scheme
    fn decrypt_symmetric_key<S: SymmetricCrypto>(
        &self,
        private_key: &<Self::KeyPair as KeyPair>::PrivateKey,
        data: &[u8],
    ) -> anyhow::Result<S::Key>;

    /// A utility function to generate random bytes from an uniform distribution
    /// using a cryptographically secure RNG
    fn generate_random_bytes(&self, len: usize) -> Vec<u8>;

    /// The encrypted message length - this may not be known in certain schemes
    /// in which case zero is returned
    fn encrypted_message_length(&self, clear_text_message_length: usize) -> usize;

    /// Encrypt a message
    fn encrypt(
        &self,
        public_key: &<Self::KeyPair as KeyPair>::PublicKey,
        data: &[u8],
    ) -> anyhow::Result<Vec<u8>>;

    /// The decrypted message length - this may not be known in certain schemes
    /// in which case zero is returned
    fn clear_text_message_length(encrypted_message_length: usize) -> usize;

    /// Decrypt a message
    fn decrypt(
        &self,
        private_key: &<Self::KeyPair as KeyPair>::PrivateKey,
        data: &[u8],
    ) -> anyhow::Result<Vec<u8>>;
}
