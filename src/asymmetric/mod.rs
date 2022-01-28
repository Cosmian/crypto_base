pub mod ristretto;

use std::vec::Vec;

use crate::symmetric_crypto::SymmetricCrypto;

pub trait KeyPair {
    type PublicKey;
    type PrivateKey;
    fn public_key(&self) -> &Self::PublicKey;
    fn private_key(&self) -> &Self::PrivateKey;
}

pub trait AsymmetricCrypto: Send + Sync {
    /// Specify the type of Keys
    type KeyPair: KeyPair;

    /// Support for schemes such as ABE which require an Access Policy and a
    /// Public Key to generate a user decryption key pair
    type KeyPairGenerationParameters;

    /// Support for schemes such as ABE which require an Access Policy to
    /// generate a user decryption key
    type PrivateKeyGenerationParameters;

    /// Support for schemes such as ABE which require Policy attributes to be
    /// passed during encryption
    type EncryptionParameters;

    /// Instantiate the asymmetric scheme
    fn new() -> Self;

    /// The plain English description of the scheme
    fn description(&self) -> String;

    /// Generate a key pair, private key and public key
    fn generate_key_pair(
        &self,
        parameters: Option<&Self::KeyPairGenerationParameters>,
    ) -> anyhow::Result<Self::KeyPair>;

    /// Generate a private key
    fn generate_private_key(
        &self,
        parameters: Option<&Self::PrivateKeyGenerationParameters>,
    ) -> anyhow::Result<<Self::KeyPair as KeyPair>::PrivateKey>;

    /// Generate a symmetric key, and its encryption,to be used in an hybrid
    /// encryption scheme
    fn generate_symmetric_key<S: SymmetricCrypto>(
        &self,
        public_key: &<Self::KeyPair as KeyPair>::PublicKey,
        encryption_parameters: Option<&Self::EncryptionParameters>,
    ) -> anyhow::Result<(S::Key, Vec<u8>)>;

    /// Decrypt a symmetric key used in an hybrid encryption scheme
    fn decrypt_symmetric_key<S: SymmetricCrypto>(
        &self,
        private_key: &<Self::KeyPair as KeyPair>::PrivateKey,
        encrypted_symmetric_key: &[u8],
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
        encryption_parameters: Option<&Self::EncryptionParameters>,
        data: &[u8],
    ) -> anyhow::Result<Vec<u8>>;

    /// The decrypted message length - this may not be known in certain schemes
    /// in which case zero is returned
    fn clear_text_message_length(encrypted_message_length: usize) -> usize;

    /// Decrypt a message
    fn decrypt(
        &self,
        private_key: &<Self::KeyPair as KeyPair>::PrivateKey,
        cipher_text: &[u8],
    ) -> anyhow::Result<Vec<u8>>;
}
