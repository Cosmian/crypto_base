use crate::{symmetric_crypto::SymmetricCrypto, CryptoBaseError, KeyTrait};
use std::vec::Vec;

pub mod bonneh_franklin;
pub mod ristretto;

pub trait KeyPair {
    /// Public key
    type PublicKey: KeyTrait;

    /// Private key
    type PrivateKey: KeyTrait;

    /// Return a reference to the public key.
    fn public_key(&self) -> &Self::PublicKey;

    /// Return a reference to the private key.
    fn private_key(&self) -> &Self::PrivateKey;
}

pub trait AsymmetricCrypto: Send + Sync + Default {
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
    ) -> Result<Self::KeyPair, CryptoBaseError>;

    /// Generate a private key
    fn generate_private_key(
        &self,
        parameters: Option<&Self::PrivateKeyGenerationParameters>,
    ) -> Result<<Self::KeyPair as KeyPair>::PrivateKey, CryptoBaseError>;

    /// Generate a symmetric key, and its encryption,to be used in an hybrid
    /// encryption scheme
    fn generate_symmetric_key<S: SymmetricCrypto>(
        &self,
        public_key: &<Self::KeyPair as KeyPair>::PublicKey,
        encryption_parameters: Option<&Self::EncryptionParameters>,
    ) -> Result<(S::Key, Vec<u8>), CryptoBaseError>;

    /// Decrypt a symmetric key used in an hybrid encryption scheme
    fn decrypt_symmetric_key<S: SymmetricCrypto>(
        &self,
        private_key: &<Self::KeyPair as KeyPair>::PrivateKey,
        encrypted_symmetric_key: &[u8],
    ) -> Result<S::Key, CryptoBaseError>;

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
    ) -> Result<Vec<u8>, CryptoBaseError>;

    /// The decrypted message length - this may not be known in certain schemes
    /// in which case zero is returned
    fn clear_text_message_length(encrypted_message_length: usize) -> usize;

    /// Decrypt a message
    fn decrypt(
        &self,
        private_key: &<Self::KeyPair as KeyPair>::PrivateKey,
        cipher_text: &[u8],
    ) -> Result<Vec<u8>, CryptoBaseError>;
}
