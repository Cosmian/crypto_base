use crate::{Error, KeyTrait};
use std::vec::Vec;

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
    fn key_gen(
        &self,
        parameters: Option<&Self::KeyPairGenerationParameters>,
    ) -> Result<Self::KeyPair, Error>;

    /// Encrypt a message
    fn encrypt(
        &self,
        public_key: &<Self::KeyPair as KeyPair>::PublicKey,
        encryption_parameters: Option<&Self::EncryptionParameters>,
        data: &[u8],
    ) -> Result<Vec<u8>, Error>;

    /// Decrypt a message
    fn decrypt(
        &self,
        private_key: &<Self::KeyPair as KeyPair>::PrivateKey,
        cipher_text: &[u8],
    ) -> Result<Vec<u8>, Error>;
}
