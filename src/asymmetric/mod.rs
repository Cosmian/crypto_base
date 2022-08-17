use cosmian_crypto_core::KeyTrait;

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

    /// Instantiate the asymmetric scheme
    fn new() -> Self;

    /// The plain English description of the scheme
    fn description(&self) -> String;

    /// Generate a key pair, private key and public key
    fn generate_key_pair(&self) -> Self::KeyPair;
}
