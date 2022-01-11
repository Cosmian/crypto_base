// TODO BGR had to de-actiavte sodium binding for now becasue decryption also
// requires TODO passing the public key (which does not make a lot of sense)
// #[cfg(all(not(target_arch = "wasm32"), not(windows), feature = "libsodium"))]
// pub mod x25519_sodium;

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

    fn new() -> Self;

    fn new_attrs(attrs: &[u32]) -> Self;

    fn description(&self) -> String;

    fn generate_key_pair(&self, param: Self::KeygenParam) -> anyhow::Result<Self::KeyPair>;

    // To allow dependencies on the asymmetric scheme
    // this function generates the usable symmetric key and its
    // encrypted form serialized. The serialization part is needed when
    // the generation is done by the asymmetric scheme but a
    // postprocessing is performed to derive the symmetric key. In this case
    // we must encrypt the pre processing form, not the key itself
    fn generate_symmetric_key<S: SymmetricCrypto>(
        &self,
        public_key: &<Self::KeyPair as KeyPair>::PublicKey,
    ) -> anyhow::Result<(S::Key, Vec<u8>)>;

    fn decrypt_symmetric_key<S: SymmetricCrypto>(
        &self,
        private_key: &<Self::KeyPair as KeyPair>::PrivateKey,
        data: &[u8],
    ) -> anyhow::Result<S::Key>;

    fn generate_random_bytes(&self, len: usize) -> Vec<u8>;

    fn encrypted_message_length(&self, clear_text_message_length: usize) -> usize;

    fn encrypt(
        &self,
        public_key: &<Self::KeyPair as KeyPair>::PublicKey,
        data: &[u8],
    ) -> anyhow::Result<Vec<u8>>;

    fn clear_text_message_length(encrypted_message_length: usize) -> usize;

    fn decrypt(
        &self,
        private_key: &<Self::KeyPair as KeyPair>::PrivateKey,
        data: &[u8],
    ) -> anyhow::Result<Vec<u8>>;
}
