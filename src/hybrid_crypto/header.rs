use crate::{
    asymmetric::{AsymmetricCrypto, KeyPair},
    symmetric_crypto::{Key, SymmetricCrypto},
};

pub const UID_LENGTH: usize = 32;

/// A `Header` contains the the resource `uid` and an
/// encryption of the symmetric key used to encrypt the resource content.
/// The symmetric key is encrypted using a public key cryptographic scheme
#[derive(Debug, PartialEq)]
pub struct Header<A: AsymmetricCrypto, S: SymmetricCrypto> {
    // the file UID: unique and never changes even when renamed
    pub uid: [u8; UID_LENGTH],
    // the randomly generated symmetric key used to encrypt the file
    pub symmetric_key: <S as SymmetricCrypto>::Key,
    // since A is not used here (but we need need it later),
    // make a phantom field that uses A
    phantom: std::marker::PhantomData<A>,
}

impl<A, S> Header<A, S>
where
    A: AsymmetricCrypto,
    S: SymmetricCrypto,
{
    #[must_use]
    pub fn length(asymmetric: &A) -> usize {
        let symmetric_key_length = <S as SymmetricCrypto>::Key::LENGTH;
        symmetric_key_length
            + <A as AsymmetricCrypto>::encrypted_message_length(asymmetric, symmetric_key_length)
    }

    /// Instantiate a new encrypted resource header from a uid and
    /// the symmetric key used to encrypt the resource content
    pub fn new(uid: [u8; UID_LENGTH], symmetric_key: <S as SymmetricCrypto>::Key) -> Self {
        Header {
            symmetric_key,
            uid,
            phantom: std::marker::PhantomData,
        }
    }

    /// Parses an encrypted header, decrypting the symmetric key
    pub fn from_encrypted_bytes(
        bytes: &[u8],
        asymmetric: &A,
        private_key: &<<A as AsymmetricCrypto>::KeyPair as KeyPair>::PrivateKey,
    ) -> anyhow::Result<Self> {
        if bytes.len() != Header::<A, S>::length(asymmetric) {
            anyhow::bail!(
                "the header has an invalid length of {} bytes; {} bytes expected",
                bytes.len(),
                Header::<A, S>::length(asymmetric)
            );
        }
        // uid
        let mut uid = [0_u8; UID_LENGTH];
        uid.copy_from_slice(&bytes[0..UID_LENGTH]);
        //key
        let enc_key_bytes = &bytes[UID_LENGTH..];
        let symmetric_key = asymmetric.decrypt_symmetric_key::<S>(private_key, enc_key_bytes)?;
        Ok(Header {
            uid,
            symmetric_key,
            phantom: std::marker::PhantomData,
        })
    }

    /// Generates the header bytes, encrypting the symmetric key
    pub fn to_bytes(&self, encrypted_symmetric_key: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        let mut bytes = self.uid.to_vec();
        bytes.extend(encrypted_symmetric_key);
        Ok(bytes)
    }
}

impl<A, S> Clone for Header<A, S>
where
    A: AsymmetricCrypto,
    S: SymmetricCrypto,
{
    fn clone(&self) -> Self {
        Header {
            uid: self.uid,
            symmetric_key: self.symmetric_key.clone(),
            phantom: std::marker::PhantomData,
        }
    }
}
