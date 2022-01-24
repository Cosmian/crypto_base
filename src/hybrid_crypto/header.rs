use std::convert::{TryFrom, TryInto};

use crate::{
    asymmetric::{AsymmetricCrypto, KeyPair},
    symmetric_crypto::{Nonce, SymmetricCrypto},
};

/// Metadata encrypted as part of the header
///
/// The `sec` is a security parameter:
///  - when using a stream cipher such as AES or ChaCha20, it uniquely
///    identifies a resource, such as a file, and is part of the AEAD of every
///    block when symmetrically encrypting data. It prevents an attacker from
///    moving blocks between resources.
///  - when using FPE, it is the "tweak"
///
/// The `additional_data` is not used as a security parameter. It is optional
/// data (such as index tags) symmetrically encrypted as part of the header.
#[derive(Debug, PartialEq, Clone)]
pub struct Metadata {
    pub sec: Vec<u8>,
    pub additional_data: Vec<u8>,
}

impl Metadata {
    /// Encode the metadata as a byte array
    pub fn as_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut bytes = u32_len(&self.sec)?.to_vec();
        bytes.extend(&self.sec);
        bytes.extend(u32_len(&self.additional_data)?.to_vec());
        bytes.extend(&self.additional_data);
        Ok(bytes)
    }

    /// Decode the metadata from a byte array
    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Metadata> {
        let mut scanner = BytesScanner::new(bytes);
        let sec_len = scanner.read_u32()? as usize;
        let sec = scanner.next(sec_len)?.to_vec();
        let additional_data_len = scanner.read_u32()? as usize;
        let additional_data = scanner.next(additional_data_len)?.to_vec();
        Ok(Metadata {
            sec,
            additional_data,
        })
    }
}

/// A `Header` contains the the resource `uid` and an
/// encryption of the symmetric key used to encrypt the resource content.
/// The symmetric key is encrypted using a public key cryptographic scheme
#[derive(Debug, PartialEq)]
pub struct Header<'a, A: AsymmetricCrypto, S: SymmetricCrypto> {
    asymmetric_scheme: &'a A,
    // the resources UID: unique and never changes even when renamed
    pub metadata: Metadata,
    // the randomly generated symmetric key used to encrypt the resources
    pub symmetric_key: <S as SymmetricCrypto>::Key,
    // // since A is not used here (but we need need it later),
}

impl<'a, A, S> Header<'a, A, S>
where
    A: AsymmetricCrypto,
    S: SymmetricCrypto,
{
    /// Generate a new encrypted resource header from a uid and
    /// the symmetric key used to encrypt the resource content
    pub fn generate(asymmetric_scheme: &'a A, metadata: Metadata) -> anyhow::Result<Self> {
        Ok(Header {
            metadata,
            symmetric_key: asymmetric_scheme.generate_symmetric_key::<S>()?,
            asymmetric_scheme,
        })
    }

    /// Parses an encrypted header, decrypting the symmetric key and the UID
    /// See `to_bytes()` for details on the format
    pub fn from_encrypted_bytes(
        bytes: &[u8],
        asymmetric_scheme: &'a A,
        private_key: &<<A as AsymmetricCrypto>::KeyPair as KeyPair>::PrivateKey,
    ) -> anyhow::Result<Self> {
        // scan the input bytes
        let mut scanner = BytesScanner::new(bytes);

        // encrypted symmetric key size
        let encrypted_symmetric_key_size = scanner.read_u32()? as usize;

        // symmetric key
        let symmetric_key = asymmetric_scheme
            .decrypt_symmetric_key::<S>(private_key, scanner.next(encrypted_symmetric_key_size)?)?;

        // Nonce
        let nonce = <<S as SymmetricCrypto>::Nonce>::try_from_slice(
            scanner.next(<<S as SymmetricCrypto>::Nonce>::LENGTH)?,
        )?;

        // encrypted metadata
        let encrypted_metadata_size = scanner.read_u32()? as usize;

        // UID
        let encrypted_metadata = scanner.next(encrypted_metadata_size)?;
        let symmetric_scheme = <S as SymmetricCrypto>::new();
        let metadata = Metadata::from_bytes(&symmetric_scheme.decrypt(
            &symmetric_key,
            encrypted_metadata,
            &nonce,
            None,
        )?)?;

        Ok(Header {
            metadata,
            symmetric_key,
            asymmetric_scheme,
        })
    }

    /// Generates the header bytes, encrypting the symmetric key
    ///
    /// The header is encoded using the following format
    ///  - [0,4[: big-endian u32: the size S of the encrypted symmetric key
    ///  - [4,S+4[: the encrypted symmetric key
    ///  - [S+4,S+4+N]: the nonce (fixed size)
    ///  - [S+4+N, S+8+N[: big-endian u32: the size M of the symmetrically
    ///    encrypted Metadata
    ///  - [S+8+N,S+8+N+M[: the symmetrically encrypted metadata
    pub fn as_bytes(
        &self,
        public_key: &<<A as AsymmetricCrypto>::KeyPair as KeyPair>::PublicKey,
        encryption_parameters: Option<&<A as AsymmetricCrypto>::EncryptionParameters>,
    ) -> anyhow::Result<Vec<u8>> {
        // Encrypted Symmetric key
        let encrypted_symmetric_key = self.asymmetric_scheme.encrypt_symmetric_key::<S>(
            public_key,
            encryption_parameters,
            &self.symmetric_key,
        )?;
        // ..size
        let mut bytes = u32_len(&encrypted_symmetric_key)?.to_vec();
        // ...bytes
        bytes.extend(encrypted_symmetric_key);

        let symmetric_scheme = <S as SymmetricCrypto>::new();

        // Nonce
        let nonce = symmetric_scheme.generate_nonce();
        bytes.extend(nonce.as_bytes());

        // Encrypted metadata
        let encrypted_metadata = symmetric_scheme.encrypt(
            &self.symmetric_key,
            &self.metadata.as_bytes()?,
            &nonce,
            None,
        )?;
        // ... size
        bytes.extend(u32_len(&encrypted_metadata)?);
        // ... bytes
        bytes.extend(encrypted_metadata);
        Ok(bytes)
    }
}

// Attempt getting the length of this slice as an u32 in 4 endian bytes and
// return an error if it overflows
fn u32_len(slice: &[u8]) -> anyhow::Result<[u8; 4]> {
    u32::try_from(slice.len())
        .map_err(|_e| anyhow::anyhow!("Slice of bytes is too big to fit in 2^32 bytes"))
        .map(|i| i.to_be_bytes())
}

/// Scans a slice sequentially, updating the cursor position on the fly
struct BytesScanner<'a> {
    bytes: &'a [u8],
    start: usize,
}

impl<'a> BytesScanner<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        BytesScanner { bytes, start: 0 }
    }

    /// Returns a slice of the next `size` bytes or an error if less is
    /// available
    pub fn next(&mut self, size: usize) -> anyhow::Result<&'a [u8]> {
        let end = self.start + size;
        if self.bytes.len() < end {
            anyhow::bail!(
                "Invalid size: {}, only {} bytes available",
                size,
                self.bytes.len() - self.start
            );
        }
        let chunk = &self.bytes[self.start..end];
        self.start = end;
        Ok(chunk)
    }

    /// Read the next 4 big endian bytes to return an u32
    pub fn read_u32(&mut self) -> anyhow::Result<u32> {
        Ok(u32::from_be_bytes(
            self.next(4)?
                .try_into()
                .map_err(|_e| anyhow::anyhow!("invalid u32"))?,
        ))
    }

    /// Returns the remainder of the slice
    #[allow(dead_code)]
    pub fn remainder(&mut self) -> Option<&'a [u8]> {
        if self.start >= self.bytes.len() {
            None
        } else {
            let remainder = &self.bytes[self.start..];
            self.start = self.bytes.len();
            Some(remainder)
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        asymmetric::{ristretto::X25519Crypto, AsymmetricCrypto},
        hybrid_crypto::{header::Metadata, Header},
        symmetric_crypto::aes_256_gcm_pure::Aes256GcmCrypto,
    };

    #[test]
    pub fn test_header() -> anyhow::Result<()> {
        let asymmetric_scheme = X25519Crypto::default();
        let key_pair = asymmetric_scheme.generate_key_pair(None)?;

        // Full metadata test
        let metadata_full = Metadata {
            sec: asymmetric_scheme.generate_random_bytes(32),
            additional_data: asymmetric_scheme.generate_random_bytes(256),
        };

        let header = Header::<X25519Crypto, Aes256GcmCrypto>::generate(
            &asymmetric_scheme,
            metadata_full.clone(),
        )?;

        let bytes = header.as_bytes(&key_pair.public_key, None)?;
        let header_ = Header::<X25519Crypto, Aes256GcmCrypto>::from_encrypted_bytes(
            &bytes,
            &asymmetric_scheme,
            &key_pair.private_key,
        )?;

        assert_eq!(&metadata_full, &header_.metadata);

        // sec only metadata test
        let metadata_sec = Metadata {
            sec: asymmetric_scheme.generate_random_bytes(32),
            additional_data: vec![],
        };

        let header = Header::<X25519Crypto, Aes256GcmCrypto>::generate(
            &asymmetric_scheme,
            metadata_sec.clone(),
        )?;

        let bytes = header.as_bytes(&key_pair.public_key, None)?;
        let header_ = Header::<X25519Crypto, Aes256GcmCrypto>::from_encrypted_bytes(
            &bytes,
            &asymmetric_scheme,
            &key_pair.private_key,
        )?;

        assert_eq!(&metadata_sec, &header_.metadata);

        // no metadata test
        let metadata_empty = Metadata {
            sec: vec![],
            additional_data: vec![],
        };

        let header = Header::<X25519Crypto, Aes256GcmCrypto>::generate(
            &asymmetric_scheme,
            metadata_empty.clone(),
        )?;

        let bytes = header.as_bytes(&key_pair.public_key, None)?;
        let header_ = Header::<X25519Crypto, Aes256GcmCrypto>::from_encrypted_bytes(
            &bytes,
            &asymmetric_scheme,
            &key_pair.private_key,
        )?;

        assert_eq!(&metadata_empty, &header_.metadata);
        Ok(())
    }
}
