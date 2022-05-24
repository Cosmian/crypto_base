use super::{Dem, Kem};
use crate::{
    asymmetric::KeyPair,
    error::Error,
    hybrid_crypto::BytesScanner,
    symmetric_crypto::{nonce::NonceTrait, SymmetricCrypto},
    KeyTrait,
};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, marker::PhantomData};

/// Metadata encrypted as part of the header
///
/// The `uid` is a security parameter:
///  - when using a stream cipher such as AES or `ChaCha20`, it uniquely
///    identifies a resource, such as a file, and is part of the AEAD of every
///    block when symmetrically encrypting data. It prevents an attacker from
///    moving blocks between resources.
///  - when using FPE, it is the "tweak"
///
/// The `additional_data` is not used as a security parameter. It is optional
/// data (such as index tags) symmetrically encrypted as part of the header.
#[derive(Debug, PartialEq, Clone, Default, Serialize, Deserialize)]
pub struct Metadata {
    pub uid: Vec<u8>,
    pub additional_data: Option<Vec<u8>>,
}

impl Metadata {
    /// The length in bytes of this meta data
    pub fn len(&self) -> usize {
        self.uid.len()
            + match &self.additional_data {
                Some(v) => v.len(),
                None => 0,
            }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Encode the metadata as a byte array
    ///
    /// The first 4 bytes is the u32 length of the UID as big endian bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        if self.is_empty() {
            return Ok(vec![]);
        }
        let mut bytes = u32_len(&self.uid)?.to_vec();
        bytes.extend(&self.uid);
        if let Some(ad) = &self.additional_data {
            bytes.extend(ad);
        }
        Ok(bytes)
    }

    /// Decode the metadata from a byte array
    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Metadata> {
        if bytes.is_empty() {
            return Ok(Metadata::default());
        }
        let mut scanner = BytesScanner::new(bytes);
        let uid_len = scanner.read_u32()? as usize;
        let uid = scanner.next(uid_len)?.to_vec();
        let additional_data = scanner.remainder().to_owned().map(|v| v.to_vec());

        Ok(Metadata {
            uid,
            additional_data,
        })
    }
}

/// A `Header` contains the the resource `uid` and an
/// encryption of the symmetric key used to encrypt the resource content.
/// The symmetric key is encrypted using a public key cryptographic scheme
#[derive(Debug, PartialEq)]
pub struct Header<K: Kem, D: Dem> {
    /// metadata that are encrypted as part of the header
    metadata: Metadata,
    /// the randomly generated symmetric key used to encrypt the resources
    symmetric_key: <D as SymmetricCrypto>::Key,
    /// the encrypted symmetric key which is part of the header
    encrypted_symmetric_key: Vec<u8>,
    phantom_kem: PhantomData<K>,
    phantom_dem: PhantomData<D>,
}

impl<K: Kem, D: Dem> Header<K, D> {
    /// Generate a new encrypted resource header from a uid and
    /// the symmetric key used to encrypt the resource content
    pub fn generate<R: CryptoRng + RngCore>(
        rng: &mut R,
        public_key: &<<K as Kem>::KeyPair as KeyPair>::PublicKey,
        metadata: Metadata,
    ) -> anyhow::Result<Self> {
        let (K, E) = <K as Kem>::encaps(rng, public_key)?;
        let symmetric_key = <D as SymmetricCrypto>::Key::try_from_bytes(
            K[..<<D as SymmetricCrypto>::Key as KeyTrait>::LENGTH].to_vec(),
        )?;
        Ok(Header {
            metadata,
            symmetric_key,
            encrypted_symmetric_key: E,
            phantom_kem: PhantomData,
            phantom_dem: PhantomData,
        })
    }

    /// Parses an encrypted header, decrypting the symmetric key and the UID
    /// See `to_bytes()` for details on the format
    pub fn from_bytes(
        bytes: &[u8],
        private_key: &<<K as Kem>::KeyPair as KeyPair>::PrivateKey,
    ) -> anyhow::Result<Self> {
        // scan the input bytes
        let mut scanner = BytesScanner::new(bytes);

        // encrypted symmetric key size
        let encrypted_symmetric_key_size = scanner.read_u32()? as usize;
        let encrypted_symmetric_key = scanner.next(encrypted_symmetric_key_size)?.to_vec();

        // symmetric key
        let K = <K as Kem>::decaps(private_key, &encrypted_symmetric_key)?;
        let symmetric_key = <D as SymmetricCrypto>::Key::try_from_bytes(
            K[..<<D as SymmetricCrypto>::Key as KeyTrait>::LENGTH].to_vec(),
        )?;

        let metadata = if scanner.has_more() {
            // Nonce
            let nonce = D::Nonce::try_from_bytes(scanner.next(D::Nonce::LENGTH)?.to_vec())?;

            // encrypted metadata
            let encrypted_metadata_size = scanner.read_u32()? as usize;

            // UID
            let encrypted_metadata = scanner.next(encrypted_metadata_size)?;
            Metadata::from_bytes(&D::decrypt(
                &symmetric_key,
                encrypted_metadata,
                &nonce,
                None,
            )?)?
        } else {
            Metadata::default()
        };

        Ok(Header {
            metadata,
            symmetric_key,
            encrypted_symmetric_key,
            phantom_kem: PhantomData,
            phantom_dem: PhantomData,
        })
    }

    /// Generates the header bytes, encrypting the symmetric key
    ///
    /// The header is encoded using the following format
    ///  - [0,4[: big-endian u32: the size S of the encrypted symmetric key
    ///  - [4,S+4[: the encrypted symmetric key
    ///  - [S+4,S+4+N]: the nonce (fixed size) if the meta data is not empty
    ///  - [S+4+N, S+8+N[: big-endian u32: the size M of the symmetrically
    ///    encrypted Metadata
    ///  - [S+8+N,S+8+N+M[: the symmetrically encrypted metadata
    pub fn to_bytes<R: CryptoRng + RngCore>(&self, rng: &mut R) -> anyhow::Result<Vec<u8>> {
        // ..size
        let mut bytes = u32_len(&self.encrypted_symmetric_key)?.to_vec();
        // ...bytes
        bytes.extend(&self.encrypted_symmetric_key);

        if !&self.meta_data().is_empty() {
            // Nonce
            let nonce = D::Nonce::new(rng);
            bytes.extend(nonce.to_bytes());

            // Encrypted metadata
            let encrypted_metadata = D::encrypt(
                &self.symmetric_key,
                &self.metadata.to_bytes()?,
                &nonce,
                None,
            )?;
            // ... size
            bytes.extend(u32_len(&encrypted_metadata)?);
            // ... bytes
            bytes.extend(encrypted_metadata);
        }
        Ok(bytes)
    }

    /// The clear text symmetric key generated in the header
    pub fn symmetric_key(&self) -> &D::Key {
        &self.symmetric_key
    }

    /// The meta data in the header
    pub fn meta_data(&self) -> &Metadata {
        &self.metadata
    }
}

// Attempt getting the length of this slice as an u32 in 4 endian bytes and
// return an error if it overflows
fn u32_len(slice: &[u8]) -> Result<[u8; 4], crate::Error> {
    u32::try_from(slice.len())
        .map_err(|_| {
            Error::InvalidSize("Slice of bytes is too big to fit in 2^32 bytes".to_string())
        })
        .map(u32::to_be_bytes)
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {

    use crate::{
        asymmetric::{ristretto::X25519Crypto, KeyPair},
        entropy::CsRng,
        hybrid_crypto::{header::Metadata, Header, Kem},
        symmetric_crypto::aes_256_gcm_pure::Aes256GcmCrypto,
    };

    #[test]
    pub fn test_meta_data() -> anyhow::Result<()> {
        let mut rng = CsRng::new();

        // Full metadata test
        let metadata_full = Metadata {
            uid: rng.generate_random_bytes(32),
            additional_data: Some(rng.generate_random_bytes(256)),
        };
        assert_eq!(
            &metadata_full,
            &Metadata::from_bytes(&metadata_full.to_bytes()?)?
        );

        // Partial metadata test
        let metadata_partial = Metadata {
            uid: rng.generate_random_bytes(32),
            additional_data: None,
        };
        assert_eq!(
            &metadata_partial,
            &Metadata::from_bytes(&metadata_partial.to_bytes()?)?
        );
        Ok(())
    }

    #[test]
    pub fn test_header() -> anyhow::Result<()> {
        let mut rng = CsRng::new();
        let key_pair = <X25519Crypto as Kem>::key_gen(&mut rng);

        // Full metadata test
        let metadata_full = Metadata {
            uid: rng.generate_random_bytes(32),
            additional_data: Some(rng.generate_random_bytes(256)),
        };

        let header = Header::<X25519Crypto, Aes256GcmCrypto>::generate(
            &mut rng,
            key_pair.public_key(),
            metadata_full.clone(),
        )?;

        let bytes = header.to_bytes(&mut rng)?;
        let header_ =
            Header::<X25519Crypto, Aes256GcmCrypto>::from_bytes(&bytes, key_pair.private_key())?;

        assert_eq!(&metadata_full, &header_.metadata);

        // sec only metadata test
        let metadata_sec = Metadata {
            uid: rng.generate_random_bytes(32),
            additional_data: None,
        };

        let header = Header::<X25519Crypto, Aes256GcmCrypto>::generate(
            &mut rng,
            key_pair.public_key(),
            metadata_sec.clone(),
        )?;

        let bytes = header.to_bytes(&mut rng)?;
        let header_ =
            Header::<X25519Crypto, Aes256GcmCrypto>::from_bytes(&bytes, key_pair.private_key())?;

        assert_eq!(&metadata_sec, &header_.metadata);

        // no metadata test
        let metadata_empty = Metadata {
            uid: vec![],
            additional_data: None,
        };

        let header = Header::<X25519Crypto, Aes256GcmCrypto>::generate(
            &mut rng,
            key_pair.public_key(),
            metadata_empty.clone(),
        )?;

        let bytes = header.to_bytes(&mut rng)?;
        let header_ =
            Header::<X25519Crypto, Aes256GcmCrypto>::from_bytes(&bytes, key_pair.private_key())?;

        assert_eq!(&metadata_empty, &header_.metadata);
        Ok(())
    }
}
