use super::{AsymmetricCrypto, KeyPair};
use crate::{entropy::CsRng, Error, KeyTrait};
use curve25519_dalek::{
    constants,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    convert::{TryFrom, TryInto},
    fmt::Display,
    ops::{Add, DerefMut, Mul, Sub},
    sync::Mutex,
};

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[serde(try_from = "Vec<u8>", into = "Vec<u8>")]
pub struct X25519PrivateKey(Scalar);

impl X25519PrivateKey {
    #[must_use]
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        X25519PrivateKey(Scalar::random(rng))
    }

    #[must_use]
    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl KeyTrait for X25519PrivateKey {
    const LENGTH: usize = 32;

    #[must_use]
    fn to_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }

    fn try_from_bytes(bytes: Vec<u8>) -> Result<Self, Error> {
        Self::try_from(bytes)
    }
}

impl TryFrom<Vec<u8>> for X25519PrivateKey {
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl TryFrom<&[u8]> for X25519PrivateKey {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let len = bytes.len();
        let bytes: [u8; <Self>::LENGTH] = bytes.try_into().map_err(|_| Error::SizeError {
            given: len,
            expected: <Self>::LENGTH,
        })?;
        let scalar = Scalar::from_canonical_bytes(bytes).ok_or_else(|| {
            Error::ConversionError("Given bytes do not represent a cannonical Scalar!".to_string())
        })?;
        Ok(X25519PrivateKey(scalar))
    }
}

impl From<X25519PrivateKey> for Vec<u8> {
    fn from(key: X25519PrivateKey) -> Self {
        key.to_bytes()
    }
}

/// Parse from an hex encoded String
impl TryFrom<&str> for X25519PrivateKey {
    type Error = Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        let bytes = hex::decode(value)?;
        X25519PrivateKey::try_from(bytes)
    }
}

/// Display the hex encoded value of the key
impl Display for X25519PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0.as_bytes()))
    }
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[serde(try_from = "Vec<u8>", into = "Vec<u8>")]
pub struct X25519PublicKey(RistrettoPoint);

impl X25519PublicKey {
    //compressed
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self::from(&X25519PrivateKey::new(rng))
    }
}

impl KeyTrait for X25519PublicKey {
    const LENGTH: usize = 32;

    #[must_use]
    fn to_bytes(&self) -> Vec<u8> {
        self.0.compress().to_bytes().to_vec()
    }

    fn try_from_bytes(bytes: Vec<u8>) -> Result<Self, Error> {
        Self::try_from(bytes)
    }
}

impl From<&X25519PrivateKey> for X25519PublicKey {
    fn from(private_key: &X25519PrivateKey) -> Self {
        X25519PublicKey(&private_key.0 * &constants::RISTRETTO_BASEPOINT_TABLE)
    }
}

impl TryFrom<Vec<u8>> for X25519PublicKey {
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl TryFrom<&[u8]> for X25519PublicKey {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let len = value.len();
        if len != <X25519PublicKey>::LENGTH {
            return Err(Error::SizeError {
                given: len,
                expected: <X25519PublicKey>::LENGTH,
            });
        };
        let compressed = CompressedRistretto::from_slice(value);
        let point = compressed.decompress().ok_or_else(|| {
            Error::ConversionError(
                "Cannot decompress given bytes into a valid curve point!".to_string(),
            )
        })?;
        Ok(X25519PublicKey(point))
    }
}

impl From<X25519PublicKey> for Vec<u8> {
    fn from(key: X25519PublicKey) -> Self {
        key.to_bytes()
    }
}

/// Parse from an hex encoded String
impl TryFrom<&str> for X25519PublicKey {
    type Error = Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        let bytes = hex::decode(value)?;
        X25519PublicKey::try_from(bytes.as_slice())
    }
}

/// Display the hex encoded value of the key
impl Display for X25519PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0.compress().to_bytes()))
    }
}

impl<'a, 'b> Mul<&'a X25519PrivateKey> for &'b X25519PublicKey {
    type Output = X25519PublicKey;

    fn mul(self, rhs: &'a X25519PrivateKey) -> Self::Output {
        X25519PublicKey(self.0 * rhs.0)
    }
}

impl<'a> Mul<&'a X25519PrivateKey> for X25519PublicKey {
    type Output = X25519PublicKey;

    fn mul(self, rhs: &'a X25519PrivateKey) -> Self::Output {
        X25519PublicKey(self.0 * rhs.0)
    }
}

impl<'a, 'b> Add<&'a X25519PublicKey> for &'b X25519PublicKey {
    type Output = X25519PublicKey;

    fn add(self, rhs: &'a X25519PublicKey) -> Self::Output {
        X25519PublicKey(self.0 + rhs.0)
    }
}

impl<'a, 'b> Sub<&'a X25519PublicKey> for &'b X25519PublicKey {
    type Output = X25519PublicKey;

    fn sub(self, rhs: &'a X25519PublicKey) -> Self::Output {
        X25519PublicKey(self.0 - rhs.0)
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct X25519KeyPair {
    private_key: X25519PrivateKey,
    public_key: X25519PublicKey,
}

impl X25519KeyPair {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let private_key = X25519PrivateKey::new(rng);
        let public_key = X25519PublicKey::from(&private_key);
        X25519KeyPair {
            private_key,
            public_key,
        }
    }
}

impl KeyPair for X25519KeyPair {
    type PrivateKey = X25519PrivateKey;
    type PublicKey = X25519PublicKey;

    fn public_key(&self) -> &Self::PublicKey {
        &self.public_key
    }

    fn private_key(&self) -> &Self::PrivateKey {
        &self.private_key
    }
}

#[allow(clippy::from_over_into)]
impl Into<Vec<u8>> for X25519KeyPair {
    fn into(self) -> Vec<u8> {
        let mut bytes = self.private_key().to_bytes();
        bytes.append(&mut self.public_key().to_bytes());
        bytes
    }
}

impl TryFrom<Vec<u8>> for X25519KeyPair {
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl TryFrom<&[u8]> for X25519KeyPair {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let len = <Self as KeyPair>::PrivateKey::LENGTH + <Self as KeyPair>::PublicKey::LENGTH;
        if len != bytes.len() {
            return Err(Error::SizeError {
                given: bytes.len(),
                expected: len,
            });
        }
        let private_key = <Self as KeyPair>::PrivateKey::try_from(
            &bytes[..<Self as KeyPair>::PrivateKey::LENGTH],
        )?;
        let public_key = <Self as KeyPair>::PublicKey::try_from(
            &bytes[<Self as KeyPair>::PrivateKey::LENGTH..],
        )?;
        Ok(X25519KeyPair {
            private_key,
            public_key,
        })
    }
}

impl Display for X25519KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}", self.private_key(), self.public_key())
    }
}

pub struct X25519Crypto {
    pub(crate) rng: Mutex<CsRng>,
}

impl Default for X25519Crypto {
    fn default() -> Self {
        Self::new()
    }
}

impl Display for X25519Crypto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.description())
    }
}

impl PartialEq for X25519Crypto {
    fn eq(&self, other: &Self) -> bool {
        self.description() == other.description()
    }
}

impl AsymmetricCrypto for X25519Crypto {
    type EncryptionParameters = ();
    type KeyPair = X25519KeyPair;
    type KeyPairGenerationParameters = ();
    type PrivateKeyGenerationParameters = ();

    /// Instantiate the Ristretto X25519 Curve
    #[must_use]
    fn new() -> Self {
        Self {
            rng: Mutex::new(CsRng::new()),
        }
    }

    /// The plain English description of the scheme
    fn description(&self) -> String {
        "Ristretto X25519".to_string()
    }

    /// Generate a key pair, private key and public key
    fn key_gen(
        &self,
        _: Option<&Self::KeyPairGenerationParameters>,
    ) -> Result<Self::KeyPair, Error> {
        Ok(X25519KeyPair::new(
            self.rng.lock().expect("a lock failed").deref_mut(),
        ))
    }

    /// Encrypt a message using ECIES
    /// https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme
    fn encrypt(
        &self,
        public_key: &<Self::KeyPair as KeyPair>::PublicKey,
        _: Option<&Self::EncryptionParameters>,
        data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let m = X25519PublicKey::try_from(data)?;
        let r = X25519PrivateKey::new(self.rng.lock().expect("Mutex lock fail").deref_mut());
        let c = (&m + &(public_key * &r), X25519PublicKey::from(&r));
        let mut res = Vec::with_capacity(X25519PublicKey::LENGTH * 2);
        res.extend(c.0.to_bytes());
        res.extend(c.1.to_bytes());
        Ok(res)
    }

    /// Decrypt a message using ECIES
    /// https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme
    fn decrypt(
        &self,
        private_key: &<Self::KeyPair as KeyPair>::PrivateKey,
        cipher_text: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if cipher_text.len() < X25519PublicKey::LENGTH * 2 {
            return Err(Error::SizeError {
                given: cipher_text.len(),
                expected: X25519PublicKey::LENGTH * 2,
            });
        }
        let c = (
            X25519PublicKey::try_from(&cipher_text[..X25519PublicKey::LENGTH])?,
            X25519PublicKey::try_from(&cipher_text[X25519PublicKey::LENGTH..])?,
        );
        let m = &c.0 - &(c.1 * private_key);
        Ok(m.to_bytes())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::convert::TryFrom;

    #[test]
    fn test_generate_key_pair() {
        let crypto = super::X25519Crypto::new();
        let key_pair_1 = crypto.key_gen(None).unwrap();
        assert_ne!(
            &[0_u8; X25519PrivateKey::LENGTH],
            key_pair_1.private_key.0.as_bytes()
        );
        assert_ne!(
            vec![0_u8; X25519PublicKey::LENGTH],
            key_pair_1.public_key.to_bytes()
        );
        assert_eq!(
            X25519PrivateKey::LENGTH as usize,
            key_pair_1.private_key.0.as_bytes().len()
        );
        assert_eq!(
            X25519PublicKey::LENGTH as usize,
            key_pair_1.public_key.to_bytes().len()
        );
        let key_pair_2 = crypto.key_gen(None).unwrap();
        assert_ne!(key_pair_2.private_key, key_pair_1.private_key);
        assert_ne!(key_pair_2.public_key, key_pair_1.public_key);
    }

    #[test]
    fn test_parse_key_pair() {
        let crypto = super::X25519Crypto::new();
        let key_pair = crypto.key_gen(None).unwrap();
        let hex = format!("{}", key_pair);
        let recovered =
            super::X25519KeyPair::try_from(hex::decode(hex).unwrap().as_slice()).unwrap();
        assert_eq!(key_pair, recovered);
    }

    #[test]
    fn test_parse_public_key() {
        let crypto = super::X25519Crypto::new();
        let key_pair = crypto.key_gen(None).unwrap();
        let hex = format!("{}", key_pair.public_key());
        let recovered =
            super::X25519PublicKey::try_from(hex::decode(hex).unwrap().as_slice()).unwrap();
        assert_eq!(key_pair.public_key(), &recovered);
    }

    #[test]
    fn test_encryption_decryption() {
        let crypto = X25519Crypto::new();
        let key_pair = crypto.key_gen(None).unwrap();
        let m = crypto.key_gen(None).unwrap().public_key().to_bytes();
        let c = crypto.encrypt(&key_pair.public_key, None, &m).unwrap();
        let res = crypto.decrypt(&key_pair.private_key, &c).unwrap();
        assert_eq!(m, res);
    }
}
