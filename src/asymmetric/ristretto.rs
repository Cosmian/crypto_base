use std::{
    convert::{TryFrom, TryInto},
    fmt::Display,
    sync::Mutex,
};

use curve25519_dalek::{
    constants,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use rand_core::{CryptoRng, RngCore};

use super::{AsymmetricCrypto, KeyPair};
use crate::{
    entropy::CsRng,
    kdf::hkdf_256,
    symmetric_crypto::{aes_256_gcm_pure, Key, Nonce as _, SymmetricCrypto},
};

const HKDF_INFO: &[u8; 21] = b"ecies-ristretto-25519";

/// For ECIES, cipher text needs to store:
//
// - the public key of the ephemeral keypair
// - the AES nonce/iv
// - the AES MAC
pub const ECIES_ENCRYPTION_OVERHEAD: usize =
    PUBLIC_KEY_LENGTH + aes_256_gcm_pure::NONCE_LENGTH + aes_256_gcm_pure::MAC_LENGTH;

pub const PRIVATE_KEY_LENGTH: usize = 32;

#[derive(Clone, PartialEq, Debug)]
pub struct X25519PrivateKey(Scalar);

impl X25519PrivateKey {
    #[must_use]
    pub fn as_bytes(&self) -> [u8; 32] {
        self.0.as_bytes().to_owned()
    }

    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        X25519PrivateKey(Scalar::random(rng))
    }
}

impl TryFrom<&[u8]> for X25519PrivateKey {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        let len = value.len();
        let bytes: [u8; PRIVATE_KEY_LENGTH] = value.try_into().map_err(|_e| {
            anyhow::anyhow!(
                "Invalid private key of length: {}, expected length: {}",
                len,
                PRIVATE_KEY_LENGTH
            )
        })?;
        let scalar = Scalar::from_canonical_bytes(bytes)
            .ok_or_else(|| anyhow::anyhow!("Invalid private key bytes"))?;
        Ok(X25519PrivateKey(scalar))
    }
}

/// Parse from an hex encoded String
impl TryFrom<&str> for X25519PrivateKey {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        let bytes = hex::decode(value)
            .map_err(|e| anyhow::anyhow!("Invalid hex encoded private key: {}", e))?;
        X25519PrivateKey::try_from(bytes.as_slice())
    }
}

/// Display the hex encoded value of the key
impl Display for X25519PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0.as_bytes()))
    }
}

pub const PUBLIC_KEY_LENGTH: usize = 32; //compressed

#[derive(Clone, PartialEq, Debug)]
pub struct X25519PublicKey(RistrettoPoint);

impl X25519PublicKey {
    #[must_use]
    pub fn as_bytes(&self) -> [u8; 32] {
        self.0.compress().as_bytes().to_owned()
    }
}

impl From<&X25519PrivateKey> for X25519PublicKey {
    fn from(private_key: &X25519PrivateKey) -> Self {
        X25519PublicKey(&private_key.0 * &constants::RISTRETTO_BASEPOINT_TABLE)
    }
}

impl TryFrom<&[u8]> for X25519PublicKey {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        let len = value.len();
        if len != PUBLIC_KEY_LENGTH {
            anyhow::bail!(
                "Invalid key of length: {}, expected length: {}",
                len,
                PUBLIC_KEY_LENGTH
            )
        };
        let compressed = CompressedRistretto::from_slice(value);
        let point = compressed
            .decompress()
            .ok_or_else(|| anyhow::anyhow!("Could nos decompress the Ristretto point"))?;
        Ok(X25519PublicKey(point))
    }
}

/// Parse from an hex encoded String
impl TryFrom<&str> for X25519PublicKey {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        let bytes = hex::decode(value)
            .map_err(|e| anyhow::anyhow!("Invalid hex encoded public key: {}", e))?;
        X25519PublicKey::try_from(bytes.as_slice())
    }
}

/// Display the hex encoded value of the key
impl Display for X25519PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0.compress().to_bytes()))
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct X25519KeyPair {
    pub private_key: X25519PrivateKey,
    pub public_key: X25519PublicKey,
}

impl X25519KeyPair {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> X25519KeyPair {
        let scalar = Scalar::random(rng);
        let public_key = X25519PublicKey(&scalar * &constants::RISTRETTO_BASEPOINT_TABLE);
        let private_key = X25519PrivateKey(scalar);
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

impl TryFrom<&[u8]> for X25519KeyPair {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let len = value.len();
        if len != PRIVATE_KEY_LENGTH + PUBLIC_KEY_LENGTH {
            anyhow::bail!(
                "Invalid key pair of length: {}, expected length: {}",
                len,
                PRIVATE_KEY_LENGTH + PUBLIC_KEY_LENGTH
            );
        }
        let private_key = X25519PrivateKey::try_from(&value[0..PRIVATE_KEY_LENGTH])?;
        let public_key = X25519PublicKey::try_from(&value[PRIVATE_KEY_LENGTH..])?;
        Ok(X25519KeyPair {
            private_key,
            public_key,
        })
    }
}

impl Display for X25519KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}", &self.private_key, &self.public_key)
    }
}

pub struct X25519Crypto {
    rng: Mutex<CsRng>,
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

impl X25519Crypto {
    /// Generate a 256 bit symmetric key used with ECIES encryption
    pub fn sym_key_from_public_key(
        ephemeral_keypair: &X25519KeyPair, // (y, gʸ)
        public_key: &X25519PublicKey,      // gˣ
    ) -> anyhow::Result<[u8; 32]> {
        //calculate the shared point: (gˣ)ʸ
        let point = public_key.0 * ephemeral_keypair.private_key.0;
        // create a 64 bytes master key using gʸ and the shared point
        let mut master = [0_u8; 2 * PUBLIC_KEY_LENGTH];
        master[..PUBLIC_KEY_LENGTH].clone_from_slice(&ephemeral_keypair.public_key.as_bytes());
        master[PUBLIC_KEY_LENGTH..].clone_from_slice(&point.compress().to_bytes());
        //Derive a 256 bit key using HKDF
        hkdf_256(&master, HKDF_INFO)
    }

    /// Generate a 256 bit symmetric key used with ECIES decryption
    pub fn sym_key_from_private_key(
        ephemeral_public_key: &X25519PublicKey, // gʸ
        private_key: &X25519PrivateKey,         // x
    ) -> anyhow::Result<[u8; 32]> {
        //calculate the shared point: (gʸ)ˣ
        let point = private_key.0 * ephemeral_public_key.0;
        // create a 64 bytes master key using gʸ and the shared point
        let mut master = [0_u8; 2 * PUBLIC_KEY_LENGTH];
        master[..PUBLIC_KEY_LENGTH].clone_from_slice(&ephemeral_public_key.as_bytes());
        master[PUBLIC_KEY_LENGTH..].clone_from_slice(&point.compress().to_bytes());
        //Derive a 256 bit key using HKDF
        hkdf_256(&master, HKDF_INFO)
    }

    pub fn new_private_key(&self) -> X25519PrivateKey {
        let rng = &mut *self.rng.lock().expect("a mutex lock failed");
        X25519PrivateKey::new(rng)
    }

    pub fn fill_bytes(&self, dest: &mut [u8]) {
        let rng = &mut *self.rng.lock().expect("a mutex lock failed");
        rng.fill_bytes(dest);
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

    /// Generate a private key
    fn generate_private_key(
        &self,
        _: Option<&Self::PrivateKeyGenerationParameters>,
    ) -> anyhow::Result<<Self::KeyPair as KeyPair>::PrivateKey> {
        let rng = &mut *self.rng.lock().expect("a mutex lock failed");
        Ok(X25519PrivateKey::new(rng))
    }

    /// Generate a key pair, private key and public key
    fn generate_key_pair(
        &self,
        _: Option<&Self::KeyPairGenerationParameters>,
    ) -> anyhow::Result<Self::KeyPair> {
        let rng = &mut *self.rng.lock().expect("a mutex lock failed");
        Ok(X25519KeyPair::new(rng))
    }

    /// Generate a symmetric key, and its encryption,to be used in an hybrid
    /// encryption scheme
    fn generate_symmetric_key<S: SymmetricCrypto>(
        &self,
        public_key: &<Self::KeyPair as KeyPair>::PublicKey,
        _: Option<&Self::EncryptionParameters>,
    ) -> anyhow::Result<(S::Key, Vec<u8>)> {
        let bytes: Vec<u8> = self.generate_random_bytes(S::Key::LENGTH);
        let symmetric_key = S::generate_key_from_rnd(&bytes)?;
        let encrypted_key = self.encrypt(public_key, None, &symmetric_key.as_bytes())?;
        Ok((symmetric_key, encrypted_key))
    }

    /// Decrypt a symmetric key used in an hybrid encryption scheme
    fn decrypt_symmetric_key<S: SymmetricCrypto>(
        &self,
        private_key: &<Self::KeyPair as KeyPair>::PrivateKey,
        data: &[u8],
    ) -> anyhow::Result<S::Key> {
        S::Key::parse(self.decrypt(private_key, data)?)
    }

    /// A utility function to generate random bytes from an uniform distribution
    /// using a cryptographically secure RNG
    fn generate_random_bytes(&self, len: usize) -> Vec<u8> {
        let rng = &mut *self.rng.lock().expect("a mutex lock failed");
        let mut bytes = vec![0_u8; len];
        rng.fill_bytes(&mut bytes);
        bytes
    }

    /// The encrypted message length
    fn encrypted_message_length(&self, clear_text_message_length: usize) -> usize {
        clear_text_message_length + ECIES_ENCRYPTION_OVERHEAD
    }

    /// Encrypt a message using ECIES
    /// https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme
    fn encrypt(
        &self,
        public_key: &<Self::KeyPair as KeyPair>::PublicKey,
        _: Option<&Self::EncryptionParameters>,
        data: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let rng = &mut *self.rng.lock().expect("a mutex lock failed");
        let ephemeral_keypair = X25519KeyPair::new(rng);
        let sym_key_bytes = Self::sym_key_from_public_key(&ephemeral_keypair, public_key)?;
        // use the pure rust aes implementation
        let sym_key = aes_256_gcm_pure::Key(sym_key_bytes);
        let aes = aes_256_gcm_pure::Aes256GcmCrypto::new();
        let nonce = aes.generate_nonce();
        //prepare the result
        let mut result: Vec<u8> = Vec::with_capacity(data.len() + ECIES_ENCRYPTION_OVERHEAD);
        result.extend_from_slice(&ephemeral_keypair.public_key.as_bytes());
        result.extend_from_slice(&nonce.0);
        result.extend(aes.encrypt(&sym_key, data, &nonce, None)?);
        Ok(result)
    }

    /// The decrypted message length
    fn clear_text_message_length(encrypted_message_length: usize) -> usize {
        if encrypted_message_length <= ECIES_ENCRYPTION_OVERHEAD {
            0
        } else {
            encrypted_message_length - ECIES_ENCRYPTION_OVERHEAD
        }
    }

    /// Decrypt a message using ECIES
    /// https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme
    fn decrypt(
        &self,
        private_key: &<Self::KeyPair as KeyPair>::PrivateKey,
        data: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        if data.len() < ECIES_ENCRYPTION_OVERHEAD {
            anyhow::bail!("decryption failed: message is too short");
        }
        if data.len() == ECIES_ENCRYPTION_OVERHEAD {
            return Ok(vec![]);
        }
        // gʸ
        let ephemeral_public_key_bytes = &data[0..PUBLIC_KEY_LENGTH];
        let ephemeral_public_key = X25519PublicKey::try_from(ephemeral_public_key_bytes)?;
        let sym_key_bytes = Self::sym_key_from_private_key(&ephemeral_public_key, private_key)?;
        // use the pure rust aes implementation
        let sym_key = aes_256_gcm_pure::Key(sym_key_bytes);
        let aes = aes_256_gcm_pure::Aes256GcmCrypto::new();
        let nonce_bytes =
            &data[PUBLIC_KEY_LENGTH..PUBLIC_KEY_LENGTH + aes_256_gcm_pure::NONCE_LENGTH];
        let nonce = aes_256_gcm_pure::Nonce::try_from_slice(nonce_bytes)?;
        aes.decrypt(
            &sym_key,
            &data[PUBLIC_KEY_LENGTH + aes_256_gcm_pure::NONCE_LENGTH..],
            &nonce,
            None,
        )
    }
}

#[cfg(test)]
mod test {
    use std::convert::TryFrom;

    use super::{AsymmetricCrypto, KeyPair};
    use crate::{
        asymmetric::ristretto::ECIES_ENCRYPTION_OVERHEAD, symmetric_crypto::aes_256_gcm_pure,
    };

    #[test]
    fn test_generate_key_pair() {
        let crypto = super::X25519Crypto::new();
        let key_pair_1 = crypto.generate_key_pair(None).unwrap();
        assert_ne!(
            &[0_u8; super::PRIVATE_KEY_LENGTH],
            key_pair_1.private_key.0.as_bytes()
        );
        assert_ne!(
            [0_u8; super::PUBLIC_KEY_LENGTH],
            key_pair_1.public_key.as_bytes()
        );
        assert_eq!(
            super::PRIVATE_KEY_LENGTH as usize,
            key_pair_1.private_key.0.as_bytes().len()
        );
        assert_eq!(
            super::PUBLIC_KEY_LENGTH as usize,
            key_pair_1.public_key.as_bytes().len()
        );
        let key_pair_2 = crypto.generate_key_pair(None).unwrap();
        assert_ne!(key_pair_2.private_key, key_pair_1.private_key);
        assert_ne!(key_pair_2.public_key, key_pair_1.public_key);
    }

    #[test]
    fn test_parse_key_pair() {
        let crypto = super::X25519Crypto::new();
        let key_pair = crypto.generate_key_pair(None).unwrap();
        let hex = format!("{}", key_pair);
        let recovered =
            super::X25519KeyPair::try_from(hex::decode(hex).unwrap().as_slice()).unwrap();
        assert_eq!(key_pair, recovered);
    }

    #[test]
    fn test_parse_public_key() {
        let crypto = super::X25519Crypto::new();
        let key_pair = crypto.generate_key_pair(None).unwrap();
        let hex = format!("{}", key_pair.public_key());
        let recovered =
            super::X25519PublicKey::try_from(hex::decode(hex).unwrap().as_slice()).unwrap();
        assert_eq!(key_pair.public_key(), &recovered);
    }

    #[test]
    fn test_encryption_decryption() {
        let crypto = super::X25519Crypto::new();
        let random_msg = crypto.generate_random_bytes(4096);
        assert_ne!(vec![0_u8; 4096], random_msg);
        let key_pair: super::X25519KeyPair = crypto.generate_key_pair(None).unwrap();
        let enc_bytes = crypto
            .encrypt(&key_pair.public_key, None, &random_msg)
            .unwrap();
        assert_eq!(
            4096_usize + ECIES_ENCRYPTION_OVERHEAD,
            crypto.encrypted_message_length(random_msg.len())
        );
        assert_eq!(
            4096_usize,
            super::X25519Crypto::clear_text_message_length(enc_bytes.len())
        );
        let clear_text = crypto.decrypt(&key_pair.private_key, &enc_bytes).unwrap();
        assert_eq!(random_msg, clear_text);
    }

    #[test]
    fn test_encryption_decryption_symmetric_key() {
        let crypto = super::X25519Crypto::new();
        let key_pair = crypto.generate_key_pair(None).unwrap();

        let (sym_key, enc_sym_key) = crypto
            .generate_symmetric_key::<aes_256_gcm_pure::Aes256GcmCrypto>(
                key_pair.public_key(),
                None,
            )
            .unwrap();
        let decrypted_key = crypto.decrypt_symmetric_key::<aes_256_gcm_pure::Aes256GcmCrypto>(
            &key_pair.private_key,
            &enc_sym_key,
        );
        println!("decrypted_key: {:?}", decrypted_key);
        assert_eq!(sym_key, decrypted_key.unwrap());
    }
}
