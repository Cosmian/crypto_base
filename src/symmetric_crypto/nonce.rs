use crate::Error;
use rand_core::{CryptoRng, RngCore};
use std::{
    cmp::min,
    convert::{TryFrom, TryInto},
    fmt::{Debug, Display},
    ops::DerefMut,
    sync::Mutex,
    vec::Vec,
};

pub trait NonceTrait:
    TryFrom<Vec<u8>, Error = Error> + Clone + PartialEq + Display + Debug + Sync + Send
{
    const LENGTH: usize;
    fn new<R: RngCore + CryptoRng>(rng: &Mutex<R>) -> Self;
    fn try_from_slice(bytes: &[u8]) -> Result<Self, Error>;
    #[must_use]
    fn increment(&self, increment: usize) -> Self;
    #[must_use]
    fn xor(&self, b2: &[u8]) -> Self;
    fn as_bytes(&self) -> Vec<u8>;
}

#[derive(Clone, Debug, PartialEq)]
pub struct Nonce<const NONCE_LENGTH: usize>(pub [u8; NONCE_LENGTH]);

impl<const NONCE_LENGTH: usize> NonceTrait for Nonce<NONCE_LENGTH> {
    const LENGTH: usize = NONCE_LENGTH;

    fn new<R: RngCore + CryptoRng>(rng: &Mutex<R>) -> Self {
        let mut bytes = [0_u8; NONCE_LENGTH];
        rng.lock()
            .expect("Could not get a hold on the mutex")
            .deref_mut()
            .fill_bytes(&mut bytes);
        Self(bytes)
    }

    fn try_from_slice(bytes: &[u8]) -> Result<Self, Error> {
        let b: [u8; NONCE_LENGTH] = bytes.try_into().map_err(|_| Error::SizeError {
            given: bytes.len(),
            expected: NONCE_LENGTH,
        })?;
        Ok(Self(b))
    }

    fn increment(&self, increment: usize) -> Self {
        let mut vec = self.0.to_vec();
        vec.extend_from_slice(&vec![0_u8; 16 - Self::LENGTH]);
        let mut v = u128::from_le_bytes(
            vec.try_into()
                .expect("This should never happen: nonce is 96 bit < 128 bits"),
        );
        v += increment as u128;
        Nonce(
            v.to_le_bytes()[0..NONCE_LENGTH]
                .try_into()
                .expect("This should never happen: nonce is 96 bit < 128 bits"),
        )
    }

    fn xor(&self, b2: &[u8]) -> Self {
        let mut n = self.0;
        for i in 0..min(b2.len(), NONCE_LENGTH) {
            n[i] ^= b2[i];
        }
        Nonce(n)
    }

    fn as_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl<const NONCE_LENGTH: usize> TryFrom<Vec<u8>> for Nonce<NONCE_LENGTH> {
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from_slice(bytes.as_slice())
    }
}

impl<'a, const NONCE_LENGTH: usize> TryFrom<&'a [u8]> for Nonce<NONCE_LENGTH> {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        Self::try_from_slice(bytes)
    }
}

impl<const NONCE_LENGTH: usize> From<[u8; NONCE_LENGTH]> for Nonce<NONCE_LENGTH> {
    fn from(b: [u8; NONCE_LENGTH]) -> Self {
        Self(b)
    }
}

impl<const NONCE_LENGTH: usize> From<Nonce<NONCE_LENGTH>> for Vec<u8> {
    fn from(n: Nonce<NONCE_LENGTH>) -> Vec<u8> {
        n.0.to_vec()
    }
}

impl<const NONCE_LENGTH: usize> Display for Nonce<NONCE_LENGTH> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[cfg(test)]
mod tests {
    use crate::symmetric_crypto::nonce::NonceTrait;

    use super::Nonce;

    #[test]
    fn test_increment_nonce() {
        const NONCE_LENGTH: usize = 12;
        let mut nonce: Nonce<NONCE_LENGTH> = Nonce::from([0_u8; NONCE_LENGTH]);
        let inc = 1_usize << 10;
        nonce = nonce.increment(inc);
        println!("{}", hex::encode(nonce.0));
        assert_eq!("000400000000000000000000", hex::encode(nonce.0));
    }
}
