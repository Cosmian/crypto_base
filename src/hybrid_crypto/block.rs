use crate::symmetric_crypto::{Nonce, SymmetricCrypto};
use rand_core::{CryptoRng, RngCore};
use std::convert::TryFrom;
use std::sync::Mutex;

/// A block holds clear text data that needs to be encrypted.
/// The max fixed length of clear text is set by the const generic
/// `MAX_CLEAR_TEXT_LENGTH`. The max block encrypted length is available as
/// `Block::MAX_ENCRYPTED_LENGTH`
///
/// When calling `to_encrypted_bytes(...)` an array of bytes is generated that
/// is made of a `BlockHeder` containing the nonce, the cipher text and  -
/// depending on the symmetric scheme - an authentication MAC. The nonce is
/// refreshed on each call to `to_encrypted_bytes(...)`
pub struct Block<S, const MAX_CLEAR_TEXT_LENGTH: usize>
where
    S: SymmetricCrypto,
{
    clear_text: Vec<u8>, //padded with zeroes if need be
    phantom_data: std::marker::PhantomData<S>,
}

impl<S, const MAX_CLEAR_TEXT_LENGTH: usize> Block<S, MAX_CLEAR_TEXT_LENGTH>
where
    S: SymmetricCrypto,
{
    pub const ENCRYPTION_OVERHEAD: usize =
        BlockHeader::<S>::LENGTH + <S as SymmetricCrypto>::MAC_LENGTH;
    pub const MAX_ENCRYPTED_LENGTH: usize = MAX_CLEAR_TEXT_LENGTH + Self::ENCRYPTION_OVERHEAD;

    // Create a new, empty block
    #[must_use]
    pub fn new() -> Block<S, MAX_CLEAR_TEXT_LENGTH> {
        Block {
            clear_text: vec![],
            phantom_data: std::marker::PhantomData::default(),
        }
    }

    // Parses a block of encrypted data to a `Block`.
    /// The resource `uid` and `block_number` are part of the
    /// authentication scheme amd must be re-supplied with the
    /// same values use to encrypt the block
    pub fn from_encrypted_bytes(
        encrypted_bytes: &[u8],
        symmetric_key: &<S as SymmetricCrypto>::Key,
        uid: &[u8],
        block_number: usize,
    ) -> anyhow::Result<Self> {
        let symmetric_crypto: S = S::default();
        // The block header is always present
        if encrypted_bytes.len() < Self::ENCRYPTION_OVERHEAD {
            anyhow::bail!(
                "array of encrypted data bytes of length {} is too small",
                encrypted_bytes.len(),
            );
        }
        if encrypted_bytes.len() > Self::MAX_ENCRYPTED_LENGTH {
            anyhow::bail!(
                "array of encrypted data bytes of length {} is too large",
                encrypted_bytes.len(),
            );
        }
        let block_header_len: usize = BlockHeader::<S>::LENGTH;
        // recover the block header and regenerate the IV
        let block_header = BlockHeader::<S>::parse(&encrypted_bytes[0..block_header_len])?;
        let mut ad = uid.to_vec();
        // Warning: usize can be interpret as u32 on 32-bits CPU-architecture.
        // The u64-cast prevents build on those 32-bits machine or on
        // `wasm32-unknown-unknown` builds.
        ad.extend(&(block_number as u64).to_le_bytes());
        // decrypt
        let clear_text = symmetric_crypto.decrypt(
            symmetric_key,
            &encrypted_bytes[block_header_len..],
            &block_header.nonce,
            Some(&ad),
        )?;
        Ok(Self {
            clear_text,
            phantom_data: std::marker::PhantomData::default(),
        })
    }

    /// Generates the block encrypted data. The nonce is refreshed
    /// on each call. the resource `uid` and `block_number` are part of the AEAD
    /// and must be re-supplied to decrypt the bytes. They are used to guarantee
    /// that a block cannot be moved within and between resources
    pub fn to_encrypted_bytes<R: RngCore + CryptoRng>(
        &self,
        rng: &Mutex<R>,
        symmetric_key: &<S as SymmetricCrypto>::Key,
        uid: &[u8],
        block_number: usize,
    ) -> anyhow::Result<Vec<u8>> {
        let symmetric_crypto: S = S::default();
        // refresh the nonce
        let nonce = S::Nonce::new(rng);
        let mut ad = uid.to_vec();
        // Warning: usize can be interpret as u32 on 32-bits CPU-architecture.
        // The u64-cast prevents build on those 32-bits machine or on
        // `wasm32-unknown-unknown` builds.
        ad.extend(&(block_number as u64).to_le_bytes());
        // write the header
        let mut bytes = BlockHeader::<S> {
            nonce: nonce.clone(),
        }
        .to_bytes();
        // write encrypted data
        bytes.extend(symmetric_crypto.encrypt(
            symmetric_key,
            &self.clear_text,
            &nonce,
            Some(&ad),
        )?);
        Ok(bytes)
    }

    /// Return a reference to the clear text
    #[must_use]
    pub fn clear_text(&self) -> &[u8] {
        &self.clear_text
    }

    /// Moves clear text data out of the block
    #[must_use]
    pub fn clear_text_owned(self) -> Vec<u8> {
        self.clear_text
    }

    /// Write the given clear text data in the block.
    /// Pad the block with zeroes if the offset is beyond the current end of the
    /// block.
    ///
    /// Returns the length of the data written
    pub fn write(&mut self, start_offset: usize, data: &[u8]) -> anyhow::Result<usize> {
        if start_offset >= MAX_CLEAR_TEXT_LENGTH {
            anyhow::bail!(
                "write in block: start offset: {} is greater than max block clear text len {}",
                start_offset,
                MAX_CLEAR_TEXT_LENGTH
            );
        }
        // pad if need be
        let num_to_pad = start_offset - self.clear_text.len();
        if num_to_pad > 0 {
            self.clear_text.extend(vec![0; num_to_pad]);
        }
        // see what space is available
        let space_left = MAX_CLEAR_TEXT_LENGTH - start_offset;
        if space_left == 0 {
            return Ok(0);
        }
        if data.len() <= space_left {
            self.clear_text.extend_from_slice(data);
            return Ok(data.len());
        }
        self.clear_text.extend_from_slice(&data[0..space_left]);
        Ok(space_left)
    }
}

impl<S, const N: usize> Default for Block<S, N>
where
    S: SymmetricCrypto,
{
    fn default() -> Self {
        Self::new()
    }
}

/// The `BlockHeader` contains the nonce/IV of an encrypted `Block`
pub struct BlockHeader<S>
where
    S: SymmetricCrypto,
{
    // clear_text_length: u16,
    nonce: <S as SymmetricCrypto>::Nonce,
}

impl<S> BlockHeader<S>
where
    S: SymmetricCrypto,
{
    pub const LENGTH: usize = <S as SymmetricCrypto>::Nonce::LENGTH;

    pub fn parse(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != Self::LENGTH {
            anyhow::bail!(
                "Invalid block header length: {}, {} expected",
                bytes.len(),
                Self::LENGTH
            )
        }
        //TODO: use transmute to make this faster ?
        Ok(Self {
            nonce: <<S as SymmetricCrypto>::Nonce>::try_from(bytes.to_vec())
                .map_err(|err| anyhow::eyre!("{:?}", err))?,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.nonce.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::Block;
    use crate::{
        entropy::CsRng,
        symmetric_crypto::aes_256_gcm_pure::{Aes256GcmCrypto, Key},
        Key as _,
    };
    use std::{ops::DerefMut, sync::Mutex};

    const MAX_CLEAR_TEXT_LENGTH: usize = 4096;
    type Bl = Block<Aes256GcmCrypto, MAX_CLEAR_TEXT_LENGTH>;

    #[test]
    fn test_empty_block() -> anyhow::Result<()> {
        let b = Bl::new();
        assert!(b.clear_text().is_empty());

        let cs_rng = Mutex::new(CsRng::new());
        let symmetric_key = Key::new(&cs_rng);
        let uid = [1_u8; 32];
        // let iv = cs_rng.generate_nonce();
        let encrypted_bytes = b.to_encrypted_bytes(&cs_rng, &symmetric_key, &uid, 1)?;
        assert_eq!(Bl::ENCRYPTION_OVERHEAD, encrypted_bytes.len());
        let c = Bl::from_encrypted_bytes(&encrypted_bytes, &symmetric_key, &uid, 1)?;
        assert!(c.clear_text().is_empty());
        Ok(())
    }

    #[test]
    fn test_full_block() -> anyhow::Result<()> {
        let cs_rng = Mutex::new(CsRng::new());
        let symmetric_key = Key::new(&cs_rng);
        let uid = [1_u8; 32];

        let mut b = Bl::new();
        assert!(b.clear_text().is_empty());
        let data = cs_rng
            .lock()
            .expect("Could not get a hold on the mutex")
            .deref_mut()
            .generate_random_bytes(16384);
        let written = b.write(0, &data)?;
        assert_eq!(MAX_CLEAR_TEXT_LENGTH, written);

        // let iv = cs_rng.generate_nonce();
        let encrypted_bytes = b.to_encrypted_bytes(&cs_rng, &symmetric_key, &uid, 1)?;
        assert_eq!(
            Bl::ENCRYPTION_OVERHEAD + MAX_CLEAR_TEXT_LENGTH,
            encrypted_bytes.len()
        );
        assert_eq!(
            Bl::ENCRYPTION_OVERHEAD + MAX_CLEAR_TEXT_LENGTH,
            Bl::MAX_ENCRYPTED_LENGTH
        );
        let c = Bl::from_encrypted_bytes(&encrypted_bytes, &symmetric_key, &uid, 1)?;
        assert_eq!(&data[0..MAX_CLEAR_TEXT_LENGTH], c.clear_text());
        Ok(())
    }

    #[test]
    fn test_partial_block() -> anyhow::Result<()> {
        let cs_rng = Mutex::new(CsRng::new());
        let symmetric_key = Key::new(&cs_rng);
        let uid = [1_u8; 32];

        let mut b = Bl::new();
        assert!(b.clear_text().is_empty());

        let data1 = cs_rng
            .lock()
            .expect("Could not get a hold on the mutex")
            .deref_mut()
            .generate_random_bytes(100);
        let written = b.write(0, &data1)?;
        assert_eq!(100, written);

        let data2 = cs_rng
            .lock()
            .expect("Could not get a hold on the mutex")
            .deref_mut()
            .generate_random_bytes(100);
        let written = b.write(200, &data2)?;
        assert_eq!(100, written);

        // let iv = cs_rng.generate_nonce();
        let encrypted_bytes = b.to_encrypted_bytes(&cs_rng, &symmetric_key, &uid, 1)?;
        assert_eq!(300 + Bl::ENCRYPTION_OVERHEAD, encrypted_bytes.len());
        let c = Bl::from_encrypted_bytes(&encrypted_bytes, &symmetric_key, &uid, 1)?;
        let mut data: Vec<u8> = vec![];
        data.extend(&data1);
        data.extend(&[0_u8; 100]);
        data.extend(&data2);

        assert_eq!(&data, c.clear_text());
        Ok(())
    }
}
