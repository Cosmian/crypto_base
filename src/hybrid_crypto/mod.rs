use crate::{
    asymmetric::{ristretto::X25519Crypto, KeyPair},
    CryptoBaseError,
};
use cosmian_crypto_core::{
    reexport::generic_array::{typenum::Unsigned, GenericArray},
    symmetric_crypto::{aes_256_gcm_pure::Aes256GcmCrypto, Dem},
    KeyTrait,
};
use rand::{CryptoRng, RngCore};

mod kem;

pub use kem::Kem;

pub trait HybridCrypto<KEM: Kem<<DEM::Key as KeyTrait>::Length>, DEM: Dem> {
    fn key_gen<R: RngCore + CryptoRng>(rng: &mut R) -> KEM::KeyPair {
        KEM::key_gen(rng)
    }

    fn encrypt<R: RngCore + CryptoRng>(
        rng: &mut R,
        pk: &<KEM::KeyPair as KeyPair>::PublicKey,
        additional_data: Option<&[u8]>,
        message: &[u8],
    ) -> Result<Vec<u8>, CryptoBaseError> {
        let (secret_key, asymmetric_encapsulation) = KEM::encap(rng, pk)?;
        let mut symmetric_encapsulation =
            DEM::encaps(rng, secret_key.as_slice(), additional_data, message)?;
        // allocate the correct number of bytes for the ciphertext
        let mut res = Vec::with_capacity(
            <KEM as Kem<<DEM::Key as KeyTrait>::Length>>::EncapsulationSize::to_usize()
                + DEM::ENCAPSULATION_OVERHEAD
                + message.len(),
        );
        res.append(&mut asymmetric_encapsulation.to_vec());
        res.append(&mut symmetric_encapsulation);
        Ok(res)
    }

    fn decrypt(
        sk: &<KEM::KeyPair as KeyPair>::PrivateKey,
        additional_data: Option<&[u8]>,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoBaseError> {
        if ciphertext.len() < KEM::EncapsulationSize::to_usize() {
            return Err(CryptoBaseError::InvalidSize(format!(
                "decrypt: ciphertext has size: {}, it should be at least: {}",
                ciphertext.len(),
                KEM::EncapsulationSize::to_usize()
            )));
        }
        let secret_key = KEM::decap(
            sk,
            GenericArray::<u8, KEM::EncapsulationSize>::clone_from_slice(
                &ciphertext[..KEM::EncapsulationSize::to_usize()],
            ),
        )?;
        DEM::decaps(
            &secret_key,
            additional_data,
            &ciphertext[KEM::EncapsulationSize::to_usize()..],
        )
        .map_err(CryptoBaseError::CryptoCoreError)
    }
}

struct HcX25519AesCrypto;
impl HybridCrypto<X25519Crypto, Aes256GcmCrypto> for HcX25519AesCrypto {}
