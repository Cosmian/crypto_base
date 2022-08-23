use crate::{
    asymmetric::{ristretto::X25519Crypto, AsymmetricCrypto, KeyPair},
    hybrid_crypto::Kem,
    CryptoBaseError,
};
use cosmian_crypto_core::{
    kdf,
    reexport::generic_array::{ArrayLength, GenericArray},
    KeyTrait,
};
use crypto_common::generic_array::sequence::Concat;
use rand::{CryptoRng, RngCore};
use std::convert::TryFrom;

const HKDF_INFO: &[u8; 21] = b"ecies-ristretto-25519";

impl<SharedSecretLength: ArrayLength<u8>> Kem<SharedSecretLength> for X25519Crypto {
    type KeyPair = <Self as AsymmetricCrypto>::KeyPair;

    type EncapsulationSize = <<Self::KeyPair as KeyPair>::PublicKey as KeyTrait>::Length;

    fn description() -> String {
        todo!()
    }

    fn key_gen<R: RngCore + CryptoRng>(rng: &mut R) -> Self::KeyPair {
        Self::KeyPair::new(rng)
    }

    fn encap<R: RngCore + CryptoRng>(
        rng: &mut R,
        pk: &<Self::KeyPair as KeyPair>::PublicKey,
    ) -> Result<
        (
            GenericArray<u8, SharedSecretLength>,
            GenericArray<u8, Self::EncapsulationSize>,
        ),
        CryptoBaseError,
    > {
        let ephemeral_keypair = Self::KeyPair::new(rng);

        // encapsulation
        let encapsulation = ephemeral_keypair.public_key().to_bytes();

        // shared secret
        let shared_secret = (pk * ephemeral_keypair.private_key()).to_bytes();

        // generate secret key
        let b = shared_secret.concat(encapsulation);
        let secret_key = kdf::hkdf_256::<SharedSecretLength>(&b, HKDF_INFO)?;
        Ok((secret_key, encapsulation))
    }

    fn decap(
        sk: &<Self::KeyPair as KeyPair>::PrivateKey,
        encapsulation: GenericArray<u8, Self::EncapsulationSize>,
    ) -> Result<GenericArray<u8, SharedSecretLength>, CryptoBaseError> {
        // case CheckMod = 1: the ciphertext should map to valid public key
        // compute the shared secret
        let h = <Self::KeyPair as KeyPair>::PublicKey::try_from(encapsulation.as_slice())? * sk;

        // TODO: check `h` is not null -> implement `is_zero`
        let shared_secret = h.to_bytes();

        // generate secret key
        let b = shared_secret.concat(encapsulation);
        kdf::hkdf_256::<SharedSecretLength>(&b, HKDF_INFO).map_err(CryptoBaseError::CryptoCoreError)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        asymmetric::{ristretto::X25519Crypto, AsymmetricCrypto, KeyPair},
        hybrid_crypto::Kem,
    };
    use cosmian_crypto_core::{entropy::CsRng, reexport::generic_array::typenum::U32};

    #[test]
    fn test_kem() {
        let mut rng = CsRng::new();
        let key_pair = <X25519Crypto as AsymmetricCrypto>::KeyPair::new(&mut rng);
        let (secret_key, encapsulation) =
            <X25519Crypto as Kem<U32>>::encap(&mut rng, key_pair.public_key())
                .expect("X25519 encaps failed");
        let res = X25519Crypto::decap(key_pair.private_key(), encapsulation)
            .expect("X25519 decaps failed");
        if secret_key != res {
            panic!("Wrong decapsulation!");
        }
    }
}
