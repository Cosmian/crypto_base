use std::{collections::HashMap, convert::TryFrom, fmt::Display, str::FromStr, vec::Vec};

use aes::Aes256;
use cosmian_fpe::ff1::{FlexibleNumeralString, FF1};
use itertools::Itertools;
use num_traits::Bounded;
use tracing::trace;

use crate::{symmetric_crypto::SymmetricCrypto, CryptoBaseError};

pub const RECOMMENDED_THRESHOLD: usize = 1_000_000;
pub const KEY_LENGTH: usize = 32;
pub const NONCE_LENGTH: usize = 0;
pub const MAC_LENGTH: usize = 0;

pub type Key = crate::symmetric_crypto::key::Key<KEY_LENGTH>;
pub type Nonce = crate::symmetric_crypto::nonce::Nonce<NONCE_LENGTH>;

#[allow(clippy::upper_case_acronyms)]
#[derive(Default)]
pub struct FF1Crypto;

impl Display for FF1Crypto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", FF1Crypto::description())
    }
}

impl PartialEq for FF1Crypto {
    // `rng` is a random generator so you obviously can't
    // compare with other `rng` instance
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

/// `RebasedInput` gives the representation of the text string to encode in a
/// new integer base
#[derive(Default)]
struct RebasedInput {
    /// The number of characters in alphabet
    /// For example, 10 for the alphabet "0123456789"
    radix: u32,
    /// The text being represented a the new base.
    /// The base used for this representation depends on the alphabet length.
    /// For example, if alphabet is "0123456789", the base used is base-10
    /// (decimal base)
    input: Vec<u16>,
    /// The original string as a char vector (for convenience)
    original_chars: Vec<char>,
    /// The indexes of chars being rebased in the original string
    rebased_chars_original_indexes: Vec<usize>,
    /// The indexes of chars being excluded (everything not in alphabet)
    excluded_chars_indexes: Vec<usize>,
    /// Mapping between orignal char representation and the integer new
    /// representation
    mapping: HashMap<char, u8>,
}

impl RebasedInput {
    // According to the given alphabet, get the plaintext (or ciphertext) in a new
    // integer `base` starting from 0.
    fn rebase_text(input: &str, alphabet: &str) -> Result<Self, CryptoBaseError> {
        trace!("input_text: {input}, alphabet: {alphabet}");
        trace!("input_text.chars: {:?}", input.chars());
        trace!("alphabet.chars: {:?}", alphabet.chars());

        if input.is_empty() {
            return Err(CryptoBaseError::InvalidSize(
                "Cannot rebase empty input".to_string(),
            ));
        }
        if alphabet.is_empty() {
            return Err(CryptoBaseError::InvalidSize(
                "Alphabet is empty. No FPE encryption is possible".to_string(),
            ));
        }

        // Our final result
        let mut result = Self::default();

        // We want to exclude characters not being in alphabet
        // But we want to keep a reference of them (excluded_chars)
        let mut stripped_input = String::new();
        for (idx, char) in input.chars().enumerate() {
            result.original_chars.push(char);
            if alphabet.find(char).is_some() {
                stripped_input.push(char);
                result.rebased_chars_original_indexes.push(idx);
            } else {
                result.excluded_chars_indexes.push(idx);
            }
        }

        if stripped_input.is_empty() {
            return Err(CryptoBaseError::InvalidSize(format!(
                "Input does not contain any characters of the alphabet! input={input} alphabet={alphabet}")
            ));
        }
        // Check if FPE is usable (in a security point of view, verifying the
        // threshold as suggested in NIST standard https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf)
        if alphabet.len() ^ stripped_input.len() >= RECOMMENDED_THRESHOLD {
            return Err(CryptoBaseError::InvalidSize( format!("Given alphabet length ({}), plaintext is too short. Plaintext length should be at least {}", alphabet.len(),(RECOMMENDED_THRESHOLD as f32).log(alphabet.len() as f32))));
        }

        // Fill the mapping between original representation ("ABCDEFG...") and
        // new base representation ("01234567...")
        let alphabet = alphabet.chars().sorted().unique().collect::<Vec<_>>();
        let len = u8::try_from(alphabet.len()).map_err(|e| {
            CryptoBaseError::ConversionError(format!(
                "cannot convert alphabet len ({}) to u8: {e}",
                alphabet.len()
            ))
        })?;
        for i in 0_u8..len {
            result.mapping.insert(alphabet[i as usize], i);
        }
        trace!("input mapping: {:?}", &result.mapping);

        // Finally rebase input string according to the new base
        for c in stripped_input.chars() {
            match result.mapping.get(&c) {
                Some(matching_char) => result.input.push(u16::from(*matching_char)),
                None => {
                    return Err(CryptoBaseError::ConversionError(format!(
                        "cannot map input text char {c} to u8"
                    )))
                }
            }
        }

        // Quick compute of radix (for convenience)
        result.radix = u32::try_from(alphabet.len()).map_err(|e| {
            CryptoBaseError::ConversionError(format!(
                "cannot convert alphabet len ({}) to u32: {e}",
                alphabet.len()
            ))
        })?;
        trace!("rebased_plaintext: {:?}", &result.input);
        trace!("radix: {:?}", &result.radix);

        Ok(result)
    }

    // Revert rebase for the given char
    fn revert_rebase(&self, integer: u16) -> Result<char, CryptoBaseError> {
        let mut result = '0';
        let integer = u8::try_from(integer).map_err(|e| {
            CryptoBaseError::ConversionError(format!("cannot convert u16 to u8 ({integer}): {e}"))
        })?;
        // TODO: remove unneeded clone?
        for (k, v) in self.mapping.clone() {
            if integer == v {
                result = k;
                break;
            }
        }
        Ok(result)
    }

    fn revert_rebase_vec(&self, input: Vec<u16>) -> Result<String, CryptoBaseError> {
        let mut result = String::new();
        for e in input {
            result += self.revert_rebase(e)?.to_string().as_str();
        }
        Ok(result)
    }

    fn reconstruct_original_format(&self, input: Vec<u16>) -> Result<String, CryptoBaseError> {
        let result = self.revert_rebase_vec(input)?;
        let result = self.reinsert_excluded_chars(result);
        Ok(result)
    }

    fn reinsert_excluded_chars(&self, input: String) -> String {
        let mut result = input;
        for idx in self.excluded_chars_indexes.clone() {
            result.insert(idx, self.original_chars[idx]);
        }
        result
    }

    fn _reinsert_negative_sign(&self, input: String) -> String {
        let mut result = input;
        for idx in self.excluded_chars_indexes.clone() {
            if idx != 0 {
                continue;
            }
            let char = self.original_chars[idx];
            if char == '-' {
                result.insert(idx, self.original_chars[idx]);
                break;
            }
        }
        result
    }

    fn remove_left_padding(&self, cleartext: String) -> String {
        // Remove left padding
        let mut is_0 = true;
        let mut result = String::new();
        for i in cleartext.chars() {
            // Ignore sign
            if i == '-' {
                result.push(i);
                continue;
            }
            if i == '0' && is_0 {
                continue;
            }
            is_0 = false;
            result.push(i)
        }
        if result.is_empty() {
            result.push('0');
        }
        result
    }
}

/// `FF1Crypto` gives multiple encryption/decryption functions.
/// Those different functions differ in the type of the input string
/// representation.
/// The most usable functions are `encrypt_string` and `encrypt_digit_string`
/// Those 2 last functions force the input string to be rebased in a new integer
/// base (base 10 for example in case of digit string)
impl FF1Crypto {
    pub const KEY_LENGTH: usize = KEY_LENGTH;

    pub fn encrypt_u16(
        key: &[u8],
        tweak: &[u8],
        radix: u32,
        plaintext: Vec<u16>,
    ) -> Result<Vec<u16>, CryptoBaseError> {
        if key.len() != KEY_LENGTH {
            return Err(CryptoBaseError::SizeError {
                given: key.len(),
                expected: KEY_LENGTH,
            });
        }

        let fpe_ff = FF1::<Aes256>::new(key, radix).map_err(|_| {
            CryptoBaseError::EncryptionError(
                "failed generating new FF1 engine for encryption".to_string(),
            )
        })?;
        let ciphertext = fpe_ff
            .encrypt(tweak, &FlexibleNumeralString::from(plaintext))
            .map_err(|_| CryptoBaseError::EncryptionError("failed FF1 encryption".to_string()))?;

        // Get ciphertext as u16-vector
        let ciphertext_vec = Vec::<u16>::from(ciphertext);
        trace!("ciphertext_vec: {ciphertext_vec:?}");

        Ok(ciphertext_vec)
    }

    pub fn decrypt_u16(
        key: &[u8],
        tweak: &[u8],
        radix: u32,
        ciphertext: Vec<u16>,
    ) -> Result<Vec<u16>, CryptoBaseError> {
        if key.len() != KEY_LENGTH {
            return Err(CryptoBaseError::SizeError {
                given: key.len(),
                expected: KEY_LENGTH,
            });
        }

        let fpe_ff = FF1::<Aes256>::new(key, radix).map_err(|_| {
            CryptoBaseError::EncryptionError(
                "failed generating new FF1 engine for decryption".to_string(),
            )
        })?;
        let cleartext = fpe_ff
            .decrypt(tweak, &FlexibleNumeralString::from(ciphertext))
            .map_err(|_| CryptoBaseError::EncryptionError("failed FF1 decryption".to_string()))?;
        // Get cleartext as u16-vector
        let cleartext_vec = Vec::<u16>::from(cleartext);
        trace!("cleartext_vec: {cleartext_vec:?}");
        Ok(cleartext_vec)
    }

    pub fn encrypt_u8(
        key: &[u8],
        tweak: &[u8],
        radix: u32,
        plaintext: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoBaseError> {
        let plaintext = plaintext.into_iter().map(u16::from).collect::<Vec<_>>();
        let ciphertext = Self::encrypt_u16(key, tweak, radix, plaintext)?;
        let mut result = Vec::with_capacity(ciphertext.len());
        for item in ciphertext {
            result
                .push(u8::try_from(item).map_err(|e| CryptoBaseError::InvalidSize(e.to_string()))?);
        }
        Ok(result)
    }

    pub fn decrypt_u8(
        key: &[u8],
        tweak: &[u8],
        radix: u32,
        ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoBaseError> {
        let ciphertext = ciphertext.into_iter().map(u16::from).collect::<Vec<_>>();
        let cleartext = Self::decrypt_u16(key, tweak, radix, ciphertext)?;
        let mut result = Vec::with_capacity(cleartext.len());
        for item in cleartext {
            result.push(
                u8::try_from(item).map_err(|e| CryptoBaseError::ConversionError(e.to_string()))?,
            );
        }
        Ok(result)
    }

    /// In `encrypt_string`, we put aside all characters not being in alphabet.
    /// We keep the index of those characters in the original string to put them
    /// back in the final encrypted string.
    pub fn encrypt_string(
        key: &[u8],
        tweak: &[u8],
        alphabet: &str,
        plaintext: &str,
    ) -> Result<String, CryptoBaseError> {
        let rebased = RebasedInput::rebase_text(plaintext, alphabet)?;

        let ciphertext = Self::encrypt_u16(key, tweak, rebased.radix, rebased.input.clone())?;
        trace!("ciphertext: {ciphertext:?}");

        // Represent the ciphertext in the original plaintext base
        let result = rebased.reconstruct_original_format(ciphertext)?;
        trace!("ciphertext (format preserved): {result:?}");

        Ok(result)
    }

    pub fn decrypt_string(
        key: &[u8],
        tweak: &[u8],
        alphabet: &str,
        ciphertext: &str,
    ) -> Result<String, CryptoBaseError> {
        let rebased = RebasedInput::rebase_text(ciphertext, alphabet)?;

        let cleartext = Self::decrypt_u16(key, tweak, rebased.radix, rebased.input.clone())?;
        trace!("cleartext: {cleartext:?}");

        // Represent the cleartext in the original plaintext base
        let result = rebased.reconstruct_original_format(cleartext)?;
        trace!("cleartext (format preserved): {result:?}");

        Ok(result)
    }

    /// Like in `encrypt_string`, we put aside the characters not being in
    /// alphabet. The difference with `encrypt_string` is the left padding that
    /// occurs. Indeed, we want to deal with very small input digit string (like
    /// number on less than 6 characters) and respect the security threshold
    /// given in NIST 800 38G (`radix^minlen>1_000_000`). This padding will be
    /// done according to the given input type (the generic `T`). For example,
    /// for a `u32` type, the left-zeroes-padding will pad the input string
    /// until 9 characters (not more because of the max u32 possible value).
    pub fn encrypt_digit_string<T>(
        key: &[u8],
        tweak: &[u8],
        plaintext: &str,
    ) -> Result<String, CryptoBaseError>
    where
        T: ToString + Bounded + FromStr + PartialOrd + Ord,
        <T as std::str::FromStr>::Err: std::error::Error,
    {
        let alphabet = ('0'..='9').collect::<String>();
        let rebased = RebasedInput::rebase_text(plaintext, alphabet.as_str())?;

        let expected_output_length = T::max_value().to_string().len() - 1;
        if expected_output_length == 0 {
            return Err(CryptoBaseError::InvalidSize(
                "Expected output length cannot be 0".to_string(),
            ));
        }

        if rebased.input.len() <= expected_output_length {
            // Add custom left padding for digit string whose length is less than
            // expected_output_length
            let padding_size = usize::min(
                expected_output_length - rebased.input.len(),
                rebased.input.len(),
            );
            let mut padded_plaintext = vec![0_u16; padding_size];
            padded_plaintext.extend_from_slice(&rebased.input);

            let ciphertext = Self::encrypt_u16(key, tweak, rebased.radix, padded_plaintext)?;
            // Represent the ciphertext in the original plaintext base
            let result = rebased.reconstruct_original_format(ciphertext)?;
            let numeric_result = result
                .parse::<T>()
                .expect("Encryption digit strings leads to an unparsable digit-strings");

            if numeric_result < T::min_value() || numeric_result > T::max_value() {
                return Err(CryptoBaseError::InvalidSize(
                    "Encrypted digit strings lead to an integer overflow".to_string(),
                ));
            }

            Ok(result)
        } else {
            let left = &rebased.input[0..rebased.input.len() - expected_output_length];
            let right = &rebased.input[rebased.input.len() - expected_output_length..];
            let right_plaintext = rebased.revert_rebase_vec(right.to_vec())?;
            let right_ciphertext = Self::encrypt_digit_string::<T>(key, tweak, &right_plaintext)?;
            let left = rebased.revert_rebase_vec(left.to_vec())?;
            let result = format!("{left}{right_ciphertext}");
            let result = rebased.reinsert_excluded_chars(result);

            trace!("result: {result:?}");
            Ok(result)
        }
    }

    pub fn decrypt_digits_string<T>(
        key: &[u8],
        tweak: &[u8],
        ciphertext: &str,
    ) -> Result<String, CryptoBaseError>
    where
        T: ToString + Bounded,
    {
        let alphabet = ('0'..='9').collect::<String>();
        let rebased = RebasedInput::rebase_text(ciphertext, alphabet.as_str())?;

        let expected_output_length = T::max_value().to_string().len() - 1;
        if expected_output_length == 0 {
            return Err(CryptoBaseError::InvalidSize(
                "Expected output length cannot be 0".to_string(),
            ));
        }

        if rebased.input.len() <= expected_output_length {
            let cleartext = Self::decrypt_u16(key, tweak, rebased.radix, rebased.input.clone())?;
            let result = rebased.reconstruct_original_format(cleartext)?;
            let result = rebased.remove_left_padding(result);
            trace!("cleartext (format preserved): {result:?}");
            Ok(result)
        } else {
            let left = &rebased.input[0..rebased.input.len() - expected_output_length];
            let right = &rebased.input[rebased.input.len() - expected_output_length..];
            let right_ciphertext = rebased.revert_rebase_vec(right.to_vec())?;
            let mut result = Self::decrypt_digits_string::<T>(key, tweak, &right_ciphertext)?;

            // This is unexpected when decrypted right part begins with 0. Those zeroes must
            // be considered as padding
            if result.len() < expected_output_length {
                let removed_zeroes_length = expected_output_length - result.len();
                let removed_zeroes_string =
                    (0..removed_zeroes_length).map(|_| "0").collect::<String>();
                result = format!("{removed_zeroes_string}{result}");
            }
            let left = rebased.revert_rebase_vec(left.to_vec())?;
            let result = format!("{left}{result}");
            let result = rebased.reinsert_excluded_chars(result);
            Ok(result)
        }
    }
}

impl SymmetricCrypto for FF1Crypto {
    type Key = Key;
    type Nonce = Nonce;

    const MAC_LENGTH: usize = MAC_LENGTH;

    fn description() -> String {
        format!("FF1 pure Rust (key bits: {})", KEY_LENGTH * 8)
    }

    fn encrypt(
        key: &Self::Key,
        bytes: &[u8],
        _nonce: &Self::Nonce,
        _additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoBaseError> {
        Self::encrypt_u8(&key.0, &[], 256, bytes.to_vec())
    }

    fn decrypt(
        key: &Self::Key,
        bytes: &[u8],
        _nonce: &Self::Nonce,
        _additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoBaseError> {
        Self::decrypt_u8(&key.0, &[], 256, bytes.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{thread_rng, Rng};
    use rand_distr::Alphanumeric;

    #[test]
    fn fpe_ff1_string_credit_card_number() -> Result<(), CryptoBaseError> {
        // let plaintext = "1234123412341234";
        let key = [0_u8; KEY_LENGTH];
        for _ in 0..100 {
            let plaintext_len = thread_rng().gen_range(4..128);
            let plaintext: String = thread_rng()
                .sample_iter(&Alphanumeric)
                .take(plaintext_len)
                .map(char::from)
                .collect();
            let ciphertext = FF1Crypto::encrypt_string(&key, &[], &plaintext, &plaintext)?;
            let cleartext = FF1Crypto::decrypt_string(&key, &[], &plaintext, ciphertext.as_str())?;
            assert_eq!(cleartext, plaintext);
        }
        Ok(())
    }

    #[test]
    fn fpe_ff1_u16_credit_card_number() -> Result<(), CryptoBaseError> {
        let ccn = "1234123412341234";
        let key = [0_u8; KEY_LENGTH];
        let plaintext = ccn
            .as_bytes()
            .iter()
            .map(|b| u16::from(*b))
            .collect::<Vec<_>>();
        let ciphertext = FF1Crypto::encrypt_u16(&key, &[], 128, plaintext.clone())?;
        let cleartext = FF1Crypto::decrypt_u16(&key, &[], 128, ciphertext)?;
        assert_eq!(cleartext, plaintext);
        Ok(())
    }

    #[test]
    fn fpe_ff1_u8_credit_card_number() -> Result<(), CryptoBaseError> {
        let ccn = "1234123412341234";
        let plaintext = ccn.as_bytes().to_vec();
        let key = [0_u8; KEY_LENGTH];
        let ciphertext = FF1Crypto::encrypt_u8(&key, &[], 128, plaintext.clone())?;
        let cleartext = FF1Crypto::decrypt_u8(&key, &[], 128, ciphertext)?;
        assert_eq!(cleartext, plaintext);
        Ok(())
    }

    #[test]
    fn fpe_ff1_u16_range_test() -> Result<(), CryptoBaseError> {
        let key = [0_u8; KEY_LENGTH];

        for _ in 1..100 {
            let plaintext = vec![0_u16; 32]
                .into_iter()
                .map(|_| thread_rng().gen_range(0..128))
                .collect::<Vec<_>>();
            let ciphertext = FF1Crypto::encrypt_u16(&key, &[], 128, plaintext.clone())?;
            let cleartext = FF1Crypto::decrypt_u16(&key, &[], 128, ciphertext)?;
            assert_eq!(cleartext, plaintext);
        }
        Ok(())
    }

    #[test]
    fn fpe_ff1_digits_encryption() -> Result<(), CryptoBaseError> {
        let key = vec![0; KEY_LENGTH];

        // Length == 0
        let pt = "0";
        let ct = FF1Crypto::encrypt_digit_string::<u32>(&key, &[], pt)?;
        let cleartext = FF1Crypto::decrypt_digits_string::<u32>(&key, &[], ct.as_str())?;
        assert_eq!(cleartext, pt);

        // Length < 9
        let pt: String = thread_rng().gen::<u16>().to_string();
        let ct = FF1Crypto::encrypt_digit_string::<u32>(&key, &[], &pt)?;
        let cleartext = FF1Crypto::decrypt_digits_string::<u32>(&key, &[], ct.as_str())?;
        assert_eq!(cleartext, pt);

        // Length < 9. Signed integer.
        let pt: String = thread_rng().gen::<i16>().to_string();
        let ct = FF1Crypto::encrypt_digit_string::<i32>(&key, &[], &pt)?;
        let cleartext = FF1Crypto::decrypt_digits_string::<i32>(&key, &[], ct.as_str())?;
        assert_eq!(cleartext, pt);

        // Length >= 9
        let pt = "4294967295"; // 2^32 - 1
        let ct = FF1Crypto::encrypt_digit_string::<u32>(&key, &[], pt)?;
        let cleartext = FF1Crypto::decrypt_digits_string::<u32>(&key, &[], ct.as_str())?;
        assert_eq!(cleartext, pt);

        // Length >= 9, splitted input with right string prepended with 0
        let pt = "1111111111000222222";
        let ct = FF1Crypto::encrypt_digit_string::<u32>(&key, &[], pt)?;
        let cleartext = FF1Crypto::decrypt_digits_string::<u32>(&key, &[], ct.as_str())?;
        assert_eq!(cleartext, pt);

        // Length >= 9 with non-digit character. Needs to respect input format
        let pt = "1234-1234-1234-1234-1234";
        let ct = FF1Crypto::encrypt_string(&key, &[], "1234567890", pt)?;
        let cleartext = FF1Crypto::decrypt_string(&key, &[], "1234567890", ct.as_str())?;
        assert_eq!(cleartext, pt);

        // Non-digits characters
        let pt = "aaaaaaaaaaaaaa";
        let ct = FF1Crypto::encrypt_digit_string::<u32>(&key, &[], pt);
        assert!(ct.is_err());
        Ok(())
    }

    #[test]
    fn fpe_ff1_limit_cases() -> Result<(), CryptoBaseError> {
        let key = vec![0; KEY_LENGTH];

        let pt = "4294967295"; // 2^32 - 1
        let ct = FF1Crypto::encrypt_digit_string::<u32>(&key, &[], pt)?;
        let cleartext = FF1Crypto::decrypt_digits_string::<u32>(&key, &[], ct.as_str())?;
        assert_eq!(cleartext, pt);

        let pt = "-4294967295"; // too big
        let ct = FF1Crypto::encrypt_digit_string::<u32>(&key, &[], pt)?;
        let cleartext = FF1Crypto::decrypt_digits_string::<u32>(&key, &[], ct.as_str())?;
        assert_eq!(cleartext, pt);

        Ok(())
    }

    #[test]
    fn fpe_ff1_digits_range_test() -> Result<(), CryptoBaseError> {
        let key = [0_u8; KEY_LENGTH];

        for _ in 0..1000 {
            let plaintext: String = thread_rng().gen::<i32>().to_string();
            let ciphertext = FF1Crypto::encrypt_digit_string::<i32>(&key, &[], &plaintext)?;
            let cleartext =
                FF1Crypto::decrypt_digits_string::<i32>(&key, &[], ciphertext.as_str())?;
            assert_eq!(cleartext, plaintext);
        }
        Ok(())
    }
}
