use hkdf::Hkdf;
use sha2::Sha256;

/// Derive a 256 bits key using a HMAC-based Extract-and-Expand Key Derivation
/// Function (HKDF) supplying a `master` key and some `info` context String
///
/// The hash function used is sha256
pub fn hkdf_256(master: &[u8], info: &[u8]) -> anyhow::Result<[u8; 32]> {
    let h = Hkdf::<Sha256>::new(None, master);
    let mut out = [0_u8; 32];
    h.expand(info, &mut out)
        .map_err(|e| anyhow::anyhow!("hkdf 256 failed. Invalid length: {}", e))?;
    Ok(out)
}
