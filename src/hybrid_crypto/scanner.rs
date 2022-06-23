use crate::CryptoBaseError;
use std::convert::TryInto;

/// Scans a slice sequentially, updating the cursor position on the fly
pub struct BytesScanner<'a> {
    bytes: &'a [u8],
    start: usize,
}

impl<'a> BytesScanner<'a> {
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        BytesScanner { bytes, start: 0 }
    }

    /// Returns a slice of the next `size` bytes or an error if less is
    /// available
    pub fn next(&mut self, size: usize) -> Result<&'a [u8], CryptoBaseError> {
        let end = self.start + size;
        if self.bytes.len() < end {
            return Err(CryptoBaseError::InvalidSize(format!(
                "{size}, only {} bytes available",
                self.bytes.len() - self.start
            )));
        }
        let chunk = &self.bytes[self.start..end];
        self.start = end;
        Ok(chunk)
    }

    /// Read the next 4 big endian bytes to return an u32
    pub fn read_u32(&mut self) -> Result<u32, CryptoBaseError> {
        Ok(u32::from_be_bytes(self.next(4)?.try_into().map_err(
            |_e| CryptoBaseError::ConversionError("invalid u32".to_string()),
        )?))
    }

    /// Returns the remainder of the slice
    pub fn remainder(&mut self) -> Option<&'a [u8]> {
        if self.start >= self.bytes.len() {
            None
        } else {
            let remainder = &self.bytes[self.start..];
            self.start = self.bytes.len();
            Some(remainder)
        }
    }

    /// Whether there are more bytes to read
    pub const fn has_more(&self) -> bool {
        self.start < self.bytes.len()
    }
}
