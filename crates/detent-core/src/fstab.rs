//! fstab field decoding shared by the mounts module and the monitor's
//! execution deny-list, so both read a mount point the same way.

/// Decodes the `\ooo` octal escapes of an fstab field, as libmount reads
/// them (`\040` is a space). Any other backslash is kept as it is.
#[must_use]
pub fn unmangle(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut rest = raw;
    while let Some((&byte, tail)) = rest.split_first() {
        if byte == b'\\'
            && let Some(decoded) = tail.get(..3).and_then(octal_byte)
        {
            out.push(decoded);
            rest = tail.get(3..).unwrap_or_default();
        } else {
            out.push(byte);
            rest = tail;
        }
    }
    out
}

/// The byte three octal digits stand for, or `None`.
fn octal_byte(digits: &[u8]) -> Option<u8> {
    if !digits.iter().all(|digit| (b'0'..=b'7').contains(digit)) {
        return None;
    }
    u8::from_str_radix(std::str::from_utf8(digits).ok()?, 8).ok()
}

#[cfg(test)]
mod tests {
    use super::unmangle;

    #[test]
    fn octal_escapes_are_decoded_and_other_backslashes_kept() {
        assert_eq!(unmangle(br"/srv/my\040disk"), b"/srv/my disk");
        assert_eq!(unmangle(br"/a\134b"), br"/a\b");
        assert_eq!(unmangle(br"/a\08b"), br"/a\08b");
        assert_eq!(unmangle(br"/a\400"), br"/a\400");
        assert_eq!(unmangle(br"/a\04"), br"/a\04");
        assert_eq!(unmangle(b"/plain"), b"/plain");
    }
}
