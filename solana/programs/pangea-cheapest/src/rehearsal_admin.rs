// REHEARSAL ONLY (feature `rehearsal-admin`, never in a default build): the program's ADMIN is the
// public key given at BUILD time in the environment variable PANGEA_REHEARSAL_ADMIN, instead of the
// live constant. rehearsal/v3c-min.sh generates a throwaway keypair on the test server, builds with
// `--features rehearsal-admin` and that key's address, and loads the build on a local validator only.
// So a rehearsal never needs the platform's real key. The program id is unchanged; only ADMIN is.
//
// The default build does not compile this file: `ADMIN` there is still the `pubkey!` literal in
// lib.rs, and the default .so is byte-identical with or without this module (rehearsal/v3c/
// default-hash.sh proves it). A build with both this and `test-stack` is a compile error.
//
// The same file is in pangea-splitter, pangea-cheapest and pangea-fastbridge (each a crate of its own).

use anchor_lang::prelude::Pubkey;

/// 32 bytes out of a base58 public key, at compile time. Anything that is not exactly a canonical
/// base58 encoding of 32 bytes stops the build (a const-evaluation panic), never a silent key.
pub const fn decode_pubkey(s: &str) -> [u8; 32] {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let b = s.as_bytes();
    assert!(!b.is_empty() && b.len() <= 44, "PANGEA_REHEARSAL_ADMIN is not a base58 public key (length)");
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < b.len() {
        let mut v = 0usize;
        while v < 58 && ALPHABET[v] != b[i] {
            v += 1;
        }
        assert!(v < 58, "PANGEA_REHEARSAL_ADMIN is not a base58 public key (character)");
        // out = out * 58 + v, big-endian
        let mut carry = v as u32;
        let mut j = 32;
        while j > 0 {
            j -= 1;
            let x = out[j] as u32 * 58 + carry;
            out[j] = (x & 0xff) as u8;
            carry = x >> 8;
        }
        assert!(carry == 0, "PANGEA_REHEARSAL_ADMIN is more than 32 bytes");
        i += 1;
    }
    // Canonical: every leading zero byte is exactly one leading '1' (so a short string is refused).
    let mut ones = 0;
    while ones < b.len() && b[ones] == b'1' {
        ones += 1;
    }
    let mut zeros = 0;
    while zeros < 32 && out[zeros] == 0 {
        zeros += 1;
    }
    assert!(ones == zeros, "PANGEA_REHEARSAL_ADMIN is not a canonical 32-byte base58 key");
    out
}

#[cfg(feature = "rehearsal-admin")]
pub const ADMIN: Pubkey = Pubkey::new_from_array(decode_pubkey(env!(
    "PANGEA_REHEARSAL_ADMIN",
    "feature rehearsal-admin: set PANGEA_REHEARSAL_ADMIN to the rehearsal admin's public key at build time"
)));

#[cfg(test)]
mod tests {
    use super::decode_pubkey;
    use anchor_lang::prelude::Pubkey;
    use std::str::FromStr;

    #[test]
    fn decodes_like_pubkey_from_str() {
        for k in [
            "7rYog4JusTy4CpwvFGPrRvWtcDrWatnA3SN3DRPuf6kM",
            "11111111111111111111111111111111",
            "So11111111111111111111111111111111111111112",
            "Hb5uTppRbNxc3RjVRqTWqfdU3E3GiZyGYKccxYf9tUej",
            "1nc1nerator11111111111111111111111111111111",
        ] {
            assert_eq!(decode_pubkey(k), Pubkey::from_str(k).unwrap().to_bytes(), "{k}");
        }
    }

    #[test]
    fn refuses_what_is_not_a_32_byte_key() {
        for bad in ["", "0", "2", "7rYog4JusTy4CpwvFGPrRvWtcDrWatnA3SN3DRPuf6kMM", "7rYog4JusTy4CpwvFGPrRvWtcDrWatnA3SN3DRPuf6kl", "17rYog4JusTy4CpwvFGPrRvWtcDrWatnA3SN3DRPuf6kM"] {
            assert!(std::panic::catch_unwind(|| decode_pubkey(bad)).is_err(), "{bad:?} accepted");
        }
    }
}
