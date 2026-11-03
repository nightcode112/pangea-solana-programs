//! "Did an earlier instruction of this transaction touch the pool?" from the instructions sysvar.
//!
//! The sysvar lists every top-level instruction with its account keys already resolved, lookup
//! tables included, so a Jupiter route, a direct swap and an address-table swap all show the pool
//! (or its vaults) by key. Walked raw, without building `Instruction`s:
//!
//!   u16 count | u16 offset[count] | per instruction at its offset:
//!     u16 n_accounts | n x (u8 flags, [u8; 32] key) | [u8; 32] program | u16 len | data
//!   ... | u16 current index (the last two bytes)
//!
//! Pure on the bytes; the caller checks the account is the sysvar.

fn u16_at(d: &[u8], at: usize) -> Option<usize> {
    Some(u16::from_le_bytes(d.get(at..at + 2)?.try_into().ok()?) as usize)
}

/// Index of the executing top-level instruction.
pub fn current_index(d: &[u8]) -> Option<usize> {
    if d.len() < 2 {
        return None;
    }
    u16_at(d, d.len() - 2)
}

/// The program id of the executing top-level instruction; None if the data is malformed.
pub fn current_program(d: &[u8]) -> Option<[u8; 32]> {
    let count = u16_at(d, 0)?;
    let current = current_index(d)?;
    if current >= count {
        return None;
    }
    let at = u16_at(d, 2 + 2 * current)?;
    let n = u16_at(d, at)?;
    let p = at + 2 + n * 33;
    d.get(p..p + 32)?.try_into().ok()
}

/// Some(true) if any top-level instruction before the current one lists one of `keys` among its
/// accounts; None if the data is malformed.
pub fn touched_earlier(d: &[u8], keys: &[[u8; 32]]) -> Option<bool> {
    let count = u16_at(d, 0)?;
    let current = current_index(d)?;
    if current >= count {
        return None;
    }
    for i in 0..current {
        let at = u16_at(d, 2 + 2 * i)?;
        let n = u16_at(d, at)?;
        for j in 0..n {
            let k = at + 2 + j * 33 + 1;
            let key: &[u8] = d.get(k..k + 32)?;
            if keys.iter().any(|x| x[..] == *key) {
                return Some(true);
            }
        }
    }
    Some(false)
}

/// Some(true) if any top-level instruction OTHER than the executing one lists `key` among its
/// accounts (before or after it); None if malformed. The PriceLog's one-write-per-transaction rule:
/// every write needs the log account, so another instruction listing it could be a second write.
pub fn listed_by_another(d: &[u8], key: &[u8; 32]) -> Option<bool> {
    let count = u16_at(d, 0)?;
    let current = current_index(d)?;
    if current >= count {
        return None;
    }
    for i in 0..count {
        if i == current {
            continue;
        }
        let at = u16_at(d, 2 + 2 * i)?;
        let n = u16_at(d, at)?;
        for j in 0..n {
            let k = at + 2 + j * 33 + 1;
            if d.get(k..k + 32)? == key {
                return Some(true);
            }
        }
    }
    Some(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ix(keys: &[[u8; 32]]) -> Vec<u8> {
        let mut v = (keys.len() as u16).to_le_bytes().to_vec();
        for k in keys {
            v.push(0);
            v.extend_from_slice(k);
        }
        v.extend_from_slice(&[9u8; 32]);
        v.extend_from_slice(&3u16.to_le_bytes());
        v.extend_from_slice(&[1, 2, 3]);
        v
    }
    fn sysvar(ixs: &[Vec<u8>], current: u16) -> Vec<u8> {
        let mut d = (ixs.len() as u16).to_le_bytes().to_vec();
        let mut at = 2 + 2 * ixs.len();
        for i in ixs {
            d.extend_from_slice(&(at as u16).to_le_bytes());
            at += i.len();
        }
        for i in ixs {
            d.extend_from_slice(i);
        }
        d.extend_from_slice(&current.to_le_bytes());
        d
    }

    #[test]
    fn earlier_only() {
        let pool = [7u8; 32];
        let other = [1u8; 32];
        let d = sysvar(&[ix(&[other, pool]), ix(&[other])], 1);
        assert_eq!(touched_earlier(&d, &[pool]), Some(true));
        let d = sysvar(&[ix(&[other]), ix(&[other]), ix(&[pool])], 1);
        assert_eq!(touched_earlier(&d, &[pool]), Some(false));
        let d = sysvar(&[ix(&[pool])], 0);
        assert_eq!(touched_earlier(&d, &[pool]), Some(false));
        assert_eq!(touched_earlier(&d[..3], &[pool]), None);
    }

    #[test]
    fn current_program_is_the_executing_instructions() {
        let pool = [7u8; 32];
        // ix() writes program [9; 32]; make the second one's program [5; 32]
        let mut second = ix(&[pool, pool, pool]);
        let p = 2 + 3 * 33;
        second[p..p + 32].copy_from_slice(&[5u8; 32]);
        let d = sysvar(&[ix(&[pool]), second.clone()], 1);
        assert_eq!(current_program(&d), Some([5u8; 32]));
        let d = sysvar(&[ix(&[pool]), second], 0);
        assert_eq!(current_program(&d), Some([9u8; 32]));
        let d = sysvar(&[ix(&[])], 0);
        assert_eq!(current_program(&d), Some([9u8; 32]));
        // current index out of range, truncated
        let d = sysvar(&[ix(&[pool])], 1);
        assert_eq!(current_program(&d), None);
        let d = sysvar(&[ix(&[pool])], 0);
        assert_eq!(current_program(&d[..10]), None);
    }

    fn ix_with(program: [u8; 32], data: &[u8], keys: &[[u8; 32]]) -> Vec<u8> {
        let mut v = (keys.len() as u16).to_le_bytes().to_vec();
        for k in keys {
            v.push(0);
            v.extend_from_slice(k);
        }
        v.extend_from_slice(&program);
        v.extend_from_slice(&(data.len() as u16).to_le_bytes());
        v.extend_from_slice(data);
        v
    }

    #[test]
    fn another_listing_the_key_before_or_after() {
        let log = [3u8; 32];
        let me = ix_with([9; 32], &[], &[log]);
        let plain = ix_with([9; 32], &[], &[[1; 32]]);
        let other = ix_with([8; 32], &[], &[[1; 32], log]);
        assert_eq!(listed_by_another(&sysvar(&[plain.clone(), me.clone(), plain.clone()], 1), &log), Some(false));
        assert_eq!(listed_by_another(&sysvar(&[other.clone(), me.clone()], 1), &log), Some(true));
        assert_eq!(listed_by_another(&sysvar(&[me.clone(), other], 0), &log), Some(true));
        assert_eq!(listed_by_another(&sysvar(&[me], 1), &log), None);
    }
}
