//! Meteora DAMM v2 (cp-amm) `Pool` reads and the price of one whole token in another, 1e18.
//!
//! Offsets are from the account start (discriminator included). Checked against a mainnet pool
//! decoded by `@meteora-ag/cp-amm-sdk` 1.5.1 (tests-litesvm/fixtures/gap, `pool.json`) and against
//! the splitter's `tokenomics.rs` / `venue.rs` readers. Pure: no accounts, never panics.
use super::math::PRICE_MAX;

pub const POOL_DISCRIMINATOR: [u8; 8] = [241, 154, 109, 4, 17, 177, 109, 188];
/// `pool_fees.base_fee.base_fee_info.data` (32 bytes, pod-aligned) starts at 8: the cliff fee
/// numerator u64 in every mode, then the mode u8 at 16, padding 17..22, and the mode's own
/// fields 22..40 (time scheduler: number_of_period u16 @22, period_frequency u64 @24,
/// reduction_factor u64 @32; the rate limiter and market-cap scheduler use the same bytes).
/// `pool_fees.dynamic_fee.initialized` u8 at 56. Offsets checked with cp-amm-sdk 1.5.1's
/// decoder on modified fixture bytes (tests-litesvm/fixtures/gap/decode-fees.cjs).
pub const POOL_CLIFF_FEE_NUMERATOR: usize = 8;
pub const POOL_BASE_FEE_MODE: usize = 16;
pub const POOL_BASE_FEE_PARAMS: usize = 22;
pub const POOL_BASE_FEE_PARAMS_END: usize = 40;
pub const POOL_DYNAMIC_FEE_INITIALIZED: usize = 56;
pub const POOL_TOKEN_A_MINT: usize = 168;
pub const POOL_TOKEN_B_MINT: usize = 200;
pub const POOL_TOKEN_A_VAULT: usize = 232;
pub const POOL_TOKEN_B_VAULT: usize = 264;
pub const POOL_LIQUIDITY: usize = 360;
/// Q64.64 square root of (raw B per raw A).
pub const POOL_SQRT_PRICE: usize = 456;
pub const POOL_MIN_LEN: usize = POOL_SQRT_PRICE + 16;
/// `permanent_lock_liquidity` u128: the liquidity of every permanently locked position (the
/// launch LP; equal to `liquidity` on mainnet Pangea pools, sol-pricelog-proof.md §3). Amendment 5's
/// depthLocked; 0 (unreadable) on an account too short to hold it.
pub const POOL_PERMANENT_LOCK_LIQUIDITY: usize = 552;

fn key(d: &[u8], at: usize) -> Option<[u8; 32]> {
    d.get(at..at + 32)?.try_into().ok()
}
fn u128_at(d: &[u8], at: usize) -> Option<u128> {
    Some(u128::from_le_bytes(d.get(at..at + 16)?.try_into().ok()?))
}

/// What the gap reads off a pool (the caller has checked the owner).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolView {
    pub mint_a: [u8; 32],
    pub mint_b: [u8; 32],
    pub vault_a: [u8; 32],
    pub vault_b: [u8; 32],
    pub liquidity: u128,
    pub sqrt_price: u128,
    pub cliff_fee_numerator: u64,
    pub base_fee_mode: u8,
    /// Any of the mode's period / frequency / reduction / limiter bytes non-zero.
    pub fee_schedule: bool,
    pub dynamic_fee: bool,
    /// `permanent_lock_liquidity` (0 when the account is too short).
    pub locked_liquidity: u128,
}

pub fn read(d: &[u8]) -> Option<PoolView> {
    if d.len() < POOL_MIN_LEN || d[..8] != POOL_DISCRIMINATOR {
        return None;
    }
    Some(PoolView {
        mint_a: key(d, POOL_TOKEN_A_MINT)?,
        mint_b: key(d, POOL_TOKEN_B_MINT)?,
        vault_a: key(d, POOL_TOKEN_A_VAULT)?,
        vault_b: key(d, POOL_TOKEN_B_VAULT)?,
        liquidity: u128_at(d, POOL_LIQUIDITY)?,
        sqrt_price: u128_at(d, POOL_SQRT_PRICE)?,
        cliff_fee_numerator: u64::from_le_bytes(d.get(POOL_CLIFF_FEE_NUMERATOR..POOL_CLIFF_FEE_NUMERATOR + 8)?.try_into().ok()?),
        base_fee_mode: *d.get(POOL_BASE_FEE_MODE)?,
        fee_schedule: d.get(POOL_BASE_FEE_PARAMS..POOL_BASE_FEE_PARAMS_END)?.iter().any(|b| *b != 0),
        dynamic_fee: *d.get(POOL_DYNAMIC_FEE_INITIALIZED)? != 0,
        locked_liquidity: u128_at(d, POOL_PERMANENT_LOCK_LIQUIDITY).unwrap_or(0),
    })
}

impl PoolView {
    /// The pool's fee, ppm rounded up, only for a FLAT base fee (mode 0, no schedule, no
    /// dynamic fee: what every Pangea launch pool is). Err(reason) otherwise.
    pub fn flat_fee_ppm(&self) -> Result<u32, u8> {
        if self.base_fee_mode != 0 || self.fee_schedule || self.dynamic_fee {
            return Err(super::math::UNSUPPORTED_FEE_MODE);
        }
        super::math::solana_pool_fee_ppm(self.cliff_fee_numerator).ok_or(super::math::DST_FEE_FAILED)
    }

    /// Some(true) if `base` is token A and `quote` token B, Some(false) for the reverse.
    pub fn side(&self, base: &[u8; 32], quote: &[u8; 32]) -> Option<bool> {
        if self.mint_a == *base && self.mint_b == *quote {
            Some(true)
        } else if self.mint_b == *base && self.mint_a == *quote {
            Some(false)
        } else {
            None
        }
    }

    /// Whole quote per whole base, 1e18; None when unreadable (no liquidity, zero, overflow when
    /// rounding up). Rounding down clamps at PRICE_MAX and returns None for 0.
    pub fn price(&self, base_is_a: bool, dec_base: u8, dec_quote: u8, round_up: bool) -> Option<u128> {
        if self.liquidity == 0 {
            return None;
        }
        price_from_sqrt(self.sqrt_price, base_is_a, dec_base, dec_quote, round_up)
    }
}

// ------------------------------------------------------------------ 256-bit helpers

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct U256 {
    hi: u128,
    lo: u128,
}

impl U256 {
    const ZERO: U256 = U256 { hi: 0, lo: 0 };
    fn bits(&self) -> u32 {
        if self.hi != 0 {
            256 - self.hi.leading_zeros()
        } else {
            128 - self.lo.leading_zeros()
        }
    }
    fn shl(self, s: u32) -> U256 {
        match s {
            0 => self,
            1..=127 => U256 { hi: (self.hi << s) | (self.lo >> (128 - s)), lo: self.lo << s },
            128..=255 => U256 { hi: self.lo << (s - 128), lo: 0 },
            _ => U256::ZERO,
        }
    }
    fn shr1(self) -> U256 {
        U256 { hi: self.hi >> 1, lo: (self.lo >> 1) | (self.hi << 127) }
    }
    fn sub(self, o: U256) -> U256 {
        let (lo, borrow) = self.lo.overflowing_sub(o.lo);
        U256 { hi: self.hi - o.hi - borrow as u128, lo }
    }
}

fn mul(a: u128, b: u128) -> U256 {
    const M: u128 = u64::MAX as u128;
    let (a1, a0) = (a >> 64, a & M);
    let (b1, b0) = (b >> 64, b & M);
    let p00 = a0 * b0;
    let p01 = a0 * b1;
    let p10 = a1 * b0;
    let p11 = a1 * b1;
    let mid = (p00 >> 64) + (p01 & M) + (p10 & M);
    U256 { hi: p11 + (p01 >> 64) + (p10 >> 64) + (mid >> 64), lo: (p00 & M) | (mid << 64) }
}

/// a (< 2^256) * m, None on overflow.
fn mul_small(a: U256, m: u128) -> Option<U256> {
    let lo = mul(a.lo, m);
    let hi = mul(a.hi, m);
    if hi.hi != 0 {
        return None;
    }
    Some(U256 { hi: hi.lo.checked_add(lo.hi)?, lo: lo.lo })
}

/// n / d as (quotient, remainder != 0); None when d == 0 or the quotient does not fit u128.
fn div(mut n: U256, d: U256) -> Option<(u128, bool)> {
    if d == U256::ZERO {
        return None;
    }
    if n < d {
        return Some((0, n != U256::ZERO));
    }
    // exact fast path (compute): both fit u128
    if n.hi == 0 && d.hi == 0 {
        return Some((n.lo / d.lo, n.lo % d.lo != 0));
    }
    let shift = n.bits() - d.bits();
    if shift > 128 {
        return None;
    }
    let mut dd = d.shl(shift);
    let mut q: u128 = 0;
    for i in (0..=shift).rev() {
        if n >= dd {
            n = n.sub(dd);
            if i >= 128 {
                return None;
            }
            q |= 1u128 << i;
        }
        dd = dd.shr1();
    }
    Some((q, n != U256::ZERO))
}

fn round(r: Option<(u128, bool)>, up: bool) -> Option<u128> {
    let (q, rem) = r?;
    if up && rem {
        q.checked_add(1)
    } else {
        Some(q)
    }
}

const fn pow10(e: u8) -> u128 {
    let mut v = 1u128;
    let mut i = 0;
    while i < e {
        v *= 10;
        i += 1;
    }
    v
}
const E18: u128 = 1_000_000_000_000_000_000;

/// Whole quote per whole base, 1e18, from a DAMM v2 sqrt price (Q64.64 of raw B per raw A).
///
///   base = A:  P = s^2 / 2^128 * 10^(dA - dB) * 1e18
///   base = B:  P = 2^128 / s^2 * 10^(dB - dA) * 1e18
///
/// Rounded up or down as asked (each step in that direction, so an up result is >= the exact
/// value and a down result <=). Up: None on zero or overflow. Down: None on zero, PRICE_MAX on
/// overflow.
pub fn price_from_sqrt(s: u128, base_is_a: bool, dec_base: u8, dec_quote: u8, up: bool) -> Option<u128> {
    if s == 0 || dec_base > 18 || dec_quote > 18 {
        return None;
    }
    // 10^(dec_base - dec_quote) as num / den
    let (num, den) = if dec_base >= dec_quote {
        (E18 * pow10(dec_base - dec_quote), 1u128)
    } else {
        (E18, pow10(dec_quote - dec_base))
    };
    let r = if base_is_a {
        // q = s^2 / 2^64 (< 2^128 for any s < 2^96; MAX_SQRT_PRICE is just under 2^96)
        let sq = mul(s, s);
        if sq.hi >> 64 != 0 {
            return overflow(up);
        }
        let q = (sq.hi << 64) | (sq.lo >> 64);
        let q = if up && (sq.lo as u64) != 0 { q.checked_add(1)? } else { q };
        let n = mul(q, num);
        // n / (den * 2^64) = floor(floor(n / 2^64) / den), its remainder non-zero iff either step's
        // is: exact, and native when n >> 64 fits u128 (compute)
        let m = U256 { hi: n.hi >> 64, lo: (n.hi << 64) | (n.lo >> 64) };
        if m.hi == 0 {
            Some((m.lo / den, n.lo as u64 != 0 || m.lo % den != 0))
        } else {
            div(n, U256 { hi: 0, lo: den }.shl(64))
        }
    } else {
        let n = U256 { hi: num, lo: 0 }; // num * 2^128
        let d = match mul_small(mul(s, s), den) {
            Some(d) => d,
            // a denominator past 2^256: the price is far below one unit, i.e. 0 (unreadable)
            None => return None,
        };
        div(n, d)
    };
    match round(r, up) {
        None => overflow(up),
        Some(0) => None,
        Some(p) => Some(p),
    }
}

fn overflow(up: bool) -> Option<u128> {
    if up {
        None
    } else {
        Some(PRICE_MAX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exact reference with f64-free big arithmetic on u128 pieces is overkill; compare against
    /// a direct u128 evaluation where it fits.
    #[test]
    fn small_prices_match_direct() {
        // s = 2^64 -> raw price 1
        let s = 1u128 << 64;
        assert_eq!(price_from_sqrt(s, true, 6, 6, false), Some(E18));
        assert_eq!(price_from_sqrt(s, false, 6, 6, true), Some(E18));
        // token A 9 decimals, B 6: whole B per whole A = raw * 1e3
        assert_eq!(price_from_sqrt(s, true, 9, 6, false), Some(1000 * E18));
        assert_eq!(price_from_sqrt(s, false, 6, 9, false), Some(E18 / 1000)); // whole A per whole B = 10^6 / 10^9
        // s = 2^63 -> raw 1/4
        let s = 1u128 << 63;
        assert_eq!(price_from_sqrt(s, true, 6, 6, false), Some(E18 / 4));
        assert_eq!(price_from_sqrt(s, false, 6, 6, false), Some(4 * E18));
    }

    #[test]
    fn up_is_never_below_down_and_close() {
        for &s in &[1u128, 12345, 1 << 40, 523461179597959695, 1233046297440711699868, (1u128 << 96) - 1] {
            for &a in &[true, false] {
                for &(db, dq) in &[(6u8, 9u8), (9, 6), (6, 6), (0, 18), (18, 0)] {
                    let up = price_from_sqrt(s, a, db, dq, true);
                    let down = price_from_sqrt(s, a, db, dq, false);
                    if let (Some(u), Some(d)) = (up, down) {
                        assert!(u >= d, "{s} {a} {db} {dq}");
                        if d < PRICE_MAX {
                            assert!(u - d <= 2 + d / 1_000_000_000_000, "{s} {a} {db} {dq}: {u} {d}");
                        }
                    }
                }
            }
        }
        assert_eq!(price_from_sqrt(0, true, 6, 6, false), None);
        assert_eq!(price_from_sqrt(1, true, 6, 6, false), None); // floors to 0
        assert_eq!(price_from_sqrt(1, false, 6, 6, true), None); // 2^128 * 1e18 overflows u128
        assert_eq!(price_from_sqrt(1, false, 6, 6, false), Some(PRICE_MAX));
    }

    /// The original shift-subtract division, kept here as the reference for the fast paths.
    fn div_ref(mut n: U256, d: U256) -> Option<(u128, bool)> {
        if d == U256::ZERO {
            return None;
        }
        if n < d {
            return Some((0, n != U256::ZERO));
        }
        let shift = n.bits() - d.bits();
        if shift > 128 {
            return None;
        }
        let mut dd = d.shl(shift);
        let mut q: u128 = 0;
        for i in (0..=shift).rev() {
            if n >= dd {
                n = n.sub(dd);
                if i >= 128 {
                    return None;
                }
                q |= 1u128 << i;
            }
            dd = dd.shr1();
        }
        Some((q, n != U256::ZERO))
    }

    #[test]
    fn the_fast_paths_equal_the_shift_subtract_division() {
        let mut x: u128 = 0x9E37_79B9_7F4A_7C15_F39C_C060_5CED_C834;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..3_000 {
            let (a, b) = (next() >> (next() % 128), next() >> (next() % 128));
            let (n, d) = (U256 { hi: 0, lo: a }, U256 { hi: 0, lo: b.max(1) });
            assert_eq!(div(n, d), div_ref(n, d), "{a} {b}");
            // the price paths, both roundings, against the reference built from div_ref
            let s = next() >> (32 + next() % 40);
            for &(db, dq) in &[(6u8, 9u8), (9, 6), (6, 6), (0, 18), (18, 0)] {
                for &up in &[false, true] {
                    let (num, den) = if db >= dq { (E18 * pow10(db - dq), 1u128) } else { (E18, pow10(dq - db)) };
                    let sq = mul(s, s);
                    if s == 0 || sq.hi >> 64 != 0 {
                        continue;
                    }
                    let q = (sq.hi << 64) | (sq.lo >> 64);
                    let q = if up && (sq.lo as u64) != 0 { q + 1 } else { q };
                    let want = round(div_ref(mul(q, num), U256 { hi: 0, lo: den }.shl(64)), up);
                    let want = match want {
                        None => overflow(up),
                        Some(0) => None,
                        Some(p) => Some(p),
                    };
                    assert_eq!(price_from_sqrt(s, true, db, dq, up), want, "{s} {db} {dq} {up}");
                }
            }
        }
    }

    #[test]
    fn div_is_exact() {
        let n = mul(u128::MAX, 3);
        assert_eq!(div(n, U256 { hi: 0, lo: 3 }), Some((u128::MAX, false)));
        assert_eq!(div(n, U256 { hi: 0, lo: 2 }), None);
        assert_eq!(div(U256 { hi: 0, lo: 7 }, U256 { hi: 0, lo: 2 }), Some((3, true)));
        assert_eq!(div(mul(1 << 100, 1 << 100), U256 { hi: 0, lo: 1 << 90 }), Some((1 << 110, false)));
    }
}
