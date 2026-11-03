//! stocks-d (v3.1, owner D3): gap route hops on Raydium CLMM (venue 2) and Orca Whirlpool (venue 3),
//! beside Meteora DAMM v2 (venue 1). Compiled only with `--features stock-hops`
//! (docs/stocks-solana-gap-hop.md). The official pool stays DAMM v2 only (`engine::read_pool`).
//!
//! A concentrated hop (kinds 2, 3; only on a 1-hop route) always carries a depth floor on BOTH sides
//! (MAIN Q86 (a), stocks-d-a1 M2, stocks-d-a2 L3, lead8 L133): the registrar's minimum in-band depth per
//! side (the Q86 listing tool's figure, `set_stock_route`) / 10; below either the hop is unreadable
//! (fail closed: a receive holds, retriable; a send is refused). A push of the price in EITHER direction
//! thins one side. Only the registrar changes the floors (re-registration). A hop price whose
//! down-rounding overflows (PRICE_MAX) is unreadable too (stocks-d-a2 L3).
//!
//! Each reader returns a `HopView` (mints, vaults, liquidity, sqrt price; no fee or lock fields: a hop's
//! fee and depth are never priced as an official pool's, stocks-d-a1 I-1). Every venue stores a Q64.64
//! sqrt of raw B per raw A, so `pool::price_from_sqrt` prices every kind. No ScaledUiAmount multiplier
//! is applied: every pool trades raw units, so it cancels (design §3).
//!
//! The functions that read a hop (`record::route_usd`, `record::live_prices`,
//! `record::refuse_earlier_touch`, `engine::refuse_earlier_touch`, `SetGapRoute::apply`) are the
//! originals with the hop read going through `read_hop`; the originals are compiled out with this
//! feature (a `cfg` on their own `fn` line, so the default build's lines do not move). `live_prices`
//! reads each hop ONCE for both roundings (stocks-d-a1 M1: compute headroom).
use super::engine::{self, GapAccounts, GapData};
use super::introspect;
use super::math::E18;
use super::pool;
use super::pricelog::{self, Live, Window};
use super::record::{check_native_route, checked, fee_at_record, RecordPrice};
use super::record::{NativeRoute, WSOL_MINT};
use super::state::*;
use crate::instructions::gap_admin::{mint_decimals, SetGapRoute, SetGapRouteParams};
use crate::*;

pub const HOP_KIND_RAYDIUM_CLMM: u8 = 2;
pub const HOP_KIND_ORCA_WHIRLPOOL: u8 = 3;
/// The depth floors of a concentrated hop: the registrar's minimum in-band depth per side (the Q86
/// listing tool's figure, `set_stock_route`) divided by this (lead8 L133 / L141). A hop thinner than
/// its minimum depth is refused at registration; at every read it is unreadable below depth / 10.
pub const DEPTH_FLOOR_DIV: u128 = 10;
/// `GapRoute.reserved`: hop 0's floors, u64 LE, token B's side at FLOOR_AT and token A's at FLOOR_AT + 8
/// (0 = none: DAMM v2). reserved[0..2] the decimals, reserved[2] 0 on a 1-hop route, reserved[3] unused
/// (0; a5's distance bound replaced the net step count), [20..28] the anchor, [28..32] the last re-anchor
/// time; the REGISTRATION anchor is in hops[1].pool[0..8] (`reg_anchor_of`). A concentrated hop is only
/// ever hop 0 (1-hop routes). Only the registrar (`set_stock_route`) sets the floors (lead8 L141).
pub const FLOOR_AT: usize = 4;
/// stocks-d-a3 M1 / lead8 L120: the window collar on EVERY PriceLog write of a concentrated route
/// (record_price, send, receive): the live hop factor usd / cls must lie inside the store's window by
/// COLLAR_NUM / COLLAR_DEN (10%); outside, or with an empty window, the write carries no USD (a receive
/// holds, a send is refused, record_price reverts). record_price may re-seed an EMPTY window within 10%
/// of the anchor (see `RecordPrice::apply`).
pub const COLLAR_NUM: u128 = 11;
pub const COLLAR_DEN: u128 = 10;
/// MAIN Q91 (ii) / lead8 L100: the cumulative bound on EVERY path that uses a concentrated hop's price
/// (receive, send, record_price): the route factor must stay within the band (25%) of the anchor
/// (set by `set_stock_route` = the hop's price at registration, micro-USD per whole quote token, u64 LE
/// at GapRoute.reserved[ANCHOR_AT..+8]; moved only by the keeper's bounded `set_route_anchor`); outside,
/// the route is unreadable.
/// The band: +-1/2^ANCHOR_BAND_SHIFT of the anchor (25%), shifts only (compute: the receive's x1.2
/// margin is a few hundred CU).
pub const ANCHOR_BAND_SHIFT: u32 = 2;
pub const ANCHOR_AT: usize = 20;
/// The anchor's unit: 1e12 of the route factor's 1e18 (micro-USD per whole quote token).
pub const ANCHOR_UNIT: u128 = 1_000_000_000_000;
/// Raydium Concentrated Liquidity (mainnet; raydium-clmm `declare_id!`).
pub const RAYDIUM_CLMM_ID: Pubkey = pubkey!("CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK");
/// Orca Whirlpools (mainnet; whirlpools `declare_id!`).
pub const ORCA_WHIRLPOOL_ID: Pubkey = pubkey!("whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc");

/// Raydium CLMM `PoolState` (raydium-clmm programs/amm/src/states/pool.rs @6d7a0f82,
/// `#[repr(C, packed)]` zero-copy: no padding). Offsets from the account start.
pub mod raydium {
    /// sha256("account:PoolState")[..8]
    pub const DISCRIMINATOR: [u8; 8] = [247, 237, 227, 245, 215, 195, 222, 70];
    pub const LEN: usize = 1544;
    pub const MINT_0: usize = 73;
    pub const MINT_1: usize = 105;
    pub const VAULT_0: usize = 137;
    pub const VAULT_1: usize = 169;
    pub const DECIMALS_0: usize = 233;
    pub const DECIMALS_1: usize = 234;
    pub const LIQUIDITY: usize = 237;
    /// Q64.64 sqrt(raw token_1 / raw token_0).
    pub const SQRT_PRICE_X64: usize = 253;
    /// Bit 4 set: swaps disabled (the price cannot be arbitraged: refused).
    pub const STATUS: usize = 389;
    pub const STATUS_SWAP_DISABLED: u8 = 1 << 4;
    /// The program's sqrt price bounds (tick -443,636 / 443,636): a value outside is not a price.
    pub const MIN_SQRT_PRICE_X64: u128 = 4_295_048_016;
    pub const MAX_SQRT_PRICE_X64: u128 = 79_226_673_521_066_979_257_578_248_091;
}

/// Orca `Whirlpool` (whirlpools programs/whirlpool/src/state/whirlpool.rs @cc683ec9, Borsh, fixed
/// size). Offsets from the account start.
pub mod whirlpool {
    /// sha256("account:Whirlpool")[..8]
    pub const DISCRIMINATOR: [u8; 8] = [63, 149, 209, 12, 225, 128, 99, 9];
    pub const LEN: usize = 653;
    pub const LIQUIDITY: usize = 49;
    /// Q64.64 sqrt(raw B / raw A).
    pub const SQRT_PRICE: usize = 65;
    pub const MINT_A: usize = 101;
    pub const VAULT_A: usize = 133;
    pub const MINT_B: usize = 181;
    pub const VAULT_B: usize = 213;
    /// The program's sqrt price bounds (tick -443,636 / 443,636): a value outside is not a price.
    pub const MIN_SQRT_PRICE: u128 = 4_295_048_016;
    pub const MAX_SQRT_PRICE: u128 = 79_226_673_515_401_279_992_447_579_055;
}

/// A hop pool as read (no fee or lock fields: never an official pool's view).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HopView {
    pub mint_a: [u8; 32],
    pub mint_b: [u8; 32],
    pub vault_a: [u8; 32],
    pub vault_b: [u8; 32],
    pub liquidity: u128,
    /// Q64.64 sqrt of raw B per raw A.
    pub sqrt_price: u128,
    /// The pool's own record of its mints' decimals (Raydium only; (A, B)).
    pub decimals: Option<(u8, u8)>,
}

impl HopView {
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

    /// Whole quote per whole base, 1e18, exactly as `pool::PoolView::price` (no liquidity: None).
    pub fn price(&self, base_is_a: bool, dec_base: u8, dec_quote: u8, round_up: bool) -> Option<u128> {
        if self.liquidity == 0 {
            return None;
        }
        pool::price_from_sqrt(self.sqrt_price, base_is_a, dec_base, dec_quote, round_up)
    }

    /// The in-range depth on the OUT side, raw units of that token, rounded down, saturating at
    /// u128::MAX: token B's virtual reserve L s / 2^64 when the hop pays out B, token A's L 2^64 / s
    /// when it pays out A. 0 with no liquidity or a zero price.
    pub fn depth_out(&self, out_is_b: bool) -> u128 {
        if self.liquidity == 0 || self.sqrt_price == 0 {
            return 0;
        }
        if out_is_b { mul_shr64(self.liquidity, self.sqrt_price) } else { shl64_div(self.liquidity, self.sqrt_price) }
    }
}

impl HopView {
    /// Both sides' depth at or above the floors (B side, A side), without a division:
    /// floor(L s / 2^64) >= fb, and floor(L 2^64 / s) >= fa <=> L 2^64 >= fa s <=> L >= ceil(fa s / 2^64)
    /// (fa < 2^64, s < 2^128: fa s / 2^64 < 2^128, exact). Equals `depth_out(true) >= fb &&
    /// depth_out(false) >= fa` (unit-tested), at a fraction of the compute.
    pub fn deep_enough(&self, (fb, fa): (u64, u64)) -> bool {
        if self.liquidity == 0 || self.sqrt_price == 0 {
            return fb == 0 && fa == 0;
        }
        if mul_shr64(self.liquidity, self.sqrt_price) < fb as u128 {
            return false;
        }
        let (q, rem) = mul_shr64_rem(fa as u128, self.sqrt_price);
        self.liquidity > q || (self.liquidity == q && !rem)
    }
}

/// floor(a b / 2^64) and whether the remainder is non-zero, for a < 2^64 (no overflow).
fn mul_shr64_rem(a: u128, b: u128) -> (u128, bool) {
    const M: u128 = u64::MAX as u128;
    let (b1, b0) = (b >> 64, b & M);
    let p1 = a * b1; // < 2^128
    let p0 = a * b0; // < 2^128
    (p1 + (p0 >> 64), p0 & M != 0)
}

/// floor or ceil(a b / 1e18) with the exact semantics of `math::mul_down` / `math::mul_up` (0 for a
/// zero factor; down: PRICE_MAX when the quotient passes u128, 0 for a zero product; up: 0 when it
/// passes PRICE_MAX - 1), but by a 64-bit-limb long division of the 256-bit product by 1e18 (two
/// u128 steps) instead of `math::div_wide`'s 128-step bit loop: no compute cliff above 2^128
/// (stocks-d-a3 M2: a hop price above $340.28 made a 1e18 x price product take ~20k CU).
pub fn mul_e18(a: u128, b: u128, up: bool) -> u128 {
    const D: u128 = E18;
    const M: u128 = u64::MAX as u128;
    if a == 0 || b == 0 {
        return 0;
    }
    let (hi, lo) = mul256(a, b);
    let (q, r) = if hi == 0 {
        (lo / D, lo % D != 0)
    } else {
        if hi >= D {
            return if up { 0 } else { super::math::PRICE_MAX };
        }
        // hi < D < 2^60: divide (hi | lo_hi) then (rem | lo_lo), each < 2^124
        let n1 = (hi << 64) | (lo >> 64);
        let (q1, r1) = (n1 / D, n1 % D);
        let n0 = (r1 << 64) | (lo & M);
        let (q0, r0) = (n0 / D, n0 % D);
        ((q1 << 64) | q0, r0 != 0)
    };
    if up {
        if !r {
            q
        } else if q < super::math::PRICE_MAX {
            q + 1
        } else {
            0
        }
    } else {
        q
    }
}

/// a b as (hi, lo).
fn mul256(a: u128, b: u128) -> (u128, u128) {
    const M: u128 = u64::MAX as u128;
    let (a1, a0) = (a >> 64, a & M);
    let (b1, b0) = (b >> 64, b & M);
    let p00 = a0 * b0;
    let p01 = a0 * b1;
    let p10 = a1 * b0;
    let p11 = a1 * b1;
    let mid = (p00 >> 64) + (p01 & M) + (p10 & M);
    (p11 + (p01 >> 64) + (p10 >> 64) + (mid >> 64), (p00 & M) | (mid << 64))
}

/// x m for a small m (< 2^64), None on overflow past 2^256.
fn mul256_small(x: (u128, u128), m: u128) -> Option<(u128, u128)> {
    let lo = mul256(x.1, m);
    let hi = mul256(x.0, m);
    if hi.0 != 0 {
        return None;
    }
    Some((hi.1.checked_add(lo.0)?, lo.1))
}

/// a b n <= c d m (n, m small), exact; false on an overflow (fail closed: outside the collar).
fn le_scaled(a: u128, b: u128, n: u128, c: u128, d: u128, m: u128) -> bool {
    match (mul256_small(mul256(a, b), n), mul256_small(mul256(c, d), m)) {
        (Some(l), Some(r)) => l <= r,
        _ => false,
    }
}

/// a b n <= c d m (n, m small): the u128 products when they fit (the common case), else exact 256-bit.
fn le_scaled_fast(a: u128, b: u128, n: u128, c: u128, d: u128, m: u128) -> bool {
    match (a.checked_mul(b).and_then(|x| x.checked_mul(n)), c.checked_mul(d).and_then(|x| x.checked_mul(m))) {
        (Some(l), Some(r)) => l <= r,
        _ => le_scaled(a, b, n, c, d, m),
    }
}

/// stocks-d-a3 M1 / lead8 L120: every PriceLog write on a concentrated route (record_price, a send,
/// a receive) carries a USD price only inside the 10% window collar; an EMPTY window carries none.
/// Returns `live` with both USD fields 0 otherwise (a receive then holds DST_PRICE_FAILED, a send is
/// refused GapSourceUnreadable, record_price reverts), logging "gap-collar" | quote mint | reason
/// (1 empty window, 2 outside the collar) for the hold alert. Judged on the down rounding (up and down
/// differ by at most one unit of 1e18). Any other route: `live` unchanged.
pub fn collar_live(d: &GapData, tail: &Tail, mut live: Live, w: &Window) -> Live {
    if !concentrated(d.route.as_ref()) || live.usd_down == 0 {
        return live;
    }
    let reason = if w.entries == 0 {
        1u8
    } else if factor_ok(live.usd_down, live.cls_down, w) {
        0
    } else {
        2
    };
    if reason != 0 {
        anchor_lang::solana_program::log::sol_log_data(&[b"gap-collar", tail.quote_mint.as_ref(), &[reason]]);
        live.usd_up = 0;
        live.usd_down = 0;
    }
    live
}

/// usd / cls within [usd_min / cls_max / 1.1, usd_max / cls_min x 1.1] (a side without data: no bound).
fn factor_ok(usd: u128, cls: u128, w: &Window) -> bool {
    if cls == 0 {
        return true;
    }
    let upper = w.usd_max == 0 || w.cls_min == 0 || le_scaled_fast(usd, w.cls_min, COLLAR_DEN, w.usd_max, cls, COLLAR_NUM);
    let lower = w.usd_min == 0 || w.cls_max == 0 || le_scaled_fast(w.usd_min, cls, COLLAR_DEN, usd, w.cls_max, COLLAR_NUM);
    upper && lower
}

/// The live hop factor usd / cls within the window's factor bounds, widened by the collar. True when
/// there is nothing to compare (an empty window, a zero price, a side without data).
pub fn factor_in_collar(usd: u128, cls: u128, w: &Window) -> bool {
    if w.entries == 0 || usd == 0 || cls == 0 {
        return true;
    }
    // every entry's factor usd_e / cls_e <= usd_max / cls_min and >= usd_min / cls_max
    let upper = w.usd_max == 0 || w.cls_min == 0 || le_scaled(usd, w.cls_min, COLLAR_DEN, w.usd_max, cls, COLLAR_NUM);
    let lower = w.usd_min == 0 || w.cls_max == 0 || le_scaled(w.usd_min, cls, COLLAR_DEN, usd, w.cls_max, COLLAR_NUM);
    upper && lower
}

/// Whether a route has a concentrated hop.
pub fn concentrated(r: Option<&GapRoute>) -> bool {
    r.map_or(false, |r| r.used().any(|(h, _, _)| floored(h.kind)))
}

/// floor(a b / 2^64), saturating at u128::MAX (stocks-c hand-off).
fn mul_shr64(a: u128, b: u128) -> u128 {
    const M: u128 = u64::MAX as u128;
    let (a1, a0) = (a >> 64, a & M);
    let (b1, b0) = (b >> 64, b & M);
    let p11 = a1 * b1;
    let p10 = a1 * b0;
    let p01 = a0 * b1;
    let p00 = a0 * b0;
    if p11 >> 64 != 0 {
        return u128::MAX;
    }
    (p11 << 64).checked_add(p10).and_then(|v| v.checked_add(p01)).and_then(|v| v.checked_add(p00 >> 64)).unwrap_or(u128::MAX)
}

/// floor(a 2^64 / b) for b > 0, saturating at u128::MAX (stocks-c hand-off).
fn shl64_div(a: u128, b: u128) -> u128 {
    if a >> 64 != 0 {
        let q = a / b;
        let r = a % b;
        if q >> 64 != 0 {
            return u128::MAX;
        }
        return (q << 64).saturating_add(frac64(r, b));
    }
    (a << 64) / b
}

/// floor(r 2^64 / b) for r < b, by long division one bit at a time.
fn frac64(mut r: u128, b: u128) -> u128 {
    let mut q: u128 = 0;
    for _ in 0..64 {
        let carry = r >> 127 != 0;
        r <<= 1;
        q <<= 1;
        if carry || r >= b {
            r = r.wrapping_sub(b);
            q |= 1;
        }
    }
    q
}

fn key(d: &[u8], at: usize) -> Option<[u8; 32]> {
    d.get(at..at + 32)?.try_into().ok()
}
fn u128_at(d: &[u8], at: usize) -> Option<u128> {
    Some(u128::from_le_bytes(d.get(at..at + 16)?.try_into().ok()?))
}

/// A DAMM v2 pool's hop fields (the same discriminator and length rule as `pool::read`; only the
/// fields a hop needs).
pub fn read_damm(d: &[u8]) -> Option<HopView> {
    if d.len() < pool::POOL_MIN_LEN || d[..8] != pool::POOL_DISCRIMINATOR {
        return None;
    }
    Some(HopView {
        mint_a: key(d, pool::POOL_TOKEN_A_MINT)?,
        mint_b: key(d, pool::POOL_TOKEN_B_MINT)?,
        vault_a: key(d, pool::POOL_TOKEN_A_VAULT)?,
        vault_b: key(d, pool::POOL_TOKEN_B_VAULT)?,
        liquidity: u128_at(d, pool::POOL_LIQUIDITY)?,
        sqrt_price: u128_at(d, pool::POOL_SQRT_PRICE)?,
        decimals: None,
    })
}

/// A Raydium CLMM `PoolState`'s bytes (the caller checked the owner).
pub fn read_raydium(d: &[u8]) -> Option<HopView> {
    use raydium::*;
    if d.len() < LEN || d[..8] != DISCRIMINATOR || d[STATUS] & STATUS_SWAP_DISABLED != 0 {
        return None;
    }
    let s = u128_at(d, SQRT_PRICE_X64)?;
    if !(MIN_SQRT_PRICE_X64..=MAX_SQRT_PRICE_X64).contains(&s) {
        return None;
    }
    Some(HopView {
        mint_a: key(d, MINT_0)?,
        mint_b: key(d, MINT_1)?,
        vault_a: key(d, VAULT_0)?,
        vault_b: key(d, VAULT_1)?,
        liquidity: u128_at(d, LIQUIDITY)?,
        sqrt_price: s,
        decimals: Some((d[DECIMALS_0], d[DECIMALS_1])),
    })
}

/// An Orca `Whirlpool`'s bytes (the caller checked the owner).
pub fn read_whirlpool(d: &[u8]) -> Option<HopView> {
    use whirlpool::*;
    if d.len() < LEN || d[..8] != DISCRIMINATOR {
        return None;
    }
    let s = u128_at(d, SQRT_PRICE)?;
    if !(MIN_SQRT_PRICE..=MAX_SQRT_PRICE).contains(&s) {
        return None;
    }
    Some(HopView {
        mint_a: key(d, MINT_A)?,
        mint_b: key(d, MINT_B)?,
        vault_a: key(d, VAULT_A)?,
        vault_b: key(d, VAULT_B)?,
        liquidity: u128_at(d, LIQUIDITY)?,
        sqrt_price: s,
        decimals: None,
    })
}

/// The venue of a recorded kind, None for anything but 1, 2, 3.
pub fn venue(kind: u8) -> Option<u8> {
    match kind {
        HOP_KIND_DAMM_V2 | HOP_KIND_RAYDIUM_CLMM | HOP_KIND_ORCA_WHIRLPOOL => Some(kind),
        _ => None,
    }
}

/// The depth floor a concentrated hop records for its out-side depth `depth` (u64, saturating).
pub fn floor_for(depth: u128) -> u64 {
    u64::try_from(depth / DEPTH_FLOOR_DIV).unwrap_or(u64::MAX)
}

/// Whether a recorded kind is a concentrated hop (it always carries a depth floor).
pub fn floored(kind: u8) -> bool {
    kind == HOP_KIND_RAYDIUM_CLMM || kind == HOP_KIND_ORCA_WHIRLPOOL
}

/// The program that must own a hop of `kind`; None for an unknown kind.
pub fn program_of(kind: u8) -> Option<Pubkey> {
    match venue(kind)? {
        HOP_KIND_DAMM_V2 => Some(CP_AMM_ID),
        HOP_KIND_RAYDIUM_CLMM => Some(RAYDIUM_CLMM_ID),
        _ => Some(ORCA_WHIRLPOOL_ID),
    }
}

/// A hop of the RECORDED `kind` from an account owned by `owner` with data `d`: None unless the
/// owner is that venue's program and the bytes are that venue's pool (pure; `read_hop` on accounts).
pub fn read_kind(kind: u8, owner: &Pubkey, d: &[u8]) -> Option<HopView> {
    if program_of(kind)? != *owner {
        return None;
    }
    match venue(kind)? {
        HOP_KIND_DAMM_V2 => read_damm(d),
        HOP_KIND_RAYDIUM_CLMM => read_raydium(d),
        _ => read_whirlpool(d),
    }
}

/// The hop account `info` read as the route's `kind` (None: unreadable).
pub fn read_hop(kind: u8, info: &AccountInfo) -> Option<HopView> {
    read_kind(kind, info.owner, &info.try_borrow_data().ok()?)
}

/// The REGISTRATION anchor of a concentrated 1-hop route (micro-USD; 0 = none): u64 LE in the first 8
/// bytes of hops[1].pool (stocks-d-a5 M1; `set_stock_route` writes it, nothing else does).
pub fn reg_anchor_of(route: &GapRoute) -> u64 {
    if route.hop_count != 1 {
        return 0;
    }
    u64::from_le_bytes(route.hops[1].pool.to_bytes()[..8].try_into().unwrap())
}

/// The route's anchor (route factor 1e18; 0 = none, a route without a concentrated hop).
pub fn anchor_of(route: &GapRoute) -> u128 {
    route.reserved.get(ANCHOR_AT..ANCHOR_AT + 8).and_then(|b| b.try_into().ok()).map_or(0, u64::from_le_bytes) as u128 * ANCHOR_UNIT
}

/// (up, down) within the anchor band: up <= anchor + anchor / 4 and down >= anchor - anchor / 4
/// (the band rounded toward the anchor: never wider than 25%).
pub fn within_anchor(up: u128, down: u128, anchor: u128) -> bool {
    let b = anchor >> ANCHOR_BAND_SHIFT;
    up <= anchor.saturating_add(b) && down >= anchor - b
}

/// Hop `i`'s recorded depth floors (token B's side, token A's side); (0, 0) = none (any hop but 0).
pub fn floors_of(route: &GapRoute, i: usize) -> (u64, u64) {
    if i != 0 {
        return (0, 0);
    }
    let at = |o: usize| route.reserved.get(o..o + 8).and_then(|b| b.try_into().ok()).map_or(0, u64::from_le_bytes);
    (at(FLOOR_AT), at(FLOOR_AT + 8))
}

/// One used hop, checked for pricing: the view and whether token_in is its token A. None when the
/// hop is unreadable as its kind, does not hold its two mints, (Raydium) its own decimals are not the
/// route's (stocks-d-a1 L3: a shifted layout), or (a concentrated hop) either side's in-range depth is
/// below its recorded floor (`floors` = (B side, A side)).
pub fn hop_checked(hop: &GapHop, floors: (u64, u64), info: &AccountInfo, dec_in: u8, dec_out: u8) -> Option<(HopView, bool)> {
    let hv = read_hop(hop.kind, info)?;
    let base_is_a = hv.side(&hop.token_in.to_bytes(), &hop.token_out.to_bytes())?;
    // stocks-d-a2 L4: a concentrated hop prices only with token_in its token A (the pinned orientation;
    // the reverse runs the slow base-is-B division, above the x1.2 compute limits)
    if floored(hop.kind) && !base_is_a {
        return None;
    }
    if let Some((da, db)) = hv.decimals {
        let mine = if base_is_a { (da, db) } else { (db, da) };
        if mine != (dec_in, dec_out) {
            return None;
        }
    }
    if floored(hop.kind) && !hv.deep_enough(floors) {
        return None;
    }
    Some((hv, base_is_a))
}

// ------------------------------------------------------------------ the hop readers

/// `record::route_usd` for both roundings at once, each hop read once: (up, down), each None on any
/// failure (the original's per-rounding result: refuses an unknown kind, a broken chain, an
/// unreadable hop, a zero product, a route not ending in a stable).
pub fn route_usd_both(global: &GapGlobal, route: Option<&GapRoute>, hops: [&AccountInfo; 2], mint: &Pubkey) -> (Option<u128>, Option<u128>) {
    walk(global, route, hops, mint, true, true)
}

/// The route walk for the roundings asked (`want_up`, `want_down`); a rounding not asked is None.
fn walk(global: &GapGlobal, route: Option<&GapRoute>, hops: [&AccountInfo; 2], mint: &Pubkey, want_up: bool, want_down: bool) -> (Option<u128>, Option<u128>) {
    if global.is_stable(mint) {
        return (Some(E18).filter(|_| want_up), Some(E18).filter(|_| want_down));
    }
    let Some(r) = route else { return (None, None) };
    if r.quote_mint != *mint || r.hop_count == 0 || r.hop_count > 2 || r.hops[0].token_in != *mint {
        return (None, None);
    }
    let (mut up, mut down) = (Some(E18).filter(|_| want_up), Some(E18).filter(|_| want_down));
    let mut last = *mint;
    for (i, (hop, dec_in, dec_out)) in r.used().enumerate() {
        if hop.token_in != last {
            return (None, None);
        }
        let Some((hv, base_is_a)) = hop_checked(hop, floors_of(r, i), hops[i], dec_in, dec_out) else {
            if floored(hop.kind) {
                // the hold alert: a concentrated hop unreadable (floor, layout, orientation, decimals)
                anchor_lang::solana_program::log::sol_log_data(&[b"gap-collar", r.quote_mint.as_ref(), &[4u8]]);
            }
            return (None, None);
        };
        // a hop price at PRICE_MAX (the down-rounding's overflow) is not a price (stocks-d-a2 L3)
        let hp = |up: bool| hv.price(base_is_a, dec_in, dec_out, up).filter(|p| *p != super::math::PRICE_MAX);
        // acc x p / 1e18 (exactly p while acc is 1e18: the first hop), u256-safe (stocks-d-a3 M2)
        let step = |acc: u128, p: u128, up: bool| if acc == E18 { p } else { mul_e18(acc, p, up) };
        up = up.and_then(|acc| hp(true).map(|p| step(acc, p, true))).filter(|a| *a != 0);
        down = down.and_then(|acc| hp(false).map(|p| step(acc, p, false))).filter(|a| *a != 0);
        last = hop.token_out;
    }
    if !global.is_stable(&last) {
        return (None, None);
    }
    // the anchor band on a concentrated route (both roundings judged together: a route is readable
    // or not); the up side alone when only up was asked, the down side alone likewise
    if concentrated(Some(r)) {
        let anchor = anchor_of(r);
        let ok = anchor != 0 && within_anchor(up.unwrap_or(0), down.unwrap_or(u128::MAX), anchor);
        if !ok {
            // the hold alert: outside the anchor band
            anchor_lang::solana_program::log::sol_log_data(&[b"gap-collar", r.quote_mint.as_ref(), &[5u8]]);
            return (None, None);
        }
    }
    (up, down)
}

/// `record::route_usd` (one rounding).
pub fn route_usd(global: &GapGlobal, route: Option<&GapRoute>, hops: [&AccountInfo; 2], mint: &Pubkey, up: bool) -> Option<u128> {
    let (u, d) = walk(global, route, hops, mint, up, !up);
    if up { u } else { d }
}

/// `record::live_prices` with the quote's route walked once for both roundings (same outputs).
pub fn live_prices(a: &GapAccounts, d: &GapData, tail: &Tail, token_mint: &Pubkey) -> Live {
    let cls_up = engine::pool_price(d, tail, token_mint, true).unwrap_or(0);
    let cls_down = engine::pool_price(d, tail, token_mint, false).unwrap_or(0);
    let Some(g) = d.global.as_ref() else { return Live { usd_up: 0, usd_down: 0, cls_up, cls_down, sol: 0 } };
    let (f_up, f_down) = if cls_up == 0 && cls_down == 0 { (None, None) } else { route_usd_both(g, d.route.as_ref(), [a.hop0, a.hop1], &tail.quote_mint) };
    let usd_up = match f_up {
        Some(f) if cls_up != 0 => mul_e18(cls_up, f, true),
        _ => 0,
    };
    let usd_down = match f_down {
        Some(f) if cls_down != 0 => mul_e18(cls_down, f, false),
        _ => 0,
    };
    Live { usd_up, usd_down, cls_up, cls_down, sol: 0 }
}

/// The used hops of `r` (their accounts `hops`) and each one's vaults, read per kind.
fn push_hops(keys: &mut Vec<[u8; 32]>, r: &GapRoute, hops: [&AccountInfo; 2]) {
    for (i, info) in hops.iter().enumerate().take((r.hop_count as usize).min(2)) {
        keys.push(info.key.to_bytes());
        if let Some(h) = read_hop(r.hops[i].kind, info) {
            keys.push(h.vault_a);
            keys.push(h.vault_b);
        }
    }
}

/// `engine::refuse_earlier_touch` (the receive's) with each hop's vaults read per kind.
pub fn engine_refuse_earlier_touch(a: &GapAccounts, d: &GapData, tail: &Tail) -> Result<()> {
    let mut keys: Vec<[u8; 32]> = vec![a.pool.key.to_bytes()];
    if let Some(p) = d.pool {
        keys.push(p.vault_a);
        keys.push(p.vault_b);
    }
    let stable = d.global.as_ref().map_or(false, |g| g.is_stable(&tail.quote_mint));
    if let (false, Some(r)) = (stable, d.route.as_ref()) {
        // `check` made each hop account the route's pool for a used slot
        push_hops(&mut keys, r, [a.hop0, a.hop1]);
    }
    let data = a.ixs.try_borrow_data()?;
    let touched = introspect::touched_earlier(&data, &keys).ok_or(OFTError::GapAccountMismatch)?;
    require!(!touched, OFTError::PoolTouchedEarlier);
    Ok(())
}

/// `record::refuse_earlier_touch` (the send's and record_price's) with each hop's vaults read per kind.
pub fn record_refuse_earlier_touch(a: &GapAccounts, d: &GapData, tail: &Tail, native: Option<&NativeRoute>) -> Result<()> {
    let mut keys: Vec<[u8; 32]> = vec![a.pool.key.to_bytes()];
    if let Some(p) = d.pool {
        keys.push(p.vault_a);
        keys.push(p.vault_b);
    }
    let mut add_hops = |route: Option<&GapRoute>, hops: [&AccountInfo; 2], mint: &Pubkey| {
        let stable = d.global.as_ref().map_or(false, |g| g.is_stable(mint));
        if let (false, Some(r)) = (stable, route) {
            push_hops(&mut keys, r, hops);
        }
    };
    add_hops(d.route.as_ref(), [a.hop0, a.hop1], &tail.quote_mint);
    if let Some(n) = native {
        add_hops(n.route.as_ref(), n.hops, &WSOL_MINT);
    }
    let data = a.ixs.try_borrow_data()?;
    let touched = introspect::touched_earlier(&data, &keys).ok_or(OFTError::GapAccountMismatch)?;
    require!(!touched, OFTError::PoolTouchedEarlier);
    Ok(())
}

/// `set_stock_route(params, min_depth_b, min_depth_a)`: the registrar's concentrated-route registration
/// (the `set_gap_route` accounts and params, plus the minimum in-band depths).
pub fn set_stock_route(ctx: &mut Context<SetGapRoute>, params: &SetGapRouteParams, min_depth_b: u64, min_depth_a: u64) -> Result<()> {
    SetGapRoute::apply_with(ctx, params, Some((min_depth_b, min_depth_a)))
}

impl RecordPrice<'_> {
    /// `RecordPrice::apply` with the collar (above) on a concentrated route; otherwise the original.
    pub fn apply(ctx: &mut Context<RecordPrice>) -> Result<()> {
        use anchor_lang::solana_program::instruction::{get_stack_height, TRANSACTION_LEVEL_STACK_HEIGHT};
        require!(get_stack_height() == TRANSACTION_LEVEL_STACK_HEIGHT, OFTError::SendViaCpi);
        require!(!ctx.accounts.oft_store.paused, OFTError::Paused);
        let tail = {
            let info = ctx.accounts.oft_store.to_account_info();
            let d = info.try_borrow_data()?;
            Tail::read(&d).ok_or(OFTError::NotV3Store)?
        };
        let rem = ctx.remaining_accounts;
        let a = GapAccounts::at(rem, 0)?;
        let d = checked(&a, &tail, ctx.program_id)?;
        let native = check_native_route(rem, engine::GAP_ACCOUNTS, ctx.program_id)?;
        record_refuse_earlier_touch(&a, &d, &tail, Some(&native))?;
        let log = ctx.accounts.price_log.to_account_info();
        require!(pricelog::open(&log, &ctx.accounts.oft_store.key(), ctx.program_id)?, OFTError::GapNeedRecords);
        pricelog::refuse_second_write(a.ixs, log.key)?;

        let mut live = live_prices(&a, &d, &tail, &ctx.accounts.token_mint.key());
        require!(live.usd_up != 0 || live.cls_up != 0, OFTError::GapSourceUnreadable);
        live.sol = d.global.as_ref().and_then(|g| route_usd(g, native.route.as_ref(), native.hops, &WSOL_MINT, false)).unwrap_or(0);
        let slot = Clock::get()?.slot;
        {
            let mut ld = log.try_borrow_mut_data()?;
            let w = d.global.as_ref().map_or(WINDOW_DEFAULT as u64, |g| g.window());
            if concentrated(d.route.as_ref()) {
                let win = pricelog::window(&ld, slot, w);
                if win.entries == 0 {
                    // the bootstrap of an empty window (the only way to (re)seed a store's log; a
                    // deviation from "empty = hold", lead8 L120, which would deadlock the store): the
                    // route factor usd / cls within 10% of the registration / keeper anchor
                    let anchor = d.route.as_ref().map_or(0, anchor_of);
                    let ok = live.usd_down != 0
                        && le_scaled(live.usd_down, E18, COLLAR_DEN, anchor, live.cls_down, COLLAR_NUM)
                        && le_scaled(anchor, live.cls_down, COLLAR_DEN, live.usd_down, E18, COLLAR_NUM);
                    if !ok {
                        anchor_lang::solana_program::log::sol_log_data(&[b"gap-collar", tail.quote_mint.as_ref(), &[3u8]]);
                        live.usd_up = 0;
                        live.usd_down = 0;
                    }
                } else {
                    live = collar_live(&d, &tail, live, &win);
                }
                // stocks-d-a3 I2: a concentrated route never writes a USD-less entry (it would block the
                // next send for a window): unreadable or collared -> nothing is written
                require!(live.usd_down != 0 && live.usd_up != 0, OFTError::GapSourceUnreadable);
            }
            let by = pricelog::Writer { key: ctx.accounts.signer.key().to_bytes(), fee_ppm: fee_at_record(&d) };
            // a forfeit stays parked in the log (the store is read-only here)
            pricelog::write(&mut ld, slot, w, &live, &by);
        }
        // "gap-price" | slot u64 | usd_up u128 | usd_down u128 | cls_up u128 | cls_down u128 | sol u128 (LE)
        anchor_lang::solana_program::log::sol_log_data(&[
            b"gap-price",
            &slot.to_le_bytes(),
            &live.usd_up.to_le_bytes(),
            &live.usd_down.to_le_bytes(),
            &live.cls_up.to_le_bytes(),
            &live.cls_down.to_le_bytes(),
            &live.sol.to_le_bytes(),
        ]);
        Ok(())
    }
}

impl SetGapRoute<'_> {
    /// `SetGapRoute::apply` (set_gap_route, feature build): DAMM v2 routes only (kind 1); a concentrated
    /// kind is refused here (lead8 L133: its floors come from `set_stock_route`). remaining_accounts:
    /// the hop pools, then the mints hops[0].token_in, hops[0].token_out [, hops[1].token_out]. Each
    /// pool is its venue's program's, is that venue's pool and holds exactly its hop's two mints.
    pub fn apply(ctx: &mut Context<SetGapRoute>, params: &SetGapRouteParams) -> Result<()> {
        Self::apply_with(ctx, params, None)
    }

    /// `set_stock_route` (lead8 L133): a concentrated route with the registrar's minimum in-band depth
    /// per side (raw units of token B, token A: the Q86 listing tool's figure); `set_gap_route` refuses
    /// concentrated kinds (their floors must come from the tool).
    pub fn apply_with(ctx: &mut Context<SetGapRoute>, params: &SetGapRouteParams, min_depth: Option<(u64, u64)>) -> Result<()> {
        let n = params.hop_count as usize;
        require!((1..=2).contains(&n), OFTError::BadGapRoute);
        let rem = ctx.remaining_accounts;
        require!(rem.len() == 2 * n + 1, OFTError::BadGapRoute);
        require!(params.hops[0].token_in == params.quote_mint, OFTError::BadGapRoute);
        if n == 1 {
            require!(params.hops[1] == GapHop::default(), OFTError::BadGapRoute);
        } else {
            require!(params.hops[1].token_in == params.hops[0].token_out, OFTError::BadGapRoute);
        }
        let mut reserved = [0u8; 32];
        // per hop: the pool's own (decimals in, decimals out), when it records them
        let mut pool_decimals: [Option<(u8, u8)>; 2] = [None, None];
        let mut concentrated = false;
        let mut reg_anchor = 0u64;
        for (i, hop) in params.hops[..n].iter().enumerate() {
            require!(venue(hop.kind).is_some() && hop.token_in != hop.token_out, OFTError::BadGapRoute);
            concentrated |= venue(hop.kind) != Some(HOP_KIND_DAMM_V2);
            require_keys_eq!(*rem[i].key, hop.pool, OFTError::BadGapRoute);
            let hv = read_hop(hop.kind, &rem[i]).ok_or(OFTError::BadGapRoute)?;
            let in_is_a = hv.side(&hop.token_in.to_bytes(), &hop.token_out.to_bytes()).ok_or(OFTError::BadGapRoute)?;
            pool_decimals[i] = hv.decimals.map(|(da, db)| if in_is_a { (da, db) } else { (db, da) });
            if floored(hop.kind) {
                // stocks-d-a2 L4: token_in must be the pool's token A (the pinned orientation)
                require!(in_is_a, OFTError::BadGapRoute);
                // lead8 L133: the registrar's minimum depths (set_stock_route only); the pool must hold
                // them now; floors = minimum / 10 (a 2-hop route with this hop is refused below: i == 0)
                let (mb, ma) = min_depth.ok_or(OFTError::BadGapRoute)?;
                let (fb, fa) = (floor_for(mb as u128), floor_for(ma as u128));
                require!(i == 0 && fb != 0 && fa != 0, OFTError::BadGapRoute);
                require!(hv.depth_out(true) >= mb as u128 && hv.depth_out(false) >= ma as u128, OFTError::BadGapRoute);
                reserved[FLOOR_AT..FLOOR_AT + 8].copy_from_slice(&fb.to_le_bytes());
                reserved[FLOOR_AT + 8..FLOOR_AT + 16].copy_from_slice(&fa.to_le_bytes());
            }
        }
        let mints = [params.hops[0].token_in, params.hops[0].token_out, params.hops[1].token_out];
        for j in 0..=n {
            let m = &rem[n + j];
            require_keys_eq!(*m.key, mints[j], OFTError::BadGapRoute);
            reserved[j] = mint_decimals(m).ok_or(OFTError::BadGapRoute)?;
        }
        for (i, pd) in pool_decimals.iter().enumerate().take(n) {
            if let Some((d_in, d_out)) = pd {
                require!(*d_in == reserved[i] && *d_out == reserved[i + 1], OFTError::BadGapRoute);
            }
        }
        require!(ctx.accounts.gap_global.is_stable(&params.hops[n - 1].token_out), OFTError::BadGapRoute);
        require!(!concentrated || ctx.accounts.gap_global.class_of(&params.quote_mint) == 0, OFTError::BadGapRoute);
        // stocks-d-a2 L2: a concentrated hop only on a 1-hop route (a 2-hop worst case is above the
        // x1.2 compute limits; the 9 xStock routes are 1 hop)
        require!(n == 1 || !concentrated, OFTError::BadGapRoute);
        if concentrated {
            // the anchor: the 1-hop route's factor now (whole stable per whole quote, rounded down),
            // micro-USD, u64 (refused when 0 or above u64)
            let hv = read_hop(params.hops[0].kind, &rem[0]).ok_or(OFTError::BadGapRoute)?;
            let p = hv.price(true, reserved[0], reserved[1], false).filter(|p| *p != super::math::PRICE_MAX).ok_or(OFTError::BadGapRoute)?;
            let anchor = u64::try_from(p / ANCHOR_UNIT).ok().filter(|a| *a != 0).ok_or(OFTError::BadGapRoute)?;
            reserved[ANCHOR_AT..ANCHOR_AT + 8].copy_from_slice(&anchor.to_le_bytes());
            reg_anchor = anchor;
        }
        // stocks-d-a5 I1 / lead8 L152: set_stock_route registers concentrated routes only
        require!(min_depth.is_none() || concentrated, OFTError::BadGapRoute);

        let r = &mut ctx.accounts.gap_route;
        r.version = 1;
        r.bump = ctx.bumps.gap_route;
        r.quote_mint = params.quote_mint;
        r.hop_count = n as u8;
        r.hops = params.hops;
        r.reserved = reserved;
        // the registration anchor (a5 M1 / Q97 band), in the all-zero hops[1] slot of a 1-hop route
        if reg_anchor != 0 {
            let mut k = [0u8; 32];
            k[..8].copy_from_slice(&reg_anchor.to_le_bytes());
            r.hops[1].pool = Pubkey::new_from_array(k);
        }
        emit!(GapRouteSet { quote_mint: params.quote_mint, hop_count: n as u8, hops: params.hops });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rnd(x: &mut u128) -> u128 {
        *x ^= *x << 13;
        *x ^= *x >> 7;
        *x ^= *x << 17;
        *x
    }
    fn k(b: u8) -> [u8; 32] {
        [b; 32]
    }
    fn sqrt_q64(raw: f64) -> u128 {
        (raw.sqrt() * 18446744073709551616.0) as u128
    }

    /// A Raydium PoolState's bytes (layout per `raydium`).
    pub fn raydium_bytes(m0: [u8; 32], m1: [u8; 32], d0: u8, d1: u8, liq: u128, sqrt: u128, status: u8) -> Vec<u8> {
        use raydium::*;
        let mut d = vec![0u8; LEN];
        d[..8].copy_from_slice(&DISCRIMINATOR);
        d[MINT_0..MINT_0 + 32].copy_from_slice(&m0);
        d[MINT_1..MINT_1 + 32].copy_from_slice(&m1);
        d[VAULT_0..VAULT_0 + 32].copy_from_slice(&k(0xA0));
        d[VAULT_1..VAULT_1 + 32].copy_from_slice(&k(0xA1));
        d[DECIMALS_0] = d0;
        d[DECIMALS_1] = d1;
        d[LIQUIDITY..LIQUIDITY + 16].copy_from_slice(&liq.to_le_bytes());
        d[SQRT_PRICE_X64..SQRT_PRICE_X64 + 16].copy_from_slice(&sqrt.to_le_bytes());
        d[STATUS] = status;
        d
    }
    pub fn whirlpool_bytes(ma: [u8; 32], mb: [u8; 32], liq: u128, sqrt: u128) -> Vec<u8> {
        use whirlpool::*;
        let mut d = vec![0u8; LEN];
        d[..8].copy_from_slice(&DISCRIMINATOR);
        d[MINT_A..MINT_A + 32].copy_from_slice(&ma);
        d[MINT_B..MINT_B + 32].copy_from_slice(&mb);
        d[VAULT_A..VAULT_A + 32].copy_from_slice(&k(0xB0));
        d[VAULT_B..VAULT_B + 32].copy_from_slice(&k(0xB1));
        d[LIQUIDITY..LIQUIDITY + 16].copy_from_slice(&liq.to_le_bytes());
        d[SQRT_PRICE..SQRT_PRICE + 16].copy_from_slice(&sqrt.to_le_bytes());
        d
    }
    /// A DAMM v2 pool's bytes with the same mints / liquidity / sqrt price.
    fn damm_bytes(ma: [u8; 32], mb: [u8; 32], liq: u128, sqrt: u128) -> Vec<u8> {
        let mut d = vec![0u8; pool::POOL_MIN_LEN];
        d[..8].copy_from_slice(&pool::POOL_DISCRIMINATOR);
        d[pool::POOL_TOKEN_A_MINT..pool::POOL_TOKEN_A_MINT + 32].copy_from_slice(&ma);
        d[pool::POOL_TOKEN_B_MINT..pool::POOL_TOKEN_B_MINT + 32].copy_from_slice(&mb);
        d[pool::POOL_TOKEN_A_VAULT..pool::POOL_TOKEN_A_VAULT + 32].copy_from_slice(&k(0xC0));
        d[pool::POOL_TOKEN_B_VAULT..pool::POOL_TOKEN_B_VAULT + 32].copy_from_slice(&k(0xC1));
        d[pool::POOL_LIQUIDITY..pool::POOL_LIQUIDITY + 16].copy_from_slice(&liq.to_le_bytes());
        d[pool::POOL_SQRT_PRICE..pool::POOL_SQRT_PRICE + 16].copy_from_slice(&sqrt.to_le_bytes());
        d
    }

    #[test]
    fn layouts_are_the_venues_sizes_and_fields_do_not_overlap() {
        assert_eq!(raydium::LEN, 1544);
        assert_eq!(whirlpool::LEN, 653);
        // Raydium, packed: disc 8 | bump 1 | amm_config 32 | owner 32 | mint0 | mint1 | vault0 | vault1 |
        // observation | dec0 | dec1 | tick_spacing 2 | liquidity 16 | sqrt 16 | tick 4 | pad 2+2 | fg 16+16 |
        // protocol fees 8+8 | padding5 16 x 4 | status
        assert_eq!(raydium::MINT_0, 8 + 1 + 32 + 32);
        assert_eq!(raydium::MINT_1, raydium::MINT_0 + 32);
        assert_eq!(raydium::VAULT_0, raydium::MINT_1 + 32);
        assert_eq!(raydium::VAULT_1, raydium::VAULT_0 + 32);
        assert_eq!(raydium::DECIMALS_0, raydium::VAULT_1 + 32 + 32);
        assert_eq!(raydium::DECIMALS_1, raydium::DECIMALS_0 + 1);
        assert_eq!(raydium::LIQUIDITY, raydium::DECIMALS_1 + 1 + 2);
        assert_eq!(raydium::SQRT_PRICE_X64, raydium::LIQUIDITY + 16);
        assert_eq!(raydium::STATUS, raydium::SQRT_PRICE_X64 + 16 + 4 + 4 + 32 + 16 + 64);
        // and the rest to LEN: status 1 | fee_on 1 | seed 2 | pad 4 | 3 x RewardInfo 169 | bitmap 128 |
        // padding6 32 | fund fees 16 | open_time 8 | recent_epoch 8 | dynamic fee 80 | padding1 112 | padding2 256
        assert_eq!(raydium::LEN, raydium::STATUS + 8 + 3 * 169 + 128 + 32 + 16 + 8 + 8 + 80 + 112 + 256);
        // Whirlpool: disc 8 | config 32 | bump 1 | tick_spacing 2 | seed 2 | fee_rate 2 | protocol 2 | liquidity
        assert_eq!(whirlpool::LIQUIDITY, 8 + 32 + 1 + 2 + 2 + 2 + 2);
        assert_eq!(whirlpool::SQRT_PRICE, whirlpool::LIQUIDITY + 16);
        assert_eq!(whirlpool::MINT_A, whirlpool::SQRT_PRICE + 16 + 4 + 16);
        assert_eq!(whirlpool::VAULT_A, whirlpool::MINT_A + 32);
        assert_eq!(whirlpool::MINT_B, whirlpool::VAULT_A + 32 + 16);
        assert_eq!(whirlpool::VAULT_B, whirlpool::MINT_B + 32);
        assert_eq!(whirlpool::LEN, whirlpool::VAULT_B + 32 + 16 + 8 + 3 * 128);
        use anchor_lang::solana_program::hash::hash;
        assert_eq!(hash(b"account:PoolState").to_bytes()[..8], raydium::DISCRIMINATOR);
        assert_eq!(hash(b"account:Whirlpool").to_bytes()[..8], whirlpool::DISCRIMINATOR);
    }

    #[test]
    fn kinds_venues_and_flags() {
        for (kind, v, fl) in [(1u8, Some(1u8), false), (2, Some(2), true), (3, Some(3), true), (0x82, None, false), (0x83, None, false), (0x81, None, false), (0, None, false), (4, None, false), (0x80, None, false), (255, None, false)] {
            assert_eq!(venue(kind), v, "{kind}");
            assert_eq!(floored(kind), fl, "{kind}");
            assert_eq!(program_of(kind).is_some(), v.is_some());
        }
        assert_eq!(program_of(2), Some(RAYDIUM_CLMM_ID));
        assert_eq!(program_of(3), Some(ORCA_WHIRLPOOL_ID));
        assert_eq!((floor_for(0), floor_for(9), floor_for(10), floor_for(12_345)), (0, 0, 1, 1_234));
        assert_eq!(floor_for(u128::MAX), u64::MAX);
        assert_eq!(floor_for(u64::MAX as u128 * 10 + 9), u64::MAX);
        assert_eq!(floor_for(u64::MAX as u128 * 10 + 10), u64::MAX);
    }

    #[test]
    fn readers_check_owner_kind_layout_and_status() {
        let ray = raydium_bytes(k(1), k(2), 8, 6, 5, 1 << 64, 0);
        let orca = whirlpool_bytes(k(1), k(2), 5, 1 << 64);
        let damm = damm_bytes(k(1), k(2), 5, 1 << 64);
        let h = read_kind(HOP_KIND_RAYDIUM_CLMM, &RAYDIUM_CLMM_ID, &ray).unwrap();
        assert_eq!((h.mint_a, h.mint_b, h.vault_a, h.vault_b, h.liquidity, h.sqrt_price, h.decimals), (k(1), k(2), k(0xA0), k(0xA1), 5, 1 << 64, Some((8, 6))));
        let h = read_kind(HOP_KIND_ORCA_WHIRLPOOL, &ORCA_WHIRLPOOL_ID, &orca).unwrap();
        assert_eq!((h.mint_a, h.mint_b, h.vault_a, h.vault_b, h.liquidity, h.sqrt_price, h.decimals), (k(1), k(2), k(0xB0), k(0xB1), 5, 1 << 64, None));
        // the DAMM v2 hop reader agrees with pool::read on every field it takes, and refuses what it refuses
        let h = read_kind(HOP_KIND_DAMM_V2, &CP_AMM_ID, &damm).unwrap();
        let p = pool::read(&damm).unwrap();
        assert_eq!((h.mint_a, h.mint_b, h.vault_a, h.vault_b, h.liquidity, h.sqrt_price, h.decimals), (p.mint_a, p.mint_b, p.vault_a, p.vault_b, p.liquidity, p.sqrt_price, None));
        assert!(read_damm(&damm[..pool::POOL_MIN_LEN - 1]).is_none() && pool::read(&damm[..pool::POOL_MIN_LEN - 1]).is_none());
        let mut bad = damm.clone();
        bad[2] ^= 1;
        assert!(read_damm(&bad).is_none() && pool::read(&bad).is_none());
        // the owner must be the RECORDED kind's program, and the bytes that venue's
        for (kind, data) in [(HOP_KIND_DAMM_V2, &damm), (HOP_KIND_RAYDIUM_CLMM, &ray), (HOP_KIND_ORCA_WHIRLPOOL, &orca)] {
            for owner in [CP_AMM_ID, RAYDIUM_CLMM_ID, ORCA_WHIRLPOOL_ID, Pubkey::new_from_array([9; 32])] {
                assert_eq!(read_kind(kind, &owner, data).is_some(), Some(owner) == program_of(kind), "kind {kind} owner {owner}");
            }
            for other in [HOP_KIND_DAMM_V2, HOP_KIND_RAYDIUM_CLMM, HOP_KIND_ORCA_WHIRLPOOL] {
                if Some(other) != venue(kind) {
                    assert!(read_kind(other, &program_of(other).unwrap(), data).is_none(), "{kind} read as {other}");
                }
            }
        }
        for kind in [0u8, 4, 0x81, 0x82, 0x83, 255] {
            assert!(read_kind(kind, &RAYDIUM_CLMM_ID, &ray).is_none());
            assert!(read_kind(kind, &CP_AMM_ID, &damm).is_none());
        }
        assert!(read_raydium(&ray[..raydium::LEN - 1]).is_none());
        assert!(read_whirlpool(&orca[..whirlpool::LEN - 1]).is_none());
        let mut bad = ray.clone();
        bad[0] ^= 1;
        assert!(read_raydium(&bad).is_none());
        let mut bad = orca.clone();
        bad[7] ^= 1;
        assert!(read_whirlpool(&bad).is_none());
        assert!(read_raydium(&raydium_bytes(k(1), k(2), 8, 6, 5, 1 << 64, 1 << 4)).is_none());
        assert!(read_raydium(&raydium_bytes(k(1), k(2), 8, 6, 5, 1 << 64, 0xFF)).is_none());
        for b in [0u8, 1, 2, 3, 5, 6, 7] {
            assert!(read_raydium(&raydium_bytes(k(1), k(2), 8, 6, 5, 1 << 64, 1 << b)).is_some(), "bit {b}");
        }
        let mut long = ray.clone();
        long.extend_from_slice(&[0u8; 64]);
        assert!(read_raydium(&long).is_some());
    }

    #[test]
    fn a_sqrt_price_outside_the_venue_bounds_is_unreadable() {
        use raydium::{MAX_SQRT_PRICE_X64 as RMAX, MIN_SQRT_PRICE_X64 as RMIN};
        use whirlpool::{MAX_SQRT_PRICE as WMAX, MIN_SQRT_PRICE as WMIN};
        for (s, ok) in [(0, false), (RMIN - 1, false), (RMIN, true), (RMAX, true), (RMAX + 1, false), (u128::MAX, false)] {
            assert_eq!(read_raydium(&raydium_bytes(k(1), k(2), 8, 6, 1, s, 0)).is_some(), ok, "{s}");
        }
        for (s, ok) in [(0, false), (WMIN - 1, false), (WMIN, true), (WMAX, true), (WMAX + 1, false), (u128::MAX, false)] {
            assert_eq!(read_whirlpool(&whirlpool_bytes(k(1), k(2), 1, s)).is_some(), ok, "{s}");
        }
    }

    /// Property: a hop of every kind prices exactly as `pool::PoolView::price` (the v3 DAMM v2 hop)
    /// with the same mints, liquidity and sqrt price, both roundings and both orientations; up >= down;
    /// liquidity 0 unreadable.
    #[test]
    fn every_kind_prices_as_damm_v2_property() {
        let mut x: u128 = 0x2545_F491_4F6C_DD1D_9E37_79B9_7F4A_7C15;
        let pairs = [(8u8, 6u8), (6, 8), (8, 9), (9, 8), (6, 6), (0, 18), (18, 0)];
        for _ in 0..4_000 {
            let s = (rnd(&mut x) >> (32 + (rnd(&mut x) % 60) as u32)).clamp(raydium::MIN_SQRT_PRICE_X64, whirlpool::MAX_SQRT_PRICE);
            let liq = (rnd(&mut x) >> 64).max(1);
            let (da, db) = pairs[(rnd(&mut x) % pairs.len() as u128) as usize];
            let v3 = pool::read(&damm_bytes(k(1), k(2), liq, s)).unwrap();
            let damm = read_damm(&damm_bytes(k(1), k(2), liq, s)).unwrap();
            let ray = read_raydium(&raydium_bytes(k(1), k(2), da, db, liq, s, 0)).unwrap();
            let orca = read_whirlpool(&whirlpool_bytes(k(1), k(2), liq, s)).unwrap();
            for &(base, quote) in &[(k(1), k(2)), (k(2), k(1))] {
                let a = v3.side(&base, &quote).unwrap();
                for h in [&damm, &ray, &orca] {
                    assert_eq!(h.side(&base, &quote), Some(a));
                }
                let (db_, dq_) = if a { (da, db) } else { (db, da) };
                for up in [false, true] {
                    let want = v3.price(a, db_, dq_, up);
                    for h in [&damm, &ray, &orca] {
                        assert_eq!(h.price(a, db_, dq_, up), want, "{s} {a} {up}");
                    }
                }
                if let (Some(u), Some(d)) = (ray.price(a, db_, dq_, true), ray.price(a, db_, dq_, false)) {
                    assert!(u >= d, "{s}: {u} < {d}");
                }
            }
            assert_eq!(ray.side(&k(1), &k(3)), None);
            assert_eq!(orca.side(&k(3), &k(2)), None);
        }
        let ray = read_raydium(&raydium_bytes(k(1), k(2), 8, 6, 0, 1 << 64, 0)).unwrap();
        let orca = read_whirlpool(&whirlpool_bytes(k(1), k(2), 0, 1 << 64)).unwrap();
        assert_eq!(ray.price(true, 8, 6, false), None);
        assert_eq!(orca.price(true, 8, 6, true), None);
    }

    /// ScaledUiAmount (stocks-c hand-off's test): the multiplier is display only.
    #[test]
    fn the_scaled_ui_multiplier_cancels() {
        let ui_usd_per_share = 250.0_f64;
        for m in [1.0_f64, 1.003269, 1.005309, 2.0] {
            let raw_usd = ui_usd_per_share * m;
            let hop = read_raydium(&raydium_bytes(k(1), k(2), 8, 6, 1 << 50, sqrt_q64(raw_usd * 1e6 / 1e8), 0)).unwrap();
            let hop_usd = hop.price(true, 8, 6, false).unwrap() as f64 / E18 as f64;
            let coin_in_raw_xstock = 0.001_f64;
            let usd_chain = coin_in_raw_xstock * hop_usd;
            let usd_ui = (coin_in_raw_xstock * m) * ui_usd_per_share;
            assert!((usd_chain / usd_ui - 1.0).abs() < 1e-9, "m {m}: {usd_chain} vs {usd_ui}");
        }
    }

    /// AAPLx (8 dec, token 0) at $230.00 in USDC (6 dec, token 1): raw price 2.3.
    #[test]
    fn an_xstock_usdc_hop_prices_whole_units() {
        let h = read_raydium(&raydium_bytes(k(1), k(2), 8, 6, 1_000_000, sqrt_q64(2.3), 0)).unwrap();
        let up = h.price(true, 8, 6, true).unwrap();
        let down = h.price(true, 8, 6, false).unwrap();
        assert!(down <= up && up - down <= 2 + down / 1_000_000_000_000, "{up} {down}");
        assert!((229_999_000_000_000_000_000..=230_001_000_000_000_000_000).contains(&down), "{down}");
        let inv = h.price(false, 6, 8, false).unwrap();
        assert!((4_347_800_000_000_000..=4_347_900_000_000_000).contains(&inv), "{inv}");
    }

    #[test]
    fn depth_out_is_the_virtual_reserve() {
        let v = HopView { mint_a: k(1), mint_b: k(2), vault_a: k(0), vault_b: k(0), liquidity: 1_000_000, sqrt_price: 1 << 64, decimals: None };
        assert_eq!((v.depth_out(true), v.depth_out(false)), (1_000_000, 1_000_000));
        let v = HopView { sqrt_price: 1 << 65, ..v };
        assert_eq!((v.depth_out(true), v.depth_out(false)), (2_000_000, 500_000));
        let v = HopView { sqrt_price: 1 << 63, ..v };
        assert_eq!((v.depth_out(true), v.depth_out(false)), (500_000, 2_000_000));
        let v = HopView { liquidity: 3, sqrt_price: 1 << 63, ..v };
        assert_eq!((v.depth_out(true), v.depth_out(false)), (1, 6));
        assert_eq!(HopView { liquidity: 0, ..v }.depth_out(true), 0);
        assert_eq!(HopView { sqrt_price: 0, ..v }.depth_out(false), 0);
        for &(l, s) in &[(u128::MAX, raydium::MAX_SQRT_PRICE_X64), (u128::MAX, u128::MAX)] {
            let v = HopView { liquidity: l, sqrt_price: s, ..v };
            assert_eq!(v.depth_out(true), u128::MAX, "{l} {s}");
            let _ = v.depth_out(false);
        }
        assert_eq!(HopView { liquidity: 1 << 100, sqrt_price: 1 << 70, ..v }.depth_out(true), 1 << 106);
        assert_eq!(HopView { liquidity: u128::MAX, sqrt_price: 1, ..v }.depth_out(false), u128::MAX);
        let v = HopView { liquidity: 5_000_000_000_000, sqrt_price: sqrt_q64(2.5), ..v };
        assert!((v.depth_out(true) as f64 / (5e12 * 2.5f64.sqrt()) - 1.0).abs() < 1e-9);
        assert!((v.depth_out(false) as f64 / (5e12 / 2.5f64.sqrt()) - 1.0).abs() < 1e-9);
    }

    /// deep_enough == the two depth_out comparisons, on random and edge values.
    #[test]
    fn deep_enough_equals_the_depth_comparisons() {
        let mut x: u128 = 0x1234_5678_9ABC_DEF0_0FED_CBA9_8765_4321;
        let base = HopView { mint_a: k(1), mint_b: k(2), vault_a: k(0), vault_b: k(0), liquidity: 1, sqrt_price: 1, decimals: None };
        let mut n_true = 0;
        for i in 0..20_000 {
            let l = rnd(&mut x) >> (rnd(&mut x) % 128);
            let s = (rnd(&mut x) >> (32 + rnd(&mut x) % 64)).max(1);
            let v = HopView { liquidity: l, sqrt_price: s, ..base };
            let (db, da) = (v.depth_out(true), v.depth_out(false));
            // floors around the real depths, so both outcomes occur
            let pick = |d: u128, r: u128| -> u64 {
                let d = d.min(u64::MAX as u128) as u64;
                match r % 4 { 0 => d, 1 => d.saturating_add(1), 2 => d.saturating_sub(1), _ => (r >> 64) as u64 }
            };
            let (fb, fa) = (pick(db, rnd(&mut x)), pick(da, rnd(&mut x)));
            let want = db >= fb as u128 && da >= fa as u128;
            assert_eq!(v.deep_enough((fb, fa)), want, "{i}: L {l} s {s} fb {fb} fa {fa}");
            n_true += want as u32;
        }
        assert!(n_true > 2_000 && n_true < 18_000, "{n_true}");
        let v = HopView { liquidity: 0, sqrt_price: 1 << 64, ..base };
        assert!(v.deep_enough((0, 0)) && !v.deep_enough((1, 0)) && !v.deep_enough((0, 1)));
        let v = HopView { liquidity: 10, sqrt_price: 1 << 64, ..base };
        assert!(v.deep_enough((10, 10)) && !v.deep_enough((11, 10)) && !v.deep_enough((10, 11)));
    }

    #[test]
    fn the_collar_bounds_the_hop_factor_by_the_window_property() {
        let w = |usd_min: u128, usd_max: u128, cls_min: u128, cls_max: u128| Window { entries: 3, usd_min, usd_max, cls_min, cls_max, sol_min: 0 };
        // a window where the coin was 100..120 (cls) at a hop factor of exactly 200: usd 20,000..24,000
        let win = w(20_000 * E18, 24_000 * E18, 100 * E18, 120 * E18);
        // factor bounds: [20,000/120, 24,000/100] = [166.67, 240], widened 10%: [151.5, 264]
        for (f, ok) in [(200u128, true), (240, true), (264, true), (265, false), (400, false), (800, false), (152, true), (151, false), (50, false)] {
            assert_eq!(factor_in_collar(f * 110 * E18, 110 * E18, &win), ok, "factor {f}");
        }
        // nothing to compare: in
        assert!(factor_in_collar(1, 1, &Window { entries: 0, ..win }));
        assert!(factor_in_collar(0, 5, &win) && factor_in_collar(5, 0, &win));
        assert!(factor_in_collar(1_000 * E18, E18, &w(0, 0, 0, 0)));
        // property vs f64 on random windows (exact integer compare vs a float reference away from the edge)
        let mut x: u128 = 0xDEAD_BEEF_0123_4567_89AB_CDEF_FEED_FACE;
        for _ in 0..5_000 {
            let cls_min = (rnd(&mut x) >> 60).max(1);
            let cls_max = cls_min + (rnd(&mut x) >> 62);
            let usd_min = (rnd(&mut x) >> 50).max(1);
            let usd_max = usd_min + (rnd(&mut x) >> 52);
            let win = w(usd_min, usd_max, cls_min, cls_max);
            let cls = (rnd(&mut x) >> 60).max(1);
            let usd = (rnd(&mut x) >> 50).max(1);
            let f = usd as f64 / cls as f64;
            let (hi, lo) = (usd_max as f64 / cls_min as f64 * 1.1, usd_min as f64 / cls_max as f64 / 1.1);
            if (f / hi - 1.0).abs() > 1e-9 && (f / lo - 1.0).abs() > 1e-9 {
                assert_eq!(factor_in_collar(usd, cls, &win), f <= hi && f >= lo, "{usd} {cls} {win:?}");
            }
        }
        // overflow fails closed (outside)
        assert!(!le_scaled(u128::MAX, u128::MAX, 11, 1, 1, 10));
        assert_eq!(mul256(u128::MAX, u128::MAX), (u128::MAX - 1, 1));
    }

    /// mul_e18 == math::mul_up / mul_down on random and edge values (incl. products above 2^128).
    #[test]
    fn mul_e18_equals_the_math_helpers_property() {
        let mut x: u128 = 0x0F1E_2D3C_4B5A_6978_8796_A5B4_C3D2_E1F0;
        let edges = [0u128, 1, E18 - 1, E18, E18 + 1, u64::MAX as u128, 1 << 100, (1 << 127) + 5, u128::MAX - 1, u128::MAX, 340_282_366_920_938_463_463u128 * E18];
        for &a in &edges {
            for &b in &edges {
                assert_eq!(mul_e18(a, b, true), super::super::math::mul_up(a, b), "up {a} {b}");
                assert_eq!(mul_e18(a, b, false), super::super::math::mul_down(a, b), "down {a} {b}");
            }
        }
        for _ in 0..20_000 {
            let a = rnd(&mut x) >> (rnd(&mut x) % 128);
            let b = rnd(&mut x) >> (rnd(&mut x) % 128);
            assert_eq!(mul_e18(a, b, true), super::super::math::mul_up(a, b), "up {a} {b}");
            assert_eq!(mul_e18(a, b, false), super::super::math::mul_down(a, b), "down {a} {b}");
        }
    }

    /// factor_ok (u128 fast path + 256-bit fallback) == factor_in_collar (256-bit), incl. overflowing products.
    #[test]
    fn factor_ok_equals_the_exact_collar_property() {
        let mut x: u128 = 0x1357_9BDF_2468_ACE0_FDB9_7531_0ECA_8642;
        for i in 0..20_000 {
            let s = |x: &mut u128| rnd(x) >> (rnd(x) % 100);
            let w = Window { entries: 2, usd_min: s(&mut x).max(1), usd_max: 0, cls_min: s(&mut x).max(1), cls_max: 0, sol_min: 0 };
            let w = Window { usd_max: w.usd_min.saturating_add(s(&mut x)), cls_max: w.cls_min.saturating_add(s(&mut x)), ..w };
            let (usd, cls) = (s(&mut x).max(1), s(&mut x).max(1));
            assert_eq!(factor_ok(usd, cls, &w), factor_in_collar(usd, cls, &w), "{i}: {usd} {cls} {w:?}");
        }
        // an overflowing case decided by the 256-bit fallback
        let w = Window { entries: 1, usd_min: 1 << 100, usd_max: 1 << 100, cls_min: 1 << 100, cls_max: 1 << 100, sol_min: 0 };
        assert!(factor_ok(1 << 100, 1 << 100, &w) && !factor_ok(1 << 101, 1 << 100, &w) && !factor_ok(1 << 99, 1 << 100, &w));
    }

    #[test]
    fn the_anchor_band() {
        let a = 200 * E18;
        // band 25%: [150, 250]
        for (up, down, ok) in [(200u128, 200u128, true), (250, 150, true), (251, 200, false), (200, 149, false), (250, 250, true), (150, 150, true)] {
            assert_eq!(within_anchor(up * E18, down * E18, a), ok, "{up} {down}");
        }
        assert!(within_anchor(0, u128::MAX, a), "no rounding asked: nothing to judge");
        assert!(!within_anchor(u128::MAX, 200 * E18, a));
        assert!(!within_anchor(250 * E18 + 1, 200 * E18, a) && !within_anchor(200 * E18, 150 * E18 - 1, a));
    }

    #[test]
    fn the_wide_helpers_match_a_reference() {
        let mut x: u128 = 0x9E37_79B9_7F4A_7C15_F39C_C060_5CED_C834;
        for _ in 0..5_000 {
            let a = rnd(&mut x) >> (rnd(&mut x) % 128);
            let b = (rnd(&mut x) >> (rnd(&mut x) % 128)).max(1);
            if a.leading_zeros() + b.leading_zeros() >= 128 {
                assert_eq!(mul_shr64(a, b), (a * b) >> 64, "{a} {b}");
            }
            if a >> 64 == 0 {
                assert_eq!(shl64_div(a, b), (a << 64) / b, "{a} {b}");
            } else {
                let res = shl64_div(a, b);
                if res != u128::MAX {
                    let (q, r) = (a / b, a % b);
                    assert_eq!(res >> 64, q);
                    let f = res & (u64::MAX as u128);
                    let lhs = (f as f64) * (b as f64);
                    let rhs = (r as f64) * 18446744073709551616.0;
                    assert!(lhs <= rhs * (1.0 + 1e-12) && rhs < (f as f64 + 1.0) * (b as f64) * (1.0 + 1e-12), "{a} {b}");
                }
            }
        }
        assert_eq!(frac64(1, 2), 1 << 63);
        assert_eq!(frac64(1, 3), u64::MAX as u128 / 3);
        assert_eq!(frac64(u128::MAX - 1, u128::MAX), u64::MAX as u128);
        assert_eq!(frac64(0, 7), 0);
    }
}
