//! The v3 bridge gap fee: the formula and the message codec, codec v3 ("v3c", docs/v3c-gap-spec.md).
//!
//! FROZEN with `src/v3/gap/GapMath.sol` and `script/gap/gap-math.mjs`; all three assert
//! `test/fixtures/gap-vectors.json` (the `evmOnly` vectors excepted: amounts above u64, prices above
//! u128). Pure: no accounts, no Anchor, never panics. Every rounding is toward the fee.

/// Version 3 (owner 2026-10-30): `priceClass` at 73, `psClassE18` at 74; Amendment 6: `srcGasMicroUsd`
/// (u32, the source's gas cover in micro-dollars) at 90 and `srcCoverCapCents` (u16) at 94, a 96-byte header.
/// Every other version byte is "not the gap codec", which the v3 receive REFUSES (GapBadVersion).
pub const VER: u8 = 0x03;
pub const SEND_TO_OFFSET: usize = 0;
pub const AMOUNT_SD_OFFSET: usize = 32;
pub const VER_OFFSET: usize = 40;
pub const PS_OFFSET: usize = 41;
pub const FEE_SRC_OFFSET: usize = 57;
pub const BRIDGE_FEE_OFFSET: usize = 61;
pub const MIN_CREDITED_OFFSET: usize = 65;
pub const PRICE_CLASS_OFFSET: usize = 73;
pub const PS_CLASS_OFFSET: usize = 74;
pub const SRC_GAS_MICRO_USD_OFFSET: usize = 90;
pub const SRC_COVER_CAP_OFFSET: usize = 94;
/// The fixed header; a gap-codec message longer than this is composed, its tail starting here.
pub const HEADER_LEN: usize = 96;

pub const PPM: u128 = 1_000_000;
pub const E18: u128 = 1_000_000_000_000_000_000;
pub const PRICE_MAX: u128 = u128::MAX;
/// Amendment 6 (AMENDMENT-6.md §2): the fixed margin, default 0.1%, hard cap 10% (lead decision 4).
pub const MARGIN_DEFAULT_PPM: u32 = 1_000;
pub const MARGIN_MAX_PPM: u32 = 100_000;
/// Amendment 6, Solana's gas cover: signature lamports of one swap tx / of the send tx, hard caps.
pub const SWAP_LAMPORTS_MAX: u32 = 100_000;
pub const SEND_LAMPORTS_MAX: u32 = 100_000;
/// The per-message cover cap is at most $200 on every chain (coordinator 2026-10-30; was $50).
pub const COVER_CAP_MAX_CENTS: u16 = 20_000;
pub const MICRO_USD_E18: u128 = 1_000_000_000_000;
pub const CENT_E18: u128 = 10_000_000_000_000_000;
/// The LayerZero cost term min(lzUsd, cost max) (USD 1e18): the default $20 (gap-math.mjs
/// COST_MAX_USD_E18); GapGlobal.cost_max_usd_e18 may set it (constants audit), at most $50.
pub const COST_MAX_USD_E18: u128 = 20 * E18;
pub const COST_MAX_CAP_USD_E18: u128 = 50 * E18;
pub const SOL_LAMPORTS: u128 = 1_000_000_000;
pub const U32_MAX: u128 = u32::MAX as u128;

pub const CHARGED: u8 = 0;
pub const NOT_V1: u8 = 1;
pub const PS_ZERO: u8 = 2;
pub const DST_NO_POOL: u8 = 3;
pub const DST_PRICE_FAILED: u8 = 4;
pub const DST_FEE_FAILED: u8 = 5;
pub const NO_GAP: u8 = 6;
pub const WITHIN_ALLOWANCE: u8 = 7;
/// The official pool's fee is not a flat base fee (a scheduler, a rate limiter, periods, or the
/// dynamic fee on). v3c: the receive reverts retriably with it (rule 4b) unless the escape is on.
pub const UNSUPPORTED_FEE_MODE: u8 = 8;
/// v3c: the store's admin escape is on: credited in full, fee 0.
pub const ESCAPED: u8 = 9;
/// v3c (4a): no official pool here yet and `to` is a listed seeder: credited in full, fee 0.
pub const SEED_NO_POOL: u8 = 10;
/// Amendment 2: an expired-compose refund (`return_expired_compose`): credited in full, fee 0.
pub const REFUND: u8 = 11;
/// Amendment 2: the refund marker's price class. Only `return_expired_compose` emits it (with both
/// prices 0); `set_gap_class` refuses it and no send carries it.
pub const REFUND_CLASS: u8 = 255;

/// Amendment 2: Some(true) for the refund marker (codec v3, class 255, psUsd = psClass = 0, not
/// composed: return_expired_compose never composes), Some(false) for any other class-255 message
/// -- a price, or a compose tail (audit I-1) -- refused (GapBadVersion), None otherwise.
pub fn refund_marker(h: &Header) -> Option<bool> {
    if !h.v1 || h.price_class != REFUND_CLASS {
        return None;
    }
    Some(h.ps_e18 == 0 && h.ps_class_e18 == 0 && !h.composed)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GapFee {
    pub withheld: u64,
    pub gap_ppm: u32,
    pub allow_ppm: u64,
    pub reason: u8,
}

/// a * b as (hi, lo).
fn mul_wide(a: u128, b: u128) -> (u128, u128) {
    const M: u128 = u64::MAX as u128;
    let (a1, a0) = (a >> 64, a & M);
    let (b1, b0) = (b >> 64, b & M);
    let p00 = a0 * b0;
    let p01 = a0 * b1;
    let p10 = a1 * b0;
    let p11 = a1 * b1;
    let mid = (p00 >> 64) + (p01 & M) + (p10 & M);
    let lo = (p00 & M) | (mid << 64);
    let hi = p11 + (p01 >> 64) + (p10 >> 64) + (mid >> 64);
    (hi, lo)
}

/// (hi, lo) / d as (quotient, remainder); None when the quotient does not fit u128 or d == 0.
fn div_wide(hi: u128, lo: u128, d: u128) -> Option<(u128, u128)> {
    if d == 0 || hi >= d {
        return None;
    }
    // exact fast path (compute): the dividend fits u128
    if hi == 0 {
        return Some((lo / d, lo % d));
    }
    let (mut q, mut r) = (0u128, hi);
    for i in (0..128).rev() {
        let carry = r >> 127;
        r = (r << 1) | ((lo >> i) & 1);
        q <<= 1;
        if carry == 1 || r >= d {
            r = r.wrapping_sub(d);
            q |= 1;
        }
    }
    Some((q, r))
}

/// GapMath.gapFee (v3c, owner 2026-10-30; Amendment 6's 8th input), for a u64 amount and u128
/// prices: the allowance valued at the SOURCE price, so the arb keeps at most about the margin (plus a
/// gas cover that never exceeds its real gas) at any gap.
///     t = floor(A * Ps / Pd);  K = (1e6 + feeSrc + margin + gasCover) * 1e6;  D = (1e6 - b) * (1e6 - feeDst)
///     credited = floor(t * K / D);  withheld = credited >= A ? 0 : A - credited
/// b = bridgeFeePpm (>= 1e6 counts as 0); feeDst >= 1e6 is DST_FEE_FAILED. allow_ppm (reported only)
/// = feeSrc + feeDst + margin + gasCover.
#[allow(clippy::too_many_arguments)]
pub fn gap_fee(amount_ld: u64, ps_e18: u128, pd_e18: u128, fee_src_ppm: u32, fee_dst_ppm: u32, bridge_fee_ppm: u32, margin_ppm: u32, gas_cover_ppm: u32) -> GapFee {
    let allow_ppm = fee_src_ppm as u64 + fee_dst_ppm as u64 + margin_ppm as u64 + gas_cover_ppm as u64;
    let out = |withheld, gap_ppm, reason| GapFee { withheld, gap_ppm, allow_ppm, reason };
    if ps_e18 == 0 {
        return out(0, 0, PS_ZERO);
    }
    if pd_e18 == 0 {
        return out(0, 0, DST_PRICE_FAILED);
    }
    if fee_dst_ppm as u128 >= PPM {
        return out(0, 0, DST_FEE_FAILED);
    }
    if pd_e18 <= ps_e18 {
        return out(0, 0, NO_GAP);
    }
    // floor((Pd - Ps) * 1e6 / Pd) == 1e6 - ceil(Ps * 1e6 / Pd); Ps < Pd so the quotient is < 1e6.
    let (hi, lo) = mul_wide(ps_e18, PPM);
    let (q, r) = match div_wide(hi, lo, pd_e18) {
        Some(v) => v,
        None => return out(0, 0, DST_PRICE_FAILED), // unreachable for Ps < Pd
    };
    let gap_ppm = (PPM - (q + (r != 0) as u128)) as u32;
    // t = floor(A * Ps / Pd) < A <= u64::MAX (Ps < Pd): div_wide never fails here.
    let (hi, lo) = mul_wide(amount_ld as u128, ps_e18);
    let t = match div_wide(hi, lo, pd_e18) {
        Some((t, _)) => t,
        None => return out(0, 0, DST_PRICE_FAILED), // unreachable for Ps < Pd
    };
    let b = if (bridge_fee_ppm as u128) < PPM { bridge_fee_ppm as u128 } else { 0 };
    // K < (1e6 + 3 * 2^32) * 1e6 < 2^54 and t < 2^64: t * K < 2^118.
    let k = (PPM + fee_src_ppm as u128 + margin_ppm as u128 + gas_cover_ppm as u128) * PPM;
    let d = (PPM - b) * (PPM - fee_dst_ppm as u128);
    let credited = t * k / d;
    if credited >= amount_ld as u128 {
        return out(0, gap_ppm, WITHIN_ALLOWANCE);
    }
    out(amount_ld - credited as u64, gap_ppm, CHARGED)
}

/// GapMath.costPpm (v3c §2, Amendment 6: the static gas allowance is gone): the LayerZero cost as
/// ppm of the gross amount, the part of feeSrcPpm above the source pool's fee. costUsd =
/// min(lzUsd, cost_max). Every step floors. `native_fee` is the LayerZero fee for the store's
/// ENFORCED options only (lamports on Solana, native_decimals 9). usd_per_native 0 counts it as 0.
/// `cost_max_usd_e18` is the admin's cost max (COST_MAX_USD_E18 = $20 by default, at most $50).
#[allow(clippy::too_many_arguments)]
pub fn cost_ppm(native_fee: u128, native_decimals: u8, usd_per_native_e18: u128, ps_e18: u128, token_decimals: u8, amount_ld: u64, bridge_fee_ppm: u32, cost_max_usd_e18: u128) -> u32 {
    if ps_e18 == 0 || amount_ld == 0 {
        return 0;
    }
    let mut lz_usd = 0u128;
    if usd_per_native_e18 != 0 && native_fee != 0 && native_decimals <= 36 {
        let (hi, lo) = mul_wide(native_fee, usd_per_native_e18);
        lz_usd = match div_wide(hi, lo, 10u128.pow(native_decimals as u32)) {
            Some((q, _)) => q,
            None => cost_max_usd_e18,
        };
    }
    let cost = lz_usd.min(cost_max_usd_e18);
    if cost == 0 || token_decimals > 36 {
        return 0;
    }
    // cost <= 50e18, 10^dec <= 1e36: the product fits 2^256; the quotient may not fit u128 (tiny Ps).
    let (hi, lo) = mul_wide(cost, 10u128.pow(token_decimals as u32));
    let cost_ld = match div_wide(hi, lo, ps_e18) {
        Some((q, _)) => q,
        None => return PPM as u32,
    };
    let den = if (bridge_fee_ppm as u128) < PPM { PPM - bridge_fee_ppm as u128 } else { PPM };
    let (hi, lo) = mul_wide(cost_ld, den);
    match div_wide(hi, lo, amount_ld as u128) {
        Some((v, _)) if v < PPM => v as u32,
        _ => PPM as u32,
    }
}

/// Which price pair the destination compares (v3c §2): the class pair when both quotes have the
/// same non-zero class and both class prices are known, else the USD pair; None = nothing
/// comparable (the receive reverts, GapUnreadable). Returns (ps, pd, is_class).
pub fn pick_pair(msg_class: u8, ps_class_e18: u128, ps_usd_e18: u128, dst_class: u8, pd_class_e18: u128, pd_usd_e18: u128) -> Option<(u128, u128, bool)> {
    if msg_class != 0 && msg_class == dst_class && ps_class_e18 != 0 && pd_class_e18 != 0 {
        return Some((ps_class_e18, pd_class_e18, true));
    }
    if ps_usd_e18 != 0 && pd_usd_e18 != 0 {
        return Some((ps_usd_e18, pd_usd_e18, false));
    }
    None
}

/// ceil(cliff_fee_numerator / 1000); None above 1e9 (a fee read failure).
pub fn solana_pool_fee_ppm(cliff_fee_numerator: u64) -> Option<u32> {
    if cliff_fee_numerator > 1_000_000_000 {
        return None;
    }
    Some(cliff_fee_numerator.div_ceil(1000) as u32)
}

/// ceil(a * b / 1e18); 0 (failure) for a zero factor or a product above PRICE_MAX.
pub fn mul_up(a: u128, b: u128) -> u128 {
    if a == 0 || b == 0 {
        return 0;
    }
    let (hi, lo) = mul_wide(a, b);
    match div_wide(hi, lo, E18) {
        Some((q, r)) if r == 0 => q,
        Some((q, _)) if q < PRICE_MAX => q + 1,
        _ => 0,
    }
}

/// floor(a * b / 1e18); 0 (failure) for a zero factor or a zero product; clamped to PRICE_MAX.
pub fn mul_down(a: u128, b: u128) -> u128 {
    if a == 0 || b == 0 {
        return 0;
    }
    let (hi, lo) = mul_wide(a, b);
    match div_wide(hi, lo, E18) {
        Some((q, _)) => q,
        None => PRICE_MAX,
    }
}

/// A reader's floor as a source factor: p + 1; 0 when p is 0 or PRICE_MAX.
pub fn src_factor(p: u128) -> u128 {
    if p == 0 || p == PRICE_MAX {
        0
    } else {
        p + 1
    }
}

/// floor(sqrt(n)).
pub fn isqrt(n: u128) -> u128 {
    if n < 2 {
        return n;
    }
    if n <= u64::MAX as u128 {
        // the same Newton walk in native 64-bit arithmetic (SBF has no 128-bit divide)
        let n = n as u64;
        let bits = 64 - n.leading_zeros();
        let mut x: u64 = 1u64 << bits.div_ceil(2).min(63);
        loop {
            let y = (x + n / x) >> 1;
            if y >= x {
                return x as u128;
            }
            x = y;
        }
    }
    // Newton from a power of two at or above the root: never overshoots after the first step
    let bits = 128 - n.leading_zeros();
    let mut x: u128 = 1u128 << bits.div_ceil(2).min(127);
    loop {
        let y = (x + n / x) >> 1;
        if y >= x {
            return x;
        }
        x = y;
    }
}

// ------------------------------------------------------------------ Amendment 6: the gas cover

/// gap-math.mjs `checkMargin`: false (MarginTooHigh) above MARGIN_MAX_PPM.
pub fn check_margin(margin_ppm: u32) -> bool {
    margin_ppm <= MARGIN_MAX_PPM
}

/// gap-math.mjs `checkSolanaGasCover`: false (BadGasCover) when a lamport figure or the cap is
/// above its hard cap.
pub fn check_solana_gas_cover(swap_lamports: u32, send_lamports: u32, cover_cap_cents: u16) -> bool {
    swap_lamports <= SWAP_LAMPORTS_MAX && send_lamports <= SEND_LAMPORTS_MAX && cover_cap_cents <= COVER_CAP_MAX_CENTS
}

/// gap-math.mjs `solanaGasUsdE18`: floor(lamports * solUsd / 1e9) (USD 1e18); 0 lamports -> Some(0)
/// with no price read; SOL/USD 0 (unreadable) -> None. lamports < 2^64 and solUsd < 2^128 keep the
/// quotient below 2^128 (it is < 2^64 * 2^128 / 2^29).
pub fn solana_gas_usd_e18(lamports: u64, sol_usd_e18: impl FnOnce() -> u128) -> Option<u128> {
    if lamports == 0 {
        return Some(0);
    }
    let sol = sol_usd_e18();
    if sol == 0 {
        return None;
    }
    let (hi, lo) = mul_wide(lamports as u128, sol);
    div_wide(hi, lo, SOL_LAMPORTS).map(|(q, _)| q)
}

/// oft-q7 (owner Q7), gap-math.mjs `deliveryChargeLd`: the destination's delivery cost in token LD,
/// withheld from a price-path arrival our keys deliver. usd = floor(lamports x solUsd / 1e9)
/// (`solana_gas_usd_e18`, the window's SOL/USD minimum, the cover's read); LD = ceil(usd x
/// 10^tokenDecimals / usdPerToken) with usdPerToken the header's psUsd (else the destination's Pd
/// USD); at most `cap_ld` (what the arrival still credits). Some(0) for 0 lamports (nothing read);
/// None (the receive holds, DST_PRICE_FAILED) when SOL/USD or the token's USD price is 0 or
/// tokenDecimals > 36.
pub fn delivery_charge_ld(lamports: u32, sol_usd_e18: impl FnOnce() -> u128, usd_per_token_e18: u128, token_decimals: u8, cap_ld: u64) -> Option<u64> {
    if lamports == 0 {
        return Some(0);
    }
    let usd = solana_gas_usd_e18(lamports as u64, sol_usd_e18)?;
    if usd_per_token_e18 == 0 || token_decimals > 36 {
        return None;
    }
    let (hi, lo) = mul_wide(usd, 10u128.pow(token_decimals as u32));
    let (qh, ql) = div_ceil_wide(hi, lo, usd_per_token_e18);
    if qh != 0 || ql > cap_ld as u128 {
        return Some(cap_ld);
    }
    Some(ql as u64)
}

/// gap-math.mjs `coverWindowIndex` (Solana): w = floor(slot / W); W 0 counts as 1 (never: W is
/// 3..=1500 by the setter, and a 0 reads as the default before that).
pub fn cover_window_index(slot: u64, window_slots: u64) -> u64 {
    slot / window_slots.max(1)
}

/// The SOURCE's header fields (@90 srcGasMicroUsd, @94 srcCoverCapCents), gap-math.mjs
/// `sourceGasFields` for a Solana source; `carried` = the send must record the window's cover.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SourceGas {
    pub src_gas_micro_usd: u32,
    pub src_cover_cap_cents: u16,
    pub gas_usd_e18: u128,
    pub carried: bool,
}

/// Amendment 6 §3 (Solana): capC = min(cover_cap_cents, 20,000); capC 0 or not granted -> (0, 0),
/// nothing read, not carried. Else gasUsd = floor((swap + send lamports) * solUsd / 1e9) with solUsd
/// the PriceLog window SOL/USD minimum (read only when the lamports are non-zero); unreadable ->
/// None (the send refuses GapSourceUnreadable, nothing written). srcGasMicroUsd = min(floor(gasUsd /
/// 1e12), capC * 1e4).
pub fn source_gas_fields(cover_cap_cents: u16, granted: bool, swap_lamports: u32, send_lamports: u32, sol_usd_e18: impl FnOnce() -> u128) -> Option<SourceGas> {
    let cap = cover_cap_cents.min(COVER_CAP_MAX_CENTS);
    if cap == 0 || !granted {
        return Some(SourceGas::default());
    }
    let gas = solana_gas_usd_e18(swap_lamports as u64 + send_lamports as u64, sol_usd_e18)?;
    let micro = (gas / MICRO_USD_E18).min(cap as u128 * 10_000) as u32;
    Some(SourceGas { src_gas_micro_usd: micro, src_cover_cap_cents: cap, gas_usd_e18: gas, carried: true })
}

/// gap-math.mjs `gasCoverPpm`: (coverPpm, coverUsd). capUsd = min(srcCap, dstCap, 20,000) cents;
/// coverUsd = min(srcGasMicroUsd * 1e12 + dstGasUsd, capUsd); coverLD = floor(coverUsd *
/// 10^tokenDecimals / psUsd); coverPpm = min(2^32 - 1, floor(coverLD * (1e6 - b') / amountLD)).
/// 0 when coverUsd, psUsd or amountLD is 0, or tokenDecimals > 36. Every step floors.
#[allow(clippy::too_many_arguments)]
pub fn gas_cover_ppm(src_gas_micro_usd: u32, src_cover_cap_cents: u16, dst_gas_usd_e18: u128, dst_cover_cap_cents: u16, ps_usd_e18: u128, token_decimals: u8, amount_ld: u64, bridge_fee_ppm: u32) -> (u32, u128) {
    let cap = src_cover_cap_cents.min(dst_cover_cap_cents).min(COVER_CAP_MAX_CENTS) as u128;
    let cover = (src_gas_micro_usd as u128 * MICRO_USD_E18).saturating_add(dst_gas_usd_e18).min(cap * CENT_E18);
    if cover == 0 || ps_usd_e18 == 0 || amount_ld == 0 || token_decimals > 36 {
        return (0, 0);
    }
    let (hi, lo) = mul_wide(cover, 10u128.pow(token_decimals as u32));
    let den = if (bridge_fee_ppm as u128) < PPM { PPM - bridge_fee_ppm as u128 } else { PPM };
    let ppm = match div_wide(hi, lo, ps_usd_e18) {
        // coverLD above 2^128: coverLD * den / amount > 2^128 / 2^64 > 2^32
        None => U32_MAX,
        Some((cover_ld, _)) => {
            let (hi, lo) = mul_wide(cover_ld, den);
            match div_wide(hi, lo, amount_ld as u128) {
                Some((v, _)) => v.min(U32_MAX),
                None => U32_MAX,
            }
        }
    };
    (ppm as u32, cover)
}

/// gap-math.mjs `coverGrant`: a send may carry a cover unless its route's last covered window is
/// this one (`last_p1` = that window's index + 1, 0 = never covered).
pub fn cover_granted(last_p1: u64, window_index: u64) -> bool {
    last_p1 != window_index.saturating_add(1)
}

/// The destination's priced step (gap-math.mjs `gapPriced`, Amendment 6 §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Priced {
    /// The receive must hold (retriable; reason DST_PRICE_FAILED): its own gas price was needed and unreadable.
    pub holds: bool,
    pub fee: GapFee,
    pub cover_ppm: u32,
    pub cover_usd_e18: u128,
    pub dst_gas_usd_e18: u128,
}

/// 1. r0 = gap_fee(.., margin, cover 0); NO_GAP / WITHIN_ALLOWANCE (any reason but CHARGED) -> r0,
///    nothing read. 2. srcCoverCapCents 0 -> r0 (the destination adds its swap gas ONLY when the
///    source granted a cover, lead decision 1). capC = min(src, dst, 20,000) 0 -> r0, nothing read.
/// 3. dstGas = `dst_gas_usd_e18()`, called only here (Solana: `solana_gas_usd_e18(swap_lamports,
///    the PriceLog window SOL/USD minimum)`, which reads the price only for non-zero lamports);
///    None (unreadable) -> holds. 4. r = gap_fee(.., margin, coverPpm) with coverPpm at the HEADER's
///    psUsd.
#[allow(clippy::too_many_arguments)]
pub fn gap_priced(amount_ld: u64, ps_e18: u128, pd_e18: u128, ps_usd_e18: u128, fee_src_ppm: u32, fee_dst_ppm: u32, bridge_fee_ppm: u32, margin_ppm: u32, token_decimals: u8, src_gas_micro_usd: u32, src_cover_cap_cents: u16, dst_cover_cap_cents: u16, dst_gas_usd_e18: impl FnOnce() -> Option<u128>) -> Priced {
    let r0 = gap_fee(amount_ld, ps_e18, pd_e18, fee_src_ppm, fee_dst_ppm, bridge_fee_ppm, margin_ppm, 0);
    let plain = Priced { holds: false, fee: r0, cover_ppm: 0, cover_usd_e18: 0, dst_gas_usd_e18: 0 };
    if r0.reason != CHARGED || src_cover_cap_cents == 0 {
        return plain;
    }
    if src_cover_cap_cents.min(dst_cover_cap_cents).min(COVER_CAP_MAX_CENTS) == 0 {
        return plain;
    }
    let Some(dst_gas) = dst_gas_usd_e18() else {
        let held = GapFee { withheld: 0, gap_ppm: 0, allow_ppm: 0, reason: DST_PRICE_FAILED };
        return Priced { holds: true, fee: held, cover_ppm: 0, cover_usd_e18: 0, dst_gas_usd_e18: 0 };
    };
    let (cover_ppm, cover_usd) = gas_cover_ppm(src_gas_micro_usd, src_cover_cap_cents, dst_gas, dst_cover_cap_cents, ps_usd_e18, token_decimals, amount_ld, bridge_fee_ppm);
    let fee = gap_fee(amount_ld, ps_e18, pd_e18, fee_src_ppm, fee_dst_ppm, bridge_fee_ppm, margin_ppm, cover_ppm);
    Priced { holds: false, fee, cover_ppm, cover_usd_e18: cover_usd, dst_gas_usd_e18: dst_gas }
}

/// ceil((hi, lo) / d) as (hi, lo), d > 0.
fn div_ceil_wide(hi: u128, lo: u128, d: u128) -> (u128, u128) {
    let (qh, rh) = (hi / d, hi % d);
    // rh < d, so the low quotient fits
    let (ql, r) = div_wide(rh, lo, d).unwrap_or((u128::MAX, 0));
    if r == 0 {
        (qh, ql)
    } else if ql == u128::MAX {
        (qh + 1, 0)
    } else {
        (qh, ql + 1)
    }
}

/// Amendment 5, Solana: a DAMM v2 pool's LOCKED quote depth in whole USD, rounded UP, saturating at
/// u32; 0 = unreadable (the destination holds). `locked_l` is the pool's `permanent_lock_liquidity`
/// (Q64 liquidity units), valued at a flash-proof price -- never the live sqrt price:
/// `usd_e18` (USD per whole token) and `quote_e18` (whole quote per whole token), each the side's
/// PriceLog window price (the source its Ps minimum, the destination its Pd maximum).
///
/// The quote side's virtual reserve at a raw price P (raw quote per raw token) is L * sqrt(P) / 2^64
/// raw quote (cp-amm: amount_b = L * sqrt_p >> 128 with sqrt_p = sqrt(P) * 2^64; the same for the
/// quote as token A with 1/sqrt_p). With P = quote_e18 / 1e18 * 10^(qd - td) and USD per whole quote
/// usd_e18 / quote_e18 it is, in whole USD,
///     D = L * usd_e18 / (2^64 * 1e9 * sqrt(quote_e18) * 10^((qd + td) / 2))
/// computed as successive ceiling divisions by 2^64, 1e9, 10^floor((qd + td) / 2) and
/// isqrt(quote_e18 * 10^((qd + td) mod 2)) (the root floors, so D only rounds up).
///
/// Audit r1 I-1: D's inputs are the stored window extremes; their rounding may move D by <= 1
/// dollar at a ceil boundary, accepted 2026-10-30, lead. (The destination passes Pd rounded down,
/// the source its Ps and pool price rounded up; the ring keeps one rounding per extreme.)
pub fn locked_depth_dollars_up(locked_l: u128, usd_e18: u128, quote_e18: u128, quote_decimals: u8, token_decimals: u8) -> u32 {
    if locked_l == 0 || usd_e18 == 0 || quote_e18 == 0 || quote_decimals > 18 || token_decimals > 18 {
        return 0;
    }
    let e = quote_decimals as u32 + token_decimals as u32;
    let radicand = if e % 2 == 1 {
        match quote_e18.checked_mul(10) {
            Some(v) => v,
            None => return 0,
        }
    } else {
        quote_e18
    };
    let root = isqrt(radicand);
    if root == 0 {
        return 0;
    }
    let (hi0, lo0) = mul_wide(locked_l, usd_e18);
    // ceil(/ 2^64) is a shift: (hi, lo) >> 64, plus one when the low 64 bits are not all 0
    let (mut hi, mut lo) = (hi0 >> 64, (hi0 << 64) | (lo0 >> 64));
    if lo0 as u64 != 0 {
        let (l, c) = lo.overflowing_add(1);
        lo = l;
        hi += c as u128;
    }
    for d in [1_000_000_000, 10u128.pow(e / 2), root] {
        (hi, lo) = div_ceil_wide(hi, lo, d);
    }
    if hi != 0 || lo > u32::MAX as u128 {
        u32::MAX
    } else {
        lo as u32
    }
}

/// A send's value in micro-dollars (USD 1e6), rounded UP, saturating at u64: the PriceLog
/// capacity unit. amount_ld * ps_usd_e18 / 10^token_decimals / 1e12.
pub fn usd_micro_up(amount_ld: u64, ps_usd_e18: u128, token_decimals: u8) -> u64 {
    if amount_ld == 0 || ps_usd_e18 == 0 || token_decimals > 36 {
        return 0;
    }
    let (mut hi, mut lo) = mul_wide(amount_ld as u128, ps_usd_e18);
    for d in [10u128.pow(token_decimals.min(36) as u32), 1_000_000_000_000] {
        (hi, lo) = div_ceil_wide(hi, lo, d);
    }
    if hi != 0 || lo > u64::MAX as u128 {
        u64::MAX
    } else {
        lo as u64
    }
}

/// (hi, lo) * m, None when it does not fit 256 bits.
fn mul_wide_small(hi: u128, lo: u128, m: u128) -> Option<(u128, u128)> {
    let (h1, l1) = mul_wide(lo, m);
    let h = hi.checked_mul(m)?.checked_add(h1)?;
    Some((h, l1))
}

/// Owner (B), docs/v3c-gap-spec.md §8.2: the capacity a send or receive of `amount_ld` needs at the
/// running quote price `quote_e18` (whole quote per whole token), in pico (1e-12) of the pool's
/// locked depth, rounded UP (toward the fee), saturating at u64::MAX (never satisfiable).
///
/// It is need_usd / D_usd with need_usd = amount * Pusd / 10^td and D_usd the locked depth of
/// `locked_depth_dollars_up` at the same price. The quote's USD rate is in both, so it cancels:
///     f = amount * 2^64 * sqrt(q') * 10^X / L,   X = 3 + floor((qd + td) / 2) - td
/// with q' = quote_e18 * 10^((qd + td) mod 2), computed exactly as:
///     r  = isqrt(q'), plus 1 when r * r < q' (the root rounds UP)
///     N  = (amount << 64) * r                       (256-bit)
///     X >= 0: N = N * 10^X  (overflow -> u64::MAX), then f = ceil(N / L)
///     X <  0: f = ceil(ceil(N / L) / 10^-X)
///     f above u64::MAX -> u64::MAX
/// 0 for amount 0; u64::MAX when L, q or a decimals value (> 18) is unusable.
/// The parts of `capacity_need_pico` that do not depend on the price, for a cheap test per entry:
/// f(q) <= free  <=>  free * den >= a * r(q)  (f = ceil(a * r / den), free an integer), with
/// a = (amount << 64) * 10^X and den = L for X >= 0, a = amount << 64 and den = L * 10^-X for X < 0.
/// None when nothing is ever enough (L 0, decimals > 18, a overflowing 256 bits).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NeedRatio {
    a: (u128, u128),
    den: (u128, u128),
    odd: bool,
    zero: bool,
}

pub fn need_ratio(amount_ld: u64, locked_l: u128, quote_decimals: u8, token_decimals: u8) -> Option<NeedRatio> {
    if amount_ld == 0 {
        return Some(NeedRatio { a: (0, 0), den: (0, 1), odd: false, zero: true });
    }
    if locked_l == 0 || quote_decimals > 18 || token_decimals > 18 {
        return None;
    }
    let e = quote_decimals as i32 + token_decimals as i32;
    let x = 3 + e / 2 - token_decimals as i32;
    let base = (0u128, (amount_ld as u128) << 64);
    let (a, den) = if x >= 0 {
        (mul_wide_small(base.0, base.1, 10u128.pow(x as u32))?, (0, locked_l))
    } else {
        (base, mul_wide(locked_l, 10u128.pow((-x) as u32)))
    };
    Some(NeedRatio { a, den, odd: e % 2 == 1, zero: false })
}

/// ceil(sqrt(q')) with q' = quote_e18 * 10^((qd + td) mod 2); None when q' overflows or q is 0.
pub fn need_root(r: &NeedRatio, quote_e18: u128) -> Option<u128> {
    if quote_e18 == 0 {
        return None;
    }
    let q = if r.odd { quote_e18.checked_mul(10)? } else { quote_e18 };
    let s = isqrt(q);
    Some(if s.checked_mul(s).map_or(true, |v| v < q) { s + 1 } else { s })
}

/// Whether `free` pico of capacity meets the need at root `root` (`need_root`): exactly
/// `free >= capacity_need_pico(..)` for every free below u64::MAX.
pub fn need_met(r: &NeedRatio, root: u128, free: u64) -> bool {
    if r.zero {
        return true;
    }
    if free == u64::MAX {
        return false;
    }
    let Some(n) = mul_wide_small(r.a.0, r.a.1, root) else { return false };
    // unreachable (lead #4: den * free < 2^212 for every input, see
    // tests::need_met_den_times_free_never_overflows); were it ever reached, the need counts as
    // NOT met (the send refuses / the receive holds): toward the fee, never an over-credit
    let Some(have) = mul_wide_small(r.den.0, r.den.1, free as u128) else { return false };
    have >= n
}

pub fn capacity_need_pico(amount_ld: u64, quote_e18: u128, locked_l: u128, quote_decimals: u8, token_decimals: u8) -> u64 {
    if amount_ld == 0 {
        return 0;
    }
    if locked_l == 0 || quote_e18 == 0 || quote_decimals > 18 || token_decimals > 18 {
        return u64::MAX;
    }
    let e = quote_decimals as i32 + token_decimals as i32;
    let q = if e % 2 == 1 {
        match quote_e18.checked_mul(10) {
            Some(v) => v,
            None => return u64::MAX,
        }
    } else {
        quote_e18
    };
    let mut r = isqrt(q);
    if r.checked_mul(r).map_or(true, |s| s < q) {
        r += 1;
    }
    let (mut hi, mut lo) = mul_wide((amount_ld as u128) << 64, r);
    let x = 3 + e / 2 - token_decimals as i32;
    if x >= 0 {
        match mul_wide_small(hi, lo, 10u128.pow(x as u32)) {
            Some((h, l)) => (hi, lo) = (h, l),
            None => return u64::MAX,
        }
        (hi, lo) = div_ceil_wide(hi, lo, locked_l);
    } else {
        (hi, lo) = div_ceil_wide(hi, lo, locked_l);
        (hi, lo) = div_ceil_wide(hi, lo, 10u128.pow((-x) as u32));
    }
    if hi != 0 || lo > u64::MAX as u128 {
        u64::MAX
    } else {
        lo as u64
    }
}

/// A PriceLog entry's capacity in micro-dollars: k_ppm of the locked depth (whole dollars), i.e.
/// depth_usd * k_ppm micro-dollars.
pub fn entry_capacity_micro(depth_usd: u32, k_ppm: u32) -> u64 {
    depth_usd as u64 * k_ppm as u64
}

/// GapMath.costClassPpm (gap-math.mjs): the bridge cost of a CLASS-ONLY send (psUsd 0, psClass
/// known). Class 1: cost_ppm at Ps = psClass. The native coin's class: the native 1:1, capped at the
/// cost max ($20 by default) of it; usd_per_native 0 -> 0. Any other class (0, 255, another) -> 0.
/// Amendment 6: a send requires psUsd, so no Solana send reaches this; kept with its vectors.
#[allow(clippy::too_many_arguments)]
pub fn cost_class_ppm(price_class: u8, native_class: u8, native_fee: u128, native_decimals: u8, usd_per_native_e18: u128, ps_class_e18: u128, token_decimals: u8, amount_ld: u64, bridge_fee_ppm: u32, cost_max_usd_e18: u128) -> u32 {
    if price_class == 1 {
        return cost_ppm(native_fee, native_decimals, usd_per_native_e18, ps_class_e18, token_decimals, amount_ld, bridge_fee_ppm, cost_max_usd_e18);
    }
    if price_class == 0 || price_class == 255 || price_class != native_class {
        return 0;
    }
    if ps_class_e18 == 0 || amount_ld == 0 || native_fee == 0 || usd_per_native_e18 == 0 || native_decimals > 36 || token_decimals > 36 {
        return 0;
    }
    // cap = floor(cost_max * 1e18 / usd)
    let (hi, lo) = mul_wide(cost_max_usd_e18, E18);
    let cap = match div_wide(hi, lo, usd_per_native_e18) {
        Some((q, _)) => q,
        None => u128::MAX,
    };
    let (hi, lo) = mul_wide(native_fee, E18);
    let mut cost = match div_wide(hi, lo, 10u128.pow(native_decimals as u32)) {
        Some((q, _)) => q,
        None => cap,
    };
    if cost > cap {
        cost = cap;
    }
    if cost == 0 {
        return 0;
    }
    let (hi, lo) = mul_wide(cost, 10u128.pow(token_decimals as u32));
    let cost_ld = match div_wide(hi, lo, ps_class_e18) {
        Some((q, _)) => q,
        None => return PPM as u32,
    };
    if cost_ld / amount_ld as u128 >= PPM {
        return PPM as u32;
    }
    let den = if (bridge_fee_ppm as u128) < PPM { PPM - bridge_fee_ppm as u128 } else { PPM };
    let (hi, lo) = mul_wide(cost_ld, den);
    match div_wide(hi, lo, amount_ld as u128) {
        Some((v, _)) if v < PPM => v as u32,
        _ => PPM as u32,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub send_to: [u8; 32],
    pub amount_sd: u64,
    /// true only for a full version-3 header ("the gap codec"); false is refused by the v3 receive.
    pub v1: bool,
    /// psUsdE18: the source's USD price per whole token (0 = unreadable).
    pub ps_e18: u128,
    /// The source pool fee plus the bridge cost (cost_ppm).
    pub fee_src_ppm: u32,
    pub bridge_fee_ppm: u32,
    /// The sender's least credited amount, in shared decimals; 0 = none.
    pub min_credited_sd: u64,
    pub price_class: u8,
    pub ps_class_e18: u128,
    /// Amendment 6: the source's gas cover (its send + one swap), micro-dollars (0 = none).
    pub src_gas_micro_usd: u32,
    /// Amendment 6: the source's cover cap, cents (0 = the source granted no cover).
    pub src_cover_cap_cents: u16,
    pub composed: bool,
}

/// The gap-codec message (version 3). `compose` is `(composeFrom, composeMsg)`; an empty
/// composeMsg is not composed.
#[allow(clippy::too_many_arguments)]
pub fn encode(send_to: [u8; 32], amount_sd: u64, ps_e18: u128, fee_src_ppm: u32, bridge_fee_ppm: u32, min_credited_sd: u64, price_class: u8, ps_class_e18: u128, src_gas_micro_usd: u32, src_cover_cap_cents: u16, compose: Option<([u8; 32], &[u8])>) -> Vec<u8> {
    let compose = compose.filter(|(_, m)| !m.is_empty());
    let mut v = Vec::with_capacity(HEADER_LEN + compose.map_or(0, |(_, m)| 32 + m.len()));
    v.extend_from_slice(&send_to);
    v.extend_from_slice(&amount_sd.to_be_bytes());
    v.push(VER);
    v.extend_from_slice(&ps_e18.to_be_bytes());
    v.extend_from_slice(&fee_src_ppm.to_be_bytes());
    v.extend_from_slice(&bridge_fee_ppm.to_be_bytes());
    v.extend_from_slice(&min_credited_sd.to_be_bytes());
    v.push(price_class);
    v.extend_from_slice(&ps_class_e18.to_be_bytes());
    v.extend_from_slice(&src_gas_micro_usd.to_be_bytes());
    v.extend_from_slice(&src_cover_cap_cents.to_be_bytes());
    if let Some((from, msg)) = compose {
        v.extend_from_slice(&from);
        v.extend_from_slice(msg);
    }
    v
}

/// None only below 40 bytes (the receive then fails: nothing to credit).
pub fn decode(m: &[u8]) -> Option<Header> {
    if m.len() < VER_OFFSET {
        return None;
    }
    let mut send_to = [0u8; 32];
    send_to.copy_from_slice(&m[SEND_TO_OFFSET..AMOUNT_SD_OFFSET]);
    let mut h = Header {
        send_to,
        amount_sd: u64::from_be_bytes(m[AMOUNT_SD_OFFSET..VER_OFFSET].try_into().ok()?),
        v1: false,
        ps_e18: 0,
        fee_src_ppm: 0,
        bridge_fee_ppm: 0,
        min_credited_sd: 0,
        price_class: 0,
        ps_class_e18: 0,
        src_gas_micro_usd: 0,
        src_cover_cap_cents: 0,
        composed: false,
    };
    if m.len() < HEADER_LEN || m[VER_OFFSET] != VER {
        return Some(h);
    }
    h.v1 = true;
    h.ps_e18 = u128::from_be_bytes(m[PS_OFFSET..FEE_SRC_OFFSET].try_into().ok()?);
    h.fee_src_ppm = u32::from_be_bytes(m[FEE_SRC_OFFSET..BRIDGE_FEE_OFFSET].try_into().ok()?);
    h.bridge_fee_ppm = u32::from_be_bytes(m[BRIDGE_FEE_OFFSET..MIN_CREDITED_OFFSET].try_into().ok()?);
    h.min_credited_sd = u64::from_be_bytes(m[MIN_CREDITED_OFFSET..PRICE_CLASS_OFFSET].try_into().ok()?);
    h.price_class = m[PRICE_CLASS_OFFSET];
    h.ps_class_e18 = u128::from_be_bytes(m[PS_CLASS_OFFSET..SRC_GAS_MICRO_USD_OFFSET].try_into().ok()?);
    h.src_gas_micro_usd = u32::from_be_bytes(m[SRC_GAS_MICRO_USD_OFFSET..SRC_COVER_CAP_OFFSET].try_into().ok()?);
    h.src_cover_cap_cents = u16::from_be_bytes(m[SRC_COVER_CAP_OFFSET..HEADER_LEN].try_into().ok()?);
    h.composed = m.len() > HEADER_LEN;
    Some(h)
}

/// The receive's least-credited rule (spec §4, §6.2): true when it may credit -- no minimum, or
/// `credited >= min_credited_sd x rate` (the store's LD per SD). Otherwise the receive reverts,
/// retriable. Never overflows (u128).
pub fn credit_meets_min(credited_ld: u64, min_credited_sd: u64, rate: u64) -> bool {
    min_credited_sd == 0 || credited_ld as u128 >= min_credited_sd as u128 * rate as u128
}

/// `composeFrom | composeMsg`, passed on in the standard compose header with amount_ld = credited.
/// Empty unless the message is a composed gap-codec message.
pub fn compose_tail(m: &[u8]) -> &[u8] {
    match decode(m) {
        Some(h) if h.composed => &m[HEADER_LEN..],
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lead #4: need_met's overflow branch (`mul_wide_small(den, free)` = None) is unreachable from
    /// any instruction. den = L (X >= 0) or L x 10^-X (X < 0) with X = 3 + floor((qd + td) / 2) - td
    /// is least, -6, at qd 0 / td 18 (3 + 9 - 18), so den <= (2^128 - 1) x 10^6 < 2^148
    /// and den x free < 2^148 x 2^64 = 2^212 < 2^256, for EVERY decimals pair the program accepts
    /// (0..=18), every L (u128) and every free capacity (a u64). Checked over the whole domain's
    /// extremes; and at those extremes need_met agrees with capacity_need_pico (the exact need), so
    /// even the largest inputs neither over-credit nor fee-0.
    #[test]
    fn need_met_den_times_free_never_overflows() {
        let mut checked = 0;
        for qd in 0u8..=18 {
            for td in 0u8..=18 {
                for l in [1u128, 1 << 64, u128::MAX / 3, u128::MAX] {
                    for amount in [1u64, 1 << 40, u64::MAX] {
                        let Some(r) = need_ratio(amount, l, qd, td) else { continue };
                        assert!(r.den.0 < 1u128 << 20, "den < 2^148: qd {qd} td {td} L {l}");
                        for free in [0u64, 1, u64::MAX - 1] {
                            assert!(mul_wide_small(r.den.0, r.den.1, free as u128).is_some(), "qd {qd} td {td} L {l} free {free}");
                        }
                        for q in [1u128, 1_000_000_000_000_000_000, u128::MAX / 10] {
                            let Some(root) = need_root(&r, q) else { continue };
                            let f = capacity_need_pico(amount, q, l, qd, td);
                            for free in [0u64, 1, f.saturating_sub(1), f, f.saturating_add(1), u64::MAX - 1] {
                                if free == u64::MAX {
                                    continue;
                                }
                                let exact = f != u64::MAX && free >= f;
                                assert_eq!(need_met(&r, root, free), exact, "qd {qd} td {td} L {l} amount {amount} q {q} free {free} f {f}");
                            }
                            checked += 1;
                        }
                    }
                }
            }
        }
        assert!(checked > 4_000, "{checked}");
    }

    fn vectors() -> serde_json::Value {
        let path = format!("{}/../../../../test/fixtures/gap-vectors.json", env!("CARGO_MANIFEST_DIR"));
        serde_json::from_str(&std::fs::read_to_string(&path).expect("the gap vectors")).unwrap()
    }
    fn dec(v: &serde_json::Value) -> u128 {
        v.as_str().unwrap().parse().unwrap()
    }
    fn hex(s: &str) -> Vec<u8> {
        let s = s.trim_start_matches("0x");
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
    }
    fn b32(s: &str) -> [u8; 32] {
        hex(s).try_into().unwrap()
    }

    #[test]
    fn worked_examples() {
        // v3c (owner 2026-10-30): $1,000 gross at $1, 50% gap, 0.3% pools, margin 0.1%, $0.50 cost (500 ppm)
        let r = gap_fee(998_000_000_000, E18, 2 * E18, 3_500, 3_000, 2_000, 1_000, 0);
        assert_eq!((r.gap_ppm, r.withheld, r.reason), (500_000, 494_238_716_149, CHARGED));
        assert_eq!(998_000_000_000 - r.withheld, 503_761_283_851);
        // the 16.67% example, no cost
        let r = gap_fee(998_000_000_000, 833_300_000_000_000_000, E18, 3_000, 3_000, 2_000, 1_000, 0);
        assert_eq!((r.gap_ppm, r.withheld, r.reason), (166_700, 158_849_348_045, CHARGED));
        // the worked cost: $0.50 of ETH at $2,000 on 998 tokens at $1
        assert_eq!(cost_ppm(250_000_000_000_000, 18, 2_000 * E18, E18, 9, 998_000_000_000, 2_000, COST_MAX_USD_E18), 500);
        // dst fee 1e6: a fee read failure
        assert_eq!(gap_fee(1_000, E18 / 2, E18, 0, 1_000_000, 0, 0, 0).reason, DST_FEE_FAILED);
        // the admin cost max (constants audit): a $30 LayerZero fee counts $20 by default, $30 under a $50 max
        let at = |max| cost_ppm(15_000_000_000_000_000, 18, 2_000 * E18, E18, 9, 998_000_000_000, 2_000, max);
        assert_eq!((at(COST_MAX_USD_E18), at(COST_MAX_CAP_USD_E18)), (20_000, 30_000));
    }

    #[test]
    fn formula_vectors() {
        let v = vectors();
        let mut n = 0;
        for f in v["formula"].as_array().unwrap() {
            if f.get("evmOnly").is_some() {
                continue;
            }
            let name = f["name"].as_str().unwrap();
            let amount = u64::try_from(dec(&f["amountLD"])).expect(name);
            let r = gap_fee(
                amount,
                dec(&f["psE18"]),
                dec(&f["pdE18"]),
                dec(&f["feeSrcPpm"]) as u32,
                dec(&f["feeDstPpm"]) as u32,
                dec(&f["bridgeFeePpm"]) as u32,
                dec(&f["marginPpm"]) as u32,
                u32::try_from(dec(&f["gasCoverPpm"])).expect(name),
            );
            assert_eq!(r.gap_ppm as u128, dec(&f["gapPpm"]), "{name}");
            assert_eq!(r.allow_ppm as u128, dec(&f["allowPpm"]), "{name}");
            assert_eq!(r.withheld as u128, dec(&f["withheld"]), "{name}");
            assert_eq!((amount - r.withheld) as u128, dec(&f["credited"]), "{name}");
            assert_eq!(r.reason as u64, f["reason"].as_u64().unwrap(), "{name}");
            n += 1;
        }
        assert!(n >= 30, "{n}");
        // Amendment 6: the five cover vectors are among them (u64 amounts only)
        let a6 = v["formula"].as_array().unwrap().iter().filter(|f| f["name"].as_str().unwrap().starts_with("A6:") && f.get("evmOnly").is_none()).count();
        assert!(a6 >= 3, "{a6}");
    }

    #[test]
    fn cost_pair_and_arb_vectors() {
        let v = vectors();
        let mut n = 0;
        for c in v["cost"].as_array().unwrap() {
            let name = c["name"].as_str().unwrap();
            // a native fee above u128 cannot reach the Solana port
            let Ok(fee) = c["nativeFee"].as_str().unwrap().parse::<u128>() else { continue };
            let got = cost_ppm(
                fee,
                c["nativeDecimals"].as_u64().unwrap() as u8,
                dec(&c["usdPerNativeE18"]),
                dec(&c["psE18"]),
                c["tokenDecimals"].as_u64().unwrap() as u8,
                u64::try_from(dec(&c["amountLD"])).expect(name),
                dec(&c["bridgeFeePpm"]) as u32,
                COST_MAX_USD_E18,
            );
            assert!(c.get("gasUsdE18").is_none(), "{name}: Amendment 6 has no gas allowance");
            assert_eq!(got as u128, dec(&c["costPpm"]), "{name}");
            n += 1;
        }
        // Amendment 6 §8: 10 cost vectors ("gas allowance above $10 is capped" removed), one with a
        // native fee above u128 that cannot reach the Solana port
        assert_eq!((v["cost"].as_array().unwrap().len(), n), (10, 9));
        for p in v["pair"].as_array().unwrap() {
            let name = p["name"].as_str().unwrap();
            let got = pick_pair(
                p["msgClass"].as_u64().unwrap() as u8,
                dec(&p["psClassE18"]),
                dec(&p["psUsdE18"]),
                p["dstClass"].as_u64().unwrap() as u8,
                dec(&p["pdClassE18"]),
                dec(&p["pdUsdE18"]),
            );
            match &p["pair"] {
                serde_json::Value::Null => assert_eq!(got, None, "{name}"),
                w => assert_eq!(got, Some((dec(&w["ps"]), dec(&w["pd"]), w["kind"].as_str().unwrap() == "class")), "{name}"),
            }
        }
        // the owner's rule: at gaps 1%, 10%, 50%, 90% the credit is the vector's (whose arb net <= margin)
        for a in v["arbNet"].as_array().unwrap() {
            let r = gap_fee(
                dec(&a["amountLD"]) as u64,
                dec(&a["psE18"]),
                dec(&a["pdE18"]),
                dec(&a["feeSrcPpm"]) as u32,
                dec(&a["feeDstPpm"]) as u32,
                dec(&a["bridgeFeePpm"]) as u32,
                dec(&a["marginPpm"]) as u32,
                0,
            );
            assert_eq!(r.withheld as u128, dec(&a["withheld"]), "{}", a["gap"]);
            assert!(dec(&a["arbNetUsdE18"]) <= dec(&a["marginUsdE18"]));
        }
    }

    fn check(d: &serde_json::Value, m: &[u8]) {
        let h = decode(m).unwrap();
        assert_eq!(h.send_to, b32(d["sendTo"].as_str().unwrap()));
        assert_eq!(h.amount_sd as u128, dec(&d["amountSD"]));
        assert_eq!(h.v1, d["v1"].as_bool().unwrap());
        assert_eq!(h.ps_e18, dec(&d["psE18"]));
        assert_eq!(h.fee_src_ppm as u128, dec(&d["feeSrcPpm"]));
        assert_eq!(h.bridge_fee_ppm as u128, dec(&d["bridgeFeePpm"]));
        assert_eq!(h.min_credited_sd as u128, dec(&d["minCreditedSD"]));
        assert_eq!(h.price_class as u128, dec(&d["priceClass"]));
        assert_eq!(h.ps_class_e18, dec(&d["psClassE18"]));
        assert_eq!(h.src_gas_micro_usd as u128, dec(&d["srcGasMicroUsd"]));
        assert_eq!(h.src_cover_cap_cents as u128, dec(&d["srcCoverCapCents"]));
        assert!(d.get("srcDepthUsd").is_none() && d.get("srcGasCents").is_none(), "Amendment 5 names are retired");
        assert_eq!(h.composed, d["composed"].as_bool().unwrap());
        assert_eq!(compose_tail(m), hex(d["composeTail"].as_str().unwrap()).as_slice());
    }

    #[test]
    fn codec_vectors() {
        let v = vectors();
        for e in v["encode"].as_array().unwrap() {
            let i = &e["input"];
            let msg = hex(i["composeMsg"].as_str().unwrap());
            let m = encode(
                b32(i["sendTo"].as_str().unwrap()),
                dec(&i["amountSD"]) as u64,
                dec(&i["psE18"]),
                dec(&i["feeSrcPpm"]) as u32,
                dec(&i["bridgeFeePpm"]) as u32,
                dec(&i["minCreditedSD"]) as u64,
                dec(&i["priceClass"]) as u8,
                dec(&i["psClassE18"]),
                u32::try_from(dec(&i["srcGasMicroUsd"])).unwrap(),
                u16::try_from(dec(&i["srcCoverCapCents"])).unwrap(),
                Some((b32(i["composeFrom"].as_str().unwrap()), msg.as_slice())),
            );
            assert_eq!(m, hex(e["message"].as_str().unwrap()), "{}", e["name"]);
            check(&e["decoded"], &m);
        }
        let mut refunds = 0;
        for d in v["decode"].as_array().unwrap().iter().chain(v["encode"].as_array().unwrap()) {
            let m = hex(d["message"].as_str().unwrap());
            check(&d["decoded"], &m);
            // amendment 2: the refund marker, as gap-math.mjs refundMarker
            let want = match d["refund"].as_str() {
                Some("refund") => Some(true),
                Some("bad") => Some(false),
                _ => None,
            };
            assert_eq!(refund_marker(&decode(&m).unwrap()), want, "{}", d["name"]);
            refunds += (want == Some(true)) as u32;
        }
        assert_eq!(refunds, 1);
        for d in v["decodeReverts"].as_array().unwrap() {
            assert!(decode(&hex(d["message"].as_str().unwrap())).is_none());
        }
        assert_eq!(HEADER_LEN, 96);
    }

    #[test]
    fn min_credited_vectors() {
        let v = vectors();
        let all = v["minCredited"].as_array().unwrap();
        assert!(all.len() >= 5);
        for c in all {
            let name = c["name"].as_str().unwrap();
            let got = credit_meets_min(dec(&c["creditedLD"]) as u64, dec(&c["minCreditedSD"]) as u64, dec(&c["rate"]) as u64);
            assert_eq!(got, c["credits"].as_bool().unwrap(), "{name}");
        }
        // the retired codec v2 (73 bytes) is not the gap codec
        let mut old = encode([1; 32], 5, 7, 1, 2, 0, 0, 0, 0, 0, None);
        old.truncate(73);
        old[VER_OFFSET] = 2;
        let h = decode(&old).unwrap();
        assert!(!h.v1 && !h.composed && h.min_credited_sd == 0);
        assert!(credit_meets_min(0, 0, 1_000) && !credit_meets_min(u64::MAX, u64::MAX, 2));
    }

    #[test]
    fn fee_and_price_vectors() {
        let v = vectors();
        for f in v["solanaPoolFee"].as_array().unwrap() {
            let n: u64 = f["cliffFeeNumerator"].as_str().unwrap().parse().unwrap();
            let want = f["ok"].as_bool().unwrap().then(|| dec(&f["ppm"]) as u32);
            assert_eq!(solana_pool_fee_ppm(n), want, "{n}");
        }
        for m in v["mul"].as_array().unwrap() {
            // a factor above u128 cannot reach the Solana port; the EVM treats it as 0.
            let (Ok(a), Ok(b)) = (m["a"].as_str().unwrap().parse::<u128>(), m["b"].as_str().unwrap().parse::<u128>()) else { continue };
            assert_eq!(mul_up(a, b), dec(&m["up"]), "up {a} {b}");
            assert_eq!(mul_down(a, b), dec(&m["down"]), "down {a} {b}");
        }
        for s in v["srcFactor"].as_array().unwrap() {
            let Ok(p) = s["p"].as_str().unwrap().parse::<u128>() else { continue };
            assert_eq!(src_factor(p), dec(&s["factor"]), "{p}");
        }
    }

    /// The class-only cost (kept with its vectors; Amendment 6 sends need psUsd), isqrt (the
    /// PriceLog capacity's root).
    #[test]
    fn isqrt_and_class_cost_vectors() {
        let v = vectors();
        for r in v["isqrt"].as_array().map(|a| a.as_slice()).unwrap_or(&[]) {
            let Ok(x) = r["n"].as_str().unwrap().parse::<u128>() else { continue };
            assert_eq!(isqrt(x), dec(&r["root"]), "{x}");
        }
        for (n, want) in [(0u128, 0u128), (1, 1), (3, 1), (4, 2), (u64::MAX as u128, u32::MAX as u128), (u128::MAX, u64::MAX as u128)] {
            assert_eq!(isqrt(n), want, "{n}");
        }
        let mut c = 0;
        for e in v["costClass"].as_array().unwrap() {
            let name = e["name"].as_str().unwrap();
            assert!(e.get("gasUsdE18").is_none(), "{name}: Amendment 6 has no gas allowance");
            let (Ok(fee), Ok(usd), Ok(ps), Ok(amount)) = (
                e["nativeFee"].as_str().unwrap().parse::<u128>(),
                e["usdPerNativeE18"].as_str().unwrap().parse::<u128>(),
                e["psClassE18"].as_str().unwrap().parse::<u128>(),
                e["amountLD"].as_str().unwrap().parse::<u64>(),
            ) else {
                continue;
            };
            let got = cost_class_ppm(
                e["priceClass"].as_u64().unwrap() as u8,
                e["nativeClass"].as_u64().unwrap() as u8,
                fee,
                e["nativeDecimals"].as_u64().unwrap() as u8,
                usd,
                ps,
                e["tokenDecimals"].as_u64().unwrap() as u8,
                amount,
                dec(&e["bridgeFeePpm"]) as u32,
                COST_MAX_USD_E18,
            );
            assert_eq!(got as u128, dec(&e["costPpm"]), "{name}");
            c += 1;
        }
        assert!(c >= 8, "{c}");
        // Amendment 5's vectors are retired
        for k in ["margin", "marginEdges", "depthGasRounding"] {
            assert!(v.get(k).is_none(), "{k}");
        }
    }

    // ---------------------------------------------------------------- Amendment 6: the gas cover

    fn opt(v: &serde_json::Value) -> Option<u128> {
        match v {
            serde_json::Value::Null => None,
            x => Some(dec(x)),
        }
    }

    /// The EVM side of a route (gap-math.mjs `evmGasUsdE18`), test-only: the Solana program never
    /// prices EVM gas, but the vectors' routes to and from Solana need the other side's figure.
    fn evm_gas(c: &serde_json::Value, units: u128, read: &core::cell::Cell<bool>) -> Option<u128> {
        if units == 0 {
            return Some(0);
        }
        let cap = dec(&c["baseFeeCapWei"]);
        if cap == 0 {
            return Some(0);
        }
        // an unreadable basefee (an off-chain mirror's RPC; never on chain) holds
        if c["baseFeeWei"].is_null() {
            read.set(true);
            return None;
        }
        let b = dec(&c["baseFeeWei"]).max(dec(&c["baseFeeFloorWei"])).min(cap);
        if b == 0 {
            return Some(0);
        }
        read.set(true);
        let usd = dec(&c["usdPerNativeE18"]);
        if usd == 0 {
            return None;
        }
        let (hi, lo) = mul_wide(b * units, usd);
        div_wide(hi, lo, E18).map(|(q, _)| q)
    }

    /// A destination's own swap gas as the receive computes it: Solana through `solana_gas_usd_e18`
    /// (the program's function), EVM through `evm_gas`. `read` records a price read.
    fn dst_gas(c: &serde_json::Value, read: &core::cell::Cell<bool>) -> Option<u128> {
        if c["kind"] == "solana" {
            solana_gas_usd_e18(dec(&c["swapLamports"]) as u64, || {
                read.set(true);
                dec(&c["solUsdE18"])
            })
        } else {
            evm_gas(c, dec(&c["swapUnits"]), read)
        }
    }

    /// The source's header fields: Solana through `source_gas_fields` (the program's function),
    /// EVM through `evm_gas` (swap + send units).
    fn src_fields(c: &serde_json::Value, granted: bool) -> Option<SourceGas> {
        let cap = (dec(&c["coverCapCents"]).min(u16::MAX as u128) as u16).min(COVER_CAP_MAX_CENTS);
        if c["kind"] == "solana" {
            return source_gas_fields(dec(&c["coverCapCents"]).min(u16::MAX as u128) as u16, granted, dec(&c["swapLamports"]) as u32, dec(&c["sendLamports"]) as u32, || dec(&c["solUsdE18"]));
        }
        if cap == 0 || !granted {
            return Some(SourceGas::default());
        }
        let gas = evm_gas(c, dec(&c["swapUnits"]) + dec(&c["sendUnits"]), &core::cell::Cell::new(false))?;
        Some(SourceGas { src_gas_micro_usd: (gas / MICRO_USD_E18).min(cap as u128 * 10_000) as u32, src_cover_cap_cents: cap, gas_usd_e18: gas, carried: true })
    }

    /// Run gap_priced as the receive does, for a vector-shaped input.
    #[allow(clippy::too_many_arguments)]
    fn priced(amount: u64, ps: u128, pd: u128, ps_usd: u128, fs: u32, fd: u32, b: u32, m: u32, td: u8, micro: u32, cap: u16, dst: &serde_json::Value) -> (Priced, bool) {
        let read = core::cell::Cell::new(false);
        let dcap = dec(&dst["coverCapCents"]).min(u16::MAX as u128) as u16;
        let p = gap_priced(amount, ps, pd, ps_usd, fs, fd, b, m, td, micro, cap, dcap, || dst_gas(dst, &read));
        (p, read.get())
    }

    #[test]
    fn a6_constants_and_setter_vectors() {
        let v = vectors();
        let g = &v["gasCover"];
        let k = &g["constants"];
        assert_eq!(dec(&k["MARGIN_DEFAULT_PPM"]), MARGIN_DEFAULT_PPM as u128);
        assert_eq!(dec(&k["MARGIN_MAX_PPM"]), MARGIN_MAX_PPM as u128);
        assert_eq!(dec(&k["SWAP_LAMPORTS_MAX"]), SWAP_LAMPORTS_MAX as u128);
        assert_eq!(dec(&k["SEND_LAMPORTS_MAX"]), SEND_LAMPORTS_MAX as u128);
        assert_eq!(dec(&k["COVER_CAP_MAX_CENTS"]), COVER_CAP_MAX_CENTS as u128);
        let mut n = 0;
        for s in g["settings"]["margin"].as_array().unwrap() {
            let ok = check_margin(u32::try_from(dec(&s["marginPpm"])).unwrap());
            assert_eq!(ok, s["error"].is_null(), "margin {}", s["marginPpm"]);
            if !ok {
                assert_eq!(s["error"], "MarginTooHigh");
            }
            n += 1;
        }
        for s in g["settings"]["solana"].as_array().unwrap() {
            let ok = check_solana_gas_cover(dec(&s["swapLamports"]) as u32, dec(&s["sendLamports"]) as u32, dec(&s["coverCapCents"]) as u16);
            assert_eq!(ok, s["error"].is_null(), "{}", s["name"]);
            if !ok {
                assert_eq!(s["error"], "BadGasCover");
            }
            n += 1;
        }
        assert!(n >= 9, "{n}");
    }

    #[test]
    fn a6_solana_gas_and_source_field_vectors() {
        let v = vectors();
        let g = &v["gasCover"];
        for s in g["solGas"].as_array().unwrap() {
            let read = core::cell::Cell::new(false);
            let lam = dec(&s["lamports"]) as u64;
            let got = solana_gas_usd_e18(lam, || {
                read.set(true);
                dec(&s["solUsdE18"])
            });
            assert_eq!(got, opt(&s["gasUsdE18"]), "{}", s["name"]);
            assert_eq!(read.get(), lam != 0, "{}: the price is read only for non-zero lamports", s["name"]);
        }
        // the source fields: the chains' figures, and the named variations of the generator
        let ch = &g["chains"];
        let mut sol = 0;
        for s in g["sourceFields"].as_array().unwrap() {
            let name = s["name"].as_str().unwrap();
            let mut c = match s["chain"].as_str().unwrap() {
                "ETH" | "ETH*" => ch["ETH"].clone(),
                "RH" => ch["RH"].clone(),
                "SOL" | "SOL*" => ch["SOL"].clone(),
                other => panic!("{other}"),
            };
            let gwei = 1_000_000_000u128;
            match name {
                "ETH source, cover cap 0: (0, 0), nothing read" => {
                    c["coverCapCents"] = "0".into();
                    c["usdPerNativeE18"] = "0".into();
                }
                "ETH source at a 400 gwei spike: 50 gwei counted, the $20 cap holds ($29.50 -> $20)" => c["baseFeeWei"] = (400 * gwei).to_string().into(),
                "ETH source, native USD unreadable: the send refuses" => c["usdPerNativeE18"] = "0".into(),
                "Solana source, SOL/USD unreadable: the send refuses" => c["solUsdE18"] = "0".into(),
                "Solana source, lamports at the hard caps" => {
                    c["swapLamports"] = SWAP_LAMPORTS_MAX.to_string().into();
                    c["sendLamports"] = SEND_LAMPORTS_MAX.to_string().into();
                }
                "cover cap above $200 in the config is clamped to $200 ($1,770 of gas -> $200)" => {
                    c["baseFeeWei"] = (1_000 * gwei).to_string().into();
                    c["baseFeeCapWei"] = (1_000 * gwei).to_string().into();
                    c["coverCapCents"] = "65535".into();
                }
                _ => assert!(name.ends_with(" as source"), "{name}: a vector this test does not know"),
            }
            sol += (c["kind"] == "solana") as u32;
            match (src_fields(&c, true), s.get("refuse")) {
                (None, Some(r)) => assert_eq!(r, "GapSourceUnreadable", "{name}"),
                (Some(f), None) => {
                    assert_eq!(f.src_gas_micro_usd as u128, dec(&s["srcGasMicroUsd"]), "{name}");
                    assert_eq!(f.src_cover_cap_cents as u128, dec(&s["srcCoverCapCents"]), "{name}");
                    assert_eq!(f.carried, f.src_cover_cap_cents != 0, "{name}");
                }
                (got, want) => panic!("{name}: {got:?} vs {want:?}"),
            }
        }
        assert_eq!(sol, 3, "the Solana source vectors");
        // not granted (the window's cover is spent): (0, 0), nothing read, nothing carried
        let f = source_gas_fields(2_000, false, 5_000, 5_000, || panic!("no price read")).unwrap();
        assert_eq!(f, SourceGas::default());
        let f = source_gas_fields(0, true, 5_000, 5_000, || panic!("no price read")).unwrap();
        assert_eq!(f, SourceGas::default());
        // lamports 0 with a cap: carried at 0 micro-dollars, no price needed
        let f = source_gas_fields(2_000, true, 0, 0, || panic!("no price read")).unwrap();
        assert_eq!((f.src_gas_micro_usd, f.src_cover_cap_cents, f.carried), (0, 2_000, true));
    }

    #[test]
    fn a6_cover_and_priced_vectors() {
        let v = vectors();
        let g = &v["gasCover"];
        let mut n = 0;
        for c in g["cover"].as_array().unwrap() {
            let name = c["name"].as_str().unwrap();
            let Ok(amount) = c["amountLD"].as_str().unwrap().parse::<u64>() else { continue };
            let Ok(dgas) = c["dstGasUsdE18"].as_str().unwrap().parse::<u128>() else { continue };
            let Ok(ps) = c["psUsdE18"].as_str().unwrap().parse::<u128>() else { continue };
            let (ppm, usd) = gas_cover_ppm(
                u32::try_from(dec(&c["srcGasMicroUsd"])).unwrap(),
                u16::try_from(dec(&c["srcCoverCapCents"])).unwrap(),
                dgas,
                u16::try_from(dec(&c["dstCoverCapCents"])).unwrap(),
                ps,
                c["tokenDecimals"].as_u64().unwrap() as u8,
                amount,
                dec(&c["bridgeFeePpm"]) as u32,
            );
            assert_eq!(ppm as u128, dec(&c["coverPpm"]), "{name}");
            if ppm != 0 {
                assert_eq!(usd, dec(&c["coverUsdE18"]), "{name}");
            }
            n += 1;
        }
        assert!(n >= 8, "cover vectors: {n}");
        let mut n = 0;
        for p in g["priced"].as_array().unwrap() {
            let name = p["name"].as_str().unwrap();
            let Ok(amount) = p["amountLD"].as_str().unwrap().parse::<u64>() else { continue };
            let (r, read) = priced(
                amount,
                dec(&p["psE18"]),
                dec(&p["pdE18"]),
                dec(&p["psUsdE18"]),
                dec(&p["feeSrcPpm"]) as u32,
                dec(&p["feeDstPpm"]) as u32,
                dec(&p["bridgeFeePpm"]) as u32,
                dec(&p["marginPpm"]) as u32,
                p["tokenDecimals"].as_u64().unwrap() as u8,
                u32::try_from(dec(&p["srcGasMicroUsd"])).unwrap(),
                u16::try_from(dec(&p["srcCoverCapCents"])).unwrap(),
                &p["dst"],
            );
            assert_eq!(r.holds, p["holds"].as_bool().unwrap(), "{name}");
            assert_eq!(r.fee.reason as u64, p["reason"].as_u64().unwrap(), "{name}");
            assert_eq!(read, p["nativeRead"].as_bool().unwrap(), "{name}: the destination price read");
            assert_eq!(r.dst_gas_usd_e18, dec(&p["dstGasUsdE18"]), "{name}");
            assert_eq!(r.cover_usd_e18, dec(&p["coverUsdE18"]), "{name}");
            assert_eq!(r.cover_ppm as u128, dec(&p["coverPpm"]), "{name}");
            assert_eq!(r.fee.gap_ppm as u128, dec(&p["gapPpm"]), "{name}");
            assert_eq!(r.fee.allow_ppm as u128, dec(&p["allowPpm"]), "{name}");
            assert_eq!(r.fee.withheld as u128, dec(&p["withheld"]), "{name}");
            let credited = if r.holds { 0 } else { amount - r.fee.withheld };
            assert_eq!(credited as u128, dec(&p["credited"]), "{name}");
            n += 1;
        }
        assert!(n >= 14, "priced vectors: {n}");
    }

    /// Lead decision 1 on the Solana side: the window index, and the solanaSequence (SOL -> ETH) with
    /// the program's grant rule, source fields and the destination's priced step.
    #[test]
    fn a6_cover_window_vectors() {
        let v = vectors();
        let g = &v["gasCover"];
        let w = &g["coverWindow"];
        let mut n = 0;
        for x in w["windowIndex"].as_array().unwrap() {
            if x["kind"] != "solana" {
                continue;
            }
            assert_eq!(cover_window_index(dec(&x["slot"]) as u64, dec(&x["windowSlots"]) as u64) as u128, dec(&x["windowIndex"]), "{}", x["name"]);
            n += 1;
        }
        assert_eq!(n, 3);
        let (src, dst) = (&g["chains"]["SOL"], &g["chains"]["ETH"]);
        let mut state = 0u64;
        let seq = w["solanaSequence"].as_array().unwrap();
        assert_eq!(seq.len(), 3);
        for s in seq {
            let name = s["name"].as_str().unwrap();
            let wi = dec(&s["windowIndex"]) as u64;
            assert_eq!(state as u128, dec(&s["lastCoverWindowP1Before"]), "{name}");
            let granted = cover_granted(state, wi);
            assert_eq!(granted, s["coverGranted"].as_bool().unwrap(), "{name}");
            let f = src_fields(src, granted).expect(name);
            if f.carried {
                state = wi + 1;
            }
            assert_eq!(state as u128, dec(&s["lastCoverWindowP1After"]), "{name}");
            assert_eq!(f.src_gas_micro_usd as u128, dec(&s["srcGasMicroUsd"]), "{name}");
            assert_eq!(f.src_cover_cap_cents as u128, dec(&s["srcCoverCapCents"]), "{name}");
            let pd = 1_111_111_111_111_111u128; // PS / 0.9, the vectors' 10% gap
            let (r, read) = priced(dec(&s["amountLD"]) as u64, 1_000_000_000_000_000, pd, 1_000_000_000_000_000, 3_000, 3_000, 2_000, 1_000, 9, f.src_gas_micro_usd, f.src_cover_cap_cents, dst);
            assert_eq!(read, s["dstNativeRead"].as_bool().unwrap(), "{name}");
            assert_eq!(r.dst_gas_usd_e18, dec(&s["dstGasUsdE18"]), "{name}");
            assert_eq!(r.cover_ppm as u128, dec(&s["coverPpm"]), "{name}");
            assert_eq!(r.cover_usd_e18, dec(&s["coverUsdE18"]), "{name}");
            assert_eq!(r.fee.withheld as u128, dec(&s["withheld"]), "{name}");
            assert_eq!((dec(&s["amountLD"]) as u64 - r.fee.withheld) as u128, dec(&s["credited"]), "{name}");
        }
        // the EVM sequence's grant rule is the same function of (state, w)
        for s in w["evmSequence"].as_array().unwrap() {
            assert_eq!(cover_granted(dec(&s["lastCoverWindowP1Before"]) as u64, dec(&s["windowIndex"]) as u64), s["coverGranted"].as_bool().unwrap(), "{}", s["name"]);
        }
    }

    /// The arb table and the bridger vectors on every route with Solana on one side: the source's
    /// cost and fields, the destination's cover, withheld and credited, to the unit.
    #[test]
    fn a6_arb_and_bridger_vectors_on_solana_routes() {
        let v = vectors();
        let g = &v["gasCover"];
        let ch = &g["chains"];
        let (ps, pd) = (1_000_000_000_000_000u128, 1_111_111_111_111_111u128);
        let native = |c: &serde_json::Value| if c["kind"] == "solana" { (9u8, dec(&c["solUsdE18"])) } else { (18u8, dec(&c["usdPerNativeE18"])) };
        let mut n = 0;
        for a in g["arb"].as_array().unwrap() {
            let (s, d) = (a["src"].as_str().unwrap(), a["dst"].as_str().unwrap());
            if s != "SOL" && d != "SOL" {
                continue;
            }
            let name = a["name"].as_str().unwrap();
            assert_eq!((dec(&a["psE18"]), dec(&a["pdE18"])), (ps, pd), "{name}");
            let st = &a["atSStar"];
            assert!(!st.is_null(), "{name}");
            let amount = dec(&st["amountLD"]) as u64;
            let f = dec(&a["poolFeePpm"]) as u32;
            let (nd, usd) = native(&ch[s]);
            let cost = cost_ppm(dec(&a["lzFeeNative"]), nd, usd, ps, 9, amount, 2_000, COST_MAX_USD_E18);
            assert_eq!(cost as u128, dec(&st["costPpm"]), "{name}");
            let sf = src_fields(&ch[s], true).unwrap();
            assert_eq!(sf.src_gas_micro_usd as u128, dec(&st["srcGasMicroUsd"]), "{name}");
            let (r, _) = priced(amount, ps, pd, ps, f + cost, f, 2_000, dec(&a["marginPpm"]) as u32, 9, sf.src_gas_micro_usd, sf.src_cover_cap_cents, &ch[d]);
            assert!(!r.holds, "{name}");
            assert_eq!(r.fee.reason as u64, st["reason"].as_u64().unwrap(), "{name}");
            assert_eq!(r.cover_ppm as u128, dec(&st["coverPpm"]), "{name}");
            assert_eq!(r.cover_usd_e18, dec(&st["coverUsdE18"]), "{name}");
            assert_eq!(r.fee.withheld as u128, dec(&st["withheld"]), "{name}");
            assert_eq!((amount - r.fee.withheld) as u128, dec(&st["credited"]), "{name}");
            // the vector's invariant, as written: the cover never exceeds the real gas
            assert!(dec(&st["coverUsdE18"]) <= dec(&st["actualGasUsdE18"]), "{name}");
            n += 1;
        }
        assert_eq!(n, 48, "4 depths x 4 Solana routes x 3 fees");
        let mut n = 0;
        for b in g["bridger"].as_array().unwrap() {
            let (s, d) = (b["src"].as_str().unwrap(), b["dst"].as_str().unwrap());
            if s != "SOL" && d != "SOL" {
                continue;
            }
            let name = b["name"].as_str().unwrap();
            let amount = dec(&b["amountLD"]) as u64;
            let (nd, usd) = native(&ch[s]);
            let lz_usd = dec(&ch[d]["lzFeeToHereUsdE18"]);
            let lz = (lz_usd * 10u128.pow(nd as u32)).div_ceil(usd);
            let cost = cost_ppm(lz, nd, usd, ps, 9, amount, 2_000, COST_MAX_USD_E18);
            let sf = src_fields(&ch[s], true).unwrap();
            let (with, _) = priced(amount, ps, pd, ps, 3_000 + cost, 3_000, 2_000, 1_000, 9, sf.src_gas_micro_usd, sf.src_cover_cap_cents, &ch[d]);
            let (without, _) = priced(amount, ps, pd, ps, 3_000 + cost, 3_000, 2_000, 1_000, 9, sf.src_gas_micro_usd, 0, &ch[d]);
            assert_eq!(with.cover_usd_e18, dec(&b["coverUsdE18"]), "{name}");
            assert_eq!(with.cover_ppm as u128, dec(&b["coverPpm"]), "{name}");
            assert_eq!(with.fee.withheld as u128, dec(&b["withheldWithCover"]), "{name}");
            assert_eq!(without.fee.withheld as u128, dec(&b["withheldNoCover"]), "{name}");
            n += 1;
        }
        assert_eq!(n, 4);
    }

    #[test]
    fn div_wide_fast_path_is_the_bitwise_one() {
        fn slow(hi: u128, lo: u128, d: u128) -> Option<(u128, u128)> {
            if d == 0 || hi >= d {
                return None;
            }
            let (mut q, mut r) = (0u128, hi);
            for i in (0..128).rev() {
                let carry = r >> 127;
                r = (r << 1) | ((lo >> i) & 1);
                q <<= 1;
                if carry == 1 || r >= d {
                    r = r.wrapping_sub(d);
                    q |= 1;
                }
            }
            Some((q, r))
        }
        let mut x: u128 = 0x2545_F491_4F6C_DD1D_9E37_79B9_7F4A_7C15;
        for _ in 0..5_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let lo = x >> (x % 128);
            let d = (x.rotate_left(64) >> (x % 127)).max(1);
            assert_eq!(div_wide(0, lo, d), slow(0, lo, d));
            let hi = d / 3;
            assert_eq!(div_wide(hi, lo, d), slow(hi, lo, d));
        }
    }

    #[test]
    fn wide_math_matches_naive_where_it_fits() {
        for &(a, b) in &[(1u128, 1u128), (u64::MAX as u128, u64::MAX as u128), (E18, 3), (12345678901234567890, 98765432109876543210)] {
            let (hi, lo) = mul_wide(a, b);
            if let Some(p) = a.checked_mul(b) {
                assert_eq!((hi, lo), (0, p));
                assert_eq!(div_wide(hi, lo, E18), Some((p / E18, p % E18)));
            }
        }
        let (hi, lo) = mul_wide(u128::MAX, u128::MAX);
        assert_eq!((hi, lo), (u128::MAX - 1, 1));
        assert_eq!(div_wide(hi, lo, u128::MAX), Some((u128::MAX, 0)));
    }

    /// Amendment 5's Solana depthLocked against the cp-amm reserve by hand.
    #[test]
    fn locked_depth_is_the_quote_reserve_at_the_given_price_rounded_up() {
        // USDC (6) / token (6) at $1: L = 2^64 * 1e9 gives 1e9 raw = $1,000 of quote, exactly
        let l = (1u128 << 64) * 1_000_000_000;
        assert_eq!(locked_depth_dollars_up(l, E18, E18, 6, 6), 1_000);
        // one unit more liquidity rounds up
        assert_eq!(locked_depth_dollars_up(l + 1, E18, E18, 6, 6), 1_001);
        // wSOL (9) / token (6), 0.5 SOL per token, SOL $200 (token $100): reserve L * sqrt(500) / 2^64
        // lamports = 22.36 SOL = $4,472.14 -> 4,473 (odd decimal sum: the sqrt(10) goes in the root)
        let l = (1u128 << 64) * 1_000_000_000;
        assert_eq!(locked_depth_dollars_up(l, 100 * E18, E18 / 2, 9, 6), 4_473);
        // a 4x higher token price at the same quote price doubles the reserve (sqrt)
        let d1 = locked_depth_dollars_up(l, E18, E18, 6, 6) as u64;
        let d4 = locked_depth_dollars_up(l, 4 * E18, 4 * E18, 6, 6) as u64;
        assert_eq!(d4, 2 * d1);
        // unreadable and saturating
        assert_eq!(locked_depth_dollars_up(0, E18, E18, 6, 6), 0);
        assert_eq!(locked_depth_dollars_up(l, 0, E18, 6, 6), 0);
        assert_eq!(locked_depth_dollars_up(l, E18, 0, 6, 6), 0);
        assert_eq!(locked_depth_dollars_up(l, E18, E18, 19, 6), 0);
        assert_eq!(locked_depth_dollars_up(u128::MAX, u128::MAX, 1, 0, 0), u32::MAX);
    }

    #[test]
    fn capacity_units_round_up() {
        // 1,000 tokens (6 decimals) at $0.50 = $500 = 5e8 micro-dollars
        assert_eq!(usd_micro_up(1_000_000_000, E18 / 2, 6), 500_000_000);
        assert_eq!(usd_micro_up(1, 1, 6), 1);
        assert_eq!(usd_micro_up(0, E18, 6), 0);
        assert_eq!(usd_micro_up(u64::MAX, u128::MAX, 0), u64::MAX);
        // $50,000 of depth at k 0.1%: $50 of capacity per entry
        assert_eq!(entry_capacity_micro(50_000, 1_000), 50_000_000);
    }
}
