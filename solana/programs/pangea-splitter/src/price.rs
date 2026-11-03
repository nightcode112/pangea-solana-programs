//! # The opening price: $3,000, signed, and derived here
//!
//! Every launch opens at a market cap of $3,000 PER CHAIN (`OPENING_MARKET_CAP_USD_WAD`): each
//! chain's slice is worth $3,000 at the opening price, on every chain.
//! The program does not take the opening price from the launcher. It derives it from the same
//! EIP-712 price snapshot the four EVM factories verify (`PriceAttestor`), and refuses the launch
//! unless the snapshot is the price signer's:
//!
//!  1. **The snapshot is rebuilt here, not handed in.** Its launch id is this launch's seed's
//!     (`launch_id_of`); its fee is the launch's; its legs are the launch's peer chains and this
//!     one (`SOLANA_EID`), ascending -- each EVM leg's token the launch's token on THAT chain
//!     (`Peers`: every chain has its own), Solana's leg this launch's OFT store, every slice the
//!     launch's slice. Only the prices and the deadline are arguments (`SignedPrice`), each price
//!     carried in twelve bytes and widened before it is hashed (`MAX_WIRE_USD_PER_QUOTE`).
//!  2. **The market cap is a constant, not a signed number.** `usdPerToken` is
//!     `floor(3,000e18 x legs / (slice x legs / 1e9))`: the $3,000 over one chain's slice in
//!     whole tokens (the launch total over the number of legs) --
//!     exactly what the web's prepare route signs (route.ts) and what `PriceAttestor` enforces.
//!     A snapshot signed at any other market cap hashes to a different digest and is refused.
//!  3. **The signature is the price signer's.** The digest is recovered with the
//!     `secp256k1_recover` syscall -- no extra instruction, no instructions sysvar, which a launch
//!     has no bytes for -- and the address it gives must be the one the admin set
//!     (`set_price_signer`). 65 bytes, r || s || v with v 27 or 28, and a high `s` refused, as
//!     `PriceAttestor` does.
//!  4. **It is current.** `now <= deadline <= now + 1 hour`, as `PriceAttestor` checks.
//!  5. **The quote asset's price is plausible for THAT asset.** The snapshot's Solana leg carries a
//!     price and not the asset it prices, so a snapshot signed for SOL would otherwise open a pool
//!     against a dollar token at a twentieth of the market cap. As the EVM registry does: the
//!     admin sets a band of USD per 10^decimals base units for each asset a launch may pair with
//!     -- in its allowlist entry, and for wrapped SOL in the price signer's record -- and the
//!     signed price must be inside the band of the asset the launch actually pairs with. No
//!     band, no launch.
//!  6. **The price follows from it.** Quote per token as the EVM attestor computes it --
//!     `floor(usdPerToken x 1e18 / usdPerQuote)`, refused if zero -- then the pool's Q64.64 square
//!     root in base units: `floor(sqrt(quotePerToken x 10^quoteDecimals x 2^128 / 10^27))`, in
//!     exact integer arithmetic. `usdPerQuote` is the USD price of 10^decimals BASE units of the
//!     quote asset (for an asset with a UI multiplier, the displayed price times it): the signer's
//!     to get right, and signed.
//!
//! The same numbers are pinned in `test/fixtures/price-vector.json` (one signed snapshot: digest,
//! signature, opening) and `test/fixtures/opening-price-vector.json` (supplies and their
//! usdPerToken), which the web, script, EVM and client tests assert too.
use crate::SplitterError;
use anchor_lang::prelude::*;
use anchor_lang::solana_program::keccak;
use anchor_lang::solana_program::secp256k1_recover::secp256k1_recover;

#[cfg(all(feature = "mainnet", feature = "devnet"))]
compile_error!("build for one cluster: the default (mainnet), or --no-default-features --features devnet");
#[cfg(not(any(feature = "mainnet", feature = "devnet")))]
compile_error!("build for a cluster: the default features (mainnet), or --no-default-features --features devnet");

/// This chain's LayerZero endpoint id: the eid every price snapshot names Solana's leg by. Fixed at
/// build time for the cluster the program is built for, so a devnet build cannot use mainnet's.
#[cfg(feature = "mainnet")]
pub const SOLANA_EID: u32 = 30168;
#[cfg(all(feature = "devnet", not(feature = "mainnet")))]
pub const SOLANA_EID: u32 = 40168;

/// $3,000, 1e18-scaled: every launch's opening market cap on each chain, over that chain's slice.
pub const OPENING_MARKET_CAP_USD_WAD: u128 = 3_000 * WAD;
pub const WAD: u128 = 1_000_000_000_000_000_000;
/// The launched token's decimals, on every chain.
pub const TOKEN_UNIT: u128 = 1_000_000_000;
/// How far ahead a snapshot's deadline may be, as `PriceAttestor.MAX_DEADLINE_WINDOW`.
pub const MAX_DEADLINE_WINDOW: i64 = 3_600;
/// Meteora's lowest square-root price.
pub const CP_AMM_MIN_SQRT_PRICE: u128 = 4_295_048_016;

pub const PRICE_SIGNER_SEED: &[u8] = b"price_signer";
pub const DOMAIN_TYPE: &[u8] = b"EIP712Domain(string name,string version)";
pub const DOMAIN_NAME: &[u8] = b"PangeaLaunchPrice";
pub const DOMAIN_VERSION: &[u8] = b"1";
pub const LEG_TYPE: &[u8] = b"Leg(uint32 lzEid,uint256 usdPerQuote,bytes32 token,uint256 slice)";
pub const SNAPSHOT_TYPE: &[u8] =
    b"Snapshot(bytes32 launchId,uint256 usdPerToken,uint16 feeBps,uint64 deadline,Leg[] legs)Leg(uint32 lzEid,uint256 usdPerQuote,bytes32 token,uint256 slice)";

/// secp256k1's order over two: a signature whose `s` is above it is the other half of a malleable
/// pair, refused as `PriceAttestor` (OpenZeppelin's ECDSA) refuses it.
const HALF_ORDER: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4,
    0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
];

/// Who signs launch prices: the EVM address of the key `PriceAttestor` trusts -- and the band the
/// signed price of wrapped SOL must be inside (wrapped SOL has no allowlist entry to hold one).
/// Both set by the admin.
#[account]
#[derive(InitSpace)]
pub struct PriceSigner {
    pub address: [u8; 20],
    pub bump: u8,
    /// Wrapped SOL's band: USD per SOL, 1e18-scaled. Zero until `set_native_price_band`.
    pub native_min_usd_per_quote: u128,
    pub native_max_usd_per_quote: u128,
}

/// The least and the most a quote asset's signed price may be: USD per 10^decimals base units,
/// 1e18-scaled, the unit of the snapshot's `usdPerQuote`.
pub type PriceBand = (u128, u128);

/// A band an admin may set: both ends above zero, the least below the most.
pub fn check_band(min: u128, max: u128) -> Result<()> {
    require!(min > 0 && min < max, SplitterError::PriceOutOfRange);
    Ok(())
}

/// Whether `usd_per_quote` is inside `band`. A band never set (0, 0) holds nothing.
pub fn in_band(usd_per_quote: u128, band: PriceBand) -> bool {
    band.0 > 0 && band.0 < band.1 && usd_per_quote >= band.0 && usd_per_quote <= band.1
}

/// The most a leg's `usdPerQuote` can be in a launch transaction: it is carried in TWELVE bytes
/// (a u96, little-endian), 2^96 - 1 -- about 7.9e28, $79.2 billion for one whole unit of the quote
/// asset at the snapshot's 1e18 scale. The value signed is the same u256 as ever (the EVM side is
/// unchanged); only its top four bytes, always zero for any price that is a price, are not sent.
pub const MAX_WIRE_USD_PER_QUOTE: u128 = (1u128 << 96) - 1;

/// What a launch carries of its price snapshot: the prices and deadline that were signed, and the
/// signature. Everything else in the snapshot the program knows already.
///
/// On the wire: the deadline (u64), the number of legs (u32), each leg's price in twelve bytes
/// (see `MAX_WIRE_USD_PER_QUOTE`), the 65-byte signature. Widened to u128 as it is read, before
/// any digest is made of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedPrice {
    /// The snapshot's deadline, in unix seconds.
    pub deadline: u64,
    /// Each leg's `usdPerQuote`, in the legs' order: ascending endpoint id, Solana's among them.
    pub usd_per_quote: Vec<u128>,
    /// r || s || v, v 27 or 28.
    pub signature: [u8; 65],
}

impl AnchorSerialize for SignedPrice {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.deadline.to_le_bytes())?;
        let count = u32::try_from(self.usd_per_quote.len())
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "too many legs"))?;
        writer.write_all(&count.to_le_bytes())?;
        for usd in &self.usd_per_quote {
            if *usd > MAX_WIRE_USD_PER_QUOTE {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "a leg's usdPerQuote past 2^96 - 1 cannot be carried"));
            }
            writer.write_all(&usd.to_le_bytes()[..12])?;
        }
        writer.write_all(&self.signature)
    }
}

impl AnchorDeserialize for SignedPrice {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut deadline = [0u8; 8];
        reader.read_exact(&mut deadline)?;
        let mut count = [0u8; 4];
        reader.read_exact(&mut count)?;
        let count = u32::from_le_bytes(count) as usize;
        // No more legs than a launch has chains (the peers' and Solana's): a length that says
        // otherwise is refused before anything is allocated for it.
        if count > crate::PEER_CHAINS.len() + 1 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "more legs than the program has chains"));
        }
        let mut usd_per_quote = Vec::with_capacity(count);
        for _ in 0..count {
            let mut wide = [0u8; 16];
            reader.read_exact(&mut wide[..12])?;
            usd_per_quote.push(u128::from_le_bytes(wide));
        }
        let mut signature = [0u8; 65];
        reader.read_exact(&mut signature)?;
        Ok(SignedPrice { deadline: u64::from_le_bytes(deadline), usd_per_quote, signature })
    }
}

impl Default for SignedPrice {
    fn default() -> Self {
        SignedPrice { deadline: 0, usd_per_quote: Vec::new(), signature: [0u8; 65] }
    }
}

/// One leg of a snapshot, as the digest hashes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Leg {
    pub eid: u32,
    pub usd_per_quote: u128,
    pub token: [u8; 32],
    pub slice: u128,
    /// That chain's pool fee, in bps: signed per leg by the v2 snapshot (domain "3",
    /// `LEG_TYPE_V3`). The v1 digest does not hash it (`launch_legs` leaves it zero).
    pub fee_bps: u16,
}

fn word(v: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    w
}

/// The EIP-712 digest of a snapshot: `keccak(0x1901 || domainSeparator || structHash)`, with the
/// domain `{name: "PangeaLaunchPrice", version: "1"}` -- no chain id, so one signature serves all.
pub fn snapshot_digest(launch_id: &[u8; 32], usd_per_token: u128, fee_bps: u16, deadline: u64, legs: &[Leg]) -> [u8; 32] {
    let domain = keccak::hashv(&[
        &keccak::hash(DOMAIN_TYPE).0,
        &keccak::hash(DOMAIN_NAME).0,
        &keccak::hash(DOMAIN_VERSION).0,
    ])
    .0;
    let leg_type = keccak::hash(LEG_TYPE).0;
    let mut leg_hashes: Vec<u8> = Vec::with_capacity(32 * legs.len());
    for l in legs {
        let h = keccak::hashv(&[&leg_type, &word(l.eid as u128), &word(l.usd_per_quote), &l.token, &word(l.slice)]).0;
        leg_hashes.extend_from_slice(&h);
    }
    let structured = keccak::hashv(&[
        &keccak::hash(SNAPSHOT_TYPE).0,
        launch_id,
        &word(usd_per_token),
        &word(fee_bps as u128),
        &word(deadline as u128),
        &keccak::hash(&leg_hashes).0,
    ])
    .0;
    keccak::hashv(&[&[0x19, 0x01], &domain, &structured]).0
}

/// The EVM address that signed `digest`, or an error for a signature that is malformed, malleable
/// (high `s`) or recovers nothing.
pub fn recover_signer(digest: &[u8; 32], signature: &[u8; 65]) -> Result<[u8; 20]> {
    let v = signature[64];
    require!(v == 27 || v == 28, SplitterError::PriceNotSigned);
    require!(signature[32..64] <= HALF_ORDER[..], SplitterError::PriceNotSigned);
    let key = secp256k1_recover(digest, v - 27, &signature[..64]).map_err(|_| error!(SplitterError::PriceNotSigned))?;
    let h = keccak::hash(&key.to_bytes()).0;
    let mut address = [0u8; 20];
    address.copy_from_slice(&h[12..]);
    Ok(address)
}

/// `usdPerToken` for a $3,000 opening on each chain: `floor(3,000e18 x legs / whole tokens)`,
/// the supply being the slice on each of `legs` chains -- so $3,000 over one chain's slice. The
/// same arithmetic, step for step, as `PriceAttestor.openingUsdPerToken`, which sums the legs'
/// slices. The supply must be whole tokens.
pub fn usd_per_token(slice: u64, legs: usize) -> Result<u128> {
    let total = (slice as u128).checked_mul(legs as u128).ok_or(error!(SplitterError::PriceOutOfRange))?;
    require!(total > 0 && total % TOKEN_UNIT == 0, SplitterError::SupplyNotWholeTokens);
    let usd = OPENING_MARKET_CAP_USD_WAD * (legs as u128) / (total / TOKEN_UNIT);
    require!(usd > 0, SplitterError::PriceOutOfRange);
    Ok(usd)
}

fn mul_wide(a: u128, b: u128) -> (u128, u128) {
    const MASK: u128 = u64::MAX as u128;
    let (a1, a0) = (a >> 64, a & MASK);
    let (b1, b0) = (b >> 64, b & MASK);
    let p00 = a0 * b0;
    let p01 = a0 * b1;
    let p10 = a1 * b0;
    let p11 = a1 * b1;
    let mid = (p00 >> 64) + (p01 & MASK) + (p10 & MASK);
    let lo = (p00 & MASK) | (mid << 64);
    let hi = p11 + (p01 >> 64) + (p10 >> 64) + (mid >> 64);
    (hi, lo)
}

/// `floor(n / d)` and the remainder, for a 256-bit `n` given as (high, low) and any `d` above zero.
/// Bit by bit from the highest set bit: `d` may be anything up to 2^128.
fn div_rem_256(n: (u128, u128), d: u128) -> ((u128, u128), u128) {
    let (mut q_hi, mut q_lo) = (0u128, 0u128);
    let mut rem: u128 = 0;
    let bits = if n.0 != 0 { 256 - n.0.leading_zeros() } else { 128 - n.1.leading_zeros() };
    for i in (0..bits).rev() {
        let bit = if i >= 128 { (n.0 >> (i - 128)) & 1 } else { (n.1 >> i) & 1 };
        let carry = rem >> 127;
        rem = (rem << 1) | bit;
        if carry == 1 || rem >= d {
            rem = rem.wrapping_sub(d);
            if i >= 128 {
                q_hi |= 1 << (i - 128);
            } else {
                q_lo |= 1 << i;
            }
        }
    }
    ((q_hi, q_lo), rem)
}

/// `floor(n x 2^128 / d)` for a 256-bit `n` and a `d` below 2^96, or None when it does not fit 256
/// bits. Thirty-two bits at a time -- the remainder stays below `d`, so shifted by 32 it fits a
/// u128 -- which is twelve divisions where bit by bit would be some three hundred steps.
fn shifted_quotient(n: (u128, u128), d: u128) -> Option<(u128, u128)> {
    debug_assert!(d > 0 && d < 1 << 96);
    const CHUNK: u128 = 0xffff_ffff;
    let mut acc: u128 = 0;
    let (mut whole_hi, mut whole_lo) = (0u128, 0u128);
    for i in (0..8u32).rev() {
        let chunk = if i >= 4 { (n.0 >> ((i - 4) * 32)) & CHUNK } else { (n.1 >> (i * 32)) & CHUNK };
        acc = (acc << 32) | chunk;
        let digit = acc / d;
        acc %= d;
        if i >= 4 {
            whole_hi |= digit << ((i - 4) * 32);
        } else {
            whole_lo |= digit << (i * 32);
        }
    }
    if whole_hi != 0 {
        return None;
    }
    // The remainder is below d, so (remainder x 2^128) / d is below 2^128.
    let mut frac: u128 = 0;
    for _ in 0..4 {
        acc <<= 32;
        frac = (frac << 32) | (acc / d);
        acc %= d;
    }
    Some((whole_lo, frac))
}

/// The largest `s` below `cap` with `s * s <= x`, `x` given as (high, low).
fn isqrt_capped(x: (u128, u128), cap: u128) -> u128 {
    let (mut lo, mut hi) = (0u128, cap);
    while lo < hi {
        let mid = lo + (hi - lo) / 2 + 1;
        if mul_wide(mid, mid) <= x {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    lo
}

/// The pool's opening square-root price (Q64.64, quote base units per token base unit) for
/// `usd_per_token` against a quote asset worth `usd_per_quote` (both 1e18-scaled, per whole unit)
/// with `quote_decimals`. See the module's note for the formula.
pub fn opening_sqrt_price(usd_per_token: u128, usd_per_quote: u128, quote_decimals: u8) -> Result<u128> {
    require!(usd_per_token > 0 && usd_per_quote > 0, SplitterError::PriceOutOfRange);
    require!(quote_decimals <= 18, SplitterError::PriceOutOfRange);
    // In 256 bits throughout, as the EVM attestor and factory compute it: a supply of a few whole
    // tokens, or an 18-decimal quote asset, takes the intermediate products past 128 bits while
    // the price itself is one a pool can open at.
    let (quote_per_token, _) = div_rem_256(mul_wide(usd_per_token, WAD), usd_per_quote);
    require!(quote_per_token != (0, 0), SplitterError::PriceOutOfRange);
    // n = quotePerToken x 10^quoteDecimals, in 256 bits or refused.
    let unit = 10u128.pow(quote_decimals as u32);
    let (carry_lo, n_lo) = mul_wide(quote_per_token.1, unit);
    let (over, mid) = mul_wide(quote_per_token.0, unit);
    let (n_hi, carried) = mid.overflowing_add(carry_lo);
    require!(over == 0 && !carried, SplitterError::PriceOutOfRange);
    // 2^128 / 10^27: the 2^64 of Q64.64, squared, over the token's 10^9 and the 1e18 of the WAD.
    let x = shifted_quotient((n_hi, n_lo), 1_000_000_000_000_000_000_000_000_000).ok_or(error!(SplitterError::PriceOutOfRange))?;
    let s = isqrt_capped(x, crate::CP_AMM_MAX_SQRT_PRICE);
    require!(s > CP_AMM_MIN_SQRT_PRICE && s < crate::CP_AMM_MAX_SQRT_PRICE, SplitterError::PriceOutOfRange);
    Ok(s)
}

/// The snapshot's legs for a launch: its peer chains' and Solana's, ascending, with the prices it
/// was given in that order. Each EVM leg names that chain's own token -- left-padded to 32 bytes,
/// exactly as the EVM factories read the same signed snapshot -- and Solana's leg the OFT store.
pub fn launch_legs(peers: &[(u32, [u8; 20])], oft_store: &Pubkey, slice: u64, usd_per_quote: &[u128]) -> Result<Vec<Leg>> {
    require!(!peers.iter().any(|(eid, _)| *eid == SOLANA_EID), SplitterError::PriceNotSigned);
    let mut legs: Vec<(u32, [u8; 32])> = peers
        .iter()
        .map(|(eid, token)| {
            let mut word = [0u8; 32];
            word[12..].copy_from_slice(token);
            (*eid, word)
        })
        .collect();
    legs.push((SOLANA_EID, oft_store.to_bytes()));
    legs.sort_unstable_by_key(|(eid, _)| *eid);
    require!(usd_per_quote.len() == legs.len(), SplitterError::PriceNotSigned);
    Ok(legs
        .iter()
        .zip(usd_per_quote)
        .map(|((eid, token), usd)| Leg { eid: *eid, usd_per_quote: *usd, token: *token, slice: slice as u128, fee_bps: 0 })
        .collect())
}

/// `launch_legs` for a v2 snapshot: each leg also carries its own chain's pool fee -- Solana's
/// `solana_fee_bps` (the pool this launch opens), each peer's from `peer_fee_bps`, in the peers'
/// order. One fee per peer, or the snapshot is not this launch's.
pub fn launch_legs_v3(peers: &[(u32, [u8; 20])], peer_fee_bps: &[u16], solana_fee_bps: u16, oft_store: &Pubkey, slice: u64, usd_per_quote: &[u128]) -> Result<Vec<Leg>> {
    require!(peer_fee_bps.len() == peers.len(), SplitterError::PriceNotSigned);
    let mut legs = launch_legs(peers, oft_store, slice, usd_per_quote)?;
    for l in legs.iter_mut() {
        l.fee_bps = if l.eid == SOLANA_EID {
            solana_fee_bps
        } else {
            let at = peers.iter().position(|(eid, _)| *eid == l.eid).ok_or(SplitterError::PriceNotSigned)?;
            peer_fee_bps[at]
        };
    }
    Ok(legs)
}

/// Everything above, for one launch: the signed snapshot checked against the price signer, then
/// the opening square-root price it gives. `now` is the cluster's unix time.
#[allow(clippy::too_many_arguments)]
pub fn verified_opening_price(
    price: &SignedPrice,
    signer: &[u8; 20],
    launch_id: &[u8; 32],
    fee_bps: u16,
    peers: &[(u32, [u8; 20])],
    oft_store: &Pubkey,
    slice: u64,
    quote_decimals: u8,
    band: PriceBand,
    now: i64,
) -> Result<u128> {
    require!(*signer != [0u8; 20], SplitterError::PriceNotSigned);
    let deadline = i64::try_from(price.deadline).map_err(|_| error!(SplitterError::PriceExpired))?;
    require!(now <= deadline, SplitterError::PriceExpired);
    require!(deadline <= now.saturating_add(MAX_DEADLINE_WINDOW), SplitterError::PriceExpired);
    let legs = launch_legs(peers, oft_store, slice, &price.usd_per_quote)?;
    let usd_token = usd_per_token(slice, legs.len())?;
    let digest = snapshot_digest(launch_id, usd_token, fee_bps, price.deadline, &legs);
    require!(recover_signer(&digest, &price.signature)? == *signer, SplitterError::PriceNotSigned);
    let solana = legs.iter().find(|l| l.eid == SOLANA_EID).ok_or(error!(SplitterError::PriceNotSigned))?;
    // The signed price is one this launch's own quote asset could have: inside the band the admin
    // set for it. A snapshot priced for another asset -- SOL's, against a dollar token -- is not.
    require!(in_band(solana.usd_per_quote, band), SplitterError::PriceOutOfRange);
    opening_sqrt_price(usd_token, solana.usd_per_quote, quote_decimals)
}

/* ================================================================ snapshot v2 (factory v2)

   `launch_v2` and `launch_self` verify the snapshot PriceAttestorV2 verifies (docs/factory-v2.md
   §3): domain version "3", and three more signed values -- the opening market cap the creator
   chose, the supply mode, and the launch's terms -- from which the price follows exactly as the
   attestor computes it. Each leg signs its own chain's pool fee (`LEG_TYPE_V3`'s feeBps): a
   launch may open a different fee on every chain, and the snapshot has no fee of its own. The
   v1 digest above is untouched: v1 launches keep verifying it.                                  */

/// The v2 snapshot's domain version: "3" since the fee moved into the legs. Its name is v1's
/// (`DOMAIN_NAME`).
pub const DOMAIN_VERSION_V3: &[u8] = b"3";
pub const LEG_TYPE_V3: &[u8] = b"Leg(uint32 lzEid,uint256 usdPerQuote,bytes32 token,uint256 slice,uint16 feeBps)";
pub const SNAPSHOT_TYPE_V3: &[u8] = b"Snapshot(bytes32 launchId,uint32 marketCapUsd,uint8 supplyMode,bytes32 terms,uint256 usdPerToken,uint64 deadline,Leg[] legs)Leg(uint32 lzEid,uint256 usdPerQuote,bytes32 token,uint256 slice,uint16 feeBps)";

/// `PriceAttestorV2.MIN_MARKET_CAP_USD`: nobody launches below $3,000 a chain.
pub const MIN_MARKET_CAP_USD: u32 = 3_000;
/// `PriceAttestorV2.MAX_MARKET_CAP_USD`: $500,000 a chain (owner, 2026-10-22).
pub const MAX_MARKET_CAP_USD: u32 = 500_000;
/// v3 (owner 2026-10-31, `PriceAttestorV3`): a v3 launch's minimum opening market cap PER CHAIN is
/// the admin's (`set_v3_min_market_cap`, in `PDA(["gap_v3"])`), within these hard bounds -- $600 to
/// $3,000 a chain -- and starts at $600. v2 launches keep `MIN_MARKET_CAP_USD`.
pub const V3_MIN_MARKET_CAP_LOWER_BOUND_USD: u32 = 600;
/// The most the v3 minimum may be set to: v2's $3,000 a chain (never above `MAX_MARKET_CAP_USD`).
pub const V3_MIN_MARKET_CAP_UPPER_BOUND_USD: u32 = 3_000;
/// The v3 minimum the gap_v3 account is made with.
pub const V3_INITIAL_MIN_MARKET_CAP_USD: u32 = 600;
const _: () = assert!(
    V3_MIN_MARKET_CAP_LOWER_BOUND_USD > 0
        && V3_MIN_MARKET_CAP_LOWER_BOUND_USD <= V3_INITIAL_MIN_MARKET_CAP_USD
        && V3_INITIAL_MIN_MARKET_CAP_USD <= V3_MIN_MARKET_CAP_UPPER_BOUND_USD
        && V3_MIN_MARKET_CAP_UPPER_BOUND_USD <= MAX_MARKET_CAP_USD
);
/// Each chain's token reports its own slice (v1's launches).
pub const SUPPLY_SLICE: u8 = 0;
/// Each chain's token reports the launch total; on Solana the rest sits in the bridge reserve.
pub const SUPPLY_TOTAL: u8 = 1;

/// What a launch's terms sign beyond its payees and its fee (Solana audit round 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TermsBinding {
    /// Who pays the fee: a Solana key when it is paid on Solana, an EVM address left-padded
    /// otherwise; never zero. Only that payer's payment counts.
    pub payer: [u8; 32],
    /// `metadata_hash(name, symbol, uri)`: what the token is called, on every chain.
    pub metadata: [u8; 32],
    /// The Solana creator: who may launch and buys the dev buy. Zero without Solana.
    pub creator_solana: [u8; 32],
    /// The Solana pool's quote mint (wrapped SOL for SOL). Zero without Solana.
    pub quote_solana: [u8; 32],
}

/// `LaunchFactoryBaseV2.termsHash`: `keccak256(abi.encode(address payeeEvm, bytes32 payeeSolana,
/// uint32 feeEid, uint256 feeMin, bytes32 payer, bytes32 metadata, bytes32 creatorSolana, bytes32
/// quoteSolana))`. `payee_solana` is the 32 bytes the EVM side hashes: zero for "the Solana creator".
pub fn terms_hash(payee_evm: &[u8; 20], payee_solana: &[u8; 32], fee_eid: u32, fee_min: u64, b: &TermsBinding) -> [u8; 32] {
    let mut evm = [0u8; 32];
    evm[12..].copy_from_slice(payee_evm);
    keccak::hashv(&[&evm, payee_solana, &word(fee_eid as u128), &word(fee_min as u128), &b.payer, &b.metadata, &b.creator_solana, &b.quote_solana]).0
}

/// One leg's own fee in a creator self-launch (`V3Shared.LegFee`): at least `fee_min` held for the
/// launch by `payer` on `eid` (a left-padded EVM address, or a Solana key).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LegFeeEntry {
    pub eid: u32,
    pub fee_min: u128,
    pub payer: [u8; 32],
}

/// `TermsV3.legFeesHash`: `keccak256(abi.encode(LegFee[] fees))` -- the head word 0x20, the length,
/// then (eid, feeMin, payer) per leg -- for fees by strictly ascending eid. None otherwise, or empty.
pub fn leg_fees_hash(fees: &[LegFeeEntry]) -> Option<[u8; 32]> {
    if fees.is_empty() || fees.windows(2).any(|w| w[1].eid <= w[0].eid) {
        return None;
    }
    let mut words: Vec<[u8; 32]> = Vec::with_capacity(2 + 3 * fees.len());
    words.push(word(32));
    words.push(word(fees.len() as u128));
    for f in fees {
        words.push(word(f.eid as u128));
        words.push(word(f.fee_min));
        words.push(f.payer);
    }
    let parts: Vec<&[u8]> = words.iter().map(|w| w.as_slice()).collect();
    Some(keccak::hashv(&parts).0)
}

/// `TermsV3.termsHash` of a creator SELF-LAUNCH (`selfUntil != 0`): ten words -- v2's eight, then
/// `uint32 selfUntil` and `bytes32 legFees`. With `self_until == 0` it is `terms_hash` exactly
/// (today's flow; the leg fees are not hashed).
pub fn terms_hash_self(
    payee_evm: &[u8; 20],
    payee_solana: &[u8; 32],
    fee_eid: u32,
    fee_min: u64,
    b: &TermsBinding,
    self_until: u32,
    leg_fees: &[u8; 32],
) -> [u8; 32] {
    if self_until == 0 {
        return terms_hash(payee_evm, payee_solana, fee_eid, fee_min, b);
    }
    let mut evm = [0u8; 32];
    evm[12..].copy_from_slice(payee_evm);
    keccak::hashv(&[
        &evm,
        payee_solana,
        &word(fee_eid as u128),
        &word(fee_min as u128),
        &b.payer,
        &b.metadata,
        &b.creator_solana,
        &b.quote_solana,
        &word(self_until as u128),
        leg_fees,
    ])
    .0
}

/// The version word a v3 (gap fee) launch's terms end with: `TermsV3.GAP_TERMS_VERSION`.
pub const GAP_TERMS_VERSION: u128 = 3;

/// `TermsV3.termsHash` since v3c (audit r1 L-3): the v2 form's words -- eight, or a self-launch's
/// ten (`self_until != 0`) -- and then `uint256 GAP_TERMS_VERSION`. A v3 launch signs this, so a
/// snapshot signed for the live v2 factory (whose terms never carry the word) cannot open a v3
/// store, and a v3 snapshot cannot open a v2 one.
pub fn terms_hash_v3(
    payee_evm: &[u8; 20],
    payee_solana: &[u8; 32],
    fee_eid: u32,
    fee_min: u64,
    b: &TermsBinding,
    self_until: u32,
    leg_fees: &[u8; 32],
) -> [u8; 32] {
    let mut evm = [0u8; 32];
    evm[12..].copy_from_slice(payee_evm);
    let (eid, min, until, version) = (word(fee_eid as u128), word(fee_min as u128), word(self_until as u128), word(GAP_TERMS_VERSION));
    let mut parts: Vec<&[u8]> = vec![&evm, payee_solana, &eid, &min, &b.payer, &b.metadata, &b.creator_solana, &b.quote_solana];
    if self_until != 0 {
        parts.push(&until);
        parts.push(leg_fees);
    }
    parts.push(&version);
    keccak::hashv(&parts).0
}

/// `LaunchFactoryBaseV2.metadataHash`: `keccak256(abi.encode(string name, string symbol, string
/// metadataURI))` -- three dynamic strings: three head words of offsets, then each string's
/// length word and its bytes padded to a whole number of words. `uri` is the exact `ipfs://...`
/// string the program writes into the mint (`launch_leg::ipfs_uri`).
pub fn metadata_hash(name: &str, symbol: &str, uri: &str) -> [u8; 32] {
    let padded = |s: &str| s.len().div_ceil(32) * 32;
    let mut out: Vec<u8> = Vec::with_capacity(96 + 3 * 32 + padded(name) + padded(symbol) + padded(uri));
    let mut offset = 96usize;
    for s in [name, symbol, uri] {
        out.extend_from_slice(&word(offset as u128));
        offset += 32 + padded(s);
    }
    for s in [name, symbol, uri] {
        out.extend_from_slice(&word(s.len() as u128));
        out.extend_from_slice(s.as_bytes());
        out.resize(out.len() + (padded(s) - s.len()), 0);
    }
    keccak::hash(&out).0
}

/// `PriceAttestorV2.openingUsdPerToken(legs, cap, mode)` for a launch of `legs` chains with
/// `slice` on each: `floor(cap x 1e18 x legs / (total / 1e9))` in SLICE mode, `floor(cap x 1e18 /
/// (total / 1e9))` in TOTAL mode, `total = slice x legs` -- the same operations in the same order.
pub fn usd_per_token_v2(slice: u64, legs: usize, market_cap_usd: u32, supply_mode: u8) -> Result<u128> {
    usd_per_token_v2_from(slice, legs, market_cap_usd, supply_mode, MIN_MARKET_CAP_USD)
}

/// `usd_per_token_v2` with the floor `min_market_cap_usd` (v2: `MIN_MARKET_CAP_USD`; v3: the
/// admin's, `v3_min_market_cap`): `PriceAttestorV3.openingUsdPerTokenV3` for a v3 SLICE launch.
pub fn usd_per_token_v2_from(slice: u64, legs: usize, market_cap_usd: u32, supply_mode: u8, min_market_cap_usd: u32) -> Result<u128> {
    require!(
        (min_market_cap_usd..=MAX_MARKET_CAP_USD).contains(&market_cap_usd),
        SplitterError::MarketCapOutOfRange
    );
    let total = (slice as u128).checked_mul(legs as u128).ok_or(error!(SplitterError::PriceOutOfRange))?;
    opening_usd_per_token_from(total, legs, market_cap_usd, supply_mode, min_market_cap_usd)
}

/// `openingUsdPerToken` over a launch total given whole (the legs' slices added up), for any
/// split of it among `legs` chains: what the attestor computes, step for step.
pub fn opening_usd_per_token(total: u128, legs: usize, market_cap_usd: u32, supply_mode: u8) -> Result<u128> {
    opening_usd_per_token_from(total, legs, market_cap_usd, supply_mode, MIN_MARKET_CAP_USD)
}

/// `opening_usd_per_token` with the floor `min_market_cap_usd` (the same arithmetic).
pub fn opening_usd_per_token_from(total: u128, legs: usize, market_cap_usd: u32, supply_mode: u8, min_market_cap_usd: u32) -> Result<u128> {
    require!(
        (min_market_cap_usd..=MAX_MARKET_CAP_USD).contains(&market_cap_usd),
        SplitterError::MarketCapOutOfRange
    );
    require!(total > 0 && total % TOKEN_UNIT == 0, SplitterError::SupplyNotWholeTokens);
    let cap = market_cap_usd as u128 * WAD;
    let usd = match supply_mode {
        SUPPLY_SLICE => cap * (legs as u128) / (total / TOKEN_UNIT),
        SUPPLY_TOTAL => cap / (total / TOKEN_UNIT),
        _ => return err!(SplitterError::UnknownSupplyMode),
    };
    require!(usd > 0, SplitterError::PriceOutOfRange);
    Ok(usd)
}

/// What a v2 snapshot signs besides v1's fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotTerms {
    pub market_cap_usd: u32,
    pub supply_mode: u8,
    pub terms: [u8; 32],
}

/// PriceAttestorV2's digest: `keccak(0x1901 || domainSeparator("PangeaLaunchPrice", "3") ||
/// structHash)`, the struct encoded in `SNAPSHOT_TYPE_V3`'s order, each leg with its own fee.
pub fn snapshot_digest_v2(launch_id: &[u8; 32], t: &SnapshotTerms, usd_per_token: u128, deadline: u64, legs: &[Leg]) -> [u8; 32] {
    let domain = keccak::hashv(&[
        &keccak::hash(DOMAIN_TYPE).0,
        &keccak::hash(DOMAIN_NAME).0,
        &keccak::hash(DOMAIN_VERSION_V3).0,
    ])
    .0;
    let leg_type = keccak::hash(LEG_TYPE_V3).0;
    let mut leg_hashes: Vec<u8> = Vec::with_capacity(32 * legs.len());
    for l in legs {
        let h = keccak::hashv(&[&leg_type, &word(l.eid as u128), &word(l.usd_per_quote), &l.token, &word(l.slice), &word(l.fee_bps as u128)]).0;
        leg_hashes.extend_from_slice(&h);
    }
    let structured = keccak::hashv(&[
        &keccak::hash(SNAPSHOT_TYPE_V3).0,
        launch_id,
        &word(t.market_cap_usd as u128),
        &word(t.supply_mode as u128),
        &t.terms,
        &word(usd_per_token),
        &word(deadline as u128),
        &keccak::hash(&leg_hashes).0,
    ])
    .0;
    keccak::hashv(&[&[0x19, 0x01], &domain, &structured]).0
}

/// A v2 launch's price, as its transaction carries it (`launch_v2::LaunchV2Args`): the deadline,
/// each leg's `usdPerQuote` (already widened from the wire's six bytes), and the signature as
/// r || s || v, v 27 or 28 (widened from the wire's 64-byte compact form).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct SignedPriceV2 {
    pub deadline: u64,
    pub usd_per_quote: Vec<u128>,
    pub signature: Vec<u8>,
}

/* The v2 wire's decimal numbers. A launch transaction that a creator's wallet sends has to fit
   1,232 bytes through the shared lookup table, so the amounts it carries travel as a mantissa
   and a power of ten: exact, for any value written with that many significant digits, which is
   what the platform quotes and signs (it rounds to them first). */

/// The four bytes a v2 leg's price travels in: a little-endian u32 whose low five bits are `e`
/// and high 27 bits `m`; `usdPerQuote = m x 10^e`. Eight significant digits (to a hundred-
/// millionth of the price). The signer rounds each price to eight leading digits.
pub const WIRE_PRICE_LEN: usize = 4;
pub const WIRE_PRICE_MANTISSA_MAX: u64 = (1 << 27) - 1;

pub fn decode_usd_per_quote(b: &[u8; WIRE_PRICE_LEN]) -> Option<u128> {
    let w = u32::from_le_bytes(*b);
    10u128.checked_pow(w & 31)?.checked_mul((w >> 5) as u128)
}

/// The shortest wire form of `v`, or None when it has more than eight significant digits' worth
/// of mantissa or needs an exponent past 31.
pub fn encode_usd_per_quote(v: u128) -> Option<[u8; WIRE_PRICE_LEN]> {
    let (m, e) = mantissa(v, WIRE_PRICE_MANTISSA_MAX)?;
    if e > 31 {
        return None;
    }
    Some((((m as u32) << 5) | e as u32).to_le_bytes())
}

/// `v = m x 10^e` with `m <= max`, `e` as small as it can be; None if no such `m` exists.
fn mantissa(v: u128, max: u64) -> Option<(u64, u8)> {
    let (mut m, mut e) = (v, 0u8);
    while m > max as u128 {
        if m % 10 != 0 {
            return None;
        }
        m /= 10;
        e += 1;
    }
    Some((m as u64, e))
}

/// The five bytes a v2 amount travels in (the slice, the dev buy, the fee minimum): one byte `e`,
/// then a little-endian u32 `m`; `value = m x 10^e`. Nine significant digits.
pub const WIRE_AMOUNT_LEN: usize = 5;

pub fn decode_amount(b: &[u8; WIRE_AMOUNT_LEN]) -> Option<u64> {
    let m = u32::from_le_bytes(b[1..].try_into().ok()?) as u64;
    10u64.checked_pow(b[0] as u32)?.checked_mul(m)
}

/// The wire form of an amount, or None when it has more than nine significant digits.
pub fn encode_amount(v: u64) -> Option<[u8; WIRE_AMOUNT_LEN]> {
    let (m, e) = mantissa(v as u128, u32::MAX as u64)?;
    let mut out = [0u8; WIRE_AMOUNT_LEN];
    out[0] = e;
    out[1..].copy_from_slice(&(m as u32).to_le_bytes());
    Some(out)
}

/// The legs' pool fees on the v2 wire: nine bits each (every chain's fee is 30-500 bps, below
/// 2^9), legs ascending by eid, packed least-significant bit first into `fees_wire_len` bytes;
/// the bits past the last fee are zero. Five legs: six bytes, where a u16 each would be ten.
pub const WIRE_FEE_BITS: usize = 9;

pub const fn fees_wire_len(legs: usize) -> usize {
    (legs * WIRE_FEE_BITS).div_ceil(8)
}

/// The most legs the fee wire packs: a u128 holds the bits (a launch has at most
/// `PEER_CHAINS.len() + 1`, never past eight).
pub const MAX_WIRE_FEE_LEGS: usize = 128 / WIRE_FEE_BITS;

/// The wire form of the legs' fees, or None for a fee past 2^9 - 1 (or more than
/// `MAX_WIRE_FEE_LEGS` of them).
pub fn encode_fees(fees: &[u16]) -> Option<Vec<u8>> {
    if fees.len() > MAX_WIRE_FEE_LEGS {
        return None;
    }
    let mut acc = 0u128;
    for (i, f) in fees.iter().enumerate() {
        if *f >> WIRE_FEE_BITS != 0 {
            return None;
        }
        acc |= (*f as u128) << (i * WIRE_FEE_BITS);
    }
    Some(acc.to_le_bytes()[..fees_wire_len(fees.len())].to_vec())
}

/// `legs` fees out of their wire form, or None when it is not `fees_wire_len(legs)` bytes or a bit
/// past the last fee is set (one wire form for one list of fees).
pub fn decode_fees(b: &[u8], legs: usize) -> Option<Vec<u16>> {
    if legs > MAX_WIRE_FEE_LEGS || b.len() != fees_wire_len(legs) {
        return None;
    }
    let mut wide = [0u8; 16];
    wide[..b.len()].copy_from_slice(b);
    let acc = u128::from_le_bytes(wide);
    if acc >> (legs * WIRE_FEE_BITS) != 0 {
        return None;
    }
    Some((0..legs).map(|i| ((acc >> (i * WIRE_FEE_BITS)) & ((1 << WIRE_FEE_BITS) - 1)) as u16).collect())
}

/// A compact (EIP-2098) signature, `r || yParity << 255 | s`, widened to r || s || v.
pub fn widen_signature(compact: &[u8; 64]) -> [u8; 65] {
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(compact);
    let parity = out[32] >> 7;
    out[32] &= 0x7f;
    out[64] = 27 + parity;
    out
}

/// r || s || v, v 27 or 28, as the compact form: what the wire carries.
pub fn compact_signature(sig: &[u8; 65]) -> Option<[u8; 64]> {
    if !(sig[64] == 27 || sig[64] == 28) || sig[32] & 0x80 != 0 {
        return None;
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&sig[..64]);
    out[32] |= (sig[64] - 27) << 7;
    Some(out)
}

/// What a v2 launch states about its snapshot, besides the v1 fields `verified_opening_price`
/// takes: the terms the program rebuilt, and the market cap and supply mode. `min_market_cap_usd`
/// is not signed: the floor the cap is held to (v2 `MIN_MARKET_CAP_USD`, v3 the admin's).
#[derive(Clone, Copy, Debug)]
pub struct V2Price<'a> {
    pub price: &'a SignedPriceV2,
    pub terms: SnapshotTerms,
    pub min_market_cap_usd: u32,
}

/// `verified_opening_price`, for a v2 snapshot: its digest is PriceAttestorV2's, and `usdPerToken`
/// is the one the market cap and supply mode give. Every leg's fee is signed: Solana's `fee_bps`
/// (the pool opened here), each peer's in `peer_fee_bps`, in the peers' order. Returns the opening
/// square-root price.
#[allow(clippy::too_many_arguments)]
pub fn verified_opening_price_v2(
    p: &V2Price,
    signer: &[u8; 20],
    launch_id: &[u8; 32],
    fee_bps: u16,
    peer_fee_bps: &[u16],
    peers: &[(u32, [u8; 20])],
    oft_store: &Pubkey,
    slice: u64,
    quote_decimals: u8,
    band: PriceBand,
    now: i64,
) -> Result<u128> {
    require!(*signer != [0u8; 20], SplitterError::PriceNotSigned);
    let deadline = i64::try_from(p.price.deadline).map_err(|_| error!(SplitterError::PriceExpired))?;
    require!(now <= deadline, SplitterError::PriceExpired);
    require!(deadline <= now.saturating_add(MAX_DEADLINE_WINDOW), SplitterError::PriceExpired);
    let legs = launch_legs_v3(peers, peer_fee_bps, fee_bps, oft_store, slice, &p.price.usd_per_quote)?;
    let usd_token = usd_per_token_v2_from(slice, legs.len(), p.terms.market_cap_usd, p.terms.supply_mode, p.min_market_cap_usd)?;
    let digest = snapshot_digest_v2(launch_id, &p.terms, usd_token, p.price.deadline, &legs);
    let signature: [u8; 65] = p.price.signature.as_slice().try_into().map_err(|_| error!(SplitterError::PriceNotSigned))?;
    require!(recover_signer(&digest, &signature)? == *signer, SplitterError::PriceNotSigned);
    let solana = legs.iter().find(|l| l.eid == SOLANA_EID).ok_or(error!(SplitterError::PriceNotSigned))?;
    require!(in_band(solana.usd_per_quote, band), SplitterError::PriceOutOfRange);
    opening_sqrt_price(usd_token, solana.usd_per_quote, quote_decimals)
}

// ------------------------------------------------------------------------ set_price_signer

#[derive(Accounts)]
pub struct SetPriceSigner<'info> {
    #[account(
        init_if_needed,
        payer = admin,
        space = 8 + PriceSigner::INIT_SPACE,
        seeds = [PRICE_SIGNER_SEED],
        bump
    )]
    pub price_signer: Account<'info, PriceSigner>,
    #[account(mut, address = crate::ADMIN @ SplitterError::NotAdmin)]
    pub admin: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[event]
pub struct PriceSignerSet {
    pub address: [u8; 20],
}

pub fn set_price_signer_handler(ctx: Context<SetPriceSigner>, address: [u8; 20]) -> Result<()> {
    require!(address != [0u8; 20], SplitterError::ZeroAddress);
    let p = &mut ctx.accounts.price_signer;
    p.address = address;
    p.bump = ctx.bumps.price_signer;
    emit!(PriceSignerSet { address });
    Ok(())
}

#[event]
pub struct NativePriceBandSet {
    pub min_usd_per_quote: u128,
    pub max_usd_per_quote: u128,
}

/// Set wrapped SOL's price band: USD per SOL, 1e18-scaled. Admin only (the same accounts as
/// `set_price_signer`; the signer's address is left as it is).
pub fn set_native_price_band_handler(ctx: Context<SetPriceSigner>, min_usd_per_quote: u128, max_usd_per_quote: u128) -> Result<()> {
    check_band(min_usd_per_quote, max_usd_per_quote)?;
    let p = &mut ctx.accounts.price_signer;
    p.native_min_usd_per_quote = min_usd_per_quote;
    p.native_max_usd_per_quote = max_usd_per_quote;
    p.bump = ctx.bumps.price_signer;
    emit!(NativePriceBandSet { min_usd_per_quote, max_usd_per_quote });
    Ok(())
}

// ------------------------------------------------------------------------ set_gap_v3_launches

/// Pangea v3 gap fee (audit r1 L-1, L-3): whether `launch_v2` and `launch_self` may make v3 OFT
/// stores (`init_oft_v3`), in its own account `PDA(["gap_v3"])`, so the live 61-byte
/// `PriceSigner` is never resized. A launch is v3 only when it names this account in its
/// `dev_buy_account` place (`launch_v2::gap_v3_named`): it then verifies the v3 terms hash
/// (`terms_hash_v3`, the version word `GAP_TERMS_VERSION` signed) and needs `enabled`. A launch
/// naming none there is v2 exactly as before (v2 hash, v2 store, the same transaction bytes).
/// So the store's version is the signed snapshot's, never the flag's at landing time.
pub const GAP_V3_SEED: &[u8] = b"gap_v3";

/// How long a RAISE of the v3 minimum waits before it is in force (owner Q26, 2026-10-31): the
/// longest a signed snapshot may be good for, so one signed before the raise lands under the minimum
/// it was signed against. A lowering is in force at once. As `PriceAttestorV3.MIN_RAISE_DELAY`.
pub const V3_MIN_RAISE_DELAY: i64 = MAX_DEADLINE_WINDOW;

/// 26 bytes: 8 + enabled + bump + min_market_cap_usd + pending_min_market_cap_usd +
/// pending_effective_at (v3, owner 2026-10-31 and Q26; was 10 bytes before the minimum, 14 before
/// the raise delay -- the account is made at the v3 cutover, so no live one has an older size).
#[account]
#[derive(InitSpace)]
pub struct GapV3Launches {
    pub enabled: bool,
    pub bump: u8,
    /// The least opening market cap PER CHAIN a v3 launch may sign, whole dollars, as last put in
    /// force: within [V3_MIN_MARKET_CAP_LOWER_BOUND_USD, V3_MIN_MARKET_CAP_UPPER_BOUND_USD], the
    /// admin's (`set_v3_min_market_cap`), V3_INITIAL_MIN_MARKET_CAP_USD when the account is made.
    pub min_market_cap_usd: u32,
    /// A raise waiting for `pending_effective_at` (0: none -- a raise is never 0). In force from then, with no write
    /// (`v3_min_in_force`); put in storage, with its event, by the next admin write.
    pub pending_min_market_cap_usd: u32,
    /// When `pending_min_market_cap_usd` is in force (unix seconds; 0 with no raise pending).
    pub pending_effective_at: i64,
}

#[derive(Accounts)]
pub struct SetGapV3Launches<'info> {
    #[account(
        init_if_needed,
        payer = admin,
        space = 8 + GapV3Launches::INIT_SPACE,
        seeds = [GAP_V3_SEED],
        bump
    )]
    pub gap_v3: Account<'info, GapV3Launches>,
    #[account(mut, address = crate::ADMIN @ SplitterError::NotAdmin)]
    pub admin: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[event]
pub struct GapV3LaunchesSet {
    pub enabled: bool,
}

/// The v3 minimum opening market cap per chain moved (`previous` 0: the account was just made).
#[event]
pub struct V3MinMarketCapSet {
    pub previous: u32,
    pub min_market_cap_usd: u32,
}

/// The admin raised the v3 minimum: `min_market_cap_usd` is in force from `effective_at` (Q26).
#[event]
pub struct V3MinMarketCapRaiseScheduled {
    pub current: u32,
    pub min_market_cap_usd: u32,
    pub effective_at: i64,
}

/// The v3 minimum in force at `now`: the pending raise once its time has come, else the stored one
/// (held to the bounds by `v3_min_market_cap`).
pub fn v3_min_in_force(g: &GapV3Launches, now: i64) -> u32 {
    if g.pending_min_market_cap_usd != 0 && now >= g.pending_effective_at {
        v3_min_market_cap(g.pending_min_market_cap_usd)
    } else {
        v3_min_market_cap(g.min_market_cap_usd)
    }
}

/// Put a raise whose time has come in force in storage, with its event.
fn activate_v3_min(g: &mut GapV3Launches, now: i64) {
    if g.pending_min_market_cap_usd != 0 && now >= g.pending_effective_at {
        let previous = g.min_market_cap_usd;
        g.min_market_cap_usd = g.pending_min_market_cap_usd;
        g.pending_min_market_cap_usd = 0;
        g.pending_effective_at = 0;
        emit!(V3MinMarketCapSet { previous, min_market_cap_usd: g.min_market_cap_usd });
    }
}

/// A new gap_v3 account starts at the initial minimum, with its event.
fn init_v3_min(g: &mut GapV3Launches) {
    if g.min_market_cap_usd == 0 {
        g.min_market_cap_usd = V3_INITIAL_MIN_MARKET_CAP_USD;
        emit!(V3MinMarketCapSet { previous: 0, min_market_cap_usd: V3_INITIAL_MIN_MARKET_CAP_USD });
    }
}

/// Allow (or stop) v3 launches. Admin only. Launches already made keep the store they were made
/// with; a launch signed for v2 stays v2 whatever this says (it never names the account).
pub fn set_gap_v3_launches_handler(ctx: Context<SetGapV3Launches>, enabled: bool) -> Result<()> {
    let g = &mut ctx.accounts.gap_v3;
    g.enabled = enabled;
    g.bump = ctx.bumps.gap_v3;
    init_v3_min(g);
    activate_v3_min(g, Clock::get()?.unix_timestamp);
    emit!(GapV3LaunchesSet { enabled });
    Ok(())
}

/// Set the v3 minimum opening market cap per chain (owner 2026-10-31). Admin only, within
/// [V3_MIN_MARKET_CAP_LOWER_BOUND_USD, V3_MIN_MARKET_CAP_UPPER_BOUND_USD]. Lower than (or equal to)
/// the one in force: in force at once (`V3MinMarketCapSet`), and a pending raise is dropped. Higher
/// (Q26): pending, in force V3_MIN_RAISE_DELAY from now (`V3MinMarketCapRaiseScheduled`); a second
/// raise replaces the first and its time starts again. Made with v3 launches off when the account
/// does not exist yet. v2 launches are not affected.
pub fn set_v3_min_market_cap_handler(ctx: Context<SetGapV3Launches>, min_market_cap_usd: u32) -> Result<()> {
    require!(
        (V3_MIN_MARKET_CAP_LOWER_BOUND_USD..=V3_MIN_MARKET_CAP_UPPER_BOUND_USD).contains(&min_market_cap_usd),
        SplitterError::V3MinMarketCapOutOfBounds
    );
    let now = Clock::get()?.unix_timestamp;
    let g = &mut ctx.accounts.gap_v3;
    g.bump = ctx.bumps.gap_v3;
    init_v3_min(g);
    activate_v3_min(g, now);
    let current = g.min_market_cap_usd;
    if min_market_cap_usd <= current {
        g.pending_min_market_cap_usd = 0;
        g.pending_effective_at = 0;
        g.min_market_cap_usd = min_market_cap_usd;
        emit!(V3MinMarketCapSet { previous: current, min_market_cap_usd });
    } else {
        let effective_at = now.saturating_add(V3_MIN_RAISE_DELAY);
        g.pending_min_market_cap_usd = min_market_cap_usd;
        g.pending_effective_at = effective_at;
        emit!(V3MinMarketCapRaiseScheduled { current, min_market_cap_usd, effective_at });
    }
    Ok(())
}

/// The v3 minimum a gap_v3 account holds; the initial one for a value outside the bounds (which
/// only an account never written by a handler could hold).
pub fn v3_min_market_cap(stored: u32) -> u32 {
    if (V3_MIN_MARKET_CAP_LOWER_BOUND_USD..=V3_MIN_MARKET_CAP_UPPER_BOUND_USD).contains(&stored) {
        stored
    } else {
        V3_INITIAL_MIN_MARKET_CAP_USD
    }
}

/// The switch `info` holds, when it is this program's `GapV3Launches` -- which only
/// `PDA(["gap_v3"])` can be: the one place `SetGapV3Launches` makes one (by its seeds), and no
/// other instruction writes that discriminator. None for any other account.
pub fn gap_v3_switch(info: &AccountInfo) -> Option<bool> {
    gap_v3_config(info).map(|(enabled, _)| enabled)
}

/// The switch and the v3 minimum opening market cap per chain IN FORCE now (`v3_min_in_force`: a
/// pending raise once its time has come; Q26) `info` holds, when it is this program's
/// `GapV3Launches`; None for any other account (or no clock).
pub fn gap_v3_config(info: &AccountInfo) -> Option<(bool, u32)> {
    if *info.owner != crate::ID {
        return None;
    }
    let data = info.try_borrow_data().ok()?;
    GapV3Launches::try_deserialize(&mut &data[..]).ok().map(|g| {
        // No clock (never on chain): the stricter of the two, never the lower.
        let min = match Clock::get() {
            Ok(c) => v3_min_in_force(&g, c.unix_timestamp),
            Err(_) => v3_min_in_force(&g, i64::MAX).max(v3_min_market_cap(g.min_market_cap_usd)),
        };
        (g.enabled, min)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// v3 at $600 a chain (owner 2026-10-31): 1B on each of five chains, 9-decimal token, against SOL
    /// (9 decimals) or a USDC-like quote (6) from $0.01 to $10,000,000 a unit -- and at $500,000 a chain:
    /// the DAMM v2 opening sqrt price is inside Meteora's range with room on both sides, and squares back
    /// to the attested price within 0.01% (no tick rounding on DAMM v2; the floor of quotePerToken, the
    /// attestor's own arithmetic, is the only loss: ~1.7e-5 at $10M a quote unit).
    #[test]
    fn six_hundred_dollars_a_chain_opens_inside_damm_v2s_range_at_every_quote_price() {
        let slice = 1_000_000_000_000_000_000u64; // 1B x 1e9
        for cap in [V3_INITIAL_MIN_MARKET_CAP_USD, 3_000, MAX_MARKET_CAP_USD] {
            let usd = usd_per_token_v2_from(slice, 5, cap, SUPPLY_SLICE, V3_MIN_MARKET_CAP_LOWER_BOUND_USD).unwrap();
            if cap == 600 {
                assert_eq!(usd, 600_000_000_000, "$600 over 1B tokens: 6e-7 USD a token");
            }
            for usd_per_quote in [10u128.pow(16), WAD, 150 * WAD, 3_000 * WAD, 100_000 * WAD, 10_000_000 * WAD] {
                for dec in [9u8, 6] {
                    let s = opening_sqrt_price(usd, usd_per_quote, dec).unwrap();
                    // Inside Meteora's range always; for SOL (9 decimals) with a thousandfold room on
                    // each side at every price from $0.01 to $10M (a 6-decimal asset at $100k+ a unit
                    // sits nearer the bottom, still inside).
                    assert!(s > CP_AMM_MIN_SQRT_PRICE && s < crate::CP_AMM_MAX_SQRT_PRICE, "cap {cap} quote {usd_per_quote} dec {dec}: {s}");
                    if dec == 9 {
                        assert!(s > CP_AMM_MIN_SQRT_PRICE * 1_000 && s < crate::CP_AMM_MAX_SQRT_PRICE / 1_000, "SOL: cap {cap} quote {usd_per_quote}: {s}");
                    }
                    // raw quote units per raw token unit, as the pool reads s: (s / 2^64)^2
                    let got = (s as f64 / 2f64.powi(64)).powi(2);
                    let want = (usd as f64 / usd_per_quote as f64) * 10f64.powi(dec as i32) / 1e9;
                    assert!(((got - want) / want).abs() < 1e-4, "cap {cap} quote {usd_per_quote} dec {dec}: {got} vs {want}");
                }
            }
        }
        // Below the v3 floor nothing is priced; v2's floor is unchanged.
        assert!(usd_per_token_v2_from(slice, 5, 599, SUPPLY_SLICE, V3_MIN_MARKET_CAP_LOWER_BOUND_USD).is_err());
        assert!(usd_per_token_v2(slice, 5, 600, SUPPLY_SLICE).is_err());
    }

    #[test]
    fn three_thousand_dollars_over_a_billion_tokens_is_3e12() {
        // 1B whole tokens, 9 decimals, on each of five chains: 1e18 base units each, $3,000 a chain.
        assert_eq!(usd_per_token(1_000_000_000_000_000_000, 5).unwrap(), 3_000_000_000_000);
        // The same per-token price whatever the number of chains.
        assert_eq!(usd_per_token(1_000_000_000_000_000_000, 2).unwrap(), 3_000_000_000_000);
        // A 200M slice: $3,000 over 200M tokens.
        assert_eq!(usd_per_token(200_000_000_000_000_000, 5).unwrap(), 15_000_000_000_000);
        // The prepare route's floor division, at a supply that does not divide: 1.4B a chain.
        assert_eq!(usd_per_token(1_400_000_000_000_000_000, 5).unwrap(), 3_000 * WAD * 5 / 7_000_000_000);
        assert!(usd_per_token(200_000_000_000_000_001, 5).is_err(), "not whole tokens");
    }

    #[test]
    fn the_square_root_is_exact_and_floored() {
        for (n, d) in [(1u128, 3u128), (123_456_789, 1_000_000_000_000_000_000_000_000_000), (u64::MAX as u128, 7)] {
            let x = shifted_quotient((0, n), d).unwrap();
            let s = isqrt_capped(x, u128::MAX);
            assert!(mul_wide(s, s) <= x && mul_wide(s + 1, s + 1) > x, "{n}/{d}");
        }
        assert_eq!(mul_wide(u128::MAX, u128::MAX), (u128::MAX - 1, 1));
        // The division: q x d + r is the numerator again, r below d, for divisors of every size.
        for n in [(0u128, 0u128), (0, 1), (0, u128::MAX), (1, 0), (u128::MAX, u128::MAX), (0x1234, 0xfeed_beef), (3, 7)] {
            for d in [1u128, 2, 3, 10u128.pow(27), u64::MAX as u128, 1 << 127, u128::MAX] {
                let (q, r) = div_rem_256(n, d);
                assert!(r < d, "{n:?}/{d}");
                // q x d + r, in 256 bits.
                let (c, lo) = mul_wide(q.1, d);
                let (over, mid) = mul_wide(q.0, d);
                let (hi, carried) = mid.overflowing_add(c);
                let (lo2, carry) = lo.overflowing_add(r);
                assert!(over == 0 && !carried);
                assert_eq!((hi + carry as u128, lo2), n, "{n:?}/{d}");
            }
        }
        assert_eq!(shifted_quotient((1, 0), 1), None, "a quotient past 256 bits is refused, not truncated");
        // And the chunked division agrees with the bit-by-bit one, whole and fraction.
        let d27 = 10u128.pow(27);
        for n in [(0u128, 0u128), (0, 1), (0, u128::MAX), (0x3fff, 12345), (0, 3 * d27), (0, d27 - 1), ((1 << 26) - 1, u128::MAX)] {
            let (whole, rem) = div_rem_256(n, d27);
            let want = if whole.0 != 0 { None } else { Some((whole.1, div_rem_256((rem, 0), d27).0 .1)) };
            assert_eq!(shifted_quotient(n, d27), want, "{n:?}");
        }
    }

    #[test]
    fn a_band_holds_what_is_inside_it_and_an_unset_band_holds_nothing() {
        assert!(in_band(200 * WAD, (20 * WAD, 2_000 * WAD)));
        assert!(in_band(20 * WAD, (20 * WAD, 2_000 * WAD)) && in_band(2_000 * WAD, (20 * WAD, 2_000 * WAD)), "the ends are inside");
        assert!(!in_band(20 * WAD - 1, (20 * WAD, 2_000 * WAD)) && !in_band(2_000 * WAD + 1, (20 * WAD, 2_000 * WAD)));
        assert!(!in_band(WAD, (0, 0)) && !in_band(0, (0, 0)), "no band, nothing in it");
        assert!(!in_band(WAD, (2 * WAD, WAD)), "a band the wrong way round holds nothing");
        assert!(check_band(1, 2).is_ok());
        assert!(check_band(0, 2).is_err() && check_band(2, 2).is_err() && check_band(3, 2).is_err());
    }

    /// Supplies of a few whole tokens and 18-decimal quote assets take the products past 128
    /// bits; the EVM chains price them, and so does this.
    #[test]
    fn small_supplies_and_eighteen_decimal_quotes_are_priced_in_256_bits() {
        // One token per leg, five legs: usdPerToken is 3,000e18, and x 1e18 does not fit a u128.
        let usd = usd_per_token(1_000_000_000, 5).unwrap();
        assert_eq!(usd, 3_000 * WAD);
        assert!(usd.checked_mul(WAD).is_none());
        // Against SOL at $200: 15 SOL a token, sqrt(15) x 2^64.
        let s = opening_sqrt_price(usd, 200 * WAD, 9).unwrap();
        let expected = 15f64.sqrt() * 18_446_744_073_709_551_616f64;
        assert!(((s as f64) - expected).abs() / expected < 1e-12, "{s} vs {expected}");
        // An 18-decimal quote at $1, 3,000 of it a token: quotePerToken x 1e18 is past 128 bits too.
        let s = opening_sqrt_price(usd, WAD, 18).unwrap();
        let expected = (3_000f64 * 1e9).sqrt() * 18_446_744_073_709_551_616f64;
        assert!(((s as f64) - expected).abs() / expected < 1e-12, "{s} vs {expected}");
    }

    #[test]
    fn a_launch_against_sol_opens_where_the_formula_says() {
        // $3,000 over 1B tokens against SOL at $150: 2e-5 SOL per token... as Q64.64 in base units.
        let s = opening_sqrt_price(3_000_000_000_000, 150 * WAD, 9).unwrap();
        // quotePerToken = 3e12 * 1e18 / 150e18 = 2e10; raw = 2e10 * 1e9 / 1e27 = 2e-8;
        // sqrt(2e-8) * 2^64 = 1.414213562e-4 * 18446744073709551616 = 2,608,763,543,...
        let expected = (2e-8f64).sqrt() * 18_446_744_073_709_551_616f64;
        assert!(((s as f64) - expected).abs() / expected < 1e-12, "{s} vs {expected}");
    }
}
