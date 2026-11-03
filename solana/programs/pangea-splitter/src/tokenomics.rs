//! Tokenomics on Solana: a launch's creator fees spent by a fixed split, as on the EVM chains.
//!
//! ## What it is
//!
//! A tokenomics launch names, as its Solana creator, a `Tokenomics` account of this program instead
//! of a wallet. `claim_fees` then pays the creator's share of the pool's fees into that account's
//! wrapped-SOL account (an account of a program is not a plain wallet, so the native-SOL payout
//! declines and pays the same amount as wrapped SOL), and `execute` -- which anyone may call --
//! spends it by the split the launch was made with, for good:
//!
//! | bucket    | what `execute` does with it                                                          |
//! |-----------|--------------------------------------------------------------------------------------|
//! | burn      | buys the coin on its own Meteora pool and sends it to the incinerator's account       |
//! | buyback   | buys the coin and sends it to the treasury's account                                  |
//! | liquidity | buys the coin's share of an add and adds both to the pool on the account's own        |
//! |           | position, locked for good (`permanent_lock_position`); coins an add cannot use wait   |
//! | creator   | pays the owner, in SOL                                                                |
//! | community | pays the community wallet, in SOL                                                     |
//!
//! The platform takes nothing from it. There is no admin: nothing here can change a split, a
//! recipient (only each recipient may hand its own role on, two-step) or where a run's money goes.
//!
//! ## The same config as the EVM chains
//!
//! The EVM vault's address is a CREATE2 clone salted with `keccak256(abi.encode(config))`, the
//! config being `(launchId, owner, treasury, community, legs)` with EVM addresses and one leg (eid
//! and five shares) per chain. A tokenomics launch's config carries a leg for Solana too (eid
//! `SOLANA_EID`; the EVM factory accepts a leg for any chain and each vault reads only its own).
//! `init_tokenomics` takes the whole config, hashes it exactly as the EVM factory does
//! (`evm_config_hash`), and takes Solana's split from Solana's leg: so the split here is provably
//! the config's. Solana's recipients cannot be in the EVM config (its addresses are 20 bytes), so
//! they are bound in beside it: the account is at
//! `PDA(["tokenomics", keccak256(DOMAIN || evm_config_hash || owner || treasury || community)])`.
//!
//! ## Life of one
//!
//!  1. `init_tokenomics`, before the launch (the worker): the account and its wrapped-SOL account.
//!  2. The launch, with the account as its creator. A dev buy paid from the owner's own payment is
//!     the creator's (`pays_for`): its coins land in the launch's slice account, now the account's,
//!     and what the payment held above the buy lands in the account's lamports.
//!  3. `bind` (anyone, with the launch's seed): fixes the coin, the pool and the launch's record.
//!  4. `forward_refund` / `forward_coins` (anyone): the dev buy's coins and every lamport the
//!     account holds above its rent go to the owner. They are the owner's, never fees: fees only
//!     ever arrive as wrapped SOL.
//!  5. `open_lp_position` (anyone, once) when the split has a liquidity share: the opener fronts the
//!     position's rent and is repaid it, up to `MAX_POSITION_REPAY_LAMPORTS`, out of the liquidity
//!     bucket -- the position is that share's, so its rent is too (the owner's decision, 2026-10-24).
//!  6. `execute` (anyone), as often as the ADMIN's cooldown lets it (3 seconds by default).
//!
//! ## At the market price, never queued (the owner's decisions, 2026-10-22 and 2026-10-29)
//!
//! The buying buckets buy at whatever the pool's price is when a run comes. There is no price
//! reference: a run that lands on a price somebody pushed up buys at that price. Two rules the
//! ADMIN sets (`tokenomics_v2::Tk2Swap`, in `PDA(["tk2-min"])`) pace the swaps; until set they are
//! the defaults -- 3 seconds, a move of up to the pool's fee (until 2026-10-29: fixed at one swap
//! every 15 minutes and one fee):
//!
//!  * `swap_cooldown_secs` (default 3, at least 3): the least time between two swaps (or adds) of an
//!    account -- never 0, so that one bundle (one slot, one clock) holds at most one run of it;
//!  * one swap for the three buying buckets together, its impact capped at `max_move_fee_bps` of
//!    the pool's own fee (default and most 10,000: the fee): sized from the pool's locked liquidity
//!    with a 1% margin and checked on the pool's price after (`PriceMovedTooFar`). What a run cannot
//!    spend within the cap is spent by the next run, seconds later -- never in one swap that moves its
//!    own pool further. A sandwich across transactions (push the price, let the run buy, sell back)
//!    pays the fee on both legs and wins at most the run's move (per run: a push held over several
//!    runs seconds apart wins each one's -- the ADMIN's cooldown or a lower cap is the knob for a thin pool): at one fee it loses unless it takes
//!    back over half the fee. The swap's minimum out (`SWAP_OUT_MARGIN_BPS` under what the pool as
//!    found returns) bounds Meteora's rounding and fee, not a price moved before the run;
//!  * `execute` runs only as a top-level instruction of a transaction holding nothing but
//!    compute-budget instructions, this program's and the associated-token program's, and at most
//!    one `execute_tokenomics`: no instruction in the same transaction can move the pool's price
//!    first. A bundle of transactions still can: that is the accepted risk.
//!
//! The liquidity add is not capped in size (the owner's decision, 2026-10-22): it pairs all it can at
//! the price as it stands, so an add at a pushed price loses when the price comes back -- the
//! accepted risk. Every add refreshes the cooldown, as a swap does.
//!
//! ## The caller's fee
//!
//! Only the operator `Tk2Config` names (`PDA(["tk2-config"])`) is repaid; any other caller is
//! repaid nothing and nothing is held back for it (owner, 2026-10-27). The operator is repaid what
//! its transaction cost -- 5,000 lamports for each signer the transaction's instructions name, the
//! priority fee as the runtime charges it (the unit price times the unit limit the transaction
//! declares, 200,000 when it declares none, the price counted up to `MAX_CU_PRICE` and the limit up
//! to `MAX_CU_LIMIT`, rounded up as the runtime rounds) and the rent the run made it pay and not
//! get back (a missing incinerator coin account's) -- times (1 + `margin_bps`), the ADMIN's rules in
//! `PDA(["tk2-min"])` (`tokenomics_v2::Tk2Min`). A run whose repayment would be above `cap_bps` of
//! what it pays out is refused (`RepayOverCap`), never paid capped. A swapping bucket holds the
//! cap's share of what it spends back for the repayment, and what the repayment does not take stays
//! in it; a paying bucket pays out whole, less its share. (A caller that is the slot's leader gets
//! its priority fee back as the leader: that cannot be seen from here, and the cap bounds it.)

use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    incinerator,
    instruction::{get_stack_height, AccountMeta, Instruction, TRANSACTION_LEVEL_STACK_HEIGHT},
    keccak,
    program::invoke_signed,
    program_pack::Pack,
    system_instruction,
    sysvar::instructions as ixs,
};
use anchor_spl::associated_token::{self, get_associated_token_address_with_program_id, AssociatedToken};
use anchor_spl::token::spl_token;
use anchor_spl::token_2022::Token2022;
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface};

use crate::{fees::on_curve, launch_id_of, read_pool, read_position, venue, LaunchRecord, CP_AMM_ID, POSITION_SEED, SOLANA_EID, SPLITTER_SEED, TOKEN_A_SEED};

// ------------------------------------------------------------------------------ constants

/// `PDA(["tokenomics", seed])`, `seed` from the config (`TokenomicsConfig::seed`).
pub const TOKENOMICS_SEED: &[u8] = b"tokenomics";
/// `PDA(["tk-temp", tokenomics])`: the wrapped-SOL account a payout passes through to become SOL.
/// Made, filled and closed inside one instruction; between instructions never an account.
pub const TK_TEMP_SEED: &[u8] = b"tk-temp";
/// `PDA(["tk-lp", tokenomics])`: the mint of the NFT of the account's own liquidity position.
pub const TK_LP_SEED: &[u8] = b"tk-lp";
/// What the account's seed is hashed under, so that it can never be some other hash's preimage.
pub const TOKENOMICS_DOMAIN: &[u8] = b"pangea tokenomics solana v1";

pub const BURN: usize = 0;
pub const BUYBACK: usize = 1;
pub const LIQUIDITY: usize = 2;
pub const CREATOR: usize = 3;
pub const COMMUNITY: usize = 4;
/// The buckets this version spends. The account keeps room for `MAX_BUCKETS`, the config's
/// shares are a list and the recipients in its seed an ordered list, so a later bucket is a later
/// version of this module -- the same seed scheme, the same account layout -- not a new program.
pub const NUM_BUCKETS: usize = 5;
pub const MAX_BUCKETS: usize = 8;
/// The recipients this version names, in seed order: owner, treasury, community.
pub const NUM_RECIPIENTS: usize = 3;
pub const BPS: u64 = 10_000;
/// The EVM factory's `MAX_LEGS`.
pub const MAX_LEGS: usize = 8;

/// The least a bucket must hold before `execute` spends it: 0.025 SOL. (The EVM chains' are about
/// $5 too, Ethereum's about $500.) The owner and the community wallet may take their own bucket at
/// any size (`claim_bucket`).
pub const MIN_EXECUTE_LAMPORTS: u64 = 25_000_000;
/// The 2% reserve `execute` set aside before the operator rule (2026-10-27); no instruction reads it now.
pub const MAX_REIMBURSE_BPS: u64 = 200;
/// The most `pay_tokenomics_holders` repays its caller's fee, whatever it declared: 0.0003 SOL. (`execute`,
/// `execute_tokenomics_v2` and `pay_tokenomics_wallets` no longer read it: the operator's cap does.)
pub const MAX_REPAY_LAMPORTS: u64 = 300_000;
/// The most `open_lp_position` repays its opener out of the liquidity bucket: the position's rent
/// (about 0.0099 SOL: the position, its NFT mint and NFT account), with room.
pub const MAX_POSITION_REPAY_LAMPORTS: u64 = 15_000_000;
/// A signature's fee.
pub const SIGNATURE_LAMPORTS: u64 = 5_000;
/// The highest compute-unit price (micro-lamports) and compute-unit limit a run is repaid at.
pub const MAX_CU_PRICE: u64 = 200_000;
/// The most compute units a run is repaid for: a full run (swap, add, lock, burn, payouts) measures
/// about 355,000-465,000 (`tests/tokenomics.rs`), so a caller declaring more than it needs -- or
/// filling the transaction with other work -- is not repaid for it.
pub const MAX_CU_LIMIT: u64 = 600_000;

/// Margins under exact figures, so Meteora's rounding never carries a step past what was sized.
pub const ROOM_MARGIN_BPS: u128 = 9_900;
pub const LIQUIDITY_MARGIN_BPS: u128 = 9_990;
/// The swap's minimum output, under what Meteora's arithmetic at the pool's base fee returns.
pub const SWAP_OUT_MARGIN_BPS: u128 = 9_800;

pub(crate) const COMPUTE_BUDGET_ID: Pubkey = pubkey!("ComputeBudget111111111111111111111111111111");
pub(crate) const POOL_AUTHORITY: Pubkey = pubkey!("HLnpSz9h2S4hiLQ43rnSD9XkcUThA7B8hQMKmDaiTLcC");

/// cp-amm's instructions.
pub(crate) const SWAP_DISCRIMINATOR: [u8; 8] = [248, 198, 158, 145, 225, 117, 135, 200];
pub(crate) const ADD_LIQUIDITY_DISCRIMINATOR: [u8; 8] = [181, 157, 89, 67, 143, 182, 52, 72];
pub(crate) const CREATE_POSITION_DISCRIMINATOR: [u8; 8] = [48, 215, 197, 153, 96, 203, 180, 133];
pub(crate) const LOCK_DISCRIMINATOR: [u8; 8] = [165, 176, 125, 6, 231, 171, 186, 213];

/// cp-amm's `Pool`, after its discriminator (the same offsets `tests/stress_support` reads).
const POOL_LIQUIDITY: usize = 360;
const POOL_SQRT_MIN: usize = 424;
const POOL_SQRT_MAX: usize = 440;
const POOL_SQRT_PRICE: usize = 456;
const POOL_STATUS: usize = 481;
/// The pool's liquidity locked for good (every position's permanently locked part): what the run's
/// caps are sized from, so that liquidity added for a moment cannot raise them.
const POOL_PERMANENT_LOCK_LIQUIDITY: usize = 552;
/// cp-amm's `Position`: its unlocked liquidity.
const POSITION_UNLOCKED: usize = 152;

// ------------------------------------------------------------------------------ the config

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct TokenomicsLeg {
    pub eid: u32,
    /// One share per bucket, in bucket order; `NUM_BUCKETS` of them in this version (the EVM
    /// struct's `uint16[5]`).
    pub bps: Vec<u16>,
}

/// The EVM config, as `TokenomicsFactory` hashes it, and Solana's three recipients.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct TokenomicsConfig {
    pub launch_id: [u8; 32],
    pub owner_evm: [u8; 20],
    pub treasury_evm: [u8; 20],
    pub community_evm: [u8; 20],
    pub legs: Vec<TokenomicsLeg>,
    /// Solana's recipients, in order: owner, treasury, community (`NUM_RECIPIENTS`). A zero key
    /// for a role no share uses.
    pub recipients: Vec<Pubkey>,
}

fn word_u(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&[0u8; 24]);
    out.extend_from_slice(&v.to_be_bytes());
}

fn word_addr(out: &mut Vec<u8>, a: &[u8; 20]) {
    out.extend_from_slice(&[0u8; 12]);
    out.extend_from_slice(a);
}

impl TokenomicsConfig {
    /// `abi.encode(TokenomicsConfig)`: the struct is dynamic (its legs are), so it is one offset
    /// word, then its head -- launchId, three addresses, the legs' offset -- then the legs: their
    /// count and each leg's six words (a leg is static: eid and five shares).
    pub fn evm_encoding(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 * (7 + (1 + NUM_BUCKETS) * self.legs.len()));
        word_u(&mut out, 0x20);
        out.extend_from_slice(&self.launch_id);
        word_addr(&mut out, &self.owner_evm);
        word_addr(&mut out, &self.treasury_evm);
        word_addr(&mut out, &self.community_evm);
        word_u(&mut out, 0xa0);
        word_u(&mut out, self.legs.len() as u64);
        for leg in &self.legs {
            word_u(&mut out, leg.eid as u64);
            for b in &leg.bps {
                word_u(&mut out, *b as u64);
            }
        }
        out
    }

    /// The EVM vault's CREATE2 salt: `keccak256(abi.encode(config))`.
    pub fn evm_config_hash(&self) -> [u8; 32] {
        keccak::hash(&self.evm_encoding()).to_bytes()
    }

    /// What the account's address is derived from.
    pub fn seed(&self) -> [u8; 32] {
        let h = self.evm_config_hash();
        let mut parts: Vec<&[u8]> = vec![TOKENOMICS_DOMAIN, &h];
        parts.extend(self.recipients.iter().map(|r| r.as_ref()));
        keccak::hashv(&parts).to_bytes()
    }

    pub fn owner(&self) -> Pubkey {
        self.recipients.first().copied().unwrap_or_default()
    }
    pub fn treasury(&self) -> Pubkey {
        self.recipients.get(1).copied().unwrap_or_default()
    }
    pub fn community(&self) -> Pubkey {
        self.recipients.get(2).copied().unwrap_or_default()
    }

    /// Solana's split: its leg's, or -- as the EVM vault does on a chain the config has no leg
    /// for -- everything to the creator, so no fees can be left where nothing spends them.
    pub fn solana_bps(&self) -> [u16; MAX_BUCKETS] {
        let mut out = [0u16; MAX_BUCKETS];
        match self.legs.iter().find(|l| l.eid == SOLANA_EID) {
            Some(l) => {
                let n = l.bps.len().min(MAX_BUCKETS);
                out[..n].copy_from_slice(&l.bps[..n]);
            }
            None => out[CREATOR] = BPS as u16,
        }
        out
    }

    /// The rules `TokenomicsFactory.check` holds a config to, and Solana's own for its recipients.
    pub fn check(&self) -> Result<()> {
        let n = self.legs.len();
        require!(n > 0 && n <= MAX_LEGS, TokenomicsError::BadConfig);
        require!(self.recipients.len() == NUM_RECIPIENTS, TokenomicsError::BadConfig);
        for (i, leg) in self.legs.iter().enumerate() {
            require!(leg.bps.len() == NUM_BUCKETS, TokenomicsError::BadConfig);
            require!(i == 0 || leg.eid > self.legs[i - 1].eid, TokenomicsError::BadConfig);
            require!(leg.bps.iter().map(|b| *b as u64).sum::<u64>() == BPS, TokenomicsError::BadConfig);
        }
        let bps = self.solana_bps();
        require!(self.owner() != Pubkey::default() && self.owner() != incinerator::ID, TokenomicsError::BadConfig);
        require!(bps[BUYBACK] == 0 || self.treasury() != Pubkey::default(), TokenomicsError::BadConfig);
        require!(bps[COMMUNITY] == 0 || self.community() != Pubkey::default(), TokenomicsError::BadConfig);
        // No recipient may be a key the runtime never lets a transaction write (agave's
        // `ReservedAccountKeys`: a builtin program, a sysvar, the native loader; `is_reserved_account`):
        // some are on the curve with no account, so they look like a payable wallet, and execute
        // would then refuse every run for good. The zero key stays allowed for a role no share uses.
        for r in [self.owner(), self.treasury(), self.community()] {
            require!(r == Pubkey::default() || !crate::is_reserved_account(&r), TokenomicsError::RecipientReserved);
        }
        Ok(())
    }
}

/// Split `amount` by `bps` (summing to 10,000): each part rounded down, the remainder to the first
/// bucket with a share. `TokenomicsMath.split`.
pub fn split(amount: u64, bps: &[u16; MAX_BUCKETS]) -> [u64; MAX_BUCKETS] {
    let mut out = [0u64; MAX_BUCKETS];
    let mut given = 0u64;
    let mut first = MAX_BUCKETS;
    for i in 0..MAX_BUCKETS {
        if bps[i] != 0 && first == MAX_BUCKETS {
            first = i;
        }
        out[i] = ((amount as u128 * bps[i] as u128) / BPS as u128) as u64;
        given += out[i];
    }
    if first < MAX_BUCKETS {
        out[first] += amount - given;
    }
    out
}

// ------------------------------------------------------------------------------ the account

#[account]
#[derive(InitSpace)]
pub struct Tokenomics {
    pub version: u8,
    pub bump: u8,
    pub bound: bool,
    /// How many buckets this account spends (`NUM_BUCKETS` in this version).
    pub num_buckets: u8,
    /// Solana's split: burn, buyback, liquidity, creator, community; the rest zero.
    pub bps: [u16; MAX_BUCKETS],
    /// `keccak256(abi.encode(config))`, the EVM vaults' salt.
    pub config_hash: [u8; 32],
    /// What the address is derived from (`TokenomicsConfig::seed`).
    pub seed: [u8; 32],
    pub launch_id: [u8; 32],
    pub owner: Pubkey,
    pub treasury: Pubkey,
    pub community: Pubkey,
    pub pending_owner: Pubkey,
    pub pending_treasury: Pubkey,
    pub pending_community: Pubkey,
    /// Fixed at `bind`: the coin, its pool, the launch's record, and the launch's slice account
    /// (where a dev buy's coins are).
    pub mint: Pubkey,
    pub pool: Pubkey,
    pub record: Pubkey,
    pub slice: Pubkey,
    /// The account's own liquidity position, once opened.
    pub lp_position: Pubkey,
    pub lp_nft_mint: Pubkey,
    /// Wrapped SOL each bucket holds, and has spent.
    pub buckets: [u64; MAX_BUCKETS],
    pub spent: [u64; MAX_BUCKETS],
    /// Payouts the owner's or the community's wallet could not take as SOL, kept for them.
    pub deferred_owner: u64,
    pub deferred_community: u64,
    /// Coins bought for liquidity that an add could not use yet.
    pub liquidity_coins: u64,
    /// Coins bought for the treasury that its account would not take (it requires a memo on every
    /// transfer in): kept here, the treasury's, until it takes them (`claim_tokenomics_treasury_coins`).
    pub treasury_coins: u64,
    pub last_swap: i64,
    pub created_at: i64,
    pub total_received: u64,
    pub coins_burned: u64,
    pub coins_to_treasury: u64,
    pub reimbursed: u64,
}

impl Tokenomics {
    /// Wrapped SOL that is some bucket's or somebody's.
    pub fn tracked(&self) -> u64 {
        self.buckets.iter().sum::<u64>() + self.deferred_owner + self.deferred_community
    }

    /// What the account's signer seeds are made of: its seed and its bump (`tk_seeds!`).
    pub fn seed_parts(&self) -> ([u8; 32], [u8; 1]) {
        (self.seed, [self.bump])
    }

}

/// Whether `creator` -- the account a launch names as its creator -- is the tokenomics account
/// OF THIS LAUNCH (its launch id, not bound yet) whose owner is `payer`: then `payer`'s own
/// payment is the creator's, dev buy and all (`launch_leg::check_dev_buy`). Read off the
/// account's data; no account is added to a launch. Another launch's account is not, so its
/// owner's payment is the fee, as anybody's is: its dev buy would land in a slice that account
/// never forwards.
pub fn pays_for(creator: &AccountInfo, payer: &Pubkey, launch_id: &[u8; 32]) -> bool {
    if *creator.owner != crate::ID {
        return false;
    }
    let Ok(data) = creator.try_borrow_data() else { return false };
    match Tokenomics::try_deserialize(&mut &data[..]) {
        Ok(t) => t.owner == *payer && t.launch_id == *launch_id && !t.bound,
        // A v2 account (`tokenomics_v2`) the same way: its owner's payment is the creator's.
        Err(_) => crate::tokenomics_v2::TokenomicsV2::try_deserialize(&mut &data[..]).is_ok_and(|t| t.owner == *payer && t.launch_id == *launch_id && !t.bound),
    }
}

/// Whether a Token-2022 account requires a memo on every transfer into it (its `MemoTransfer`
/// extension, type 8, enabled): a transfer this program makes into it would fail.
pub fn requires_memo(account: &AccountInfo) -> bool {
    if *account.owner != anchor_spl::token_2022::ID {
        return false;
    }
    let Ok(d) = account.try_borrow_data() else { return false };
    // The base account (165 bytes), its account-type byte, then the extensions: type, length, data.
    let mut at = 166;
    while at + 4 <= d.len() {
        let kind = u16::from_le_bytes([d[at], d[at + 1]]);
        let len = u16::from_le_bytes([d[at + 2], d[at + 3]]) as usize;
        if kind == 8 {
            return d.get(at + 4).copied() == Some(1);
        }
        if kind == 0 {
            break;
        }
        at += 4 + len;
    }
    false
}

// ------------------------------------------------------------------------------ math

pub fn median3(a: u128, b: u128, c: u128) -> u128 {
    let (a, b) = if a > b { (b, a) } else { (a, b) };
    let (b, c) = if b > c { (c, b) } else { (b, c) };
    let (_, b) = if a > b { (b, a) } else { (a, b) };
    let _ = c;
    b
}

type U256 = (u128, u128);

fn mul_full(a: u128, b: u128) -> U256 {
    const M: u128 = u64::MAX as u128;
    let (a0, a1, b0, b1) = (a & M, a >> 64, b & M, b >> 64);
    let (p00, p01, p10, p11) = (a0 * b0, a0 * b1, a1 * b0, a1 * b1);
    let mid = (p00 >> 64) + (p01 & M) + (p10 & M);
    let low = (p00 & M) | (mid << 64);
    let high = p11 + (p01 >> 64) + (p10 >> 64) + (mid >> 64);
    (high, low)
}

/// floor(a * b / d), or None when d is zero or the quotient does not fit 128 bits.
pub fn mul_div(a: u128, b: u128, d: u128) -> Option<u128> {
    if d == 0 {
        return None;
    }
    let (hi, lo) = mul_full(a, b);
    if hi >= d {
        return None;
    }
    // Long division of (hi, lo) by d; the remainder stays below d.
    let (mut r, mut q) = (hi, 0u128);
    for bit in (0..128).rev() {
        let carry = r >> 127;
        r = (r << 1) | ((lo >> bit) & 1);
        if carry == 1 || r >= d {
            r = r.wrapping_sub(d);
            q |= 1u128 << bit;
        }
    }
    Some(q)
}

/// ceil(a * b / d).
pub fn mul_div_up(a: u128, b: u128, d: u128) -> Option<u128> {
    let q = mul_div(a, b, d)?;
    let exact = mul_full(q, d) == mul_full(a, b);
    if exact {
        Some(q)
    } else {
        q.checked_add(1)
    }
}

pub fn isqrt(n: u128) -> u128 {
    if n < 2 {
        return n;
    }
    let mut x = 1u128 << ((128 - n.leading_zeros()).div_ceil(2));
    loop {
        let y = (x + n / x) >> 1;
        if y >= x {
            return x;
        }
        x = y;
    }
}

/// `1e18 * sqrt(1 + numerator / 1e9)`, rounded down: the factor a square-root price moves by when
/// the price moves by that fraction.
pub fn sqrt_factor(numerator: u64) -> u128 {
    isqrt((1_000_000_000u128 + numerator as u128) * 1_000_000_000_000_000_000_000_000_000)
}

/// The most one swap may make the coin dearer, over 1e9: `max_move_fee_bps` of the pool's fee
/// numerator `fee` (rounded down, the conservative side). 10,000 is the fee itself.
pub fn move_numerator(fee: u64, max_move_fee_bps: u16) -> u64 {
    ((fee as u128 * max_move_fee_bps as u128) / BPS as u128) as u64
}

/// The fraction `bps` of 10,000 as a numerator over 1e9.
pub const fn bps_numerator(bps: u64) -> u64 {
    bps * 100_000
}

/// The square-root price at which the coin is `numerator`/1e9 dearer than at `sqrt_price`. The
/// coin is token A and the price is SOL per coin, so dearer is HIGHER: rounded down, toward
/// `sqrt_price`, the conservative side of a bound on how far a buy may move it.
pub fn dearer_by(sqrt_price: u128, numerator: u64) -> Option<u128> {
    mul_div(sqrt_price, sqrt_factor(numerator), 1_000_000_000_000_000_000)
}

/// The square-root price at which the coin is that much CHEAPER: rounded up.
pub fn cheaper_by(sqrt_price: u128, numerator: u64) -> Option<u128> {
    mul_div_up(sqrt_price, 1_000_000_000_000_000_000, sqrt_factor(numerator))
}

/// The SOL, net of the fee, a buy must put in to move the price from `s` up to `limit` at
/// `liquidity`: `L * (limit - s) / 2^128`, rounded down, less one unit (Meteora rounds its own
/// step down, so a buy of exactly this stays at or under the limit).
pub fn net_to_reach(s: u128, limit: u128, liquidity: u128) -> u64 {
    if limit <= s || liquidity == 0 {
        return 0;
    }
    // L * d / 2^128 = mul_div(L, d, 2^128) -- 2^128 does not fit; take the high half of the product.
    let (hi, _) = mul_full(liquidity, limit - s);
    u64::try_from(hi).unwrap_or(u64::MAX).saturating_sub(1)
}

/// What to put in, gross, so that a fee of `numerator`/1e9 (rounded up by Meteora) leaves at most
/// `net`: floor(net * 1e9 / (1e9 - numerator)).
pub fn gross_for_net(net: u64, numerator: u64) -> u64 {
    if numerator >= 1_000_000_000 {
        return 0;
    }
    (net as u128 * 1_000_000_000 / (1_000_000_000 - numerator as u128)).min(u64::MAX as u128) as u64
}

/// What a buy of `lamports` returns, and where it leaves the price, at a fee of `numerator`/1e9:
/// `dev_buy::buy_output`, step for step, with the pool's own numerator.
pub fn buy(liquidity: u128, s: u128, numerator: u64, lamports: u64) -> Option<(u64, u128)> {
    if liquidity == 0 || s == 0 {
        return None;
    }
    let fee = ((lamports as u128 * numerator as u128) + 999_999_999) / 1_000_000_000;
    let net = lamports.checked_sub(u64::try_from(fee).ok()?)?;
    let next = s.checked_add(crate::shl128_div(net, liquidity)?)?;
    let tokens = crate::mul_div_floor(liquidity, next - s, s, next)?;
    Some((tokens, next))
}

/// The share of a liquidity add's VALUE that must be in the coin, 1e18-scaled, for the pool's range
/// `[a, b]` at `s` (all square roots, Q64.64). With the coin as token A and the price SOL per coin:
///
/// ```text
/// coin = L (b - s) / (s b)     worth  L (b - s) s / (b 2^128)  SOL
/// SOL  = L (s - a) / 2^128
/// ```
///
/// so the coin's share is X / (X + Y) with X = (b - s) s / b and Y = s - a.
pub fn coin_share(s: u128, a: u128, b: u128) -> u128 {
    // At or under the bottom of the range a position is all coin; at or over the top, all SOL.
    if s <= a {
        return 1_000_000_000_000_000_000;
    }
    if s >= b {
        return 0;
    }
    let x = mul_div(b - s, s, b).unwrap_or(0);
    let y = s - a;
    mul_div(x, 1_000_000_000_000_000_000, x + y).unwrap_or(0)
}

/// The most liquidity `sol` and `coins` can add on `[a, b]` at `s`, rounded down: the lesser of
/// what each side alone could make. Zero outside the range.
pub fn liquidity_for(s: u128, a: u128, b: u128, sol: u64, coins: u64) -> u128 {
    if s <= a || s >= b {
        return 0;
    }
    let from_sol = crate::shl128_div(sol, s - a);
    let from_coins = crate::single_sided_liquidity(coins, s, b);
    match (from_sol, from_coins) {
        (Some(x), Some(y)) => x.min(y),
        (Some(x), None) | (None, Some(x)) => x,
        // Neither side can be worked out: no add (rather than an add sized by nothing).
        (None, None) => 0,
    }
}

/// The SOL value of `coins` at `s`: coins * s^2 / 2^128, rounded down.
pub fn coin_value(coins: u64, s: u128) -> u64 {
    let half = mul_div(coins as u128, s, 1u128 << 64).unwrap_or(u128::MAX);
    mul_div(half, s, 1u128 << 64).unwrap_or(u128::MAX).min(u64::MAX as u128) as u64
}

// ------------------------------------------------------------------------------ reading

pub(crate) fn u128_at(d: &[u8], at: usize) -> Result<u128> {
    Ok(u128::from_le_bytes(d.get(at..at + 16).and_then(|b| b.try_into().ok()).ok_or(TokenomicsError::NotThePool)?))
}

/// What `execute` reads off the pool.
#[derive(Clone, Copy, Debug)]
pub struct PoolState {
    pub liquidity: u128,
    /// What the swap's cap is sized from: the lesser of the pool's liquidity and its permanently
    /// locked liquidity. Liquidity somebody adds and takes away again around a run does not raise it.
    pub cap_liquidity: u128,
    pub sqrt_min: u128,
    pub sqrt_max: u128,
    pub sqrt_price: u128,
    pub enabled: bool,
    pub fee_numerator: u64,
}

pub fn read_pool_state(pool: &AccountInfo) -> Result<PoolState> {
    require_keys_eq!(*pool.owner, CP_AMM_ID, TokenomicsError::NotThePool);
    let d = pool.try_borrow_data()?;
    let fee = venue::read_fee(&d).ok_or(TokenomicsError::NotThePool)?;
    let liquidity = u128_at(&d, POOL_LIQUIDITY)?;
    Ok(PoolState {
        liquidity,
        cap_liquidity: liquidity.min(u128_at(&d, POOL_PERMANENT_LOCK_LIQUIDITY)?),
        sqrt_min: u128_at(&d, POOL_SQRT_MIN)?,
        sqrt_max: u128_at(&d, POOL_SQRT_MAX)?,
        sqrt_price: u128_at(&d, POOL_SQRT_PRICE)?,
        enabled: *d.get(POOL_STATUS).ok_or(TokenomicsError::NotThePool)? == 0,
        fee_numerator: fee.fee_numerator,
    })
}

pub(crate) fn balance(account: &AccountInfo) -> Result<u64> {
    Ok(crate::read_token_account(&account.try_borrow_data()?).ok_or(TokenomicsError::NotTheAccount)?.1)
}

/// A token account's mint, owner and amount, if it is an initialised one.
pub(crate) fn token_account(account: &AccountInfo) -> Option<(Pubkey, Pubkey, u64)> {
    if *account.owner != spl_token::ID && *account.owner != anchor_spl::token_2022::ID {
        return None;
    }
    let d = account.try_borrow_data().ok()?;
    if d.len() < 165 || d[108] != 1 {
        return None;
    }
    let key = |at: usize| Pubkey::new_from_array(d[at..at + 32].try_into().unwrap());
    Some((key(0), key(32), u64::from_le_bytes(d[64..72].try_into().unwrap())))
}

/// Every top-level instruction of this transaction is a compute-budget instruction, this
/// program's or the associated-token program's -- none can move a pool's price -- and this one is
/// one of them, not called from another program.
pub fn alone_in_transaction(instructions: &AccountInfo) -> Result<()> {
    alone_in_transaction_with(instructions, false)
}

/// `alone_in_transaction`, and -- for `execute` -- no other `execute_tokenomics` in it: the caller's
/// fee is the transaction's, repaid once, never once per run.
pub fn alone_in_transaction_with(instructions: &AccountInfo, one_execute: bool) -> Result<()> {
    let disc = <crate::instruction::ExecuteTokenomics as anchor_lang::Discriminator>::DISCRIMINATOR;
    let mut executes = 0usize;
    require!(get_stack_height() == TRANSACTION_LEVEL_STACK_HEIGHT, TokenomicsError::NotAlone);
    let count = {
        let d = instructions.try_borrow_data()?;
        u16::from_le_bytes(d.get(..2).and_then(|b| b.try_into().ok()).ok_or(TokenomicsError::NotAlone)?) as usize
    };
    for i in 0..count {
        let ix = ixs::load_instruction_at_checked(i, instructions)?;
        require!(
            ix.program_id == COMPUTE_BUDGET_ID || ix.program_id == crate::ID || ix.program_id == associated_token::ID,
            TokenomicsError::NotAlone
        );
        if ix.program_id == crate::ID && ix.data.get(..8) == Some(&disc[..]) {
            executes += 1;
        }
    }
    require!(!one_execute || executes <= 1, TokenomicsError::NotAlone);
    Ok(())
}

/// What this transaction's compute-budget instructions declare: the unit price in micro-lamports
/// and the unit limit. The priority fee is charged on the limit declared, used or not.
pub fn declared_priority(instructions: &AccountInfo) -> Result<u64> {
    let count = {
        let d = instructions.try_borrow_data()?;
        u16::from_le_bytes(d.get(..2).and_then(|b| b.try_into().ok()).ok_or(TokenomicsError::NotAlone)?) as usize
    };
    let (mut price, mut limit) = (0u64, 200_000u64);
    for i in 0..count {
        let ix = ixs::load_instruction_at_checked(i, instructions)?;
        if ix.program_id != COMPUTE_BUDGET_ID {
            continue;
        }
        match ix.data.first() {
            Some(2) if ix.data.len() >= 5 => limit = u32::from_le_bytes(ix.data[1..5].try_into().unwrap()) as u64,
            Some(3) if ix.data.len() >= 9 => price = u64::from_le_bytes(ix.data[1..9].try_into().unwrap()),
            _ => {}
        }
    }
    let priority = (price.min(MAX_CU_PRICE) as u128 * limit.min(MAX_CU_LIMIT) as u128).div_ceil(1_000_000);
    Ok(priority as u64)
}

/// Writable, or not a wallet `takes_sol` could ever pay (not a plain, empty, system-owned key on the
/// curve): a program, a sysvar, a data account, an off-curve address. Those are deferred whether
/// the runtime lets them be writable or not -- a program id or a reserved key never is -- so they
/// cannot stop a run; a caller may not pass a payable wallet read-only to have its payout deferred.
pub fn writable_or_reserved(wallet: &AccountInfo) -> bool {
    let payable = *wallet.owner == System::id()
        && wallet.data_is_empty()
        && !wallet.executable
        && on_curve(&wallet.key())
        && !crate::is_reserved_account(wallet.key);
    wallet.is_writable || !payable
}

/// Whether `wallet` can be paid SOL safely: the rule `fees::sol_payout` pays a creator in SOL by --
/// a plain wallet (system-owned, no data, not executable), the address of a key (on the curve),
/// writable, and left rent-exempt.
pub fn takes_sol(wallet: &AccountInfo, amount: u64) -> Result<bool> {
    if *wallet.owner != System::id() || !wallet.data_is_empty() || wallet.executable || !wallet.is_writable {
        return Ok(false);
    }
    // A reserved key (`is_reserved_account`) is never writable, so never paid, even when on the curve.
    if !on_curve(&wallet.key()) || crate::is_reserved_account(wallet.key) {
        return Ok(false);
    }
    let after = wallet.lamports().saturating_add(amount);
    Ok(after >= Rent::get()?.minimum_balance(0))
}

// ------------------------------------------------------------------------------ errors

#[error_code(offset = 9000)]
pub enum TokenomicsError {
    #[msg("the tokenomics config breaks a rule: legs, shares or recipients")]
    BadConfig,
    #[msg("the seed is not the config's")]
    WrongSeed,
    #[msg("the tokenomics account is already bound to its launch")]
    AlreadyBound,
    #[msg("the tokenomics account is not bound to its launch yet")]
    NotBound,
    #[msg("that launch is not this tokenomics account's: its id, creator or quote asset differs")]
    NotItsLaunch,
    #[msg("that is not the launch's pool")]
    NotThePool,
    #[msg("that is not the account expected")]
    NotTheAccount,
    #[msg("execute runs only at the top level of a transaction with no instruction that could move a price, and once")]
    NotAlone,
    #[msg("too soon")]
    TooSoon,
    #[msg("nothing is due")]
    NothingToExecute,
    #[msg("nothing to claim")]
    NothingToClaim,
    #[msg("only that role's holder may do this")]
    NotTheRole,
    #[msg("the liquidity position is already open")]
    PositionOpen,
    #[msg("arithmetic overflow")]
    Overflow,
    #[msg("the swap moved the price past its cap")]
    PriceMovedTooFar,
    #[msg("the caller must be a plain wallet")]
    CallerNotAWallet,
    #[msg("no such role")]
    NoSuchRole,
    #[msg("a tokenomics recipient is a key the runtime reserves (a sysvar, a builtin program, a loader), not a wallet")]
    RecipientReserved,
}

// ------------------------------------------------------------------------------ events

#[event]
pub struct TokenomicsCreated {
    pub tokenomics: Pubkey,
    pub config_hash: [u8; 32],
    pub launch_id: [u8; 32],
    pub owner: Pubkey,
    pub bps: [u16; MAX_BUCKETS],
}

#[event]
pub struct TokenomicsBound {
    pub tokenomics: Pubkey,
    pub mint: Pubkey,
    pub pool: Pubkey,
    pub record: Pubkey,
}

#[event]
pub struct TokenomicsAllocated {
    pub tokenomics: Pubkey,
    pub amount: u64,
    pub per_bucket: [u64; MAX_BUCKETS],
}

#[event]
pub struct TokenomicsSwapped {
    pub tokenomics: Pubkey,
    pub sol_in: u64,
    pub coins_out: u64,
    pub sqrt_before: u128,
    pub sqrt_after: u128,
}

/// Why a step was skipped: 3 no room, 4 too soon, 5 pool disabled, 6 no liquidity position, 7 an
/// add too small to make. (1 and 2 were the price reference's, removed.)
#[event]
pub struct TokenomicsSkipped {
    pub tokenomics: Pubkey,
    pub step: u8,
    pub reason: u8,
}

#[event]
pub struct TokenomicsBurned {
    pub tokenomics: Pubkey,
    pub coins: u64,
}

#[event]
pub struct TokenomicsSentToTreasury {
    pub tokenomics: Pubkey,
    pub treasury: Pubkey,
    pub coins: u64,
}

#[event]
pub struct TokenomicsLiquidityAdded {
    pub tokenomics: Pubkey,
    pub liquidity: u128,
    pub sol_in: u64,
    pub coins_in: u64,
}

#[event]
pub struct TokenomicsPaid {
    pub tokenomics: Pubkey,
    pub bucket: u8,
    pub to: Pubkey,
    pub lamports: u64,
}

#[event]
pub struct TokenomicsDeferred {
    pub tokenomics: Pubkey,
    pub bucket: u8,
    pub to: Pubkey,
    pub lamports: u64,
}

#[event]
pub struct TokenomicsSpent {
    pub tokenomics: Pubkey,
    pub bucket: u8,
    pub lamports: u64,
}

#[event]
pub struct TokenomicsReimbursed {
    pub tokenomics: Pubkey,
    pub caller: Pubkey,
    pub lamports: u64,
}

/// `open_lp_position`: what the opener fronted for the position's rent and what the liquidity bucket repaid it.
#[event]
pub struct TokenomicsPositionRepaid {
    pub tokenomics: Pubkey,
    pub opener: Pubkey,
    pub rent: u64,
    pub lamports: u64,
}

#[event]
pub struct TokenomicsForwarded {
    pub tokenomics: Pubkey,
    pub to: Pubkey,
    pub lamports: u64,
    pub coins: u64,
}

#[event]
pub struct TokenomicsRoleProposed {
    pub tokenomics: Pubkey,
    pub role: u8,
    pub from: Pubkey,
    pub to: Pubkey,
}

#[event]
pub struct TokenomicsRoleChanged {
    pub tokenomics: Pubkey,
    pub role: u8,
    pub from: Pubkey,
    pub to: Pubkey,
}

// ------------------------------------------------------------------------------ CPI helpers

pub(crate) fn ro(k: &Pubkey) -> AccountMeta {
    AccountMeta::new_readonly(*k, false)
}
pub(crate) fn rw(k: &Pubkey) -> AccountMeta {
    AccountMeta::new(*k, false)
}

/// One call, with every account of the instruction available to it.
pub(crate) fn send(all: &[AccountInfo], program: Pubkey, accounts: Vec<AccountMeta>, data: Vec<u8>, seeds: &[&[&[u8]]]) -> Result<()> {
    invoke_signed(&Instruction { program_id: program, accounts, data }, all, seeds)?;
    Ok(())
}

/// The cp-amm event authority: `PDA(["__event_authority"], cp-amm)`.
pub fn cp_amm_event_authority() -> Pubkey {
    Pubkey::find_program_address(&[b"__event_authority"], &CP_AMM_ID).0
}

/// Pay `amount` of the account's wrapped SOL to `funder` as SOL, through `PDA(["tk-temp", tk])`:
/// made with the funder's lamports for its rent, filled, and closed to the funder -- who ends
/// `amount` richer (and with any lamports somebody had sent to the address), the rent back. The
/// pattern `fees::pay_creator_in_sol` pays a creator through.
#[allow(clippy::too_many_arguments)]
pub(crate) fn unwrap_to<'info>(
    all: &[AccountInfo<'info>],
    funder: &AccountInfo<'info>,
    temp: &AccountInfo<'info>,
    temp_bump: u8,
    tk: &AccountInfo<'info>,
    tk_seeds: &[&[u8]],
    vault_wsol: &AccountInfo<'info>,
    amount: u64,
) -> Result<()> {
    if amount == 0 {
        return Ok(());
    }
    require!(*funder.owner == System::id() && funder.data_is_empty(), TokenomicsError::CallerNotAWallet);
    require!(temp.data_is_empty() && *temp.owner == System::id(), TokenomicsError::NotTheAccount);
    let space = spl_token::state::Account::LEN;
    let rent = Rent::get()?.minimum_balance(space);
    let tk_key = tk.key();
    let temp_seeds: &[&[u8]] = &[TK_TEMP_SEED, tk_key.as_ref(), &[temp_bump]];
    let held = temp.lamports();
    if held == 0 {
        let ix = system_instruction::create_account(funder.key, temp.key, rent, space as u64, &spl_token::ID);
        invoke_signed(&ix, all, &[temp_seeds])?;
    } else {
        if held < rent {
            invoke_signed(&system_instruction::transfer(funder.key, temp.key, rent - held), all, &[])?;
        }
        invoke_signed(&system_instruction::allocate(temp.key, space as u64), all, &[temp_seeds])?;
        invoke_signed(&system_instruction::assign(temp.key, &spl_token::ID), all, &[temp_seeds])?;
    }
    let wsol = spl_token::native_mint::ID;
    invoke_signed(&spl_token::instruction::initialize_account3(&spl_token::ID, temp.key, &wsol, &tk_key)?, all, &[])?;
    invoke_signed(
        &spl_token::instruction::transfer_checked(&spl_token::ID, vault_wsol.key, &wsol, temp.key, &tk_key, &[], amount, 9)?,
        all,
        &[tk_seeds],
    )?;
    let before = funder.lamports();
    invoke_signed(&spl_token::instruction::close_account(&spl_token::ID, temp.key, funder.key, &tk_key, &[])?, all, &[tk_seeds])?;
    require!(funder.lamports().checked_sub(before).ok_or(TokenomicsError::Overflow)? >= amount, TokenomicsError::Overflow);
    Ok(())
}

/// A system transfer out of `from`, which signed this transaction.
pub(crate) fn pay<'info>(all: &[AccountInfo<'info>], from: &AccountInfo<'info>, to: &AccountInfo<'info>, lamports: u64) -> Result<()> {
    if lamports == 0 || from.key == to.key {
        return Ok(());
    }
    invoke_signed(&system_instruction::transfer(from.key, to.key, lamports), all, &[])?;
    Ok(())
}

/// Create `owner`'s associated account for the coin if it is not there; `payer` pays its rent.
pub(crate) fn ensure_coin_account<'info>(all: &[AccountInfo<'info>], payer: &Pubkey, account: &AccountInfo<'info>, owner: &Pubkey, mint: &Pubkey) -> Result<()> {
    let t22 = anchor_spl::token_2022::ID;
    require_keys_eq!(account.key(), get_associated_token_address_with_program_id(owner, mint, &t22), TokenomicsError::NotTheAccount);
    if *account.owner == t22 && !account.data_is_empty() {
        return Ok(());
    }
    let ix = Instruction {
        program_id: associated_token::ID,
        accounts: vec![
            AccountMeta::new(*payer, true),
            rw(&account.key()),
            ro(owner),
            ro(mint),
            ro(&System::id()),
            ro(&t22),
        ],
        data: vec![1], // CreateIdempotent
    };
    invoke_signed(&ix, all, &[])?;
    Ok(())
}

/// A Token-2022 transfer of the coin out of an account the tokenomics account owns.
pub(crate) fn send_coins<'info>(all: &[AccountInfo<'info>], from: &Pubkey, mint: &Pubkey, to: &Pubkey, tk: &Pubkey, tk_seeds: &[&[u8]], amount: u64) -> Result<()> {
    if amount == 0 {
        return Ok(());
    }
    let ix = anchor_spl::token_2022::spl_token_2022::instruction::transfer_checked(
        &anchor_spl::token_2022::ID,
        from,
        mint,
        to,
        tk,
        &[],
        amount,
        crate::TOKEN_DECIMALS,
    )?;
    invoke_signed(&ix, all, &[tk_seeds])?;
    Ok(())
}

// ------------------------------------------------------------------------------ init

#[derive(Accounts)]
#[instruction(config: TokenomicsConfig, seed: [u8; 32])]
pub struct InitTokenomics<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(init, payer = payer, space = 8 + Tokenomics::INIT_SPACE, seeds = [TOKENOMICS_SEED, seed.as_ref()], bump)]
    pub tokenomics: Box<Account<'info, Tokenomics>>,
    /// Where `claim_fees` pays the creator's share: the account's associated wrapped-SOL account.
    /// Made here so that a launch finds it there, which a dev buy needs (`check_dev_buy`).
    #[account(
        init_if_needed,
        payer = payer,
        associated_token::mint = wsol_mint,
        associated_token::authority = tokenomics,
        associated_token::token_program = token_program
    )]
    pub vault_wsol: Box<InterfaceAccount<'info, TokenAccount>>,
    #[account(address = spl_token::native_mint::ID)]
    pub wsol_mint: Box<InterfaceAccount<'info, Mint>>,
    #[account(address = spl_token::ID)]
    pub token_program: Interface<'info, TokenInterface>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

pub fn init_handler(ctx: Context<InitTokenomics>, config: TokenomicsConfig, seed: [u8; 32]) -> Result<()> {
    config.check()?;
    require!(config.seed() == seed, TokenomicsError::WrongSeed);
    let key = ctx.accounts.tokenomics.key();
    require!(!config.recipients.contains(&key), TokenomicsError::BadConfig);
    let t = &mut ctx.accounts.tokenomics;
    t.version = 1;
    t.num_buckets = NUM_BUCKETS as u8;
    t.bump = ctx.bumps.tokenomics;
    t.bps = config.solana_bps();
    t.config_hash = config.evm_config_hash();
    t.seed = seed;
    t.launch_id = config.launch_id;
    t.owner = config.owner();
    t.treasury = config.treasury();
    t.community = config.community();
    t.created_at = Clock::get()?.unix_timestamp;
    emit!(TokenomicsCreated { tokenomics: key, config_hash: t.config_hash, launch_id: t.launch_id, owner: t.owner, bps: t.bps });
    // LAMPORTS THAT WERE HERE BEFORE THE ACCOUNT ARE FEES (audit round 7, L). The address is public
    // before it exists, and a v2 wrapped-SOL launch may name it as its payee then: `claim_fees_native`
    // pays a payee no program owns in raw lamports, and Anchor's `init` takes an address already
    // holding lamports as it is. Left here, `forward_refund` would hand them to the owner, past the
    // buckets. They cannot be a dev buy's refund -- the owner's payment is the creator's only once
    // this account exists (`pays_for`) -- so whatever is above the rent goes into the vault, as
    // wrapped SOL, where `execute` splits it as the fees it is.
    let tk = ctx.accounts.tokenomics.to_account_info();
    let before = tk.lamports().saturating_sub(Rent::get()?.minimum_balance(tk.data_len()));
    if before > 0 {
        let vault = ctx.accounts.vault_wsol.to_account_info();
        **tk.try_borrow_mut_lamports()? -= before;
        **vault.try_borrow_mut_lamports()? += before;
        let program = ctx.accounts.token_program.to_account_info();
        let payer = ctx.accounts.payer.to_account_info();
        let system = ctx.accounts.system_program.to_account_info();
        // Both sides of the lamport move reach the runtime in a call of NOTHING: a system transfer of
        // zero lamports from the payer (a signer here) to the vault, with this account riding along
        // as a third, writable (the system program reads only the first two). Not on `sync_native`:
        // mainnet's token program takes exactly its one account and refuses a second
        // (InvalidArgument), which failed every dev buy on 2026-10-21 (`launch_leg::buy_for_creator`).
        let mut both_sides = anchor_lang::solana_program::system_instruction::transfer(payer.key, vault.key, 0);
        both_sides.accounts.push(anchor_lang::solana_program::instruction::AccountMeta::new(tk.key(), false));
        invoke_signed(&both_sides, &[payer, vault.clone(), tk.clone(), system], &[])?;
        let count = spl_token::instruction::sync_native(&spl_token::ID, vault.key)?;
        invoke_signed(&count, &[vault, program], &[])?;
    }
    Ok(())
}

// ------------------------------------------------------------------------------ bind

#[derive(Accounts)]
#[instruction(launch_seed: [u8; 32])]
pub struct BindTokenomics<'info> {
    /// Anyone; pays for the account's associated account for the coin.
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut)]
    pub tokenomics: Box<Account<'info, Tokenomics>>,
    /// CHECK: the launch's position NFT mint, `PDA(["position", seed])`: what its record is at.
    #[account(seeds = [POSITION_SEED, launch_seed.as_ref()], bump)]
    pub position_nft_mint: UncheckedAccount<'info>,
    #[account(seeds = [SPLITTER_SEED, position_nft_mint.key().as_ref()], bump = record.bump)]
    pub record: Box<Account<'info, LaunchRecord>>,
    /// CHECK: the launch's position, from its record; read for its pool.
    #[account(address = record.position @ TokenomicsError::NotItsLaunch)]
    pub position: UncheckedAccount<'info>,
    /// CHECK: the position's pool, checked in the handler.
    pub pool: UncheckedAccount<'info>,
    /// The coin: the pool's token A, under Token-2022.
    #[account(mint::token_program = token_2022_program)]
    pub mint: Box<InterfaceAccount<'info, Mint>>,
    #[account(
        init_if_needed,
        payer = payer,
        associated_token::mint = mint,
        associated_token::authority = tokenomics,
        associated_token::token_program = token_2022_program
    )]
    pub vault_coin: Box<InterfaceAccount<'info, TokenAccount>>,
    /// CHECK: the treasury wallet; its coin account is made here when the split buys back.
    #[account(address = tokenomics.treasury @ TokenomicsError::NotTheRole)]
    pub treasury: UncheckedAccount<'info>,
    /// CHECK: the treasury's associated coin account (`ensure_coin_account`).
    #[account(mut)]
    pub treasury_coin: UncheckedAccount<'info>,
    /// CHECK: pinned.
    #[account(address = incinerator::ID)]
    pub incinerator: UncheckedAccount<'info>,
    /// CHECK: the incinerator's associated coin account, made here when the split burns.
    #[account(mut)]
    pub incinerator_coin: UncheckedAccount<'info>,
    pub token_2022_program: Program<'info, Token2022>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

pub fn bind_handler(ctx: Context<BindTokenomics>, launch_seed: [u8; 32]) -> Result<()> {
    let a = &ctx.accounts;
    let key = a.tokenomics.key();
    require!(!a.tokenomics.bound, TokenomicsError::AlreadyBound);
    require!(launch_id_of(&launch_seed) == a.tokenomics.launch_id, TokenomicsError::NotItsLaunch);
    require_keys_eq!(a.record.creator, key, TokenomicsError::NotItsLaunch);
    require_keys_eq!(a.record.quote_mint, spl_token::native_mint::ID, TokenomicsError::NotItsLaunch);
    require_keys_eq!(*a.position.owner, CP_AMM_ID, TokenomicsError::NotThePool);
    let (position_pool, _) = read_position(&a.position.try_borrow_data()?).ok_or(TokenomicsError::NotThePool)?;
    require_keys_eq!(position_pool, a.pool.key(), TokenomicsError::NotThePool);
    require_keys_eq!(*a.pool.owner, CP_AMM_ID, TokenomicsError::NotThePool);
    let [(mint_a, _), (mint_b, _)] = read_pool(&a.pool.try_borrow_data()?).ok_or(TokenomicsError::NotThePool)?;
    require_keys_eq!(mint_a, a.mint.key(), TokenomicsError::NotThePool);
    require_keys_eq!(mint_b, spl_token::native_mint::ID, TokenomicsError::NotThePool);
    let slice = Pubkey::find_program_address(&[TOKEN_A_SEED, launch_seed.as_ref()], &crate::ID).0;
    // The coin accounts the split sends to, made now by the binder, so that a run does not have
    // to (a run still makes one that has since been closed, at its caller's cost).
    let all = a.to_account_infos();
    let payer = a.payer.key();
    if a.tokenomics.bps[BURN] != 0 {
        ensure_coin_account(&all, &payer, &a.incinerator_coin, &incinerator::ID, &a.mint.key())?;
    }
    if a.tokenomics.bps[BUYBACK] != 0 {
        ensure_coin_account(&all, &payer, &a.treasury_coin, &a.tokenomics.treasury, &a.mint.key())?;
    }
    let record = a.record.key();
    let (mint, pool) = (a.mint.key(), a.pool.key());
    let t = &mut ctx.accounts.tokenomics;
    t.bound = true;
    t.mint = mint;
    t.pool = pool;
    t.record = record;
    t.slice = slice;
    emit!(TokenomicsBound { tokenomics: key, mint, pool, record });
    Ok(())
}

// ------------------------------------------------------------------------------ forwarding

#[derive(Accounts)]
pub struct ForwardRefund<'info> {
    #[account(mut)]
    pub tokenomics: Box<Account<'info, Tokenomics>>,
    /// CHECK: the owner's wallet.
    #[account(mut, address = tokenomics.owner @ TokenomicsError::NotTheRole)]
    pub owner: UncheckedAccount<'info>,
}

/// Every lamport the account holds above its rent, to the owner. Fees are only ever wrapped SOL;
/// lamports here are what a launch handed back of the owner's payment above their dev buy, or what
/// somebody sent. (Lamports at the address before it was made -- a native claim's, perhaps -- went
/// into the vault at `init_tokenomics`, as fees.)
pub fn forward_refund_handler(ctx: Context<ForwardRefund>) -> Result<()> {
    let tk = ctx.accounts.tokenomics.to_account_info();
    let owner = ctx.accounts.owner.to_account_info();
    let rent = Rent::get()?.minimum_balance(tk.data_len());
    let extra = tk.lamports().saturating_sub(rent);
    require!(extra > 0, TokenomicsError::NothingToClaim);
    // A plain wallet is paid by anybody's call; any other owner (a multisig's vault, say) signs
    // for it, and so says it can spend lamports there. Never left between nothing and rent-exempt.
    let rent_ok = owner.lamports().saturating_add(extra) >= Rent::get()?.minimum_balance(owner.data_len());
    require!(takes_sol(&owner, extra)? || (owner.is_signer && !owner.executable && rent_ok), TokenomicsError::NotTheRole);
    **tk.try_borrow_mut_lamports()? -= extra;
    **owner.try_borrow_mut_lamports()? += extra;
    emit!(TokenomicsForwarded { tokenomics: tk.key(), to: owner.key(), lamports: extra, coins: 0 });
    Ok(())
}

#[derive(Accounts)]
pub struct ForwardCoins<'info> {
    /// Anyone; pays for the owner's account for the coin if it has none.
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, constraint = tokenomics.bound @ TokenomicsError::NotBound)]
    pub tokenomics: Box<Account<'info, Tokenomics>>,
    /// CHECK: the owner's wallet.
    #[account(address = tokenomics.owner @ TokenomicsError::NotTheRole)]
    pub owner: UncheckedAccount<'info>,
    /// CHECK: the owner's associated account for the coin, made here if missing.
    #[account(mut)]
    pub owner_coin: UncheckedAccount<'info>,
    /// CHECK: the launch's slice account, where a dev buy's coins are; checked in the handler.
    #[account(mut, address = tokenomics.slice @ TokenomicsError::NotTheAccount)]
    pub slice: UncheckedAccount<'info>,
    /// CHECK: the account's own associated account for the coin.
    #[account(mut)]
    pub vault_coin: UncheckedAccount<'info>,
    /// CHECK: the coin.
    #[account(address = tokenomics.mint @ TokenomicsError::NotTheAccount)]
    pub mint: UncheckedAccount<'info>,
    pub token_2022_program: Program<'info, Token2022>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

/// The dev buy's coins (the slice account's, which the launch made the account's) and any coins
/// in the account's own coin account beyond what it holds for liquidity, to the owner. The slice
/// account is closed once empty; its rent becomes the owner's (`forward_refund`).
pub fn forward_coins_handler<'info>(ctx: Context<'_, '_, 'info, 'info, ForwardCoins<'info>>) -> Result<()> {
    let all = ctx.accounts.to_account_infos();
    let a = &ctx.accounts;
    let t = &a.tokenomics;
    let tk = t.key();
    let (seed_, bump_) = t.seed_parts();
    let seeds: [&[u8]; 3] = [TOKENOMICS_SEED, &seed_, &bump_];
    let mint = t.mint;
    require_keys_eq!(a.vault_coin.key(), get_associated_token_address_with_program_id(&tk, &mint, &anchor_spl::token_2022::ID), TokenomicsError::NotTheAccount);
    ensure_coin_account(&all, &a.payer.key(), &a.owner_coin, &t.owner, &mint)?;
    let mut moved = 0u64;
    let mut closed = false;
    if let Some((m, owner, amount)) = token_account(&a.slice) {
        if m == mint && owner == tk && *a.slice.owner == anchor_spl::token_2022::ID {
            send_coins(&all, &a.slice.key(), &mint, &a.owner_coin.key(), &tk, &seeds, amount)?;
            moved += amount;
            let ix = anchor_spl::token_2022::spl_token_2022::instruction::close_account(&anchor_spl::token_2022::ID, &a.slice.key(), &tk, &tk, &[])?;
            invoke_signed(&ix, &all, &[&seeds])?;
            closed = true;
        }
    }
    let held = balance(&a.vault_coin)?;
    let extra = held.saturating_sub(t.liquidity_coins + t.treasury_coins);
    send_coins(&all, &a.vault_coin.key(), &mint, &a.owner_coin.key(), &tk, &seeds, extra)?;
    moved += extra;
    require!(moved > 0 || closed, TokenomicsError::NothingToClaim);
    emit!(TokenomicsForwarded { tokenomics: tk, to: t.owner, lamports: 0, coins: moved });
    Ok(())
}

// ------------------------------------------------------------------------------ the position

#[derive(Accounts)]
pub struct OpenLpPosition<'info> {
    /// Anyone (a plain wallet); fronts the position's rent (about 0.0099 SOL, once) and is repaid it
    /// out of the liquidity bucket, up to `MAX_POSITION_REPAY_LAMPORTS` and what the bucket holds.
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, constraint = tokenomics.bound @ TokenomicsError::NotBound)]
    pub tokenomics: Box<Account<'info, Tokenomics>>,
    /// CHECK: `PDA(["tk-lp", tokenomics])`, the position NFT's mint, made by cp-amm.
    #[account(mut, seeds = [TK_LP_SEED, tokenomics.key().as_ref()], bump)]
    pub lp_nft_mint: UncheckedAccount<'info>,
    /// CHECK: cp-amm's `PDA(["position_nft_account", nft mint])`; cp-amm checks it.
    #[account(mut)]
    pub lp_nft_account: UncheckedAccount<'info>,
    /// CHECK: cp-amm's `PDA(["position", nft mint])`; cp-amm checks it.
    #[account(mut)]
    pub lp_position: UncheckedAccount<'info>,
    /// CHECK: the launch's pool.
    #[account(mut, address = tokenomics.pool @ TokenomicsError::NotThePool)]
    pub pool: UncheckedAccount<'info>,
    /// CHECK: cp-amm's.
    #[account(address = POOL_AUTHORITY)]
    pub pool_authority: UncheckedAccount<'info>,
    /// CHECK: cp-amm checks it.
    pub cp_amm_event_authority: UncheckedAccount<'info>,
    /// CHECK: pinned.
    #[account(address = CP_AMM_ID)]
    pub cp_amm_program: UncheckedAccount<'info>,
    pub token_2022_program: Program<'info, Token2022>,
    pub system_program: Program<'info, System>,
    /// CHECK: the account's wrapped-SOL account (its associated account), where the fees land: the repayment's source.
    #[account(mut, address = get_associated_token_address_with_program_id(&tokenomics.key(), &spl_token::native_mint::ID, &spl_token::ID) @ TokenomicsError::NotTheAccount)]
    pub vault_wsol: UncheckedAccount<'info>,
    /// CHECK: `PDA(["tk-temp", tokenomics])`, made and closed in this instruction (`unwrap_to`).
    #[account(mut, seeds = [TK_TEMP_SEED, tokenomics.key().as_ref()], bump)]
    pub temp: UncheckedAccount<'info>,
    /// CHECK: pinned.
    #[account(address = spl_token::ID)]
    pub token_program: UncheckedAccount<'info>,
    /// CHECK: pinned (the temporary wrapped-SOL account is made on it).
    #[account(address = spl_token::native_mint::ID)]
    pub wsol_mint: UncheckedAccount<'info>,
}

pub fn open_lp_position_handler<'info>(ctx: Context<'_, '_, 'info, 'info, OpenLpPosition<'info>>) -> Result<()> {
    require!(ctx.accounts.tokenomics.lp_position == Pubkey::default(), TokenomicsError::PositionOpen);
    // (the opener is repaid as SOL through `unwrap_to`, which pays only a plain wallet)
    require!(*ctx.accounts.payer.owner == System::id() && ctx.accounts.payer.data_is_empty(), TokenomicsError::CallerNotAWallet);
    let all = ctx.accounts.to_account_infos();
    let a = &ctx.accounts;
    let tk = a.tokenomics.key();
    let fronted_from = a.payer.lamports();
    let nft_seeds: &[&[u8]] = &[TK_LP_SEED, tk.as_ref(), &[ctx.bumps.lp_nft_mint]];
    let accounts = vec![
        ro(&tk),
        AccountMeta::new(a.lp_nft_mint.key(), true),
        rw(&a.lp_nft_account.key()),
        rw(&a.pool.key()),
        rw(&a.lp_position.key()),
        ro(&POOL_AUTHORITY),
        AccountMeta::new(a.payer.key(), true),
        ro(&anchor_spl::token_2022::ID),
        ro(&System::id()),
        ro(&a.cp_amm_event_authority.key()),
        ro(&CP_AMM_ID),
    ];
    send(&all, CP_AMM_ID, accounts, CREATE_POSITION_DISCRIMINATOR.to_vec(), &[nft_seeds])?;
    let (pool, _) = read_position(&a.lp_position.try_borrow_data()?).ok_or(TokenomicsError::NotThePool)?;
    require_keys_eq!(pool, a.pool.key(), TokenomicsError::NotThePool);
    let (position, nft) = (a.lp_position.key(), a.lp_nft_mint.key());
    // THE RENT, OUT OF THE LIQUIDITY BUCKET (owner, 2026-10-24): what the opener fronted for cp-amm's accounts, measured, capped, and
    // never more than the bucket holds once the fees waiting in the wrapped-SOL account are allocated -- the rest, if any, is the
    // opener's own. The bucket's spend is counted like a run's (`spent`, `reimbursed`).
    let rent = fronted_from.saturating_sub(a.payer.lamports());
    let mut t: Tokenomics = (**a.tokenomics).clone();
    allocate(&mut t, tk, balance(&a.vault_wsol)?);
    let repay = rent.min(MAX_POSITION_REPAY_LAMPORTS).min(t.buckets[LIQUIDITY]);
    if repay > 0 {
        t.buckets[LIQUIDITY] -= repay;
        t.spent[LIQUIDITY] = t.spent[LIQUIDITY].saturating_add(repay);
        t.reimbursed = t.reimbursed.saturating_add(repay);
        let (seed_, bump_) = t.seed_parts();
        let seeds: [&[u8]; 3] = [TOKENOMICS_SEED, &seed_, &bump_];
        let tk_info = a.tokenomics.to_account_info();
        let payer = a.payer.to_account_info();
        unwrap_to(&all, &payer, &a.temp, ctx.bumps.temp, &tk_info, &seeds, &a.vault_wsol, repay)?;
    }
    emit!(TokenomicsPositionRepaid { tokenomics: tk, opener: a.payer.key(), rent, lamports: repay });
    t.lp_position = position;
    t.lp_nft_mint = nft;
    // Everything the account holds is still accounted for, to the unit.
    require!(balance(&a.vault_wsol)? >= t.tracked(), TokenomicsError::Overflow);
    **ctx.accounts.tokenomics = t;
    Ok(())
}

#[derive(Accounts)]
pub struct ClaimLpFees<'info> {
    #[account(mut, constraint = tokenomics.bound @ TokenomicsError::NotBound)]
    pub tokenomics: Box<Account<'info, Tokenomics>>,
    /// CHECK: the account's position.
    #[account(mut, address = tokenomics.lp_position @ TokenomicsError::NotTheAccount)]
    pub lp_position: UncheckedAccount<'info>,
    /// CHECK: cp-amm checks it against the position and its owner against the signer.
    pub lp_nft_account: UncheckedAccount<'info>,
    /// CHECK: the pool.
    #[account(address = tokenomics.pool @ TokenomicsError::NotThePool)]
    pub pool: UncheckedAccount<'info>,
    /// CHECK: cp-amm's.
    #[account(address = POOL_AUTHORITY)]
    pub pool_authority: UncheckedAccount<'info>,
    /// CHECK: the account's coin account; cp-amm writes nothing to it (fees are in SOL only).
    #[account(mut)]
    pub vault_coin: UncheckedAccount<'info>,
    /// CHECK: the account's wrapped-SOL account, where the fees land.
    #[account(mut)]
    pub vault_wsol: UncheckedAccount<'info>,
    /// CHECK: cp-amm checks them against the pool.
    #[account(mut)]
    pub token_a_vault: UncheckedAccount<'info>,
    /// CHECK: as above.
    #[account(mut)]
    pub token_b_vault: UncheckedAccount<'info>,
    /// CHECK: the coin.
    #[account(address = tokenomics.mint @ TokenomicsError::NotTheAccount)]
    pub mint: UncheckedAccount<'info>,
    /// CHECK: pinned.
    #[account(address = spl_token::native_mint::ID)]
    pub wsol_mint: UncheckedAccount<'info>,
    pub token_2022_program: Program<'info, Token2022>,
    /// CHECK: pinned.
    #[account(address = spl_token::ID)]
    pub token_program: UncheckedAccount<'info>,
    /// CHECK: cp-amm checks it.
    pub cp_amm_event_authority: UncheckedAccount<'info>,
    /// CHECK: pinned.
    #[account(address = CP_AMM_ID)]
    pub cp_amm_program: UncheckedAccount<'info>,
}

/// The account's own position's fees, into its wrapped-SOL account: they are then fees like any.
pub fn claim_lp_fees_handler<'info>(ctx: Context<'_, '_, 'info, 'info, ClaimLpFees<'info>>) -> Result<()> {
    let all = ctx.accounts.to_account_infos();
    let a = &ctx.accounts;
    let t = &a.tokenomics;
    let tk = t.key();
    vault_accounts(tk, t.mint, &a.vault_wsol, &a.vault_coin)?;
    let (seed_, bump_) = t.seed_parts();
    let seeds: [&[u8]; 3] = [TOKENOMICS_SEED, &seed_, &bump_];
    let accounts = vec![
        ro(&POOL_AUTHORITY),
        ro(&a.pool.key()),
        rw(&a.lp_position.key()),
        rw(&a.vault_coin.key()),
        rw(&a.vault_wsol.key()),
        rw(&a.token_a_vault.key()),
        rw(&a.token_b_vault.key()),
        ro(&a.mint.key()),
        ro(&spl_token::native_mint::ID),
        ro(&a.lp_nft_account.key()),
        AccountMeta::new_readonly(tk, true),
        ro(&anchor_spl::token_2022::ID),
        ro(&spl_token::ID),
        ro(&a.cp_amm_event_authority.key()),
        ro(&CP_AMM_ID),
    ];
    send(&all, CP_AMM_ID, accounts, crate::CLAIM_POSITION_FEE_DISCRIMINATOR.to_vec(), &[&seeds])
}

pub(crate) fn vault_accounts(tk: Pubkey, mint: Pubkey, vault_wsol: &AccountInfo, vault_coin: &AccountInfo) -> Result<()> {
    require_keys_eq!(vault_wsol.key(), get_associated_token_address_with_program_id(&tk, &spl_token::native_mint::ID, &spl_token::ID), TokenomicsError::NotTheAccount);
    require_keys_eq!(vault_coin.key(), get_associated_token_address_with_program_id(&tk, &mint, &anchor_spl::token_2022::ID), TokenomicsError::NotTheAccount);
    Ok(())
}

// ------------------------------------------------------------------------------ execute

#[derive(Accounts)]
pub struct Execute<'info> {
    /// Anyone, a plain wallet: puts up the rent of the payout's passage for the moment, and of a
    /// recipient's coin account if one is missing; repaid its cost only when it is the operator.
    #[account(mut)]
    pub caller: Signer<'info>,
    #[account(mut, constraint = tokenomics.bound @ TokenomicsError::NotBound)]
    pub tokenomics: Box<Account<'info, Tokenomics>>,
    /// CHECK: the account's associated wrapped-SOL account (`vault_accounts`).
    #[account(mut)]
    pub vault_wsol: UncheckedAccount<'info>,
    /// CHECK: the account's associated coin account (`vault_accounts`).
    #[account(mut)]
    pub vault_coin: UncheckedAccount<'info>,
    /// CHECK: `PDA(["tk-temp", tokenomics])`, made and closed in this instruction.
    #[account(mut, seeds = [TK_TEMP_SEED, tokenomics.key().as_ref()], bump)]
    pub temp: UncheckedAccount<'info>,
    /// CHECK: the owner's wallet: the creator bucket is paid here. Writable (checked in the handler)
    /// unless it is not a payable wallet at all (`writable_or_reserved`).
    #[account(address = tokenomics.owner @ TokenomicsError::NotTheRole)]
    pub owner: UncheckedAccount<'info>,
    /// CHECK: the community wallet. Writable whenever the split pays it (checked in the handler),
    /// unless it is a key no transaction can write-lock -- like the zero key of a split without a
    /// community share, the system program's.
    #[account(address = tokenomics.community @ TokenomicsError::NotTheRole)]
    pub community: UncheckedAccount<'info>,
    /// CHECK: the treasury wallet: the buyback's coins go to its associated account.
    #[account(address = tokenomics.treasury @ TokenomicsError::NotTheRole)]
    pub treasury: UncheckedAccount<'info>,
    /// CHECK: the treasury's associated coin account; made if missing and coins are sent.
    #[account(mut)]
    pub treasury_coin: UncheckedAccount<'info>,
    /// CHECK: pinned: the burn's coins go to its associated account.
    #[account(address = incinerator::ID)]
    pub incinerator: UncheckedAccount<'info>,
    /// CHECK: the incinerator's associated coin account; made if missing and coins are burned.
    #[account(mut)]
    pub incinerator_coin: UncheckedAccount<'info>,
    /// CHECK: the launch's pool.
    #[account(mut, address = tokenomics.pool @ TokenomicsError::NotThePool)]
    pub pool: UncheckedAccount<'info>,
    /// CHECK: cp-amm's.
    #[account(address = POOL_AUTHORITY)]
    pub pool_authority: UncheckedAccount<'info>,
    /// CHECK: cp-amm checks them against the pool.
    #[account(mut)]
    pub token_a_vault: UncheckedAccount<'info>,
    /// CHECK: as above.
    #[account(mut)]
    pub token_b_vault: UncheckedAccount<'info>,
    /// CHECK: the coin.
    #[account(address = tokenomics.mint @ TokenomicsError::NotTheAccount)]
    pub mint: UncheckedAccount<'info>,
    /// CHECK: pinned.
    #[account(address = spl_token::native_mint::ID)]
    pub wsol_mint: UncheckedAccount<'info>,
    /// CHECK: the account's position, when it has one (else any account: it is not used).
    #[account(mut)]
    pub lp_position: UncheckedAccount<'info>,
    /// CHECK: the position's NFT account; cp-amm checks it.
    pub lp_nft_account: UncheckedAccount<'info>,
    /// CHECK: cp-amm checks it.
    pub cp_amm_event_authority: UncheckedAccount<'info>,
    /// CHECK: pinned.
    #[account(address = CP_AMM_ID)]
    pub cp_amm_program: UncheckedAccount<'info>,
    /// CHECK: pinned.
    #[account(address = spl_token::ID)]
    pub token_program: UncheckedAccount<'info>,
    pub token_2022_program: Program<'info, Token2022>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
    /// CHECK: pinned.
    #[account(address = ixs::ID)]
    pub instructions: UncheckedAccount<'info>,
    /// CHECK: `PDA(["tk2-min"])`, the ADMIN's rules, shared with v2 (`tokenomics_v2::tk2_rules`;
    /// the defaults while unset).
    #[account(seeds = [crate::TK2_MIN_SEED], bump)]
    pub min: UncheckedAccount<'info>,
    /// CHECK: `PDA(["tk2-config"])`: its operator is the one caller repaid (`tokenomics_v2::operator_of`).
    #[account(seeds = [crate::TK2_CONFIG_SEED], bump)]
    pub config: UncheckedAccount<'info>,
}

/// What one run spends, per bucket, and does.
#[derive(Default, Debug)]
pub(crate) struct Run {
    pub(crate) spend: [u64; MAX_BUCKETS],
    pub(crate) coins_burned: u64,
    pub(crate) coins_to_treasury: u64,
}

/// The accounts a run's buy stage touches: v1's `Execute` and v2's `ExecuteV2` both give them.
pub(crate) struct BuyAccounts<'a, 'info> {
    pub(crate) tk: Pubkey,
    /// The pool's token B, which the buys spend: wrapped SOL (v1, and v2 on a SOL launch) or the
    /// asset a v2.3 account's launch pairs against; and its token program.
    pub(crate) quote_mint: Pubkey,
    pub(crate) quote_program: Pubkey,
    pub(crate) caller: &'a AccountInfo<'info>,
    pub(crate) vault_wsol: &'a AccountInfo<'info>,
    pub(crate) vault_coin: &'a AccountInfo<'info>,
    pub(crate) treasury_coin: &'a AccountInfo<'info>,
    pub(crate) incinerator_coin: &'a AccountInfo<'info>,
    pub(crate) pool: &'a AccountInfo<'info>,
    pub(crate) token_a_vault: &'a AccountInfo<'info>,
    pub(crate) token_b_vault: &'a AccountInfo<'info>,
    pub(crate) mint: &'a AccountInfo<'info>,
    pub(crate) lp_position: &'a AccountInfo<'info>,
    pub(crate) lp_nft_account: &'a AccountInfo<'info>,
    pub(crate) cp_amm_event_authority: &'a AccountInfo<'info>,
}

/// The books the buy stage reads and writes, copied out of the account and back.
pub(crate) struct BuyBooks {
    pub(crate) mint: Pubkey,
    pub(crate) treasury: Pubkey,
    pub(crate) liquidity_coins: u64,
    pub(crate) treasury_coins: u64,
    pub(crate) last_swap: i64,
}

/// Bring every wrapped-SOL unit the account holds that is nobody's yet into the buckets.
fn allocate(t: &mut Tokenomics, tk: Pubkey, held: u64) {
    let amount = held.saturating_sub(t.tracked());
    if amount == 0 {
        return;
    }
    let parts = split(amount, &t.bps);
    for i in 0..MAX_BUCKETS {
        t.buckets[i] += parts[i];
    }
    t.total_received = t.total_received.saturating_add(amount);
    emit!(TokenomicsAllocated { tokenomics: tk, amount, per_bucket: parts });
}

pub(crate) fn skipped(tk: Pubkey, step: u8, reason: u8) {
    emit!(TokenomicsSkipped { tokenomics: tk, step, reason });
}

pub fn execute_handler<'info>(ctx: Context<'_, '_, 'info, 'info, Execute<'info>>) -> Result<()> {
    alone_in_transaction_with(&ctx.accounts.instructions, true)?;
    let all = ctx.accounts.to_account_infos();
    let a = &ctx.accounts;
    let tk = a.tokenomics.key();
    let caller = a.caller.to_account_info();
    require!(*caller.owner == System::id() && caller.data_is_empty(), TokenomicsError::CallerNotAWallet);
    vault_accounts(tk, a.tokenomics.mint, &a.vault_wsol, &a.vault_coin)?;
    // A caller may not pass a payable wallet read-only to have its payout deferred; anything else
    // (a program id, a sysvar: keys the runtime may never write-lock) is deferred instead of
    // stopping every run.
    require!(writable_or_reserved(&a.owner) || a.tokenomics.bps[CREATOR] == 0, TokenomicsError::NotTheRole);
    require!(writable_or_reserved(&a.community) || a.tokenomics.bps[COMMUNITY] == 0, TokenomicsError::NotTheRole);
    let now = Clock::get()?.unix_timestamp;

    let mut t: Tokenomics = (**a.tokenomics).clone();
    allocate(&mut t, tk, balance(&a.vault_wsol)?);

    // The ADMIN's rules, read live (`PDA(["tk2-min"])`, shared with v2): the minimum (0 until set;
    // `MIN_EXECUTE_LAMPORTS` is what the program enforced before, kept for readers), and the
    // operator's repayment -- the run's cost x (1 + margin), at most the cap of what it pays out.
    // Nobody but `Tk2Config.operator` is repaid; there is no reserve (owner, 2026-10-27).
    let rules = crate::tk2_rules(&a.min)?;
    let operator = crate::operator_of(&a.config)?.is_some_and(|o| o == caller.key());
    let minimum = rules.min_execute_lamports;
    let due = |b: u64| b >= minimum && b != 0;
    // A swap holds the cap's share of its bucket back for the operator's repayment; what the
    // repayment does not take stays in the bucket. Nobody else's run holds anything back.
    let cap = if operator { rules.cap_bps as u128 } else { 0 };
    let budget = |b: u64| ((b as u128 * BPS as u128) / (BPS as u128 + cap)) as u64;
    let rent_from = caller.lamports();
    let mut run = Run::default();
    require!(t.num_buckets as usize == NUM_BUCKETS, TokenomicsError::BadConfig);

    let buy_due = due(t.buckets[BURN]);
    let back_due = due(t.buckets[BUYBACK]);
    // Once the account has a position, a run names it: a caller may not skip the liquidity add
    // by naming something else.
    let has_position = t.lp_position != Pubkey::default();
    if has_position {
        require_keys_eq!(a.lp_position.key(), t.lp_position, TokenomicsError::NotTheAccount);
    }
    // Coins held for liquidity are added with whatever the bucket has, even under the minimum, so
    // they are never stranded when fees stop.
    let liq_due = (due(t.buckets[LIQUIDITY]) || (t.liquidity_coins > 0 && t.buckets[LIQUIDITY] > 0)) && has_position;
    if due(t.buckets[LIQUIDITY]) && !has_position {
        skipped(tk, 2, 6);
    }
    if buy_due || back_due || liq_due {
        if now < t.last_swap.saturating_add(rules.swap_cooldown_secs.max(crate::MIN_SWAP_COOLDOWN_SECS) as i64) {
            skipped(tk, 1, 4);
        } else {
            let burn = if buy_due { budget(t.buckets[BURN]) } else { 0 };
            let back = if back_due { budget(t.buckets[BUYBACK]) } else { 0 };
            let liq = if liq_due { budget(t.buckets[LIQUIDITY]) } else { 0 };
            // Under the minimum (a run for coins held for liquidity), the bucket only pairs them:
            // it buys no more coins.
            let liq_add_only = !due(t.buckets[LIQUIDITY]);
            let acc = BuyAccounts {
                tk,
                quote_mint: spl_token::native_mint::ID,
                quote_program: spl_token::ID,
                caller: a.caller.as_ref(),
                vault_wsol: a.vault_wsol.as_ref(),
                vault_coin: a.vault_coin.as_ref(),
                treasury_coin: a.treasury_coin.as_ref(),
                incinerator_coin: a.incinerator_coin.as_ref(),
                pool: a.pool.as_ref(),
                token_a_vault: a.token_a_vault.as_ref(),
                token_b_vault: a.token_b_vault.as_ref(),
                mint: a.mint.as_ref(),
                lp_position: a.lp_position.as_ref(),
                lp_nft_account: a.lp_nft_account.as_ref(),
                cp_amm_event_authority: a.cp_amm_event_authority.as_ref(),
            };
            let mut books = BuyBooks { mint: t.mint, treasury: t.treasury, liquidity_coins: t.liquidity_coins, treasury_coins: t.treasury_coins, last_swap: t.last_swap };
            let (seed_, bump_) = t.seed_parts();
            let seeds: [&[u8]; 3] = [TOKENOMICS_SEED, &seed_, &bump_];
            buy_stage(&all, &acc, &mut books, &seeds, &mut run, burn, back, liq, liq_add_only, now, rules.max_move_fee_bps)?;
            t.liquidity_coins = books.liquidity_coins;
            t.treasury_coins = books.treasury_coins;
            t.last_swap = books.last_swap;
        }
    }

    // The paying buckets pay out whole (less their share of the operator's repayment, below).
    let pays = [CREATOR, COMMUNITY];
    for &i in &pays {
        if due(t.buckets[i]) {
            run.spend[i] = t.buckets[i];
        }
    }
    let total: u64 = run.spend.iter().take(NUM_BUCKETS).sum();
    require!(total > 0, TokenomicsError::NothingToExecute);
    // The operator's repayment: what the run cost x (1 + margin), refused above the cap of what it
    // pays out; pro rata off every bucket that paid out.
    let owed = if operator { crate::operator_repay(&a.instructions, rent_from.saturating_sub(caller.lamports()), rules, total)? } else { 0 };
    let mut share = [0u64; MAX_BUCKETS];
    let mut left = owed;
    for i in 0..NUM_BUCKETS {
        if run.spend[i] > 0 {
            share[i] = ((owed as u128 * run.spend[i] as u128) / total as u128) as u64;
            left -= share[i];
        }
    }
    // The dust: off a paying bucket's payout, else off a swapping bucket's held-back part.
    for i in 0..NUM_BUCKETS {
        if left == 0 {
            break;
        }
        if run.spend[i] == 0 {
            continue;
        }
        let room = if pays.contains(&i) { run.spend[i] - share[i] } else { t.buckets[i] - run.spend[i] - share[i] };
        let d = left.min(room);
        share[i] += d;
        left -= d;
    }
    require!(left == 0, TokenomicsError::Overflow);
    for i in 0..NUM_BUCKETS {
        let s = run.spend[i];
        if s == 0 {
            continue;
        }
        if pays.contains(&i) {
            // The bucket goes whole: the payout and its share of the repayment.
            t.buckets[i] -= s;
            t.spent[i] += s - share[i];
            emit!(TokenomicsSpent { tokenomics: tk, bucket: i as u8, lamports: s - share[i] });
        } else {
            t.buckets[i] = t.buckets[i].checked_sub(s + share[i]).ok_or(TokenomicsError::Overflow)?;
            t.spent[i] += s;
            emit!(TokenomicsSpent { tokenomics: tk, bucket: i as u8, lamports: s });
        }
    }
    t.reimbursed += owed;
    // The paying buckets' SOL to the wallet, or kept for it when it cannot take SOL.
    let mut to_owner = 0u64;
    let mut to_community = 0u64;
    if run.spend[CREATOR] > 0 {
        let x = run.spend[CREATOR] - share[CREATOR];
        if takes_sol(&a.owner, x)? {
            to_owner = x;
        } else {
            t.deferred_owner += x;
            emit!(TokenomicsDeferred { tokenomics: tk, bucket: CREATOR as u8, to: t.owner, lamports: x });
        }
    }
    if run.spend[COMMUNITY] > 0 {
        let x = run.spend[COMMUNITY] - share[COMMUNITY];
        let same_wallet = a.community.key() == a.owner.key();
        if takes_sol(&a.community, x + if same_wallet { to_owner } else { 0 })? {
            to_community = x;
        } else {
            t.deferred_community += x;
            emit!(TokenomicsDeferred { tokenomics: tk, bucket: COMMUNITY as u8, to: t.community, lamports: x });
        }
    }

    // The SOL: the wallets' and the caller's fee, unwrapped through the caller, then passed on.
    let out = to_owner + to_community + owed;
    let (seed_, bump_) = t.seed_parts();
    let seeds: [&[u8]; 3] = [TOKENOMICS_SEED, &seed_, &bump_];
    let tk_info = a.tokenomics.to_account_info();
    unwrap_to(&all, &caller, &a.temp, ctx.bumps.temp, &tk_info, &seeds, &a.vault_wsol, out)?;
    pay(&all, &caller, &a.owner, to_owner)?;
    pay(&all, &caller, &a.community, to_community)?;
    if to_owner > 0 {
        emit!(TokenomicsPaid { tokenomics: tk, bucket: CREATOR as u8, to: t.owner, lamports: to_owner });
    }
    if to_community > 0 {
        emit!(TokenomicsPaid { tokenomics: tk, bucket: COMMUNITY as u8, to: t.community, lamports: to_community });
    }
    emit!(TokenomicsReimbursed { tokenomics: tk, caller: caller.key(), lamports: owed });
    t.coins_burned += run.coins_burned;
    t.coins_to_treasury += run.coins_to_treasury;

    // Everything the account holds is accounted for, to the unit.
    require!(balance(&a.vault_wsol)? >= t.tracked(), TokenomicsError::Overflow);
    require!(balance(&a.vault_coin)? >= t.liquidity_coins + t.treasury_coins, TokenomicsError::Overflow);
    **ctx.accounts.tokenomics = t;
    Ok(())
}

/// The three buying buckets' budgets, in one capped, guarded swap -- the coin at most
/// `max_move_fee_bps` of the pool's fee dearer after it (`Tk2Swap`) -- then the burn, the
/// treasury's coins and the liquidity add. Skips -- saying why -- rather than failing, wherever it can.
#[allow(clippy::too_many_arguments)]
pub(crate) fn buy_stage<'info>(
    all: &[AccountInfo<'info>],
    a: &BuyAccounts<'_, 'info>,
    t: &mut BuyBooks,
    seeds: &[&[u8]],
    run: &mut Run,
    mut burn: u64,
    mut back: u64,
    liq_budget: u64,
    liq_add_only: bool,
    now: i64,
    max_move_fee_bps: u16,
) -> Result<()> {
    let tk = a.tk;
    let p = read_pool_state(a.pool)?;
    if !p.enabled {
        skipped(tk, 1, 5);
        return Ok(());
    }
    let s = p.sqrt_price;
    // The cap: the swap may make the coin at most `max_move_fee_bps` of the pool's fee dearer.
    let fee = p.fee_numerator;
    let limit = dearer_by(s, move_numerator(fee, max_move_fee_bps)).ok_or(TokenomicsError::Overflow)?.min(p.sqrt_max);
    let room = ((gross_for_net(net_to_reach(s, limit, p.cap_liquidity), fee) as u128 * ROOM_MARGIN_BPS) / BPS as u128) as u64;
    if room == 0 {
        skipped(tk, 1, 3);
        return Ok(());
    }
    // The liquidity budget: the coin's share of an add, priced where this run's own swap leaves
    // the price (a first pass sizes the swap with today's share).
    let one = 1_000_000_000_000_000_000u128;
    let mut liq_swap = 0u64;
    if liq_budget != 0 && !liq_add_only {
        let first = (burn as u128 + back as u128 + mul_div(liq_budget as u128, coin_share(s, p.sqrt_min, p.sqrt_max), one).unwrap_or(0)).min(room as u128) as u64;
        let ends = if first == 0 { s } else { buy(p.liquidity, s, fee, first).map(|x| x.1).unwrap_or(s) };
        let held_value = coin_value(t.liquidity_coins, ends);
        let target = mul_div(liq_budget as u128 + held_value as u128, coin_share(ends, p.sqrt_min, p.sqrt_max), one).unwrap_or(0) as u64;
        liq_swap = target.saturating_sub(held_value).min(liq_budget);
    }
    let mut liq_keep = liq_budget - liq_swap;
    let want = burn as u128 + back as u128 + liq_swap as u128;
    if want == 0 {
        if liq_budget != 0 && t.liquidity_coins != 0 {
            let held = t.liquidity_coins;
            let (sol_in, coins_in) = add_liquidity(all, a, seeds, liq_budget, held)?;
            run.spend[LIQUIDITY] = sol_in;
            t.liquidity_coins = held - coins_in;
            // An add is a step of the cadence too: at most one per cooldown, swap or not.
            if sol_in > 0 || coins_in > 0 {
                t.last_swap = now;
            }
        }
        return Ok(());
    }
    if want > room as u128 {
        let scale = |x: u64| ((x as u128 * room as u128) / want) as u64;
        burn = scale(burn);
        back = scale(back);
        liq_swap = scale(liq_swap);
        liq_keep = scale(liq_keep);
    }
    let gross = burn + back + liq_swap;
    if gross == 0 {
        return Ok(());
    }

    let (expected, _) = buy(p.liquidity, s, fee, gross).ok_or(TokenomicsError::Overflow)?;
    if expected == 0 {
        skipped(tk, 1, 3);
        return Ok(());
    }
    let minimum = ((expected as u128 * SWAP_OUT_MARGIN_BPS) / BPS as u128) as u64;
    let coins_before = balance(a.vault_coin)?;
    let mut data = SWAP_DISCRIMINATOR.to_vec();
    data.extend_from_slice(&gross.to_le_bytes());
    data.extend_from_slice(&minimum.max(1).to_le_bytes());
    let accounts = vec![
        ro(&POOL_AUTHORITY),
        rw(&a.pool.key()),
        rw(&a.vault_wsol.key()),
        rw(&a.vault_coin.key()),
        rw(&a.token_a_vault.key()),
        rw(&a.token_b_vault.key()),
        ro(&a.mint.key()),
        ro(&a.quote_mint),
        AccountMeta::new_readonly(tk, true),
        ro(&anchor_spl::token_2022::ID),
        ro(&a.quote_program),
        ro(&CP_AMM_ID), // no referral account: Anchor's "none" is the program's own id
        ro(&a.cp_amm_event_authority.key()),
        ro(&CP_AMM_ID),
    ];
    send(all, CP_AMM_ID, accounts, data, &[seeds])?;
    let coins = balance(a.vault_coin)?.checked_sub(coins_before).ok_or(TokenomicsError::Overflow)?;
    let after = read_pool_state(a.pool)?.sqrt_price;
    require!(after <= limit, TokenomicsError::PriceMovedTooFar);
    t.last_swap = now;
    emit!(TokenomicsSwapped { tokenomics: tk, sol_in: gross, coins_out: coins, sqrt_before: s, sqrt_after: after });

    // The coins, shared by what each bucket put in; the rounding to the first that put anything.
    let share = |x: u64| ((coins as u128 * x as u128) / gross as u128) as u64;
    let (mut c_burn, mut c_back, mut c_liq) = (share(burn), share(back), share(liq_swap));
    let dust = coins - c_burn - c_back - c_liq;
    if burn != 0 {
        c_burn += dust;
    } else if back != 0 {
        c_back += dust;
    } else {
        c_liq += dust;
    }
    run.spend[BURN] = burn;
    run.spend[BUYBACK] = back;
    run.spend[LIQUIDITY] = liq_swap;

    let mint = t.mint;
    if c_back != 0 {
        require_keys_eq!(
            a.treasury_coin.key(),
            get_associated_token_address_with_program_id(&t.treasury, &mint, &anchor_spl::token_2022::ID),
            TokenomicsError::NotTheAccount
        );
        // An account that is not there (bind made it; its holder may close it) or requires a memo
        // on every transfer in would cost the caller its rent, or refuse this transfer and the whole
        // run with it: its coins are kept for the treasury instead, to take when it likes.
        let there = *a.treasury_coin.owner == anchor_spl::token_2022::ID && !a.treasury_coin.data_is_empty();
        if !there || requires_memo(&a.treasury_coin) {
            t.treasury_coins += c_back;
            emit!(TokenomicsDeferred { tokenomics: tk, bucket: BUYBACK as u8, to: t.treasury, lamports: c_back });
        } else {
            send_coins(all, &a.vault_coin.key(), &mint, &a.treasury_coin.key(), &tk, seeds, c_back)?;
            emit!(TokenomicsSentToTreasury { tokenomics: tk, treasury: t.treasury, coins: c_back });
        }
        run.coins_to_treasury = c_back;
    }
    if liq_budget != 0 {
        let for_add = c_liq + t.liquidity_coins;
        if for_add != 0 {
            let (sol_in, coins_in) = add_liquidity(all, a, seeds, liq_keep, for_add)?;
            run.spend[LIQUIDITY] += sol_in;
            t.liquidity_coins = for_add - coins_in;
        }
    }
    if c_burn != 0 {
        ensure_coin_account(all, &a.caller.key(), a.incinerator_coin, &incinerator::ID, &mint)?;
        send_coins(all, &a.vault_coin.key(), &mint, &a.incinerator_coin.key(), &tk, seeds, c_burn)?;
        run.coins_burned = c_burn;
        emit!(TokenomicsBurned { tokenomics: tk, coins: c_burn });
    }
    Ok(())
}

/// Add `sol` and `coins` to the pool on the account's position, at the price as it stands, and
/// lock what was added for good. Returns what it took; nothing when the add would be nothing.
pub(crate) fn add_liquidity<'info>(all: &[AccountInfo<'info>], a: &BuyAccounts<'_, 'info>, seeds: &[&[u8]], sol: u64, coins: u64) -> Result<(u64, u64)> {
    let tk = a.tk;
    let p = read_pool_state(a.pool)?;
    let l = liquidity_for(p.sqrt_price, p.sqrt_min, p.sqrt_max, sol, coins);
    let l = mul_div(l, LIQUIDITY_MARGIN_BPS, BPS as u128).unwrap_or(0);
    // No cap on the add's size (owner decision 2026-10-22): it adds all it can pair, at the price as
    // it stands -- an add at a price somebody pushed loses when the price comes back (the accepted
    // risk). The cooldown (`Tk2Swap`), which every add refreshes, and the swap's impact cap stay.
    if l == 0 {
        skipped(tk, 2, 7);
        return Ok((0, 0));
    }
    let (sol_before, coins_before) = (balance(a.vault_wsol)?, balance(a.vault_coin)?);
    let mut data = ADD_LIQUIDITY_DISCRIMINATOR.to_vec();
    data.extend_from_slice(&l.to_le_bytes());
    data.extend_from_slice(&coins.to_le_bytes());
    data.extend_from_slice(&sol.to_le_bytes());
    let accounts = vec![
        rw(&a.pool.key()),
        rw(&a.lp_position.key()),
        rw(&a.vault_coin.key()),
        rw(&a.vault_wsol.key()),
        rw(&a.token_a_vault.key()),
        rw(&a.token_b_vault.key()),
        ro(&a.mint.key()),
        ro(&a.quote_mint),
        ro(&a.lp_nft_account.key()),
        AccountMeta::new_readonly(tk, true),
        ro(&anchor_spl::token_2022::ID),
        ro(&a.quote_program),
        ro(&a.cp_amm_event_authority.key()),
        ro(&CP_AMM_ID),
    ];
    send(all, CP_AMM_ID, accounts, data, &[seeds])?;
    // Lock everything the position holds unlocked: what was just added.
    let unlocked = u128_at(&a.lp_position.try_borrow_data()?, POSITION_UNLOCKED)?;
    let mut lock = LOCK_DISCRIMINATOR.to_vec();
    lock.extend_from_slice(&unlocked.to_le_bytes());
    send(
        all,
        CP_AMM_ID,
        vec![rw(&a.pool.key()), rw(&a.lp_position.key()), ro(&a.lp_nft_account.key()), AccountMeta::new_readonly(tk, true), ro(&a.cp_amm_event_authority.key()), ro(&CP_AMM_ID)],
        lock,
        &[seeds],
    )?;
    require!(u128_at(&a.lp_position.try_borrow_data()?, POSITION_UNLOCKED)? == 0, TokenomicsError::Overflow);
    let sol_in = sol_before.checked_sub(balance(a.vault_wsol)?).ok_or(TokenomicsError::Overflow)?;
    let coins_in = coins_before.checked_sub(balance(a.vault_coin)?).ok_or(TokenomicsError::Overflow)?;
    require!(sol_in <= sol && coins_in <= coins, TokenomicsError::Overflow);
    emit!(TokenomicsLiquidityAdded { tokenomics: tk, liquidity: l, sol_in, coins_in });
    Ok((sol_in, coins_in))
}

// ------------------------------------------------------------------------------ claims

#[derive(Accounts)]
pub struct ClaimOwn<'info> {
    /// The owner (for the creator bucket and the owner's deferred payouts) or the community wallet.
    #[account(mut)]
    pub claimer: Signer<'info>,
    #[account(mut, constraint = tokenomics.bound @ TokenomicsError::NotBound)]
    pub tokenomics: Box<Account<'info, Tokenomics>>,
    /// CHECK: the account's associated wrapped-SOL account.
    #[account(mut)]
    pub vault_wsol: UncheckedAccount<'info>,
    /// CHECK: `PDA(["tk-temp", tokenomics])`.
    #[account(mut, seeds = [TK_TEMP_SEED, tokenomics.key().as_ref()], bump)]
    pub temp: UncheckedAccount<'info>,
    /// CHECK: pinned.
    #[account(address = spl_token::native_mint::ID)]
    pub wsol_mint: UncheckedAccount<'info>,
    /// CHECK: pinned.
    #[account(address = spl_token::ID)]
    pub token_program: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

/// The owner takes the creator bucket, or the community wallet its bucket, at any size, with what
/// either is owed of payouts it could not take: all of it, as SOL, to the signer. No fee is repaid
/// (the caller pays its own) and nothing reaches anybody else. Below the minimum `execute` never
/// pays a bucket, so on a quiet coin this is how they are paid.
pub fn claim_own_handler<'info>(ctx: Context<'_, '_, 'info, 'info, ClaimOwn<'info>>) -> Result<()> {
    let all = ctx.accounts.to_account_infos();
    let a = &ctx.accounts;
    let tk = a.tokenomics.key();
    require_keys_eq!(
        a.vault_wsol.key(),
        get_associated_token_address_with_program_id(&tk, &spl_token::native_mint::ID, &spl_token::ID),
        TokenomicsError::NotTheAccount
    );
    let who = a.claimer.key();
    let mut t: Tokenomics = (**a.tokenomics).clone();
    allocate(&mut t, tk, balance(&a.vault_wsol)?);
    let mut amount = 0u64;
    let mut any = false;
    if who == t.owner {
        any = true;
        amount += t.buckets[CREATOR] + t.deferred_owner;
        t.spent[CREATOR] += t.buckets[CREATOR];
        if t.buckets[CREATOR] > 0 {
            emit!(TokenomicsSpent { tokenomics: tk, bucket: CREATOR as u8, lamports: t.buckets[CREATOR] });
        }
        t.buckets[CREATOR] = 0;
        t.deferred_owner = 0;
    }
    if who == t.community {
        any = true;
        amount += t.buckets[COMMUNITY] + t.deferred_community;
        t.spent[COMMUNITY] += t.buckets[COMMUNITY];
        if t.buckets[COMMUNITY] > 0 {
            emit!(TokenomicsSpent { tokenomics: tk, bucket: COMMUNITY as u8, lamports: t.buckets[COMMUNITY] });
        }
        t.buckets[COMMUNITY] = 0;
        t.deferred_community = 0;
    }
    require!(any, TokenomicsError::NotTheRole);
    require!(amount > 0, TokenomicsError::NothingToClaim);
    let (seed_, bump_) = t.seed_parts();
    let seeds: [&[u8]; 3] = [TOKENOMICS_SEED, &seed_, &bump_];
    let tk_info = a.tokenomics.to_account_info();
    let claimer = a.claimer.to_account_info();
    unwrap_to(&all, &claimer, &a.temp, ctx.bumps.temp, &tk_info, &seeds, &a.vault_wsol, amount)?;
    emit!(TokenomicsPaid { tokenomics: tk, bucket: if who == t.owner { CREATOR as u8 } else { COMMUNITY as u8 }, to: who, lamports: amount });
    **ctx.accounts.tokenomics = t;
    Ok(())
}

// ------------------------------------------------------------------------------ strays

#[derive(Accounts)]
pub struct SweepWsol<'info> {
    #[account(mut)]
    pub tokenomics: Box<Account<'info, Tokenomics>>,
    /// CHECK: a wrapped-SOL account the tokenomics account owns, other than its own associated one.
    #[account(mut)]
    pub stray: UncheckedAccount<'info>,
    /// CHECK: the account's associated wrapped-SOL account.
    #[account(mut)]
    pub vault_wsol: UncheckedAccount<'info>,
    /// CHECK: pinned.
    #[account(address = spl_token::native_mint::ID)]
    pub wsol_mint: UncheckedAccount<'info>,
    /// CHECK: pinned.
    #[account(address = spl_token::ID)]
    pub token_program: UncheckedAccount<'info>,
}

/// Anyone: a wrapped-SOL account the tokenomics account owns that is NOT its associated one -- one
/// anybody can make, and `claim_fees` will pay a creator's share into any account its creator
/// owns -- emptied into the associated one, where it is fees like any, and closed (its rent
/// becomes the account's lamports, the owner's: `forward_tokenomics_refund`). So nothing paid to
/// the account can be stranded, wherever it was paid.
pub fn sweep_wsol_handler<'info>(ctx: Context<'_, '_, 'info, 'info, SweepWsol<'info>>) -> Result<()> {
    let all = ctx.accounts.to_account_infos();
    let a = &ctx.accounts;
    let tk = a.tokenomics.key();
    let vault = get_associated_token_address_with_program_id(&tk, &spl_token::native_mint::ID, &spl_token::ID);
    require_keys_eq!(a.vault_wsol.key(), vault, TokenomicsError::NotTheAccount);
    require_keys_neq!(a.stray.key(), vault, TokenomicsError::NotTheAccount);
    require_keys_eq!(*a.stray.owner, spl_token::ID, TokenomicsError::NotTheAccount);
    let (mint, owner, amount) = token_account(&a.stray).ok_or(TokenomicsError::NotTheAccount)?;
    require_keys_eq!(mint, spl_token::native_mint::ID, TokenomicsError::NotTheAccount);
    require_keys_eq!(owner, tk, TokenomicsError::NotTheAccount);
    let (seed_, bump_) = a.tokenomics.seed_parts();
    let seeds: [&[u8]; 3] = [TOKENOMICS_SEED, &seed_, &bump_];
    if amount > 0 {
        let ix = spl_token::instruction::transfer_checked(&spl_token::ID, &a.stray.key(), &spl_token::native_mint::ID, &vault, &tk, &[], amount, 9)?;
        invoke_signed(&ix, &all, &[&seeds])?;
    }
    let ix = spl_token::instruction::close_account(&spl_token::ID, &a.stray.key(), &tk, &tk, &[])?;
    invoke_signed(&ix, &all, &[&seeds])?;
    emit!(TokenomicsForwarded { tokenomics: tk, to: vault, lamports: 0, coins: amount });
    Ok(())
}

#[derive(Accounts)]
pub struct ClaimTreasuryCoins<'info> {
    /// The treasury.
    pub treasury: Signer<'info>,
    #[account(mut, has_one = treasury @ TokenomicsError::NotTheRole, constraint = tokenomics.bound @ TokenomicsError::NotBound)]
    pub tokenomics: Box<Account<'info, Tokenomics>>,
    /// CHECK: the account's associated coin account.
    #[account(mut)]
    pub vault_coin: UncheckedAccount<'info>,
    /// CHECK: where the treasury wants its coins: any account of the coin (Token-2022 checks it).
    #[account(mut)]
    pub to: UncheckedAccount<'info>,
    /// CHECK: the coin.
    #[account(address = tokenomics.mint @ TokenomicsError::NotTheAccount)]
    pub mint: UncheckedAccount<'info>,
    pub token_2022_program: Program<'info, Token2022>,
}

/// The treasury takes the coins kept for it (its account required memos), into any account it names.
pub fn claim_treasury_coins_handler<'info>(ctx: Context<'_, '_, 'info, 'info, ClaimTreasuryCoins<'info>>) -> Result<()> {
    let all = ctx.accounts.to_account_infos();
    let a = &ctx.accounts;
    let tk = a.tokenomics.key();
    let mint = a.tokenomics.mint;
    require_keys_eq!(a.vault_coin.key(), get_associated_token_address_with_program_id(&tk, &mint, &anchor_spl::token_2022::ID), TokenomicsError::NotTheAccount);
    let amount = a.tokenomics.treasury_coins;
    require!(amount > 0, TokenomicsError::NothingToClaim);
    let (seed_, bump_) = a.tokenomics.seed_parts();
    let seeds: [&[u8]; 3] = [TOKENOMICS_SEED, &seed_, &bump_];
    send_coins(&all, &a.vault_coin.key(), &mint, &a.to.key(), &tk, &seeds, amount)?;
    let treasury = a.treasury.key();
    ctx.accounts.tokenomics.treasury_coins = 0;
    emit!(TokenomicsSentToTreasury { tokenomics: tk, treasury, coins: amount });
    Ok(())
}

// ------------------------------------------------------------------------------ roles

pub const ROLE_OWNER: u8 = 0;
pub const ROLE_TREASURY: u8 = 1;
pub const ROLE_COMMUNITY: u8 = 2;

#[derive(Accounts)]
pub struct TokenomicsRole<'info> {
    pub signer: Signer<'info>,
    #[account(mut)]
    pub tokenomics: Box<Account<'info, Tokenomics>>,
}

fn role_slots(t: &mut Tokenomics, role: u8) -> Result<(&mut Pubkey, &mut Pubkey)> {
    match role {
        ROLE_OWNER => Ok((&mut t.owner, &mut t.pending_owner)),
        ROLE_TREASURY => Ok((&mut t.treasury, &mut t.pending_treasury)),
        ROLE_COMMUNITY => Ok((&mut t.community, &mut t.pending_community)),
        _ => err!(TokenomicsError::NoSuchRole),
    }
}

/// A recipient offers its own role to `to`; it applies when `to` accepts. Only the holder can.
pub fn propose_role_handler(ctx: Context<TokenomicsRole>, role: u8, to: Pubkey) -> Result<()> {
    // Not before the launch is bound: the launch counts the OWNER's payment as the account's
    // (pays_for), and an owner changed in between would leave a paid launch unable to land.
    require!(ctx.accounts.tokenomics.bound, TokenomicsError::NotBound);
    let who = ctx.accounts.signer.key();
    let tk = ctx.accounts.tokenomics.key();
    require!(to != Pubkey::default() && to != tk, TokenomicsError::BadConfig);
    require!(!(role == ROLE_OWNER && to == incinerator::ID), TokenomicsError::BadConfig);
    let t = &mut ctx.accounts.tokenomics;
    let (current, pending) = role_slots(t, role)?;
    require_keys_eq!(*current, who, TokenomicsError::NotTheRole);
    *pending = to;
    emit!(TokenomicsRoleProposed { tokenomics: tk, role, from: who, to });
    Ok(())
}

pub fn accept_role_handler(ctx: Context<TokenomicsRole>, role: u8) -> Result<()> {
    require!(ctx.accounts.tokenomics.bound, TokenomicsError::NotBound);
    let who = ctx.accounts.signer.key();
    let tk = ctx.accounts.tokenomics.key();
    let t = &mut ctx.accounts.tokenomics;
    // Deferred payouts follow the role: they are its, and the new holder takes them.
    let (current, pending) = role_slots(t, role)?;
    require!(*pending != Pubkey::default(), TokenomicsError::NotTheRole);
    require_keys_eq!(*pending, who, TokenomicsError::NotTheRole);
    let from = *current;
    *current = who;
    *pending = Pubkey::default();
    emit!(TokenomicsRoleChanged { tokenomics: tk, role, from, to: who });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_config_hashes_as_the_evm_factory_does() {
        // test/fixtures/tokenomics-vector.json
        let h = |s: &str| {
            let s = s.trim_start_matches("0x");
            (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect::<Vec<u8>>()
        };
        let c = TokenomicsConfig {
            launch_id: [0xab; 32],
            owner_evm: [0x33; 20],
            treasury_evm: [0x44; 20],
            community_evm: [0x55; 20],
            legs: vec![TokenomicsLeg { eid: 30101, bps: vec![3000, 2000, 2000, 2000, 1000] }, TokenomicsLeg { eid: 30416, bps: vec![10000, 0, 0, 0, 0] }],
            recipients: vec![Pubkey::new_unique(), Pubkey::default(), Pubkey::default()],
        };
        assert_eq!(c.evm_config_hash().to_vec(), h("0x42354f6a0c7fc4ac815ffe0e9afb835f68cb85b7fec74f5a6778e1cd2275f9bd"));
        assert_eq!(c.solana_bps(), [0, 0, 0, 10_000, 0, 0, 0, 0], "no Solana leg: all to the creator");
    }

    /// The vector `web/lib/tokenomics/solana.test.mjs` holds the JavaScript to
    /// (`test/fixtures/tokenomics-solana-vector.json`): the EVM vector's config with a Solana leg.
    #[test]
    #[cfg(not(feature = "test-stack"))] // pinned to the live program id
    fn the_solana_vector() {
        let c = TokenomicsConfig {
            launch_id: [0xab; 32],
            owner_evm: [0x33; 20],
            treasury_evm: [0x44; 20],
            community_evm: [0x55; 20],
            legs: vec![
                TokenomicsLeg { eid: 30101, bps: vec![3000, 2000, 2000, 2000, 1000] },
                TokenomicsLeg { eid: SOLANA_EID, bps: vec![2000, 2000, 2000, 2000, 2000] },
                TokenomicsLeg { eid: 30416, bps: vec![10000, 0, 0, 0, 0] },
            ],
            recipients: vec![Pubkey::new_from_array([0x11; 32]), Pubkey::new_from_array([0x22; 32]), Pubkey::new_from_array([0x33; 32])],
        };
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let address = Pubkey::find_program_address(&[TOKENOMICS_SEED, &c.seed()], &crate::ID).0;
        println!("configHash 0x{}\nseed 0x{}\naddress {address}\nborsh {}", hex(&c.evm_config_hash()), hex(&c.seed()), hex(&c.try_to_vec().unwrap()));
        assert_eq!(hex(&c.seed()), SOLANA_VECTOR_SEED);
        assert_eq!(address.to_string(), SOLANA_VECTOR_ADDRESS);
    }

    #[test]
    fn a_split_sums_to_the_amount_and_rounds_to_the_first_share() {
        assert_eq!(split(1_000_000_000, &[2000, 2000, 2000, 2000, 2000, 0, 0, 0]), [200_000_000, 200_000_000, 200_000_000, 200_000_000, 200_000_000, 0, 0, 0]);
        assert_eq!(split(7, &[0, 3333, 3333, 3334, 0, 0, 0, 0]), [0, 3, 2, 2, 0, 0, 0, 0]);
        let s = split(123_456_789, &[1, 2, 3, 4, 9990, 0, 0, 0]);
        assert_eq!(s.iter().sum::<u64>(), 123_456_789);
    }

    #[test]
    fn the_median_of_three() {
        for (a, b, c) in [(1, 2, 3), (3, 2, 1), (2, 3, 1), (1, 3, 2), (2, 1, 3), (3, 1, 2), (5, 5, 1)] {
            let mut v = [a, b, c];
            v.sort();
            assert_eq!(median3(a, b, c), v[1]);
        }
    }

    #[test]
    fn sqrt_factors_and_bounds() {
        assert_eq!(sqrt_factor(0), 1_000_000_000_000_000_000);
        // sqrt(1.03) = 1.014889156509221...
        assert_eq!(sqrt_factor(bps_numerator(300)) / 1_000_000_000, 1_014_889_156);
        let s = 1u128 << 64;
        let d = dearer_by(s, 10_000_000).unwrap();
        assert!(d > s && d < s + s / 100);
        let c = cheaper_by(s, 10_000_000).unwrap();
        assert!(c < s);
        assert_eq!(mul_div(u128::MAX, 2, 4), Some(u128::MAX / 2));
        assert_eq!(mul_div_up(10, 1, 3), Some(4));
        assert_eq!(mul_div_up(9, 1, 3), Some(3));
        assert_eq!(isqrt(u128::MAX), 18446744073709551615);
    }

    #[test]
    fn a_buy_sized_to_the_room_stays_under_the_cap() {
        let l: u128 = 3_000_000_000_000_000_000_000_000_000_000; // deep enough for a room at a quarter of a 0.3% fee
        let s: u128 = 6_000_000_000_000_000;
        for fee in [3_000_000u64, 10_000_000, 50_000_000] {
            for move_bps in [2_500u16, 5_000, 10_000] {
                let limit = dearer_by(s, move_numerator(fee, move_bps)).unwrap();
                let gross = gross_for_net(net_to_reach(s, limit, l), fee);
                assert!(gross > 0, "fee {fee}, move {move_bps}: a room to test");
                let (_, next) = buy(l, s, fee, gross).unwrap();
                assert!(next <= limit, "fee {fee}, move {move_bps}: {next} > {limit}");
                let (_, over) = buy(l, s, fee, gross + gross / 50 + 10).unwrap();
                assert!(over > limit, "the room is the room, not a lot less");
            }
        }
    }

    /// The swap's cap as a share of the pool's fee: 10,000 bps is the fee (the default and the
    /// ADMIN's most); rounded down; never overflowing for any fee Meteora allows.
    #[test]
    fn the_move_cap_is_a_share_of_the_fee() {
        assert_eq!(move_numerator(10_000_000, 10_000), 10_000_000);
        assert_eq!(move_numerator(10_000_000, 20_000), 20_000_000);
        assert_eq!(move_numerator(3_000_000, 1), 300);
        assert_eq!(move_numerator(3, 1), 0, "rounded down");
        assert_eq!(move_numerator(999_999_999, u16::MAX), 6_553_499_993);
        let s = 1u128 << 64;
        // The most the ADMIN may set on a 1% pool: the price at most 1% up (sqrt(1.01) on the root).
        assert_eq!(crate::MAX_MOVE_FEE_BPS, 10_000);
        let d = dearer_by(s, move_numerator(10_000_000, crate::MAX_MOVE_FEE_BPS)).unwrap();
        let p = (d as f64 / s as f64).powi(2);
        assert!(p > 1.0099 && p <= 1.01, "{p}");
        assert!(dearer_by(s, move_numerator(999_999_999, crate::MAX_MOVE_FEE_BPS)).is_some());
    }

    #[test]
    fn the_coin_share_is_between_nothing_and_everything() {
        let (a, b) = (1u128 << 50, crate::CP_AMM_MAX_SQRT_PRICE);
        assert_eq!(coin_share(a, a, b), 1_000_000_000_000_000_000, "at the bottom: all coin");
        assert_eq!(coin_share(b, a, b), 0, "at the top: all SOL");
        let mid = coin_share(a * 2, a, b);
        assert!(mid > 666_000_000_000_000_000 && mid < 667_000_000_000_000_000, "{mid}: X = (b-s)s/b is about 2a, Y = s-a = a");
    }
}

#[cfg(test)]
const SOLANA_VECTOR_SEED: &str = "ef0fd0022945cc1561d2673d285c0caec3d1bcf3bb97ff6f4f75e04139ad629e";
#[cfg(test)]
const SOLANA_VECTOR_ADDRESS: &str = "Aa9EuSsmguxPwAiu4dTuqpWHpWztywSjwNif9iYooUGE";
