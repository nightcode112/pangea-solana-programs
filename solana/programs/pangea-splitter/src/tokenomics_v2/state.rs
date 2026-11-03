//! The v2 account, the program-wide v2 config, a holder's payout record, the config's rules on
//! Solana, the allocation, errors and events.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::incinerator;
use anchor_spl::token::spl_token;

use super::config::*;
use crate::tokenomics::{split, MAX_BUCKETS};
use crate::SOLANA_EID;

/// `PDA(["tk2-config"])`: the operator the ADMIN names (holder payouts, reward buys).
pub const TK2_CONFIG_SEED: &[u8] = b"tk2-config";
/// `PDA(["tk2-min"])`: the least a v2 bucket (`execute_tokenomics_v2`), the wallets in a crank's
/// range (`pay_tokenomics_wallets`) or a v1 bucket (`execute_tokenomics`) must hold before they are
/// spent (`Tk2Min`). The ADMIN sets it
/// (`set_tk2_min_execute`), 0 allowed; until it does the account does not exist and the minimum is
/// 0 (owner, 2026-10-27: no fixed payout minimum).
pub const TK2_MIN_SEED: &[u8] = b"tk2-min";
/// `PDA(["tk2-pot", tokenomics, [index]])`: the holders pot of reward entry `index`. It owns only
/// that entry's two token accounts -- its wrapped-SOL account (a native entry's pot, or an SPL
/// entry's budget) and, for an SPL entry, its token-`index` account -- so that a reward buy, which
/// it signs, can reach nothing else (one PDA per entry rather than one per account: the brief's
/// "separate PDA that owns ONLY holders-pot token accounts", made per entry so a buy of entry i
/// cannot touch entry j's pot either).
pub const TK2_POT_SEED: &[u8] = b"tk2-pot";
/// `PDA(["tk2-paid", tokenomics, [index], holder])`: how much of entry `index` the holder has been
/// paid in all (`Tk2Paid`).
pub const TK2_PAID_SEED: &[u8] = b"tk2-paid";
/// What a holder's claim voucher signs: `"pangea-tk2-claim" || program id:32 || cluster:u8 ||
/// tokenomics:32 || index:u8 || holder:32 || cumulative:u64 LE` (`holders::claim_message`).
pub const CLAIM_DOMAIN: &[u8] = b"pangea-tk2-claim";
/// The cluster a voucher is for, compiled per cluster (the genesis hash cannot be read on chain):
/// 1 mainnet (the default build), 2 devnet, 3 localnet (`--features localnet` on either).
#[cfg(feature = "localnet")]
pub const CLAIM_CLUSTER: u8 = 3;
#[cfg(all(feature = "devnet", not(feature = "localnet")))]
pub const CLAIM_CLUSTER: u8 = 2;
#[cfg(all(feature = "mainnet", not(feature = "devnet"), not(feature = "localnet")))]
pub const CLAIM_CLUSTER: u8 = 1;
pub const CLAIM_CLUSTER_MAINNET: u8 = 1;
pub const CLAIM_CLUSTER_DEVNET: u8 = 2;
pub const CLAIM_CLUSTER_LOCALNET: u8 = 3;

/// The account's spending buckets, in order. HOLDERS and WALLETS are not buckets: their shares go
/// straight to the reward entries and the wallets at allocation.
pub const V2_BURN: usize = 0;
pub const V2_BUYBACK: usize = 1;
pub const V2_LIQUIDITY: usize = 2;
pub const V2_BUCKETS: usize = 3;

/// One payout wallet's slot: its address (handed on only by itself, two-step), its share, what it
/// is owed (`accrued`) and what it has been paid.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, Default, PartialEq, Eq, InitSpace)]
pub struct WalletSlot {
    pub key: Pubkey,
    pub pending: Pubkey,
    pub bps: u16,
    pub accrued: u64,
    pub paid: u64,
}

/// One reward entry of the holders share: `token` (the zero key for native SOL) and its share of
/// the holders share. `incoming` is booked for the entry but still in the main vault (moved into
/// the entry's pot by the next holders instruction); `pot` is payable to holders (SOL as wrapped
/// SOL in the pot's wrapped-SOL account for a native entry, the token in the pot's token account
/// for an SPL entry); `budget` is wrapped SOL waiting to be swapped into the token (SPL only).
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, Default, PartialEq, Eq, InitSpace)]
pub struct RewardSlot {
    pub token: Pubkey,
    pub bps: u16,
    pub incoming: u64,
    pub pot: u64,
    pub budget: u64,
    /// Paid to holders, in the entry's token, ever.
    pub paid: u64,
    /// Bought with the budget, in the token, ever.
    pub bought: u64,
    /// The operator's gas and record rent repaid out of this entry, in lamports, ever.
    pub gas_repaid: u64,
}

impl RewardSlot {
    pub fn native(&self) -> bool {
        self.token == Pubkey::default()
    }
}

#[account]
#[derive(InitSpace)]
pub struct TokenomicsV2 {
    /// 2.
    pub version: u8,
    pub bump: u8,
    pub bound: bool,
    /// The seed: `configHash`, as every chain computes it.
    pub config_hash: [u8; 32],
    pub launch_id: [u8; 32],
    /// The config's `ownerSol`: metadata, forwarding, eligibility. Two-step hand-over.
    pub owner: Pubkey,
    pub pending_owner: Pubkey,
    /// The Solana leg's buy & hold treasury. Two-step hand-over.
    pub treasury: Pubkey,
    pub pending_treasury: Pubkey,
    /// The Solana leg's burn, buy & hold, liquidity and holders shares.
    pub bps: [u16; 4],
    pub num_wallets: u8,
    pub wallets: [WalletSlot; 10],
    pub num_rewards: u8,
    pub rewards: [RewardSlot; 5],
    /// Eligibility, for the payout service (the program does not use them): the least share of the
    /// supply a holder needs, in bps, the selection mode (0 all, 1 top, 2 random) and its count.
    pub min_holder_bps: u16,
    pub select_mode: u8,
    pub select_count: u32,
    /// Fixed at `bind_tokenomics_v2`, as v1's.
    pub mint: Pubkey,
    pub pool: Pubkey,
    pub record: Pubkey,
    pub slice: Pubkey,
    pub lp_position: Pubkey,
    pub lp_nft_mint: Pubkey,
    /// Wrapped SOL each spending bucket (burn, buy & hold, liquidity) holds, and has spent.
    pub buckets: [u64; 3],
    pub spent: [u64; 3],
    /// Lamports the address held before the account was made: fees (as v1's init treats them),
    /// moved into the vault at the bind, never forwarded to the owner.
    pub prefunded: u64,
    pub liquidity_coins: u64,
    pub treasury_coins: u64,
    pub last_swap: i64,
    pub created_at: i64,
    pub total_received: u64,
    pub coins_burned: u64,
    pub coins_to_treasury: u64,
    /// The operator's repayments, out of the spending buckets and the wallets' payouts.
    pub reimbursed: u64,
}

impl TokenomicsV2 {
    /// Wrapped SOL in the main vault that is some bucket's, some wallet's or some reward entry's.
    pub fn tracked(&self) -> u64 {
        let w: u64 = self.wallets[..self.num_wallets as usize].iter().map(|w| w.accrued).sum();
        let r: u64 = self.rewards[..self.num_rewards as usize].iter().map(|r| r.incoming).sum();
        self.buckets.iter().sum::<u64>() + w + r
    }

    pub fn wallet_bps(&self) -> u16 {
        self.wallets[..self.num_wallets as usize].iter().map(|w| w.bps).sum()
    }

    pub fn bump_bytes(&self) -> [u8; 1] {
        [self.bump]
    }
}

#[account]
#[derive(InitSpace)]
pub struct Tk2Config {
    pub bump: u8,
    /// Pays holders and buys reward tokens; signs claim vouchers. Set by the ADMIN.
    pub operator: Pubkey,
    /// The most the operator may take from one holder's SOL payout as that payout's fee (its gas and
    /// the holder's record rent), in lamports. Set by the ADMIN, at most `MAX_FEE_PER_RECIPIENT_CAP`;
    /// 0 (no fee) until set.
    pub max_fee_per_recipient: u64,
}

/// The v2 minimum the ADMIN sets (`TK2_MIN_SEED`), in lamports; any value, 0 included. Its own
/// account rather than a field of `Tk2Config`: the live config is fixed-size Borsh, so a field added
/// there would leave it unreadable to every instruction that names it until it was reallocated.
///
/// It also holds the repayment rules (owner, 2026-10-27): the OPERATOR alone is repaid what a run
/// cost -- its signatures, its priority fee and the rent it paid and did not get back -- times
/// `1 + margin_bps`, and a run whose repayment would be above `cap_bps` of what it paid out is
/// refused. Nobody else is repaid anything.
///
/// Layout (for readers): 8 bytes of Anchor discriminator (sha256("account:Tk2Min")[..8]); `bump`
/// (u8, offset 8); `version` (u8, offset 9: 1 once made); `min_execute_lamports` (u64 LE, offset
/// 10); `margin_bps` (u16 LE, offset 18); `cap_bps` (u16 LE, offset 20). 22 bytes. While the account
/// does not exist the rules are the defaults: minimum 0, margin 1,000, cap 500.
///
/// The swap rules (`Tk2Swap`, owner 2026-10-29) follow these 22 bytes in the same account, so that
/// every instruction that already names `PDA(["tk2-min"])` reads them with no new account and a
/// reader of the 22 bytes above reads them as before (the version stays 1): `swap_cooldown_secs`
/// (u32 LE, offset 22) and `max_move_fee_bps` (u16 LE, offset 26). 28 bytes in all. An account made
/// before them (22 bytes) reads as their defaults, and is grown to 28 bytes by the ADMIN's next set
/// (`holders::open_tk2_min`).
#[account]
#[derive(InitSpace, Debug, PartialEq, Eq)]
pub struct Tk2Min {
    pub bump: u8,
    pub version: u8,
    pub min_execute_lamports: u64,
    pub margin_bps: u16,
    pub cap_bps: u16,
}

/// The repayment margin and cap until the ADMIN sets them: 10% over the run's cost, at most 5% of
/// what the run pays out.
pub const DEFAULT_MARGIN_BPS: u16 = 1_000;
pub const DEFAULT_CAP_BPS: u16 = 500;
/// The bounds the ADMIN may set them inside.
pub const MAX_MARGIN_BPS: u16 = 5_000;
pub const MAX_CAP_BPS: u16 = 1_000;

/// The swap rules of v1's `execute_tokenomics` and v2's `execute_tokenomics_v2` (owner, 2026-10-29:
/// tokenomics never queue), after `Tk2Min`'s 22 bytes in its account (see `Tk2Min`):
///
///  * `swap_cooldown_secs`: the least time between two of an account's swaps (or adds), in seconds:
///    `MIN_SWAP_COOLDOWN_SECS` (3) to `MAX_SWAP_COOLDOWN_SECS` (a day); 3 by default (it was 900).
///    Never 0: every transaction of a slot -- every transaction of one bundle -- reads the same clock,
///    so with no cooldown one bundle could hold the attacker's push, several runs of the same account
///    and its sell, and win every run's move for the fee of one round trip. One second keeps a bundle
///    to one run; three outlast one leader's usual four slots (~1.6 s; a validator holding several
///    windows in a row, or the clock's drift, can still fit two). A bucket a run cannot spend whole is
///    still spent in seconds: tokenomics never queue -- and so a holder who knows a big bucket is
///    being spent can sell into its runs seconds apart, where the 15 minutes made it wait (the cost of
///    never queueing; the ADMIN's cooldown is the knob).
///  * `max_move_fee_bps`: the most one swap may make the coin dearer, as a share of the pool's own
///    fee in bps: `MIN_MOVE_FEE_BPS` (1) to `MAX_MOVE_FEE_BPS` (10,000 = the fee), 10,000 by
///    default (the rule before 2026-10-29). A sandwich across transactions -- push the price, let the
///    run buy, sell back -- pays the fee on both legs of what it moves and wins at most the run's own
///    move: at one fee it loses unless it takes back over half the fee it pays (as the pool's LP, say),
///    and at twice the fee it would be break-even before any take-back -- so the ADMIN may lower the
///    cap, never raise it past the fee. The swap's minimum out is no such guard: it is worked out from
///    the pool as the swap finds it, in the same instruction, so it bounds Meteora's rounding and fee,
///    never a price somebody moved first.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tk2Swap {
    pub swap_cooldown_secs: u32,
    pub max_move_fee_bps: u16,
}

impl Tk2Swap {
    pub const DEFAULT: Tk2Swap = Tk2Swap { swap_cooldown_secs: DEFAULT_SWAP_COOLDOWN_SECS, max_move_fee_bps: DEFAULT_MAX_MOVE_FEE_BPS };
}

/// The swap rules until the ADMIN sets them: 3 seconds between an account's swaps, a swap's move up
/// to the pool's fee.
pub const DEFAULT_SWAP_COOLDOWN_SECS: u32 = 3;
pub const DEFAULT_MAX_MOVE_FEE_BPS: u16 = 10_000;
/// The bounds the ADMIN may set them inside: a cooldown of three seconds (never two runs of an
/// account in one slot, nor in one leader's usual four slots -- audit r3 L1: at one second a leader
/// holding four slots could fit push, run, run, sell, two fees of move) to a day (the cadence before 2026-10-29 was 15 minutes); a move of 0.01% of the fee to
/// the fee (0 would stop every swap; over the fee a sandwich comes closer to paying, see `Tk2Swap`).
pub const MIN_SWAP_COOLDOWN_SECS: u32 = 3;
pub const MAX_SWAP_COOLDOWN_SECS: u32 = 86_400;
pub const MIN_MOVE_FEE_BPS: u16 = 1;
pub const MAX_MOVE_FEE_BPS: u16 = 10_000;
/// `PDA(["tk2-min"])`'s length before the swap rules (discriminator and `Tk2Min`), and with them.
pub const TK2_MIN_HEAD_LEN: usize = 22;
pub const TK2_MIN_LEN: usize = TK2_MIN_HEAD_LEN + 6;

/// The live rules a v2 run (and v1's execute) is held to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tk2Rules {
    pub min_execute_lamports: u64,
    pub margin_bps: u16,
    pub cap_bps: u16,
    pub swap_cooldown_secs: u32,
    pub max_move_fee_bps: u16,
}

/// `PDA(["tk2-min"])`'s data as this program writes it: `Tk2Min` (the discriminator checked, version
/// 1), then `Tk2Swap` -- or, for an account made before the swap rules (22 bytes), their defaults.
/// None for anything else.
pub fn decode_tk2_min(data: &[u8]) -> Option<(Tk2Min, Tk2Swap)> {
    if data.len() != TK2_MIN_HEAD_LEN && data.len() != TK2_MIN_LEN {
        return None;
    }
    let head = Tk2Min::try_deserialize(&mut &data[..TK2_MIN_HEAD_LEN]).ok()?;
    if head.version != 1 {
        return None;
    }
    let swap = if data.len() == TK2_MIN_LEN { Tk2Swap::deserialize(&mut &data[TK2_MIN_HEAD_LEN..]).ok()? } else { Tk2Swap::DEFAULT };
    Some((head, swap))
}

#[cfg(test)]
mod tk2_min_tests {
    use super::*;

    fn head(m: &Tk2Min) -> Vec<u8> {
        let mut d = vec![];
        m.try_serialize(&mut d).unwrap();
        d
    }

    /// The 22 bytes readers decode stay where they were; the swap rules follow them; an account made
    /// before them reads as their defaults; anything else is refused.
    #[test]
    fn the_tk2_min_layout() {
        let m = Tk2Min { bump: 254, version: 1, min_execute_lamports: 0x0102_0304_0506_0708, margin_bps: 1234, cap_bps: 567 };
        let old = head(&m);
        assert_eq!(old.len(), TK2_MIN_HEAD_LEN);
        assert_eq!(decode_tk2_min(&old), Some((m.clone(), Tk2Swap::DEFAULT)), "a 22-byte account: the swap defaults");
        assert_eq!(Tk2Swap::DEFAULT, Tk2Swap { swap_cooldown_secs: 3, max_move_fee_bps: 10_000 });
        let mut new = old.clone();
        Tk2Swap { swap_cooldown_secs: 0x0a0b_0c0d, max_move_fee_bps: 0x0e0f }.serialize(&mut new).unwrap();
        assert_eq!(new.len(), TK2_MIN_LEN);
        assert_eq!(&new[..22], &old[..], "the old fields where they were");
        assert_eq!(&new[22..], &[0x0d, 0x0c, 0x0b, 0x0a, 0x0f, 0x0e], "cooldown u32 LE at 22, move u16 LE at 26");
        assert_eq!(decode_tk2_min(&new).unwrap().1, Tk2Swap { swap_cooldown_secs: 0x0a0b_0c0d, max_move_fee_bps: 0x0e0f });
        for len in [0usize, 8, 21, 23, 27, 29, 64] {
            let mut d = new.clone();
            d.resize(len, 0);
            assert_eq!(decode_tk2_min(&d), None, "{len} bytes");
        }
        let mut d = new.clone();
        d[0] ^= 1;
        assert_eq!(decode_tk2_min(&d), None, "another discriminator");
        let mut d = new.clone();
        d[9] = 2;
        assert_eq!(decode_tk2_min(&d), None, "another version");
    }
}

/// The live rules, from the account at `PDA(["tk2-min"])` the instruction was given (its address is
/// the caller's constraint): the defaults while it does not exist; otherwise this program's
/// `Tk2Min` (and `Tk2Swap`), or the instruction is refused.
pub fn tk2_rules(account: &AccountInfo) -> Result<Tk2Rules> {
    if account.data_is_empty() && *account.owner == anchor_lang::system_program::ID {
        let s = Tk2Swap::DEFAULT;
        return Ok(Tk2Rules {
            min_execute_lamports: 0,
            margin_bps: DEFAULT_MARGIN_BPS,
            cap_bps: DEFAULT_CAP_BPS,
            swap_cooldown_secs: s.swap_cooldown_secs,
            max_move_fee_bps: s.max_move_fee_bps,
        });
    }
    require_keys_eq!(*account.owner, crate::ID, TokenomicsV2Error::NotTheAccount);
    let data = account.try_borrow_data()?;
    let (m, s) = decode_tk2_min(&data).ok_or_else(|| error!(TokenomicsV2Error::NotTheAccount))?;
    Ok(Tk2Rules {
        min_execute_lamports: m.min_execute_lamports,
        margin_bps: m.margin_bps,
        cap_bps: m.cap_bps,
        // Only the bounded setter writes them; held to the bounds here too, as a reader would.
        swap_cooldown_secs: s.swap_cooldown_secs.clamp(MIN_SWAP_COOLDOWN_SECS, MAX_SWAP_COOLDOWN_SECS),
        max_move_fee_bps: s.max_move_fee_bps.clamp(MIN_MOVE_FEE_BPS, MAX_MOVE_FEE_BPS),
    })
}

/// The live minimum alone (v1's `execute_tokenomics` reads it too).
pub fn min_execute(account: &AccountInfo) -> Result<u64> {
    Ok(tk2_rules(account)?.min_execute_lamports)
}

/// The operator `Tk2Config` names, from the account at `PDA(["tk2-config"])` the instruction was
/// given; None while it does not exist (then nobody is repaid).
pub fn operator_of(config: &AccountInfo) -> Result<Option<Pubkey>> {
    if config.data_is_empty() && *config.owner == anchor_lang::system_program::ID {
        return Ok(None);
    }
    require_keys_eq!(*config.owner, crate::ID, TokenomicsV2Error::NotTheAccount);
    let data = config.try_borrow_data()?;
    Ok(Some(Tk2Config::try_deserialize(&mut &data[..]).map_err(|_| error!(TokenomicsV2Error::NotTheAccount))?.operator))
}

/// The highest `max_fee_per_recipient` the ADMIN may set: 0.005 SOL -- a record's rent (~0.001 SOL),
/// an associated account's (~0.002 SOL) and the transaction's fee, with room.
pub const MAX_FEE_PER_RECIPIENT_CAP: u64 = 5_000_000;
/// A SOL payout's fee is at most this share of what the holder is due: 10%.
pub const FEE_MAX_BPS: u64 = 1_000;

#[account]
#[derive(InitSpace)]
pub struct Tk2Paid {
    /// Everything of the entry this holder has been paid, in the entry's token.
    pub cumulative: u64,
}

// ------------------------------------------------------------------------------ the rules

/// `checkConfig`'s rules for one leg (web/lib/tokenomics/v2-config.mjs, normative), on Solana's
/// raw 32-byte keys.
pub fn check_leg(l: &TokenomicsLegV2) -> Result<()> {
    require!(l.wallets.len() == l.wallet_bps.len() && l.wallets.len() <= MAX_WALLETS, TokenomicsV2Error::BadConfig);
    require!(l.reward_tokens.len() == l.reward_bps.len(), TokenomicsV2Error::BadConfig);
    let mut sum = l.burn_bps as u32 + l.buy_hold_bps as u32 + l.liquidity_bps as u32 + l.holders_bps as u32;
    for (i, w) in l.wallets.iter().enumerate() {
        require!(*w != [0u8; 32] && !l.wallets[..i].contains(w), TokenomicsV2Error::BadConfig);
        require!(l.wallet_bps[i] > 0 && l.wallet_bps[i] as u32 <= V2_BPS, TokenomicsV2Error::BadConfig);
        sum += l.wallet_bps[i] as u32;
    }
    require!(sum == V2_BPS, TokenomicsV2Error::BadConfig);
    require!((l.buy_hold_bps > 0) == (l.treasury != [0u8; 32]), TokenomicsV2Error::BadConfig);
    if l.holders_bps > 0 {
        require!(!l.reward_tokens.is_empty() && l.reward_tokens.len() <= MAX_REWARD_TOKENS, TokenomicsV2Error::BadConfig);
        let mut rsum = 0u32;
        for (i, r) in l.reward_tokens.iter().enumerate() {
            require!(!l.reward_tokens[..i].contains(r), TokenomicsV2Error::BadConfig);
            require!(l.reward_bps[i] > 0 && l.reward_bps[i] as u32 <= V2_BPS, TokenomicsV2Error::BadConfig);
            rsum += l.reward_bps[i] as u32;
        }
        require!(rsum == V2_BPS, TokenomicsV2Error::BadConfig);
    } else {
        require!(l.reward_tokens.is_empty(), TokenomicsV2Error::BadConfig);
    }
    Ok(())
}

/// The launch-wide rules, and Solana's leg: the one given when the config has a Solana leg (its
/// hash must be the config's entry), else the fallback -- one wallet, `ownerSol`, at 100%.
pub fn solana_leg(c: &TokenomicsConfigV2, given: &TokenomicsLegV2) -> Result<TokenomicsLegV2> {
    let n = c.leg_eids.len();
    require!(n >= 1 && n <= V2_MAX_LEGS && c.leg_hashes.len() == n, TokenomicsV2Error::BadConfig);
    for i in 1..n {
        require!(c.leg_eids[i] > c.leg_eids[i - 1], TokenomicsV2Error::BadConfig);
    }
    require!(c.launch_id != [0u8; 32], TokenomicsV2Error::BadConfig);
    require!(c.owner_evm[..12] == [0u8; 12], TokenomicsV2Error::BadConfig);
    // Solana's owner is needed here (the fallback's wallet; forwarding; eligibility): a config whose
    // `ownerSol` is zero has no Solana account. (checkConfig allows it when `ownerEvm` is set.)
    require!(c.owner_sol != [0u8; 32], TokenomicsV2Error::BadConfig);
    require!(c.min_holder_bps >= MIN_HOLDER_BPS_FLOOR && c.min_holder_bps as u32 <= V2_BPS, TokenomicsV2Error::BadConfig);
    check_selection(c.select_mode, c.select_count)?;
    match c.leg_eids.iter().position(|x| *x == SOLANA_EID) {
        Some(p) => {
            require!(given.eid == SOLANA_EID, TokenomicsV2Error::BadConfig);
            require!(given.hash() == c.leg_hashes[p], TokenomicsV2Error::WrongLeg);
            check_leg(given)?;
            Ok(given.clone())
        }
        None => Ok(TokenomicsLegV2 { eid: SOLANA_EID, wallets: vec![c.owner_sol], wallet_bps: vec![V2_BPS as u16], ..Default::default() }),
    }
}

pub fn check_selection(mode: u8, count: u32) -> Result<()> {
    let ok = match mode {
        SELECT_ALL => count == 0,
        SELECT_TOP | SELECT_RANDOM => count >= 1,
        _ => false,
    };
    require!(ok, TokenomicsV2Error::BadConfig);
    Ok(())
}

/// Solana's own rules for the keys the leg names (v1's `RecipientReserved`): none is a key the
/// runtime never lets a transaction write, nor the account itself; the owner is not the
/// incinerator; no reward token is wrapped SOL's mint (native SOL is the zero key: an SPL entry of
/// wrapped SOL would share the pot's one wrapped-SOL account between its budget and its pot).
pub fn check_keys(owner: &Pubkey, leg: &TokenomicsLegV2, tk: &Pubkey) -> Result<()> {
    require!(*owner != incinerator::ID, TokenomicsV2Error::BadConfig);
    let mut keys = vec![*owner];
    if leg.treasury != [0u8; 32] {
        keys.push(Pubkey::new_from_array(leg.treasury));
    }
    keys.extend(leg.wallets.iter().map(|w| Pubkey::new_from_array(*w)));
    for k in keys {
        require!(!crate::is_reserved_account(&k), TokenomicsV2Error::RecipientReserved);
        require!(k != *tk, TokenomicsV2Error::BadConfig);
    }
    for r in &leg.reward_tokens {
        let k = Pubkey::new_from_array(*r);
        require!(k != spl_token::native_mint::ID && k != *tk, TokenomicsV2Error::BadConfig);
    }
    Ok(())
}

// ------------------------------------------------------------------------------ allocation

/// Bring every wrapped-SOL unit in the main vault that is nobody's yet into the books: the leg's
/// five shares split as v1 (`split`: each rounded down, the remainder to the first share there
/// is), then the wallets' share by each wallet's bps and the holders' share by each reward entry's
/// bps, each rounded down with the dust to the first (wallet 0, entry 0).
pub fn allocate_v2(t: &mut TokenomicsV2, tk: Pubkey, held: u64) {
    let amount = held.saturating_sub(t.tracked());
    if amount == 0 {
        return;
    }
    let mut bps = [0u16; MAX_BUCKETS];
    bps[..4].copy_from_slice(&t.bps);
    bps[4] = t.wallet_bps();
    let parts = split(amount, &bps);
    for i in 0..V2_BUCKETS {
        t.buckets[i] += parts[i];
    }
    let shares = |total: u64, of: u64, bps: u16| ((total as u128 * bps as u128) / of as u128) as u64;
    let (holders, wallets) = (parts[3], parts[4]);
    if holders > 0 {
        let n = t.num_rewards as usize;
        let mut given = 0u64;
        for r in t.rewards[..n].iter_mut() {
            let part = shares(holders, V2_BPS as u64, r.bps);
            r.incoming += part;
            given += part;
        }
        t.rewards[0].incoming += holders - given;
    }
    if wallets > 0 {
        let n = t.num_wallets as usize;
        let of = bps[4] as u64;
        let mut given = 0u64;
        for w in t.wallets[..n].iter_mut() {
            let part = shares(wallets, of, w.bps);
            w.accrued += part;
            given += part;
        }
        t.wallets[0].accrued += wallets - given;
    }
    t.total_received = t.total_received.saturating_add(amount);
    emit!(TokenomicsV2Allocated { tokenomics: tk, amount, burn: parts[0], buy_hold: parts[1], liquidity: parts[2], holders, wallets });
}

// ------------------------------------------------------------------------------ errors

#[error_code(offset = 9100)]
pub enum TokenomicsV2Error {
    #[msg("the tokenomics v2 config breaks a rule")]
    BadConfig,
    #[msg("the Solana leg is not the config's: its hash differs")]
    WrongLeg,
    #[msg("a tokenomics recipient is a key the runtime reserves, not a wallet")]
    RecipientReserved,
    #[msg("only that slot's or role's holder may do this")]
    NotTheRole,
    #[msg("no such wallet slot, role or reward entry")]
    NoSuch,
    #[msg("nothing is due")]
    NothingDue,
    #[msg("that is not the account expected")]
    NotTheAccount,
    #[msg("only the operator may do this")]
    NotOperator,
    #[msg("only the admin may do this")]
    NotAdmin,
    #[msg("a payout would exceed the reward entry's pot")]
    PotExceeded,
    #[msg("the reward buy spent more than allowed or bought less than its minimum")]
    BadBuy,
    #[msg("that program may not be a reward route")]
    BadRoute,
    #[msg("a pot account's owner, delegate or close authority changed")]
    PotAccountChanged,
    #[msg("no valid voucher from the operator for this claim in the transaction")]
    BadVoucher,
    #[msg("that money is booked and cannot be recovered this way")]
    Booked,
    #[msg("this instruction runs once per transaction, at its top level")]
    NotAlone,
    #[msg("arithmetic overflow")]
    Overflow,
    #[msg("that reward mint cannot be paid out: a Token-2022 mint with an extension not on the allowlist (only metadata and group data)")]
    RewardMintRefused,
    #[msg("the run's repayment would be above the cap of what it pays out: too small to run now")]
    RepayOverCap,
}

// ------------------------------------------------------------------------------ events

#[event]
pub struct TokenomicsV2Created {
    pub tokenomics: Pubkey,
    pub config_hash: [u8; 32],
    pub launch_id: [u8; 32],
    pub owner: Pubkey,
}

#[event]
pub struct TokenomicsV2Bound {
    pub tokenomics: Pubkey,
    pub mint: Pubkey,
    pub pool: Pubkey,
    pub record: Pubkey,
}

#[event]
pub struct TokenomicsV2Allocated {
    pub tokenomics: Pubkey,
    pub amount: u64,
    pub burn: u64,
    pub buy_hold: u64,
    pub liquidity: u64,
    pub holders: u64,
    pub wallets: u64,
}

#[event]
pub struct WalletPaid {
    pub tokenomics: Pubkey,
    pub index: u8,
    pub to: Pubkey,
    pub lamports: u64,
}

#[event]
pub struct WalletProposed {
    pub tokenomics: Pubkey,
    pub index: u8,
    pub from: Pubkey,
    pub to: Pubkey,
}

#[event]
pub struct WalletChanged {
    pub tokenomics: Pubkey,
    pub index: u8,
    pub from: Pubkey,
    pub to: Pubkey,
}

#[event]
pub struct EligibilitySet {
    pub tokenomics: Pubkey,
    pub by: Pubkey,
    pub min_holder_bps: u16,
    pub select_mode: u8,
    pub select_count: u32,
}

#[event]
pub struct OperatorSet {
    pub operator: Pubkey,
}

#[event]
pub struct MaxFeeSet {
    pub max_fee_per_recipient: u64,
}

/// The ADMIN set the v2 minimum (`Tk2Min`).
#[event]
pub struct MinExecuteSet {
    pub min_execute_lamports: u64,
}

/// The ADMIN set the repayment margin and cap (`Tk2Min`).
#[event]
pub struct RepayRulesSet {
    pub margin_bps: u16,
    pub cap_bps: u16,
}

/// The ADMIN set the swap rules (`Tk2Swap`).
#[event]
pub struct SwapRulesSet {
    pub swap_cooldown_secs: u32,
    pub max_move_fee_bps: u16,
}

#[event]
pub struct RewardsBought {
    pub tokenomics: Pubkey,
    pub index: u8,
    pub sol_in: u64,
    pub tokens_out: u64,
}

/// One holder paid: `amount` it was due (the pot's decrease), `sent` what reached it, `fee` what the
/// operator took (a SOL entry's payout; 0 for a token payout or a claim).
#[event]
pub struct HolderPaid {
    pub tokenomics: Pubkey,
    pub index: u8,
    pub holder: Pubkey,
    pub amount: u64,
    pub cumulative: u64,
    pub sent: u64,
    pub fee: u64,
}

/// A holder `pay_holders` passed over: 1 nothing due, 2 cannot take SOL, 3 no usable token account,
/// 4 its fee over the caps (10% of what it is due, `max_fee_per_recipient`).
#[event]
pub struct HolderSkipped {
    pub tokenomics: Pubkey,
    pub index: u8,
    pub account: Pubkey,
    pub reason: u8,
}

/// One batch: `amount` the holders were due in all; `repaid` the operator's take -- a SOL entry's
/// fees in all, or a token entry's gas and rents repaid from its budget.
#[event]
pub struct HoldersPaid {
    pub tokenomics: Pubkey,
    pub index: u8,
    pub holders: u16,
    pub amount: u64,
    pub repaid: u64,
}

#[event]
pub struct Recovered {
    pub tokenomics: Pubkey,
    pub index: u8,
    pub kind: u8,
    pub from: Pubkey,
    pub to: Pubkey,
    pub amount: u64,
}
