//! The venue a launch's pool is on, and the one thing the fee split needs from it.
//!
//! The fee split (`fees`) knows a launch by its record -- who is paid, at what fee, out of which
//! position -- and asks this module for one thing: claim the position's accrued fees, in the quote
//! asset, into an account of the program's. Everything Meteora-specific about that is here: its
//! instruction, its accounts and their order, and what it pays a position. A pool on another
//! venue would be another module with the same function; nothing in `fees` would change.
//!
//! (Opening the pool, locking the position and the dev buy's swap are part of `launch`, in
//! `launch_leg`. They happen once, inside the launch; this is what happens for the life of the
//! pool.)

use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    instruction::{AccountMeta, Instruction},
    program::invoke_signed,
};

use crate::{SplitterError, CLAIM_POSITION_FEE_DISCRIMINATOR, CP_AMM_ID, CP_AMM_POOL_DISCRIMINATOR, METEORA_LP_SHARE_BPS};

/// The share of the pool's fee that reaches the position, for the venue launches open their pools
/// on: Meteora passes 80% to the position and keeps 20%. Recorded per launch (`LaunchRecord`), so
/// a launch on another venue would carry its own.
pub const VENUE_LP_SHARE_BPS: u16 = METEORA_LP_SHARE_BPS;

/// cp-amm's fee denominator: a fee numerator of 10,000,000 is 1%, of 3,000,000 is 0.3%.
pub const FEE_DENOMINATOR: u64 = 1_000_000_000;

/// Where cp-amm's `Pool` keeps what a claim is split by (its zero-copy layout, after the 8-byte
/// discriminator): the base fee's cliff numerator, first in `pool_fees.base_fee` whatever its mode,
/// and `pool_fees.protocol_fee_percent`, the share of every fee Meteora keeps. Pinned against a real
/// pool in tests/launch.rs and read back off a live one in the rehearsal.
const POOL_CLIFF_FEE_NUMERATOR: usize = 8;
const POOL_PROTOCOL_FEE_PERCENT: usize = 48;

/// What a pool charges now, as a claim needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VenueFee {
    /// The base fee, over `FEE_DENOMINATOR`.
    pub fee_numerator: u64,
    /// The share of that fee which reaches the position, in basis points: what Meteora does not keep.
    pub lp_share_bps: u16,
}

/// A pool's fee as it stands, out of its account's data; None if it is not a cp-amm pool.
///
/// The fee a launch opened its pool at is not fixed: Meteora's operator can change a pool's base fee
/// (`update_pool_fees`), and the split follows what the pool charges -- trusting the operator not to
/// change it, but not trusting the launch's own record of it. What it reads is the BASE fee. A pool
/// whose operator turned on a dynamic (volatility) fee charges more than that on some trades: those
/// fees are split as if they had been charged at the base fee -- the platform's floor of 0.2% of
/// volume is then worked out on more volume than there was, which favours the platform -- and no
/// launch opens a pool with one.
///
/// The fee is read when the claim is made, not when the fees were earned: a claim made after the
/// operator changed the fee splits everything still pending at the NEW fee, including what was
/// earned before the change, and anyone can send a claim, so anyone can time one around a change.
/// Accepted with the operator trust above: there is no per-trade record of the fee to split by.
pub fn read_fee(data: &[u8]) -> Option<VenueFee> {
    if data.get(..8)? != CP_AMM_POOL_DISCRIMINATOR {
        return None;
    }
    let fee_numerator = u64::from_le_bytes(data.get(POOL_CLIFF_FEE_NUMERATOR..POOL_CLIFF_FEE_NUMERATOR + 8)?.try_into().ok()?);
    let protocol = *data.get(POOL_PROTOCOL_FEE_PERCENT)?;
    if protocol > 100 || fee_numerator >= FEE_DENOMINATOR {
        return None;
    }
    Some(VenueFee { fee_numerator, lp_share_bps: (100 - protocol as u16) * 100 })
}

/// The pool's fee as it stands, from its account: the venue's account 1 of a claim, which Meteora's
/// claim has just checked is the position's pool.
pub fn current_fee(pool: &AccountInfo) -> Result<VenueFee> {
    require_keys_eq!(*pool.owner, CP_AMM_ID, SplitterError::NotThisLaunch);
    let data = pool.try_borrow_data()?;
    read_fee(&data).ok_or_else(|| error!(SplitterError::NotThisLaunch))
}

/// The venue's accounts a claim names, after the fee split's own, in this order:
///
///   0 pool authority     Meteora's constant
///   1 pool
///   2 position           must be the launch's (checked here against its record)
///   3 token a vault      the launched token's
///   4 token b vault      the quote asset's
///   5 token a mint       the launched token
///   6 position nft account   held by the program's fee owner
///   7 event authority    Meteora's
///   8 the program        Meteora's, pinned
///   9 token a program    the launched token's (Token-2022)
///
/// Meteora checks the rest: the pool against the vaults and both mints (`has_one`), the position
/// against the pool, the NFT account against the position's NFT and its owner against the signer.
pub const CLAIM_ACCOUNTS: usize = 10;

/// What the claim needs besides the venue's accounts.
pub struct ClaimInto<'a, 'info> {
    /// The launch's position, from its record: the venue's account 2 must be this.
    pub position: Pubkey,
    /// The program's fee owner: the position NFT's holder, and the claim's only signer.
    pub fee_owner: &'a AccountInfo<'info>,
    pub fee_owner_seeds: &'a [&'a [u8]],
    /// Where the quote asset arrives: the program's own account for that asset.
    pub into: &'a AccountInfo<'info>,
    pub quote_mint: &'a AccountInfo<'info>,
    pub quote_program: &'a AccountInfo<'info>,
    /// A token account Meteora is handed for the launched token's side, which it never writes:
    /// launches open their pools collecting fees in the quote asset only (`collect_fee_mode` OnlyB),
    /// so there is never a fee in the launched token to pay. Any token account will do; if one
    /// ever arrived, a quote-asset account would refuse it and the claim would fail rather than
    /// pay it anywhere.
    pub unused_token_a: &'a AccountInfo<'info>,
}

/// cp-amm's `claim_position_fee`, from the venue's accounts (`CLAIM_ACCOUNTS` order) and the four
/// the fee split supplies: the unused token-A account, the account the quote asset lands in, the
/// quote mint, the fee owner (the only signer) and the quote's token program.
///
/// The order is `ClaimPositionFeeCtx` as cp-amm declares it, and the writable flags mirror its
/// `#[account(mut)]` annotations exactly: the position and the four token accounts it moves
/// balances between. `#[event_cpi]` appends the event authority and the program itself, last.
pub fn claim_ix(v: &[Pubkey; CLAIM_ACCOUNTS], unused_token_a: Pubkey, into: Pubkey, quote_mint: Pubkey, fee_owner: Pubkey, quote_program: Pubkey) -> Instruction {
    Instruction {
        program_id: CP_AMM_ID,
        accounts: vec![
            AccountMeta::new_readonly(v[0], false),
            AccountMeta::new_readonly(v[1], false),
            AccountMeta::new(v[2], false),
            AccountMeta::new(unused_token_a, false),
            AccountMeta::new(into, false),
            AccountMeta::new(v[3], false),
            AccountMeta::new(v[4], false),
            AccountMeta::new_readonly(v[5], false),
            AccountMeta::new_readonly(quote_mint, false),
            AccountMeta::new_readonly(v[6], false),
            AccountMeta::new_readonly(fee_owner, true),
            AccountMeta::new_readonly(v[9], false),
            AccountMeta::new_readonly(quote_program, false),
            AccountMeta::new_readonly(v[7], false),
            AccountMeta::new_readonly(v[8], false),
        ],
        data: CLAIM_POSITION_FEE_DISCRIMINATOR.to_vec(),
    }
}

/// Claim the launch's accrued fees, in the quote asset, into `c.into`.
pub fn claim_quote_fees<'info>(venue: &[AccountInfo<'info>], c: &ClaimInto<'_, 'info>) -> Result<()> {
    require!(venue.len() >= CLAIM_ACCOUNTS, SplitterError::NotThisLaunch);
    let v = &venue[..CLAIM_ACCOUNTS];
    require_keys_eq!(v[2].key(), c.position, SplitterError::NotThisLaunch);
    require_keys_eq!(v[8].key(), CP_AMM_ID, SplitterError::WrongProgram);
    let keys: [Pubkey; CLAIM_ACCOUNTS] = core::array::from_fn(|i| v[i].key());
    let ix = claim_ix(&keys, c.unused_token_a.key(), c.into.key(), c.quote_mint.key(), c.fee_owner.key(), c.quote_program.key());
    let mut infos: Vec<AccountInfo<'info>> = v.to_vec();
    infos.extend([c.unused_token_a.clone(), c.into.clone(), c.quote_mint.clone(), c.fee_owner.clone(), c.quote_program.clone()]);
    invoke_signed(&ix, &infos, &[c.fee_owner_seeds])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(n: u8) -> Pubkey {
        Pubkey::new_from_array([n; 32])
    }

    /// Distinct keys, numbered in cp-amm's own order, so a transposition is visible.
    fn built() -> Instruction {
        // venue order: pool authority 1, pool 2, position 3, vault a 6, vault b 7, mint a 8,
        // nft account 10, event authority 14, cp-amm 15, token a program 12
        let v = [k(1), k(2), k(3), k(6), k(7), k(8), k(10), k(14), k(15), k(12)];
        claim_ix(&v, k(4), k(5), k(9), k(11), k(13))
    }

    /// The account order cp-amm declares in ClaimPositionFeeCtx. It reads them positionally, so a
    /// transposition fails somewhere inside someone else's program with an error that does not
    /// name the account that was wrong.
    #[test]
    fn the_claim_names_cp_amms_accounts_in_its_order() {
        let ix = built();
        let got: Vec<u8> = ix.accounts.iter().map(|m| m.pubkey.to_bytes()[0]).collect();
        assert_eq!(got, (1..=15).collect::<Vec<u8>>());
        assert_eq!(ix.program_id, CP_AMM_ID);
        assert_eq!(ix.data, CLAIM_POSITION_FEE_DISCRIMINATOR.to_vec(), "claim_position_fee takes no arguments");
    }

    /// The pool's base fee at offset 8 and Meteora's protocol share at 48, as cp-amm lays them out.
    #[test]
    fn a_pools_fee_is_read_where_cp_amm_keeps_it() {
        let mut d = vec![0u8; 1112];
        d[..8].copy_from_slice(&CP_AMM_POOL_DISCRIMINATOR);
        d[8..16].copy_from_slice(&10_000_000u64.to_le_bytes());
        d[48] = 20;
        assert_eq!(read_fee(&d), Some(VenueFee { fee_numerator: 10_000_000, lp_share_bps: 8_000 }));
        d[48] = 101;
        assert_eq!(read_fee(&d), None, "a protocol share over 100% is not a pool");
        d[48] = 0;
        assert_eq!(read_fee(&d).unwrap().lp_share_bps, 10_000);
        d[8..16].copy_from_slice(&FEE_DENOMINATOR.to_le_bytes());
        assert_eq!(read_fee(&d), None, "a fee of the whole amount is not one");
        d[..8].copy_from_slice(&[0u8; 8]);
        assert_eq!(read_fee(&d), None);
    }

    #[test]
    fn only_the_fee_owner_signs_and_only_what_cp_amm_writes_is_writable() {
        let ix = built();
        let signers: Vec<u8> = ix.accounts.iter().filter(|m| m.is_signer).map(|m| m.pubkey.to_bytes()[0]).collect();
        assert_eq!(signers, vec![11]);
        let writable: Vec<u8> = ix.accounts.iter().filter(|m| m.is_writable).map(|m| m.pubkey.to_bytes()[0]).collect();
        assert_eq!(writable, vec![3, 4, 5, 6, 7]);
    }
}
