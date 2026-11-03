//! Owner (A) 2026-10-30: the PriceLog writer reward (docs/v3c-gap-spec.md §8.3).
//!
//! A send that consumes a PriceLog entry's capacity owes that entry's writer `reward_bps` of the LD
//! the entry covered, out of the bridge fee the send collected (never on top of the user's cost,
//! never more than that fee). The owed is kept on the entry (`owed_ld`); the store reserves the
//! total (tail bytes 300..308) so `withdraw_fee` never takes it. An entry merged or dropped with
//! owed moves it to the log's reward table (9 slots, one per writer); from there
//! `settle_writer_rewards` (anyone, paying the rent) or a claim moves it into the writer's ledger
//! PDA ["GapReward", store, writer].
//!
//!   * `claim_writer_rewards(indices)`: the writer signs; the owed of every entry at `indices` it
//!     wrote, its reward-table slot and its ledger's owed are paid to its associated token account
//!     from the store's escrow, and the store's reserved total falls by as much.
//!   * `settle_writer_rewards(writer)`: anyone; the writer's reward-table slot moves into its
//!     ledger (created here, the payer pays the rent), so a full table can never forfeit it.
//!
//! Paused store (round 2 B I-5, decided): `claim_writer_rewards` REFUSES (Paused) while the store is
//! paused -- the pause is the emergency stop of everything that moves tokens out of the escrow, and
//! a reward-accounting fault is one reason to pull it; nothing is lost, the owed stays reserved and
//! the claim pays after `set_pause(false)`. `settle_writer_rewards` still runs while paused: it moves
//! no token, only a table slot into its ledger (and protects it from a forfeit meanwhile).
//!
//! Ledger layout (raw, LE, 90 B): tag "GapRwd01" @0 | version u8 = 1 @8 | bump u8 @9 | store @10 |
//! writer @42 | owed_ld u64 @74 | claimed_ld u64 @82.
use crate::gap::{pricelog, state::*};
use crate::*;
use anchor_lang::solana_program::{program::invoke_signed, rent::Rent, system_instruction};
use anchor_spl::token_interface::{self, Mint, TokenAccount, TokenInterface, TransferChecked};

pub const GAP_REWARD_SEED: &[u8] = b"GapReward";
pub const LEDGER_TAG: [u8; 8] = *b"GapRwd01";
pub const LEDGER_LEN: usize = 90;
const L_OWED: usize = 74;
const L_CLAIMED: usize = 82;
pub const ATA_PROGRAM_ID: Pubkey = pubkey!("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");

pub fn ledger_address(program_id: &Pubkey, store: &Pubkey, writer: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[GAP_REWARD_SEED, store.as_ref(), writer.as_ref()], program_id)
}

fn u64_at(d: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(d[at..at + 8].try_into().unwrap())
}

/// The writer's ledger as passed: Ok(true) when it exists (checked), Ok(false) when it is the PDA
/// and not created yet, Err otherwise.
fn open_ledger(info: &AccountInfo, store: &Pubkey, writer: &Pubkey, program_id: &Pubkey) -> Result<bool> {
    let (key, _) = ledger_address(program_id, store, writer);
    require_keys_eq!(*info.key, key, OFTError::RewardAccountMismatch);
    if info.owner != program_id {
        return Ok(false);
    }
    let d = info.try_borrow_data()?;
    require!(d.len() == LEDGER_LEN && d[..8] == LEDGER_TAG && d[10..42] == store.to_bytes() && d[42..74] == writer.to_bytes(), OFTError::RewardAccountMismatch);
    Ok(true)
}

/// Create the ledger at `info` (the PDA), paid by `payer`. Lamports sent beforehand do not block it.
fn create_ledger<'info>(info: &AccountInfo<'info>, payer: &AccountInfo<'info>, system: &AccountInfo<'info>, store: &Pubkey, writer: &Pubkey, program_id: &Pubkey) -> Result<()> {
    let (_, bump) = ledger_address(program_id, store, writer);
    let seeds: &[&[u8]] = &[GAP_REWARD_SEED, store.as_ref(), writer.as_ref(), &[bump]];
    let need = Rent::get()?.minimum_balance(LEDGER_LEN);
    require!(info.data_is_empty() && *info.owner == anchor_lang::system_program::ID, OFTError::RewardAccountMismatch);
    let have = info.lamports();
    if have == 0 {
        invoke_signed(&system_instruction::create_account(payer.key, info.key, need, LEDGER_LEN as u64, program_id), &[payer.clone(), info.clone(), system.clone()], &[seeds])?;
    } else {
        if have < need {
            anchor_lang::solana_program::program::invoke(&system_instruction::transfer(payer.key, info.key, need - have), &[payer.clone(), info.clone(), system.clone()])?;
        }
        invoke_signed(&system_instruction::allocate(info.key, LEDGER_LEN as u64), &[info.clone(), system.clone()], &[seeds])?;
        invoke_signed(&system_instruction::assign(info.key, program_id), &[info.clone(), system.clone()], &[seeds])?;
    }
    let mut d = info.try_borrow_mut_data()?;
    d.fill(0);
    d[..8].copy_from_slice(&LEDGER_TAG);
    d[8] = 1;
    d[9] = bump;
    d[10..42].copy_from_slice(store.as_ref());
    d[42..74].copy_from_slice(writer.as_ref());
    Ok(())
}

/// Add `amount` to the ledger's owed (created first when missing and `amount` > 0).
fn credit_ledger<'info>(info: &AccountInfo<'info>, payer: &AccountInfo<'info>, system: &AccountInfo<'info>, store: &Pubkey, writer: &Pubkey, amount: u64, program_id: &Pubkey) -> Result<bool> {
    let exists = open_ledger(info, store, writer, program_id)?;
    if !exists {
        if amount == 0 {
            return Ok(false);
        }
        create_ledger(info, payer, system, store, writer, program_id)?;
    }
    let mut d = info.try_borrow_mut_data()?;
    let v = u64_at(&d, L_OWED).checked_add(amount).ok_or(OFTError::RewardAccounting)?;
    d[L_OWED..L_OWED + 8].copy_from_slice(&v.to_le_bytes());
    Ok(true)
}

// ------------------------------------------------------------------ claim_writer_rewards

#[derive(Accounts)]
pub struct ClaimWriterRewards<'info> {
    #[account(mut)]
    pub writer: Signer<'info>,
    #[account(mut, seeds = [OFT_SEED, oft_store.token_escrow.as_ref()], bump = oft_store.bump)]
    pub oft_store: Account<'info, OFTStore>,
    #[account(address = oft_store.token_mint, mint::token_program = token_program)]
    pub token_mint: InterfaceAccount<'info, Mint>,
    #[account(
        mut,
        address = oft_store.token_escrow,
        token::authority = oft_store,
        token::mint = token_mint,
        token::token_program = token_program
    )]
    pub token_escrow: InterfaceAccount<'info, TokenAccount>,
    /// The writer's associated token account (checked in apply).
    #[account(mut, token::mint = token_mint, token::authority = writer, token::token_program = token_program)]
    pub writer_token: InterfaceAccount<'info, TokenAccount>,
    /// CHECK: the store's PriceLog (pricelog::open)
    #[account(mut)]
    pub price_log: UncheckedAccount<'info>,
    /// CHECK: PDA ["GapReward", oft_store, writer] (open_ledger), created here when missing
    #[account(mut)]
    pub ledger: UncheckedAccount<'info>,
    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}

impl ClaimWriterRewards<'_> {
    pub fn apply(ctx: &mut Context<ClaimWriterRewards>, indices: &[u8]) -> Result<()> {
        require!(is_v3_store(&ctx.accounts.oft_store.to_account_info()), OFTError::NotV3Store);
        // round 2 B I-5: no claim while the store is paused (module doc)
        require!(!ctx.accounts.oft_store.paused, OFTError::Paused);
        let store = ctx.accounts.oft_store.key();
        let writer = ctx.accounts.writer.key();
        let mint = ctx.accounts.token_mint.key();
        let token_program = ctx.accounts.token_program.key();
        let ata = Pubkey::find_program_address(&[writer.as_ref(), token_program.as_ref(), mint.as_ref()], &ATA_PROGRAM_ID).0;
        require_keys_eq!(ctx.accounts.writer_token.key(), ata, OFTError::RewardAccountMismatch);

        // entries + reward-table slot -> the ledger (nothing double-pays: each is zeroed as taken)
        let log = ctx.accounts.price_log.to_account_info();
        require!(pricelog::open(&log, &store, ctx.program_id)?, OFTError::PriceLogMismatch);
        let moved = {
            let mut d = log.try_borrow_mut_data()?;
            let w = writer.to_bytes();
            let mut t: u64 = 0;
            for i in indices {
                t = t.checked_add(pricelog::take_entry_owed(&mut d, *i as usize, &w)).ok_or(OFTError::RewardAccounting)?;
            }
            t.checked_add(pricelog::take_orphan(&mut d, &w)).ok_or(OFTError::RewardAccounting)?
        };
        // the parked forfeits leave the reserved total here too
        let lost = {
            let mut d = log.try_borrow_mut_data()?;
            pricelog::take_forfeit(&mut d)
        };
        if lost > 0 {
            let info = ctx.accounts.oft_store.to_account_info();
            let mut d = info.try_borrow_mut_data()?;
            Tail::adjust_reward_owed(&mut d, 0, lost)?;
        }
        let ledger = ctx.accounts.ledger.to_account_info();
        let payer = ctx.accounts.writer.to_account_info();
        let system = ctx.accounts.system_program.to_account_info();
        if !credit_ledger(&ledger, &payer, &system, &store, &writer, moved, ctx.program_id)? {
            return Ok(()); // nothing owed and no ledger: nothing to do
        }
        let pay = {
            let mut d = ledger.try_borrow_mut_data()?;
            let pay = u64_at(&d, L_OWED);
            let claimed = u64_at(&d, L_CLAIMED).saturating_add(pay);
            d[L_OWED..L_OWED + 8].copy_from_slice(&0u64.to_le_bytes());
            d[L_CLAIMED..L_CLAIMED + 8].copy_from_slice(&claimed.to_le_bytes());
            pay
        };
        if pay == 0 {
            return Ok(());
        }
        // never out of the TVL (an Adapter's escrow backs the other chains' supply): the fees in the
        // escrow must cover the payment, whatever the reserved total says (lead audit 2026-10-30)
        let fees = ctx.accounts.token_escrow.amount.checked_sub(ctx.accounts.oft_store.tvl_ld).ok_or(OFTError::RewardAccounting)?;
        require!(fees >= pay, OFTError::RewardAccounting);
        {
            let info = ctx.accounts.oft_store.to_account_info();
            let mut d = info.try_borrow_mut_data()?;
            Tail::adjust_reward_owed(&mut d, 0, pay)?;
        }
        let escrow_key = ctx.accounts.token_escrow.key();
        let seeds: &[&[u8]] = &[OFT_SEED, escrow_key.as_ref(), &[ctx.accounts.oft_store.bump]];
        token_interface::transfer_checked(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.token_escrow.to_account_info(),
                    mint: ctx.accounts.token_mint.to_account_info(),
                    to: ctx.accounts.writer_token.to_account_info(),
                    authority: ctx.accounts.oft_store.to_account_info(),
                },
            )
            .with_signer(&[seeds]),
            pay,
            ctx.accounts.token_mint.decimals,
        )?;
        emit!(GapRewardClaimed { oft_store: store, writer, amount_ld: pay });
        Ok(())
    }
}

// ------------------------------------------------------------------ settle_writer_rewards

#[derive(Accounts)]
pub struct SettleWriterRewards<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(seeds = [OFT_SEED, oft_store.token_escrow.as_ref()], bump = oft_store.bump)]
    pub oft_store: Account<'info, OFTStore>,
    /// CHECK: the store's PriceLog (pricelog::open)
    #[account(mut)]
    pub price_log: UncheckedAccount<'info>,
    /// CHECK: PDA ["GapReward", oft_store, writer] (open_ledger), created here when missing
    #[account(mut)]
    pub ledger: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

impl SettleWriterRewards<'_> {
    pub fn apply(ctx: &mut Context<SettleWriterRewards>, writer: Pubkey) -> Result<()> {
        let store = ctx.accounts.oft_store.key();
        let log = ctx.accounts.price_log.to_account_info();
        require!(pricelog::open(&log, &store, ctx.program_id)?, OFTError::PriceLogMismatch);
        let moved = {
            let mut d = log.try_borrow_mut_data()?;
            pricelog::take_orphan(&mut d, &writer.to_bytes())
        };
        let ledger = ctx.accounts.ledger.to_account_info();
        credit_ledger(&ledger, &ctx.accounts.payer.to_account_info(), &ctx.accounts.system_program.to_account_info(), &store, &writer, moved, ctx.program_id)?;
        if moved > 0 {
            emit!(GapRewardSettled { oft_store: store, writer, amount_ld: moved });
        }
        Ok(())
    }
}
