//! The holders pot: the program-wide operator (`tk2-config`), each reward entry's pot PDA and its
//! token accounts, reward buys, batched holder payouts, holders' own claims (operator vouchers) and
//! the admin's recovery of stuck money.
//!
//! Money of a reward entry `i` moves: main vault (`incoming[i]`, booked at allocation) -> the pot's
//! wrapped-SOL account at the next holders instruction (`sync`): a native entry's `pot[i]`, an SPL
//! entry's `budget[i]` -> `buy_rewards` swaps budget into the pot's token account (`pot[i]`) ->
//! `pay_tokenomics_holders` / `claim_holder_reward` pay holders out of `pot[i]`. A holder's record
//! `PDA(["tk2-paid", tokenomics, [i], holder])` holds everything it has been paid of entry i, so a
//! payout is `cumulative - paid` and paying the same batch twice pays nothing the second time.
//! The program never pays an entry more than its pot holds; who is owed what is the operator's
//! (own-key risk accepted by the owner).

use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    ed25519_program,
    instruction::{AccountMeta, Instruction},
    program::{invoke, invoke_signed},
    system_instruction,
    sysvar::instructions as ixs,
};
use anchor_spl::associated_token::{self, get_associated_token_address_with_program_id};
use anchor_spl::token::spl_token;

use super::config::*;
use super::state::*;
use super::vault::once_at_top;
use crate::tokenomics::{balance, declared_priority, takes_sol, unwrap_to, TokenomicsError, MAX_REPAY_LAMPORTS, SIGNATURE_LAMPORTS, TK_TEMP_SEED};
use crate::ADMIN;

pub const RECOVER_POT: u8 = 0;
pub const RECOVER_BUDGET: u8 = 1;
pub const RECOVER_UNBOOKED_TOKENS: u8 = 2;
pub const RECOVER_UNBOOKED_LAMPORTS: u8 = 3;


// ------------------------------------------------------------------------------ the config

#[derive(Accounts)]
pub struct InitTk2Config<'info> {
    #[account(mut, address = ADMIN @ TokenomicsV2Error::NotAdmin)]
    pub admin: Signer<'info>,
    #[account(init, payer = admin, space = 8 + Tk2Config::INIT_SPACE, seeds = [TK2_CONFIG_SEED], bump)]
    pub config: Account<'info, Tk2Config>,
    pub system_program: Program<'info, System>,
}

pub fn init_tk2_config_handler(ctx: Context<InitTk2Config>, operator: Pubkey) -> Result<()> {
    require!(operator != Pubkey::default(), TokenomicsV2Error::BadConfig);
    let c = &mut ctx.accounts.config;
    c.bump = ctx.bumps.config;
    c.operator = operator;
    emit!(OperatorSet { operator });
    Ok(())
}

#[derive(Accounts)]
pub struct SetTk2Operator<'info> {
    #[account(address = ADMIN @ TokenomicsV2Error::NotAdmin)]
    pub admin: Signer<'info>,
    #[account(mut, seeds = [TK2_CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Tk2Config>,
}

/// The ADMIN sets the most a SOL payout may take from one holder, up to `MAX_FEE_PER_RECIPIENT_CAP`.
pub fn set_tk2_max_fee_handler(ctx: Context<SetTk2Operator>, max_fee_per_recipient: u64) -> Result<()> {
    require!(max_fee_per_recipient <= MAX_FEE_PER_RECIPIENT_CAP, TokenomicsV2Error::BadConfig);
    ctx.accounts.config.max_fee_per_recipient = max_fee_per_recipient;
    emit!(MaxFeeSet { max_fee_per_recipient });
    Ok(())
}

#[derive(Accounts)]
pub struct SetTk2Min<'info> {
    #[account(mut, address = ADMIN @ TokenomicsV2Error::NotAdmin)]
    pub admin: Signer<'info>,
    /// CHECK: `PDA(["tk2-min"])` (its seeds checked here), read and written by `open_tk2_min` and
    /// `store_tk2_min` only: made by the first set at the ADMIN's rent (`Tk2Min` then `Tk2Swap`,
    /// `TK2_MIN_LEN` bytes); one made before the swap rules (22 bytes) is grown by the next set.
    #[account(mut, seeds = [TK2_MIN_SEED], bump)]
    pub min: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

/// The ADMIN sets the v2 minimum: any number of lamports, 0 included. Read live by every v2
/// execute and crank (`state::min_execute`).
pub fn set_tk2_min_execute_handler(ctx: Context<SetTk2Min>, min_execute_lamports: u64) -> Result<()> {
    let (mut m, s) = open_tk2_min(&ctx.accounts, ctx.bumps.min)?;
    m.min_execute_lamports = min_execute_lamports;
    store_tk2_min(&ctx.accounts.min, &m, &s)?;
    emit!(MinExecuteSet { min_execute_lamports });
    Ok(())
}

/// The ADMIN sets the operator's repayment margin (0..=5,000 bps over the run's cost) and cap
/// (0..=1,000 bps of what the run pays out).
pub fn set_tk2_repay_handler(ctx: Context<SetTk2Min>, margin_bps: u16, cap_bps: u16) -> Result<()> {
    require!(margin_bps <= MAX_MARGIN_BPS && cap_bps <= MAX_CAP_BPS, TokenomicsV2Error::BadConfig);
    let (mut m, s) = open_tk2_min(&ctx.accounts, ctx.bumps.min)?;
    m.margin_bps = margin_bps;
    m.cap_bps = cap_bps;
    store_tk2_min(&ctx.accounts.min, &m, &s)?;
    emit!(RepayRulesSet { margin_bps, cap_bps });
    Ok(())
}

/// The ADMIN sets the swap rules (`Tk2Swap`): the cooldown (`MIN_SWAP_COOLDOWN_SECS..=MAX_SWAP_COOLDOWN_SECS` seconds)
/// and the most one swap may move the price (`MIN_MOVE_FEE_BPS..=MAX_MOVE_FEE_BPS` bps of the pool's
/// fee). Read live by v1's `execute_tokenomics` and v2's `execute_tokenomics_v2`.
pub fn set_tk2_swap_handler(ctx: Context<SetTk2Min>, swap_cooldown_secs: u32, max_move_fee_bps: u16) -> Result<()> {
    require!(
        (MIN_SWAP_COOLDOWN_SECS..=MAX_SWAP_COOLDOWN_SECS).contains(&swap_cooldown_secs) && (MIN_MOVE_FEE_BPS..=MAX_MOVE_FEE_BPS).contains(&max_move_fee_bps),
        TokenomicsV2Error::BadConfig
    );
    let (m, _) = open_tk2_min(&ctx.accounts, ctx.bumps.min)?;
    let s = Tk2Swap { swap_cooldown_secs, max_move_fee_bps };
    store_tk2_min(&ctx.accounts.min, &m, &s)?;
    emit!(SwapRulesSet { swap_cooldown_secs, max_move_fee_bps });
    Ok(())
}

/// `PDA(["tk2-min"])`'s rules as they stand, the account made ready for `store_tk2_min`
/// (`TK2_MIN_LEN` bytes, rent-exempt, at the ADMIN's cost): made with every default when it does not
/// exist (lamports somebody sent it beforehand count toward its rent, as Anchor's `init` would take
/// them); grown, with the swap rules' defaults, when it was made before them. So a setter of one
/// rule leaves every other as the program read it.
fn open_tk2_min(a: &SetTk2Min, bump: u8) -> Result<(Tk2Min, Tk2Swap)> {
    let min = a.min.to_account_info();
    let admin = a.admin.to_account_info();
    let system = a.system_program.to_account_info();
    let rent = Rent::get()?.minimum_balance(TK2_MIN_LEN);
    // The ADMIN pays what the account lacks of its rent at TK2_MIN_LEN bytes.
    let top_up = || -> Result<()> {
        let short = rent.saturating_sub(min.lamports());
        if short > 0 {
            invoke(&system_instruction::transfer(&admin.key(), &min.key(), short), &[admin.clone(), min.clone(), system.clone()])?;
        }
        Ok(())
    };
    if min.data_is_empty() && *min.owner == anchor_lang::system_program::ID {
        top_up()?;
        let seeds: &[&[u8]] = &[TK2_MIN_SEED, &[bump]];
        invoke_signed(&system_instruction::allocate(&min.key(), TK2_MIN_LEN as u64), &[min.clone(), system.clone()], &[seeds])?;
        invoke_signed(&system_instruction::assign(&min.key(), &crate::ID), &[min.clone(), system.clone()], &[seeds])?;
        let m = Tk2Min { bump, version: 1, min_execute_lamports: 0, margin_bps: DEFAULT_MARGIN_BPS, cap_bps: DEFAULT_CAP_BPS };
        return Ok((m, Tk2Swap::DEFAULT));
    }
    require_keys_eq!(*min.owner, crate::ID, TokenomicsV2Error::NotTheAccount);
    let (m, s) = decode_tk2_min(&min.try_borrow_data()?).ok_or_else(|| error!(TokenomicsV2Error::NotTheAccount))?;
    if min.data_len() != TK2_MIN_LEN {
        top_up()?;
        min.realloc(TK2_MIN_LEN, true)?;
    }
    Ok((m, s))
}

/// Write the rules into `PDA(["tk2-min"])` (made ready by `open_tk2_min`): `Tk2Min` with its
/// discriminator, then `Tk2Swap`.
fn store_tk2_min(min: &AccountInfo, m: &Tk2Min, s: &Tk2Swap) -> Result<()> {
    let mut out = Vec::with_capacity(TK2_MIN_LEN);
    m.try_serialize(&mut out)?;
    s.serialize(&mut out)?;
    let mut data = min.try_borrow_mut_data()?;
    require!(out.len() == TK2_MIN_LEN && data.len() == TK2_MIN_LEN, TokenomicsV2Error::Overflow);
    data.copy_from_slice(&out);
    Ok(())
}

pub fn set_tk2_operator_handler(ctx: Context<SetTk2Operator>, operator: Pubkey) -> Result<()> {
    require!(operator != Pubkey::default(), TokenomicsV2Error::BadConfig);
    ctx.accounts.config.operator = operator;
    emit!(OperatorSet { operator });
    Ok(())
}

// ------------------------------------------------------------------------------ helpers

pub fn pot_of(tk: &Pubkey, index: u8) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[TK2_POT_SEED, tk.as_ref(), &[index]], &crate::ID)
}

pub fn paid_record_of(tk: &Pubkey, index: u8, holder: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[TK2_PAID_SEED, tk.as_ref(), &[index], holder.as_ref()], &crate::ID)
}

/// A token account's base fields, if it is an initialised (not frozen) one of a token program.
pub struct TokenView {
    pub mint: Pubkey,
    pub owner: Pubkey,
    pub amount: u64,
    pub has_delegate: bool,
    pub has_close_authority: bool,
}

pub fn token_view(account: &AccountInfo) -> Option<TokenView> {
    if *account.owner != spl_token::ID && *account.owner != anchor_spl::token_2022::ID {
        return None;
    }
    let d = account.try_borrow_data().ok()?;
    if d.len() < 165 || d[108] != 1 {
        return None;
    }
    let key = |at: usize| Pubkey::new_from_array(d[at..at + 32].try_into().unwrap());
    Some(TokenView {
        mint: key(0),
        owner: key(32),
        amount: u64::from_le_bytes(d[64..72].try_into().unwrap()),
        has_delegate: d[72..76] != [0, 0, 0, 0],
        has_close_authority: d[129..133] != [0, 0, 0, 0],
    })
}

/// A pot account as it must stay: `pot`'s associated account for `mint` under `program`, owned by
/// `pot`, no delegate, no close authority. Returns its balance.
fn pot_account(account: &AccountInfo, pot: &Pubkey, mint: &Pubkey, program: &Pubkey) -> Result<u64> {
    require_keys_eq!(account.key(), get_associated_token_address_with_program_id(pot, mint, program), TokenomicsV2Error::NotTheAccount);
    require_keys_eq!(*account.owner, *program, TokenomicsV2Error::NotTheAccount);
    let v = token_view(account).ok_or(TokenomicsV2Error::NotTheAccount)?;
    require!(v.mint == *mint && v.owner == *pot && !v.has_delegate && !v.has_close_authority, TokenomicsV2Error::PotAccountChanged);
    Ok(v.amount)
}

/// Token-2022 mint extensions (`ExtensionType`) a reward mint may carry: data only, read by wallets
/// and indexers, never consulted by a transfer.
///
/// THE ONES AN AUTHORITY CAN ADD AFTER `InitializeMint` ARE ALL ON IT (audit round 4): an entry's
/// pot is opened once and bought into for good, so a mint that gains one later must not stop its
/// buys and payouts. Token-2022 lets an authority add, after the mint is made, only these three --
/// each realloc'd onto the mint by its own initialise instruction, each data the transfer path
/// never reads:
///  - TokenMetadata (19), by the metadata pointer's authority (`token_metadata::initialize`);
///  - TokenGroup (21), by the group pointer's authority (`token_group::initialize_group`);
///  - TokenGroupMember (23), by the member pointer's authority (`token_group::initialize_member`).
/// Every other mint extension can only be set before `InitializeMint`, so a mint's other
/// extensions are fixed when its pot is opened: the pointers (18, 20, 22), data only, allowed; all
/// else refused (`reward_mint_ok`).
const EXT_METADATA_POINTER: u16 = 18;
const EXT_TOKEN_METADATA: u16 = 19;
const EXT_GROUP_POINTER: u16 = 20;
const EXT_TOKEN_GROUP: u16 = 21;
const EXT_GROUP_MEMBER_POINTER: u16 = 22;
const EXT_TOKEN_GROUP_MEMBER: u16 = 23;
/// The one account extension a payout may meet: ImmutableOwner, which every Token-2022 associated
/// account carries.
const EXT_IMMUTABLE_OWNER: u16 = 7;

/// The extension types a Token-2022 account's data carries (the base padded to 165 bytes, its
/// account type, then type-length-value entries), or None when the list cannot be read.
fn extensions(d: &[u8]) -> Option<Vec<u16>> {
    let mut out = Vec::new();
    if d.len() <= 165 {
        return Some(out);
    }
    let mut at = 166;
    while at + 4 <= d.len() {
        let kind = u16::from_le_bytes([d[at], d[at + 1]]);
        let len = u16::from_le_bytes([d[at + 2], d[at + 3]]) as usize;
        if kind == 0 {
            break;
        }
        at = at.checked_add(4 + len)?;
        if at > d.len() {
            return None;
        }
        out.push(kind);
    }
    Some(out)
}

/// A reward mint holders can be paid in (audit rounds 1-3): a classic SPL mint, or a Token-2022
/// mint whose every extension is on the allowlist above. Every other extension is refused -- a
/// transfer hook, a permanent delegate, pausable, non-transferable, a transfer fee, confidential
/// transfers, a default account state, interest-bearing or scaled amounts, a mint close authority,
/// and whatever Token-2022 adds next -- since each can stop, skew or drain an entry's payouts.
///
/// A FREEZE AUTHORITY IS ACCEPTED (USDC has one): a freeze stops only that entry's payouts, the
/// admin can still recover its budget (`admin_recover`), and no other entry or bucket is touched.
fn reward_mint_ok(mint: &AccountInfo) -> Result<()> {
    if *mint.owner != anchor_spl::token_2022::ID {
        return Ok(());
    }
    let d = mint.try_borrow_data()?;
    let allowed = [EXT_METADATA_POINTER, EXT_TOKEN_METADATA, EXT_GROUP_POINTER, EXT_TOKEN_GROUP, EXT_GROUP_MEMBER_POINTER, EXT_TOKEN_GROUP_MEMBER];
    let ok = extensions(&d).is_some_and(|x| x.iter().all(|k| allowed.contains(k)));
    require!(ok, TokenomicsV2Error::RewardMintRefused);
    Ok(())
}

/// A holder's token account a payout or a claim may pay into: no account extension but
/// ImmutableOwner (audit round 3) -- nothing its holder enables (confidential-only credits, a memo
/// requirement, a CPI guard) can then revert a batch.
fn plain_account(account: &AccountInfo) -> bool {
    let Ok(d) = account.try_borrow_data() else { return false };
    extensions(&d).is_some_and(|x| x.iter().all(|k| *k == EXT_IMMUTABLE_OWNER))
}

fn mint_decimals(mint: &AccountInfo) -> Result<u8> {
    require!(*mint.owner == spl_token::ID || *mint.owner == anchor_spl::token_2022::ID, TokenomicsV2Error::NotTheAccount);
    let d = mint.try_borrow_data()?;
    require!(d.len() >= 82 && d[45] == 1, TokenomicsV2Error::NotTheAccount);
    Ok(d[44])
}

/// A transfer out of an account `authority` (a PDA of this program) owns, under the account's own
/// token program.
#[allow(clippy::too_many_arguments)]
fn transfer_out<'info>(all: &[AccountInfo<'info>], program: &Pubkey, from: &Pubkey, mint: &Pubkey, to: &Pubkey, authority: &Pubkey, seeds: &[&[u8]], amount: u64, decimals: u8) -> Result<()> {
    if amount == 0 {
        return Ok(());
    }
    let ix = if *program == spl_token::ID {
        spl_token::instruction::transfer_checked(program, from, mint, to, authority, &[], amount, decimals)?
    } else {
        anchor_spl::token_2022::spl_token_2022::instruction::transfer_checked(program, from, mint, to, authority, &[], amount, decimals)?
    };
    invoke_signed(&ix, all, &[seeds])?;
    Ok(())
}

/// Allocate the main vault's new fees, then move entry `i`'s `incoming` into its pot's wrapped-SOL
/// account, booked as its pot (native) or its budget (SPL). Both accounts are pinned here, before
/// anything moves (audit round 1, L: a wrong pot account would book money the pot does not hold).
#[allow(clippy::too_many_arguments)]
fn sync<'info>(all: &[AccountInfo<'info>], t: &mut TokenomicsV2, tk: Pubkey, vault_wsol: &AccountInfo<'info>, pot_wsol: &AccountInfo<'info>, pot: &Pubkey, i: usize) -> Result<()> {
    require_keys_eq!(vault_wsol.key(), get_associated_token_address_with_program_id(&tk, &spl_token::native_mint::ID, &spl_token::ID), TokenomicsV2Error::NotTheAccount);
    require_keys_eq!(pot_wsol.key(), get_associated_token_address_with_program_id(pot, &spl_token::native_mint::ID, &spl_token::ID), TokenomicsV2Error::NotTheAccount);
    allocate_v2(t, tk, balance(vault_wsol)?);
    let amount = t.rewards[i].incoming;
    if amount == 0 {
        return Ok(());
    }
    let (hash, bump) = (t.config_hash, [t.bump]);
    let seeds: [&[u8]; 3] = [TOKENOMICS_V2_SEED, &hash, &bump];
    let ix = spl_token::instruction::transfer_checked(&spl_token::ID, vault_wsol.key, &spl_token::native_mint::ID, pot_wsol.key, &tk, &[], amount, 9)?;
    invoke_signed(&ix, all, &[&seeds])?;
    let r = &mut t.rewards[i];
    r.incoming = 0;
    if r.native() {
        r.pot += amount;
    } else {
        r.budget += amount;
    }
    Ok(())
}

/// What a pot's wrapped-SOL account must hold: the entry's pot (native) or budget (SPL).
fn wsol_booked(r: &RewardSlot) -> u64 {
    if r.native() {
        r.pot
    } else {
        r.budget
    }
}

/// Every top-level instruction of the transaction is checked for one by the ed25519 program
/// verifying `operator`'s signature over `message`, all within that instruction's own data.
fn voucher_signed(instructions: &AccountInfo, operator: &Pubkey, message: &[u8]) -> Result<bool> {
    let count = {
        let d = instructions.try_borrow_data()?;
        u16::from_le_bytes(d.get(..2).and_then(|b| b.try_into().ok()).ok_or(TokenomicsV2Error::BadVoucher)?) as usize
    };
    for i in 0..count {
        let ix = ixs::load_instruction_at_checked(i, instructions)?;
        if ix.program_id != ed25519_program::ID {
            continue;
        }
        let d = &ix.data;
        if d.len() < 16 || d[0] != 1 {
            continue;
        }
        let u = |at: usize| u16::from_le_bytes([d[at], d[at + 1]]);
        let (sig_ix, pk_at, pk_ix, msg_at, msg_len, msg_ix) = (u(4), u(6) as usize, u(8), u(10) as usize, u(12) as usize, u(14));
        let here = |x: u16| x == u16::MAX || x as usize == i;
        if !(here(sig_ix) && here(pk_ix) && here(msg_ix)) {
            continue;
        }
        if d.get(pk_at..pk_at + 32) == Some(operator.as_ref()) && msg_len == message.len() && d.get(msg_at..msg_at + msg_len) == Some(message) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The voucher message this build takes: `"pangea-tk2-claim" || program id || cluster:u8 ||
/// tokenomics || index:u8 || holder:32 || cumulative:u64 LE`, naming this program and the cluster
/// it was built for, so a voucher for another deployment or cluster never pays here.
pub fn claim_message(tk: &Pubkey, index: u8, holder: &Pubkey, cumulative: u64) -> Vec<u8> {
    claim_message_for(&crate::ID, CLAIM_CLUSTER, tk, index, holder, cumulative)
}

/// The voucher message for any program and cluster.
pub fn claim_message_for(program: &Pubkey, cluster: u8, tk: &Pubkey, index: u8, holder: &Pubkey, cumulative: u64) -> Vec<u8> {
    let mut m = Vec::with_capacity(CLAIM_DOMAIN.len() + 32 + 1 + 32 + 1 + 32 + 8);
    m.extend_from_slice(CLAIM_DOMAIN);
    m.extend_from_slice(program.as_ref());
    m.push(cluster);
    m.extend_from_slice(tk.as_ref());
    m.push(index);
    m.extend_from_slice(holder.as_ref());
    m.extend_from_slice(&cumulative.to_le_bytes());
    m
}

// ------------------------------------------------------------------------------ the pot's accounts

#[derive(Accounts)]
#[instruction(index: u8)]
pub struct OpenRewardPot<'info> {
    /// Anyone; pays the pot accounts' rent (not repaid).
    #[account(mut)]
    pub payer: Signer<'info>,
    pub tokenomics: Box<Account<'info, TokenomicsV2>>,
    /// CHECK: `PDA(["tk2-pot", tokenomics, [index]])`.
    #[account(seeds = [TK2_POT_SEED, tokenomics.key().as_ref(), &[index]], bump)]
    pub pot: UncheckedAccount<'info>,
    /// CHECK: the pot's wrapped-SOL account, made here (idempotent).
    #[account(mut)]
    pub pot_wsol: UncheckedAccount<'info>,
    /// CHECK: pinned.
    #[account(address = spl_token::native_mint::ID)]
    pub wsol_mint: UncheckedAccount<'info>,
    /// CHECK: an SPL entry's token account, made here; for a native entry, any account (unused).
    #[account(mut)]
    pub pot_token: UncheckedAccount<'info>,
    /// CHECK: an SPL entry's mint (its owner is its token program); unused for native.
    pub reward_mint: UncheckedAccount<'info>,
    /// CHECK: the reward mint's token program (Token or Token-2022); unused for native.
    pub reward_token_program: UncheckedAccount<'info>,
    /// CHECK: pinned.
    #[account(address = spl_token::ID)]
    pub token_program: UncheckedAccount<'info>,
    pub associated_token_program: Program<'info, anchor_spl::associated_token::AssociatedToken>,
    pub system_program: Program<'info, System>,
}

pub(crate) fn create_ata<'info>(all: &[AccountInfo<'info>], payer: &Pubkey, account: &Pubkey, owner: &Pubkey, mint: &Pubkey, program: &Pubkey) -> Result<()> {
    let ix = Instruction {
        program_id: associated_token::ID,
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(*account, false),
            AccountMeta::new_readonly(*owner, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new_readonly(System::id(), false),
            AccountMeta::new_readonly(*program, false),
        ],
        data: vec![1], // CreateIdempotent
    };
    invoke(&ix, all)?;
    Ok(())
}

/// The pot accounts of entry `index`: its wrapped-SOL account, and an SPL entry's token account.
pub fn open_reward_pot_handler(ctx: Context<OpenRewardPot>, index: u8) -> Result<()> {
    let a = &ctx.accounts;
    let t = &a.tokenomics;
    let i = index as usize;
    require!(i < t.num_rewards as usize, TokenomicsV2Error::NoSuch);
    let all = a.to_account_infos();
    let pot = a.pot.key();
    let payer = a.payer.key();
    require_keys_eq!(a.pot_wsol.key(), get_associated_token_address_with_program_id(&pot, &spl_token::native_mint::ID, &spl_token::ID), TokenomicsV2Error::NotTheAccount);
    create_ata(&all, &payer, &a.pot_wsol.key(), &pot, &spl_token::native_mint::ID, &spl_token::ID)?;
    let r = t.rewards[i];
    if !r.native() {
        let program = a.reward_token_program.key();
        require_keys_eq!(a.reward_mint.key(), r.token, TokenomicsV2Error::NotTheAccount);
        require!(program == spl_token::ID || program == anchor_spl::token_2022::ID, TokenomicsV2Error::NotTheAccount);
        require_keys_eq!(*a.reward_mint.owner, program, TokenomicsV2Error::NotTheAccount);
        reward_mint_ok(&a.reward_mint)?;
        require_keys_eq!(a.pot_token.key(), get_associated_token_address_with_program_id(&pot, &r.token, &program), TokenomicsV2Error::NotTheAccount);
        create_ata(&all, &payer, &a.pot_token.key(), &pot, &r.token, &program)?;
    }
    Ok(())
}

// ------------------------------------------------------------------------------ reward buys

#[derive(Accounts)]
#[instruction(index: u8)]
pub struct BuyRewards<'info> {
    pub operator: Signer<'info>,
    #[account(seeds = [TK2_CONFIG_SEED], bump = config.bump, has_one = operator @ TokenomicsV2Error::NotOperator)]
    pub config: Box<Account<'info, Tk2Config>>,
    #[account(mut, constraint = tokenomics.bound @ TokenomicsError::NotBound)]
    pub tokenomics: Box<Account<'info, TokenomicsV2>>,
    /// CHECK: the main vault (`sync`).
    #[account(mut)]
    pub vault_wsol: UncheckedAccount<'info>,
    /// CHECK: `PDA(["tk2-pot", tokenomics, [index]])`: signs the route's call.
    #[account(seeds = [TK2_POT_SEED, tokenomics.key().as_ref(), &[index]], bump)]
    pub pot: UncheckedAccount<'info>,
    /// CHECK: the pot's wrapped-SOL account (`pot_account`).
    #[account(mut)]
    pub pot_wsol: UncheckedAccount<'info>,
    /// CHECK: the pot's token account (`pot_account`).
    #[account(mut)]
    pub pot_token: UncheckedAccount<'info>,
    /// CHECK: the entry's mint.
    pub reward_mint: UncheckedAccount<'info>,
    /// CHECK: pinned.
    #[account(address = spl_token::ID)]
    pub token_program: UncheckedAccount<'info>,
    /// CHECK: the route: any program but the ones `route_refused` lists.
    pub route_program: UncheckedAccount<'info>,
    // Then the route's accounts, in its order; the pot among them is made a signer.
}

/// Programs a route may not be: this program, the token programs (the pot signs: a direct call
/// could approve, transfer or close its accounts), the system and associated-token programs.
fn route_refused(p: &Pubkey) -> bool {
    [crate::ID, spl_token::ID, anchor_spl::token_2022::ID, System::id(), associated_token::ID, ed25519_program::ID].contains(p)
}

/// OPERATOR: swap at most `amount_in` of entry `index`'s budget into its token through
/// `route_program` (the operator's route, its accounts after this instruction's), the pot PDA
/// signing. Then: the pot's wrapped SOL fell by at most `amount_in`, its token account rose by at
/// least `min_out`, both still the pot's with no delegate or close authority; the rise is the pot's,
/// the fall comes off the budget (a refund of unspent SOL stays in it).
pub fn buy_rewards_handler<'info>(ctx: Context<'_, '_, 'info, 'info, BuyRewards<'info>>, index: u8, amount_in: u64, min_out: u64, data: Vec<u8>) -> Result<()> {
    let a = &ctx.accounts;
    let tk = a.tokenomics.key();
    let i = index as usize;
    let mut t: TokenomicsV2 = (**a.tokenomics).clone();
    require!(i < t.num_rewards as usize && !t.rewards[i].native(), TokenomicsV2Error::NoSuch);
    let mut all = a.to_account_infos();
    all.extend_from_slice(ctx.remaining_accounts);
    sync(&all, &mut t, tk, &a.vault_wsol, &a.pot_wsol, &a.pot.key(), i)?;
    require!(amount_in > 0 && min_out > 0 && amount_in <= t.rewards[i].budget, TokenomicsV2Error::BadBuy);
    let route = a.route_program.key();
    require!(a.route_program.executable && !route_refused(&route), TokenomicsV2Error::BadRoute);
    let pot = a.pot.key();
    let mint = t.rewards[i].token;
    require_keys_eq!(a.reward_mint.key(), mint, TokenomicsV2Error::NotTheAccount);
    let program = *a.reward_mint.owner;
    require!(program == spl_token::ID || program == anchor_spl::token_2022::ID, TokenomicsV2Error::NotTheAccount);
    // Bought only into a token holders can be paid in (a pot account anyone made through the
    // associated-token program directly skips `open_reward_pot`'s check).
    reward_mint_ok(&a.reward_mint)?;
    let wsol_before = pot_account(&a.pot_wsol, &pot, &spl_token::native_mint::ID, &spl_token::ID)?;
    let token_before = pot_account(&a.pot_token, &pot, &mint, &program)?;
    let metas = ctx
        .remaining_accounts
        .iter()
        .map(|r| AccountMeta { pubkey: r.key(), is_signer: r.is_signer || r.key() == pot, is_writable: r.is_writable })
        .collect();
    let pot_seeds: &[&[u8]] = &[TK2_POT_SEED, tk.as_ref(), &[index], &[ctx.bumps.pot]];
    invoke_signed(&Instruction { program_id: route, accounts: metas, data }, &all, &[pot_seeds])?;
    let wsol_after = pot_account(&a.pot_wsol, &pot, &spl_token::native_mint::ID, &spl_token::ID)?;
    let token_after = pot_account(&a.pot_token, &pot, &mint, &program)?;
    let fell = wsol_before.saturating_sub(wsol_after);
    require!(fell <= amount_in && token_after >= token_before, TokenomicsV2Error::BadBuy);
    let rise = token_after - token_before;
    require!(rise >= min_out, TokenomicsV2Error::BadBuy);
    let r = &mut t.rewards[i];
    r.budget -= fell;
    r.pot += rise;
    r.bought += rise;
    require!(wsol_after >= r.budget && token_after >= r.pot, TokenomicsV2Error::Overflow);
    emit!(RewardsBought { tokenomics: tk, index, sol_in: fell, tokens_out: rise });
    **ctx.accounts.tokenomics = t;
    Ok(())
}

// ------------------------------------------------------------------------------ holder payouts

#[derive(Accounts)]
#[instruction(index: u8)]
pub struct PayHolders<'info> {
    /// The operator: fronts each first-time record's rent and the SOL passage's, repaid with its
    /// fee out of the entry (`pay_holders_handler`).
    #[account(mut)]
    pub operator: Signer<'info>,
    #[account(seeds = [TK2_CONFIG_SEED], bump = config.bump, has_one = operator @ TokenomicsV2Error::NotOperator)]
    pub config: Box<Account<'info, Tk2Config>>,
    #[account(mut, constraint = tokenomics.bound @ TokenomicsError::NotBound)]
    pub tokenomics: Box<Account<'info, TokenomicsV2>>,
    /// CHECK: the main vault (`sync`).
    #[account(mut)]
    pub vault_wsol: UncheckedAccount<'info>,
    /// CHECK: `PDA(["tk2-pot", tokenomics, [index]])`.
    #[account(seeds = [TK2_POT_SEED, tokenomics.key().as_ref(), &[index]], bump)]
    pub pot: UncheckedAccount<'info>,
    /// CHECK: the pot's wrapped-SOL account (`pot_account`).
    #[account(mut)]
    pub pot_wsol: UncheckedAccount<'info>,
    /// CHECK: `PDA(["tk-temp", pot])`: the SOL passage, made and closed here.
    #[account(mut, seeds = [TK_TEMP_SEED, pot.key().as_ref()], bump)]
    pub temp: UncheckedAccount<'info>,
    /// CHECK: pinned.
    #[account(address = spl_token::native_mint::ID)]
    pub wsol_mint: UncheckedAccount<'info>,
    /// CHECK: pinned.
    #[account(address = spl_token::ID)]
    pub token_program: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
    /// CHECK: pinned.
    #[account(address = ixs::ID)]
    pub instructions: UncheckedAccount<'info>,
    /// CHECK: an SPL entry's pot token account (`pot_account`); a native entry passes none.
    #[account(mut)]
    pub pot_token: Option<UncheckedAccount<'info>>,
    /// CHECK: an SPL entry's mint.
    pub reward_mint: Option<UncheckedAccount<'info>>,
    /// CHECK: its token program (the mint's owner).
    pub reward_token_program: Option<UncheckedAccount<'info>>,
    /// CHECK: an SPL entry: the associated-token program, which makes a holder's missing account.
    #[account(address = associated_token::ID @ TokenomicsV2Error::NotTheAccount)]
    pub associated_token_program: Option<UncheckedAccount<'info>>,
    // Then, per holder: native -- two accounts, the holder's wallet (writable) and its record
    // (writable); SPL -- three, the holder's wallet, its associated token account for the entry's
    // mint (writable) and its record (writable).
}

/// OPERATOR: pay holders of entry `index` up to the cumulative amounts given. A holder is paid
/// `cumulative - paid` (nothing when that is not positive), SOL to a plain wallet that stays
/// rent-exempt, the token into its associated account for the entry's mint -- made here when it is
/// missing (token entries only: the operator fronts its rent, repaid from the entry's budget; the rent
/// stays in the holder's account), skipped when it is frozen or carries any account extension but
/// ImmutableOwner (`plain_account`: confidential-only credits, a memo requirement, a CPI guard --
/// nothing its holder enables can revert a batch). One that cannot be paid is skipped, not failed;
/// its holder stays owed and may claim into any plain account of its own.
/// The batch may never pay more than the pot (`PotExceeded`, checked before each payment).
///
/// THE OPERATOR'S TAKE (owner, 2026-10-24):
///  - a SOL entry: each holder bears its own payout's cost as its fee, which the operator names
///    and the program caps -- at most 10% of what the holder is due and at most the config's
///    `max_fee_per_recipient`, else the holder is skipped (reason 4). The holder is sent `due - fee`,
///    the pot falls by `due`, the operator receives the fees in all; the first-time records' rent it
///    fronted is its own to cover from them (charging less only costs the operator). Nothing else is
///    repaid.
///  - a token entry: no fee; the operator is repaid its fee (signature + declared priority, as
///    `execute`), each first-time record's rent and each account it made, out of the entry's budget
///    (wrapped SOL no holder is owed); nothing for a batch that paid nobody.
///
/// `amounts`: a SOL entry's `cumulative, fee` per holder (two words each), a token entry's
/// `cumulative` per holder (one): one list, so a token batch spends no bytes on fees it has none of.
pub fn pay_holders_handler<'info>(ctx: Context<'_, '_, 'info, 'info, PayHolders<'info>>, index: u8, amounts: Vec<u64>) -> Result<()> {
    once_at_top(&ctx.accounts.instructions, false)?;
    let a = &ctx.accounts;
    let tk = a.tokenomics.key();
    let i = index as usize;
    let operator = a.operator.to_account_info();
    require!(*operator.owner == System::id() && operator.data_is_empty(), TokenomicsError::CallerNotAWallet);
    let mut t: TokenomicsV2 = (**a.tokenomics).clone();
    require!(i < t.num_rewards as usize, TokenomicsV2Error::NoSuch);
    let rest = ctx.remaining_accounts;
    let native = t.rewards[i].native();
    let stride = if native { 2 } else { 3 };
    // A SOL entry: (cumulative, fee) per holder; a token entry: cumulative.
    let words = if native { 2 } else { 1 };
    require!(amounts.len() % words == 0, TokenomicsV2Error::BadConfig);
    let (cumulative, fees): (Vec<u64>, Vec<u64>) = if native {
        (amounts.iter().step_by(2).copied().collect(), amounts.iter().skip(1).step_by(2).copied().collect())
    } else {
        (amounts, Vec::new())
    };
    require!(rest.len() == stride * cumulative.len(), TokenomicsV2Error::NotTheAccount);
    let max_fee = a.config.max_fee_per_recipient;
    let mut all = a.to_account_infos();
    all.extend_from_slice(rest);
    sync(&all, &mut t, tk, &a.vault_wsol, &a.pot_wsol, &a.pot.key(), i)?;
    let pot = a.pot.key();
    pot_account(&a.pot_wsol, &pot, &spl_token::native_mint::ID, &spl_token::ID)?;
    // An SPL entry's token side.
    let spl = if native {
        None
    } else {
        let pot_token = a.pot_token.as_ref().ok_or(TokenomicsV2Error::NotTheAccount)?;
        let mint = a.reward_mint.as_ref().ok_or(TokenomicsV2Error::NotTheAccount)?;
        let program = a.reward_token_program.as_ref().ok_or(TokenomicsV2Error::NotTheAccount)?.key();
        require_keys_eq!(mint.key(), t.rewards[i].token, TokenomicsV2Error::NotTheAccount);
        require_keys_eq!(*mint.owner, program, TokenomicsV2Error::NotTheAccount);
        pot_account(pot_token, &pot, &mint.key(), &program)?;
        a.associated_token_program.as_ref().ok_or(TokenomicsV2Error::NotTheAccount)?;
        Some((pot_token.key(), mint.key(), program, mint_decimals(mint)?))
    };
    let pot_seeds: &[&[u8]] = &[TK2_POT_SEED, tk.as_ref(), &[index], &[ctx.bumps.pot]];
    let record_space = 8 + Tk2Paid::INIT_SPACE;
    let record_rent = Rent::get()?.minimum_balance(record_space);
    let (mut paid, mut rents, mut count, mut fees_total) = (0u64, 0u64, 0u16, 0u64);
    let mut sol_to: Vec<(usize, u64)> = Vec::new();
    let available = t.rewards[i].pot;
    for (k, c) in cumulative.iter().copied().enumerate() {
        // Native: the holder's wallet is paid. SPL: the holder's associated account for the mint.
        let (holder, acct, rec) = match &spl {
            None => (rest[2 * k].key(), &rest[2 * k], &rest[2 * k + 1]),
            Some((_, mint, program, _)) => {
                let (wallet, acct) = (&rest[3 * k], &rest[3 * k + 1]);
                require_keys_eq!(acct.key(), get_associated_token_address_with_program_id(wallet.key, mint, program), TokenomicsV2Error::NotTheAccount);
                (wallet.key(), acct, &rest[3 * k + 2])
            }
        };
        let (expected, bump) = paid_record_of(&tk, index, &holder);
        require_keys_eq!(rec.key(), expected, TokenomicsV2Error::NotTheAccount);
        let exists = *rec.owner == crate::ID;
        let before = if exists { Tk2Paid::try_deserialize(&mut &rec.try_borrow_data()?[..])?.cumulative } else { 0 };
        if c <= before {
            emit!(HolderSkipped { tokenomics: tk, index, account: acct.key(), reason: 1 });
            continue;
        }
        let due = c - before;
        let mut fee = 0u64;
        if spl.is_none() {
            fee = fees[k];
            if fee > ((due as u128 * FEE_MAX_BPS as u128) / 10_000) as u64 || fee > max_fee {
                emit!(HolderSkipped { tokenomics: tk, index, account: acct.key(), reason: 4 });
                continue;
            }
            // Sent after the loop: what this holder is already sent in the batch counts too.
            let queued: u64 = sol_to.iter().filter(|(x, _)| rest[*x].key == acct.key).map(|(_, v)| *v).sum();
            if !takes_sol(acct, queued + due - fee)? {
                emit!(HolderSkipped { tokenomics: tk, index, account: acct.key(), reason: 2 });
                continue;
            }
        }
        require!(paid.checked_add(due).ok_or(TokenomicsV2Error::Overflow)? <= available, TokenomicsV2Error::PotExceeded);
        if let Some((_, mint, program, _)) = &spl {
            // A missing account is made (the operator fronts its rent, counted as this payout's gas);
            // one that is there must be usable: initialised, not frozen, no memo required.
            // An account made here is new: initialised, and not frozen -- a mint with a default
            // account state is not on the allowlist (`reward_mint_ok`), so none starts frozen -- and
            // carrying ImmutableOwner alone; so it is never made and then skipped (and if it ever
            // were, the instruction fails). Its rent is repaid only with a payment (audit round 2).
            let mut made = 0u64;
            if *acct.owner == System::id() && acct.data_is_empty() {
                require!(acct.is_writable, TokenomicsV2Error::NotTheAccount);
                let fronted = operator.lamports();
                create_ata(&all, operator.key, acct.key, &holder, mint, program)?;
                made = fronted.saturating_sub(operator.lamports());
            }
            let usable = *acct.owner == *program && acct.is_writable && plain_account(acct);
            if !token_view(acct).is_some_and(|v| usable && v.mint == *mint && v.owner == holder) {
                require!(made == 0, TokenomicsV2Error::NotTheAccount);
                emit!(HolderSkipped { tokenomics: tk, index, account: acct.key(), reason: 3 });
                continue;
            }
            rents += made;
        }
        // The record: made on the first payment (the operator fronts its rent), then written.
        if !exists {
            let rec_seeds: &[&[u8]] = &[TK2_PAID_SEED, tk.as_ref(), &[index], holder.as_ref(), &[bump]];
            let held = rec.lamports();
            if held < record_rent {
                invoke(&system_instruction::transfer(operator.key, rec.key, record_rent - held), &all)?;
                // Repaid for a token entry; a SOL entry's holder's fee covers it.
                rents += record_rent - held;
            }
            invoke_signed(&system_instruction::allocate(rec.key, record_space as u64), &all, &[rec_seeds])?;
            invoke_signed(&system_instruction::assign(rec.key, &crate::ID), &all, &[rec_seeds])?;
        }
        {
            let mut d = rec.try_borrow_mut_data()?;
            Tk2Paid { cumulative: c }.try_serialize(&mut &mut d[..])?;
        }
        match &spl {
            None => sol_to.push((2 * k, due - fee)),
            Some((pot_token, mint, program, decimals)) => transfer_out(&all, program, pot_token, mint, &acct.key(), &pot, pot_seeds, due, *decimals)?,
        }
        paid += due;
        fees_total += fee;
        count += 1;
        emit!(HolderPaid { tokenomics: tk, index, holder, amount: due, cumulative: c, sent: due - fee, fee });
    }
    // The operator's take: a SOL entry's fees (out of what the holders were due), or a token entry's
    // gas and rents out of its budget.
    let r = &mut t.rewards[i];
    let repay = if native {
        fees_total
    } else if count == 0 {
        0
    } else {
        ((SIGNATURE_LAMPORTS + declared_priority(&a.instructions)?).min(MAX_REPAY_LAMPORTS) + rents).min(r.budget)
    };
    r.pot -= paid;
    if !native {
        r.budget -= repay;
    }
    r.paid += paid;
    r.gas_repaid += repay;
    let booked_wsol = wsol_booked(r);
    let booked_pot = r.pot;
    let sol_out: u64 = sol_to.iter().map(|(_, v)| *v).sum();
    let pot_info = a.pot.to_account_info();
    unwrap_to(&all, &operator, &a.temp, ctx.bumps.temp, &pot_info, pot_seeds, &a.pot_wsol, sol_out + repay)?;
    for (x, v) in &sol_to {
        invoke(&system_instruction::transfer(operator.key, rest[*x].key, *v), &all)?;
    }
    emit!(HoldersPaid { tokenomics: tk, index, holders: count, amount: paid, repaid: repay });
    require!(balance(&a.pot_wsol)? >= booked_wsol, TokenomicsV2Error::Overflow);
    if let (Some(pt), false) = (a.pot_token.as_ref(), native) {
        require!(balance(pt)? >= booked_pot, TokenomicsV2Error::Overflow);
    }
    require!(balance(&a.vault_wsol)? >= t.tracked(), TokenomicsV2Error::Overflow);
    **ctx.accounts.tokenomics = t;
    Ok(())
}

// ------------------------------------------------------------------------------ a holder's claim

#[derive(Accounts)]
#[instruction(index: u8)]
pub struct ClaimHolder<'info> {
    /// The holder: pays its own fee and its record's rent.
    #[account(mut)]
    pub holder: Signer<'info>,
    #[account(seeds = [TK2_CONFIG_SEED], bump = config.bump)]
    pub config: Box<Account<'info, Tk2Config>>,
    #[account(mut, constraint = tokenomics.bound @ TokenomicsError::NotBound)]
    pub tokenomics: Box<Account<'info, TokenomicsV2>>,
    /// CHECK: the main vault (`sync`).
    #[account(mut)]
    pub vault_wsol: UncheckedAccount<'info>,
    /// CHECK: `PDA(["tk2-pot", tokenomics, [index]])`.
    #[account(seeds = [TK2_POT_SEED, tokenomics.key().as_ref(), &[index]], bump)]
    pub pot: UncheckedAccount<'info>,
    /// CHECK: the pot's wrapped-SOL account (`pot_account`).
    #[account(mut)]
    pub pot_wsol: UncheckedAccount<'info>,
    #[account(init_if_needed, payer = holder, space = 8 + Tk2Paid::INIT_SPACE, seeds = [TK2_PAID_SEED, tokenomics.key().as_ref(), &[index], holder.key().as_ref()], bump)]
    pub record: Box<Account<'info, Tk2Paid>>,
    /// CHECK: `PDA(["tk-temp", pot])`.
    #[account(mut, seeds = [TK_TEMP_SEED, pot.key().as_ref()], bump)]
    pub temp: UncheckedAccount<'info>,
    /// CHECK: pinned.
    #[account(address = spl_token::native_mint::ID)]
    pub wsol_mint: UncheckedAccount<'info>,
    /// CHECK: pinned.
    #[account(address = spl_token::ID)]
    pub token_program: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
    /// CHECK: pinned.
    #[account(address = ixs::ID)]
    pub instructions: UncheckedAccount<'info>,
    /// CHECK: an SPL entry's pot token account.
    #[account(mut)]
    pub pot_token: Option<UncheckedAccount<'info>>,
    /// CHECK: an SPL entry's mint.
    pub reward_mint: Option<UncheckedAccount<'info>>,
    /// CHECK: its token program.
    pub reward_token_program: Option<UncheckedAccount<'info>>,
    /// CHECK: an SPL entry: the holder's token account the claim pays into (any of the mint's
    /// owned by the holder).
    #[account(mut)]
    pub destination: Option<UncheckedAccount<'info>>,
}

/// The holder takes `cumulative - paid` of entry `index` with the operator's voucher for
/// `cumulative` (an ed25519 instruction in this transaction over `claim_message`): SOL to itself,
/// or the token into its own account. The same pot cap; no fee repaid.
pub fn claim_holder_handler<'info>(ctx: Context<'_, '_, 'info, 'info, ClaimHolder<'info>>, index: u8, cumulative: u64) -> Result<()> {
    let a = &ctx.accounts;
    let tk = a.tokenomics.key();
    let i = index as usize;
    let holder = a.holder.key();
    let mut t: TokenomicsV2 = (**a.tokenomics).clone();
    require!(i < t.num_rewards as usize, TokenomicsV2Error::NoSuch);
    require!(voucher_signed(&a.instructions, &a.config.operator, &claim_message(&tk, index, &holder, cumulative))?, TokenomicsV2Error::BadVoucher);
    let all = a.to_account_infos();
    sync(&all, &mut t, tk, &a.vault_wsol, &a.pot_wsol, &a.pot.key(), i)?;
    let pot = a.pot.key();
    pot_account(&a.pot_wsol, &pot, &spl_token::native_mint::ID, &spl_token::ID)?;
    let before = a.record.cumulative;
    require!(cumulative > before, TokenomicsV2Error::NothingDue);
    let due = cumulative - before;
    require!(due <= t.rewards[i].pot, TokenomicsV2Error::PotExceeded);
    let pot_seeds: &[&[u8]] = &[TK2_POT_SEED, tk.as_ref(), &[index], &[ctx.bumps.pot]];
    if t.rewards[i].native() {
        let pot_info = a.pot.to_account_info();
        let h = a.holder.to_account_info();
        unwrap_to(&all, &h, &a.temp, ctx.bumps.temp, &pot_info, pot_seeds, &a.pot_wsol, due)?;
    } else {
        let pot_token = a.pot_token.as_ref().ok_or(TokenomicsV2Error::NotTheAccount)?;
        let mint = a.reward_mint.as_ref().ok_or(TokenomicsV2Error::NotTheAccount)?;
        let program = a.reward_token_program.as_ref().ok_or(TokenomicsV2Error::NotTheAccount)?.key();
        let dest = a.destination.as_ref().ok_or(TokenomicsV2Error::NotTheAccount)?;
        require_keys_eq!(mint.key(), t.rewards[i].token, TokenomicsV2Error::NotTheAccount);
        require_keys_eq!(*mint.owner, program, TokenomicsV2Error::NotTheAccount);
        pot_account(pot_token, &pot, &mint.key(), &program)?;
        // Any account of the holder's for the mint -- not only its associated one, which a holder
        // whose payouts were skipped (an account extension it enabled) cannot make again --
        // initialised, not frozen (`token_view`), carrying no extension but ImmutableOwner.
        let v = token_view(dest).ok_or(TokenomicsV2Error::NotTheAccount)?;
        require!(v.owner == holder && v.mint == mint.key() && *dest.owner == program && plain_account(dest), TokenomicsV2Error::NotTheAccount);
        transfer_out(&all, &program, &pot_token.key(), &mint.key(), &dest.key(), &pot, pot_seeds, due, mint_decimals(mint)?)?;
    }
    let r = &mut t.rewards[i];
    r.pot -= due;
    r.paid += due;
    // The pot still holds its books, to the unit (as pay_holders checks; audit round 2).
    let (booked_wsol, booked_pot, native) = (wsol_booked(r), r.pot, r.native());
    require!(balance(&a.pot_wsol)? >= booked_wsol, TokenomicsV2Error::Overflow);
    if let (Some(pt), false) = (a.pot_token.as_ref(), native) {
        require!(balance(pt)? >= booked_pot, TokenomicsV2Error::Overflow);
    }
    require!(balance(&a.vault_wsol)? >= t.tracked(), TokenomicsV2Error::Overflow);
    // A claim takes no fee: the holder pays its own transaction.
    emit!(HolderPaid { tokenomics: tk, index, holder, amount: due, cumulative, sent: due, fee: 0 });
    ctx.accounts.record.cumulative = cumulative;
    **ctx.accounts.tokenomics = t;
    Ok(())
}

// ------------------------------------------------------------------------------ recovery

#[derive(Accounts)]
#[instruction(index: u8)]
pub struct AdminRecover<'info> {
    #[account(mut, address = ADMIN @ TokenomicsV2Error::NotAdmin)]
    pub admin: Signer<'info>,
    #[account(mut)]
    pub tokenomics: Box<Account<'info, TokenomicsV2>>,
    /// CHECK: the main vault (`sync`, and refused as a source: what is in it is fees).
    #[account(mut)]
    pub vault_wsol: UncheckedAccount<'info>,
    /// CHECK: `PDA(["tk2-pot", tokenomics, [index]])`.
    #[account(mut, seeds = [TK2_POT_SEED, tokenomics.key().as_ref(), &[index]], bump)]
    pub pot: UncheckedAccount<'info>,
    /// CHECK: the pot's wrapped-SOL account (when `index` is an entry).
    #[account(mut)]
    pub pot_wsol: UncheckedAccount<'info>,
    /// CHECK: the token account the money leaves (by kind, checked in the handler).
    #[account(mut)]
    pub source: UncheckedAccount<'info>,
    /// CHECK: where it goes: any account of the mint (holders money), the owner's (unbooked).
    #[account(mut)]
    pub destination: UncheckedAccount<'info>,
    /// CHECK: the source's mint.
    pub mint: UncheckedAccount<'info>,
    /// CHECK: the source's token program.
    pub source_program: UncheckedAccount<'info>,
    /// CHECK: the account's owner (unbooked money's destination).
    #[account(mut, address = tokenomics.owner @ TokenomicsV2Error::NotTheRole)]
    pub owner: UncheckedAccount<'info>,
    /// CHECK: pinned.
    #[account(address = spl_token::ID)]
    pub token_program: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

/// The ADMIN, for stuck money:
///  - `RECOVER_POT` / `RECOVER_BUDGET`: `amount` of entry `index`'s pot / budget (holders money
///    only) to any token account of the mint the admin names (a stuck route, an unreachable holder);
///  - `RECOVER_UNBOOKED_TOKENS`: what a token account of the pot's or the main account's holds
///    beyond its books, to a token account of the owner's -- never the main vault's wrapped SOL or
///    any other wrapped SOL of the main account (fees: `sweep_tokenomics_v2_wsol`), never the coins
///    the account holds for liquidity or the treasury;
///  - `RECOVER_UNBOOKED_LAMPORTS`: lamports someone sent the pot's address, to the owner.
///
/// It never touches the burn, buy & hold or liquidity buckets, the wallets' accrued, or another
/// entry's pot or budget.
pub fn admin_recover_handler<'info>(ctx: Context<'_, '_, 'info, 'info, AdminRecover<'info>>, index: u8, kind: u8, amount: u64) -> Result<()> {
    let a = &ctx.accounts;
    let tk = a.tokenomics.key();
    let i = index as usize;
    let mut t: TokenomicsV2 = (**a.tokenomics).clone();
    let all = a.to_account_infos();
    let entry = i < t.num_rewards as usize;
    if entry {
        sync(&all, &mut t, tk, &a.vault_wsol, &a.pot_wsol, &a.pot.key(), i)?;
    }
    require!(amount > 0, TokenomicsV2Error::NothingDue);
    let pot = a.pot.key();
    let pot_seeds: &[&[u8]] = &[TK2_POT_SEED, tk.as_ref(), &[index], &[ctx.bumps.pot]];
    let (hash, bump) = (t.config_hash, [t.bump]);
    let tk_seeds: [&[u8]; 3] = [TOKENOMICS_V2_SEED, &hash, &bump];
    let (src, dst, mint, program) = (a.source.key(), a.destination.key(), a.mint.key(), a.source_program.key());
    match kind {
        RECOVER_POT | RECOVER_BUDGET => {
            require!(entry, TokenomicsV2Error::NoSuch);
            let r = t.rewards[i];
            let (book, account_mint, account_program) = match (kind, r.native()) {
                (RECOVER_POT, true) => (r.pot, spl_token::native_mint::ID, spl_token::ID),
                (RECOVER_POT, false) => (r.pot, r.token, *a.mint.owner),
                (_, false) => (r.budget, spl_token::native_mint::ID, spl_token::ID),
                (_, true) => return err!(TokenomicsV2Error::NoSuch),
            };
            require!(amount <= book, TokenomicsV2Error::PotExceeded);
            require_keys_eq!(mint, account_mint, TokenomicsV2Error::NotTheAccount);
            require_keys_eq!(program, account_program, TokenomicsV2Error::NotTheAccount);
            pot_account(&a.source, &pot, &mint, &program)?;
            transfer_out(&all, &program, &src, &mint, &dst, &pot, pot_seeds, amount, mint_decimals(&a.mint)?)?;
            let r = &mut t.rewards[i];
            if kind == RECOVER_POT {
                r.pot -= amount;
            } else {
                r.budget -= amount;
            }
        }
        RECOVER_UNBOOKED_TOKENS => {
            require_keys_eq!(*a.source.owner, program, TokenomicsV2Error::NotTheAccount);
            let v = token_view(&a.source).ok_or(TokenomicsV2Error::NotTheAccount)?;
            require_keys_eq!(v.mint, mint, TokenomicsV2Error::NotTheAccount);
            let d = token_view(&a.destination).ok_or(TokenomicsV2Error::NotTheAccount)?;
            require!(d.owner == t.owner && d.mint == mint, TokenomicsV2Error::NotTheAccount);
            let booked = if v.owner == tk {
                // Wrapped SOL of the main account's is fees; its position's NFT is the liquidity share's.
                require!(mint != spl_token::native_mint::ID && mint != t.lp_nft_mint, TokenomicsV2Error::Booked);
                if mint == t.mint && src == get_associated_token_address_with_program_id(&tk, &mint, &program) {
                    t.liquidity_coins + t.treasury_coins
                } else {
                    0
                }
            } else {
                require_keys_eq!(v.owner, pot, TokenomicsV2Error::NotTheAccount);
                let r = if entry { t.rewards[i] } else { RewardSlot::default() };
                if entry && mint == spl_token::native_mint::ID && src == a.pot_wsol.key() {
                    wsol_booked(&r)
                } else if entry && !r.native() && mint == r.token && src == get_associated_token_address_with_program_id(&pot, &mint, &program) {
                    r.pot
                } else {
                    0
                }
            };
            require!(amount <= v.amount.saturating_sub(booked), TokenomicsV2Error::Booked);
            let decimals = mint_decimals(&a.mint)?;
            if v.owner == tk {
                transfer_out(&all, &program, &src, &mint, &dst, &tk, &tk_seeds, amount, decimals)?;
            } else {
                transfer_out(&all, &program, &src, &mint, &dst, &pot, pot_seeds, amount, decimals)?;
            }
        }
        RECOVER_UNBOOKED_LAMPORTS => {
            require!(amount <= a.pot.lamports(), TokenomicsV2Error::Booked);
            let owner = a.owner.to_account_info();
            require!(*owner.owner == System::id() && owner.data_is_empty(), TokenomicsV2Error::NotTheRole);
            invoke_signed(&system_instruction::transfer(&pot, owner.key, amount), &all, &[pot_seeds])?;
        }
        _ => return err!(TokenomicsV2Error::NoSuch),
    }
    emit!(Recovered { tokenomics: tk, index, kind, from: src, to: dst, amount });
    if entry {
        let r = t.rewards[i];
        require!(balance(&a.pot_wsol)? >= wsol_booked(&r), TokenomicsV2Error::Overflow);
    }
    require!(balance(&a.vault_wsol)? >= t.tracked(), TokenomicsV2Error::Overflow);
    **ctx.accounts.tokenomics = t;
    Ok(())
}
