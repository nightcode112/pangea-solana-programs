//! Tokenomics v2.3: an account whose launch pairs against an allow-listed quote asset (a tokenized
//! stock) rather than wrapped SOL.
//!
//! THE QUOTE IS A TAIL, NOT A FIELD. `TokenomicsV2` keeps its layout byte for byte: every account
//! made before v2.3 (all paired against wrapped SOL) is read and written as it was. An account
//! made by `init_tokenomics_v2` from v2.3 on is `QUOTE_TAIL_LEN` bytes longer; `bind_tokenomics_v2`
//! writes the launch's quote mint and its token program there (`write_quote`) when the launch is
//! not paired against wrapped SOL -- growing an older, shorter account when it has to, at the
//! binder's rent. Anchor reads the struct off the front and writes it back there, so the tail is
//! never touched by anything but the bind. A short account, or a zero tail, is wrapped SOL.
//!
//! What changes for a quote-asset account (`QuoteOf::native` false):
//!  * the vault is the account's associated account for the quote mint under its token program
//!    (`QuoteOf::vault`) -- for wrapped SOL the same address as ever;
//!  * buckets, wallets' accrued and reward entries are in the quote's base units;
//!  * the buys swap the quote into the coin through the coin's own pool (it IS the pool's token B);
//!  * the wallets, a native ("SOL") reward entry and the operator are paid in the quote asset,
//!    into a token account of the quote mint of theirs (`payable`), never as lamports;
//!  * the operator's repayment -- worked out in lamports from the transaction, as ever -- is
//!    converted at the ADMIN's rate for the asset (`Tk2QuoteRate`, `to_quote`), and held to the
//!    same cap of what the run pays out, in the quote; with no rate set nobody is repaid, and the
//!    admin's minimum (lamports) is converted the same way (0 without a rate).

use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::invoke_signed;
use anchor_spl::associated_token::get_associated_token_address_with_program_id;
use anchor_spl::token::spl_token;

use super::state::*;
use crate::ADMIN;

/// The tail: the quote mint (32) then its token program (32).
pub const QUOTE_TAIL_LEN: usize = 64;

/// The struct's bytes with its discriminator.
pub const fn base_len() -> usize {
    8 + TokenomicsV2::INIT_SPACE
}

/// The size `init_tokenomics_v2` makes an account at from v2.3 on.
pub const fn full_len() -> usize {
    base_len() + QUOTE_TAIL_LEN
}

/// The asset an account's fees, buckets and payouts are in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuoteOf {
    pub mint: Pubkey,
    pub program: Pubkey,
}

impl QuoteOf {
    pub const NATIVE: QuoteOf = QuoteOf { mint: spl_token::native_mint::ID, program: spl_token::ID };

    pub fn native(&self) -> bool {
        self.mint == spl_token::native_mint::ID
    }

    /// The account's vault: its associated account for the quote mint.
    pub fn vault(&self, tk: &Pubkey) -> Pubkey {
        get_associated_token_address_with_program_id(tk, &self.mint, &self.program)
    }

    /// `owner`'s associated account for the quote mint.
    pub fn ata(&self, owner: &Pubkey) -> Pubkey {
        get_associated_token_address_with_program_id(owner, &self.mint, &self.program)
    }
}

/// The quote of a v2 account, from its tail: wrapped SOL for an account with none (made before
/// v2.3) or a zero one.
pub fn quote_of(tk: &AccountInfo) -> QuoteOf {
    let Ok(d) = tk.try_borrow_data() else { return QuoteOf::NATIVE };
    if d.len() < full_len() {
        return QuoteOf::NATIVE;
    }
    let at = base_len();
    let mint = Pubkey::new_from_array(d[at..at + 32].try_into().unwrap());
    let program = Pubkey::new_from_array(d[at + 32..at + 64].try_into().unwrap());
    if mint == Pubkey::default() {
        return QuoteOf::NATIVE;
    }
    QuoteOf { mint, program }
}

/// The vault address of the account at `tk` (for the Accounts constraints).
pub fn vault_of(tk: &AccountInfo) -> Pubkey {
    quote_of(tk).vault(tk.key)
}

/// Write the quote into the tail, growing the account to `full_len` first when it is shorter
/// (an account made before v2.3), `payer` putting up the rent the growth needs.
pub fn write_quote<'info>(tk: &AccountInfo<'info>, payer: &AccountInfo<'info>, system: &AccountInfo<'info>, q: &QuoteOf) -> Result<()> {
    if tk.data_len() < full_len() {
        let rent = Rent::get()?.minimum_balance(full_len());
        let short = rent.saturating_sub(tk.lamports());
        if short > 0 {
            anchor_lang::solana_program::program::invoke(
                &anchor_lang::solana_program::system_instruction::transfer(payer.key, tk.key, short),
                &[payer.clone(), tk.clone(), system.clone()],
            )?;
        }
        tk.realloc(full_len(), true)?;
    }
    let mut d = tk.try_borrow_mut_data()?;
    let at = base_len();
    d[at..at + 32].copy_from_slice(q.mint.as_ref());
    d[at + 32..at + 64].copy_from_slice(q.program.as_ref());
    Ok(())
}

/// A mint's decimals, from its account (either token program).
pub fn decimals_of(mint: &AccountInfo) -> Result<u8> {
    require!(*mint.owner == spl_token::ID || *mint.owner == anchor_spl::token_2022::ID, TokenomicsV2Error::NotTheAccount);
    let d = mint.try_borrow_data()?;
    require!(d.len() >= 82 && d[45] == 1, TokenomicsV2Error::NotTheAccount);
    Ok(d[44])
}

/// The quote's decimals: 9 for wrapped SOL, else read off its mint among `all`.
pub fn quote_decimals(all: &[AccountInfo], q: &QuoteOf) -> Result<u8> {
    if q.native() {
        return Ok(9);
    }
    let mint = all.iter().find(|a| *a.key == q.mint).ok_or(TokenomicsV2Error::NotTheAccount)?;
    decimals_of(mint)
}

/// A checked transfer of the quote out of an account `authority` (a PDA of this program) owns.
#[allow(clippy::too_many_arguments)]
pub fn send_quote<'info>(all: &[AccountInfo<'info>], q: &QuoteOf, from: &Pubkey, to: &Pubkey, authority: &Pubkey, seeds: &[&[u8]], amount: u64, decimals: u8) -> Result<()> {
    if amount == 0 {
        return Ok(());
    }
    let ix = if q.program == spl_token::ID {
        spl_token::instruction::transfer_checked(&q.program, from, &q.mint, to, authority, &[], amount, decimals)?
    } else {
        anchor_spl::token_2022::spl_token_2022::instruction::transfer_checked(&q.program, from, &q.mint, to, authority, &[], amount, decimals)?
    };
    invoke_signed(&ix, all, &[seeds])?;
    Ok(())
}

/// Token-2022 account extensions a quote-asset payout may meet: ImmutableOwner (every associated
/// account), TransferHookAccount and PausableAccount (every account of an xStock: one flag each,
/// written by the token program, never by the holder). Anything the holder enables -- a memo
/// requirement, a CPI guard, confidential-only credits -- is refused, so no holder can revert a batch.
const EXT_IMMUTABLE_OWNER: u16 = 7;
const EXT_TRANSFER_HOOK_ACCOUNT: u16 = 15;
const EXT_PAUSABLE_ACCOUNT: u16 = 27;

fn account_extensions(d: &[u8]) -> Option<Vec<u16>> {
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

/// Whether `account` can be paid the quote for `owner` now: an initialised (not frozen) account of
/// the quote mint under its program, `owner`'s, writable, with no extension its holder enabled.
pub fn payable(account: &AccountInfo, owner: &Pubkey, q: &QuoteOf) -> bool {
    if *account.owner != q.program || !account.is_writable {
        return false;
    }
    let Ok(d) = account.try_borrow_data() else { return false };
    if d.len() < 165 || d[108] != 1 {
        return false;
    }
    let key = |at: usize| Pubkey::new_from_array(d[at..at + 32].try_into().unwrap());
    key(0) == q.mint
        && key(32) == *owner
        && account_extensions(&d).is_some_and(|x| x.iter().all(|k| [EXT_IMMUTABLE_OWNER, EXT_TRANSFER_HOOK_ACCOUNT, EXT_PAUSABLE_ACCOUNT].contains(k)))
}

// ------------------------------------------------------------------------------ the rate

/// `PDA(["tk2-rate", mint])`: the ADMIN's rate for a quote asset, which converts what a run cost in
/// lamports into the asset (the operator's repayment, a holder payout's fee cap, the minimum).
pub const TK2_RATE_SEED: &[u8] = b"tk2-rate";

#[account]
#[derive(InitSpace)]
pub struct Tk2QuoteRate {
    pub bump: u8,
    pub mint: Pubkey,
    /// Base units of the asset one SOL (1e9 lamports) is worth. 0: no conversion (nobody repaid).
    pub quote_per_sol: u64,
    pub set_at: i64,
}

pub fn rate_address(mint: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[TK2_RATE_SEED, mint.as_ref()], &crate::ID).0
}

/// The rate for `mint` from `account` (`PDA(["tk2-rate", mint])`): 0 while it does not exist or
/// none was given; anything else at that address is refused.
pub fn rate_of(account: Option<&AccountInfo>, mint: &Pubkey) -> Result<u64> {
    let Some(a) = account else { return Ok(0) };
    require_keys_eq!(a.key(), rate_address(mint), TokenomicsV2Error::NotTheAccount);
    if a.data_is_empty() && *a.owner == anchor_lang::system_program::ID {
        return Ok(0);
    }
    require_keys_eq!(*a.owner, crate::ID, TokenomicsV2Error::NotTheAccount);
    let r = Tk2QuoteRate::try_deserialize(&mut &a.try_borrow_data()?[..]).map_err(|_| error!(TokenomicsV2Error::NotTheAccount))?;
    require_keys_eq!(r.mint, *mint, TokenomicsV2Error::NotTheAccount);
    Ok(r.quote_per_sol)
}

/// `lamports` in the asset at `rate` (base units per SOL), rounded down.
pub fn to_quote(lamports: u64, rate: u64) -> u64 {
    ((lamports as u128 * rate as u128) / 1_000_000_000u128).min(u64::MAX as u128) as u64
}

#[derive(Accounts)]
#[instruction(quote_per_sol: u64)]
pub struct SetTk2QuoteRate<'info> {
    #[account(mut, address = ADMIN @ TokenomicsV2Error::NotAdmin)]
    pub admin: Signer<'info>,
    /// CHECK: the asset's mint (either token program).
    pub mint: UncheckedAccount<'info>,
    #[account(init_if_needed, payer = admin, space = 8 + Tk2QuoteRate::INIT_SPACE, seeds = [TK2_RATE_SEED, mint.key().as_ref()], bump)]
    pub rate: Account<'info, Tk2QuoteRate>,
    pub system_program: Program<'info, System>,
}

#[event]
pub struct QuoteRateSet {
    pub mint: Pubkey,
    pub quote_per_sol: u64,
}

/// ADMIN: the asset's rate (base units per SOL), 0 to stop conversions. Never wrapped SOL's.
pub fn set_tk2_quote_rate_handler(ctx: Context<SetTk2QuoteRate>, quote_per_sol: u64) -> Result<()> {
    let mint = ctx.accounts.mint.key();
    require_keys_neq!(mint, spl_token::native_mint::ID, TokenomicsV2Error::BadConfig);
    decimals_of(&ctx.accounts.mint)?;
    let r = &mut ctx.accounts.rate;
    r.bump = ctx.bumps.rate;
    r.mint = mint;
    r.quote_per_sol = quote_per_sol;
    r.set_at = Clock::get()?.unix_timestamp;
    emit!(QuoteRateSet { mint, quote_per_sol });
    Ok(())
}

/// What a quote-asset instruction is given beyond its named accounts, first among its remaining
/// accounts: the rate, then the caller's (or operator's) account for the asset, where its
/// repayment goes. Both optional at the end of the list (no rate: nobody is repaid).
pub struct QuoteExtras<'a, 'info> {
    pub rate: u64,
    pub repay_to: Option<&'a AccountInfo<'info>>,
}

pub fn quote_extras<'a, 'info>(rest: &'a [AccountInfo<'info>], q: &QuoteOf) -> Result<QuoteExtras<'a, 'info>> {
    Ok(QuoteExtras { rate: rate_of(rest.first(), &q.mint)?, repay_to: rest.get(1) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tail_follows_the_struct() {
        assert_eq!(full_len(), base_len() + 64);
        assert_eq!(to_quote(1_000_000_000, 87_000_000), 87_000_000);
        assert_eq!(to_quote(5_000, 87_000_000), 435);
        assert_eq!(to_quote(u64::MAX, u64::MAX), u64::MAX);
    }
}
