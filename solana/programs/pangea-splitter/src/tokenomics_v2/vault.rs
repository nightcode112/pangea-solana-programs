//! The v2 account's life outside the holders pot: init, bind, forwarding, the liquidity position,
//! execute (burn, buy & hold, liquidity -- v1's run), the wallets (credited at allocation, paid by
//! the `pay_tokenomics_wallets` crank or claimed by themselves), roles and eligibility.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    incinerator,
    instruction::{get_stack_height, AccountMeta, TRANSACTION_LEVEL_STACK_HEIGHT},
    program::invoke_signed,
    sysvar::instructions as ixs,
};
use anchor_spl::associated_token::{self, get_associated_token_address_with_program_id, AssociatedToken};
use anchor_spl::token::spl_token;
use anchor_spl::token_2022::Token2022;

use super::config::*;
use super::quote_asset::*;
use super::state::*;
use crate::tokenomics::{
    balance, buy_stage, declared_priority, ensure_coin_account, ro, rw, send, send_coins, skipped, takes_sol, token_account, unwrap_to,
    writable_or_reserved, BuyAccounts, BuyBooks, Run, TokenomicsError, TokenomicsForwarded, TokenomicsPositionRepaid, TokenomicsReimbursed,
    TokenomicsRoleChanged, TokenomicsRoleProposed, TokenomicsSentToTreasury, TokenomicsSpent, BPS, COMPUTE_BUDGET_ID, CREATE_POSITION_DISCRIMINATOR,
    MAX_POSITION_REPAY_LAMPORTS, POOL_AUTHORITY, ROLE_OWNER, ROLE_TREASURY, SIGNATURE_LAMPORTS,
    TK_LP_SEED, TK_TEMP_SEED,
};
use crate::{launch_id_of, read_pool, read_position, LaunchRecord, ADMIN, CP_AMM_ID, POSITION_SEED, SPLITTER_SEED, TOKEN_A_SEED};

// ------------------------------------------------------------------------------ helpers

/// This instruction runs at the top level, and is the transaction's only one that repays its
/// caller's fee (v1's and v2's execute, the wallets' crank, holder payouts): the fee is the
/// transaction's, repaid once. `strict` (execute): every top-level instruction is a compute-budget
/// instruction, this program's or the associated-token program's, as v1's `execute` requires --
/// nothing in the transaction can move the pool's price first.
pub fn once_at_top(instructions: &AccountInfo, strict: bool) -> Result<()> {
    use anchor_lang::Discriminator;
    require!(get_stack_height() == TRANSACTION_LEVEL_STACK_HEIGHT, TokenomicsV2Error::NotAlone);
    let repaid = [
        crate::instruction::ExecuteTokenomics::DISCRIMINATOR,
        crate::instruction::ExecuteTokenomicsV2::DISCRIMINATOR,
        crate::instruction::PayTokenomicsWallets::DISCRIMINATOR,
        crate::instruction::PayTokenomicsHolders::DISCRIMINATOR,
    ];
    let count = {
        let d = instructions.try_borrow_data()?;
        u16::from_le_bytes(d.get(..2).and_then(|b| b.try_into().ok()).ok_or(TokenomicsV2Error::NotAlone)?) as usize
    };
    let mut n = 0usize;
    for i in 0..count {
        let ix = ixs::load_instruction_at_checked(i, instructions)?;
        if strict {
            require!(
                ix.program_id == COMPUTE_BUDGET_ID || ix.program_id == crate::ID || ix.program_id == associated_token::ID,
                TokenomicsV2Error::NotAlone
            );
        }
        if ix.program_id == crate::ID && ix.data.len() >= 8 && repaid.iter().any(|d| ix.data[..8] == d[..]) {
            n += 1;
        }
    }
    require!(n <= 1, TokenomicsV2Error::NotAlone);
    Ok(())
}

/// Move `lamports` from the program-owned `from` into the wrapped-SOL account `vault` and have the
/// token program count them: v1 `init_tokenomics`'s way (a zero transfer from `payer`, a signer,
/// with both sides riding along, then `sync_native`).
fn lamports_into_vault<'info>(from: &AccountInfo<'info>, vault: &AccountInfo<'info>, payer: &AccountInfo<'info>, system: &AccountInfo<'info>, token: &AccountInfo<'info>, lamports: u64) -> Result<()> {
    if lamports == 0 {
        return Ok(());
    }
    **from.try_borrow_mut_lamports()? -= lamports;
    **vault.try_borrow_mut_lamports()? += lamports;
    let mut both_sides = anchor_lang::solana_program::system_instruction::transfer(payer.key, vault.key, 0);
    both_sides.accounts.push(AccountMeta::new(from.key(), false));
    invoke_signed(&both_sides, &[payer.clone(), vault.clone(), from.clone(), system.clone()], &[])?;
    let count = spl_token::instruction::sync_native(&spl_token::ID, vault.key)?;
    invoke_signed(&count, &[vault.clone(), token.clone()], &[])?;
    Ok(())
}

// ------------------------------------------------------------------------------ init

#[derive(Accounts)]
#[instruction(config: TokenomicsConfigV2)]
pub struct InitTokenomicsV2<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    /// `PDA(["tokenomics-v2", configHash])`, configHash recomputed here from the config. Made with
    /// the quote tail (`quote_asset`), zero (wrapped SOL) until the bind writes it.
    #[account(init, payer = payer, space = full_len(), seeds = [TOKENOMICS_V2_SEED, config.hash().as_ref()], bump)]
    pub tokenomics: Box<Account<'info, TokenomicsV2>>,
    pub system_program: Program<'info, System>,
}

/// The account, from the launch-wide config and the Solana leg (ignored, and the fallback used,
/// when the config has no Solana leg). Its wrapped-SOL vault is made at the bind, not here: the
/// largest config (8 legs, 10 wallets, 5 reward tokens) fills a transaction with this
/// instruction's data alone.
pub fn init_v2_handler(ctx: Context<InitTokenomicsV2>, config: TokenomicsConfigV2, leg: TokenomicsLegV2) -> Result<()> {
    let leg = solana_leg(&config, &leg)?;
    let key = ctx.accounts.tokenomics.key();
    let owner = Pubkey::new_from_array(config.owner_sol);
    check_keys(&owner, &leg, &key)?;
    let rent = Rent::get()?.minimum_balance(ctx.accounts.tokenomics.to_account_info().data_len());
    let held = ctx.accounts.tokenomics.to_account_info().lamports();
    let t = &mut ctx.accounts.tokenomics;
    t.version = 2;
    t.bump = ctx.bumps.tokenomics;
    t.config_hash = config.hash();
    t.launch_id = config.launch_id;
    t.owner = owner;
    t.treasury = Pubkey::new_from_array(leg.treasury);
    t.bps = [leg.burn_bps, leg.buy_hold_bps, leg.liquidity_bps, leg.holders_bps];
    t.num_wallets = leg.wallets.len() as u8;
    for (i, w) in leg.wallets.iter().enumerate() {
        t.wallets[i] = WalletSlot { key: Pubkey::new_from_array(*w), bps: leg.wallet_bps[i], ..Default::default() };
    }
    t.num_rewards = leg.reward_tokens.len() as u8;
    for (i, r) in leg.reward_tokens.iter().enumerate() {
        t.rewards[i] = RewardSlot { token: Pubkey::new_from_array(*r), bps: leg.reward_bps[i], ..Default::default() };
    }
    t.min_holder_bps = config.min_holder_bps;
    t.select_mode = config.select_mode;
    t.select_count = config.select_count;
    t.created_at = Clock::get()?.unix_timestamp;
    // LAMPORTS THAT WERE HERE BEFORE THE ACCOUNT ARE FEES (v1 audit round 7, L): a payee no program
    // owned was paid raw lamports. Kept apart from the owner's refunds and moved into the vault at the bind.
    t.prefunded = held.saturating_sub(rent);
    emit!(TokenomicsV2Created { tokenomics: key, config_hash: t.config_hash, launch_id: t.launch_id, owner });
    Ok(())
}

// ------------------------------------------------------------------------------ bind

#[derive(Accounts)]
#[instruction(launch_seed: [u8; 32])]
pub struct BindTokenomicsV2<'info> {
    /// Anyone; pays for the vault and the coin accounts.
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut)]
    pub tokenomics: Box<Account<'info, TokenomicsV2>>,
    /// CHECK: `PDA(["position", seed])`.
    #[account(seeds = [POSITION_SEED, launch_seed.as_ref()], bump)]
    pub position_nft_mint: UncheckedAccount<'info>,
    #[account(seeds = [SPLITTER_SEED, position_nft_mint.key().as_ref()], bump = record.bump)]
    pub record: Box<Account<'info, LaunchRecord>>,
    /// CHECK: the launch's position, from its record.
    #[account(address = record.position @ TokenomicsError::NotItsLaunch)]
    pub position: UncheckedAccount<'info>,
    /// CHECK: the position's pool, checked in the handler.
    pub pool: UncheckedAccount<'info>,
    /// CHECK: the coin: the pool's token A (checked in the handler), a Token-2022 mint.
    #[account(owner = anchor_spl::token_2022::ID @ TokenomicsV2Error::NotTheAccount)]
    pub mint: UncheckedAccount<'info>,
    /// CHECK: the account's associated coin account, made here if missing.
    #[account(mut)]
    pub vault_coin: UncheckedAccount<'info>,
    /// CHECK: where the fees land (`fees::tokenomics_vault`, `fees::claim_fees`): the account's
    /// associated account for the launch's quote asset -- wrapped SOL, or the allow-listed asset the
    /// launch pairs against (v2.3) -- made here if missing, never closed.
    #[account(mut, address = get_associated_token_address_with_program_id(&tokenomics.key(), &record.quote_mint, &token_program.key()) @ TokenomicsV2Error::NotTheAccount)]
    pub vault_wsol: UncheckedAccount<'info>,
    /// CHECK: the launch's quote mint (wrapped SOL's for a SOL launch).
    #[account(address = record.quote_mint @ TokenomicsError::NotItsLaunch)]
    pub wsol_mint: UncheckedAccount<'info>,
    /// CHECK: the treasury.
    #[account(address = tokenomics.treasury @ TokenomicsV2Error::NotTheRole)]
    pub treasury: UncheckedAccount<'info>,
    /// CHECK: its associated coin account (`ensure_coin_account`).
    #[account(mut)]
    pub treasury_coin: UncheckedAccount<'info>,
    /// CHECK: pinned.
    #[account(address = incinerator::ID)]
    pub incinerator: UncheckedAccount<'info>,
    /// CHECK: its associated coin account.
    #[account(mut)]
    pub incinerator_coin: UncheckedAccount<'info>,
    /// CHECK: the quote mint's token program (its owner): the token program for wrapped SOL.
    #[account(address = *wsol_mint.owner @ TokenomicsV2Error::NotTheAccount)]
    pub token_program: UncheckedAccount<'info>,
    pub token_2022_program: Program<'info, Token2022>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

pub fn bind_v2_handler(ctx: Context<BindTokenomicsV2>, launch_seed: [u8; 32]) -> Result<()> {
    let a = &ctx.accounts;
    let key = a.tokenomics.key();
    require!(!a.tokenomics.bound, TokenomicsError::AlreadyBound);
    require!(launch_id_of(&launch_seed) == a.tokenomics.launch_id, TokenomicsError::NotItsLaunch);
    require_keys_eq!(a.record.creator, key, TokenomicsError::NotItsLaunch);
    // The launch's quote: wrapped SOL, or the allow-listed asset it pairs against (v2.3). The record
    // is this program's and was written by a launch that checked the asset against the allowlist;
    // here only what would stop the account's own transfers is checked again: an asset that has
    // since gained a transfer-hook program, or carries an extension a launch cannot live with.
    let quote = QuoteOf { mint: a.record.quote_mint, program: a.token_program.key() };
    require!(quote.program == spl_token::ID || quote.program == anchor_spl::token_2022::ID, TokenomicsV2Error::NotTheAccount);
    if !quote.native() {
        let m = crate::inspect_mint(a.wsol_mint.owner, &a.wsol_mint.try_borrow_data()?).ok_or(TokenomicsError::NotItsLaunch)?;
        require!(!m.unsupported && !m.hook_program, TokenomicsError::NotItsLaunch);
        // A reward entry of the quote itself would share its pot's one quote account between the
        // entry's budget and its pot (the rule `check_keys` holds wrapped SOL to).
        let n = a.tokenomics.num_rewards as usize;
        require!(a.tokenomics.rewards[..n].iter().all(|r| r.token != quote.mint), TokenomicsV2Error::BadConfig);
    }
    require_keys_eq!(*a.position.owner, CP_AMM_ID, TokenomicsError::NotThePool);
    let (position_pool, _) = read_position(&a.position.try_borrow_data()?).ok_or(TokenomicsError::NotThePool)?;
    require_keys_eq!(position_pool, a.pool.key(), TokenomicsError::NotThePool);
    require_keys_eq!(*a.pool.owner, CP_AMM_ID, TokenomicsError::NotThePool);
    let [(mint_a, _), (mint_b, _)] = read_pool(&a.pool.try_borrow_data()?).ok_or(TokenomicsError::NotThePool)?;
    require_keys_eq!(mint_a, a.mint.key(), TokenomicsError::NotThePool);
    require_keys_eq!(mint_b, quote.mint, TokenomicsError::NotThePool);
    let slice = Pubkey::find_program_address(&[TOKEN_A_SEED, launch_seed.as_ref()], &crate::ID).0;
    let all = a.to_account_infos();
    let payer = a.payer.key();
    ensure_coin_account(&all, &payer, &a.vault_coin, &key, &a.mint.key())?;
    crate::tokenomics_v2::holders::create_ata(&all, &payer, &a.vault_wsol.key(), &key, &quote.mint, &quote.program)?;
    if a.tokenomics.bps[V2_BURN] != 0 {
        ensure_coin_account(&all, &payer, &a.incinerator_coin, &incinerator::ID, &a.mint.key())?;
    }
    if a.tokenomics.bps[V2_BUYBACK] != 0 {
        ensure_coin_account(&all, &payer, &a.treasury_coin, &a.tokenomics.treasury, &a.mint.key())?;
    }
    let tk_info = a.tokenomics.to_account_info();
    if quote.native() {
        // The lamports that were at the address before the account: fees, into the vault.
        let prefunded = a.tokenomics.prefunded;
        let vault = a.vault_wsol.to_account_info();
        lamports_into_vault(&tk_info, &vault, &a.payer.to_account_info(), &a.system_program.to_account_info(), &a.token_program.to_account_info(), prefunded)?;
    } else {
        // An asset launch's fees are the asset: lamports somebody sent the address are not, and
        // `forward_tokenomics_v2_refund` hands them to the owner from here on (prefunded is cleared).
        write_quote(&tk_info, &a.payer.to_account_info(), &a.system_program.to_account_info(), &quote)?;
    }
    let record = a.record.key();
    let (mint, pool) = (a.mint.key(), a.pool.key());
    let t = &mut ctx.accounts.tokenomics;
    t.prefunded = 0;
    t.bound = true;
    t.mint = mint;
    t.pool = pool;
    t.record = record;
    t.slice = slice;
    emit!(TokenomicsV2Bound { tokenomics: key, mint, pool, record });
    Ok(())
}

// ------------------------------------------------------------------------------ forwarding

#[derive(Accounts)]
pub struct ForwardRefundV2<'info> {
    #[account(mut)]
    pub tokenomics: Box<Account<'info, TokenomicsV2>>,
    /// CHECK: the owner's wallet.
    #[account(mut, address = tokenomics.owner @ TokenomicsV2Error::NotTheRole)]
    pub owner: UncheckedAccount<'info>,
}

/// v1's `forward_tokenomics_refund`: every lamport above the rent -- and above lamports that were
/// there before the account (fees, `prefunded`, until the bind moves them) -- to the owner.
pub fn forward_refund_v2_handler(ctx: Context<ForwardRefundV2>) -> Result<()> {
    let tk = ctx.accounts.tokenomics.to_account_info();
    let owner = ctx.accounts.owner.to_account_info();
    let keep = Rent::get()?.minimum_balance(tk.data_len()) + ctx.accounts.tokenomics.prefunded;
    let extra = tk.lamports().saturating_sub(keep);
    require!(extra > 0, TokenomicsError::NothingToClaim);
    let rent_ok = owner.lamports().saturating_add(extra) >= Rent::get()?.minimum_balance(owner.data_len());
    require!(takes_sol(&owner, extra)? || (owner.is_signer && !owner.executable && rent_ok), TokenomicsV2Error::NotTheRole);
    **tk.try_borrow_mut_lamports()? -= extra;
    **owner.try_borrow_mut_lamports()? += extra;
    emit!(TokenomicsForwarded { tokenomics: tk.key(), to: owner.key(), lamports: extra, coins: 0 });
    Ok(())
}

#[derive(Accounts)]
pub struct ForwardCoinsV2<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, constraint = tokenomics.bound @ TokenomicsError::NotBound)]
    pub tokenomics: Box<Account<'info, TokenomicsV2>>,
    /// CHECK: the owner's wallet.
    #[account(address = tokenomics.owner @ TokenomicsV2Error::NotTheRole)]
    pub owner: UncheckedAccount<'info>,
    /// CHECK: the owner's associated coin account, made if missing.
    #[account(mut)]
    pub owner_coin: UncheckedAccount<'info>,
    /// CHECK: the launch's slice account.
    #[account(mut, address = tokenomics.slice @ TokenomicsV2Error::NotTheAccount)]
    pub slice: UncheckedAccount<'info>,
    /// CHECK: the account's associated coin account.
    #[account(mut)]
    pub vault_coin: UncheckedAccount<'info>,
    /// CHECK: the coin.
    #[account(address = tokenomics.mint @ TokenomicsV2Error::NotTheAccount)]
    pub mint: UncheckedAccount<'info>,
    pub token_2022_program: Program<'info, Token2022>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

/// v1's `forward_tokenomics_coins`.
pub fn forward_coins_v2_handler<'info>(ctx: Context<'_, '_, 'info, 'info, ForwardCoinsV2<'info>>) -> Result<()> {
    let all = ctx.accounts.to_account_infos();
    let a = &ctx.accounts;
    let t = &a.tokenomics;
    let tk = t.key();
    let (hash, bump) = (t.config_hash, [t.bump]);
    let seeds: [&[u8]; 3] = [TOKENOMICS_V2_SEED, &hash, &bump];
    let mint = t.mint;
    require_keys_eq!(a.vault_coin.key(), get_associated_token_address_with_program_id(&tk, &mint, &anchor_spl::token_2022::ID), TokenomicsV2Error::NotTheAccount);
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
pub struct OpenLpPositionV2<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, constraint = tokenomics.bound @ TokenomicsError::NotBound)]
    pub tokenomics: Box<Account<'info, TokenomicsV2>>,
    /// CHECK: `PDA(["tk-lp", tokenomics])`.
    #[account(mut, seeds = [TK_LP_SEED, tokenomics.key().as_ref()], bump)]
    pub lp_nft_mint: UncheckedAccount<'info>,
    /// CHECK: cp-amm checks it.
    #[account(mut)]
    pub lp_nft_account: UncheckedAccount<'info>,
    /// CHECK: cp-amm checks it.
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
    /// CHECK: the account's vault (its quote's associated account: wrapped SOL's, or the asset's).
    #[account(mut, address = vault_of(&tokenomics.to_account_info()) @ TokenomicsV2Error::NotTheAccount)]
    pub vault_wsol: UncheckedAccount<'info>,
    /// CHECK: `PDA(["tk-temp", tokenomics])`.
    #[account(mut, seeds = [TK_TEMP_SEED, tokenomics.key().as_ref()], bump)]
    pub temp: UncheckedAccount<'info>,
    /// CHECK: the quote's token program.
    #[account(address = quote_of(&tokenomics.to_account_info()).program @ TokenomicsV2Error::NotTheAccount)]
    pub token_program: UncheckedAccount<'info>,
    /// CHECK: the quote mint.
    #[account(address = quote_of(&tokenomics.to_account_info()).mint @ TokenomicsV2Error::NotTheAccount)]
    pub wsol_mint: UncheckedAccount<'info>,
    // A quote-asset account (v2.3), optionally: `PDA(["tk2-rate", mint])` and the opener's own
    // account for the asset (`quote_extras`), for the repayment in the asset.
}

/// v1's `open_tokenomics_position`: the opener fronts the position's rent and is repaid it out of
/// the liquidity bucket, capped. A quote-asset account repays it in the asset, at the ADMIN's rate,
/// into the opener's own account for it (nothing without a rate or an account that can take it).
pub fn open_lp_position_v2_handler<'info>(ctx: Context<'_, '_, 'info, 'info, OpenLpPositionV2<'info>>) -> Result<()> {
    require!(ctx.accounts.tokenomics.lp_position == Pubkey::default(), TokenomicsError::PositionOpen);
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
    let rent = fronted_from.saturating_sub(a.payer.lamports());
    let mut t: TokenomicsV2 = (**a.tokenomics).clone();
    allocate_v2(&mut t, tk, balance(&a.vault_wsol)?);
    let quote = quote_of(&a.tokenomics.to_account_info());
    let mut all = all;
    all.extend_from_slice(ctx.remaining_accounts);
    // A quote-asset account: the rent in the asset, at the rate, into the opener's own account.
    let (repay, to) = if quote.native() {
        (rent.min(MAX_POSITION_REPAY_LAMPORTS), None)
    } else {
        let x = quote_extras(ctx.remaining_accounts, &quote)?;
        match x.repay_to.filter(|d| payable(d, &a.payer.key(), &quote)) {
            Some(d) => (to_quote(rent.min(MAX_POSITION_REPAY_LAMPORTS), x.rate), Some(d.key())),
            None => (0, None),
        }
    };
    let repay = repay.min(t.buckets[V2_LIQUIDITY]);
    if repay > 0 {
        t.buckets[V2_LIQUIDITY] -= repay;
        t.spent[V2_LIQUIDITY] = t.spent[V2_LIQUIDITY].saturating_add(repay);
        t.reimbursed = t.reimbursed.saturating_add(repay);
        let (hash, bump) = (t.config_hash, [t.bump]);
        let seeds: [&[u8]; 3] = [TOKENOMICS_V2_SEED, &hash, &bump];
        let tk_info = a.tokenomics.to_account_info();
        let payer = a.payer.to_account_info();
        match to {
            None => unwrap_to(&all, &payer, &a.temp, ctx.bumps.temp, &tk_info, &seeds, &a.vault_wsol, repay)?,
            Some(to) => send_quote(&all, &quote, &a.vault_wsol.key(), &to, &tk, &seeds, repay, quote_decimals(&all, &quote)?)?,
        }
    }
    emit!(TokenomicsPositionRepaid { tokenomics: tk, opener: a.payer.key(), rent, lamports: repay });
    t.lp_position = position;
    t.lp_nft_mint = nft;
    require!(balance(&a.vault_wsol)? >= t.tracked(), TokenomicsError::Overflow);
    **ctx.accounts.tokenomics = t;
    Ok(())
}

#[derive(Accounts)]
pub struct ClaimLpFeesV2<'info> {
    #[account(mut, constraint = tokenomics.bound @ TokenomicsError::NotBound)]
    pub tokenomics: Box<Account<'info, TokenomicsV2>>,
    /// CHECK: the account's position.
    #[account(mut, address = tokenomics.lp_position @ TokenomicsV2Error::NotTheAccount)]
    pub lp_position: UncheckedAccount<'info>,
    /// CHECK: cp-amm checks it.
    pub lp_nft_account: UncheckedAccount<'info>,
    /// CHECK: the pool.
    #[account(address = tokenomics.pool @ TokenomicsError::NotThePool)]
    pub pool: UncheckedAccount<'info>,
    /// CHECK: cp-amm's.
    #[account(address = POOL_AUTHORITY)]
    pub pool_authority: UncheckedAccount<'info>,
    /// CHECK: the account's coin account.
    #[account(mut)]
    pub vault_coin: UncheckedAccount<'info>,
    /// CHECK: the account's wrapped-SOL account.
    #[account(mut)]
    pub vault_wsol: UncheckedAccount<'info>,
    /// CHECK: cp-amm checks them.
    #[account(mut)]
    pub token_a_vault: UncheckedAccount<'info>,
    /// CHECK: as above.
    #[account(mut)]
    pub token_b_vault: UncheckedAccount<'info>,
    /// CHECK: the coin.
    #[account(address = tokenomics.mint @ TokenomicsV2Error::NotTheAccount)]
    pub mint: UncheckedAccount<'info>,
    /// CHECK: the quote mint.
    #[account(address = quote_of(&tokenomics.to_account_info()).mint @ TokenomicsV2Error::NotTheAccount)]
    pub wsol_mint: UncheckedAccount<'info>,
    pub token_2022_program: Program<'info, Token2022>,
    /// CHECK: the quote's token program.
    #[account(address = quote_of(&tokenomics.to_account_info()).program @ TokenomicsV2Error::NotTheAccount)]
    pub token_program: UncheckedAccount<'info>,
    /// CHECK: cp-amm checks it.
    pub cp_amm_event_authority: UncheckedAccount<'info>,
    /// CHECK: pinned.
    #[account(address = CP_AMM_ID)]
    pub cp_amm_program: UncheckedAccount<'info>,
}

/// The vault and the coin account of a v2 account, at their addresses (`vault_accounts` for any quote).
pub(crate) fn vault_accounts_v2(tk: &AccountInfo, mint: Pubkey, vault: &AccountInfo, vault_coin: &AccountInfo) -> Result<QuoteOf> {
    let q = quote_of(tk);
    require_keys_eq!(vault.key(), q.vault(tk.key), TokenomicsError::NotTheAccount);
    require_keys_eq!(vault_coin.key(), get_associated_token_address_with_program_id(tk.key, &mint, &anchor_spl::token_2022::ID), TokenomicsError::NotTheAccount);
    Ok(q)
}

/// v1's: the position's fees, into the vault, where they are fees like any.
pub fn claim_lp_fees_v2_handler<'info>(ctx: Context<'_, '_, 'info, 'info, ClaimLpFeesV2<'info>>) -> Result<()> {
    let all = ctx.accounts.to_account_infos();
    let a = &ctx.accounts;
    let t = &a.tokenomics;
    let tk = t.key();
    let quote = vault_accounts_v2(&t.to_account_info(), t.mint, &a.vault_wsol, &a.vault_coin)?;
    let (hash, bump) = (t.config_hash, [t.bump]);
    let seeds: [&[u8]; 3] = [TOKENOMICS_V2_SEED, &hash, &bump];
    let accounts = vec![
        ro(&POOL_AUTHORITY),
        ro(&a.pool.key()),
        rw(&a.lp_position.key()),
        rw(&a.vault_coin.key()),
        rw(&a.vault_wsol.key()),
        rw(&a.token_a_vault.key()),
        rw(&a.token_b_vault.key()),
        ro(&a.mint.key()),
        ro(&quote.mint),
        ro(&a.lp_nft_account.key()),
        AccountMeta::new_readonly(tk, true),
        ro(&anchor_spl::token_2022::ID),
        ro(&quote.program),
        ro(&a.cp_amm_event_authority.key()),
        ro(&CP_AMM_ID),
    ];
    send(&all, CP_AMM_ID, accounts, crate::CLAIM_POSITION_FEE_DISCRIMINATOR.to_vec(), &[&seeds])
}

// ------------------------------------------------------------------------------ execute

#[derive(Accounts)]
pub struct ExecuteV2<'info> {
    /// Anyone, a plain wallet: fronts the payout passage's rent for the moment, and a missing
    /// incinerator coin account's; repaid its cost only when it is the operator (`operator_repay`).
    #[account(mut)]
    pub caller: Signer<'info>,
    #[account(mut, constraint = tokenomics.bound @ TokenomicsError::NotBound)]
    pub tokenomics: Box<Account<'info, TokenomicsV2>>,
    /// CHECK: the vault (`vault_accounts`).
    #[account(mut)]
    pub vault_wsol: UncheckedAccount<'info>,
    /// CHECK: the coin account (`vault_accounts`).
    #[account(mut)]
    pub vault_coin: UncheckedAccount<'info>,
    /// CHECK: `PDA(["tk-temp", tokenomics])`.
    #[account(mut, seeds = [TK_TEMP_SEED, tokenomics.key().as_ref()], bump)]
    pub temp: UncheckedAccount<'info>,
    /// CHECK: the treasury's associated coin account; the buy & hold's coins go there (kept for it
    /// when it is not there or requires memos).
    #[account(mut)]
    pub treasury_coin: UncheckedAccount<'info>,
    /// CHECK: pinned.
    #[account(address = incinerator::ID)]
    pub incinerator: UncheckedAccount<'info>,
    /// CHECK: made if missing and coins are burned.
    #[account(mut)]
    pub incinerator_coin: UncheckedAccount<'info>,
    /// CHECK: the launch's pool.
    #[account(mut, address = tokenomics.pool @ TokenomicsError::NotThePool)]
    pub pool: UncheckedAccount<'info>,
    /// CHECK: cp-amm's.
    #[account(address = POOL_AUTHORITY)]
    pub pool_authority: UncheckedAccount<'info>,
    /// CHECK: cp-amm checks them.
    #[account(mut)]
    pub token_a_vault: UncheckedAccount<'info>,
    /// CHECK: as above.
    #[account(mut)]
    pub token_b_vault: UncheckedAccount<'info>,
    /// CHECK: the coin.
    #[account(address = tokenomics.mint @ TokenomicsV2Error::NotTheAccount)]
    pub mint: UncheckedAccount<'info>,
    /// CHECK: the quote mint.
    #[account(address = quote_of(&tokenomics.to_account_info()).mint @ TokenomicsV2Error::NotTheAccount)]
    pub wsol_mint: UncheckedAccount<'info>,
    /// CHECK: the account's position, when it has one.
    #[account(mut)]
    pub lp_position: UncheckedAccount<'info>,
    /// CHECK: cp-amm checks it.
    pub lp_nft_account: UncheckedAccount<'info>,
    /// CHECK: cp-amm checks it.
    pub cp_amm_event_authority: UncheckedAccount<'info>,
    /// CHECK: pinned.
    #[account(address = CP_AMM_ID)]
    pub cp_amm_program: UncheckedAccount<'info>,
    /// CHECK: the quote's token program.
    #[account(address = quote_of(&tokenomics.to_account_info()).program @ TokenomicsV2Error::NotTheAccount)]
    pub token_program: UncheckedAccount<'info>,
    pub token_2022_program: Program<'info, Token2022>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
    /// CHECK: pinned.
    #[account(address = ixs::ID)]
    pub instructions: UncheckedAccount<'info>,
    /// CHECK: `PDA(["tk2-min"])`, the ADMIN's rules (`state::tk2_rules`; the defaults while unset).
    #[account(seeds = [TK2_MIN_SEED], bump)]
    pub min: UncheckedAccount<'info>,
    /// CHECK: `PDA(["tk2-config"])`: its operator is the one caller repaid (`state::operator_of`).
    #[account(seeds = [TK2_CONFIG_SEED], bump)]
    pub config: UncheckedAccount<'info>,
    // A quote-asset account (v2.3), optionally: `PDA(["tk2-rate", mint])` and the caller's own
    // account for the asset (`quote_extras`): the minimum and the operator's repayment, in the asset.
}

/// v1's `execute` for the burn, buy & hold and liquidity buckets -- the same swap, cap, cooldown,
/// add, lock, burn and operator repayment -- with no payouts: the wallets were credited at
/// allocation (`pay_tokenomics_wallets` pays them), the holders' share is the reward entries'.
///
/// A quote-asset account (v2.3) buys with the asset, through the coin's own pool (its token B),
/// and repays the operator in the asset at the ADMIN's rate (`operator_repay_quote`), into the
/// operator's own account for it; given no rate or no such account, nobody is repaid.
pub fn execute_v2_handler<'info>(ctx: Context<'_, '_, 'info, 'info, ExecuteV2<'info>>) -> Result<()> {
    once_at_top(&ctx.accounts.instructions, true)?;
    let mut all = ctx.accounts.to_account_infos();
    all.extend_from_slice(ctx.remaining_accounts);
    let a = &ctx.accounts;
    let tk = a.tokenomics.key();
    let caller = a.caller.to_account_info();
    require!(*caller.owner == System::id() && caller.data_is_empty(), TokenomicsError::CallerNotAWallet);
    let quote = vault_accounts_v2(&a.tokenomics.to_account_info(), a.tokenomics.mint, &a.vault_wsol, &a.vault_coin)?;
    let extras = if quote.native() { None } else { Some(quote_extras(ctx.remaining_accounts, &quote)?) };
    let now = Clock::get()?.unix_timestamp;

    let mut t: TokenomicsV2 = (**a.tokenomics).clone();
    allocate_v2(&mut t, tk, balance(&a.vault_wsol)?);

    let rules = tk2_rules(&a.min)?;
    let operator = operator_of(&a.config)?.is_some_and(|o| o == caller.key());
    // The minimum is lamports: an asset's buckets are held to it at the rate (none without one).
    let minimum = match &extras {
        None => rules.min_execute_lamports,
        Some(x) => to_quote(rules.min_execute_lamports, x.rate),
    };
    let due = |b: u64| b >= minimum && b != 0;
    // The operator's repayment comes out of what the run spends, at most `cap_bps` of it: so much of
    // each bucket is held back from the swap, and what the repayment does not take stays in the
    // bucket. A run by anybody else repays nothing and holds nothing back.
    let cap = if operator { rules.cap_bps as u128 } else { 0 };
    let budget = |b: u64| ((b as u128 * BPS as u128) / (BPS as u128 + cap)) as u64;
    // What the run makes the caller pay and not get back in it (a missing incinerator coin account's
    // rent), measured: the caller's lamports now, against just before the repayment.
    let rent_from = caller.lamports();
    let mut run = Run::default();

    let buy_due = due(t.buckets[V2_BURN]);
    let back_due = due(t.buckets[V2_BUYBACK]);
    let has_position = t.lp_position != Pubkey::default();
    if has_position {
        require_keys_eq!(a.lp_position.key(), t.lp_position, TokenomicsV2Error::NotTheAccount);
    }
    let liq_due = (due(t.buckets[V2_LIQUIDITY]) || (t.liquidity_coins > 0 && t.buckets[V2_LIQUIDITY] > 0)) && has_position;
    if due(t.buckets[V2_LIQUIDITY]) && !has_position {
        skipped(tk, 2, 6);
    }
    if buy_due || back_due || liq_due {
        if now < t.last_swap.saturating_add(rules.swap_cooldown_secs.max(crate::MIN_SWAP_COOLDOWN_SECS) as i64) {
            skipped(tk, 1, 4);
        } else {
            let burn = if buy_due { budget(t.buckets[V2_BURN]) } else { 0 };
            let back = if back_due { budget(t.buckets[V2_BUYBACK]) } else { 0 };
            let liq = if liq_due { budget(t.buckets[V2_LIQUIDITY]) } else { 0 };
            let liq_add_only = !due(t.buckets[V2_LIQUIDITY]);
            let acc = BuyAccounts {
                tk,
                quote_mint: quote.mint,
                quote_program: quote.program,
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
            let (hash, bump) = (t.config_hash, [t.bump]);
            let seeds: [&[u8]; 3] = [TOKENOMICS_V2_SEED, &hash, &bump];
            buy_stage(&all, &acc, &mut books, &seeds, &mut run, burn, back, liq, liq_add_only, now, rules.max_move_fee_bps)?;
            t.liquidity_coins = books.liquidity_coins;
            t.treasury_coins = books.treasury_coins;
            t.last_swap = books.last_swap;
        }
    }

    let total: u64 = run.spend.iter().take(V2_BUCKETS).sum();
    require!(total > 0, TokenomicsError::NothingToExecute);
    // The operator's repayment: what the run cost, times (1 + margin); a run it would cost more
    // than the cap of what it pays out is refused (skipped, never paid capped).
    let fronted = rent_from.saturating_sub(caller.lamports());
    let (owed, repay_to) = match (&extras, operator) {
        (_, false) => (0, None),
        (None, true) => (operator_repay(&a.instructions, fronted, rules, total)?, None),
        (Some(x), true) => match x.repay_to.filter(|d| payable(d, &caller.key(), &quote)) {
            Some(d) => (operator_repay_quote(&a.instructions, fronted, rules, total, x.rate)?, Some(d.key())),
            None => (0, None),
        },
    };
    // What was spent, and the repayment pro rata, come off the buckets that spent.
    let mut left = owed;
    for i in 0..V2_BUCKETS {
        let s = run.spend[i];
        if s == 0 {
            continue;
        }
        let share = ((owed as u128 * s as u128) / total as u128) as u64;
        t.buckets[i] = t.buckets[i].checked_sub(s + share).ok_or(TokenomicsError::Overflow)?;
        left -= share;
        t.spent[i] += s;
        emit!(TokenomicsSpent { tokenomics: tk, bucket: i as u8, lamports: s });
    }
    for i in 0..V2_BUCKETS {
        if left == 0 {
            break;
        }
        if run.spend[i] > 0 {
            let d = left.min(t.buckets[i]);
            t.buckets[i] -= d;
            left -= d;
        }
    }
    require!(left == 0, TokenomicsError::Overflow);
    t.reimbursed += owed;
    let (hash, bump) = (t.config_hash, [t.bump]);
    let seeds: [&[u8]; 3] = [TOKENOMICS_V2_SEED, &hash, &bump];
    let tk_info = a.tokenomics.to_account_info();
    match repay_to {
        None => unwrap_to(&all, &caller, &a.temp, ctx.bumps.temp, &tk_info, &seeds, &a.vault_wsol, owed)?,
        Some(to) => send_quote(&all, &quote, &a.vault_wsol.key(), &to, &tk, &seeds, owed, quote_decimals(&all, &quote)?)?,
    }
    emit!(TokenomicsReimbursed { tokenomics: tk, caller: caller.key(), lamports: owed });
    t.coins_burned += run.coins_burned;
    t.coins_to_treasury += run.coins_to_treasury;
    require!(balance(&a.vault_wsol)? >= t.tracked(), TokenomicsError::Overflow);
    require!(balance(&a.vault_coin)? >= t.liquidity_coins + t.treasury_coins, TokenomicsError::Overflow);
    **ctx.accounts.tokenomics = t;
    Ok(())
}

/// The operator's repayment for a run that pays out `paid`: what the transaction cost -- 5,000
/// lamports for each signer its instructions name, the priority fee its compute-budget
/// instructions declare (`declared_priority`: price x limit, as the runtime charges it), and `rent`
/// the run made it pay and not get back -- times (1 + `margin_bps`). Refused above `cap_bps` of
/// `paid`: a run too small for what it costs is skipped, never paid capped.
pub(crate) fn operator_repay(instructions: &AccountInfo, rent: u64, rules: Tk2Rules, paid: u64) -> Result<u64> {
    let count = {
        let d = instructions.try_borrow_data()?;
        u16::from_le_bytes(d.get(..2).and_then(|b| b.try_into().ok()).ok_or(TokenomicsV2Error::NotAlone)?) as usize
    };
    let mut signers: Vec<Pubkey> = Vec::new();
    for i in 0..count {
        for m in ixs::load_instruction_at_checked(i, instructions)?.accounts {
            if m.is_signer && !signers.contains(&m.pubkey) {
                signers.push(m.pubkey);
            }
        }
    }
    let cost = SIGNATURE_LAMPORTS * (signers.len().max(1) as u64) + declared_priority(instructions)? + rent;
    let owed = u64::try_from((cost as u128 * (BPS as u128 + rules.margin_bps as u128)) / BPS as u128).map_err(|_| error!(TokenomicsV2Error::Overflow))?;
    require!(owed as u128 * BPS as u128 <= rules.cap_bps as u128 * paid as u128, TokenomicsV2Error::RepayOverCap);
    Ok(owed)
}

/// `operator_repay` for a quote-asset account (v2.3): the run's cost in lamports, times (1 +
/// margin), converted into the asset at `rate` (base units per SOL), and refused above `cap_bps`
/// of `paid` -- which is in the asset too. At a rate of 0 nothing is owed (and nothing refused).
pub(crate) fn operator_repay_quote(instructions: &AccountInfo, rent: u64, rules: Tk2Rules, paid: u64, rate: u64) -> Result<u64> {
    if rate == 0 {
        return Ok(0);
    }
    // The lamport figure with the cap lifted (it is checked below, in the asset).
    let lamports = operator_repay(instructions, rent, Tk2Rules { cap_bps: u16::MAX, ..rules }, u64::MAX)?;
    let owed = to_quote(lamports, rate);
    require!(owed as u128 * BPS as u128 <= rules.cap_bps as u128 * paid as u128, TokenomicsV2Error::RepayOverCap);
    Ok(owed)
}

/// The least a crank pays a wallet owed `owed` when the operator's cap is `cap` bps (> 0): its
/// share of a repayment of at most `cap` bps of the crank's total is at most ceil(owed·cap/BPS),
/// and the dust left by the shares' rounding, under one lamport for each wallet paid, may all come
/// off it.
pub(crate) fn least_paid(owed: u64, cap: u128) -> u64 {
    let share = (owed as u128 * cap).div_ceil(BPS as u128);
    (owed as u128).saturating_sub(share).saturating_sub(MAX_WALLETS as u128) as u64
}

// ------------------------------------------------------------------------------ the wallets

#[derive(Accounts)]
pub struct PayWallets<'info> {
    /// Anyone, a plain wallet: fronts the passage's rent; repaid its cost only when it is the operator.
    #[account(mut)]
    pub caller: Signer<'info>,
    #[account(mut, constraint = tokenomics.bound @ TokenomicsError::NotBound)]
    pub tokenomics: Box<Account<'info, TokenomicsV2>>,
    /// CHECK: the vault.
    #[account(mut, address = vault_of(&tokenomics.to_account_info()) @ TokenomicsV2Error::NotTheAccount)]
    pub vault_wsol: UncheckedAccount<'info>,
    /// CHECK: `PDA(["tk-temp", tokenomics])`.
    #[account(mut, seeds = [TK_TEMP_SEED, tokenomics.key().as_ref()], bump)]
    pub temp: UncheckedAccount<'info>,
    /// CHECK: the quote mint.
    #[account(address = quote_of(&tokenomics.to_account_info()).mint @ TokenomicsV2Error::NotTheAccount)]
    pub wsol_mint: UncheckedAccount<'info>,
    /// CHECK: the quote's token program.
    #[account(address = quote_of(&tokenomics.to_account_info()).program @ TokenomicsV2Error::NotTheAccount)]
    pub token_program: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
    /// CHECK: pinned.
    #[account(address = ixs::ID)]
    pub instructions: UncheckedAccount<'info>,
    /// CHECK: `PDA(["tk2-min"])`, the ADMIN's rules (`state::tk2_rules`; the defaults while unset).
    #[account(seeds = [TK2_MIN_SEED], bump)]
    pub min: UncheckedAccount<'info>,
    /// CHECK: `PDA(["tk2-config"])`: its operator is the one caller repaid (`state::operator_of`).
    #[account(seeds = [TK2_CONFIG_SEED], bump)]
    pub config: UncheckedAccount<'info>,
    // Then the wallets of slots `from..to`, in order, writable. A quote-asset account (v2.3):
    // first `PDA(["tk2-rate", mint])` and the caller's own account for the asset (`quote_extras`),
    // then, for each slot of `from..to`, the wallet's associated account for the asset, writable.
}

/// The crank (anyone): each wallet of slots `from..to` that can take SOL is paid what it is owed,
/// less, when the caller is the operator, its pro-rata share of the operator's repayment
/// (`operator_repay`, at most `cap_bps` of what is paid out); anybody else is repaid nothing and
/// the wallets are paid whole. Runs when the wallets in range that can be
/// paid are owed at least the minimum together. A wallet that cannot take SOL (not a plain
/// wallet, or left under the rent-exempt minimum) keeps what it is owed, to claim.
pub fn pay_wallets_handler<'info>(ctx: Context<'_, '_, 'info, 'info, PayWallets<'info>>, from: u8, to: u8) -> Result<()> {
    once_at_top(&ctx.accounts.instructions, false)?;
    let a = &ctx.accounts;
    let tk = a.tokenomics.key();
    let caller = a.caller.to_account_info();
    require!(*caller.owner == System::id() && caller.data_is_empty(), TokenomicsError::CallerNotAWallet);
    let (from, to) = (from as usize, to as usize);
    let mut t: TokenomicsV2 = (**a.tokenomics).clone();
    require!(from < to && to <= t.num_wallets as usize, TokenomicsV2Error::NoSuch);
    let quote = quote_of(&a.tokenomics.to_account_info());
    // A quote-asset account: the rate and the caller's account first, then each wallet's account.
    let (extras, given) = if quote.native() {
        (None, ctx.remaining_accounts)
    } else {
        require!(ctx.remaining_accounts.len() >= 2, TokenomicsV2Error::NotTheAccount);
        (Some(quote_extras(ctx.remaining_accounts, &quote)?), &ctx.remaining_accounts[2..])
    };
    require!(given.len() == to - from, TokenomicsV2Error::NotTheAccount);
    allocate_v2(&mut t, tk, balance(&a.vault_wsol)?);

    let rules = tk2_rules(&a.min)?;
    let operator = operator_of(&a.config)?.is_some_and(|o| o == caller.key());
    // An asset account's operator is repaid only into its own account for the asset, at a rate.
    let repay_to = match &extras {
        Some(x) if operator && x.rate > 0 => x.repay_to.filter(|d| payable(d, &caller.key(), &quote)).map(|d| d.key()),
        _ => None,
    };
    let operator = operator && (quote.native() || repay_to.is_some());
    let minimum = match &extras {
        None => rules.min_execute_lamports,
        Some(x) => to_quote(rules.min_execute_lamports, x.rate),
    };
    let cap = if operator { rules.cap_bps as u128 } else { 0 };
    let mut due = [0u64; MAX_WALLETS];
    let mut pay = [0u64; MAX_WALLETS];
    let mut total = 0u64;
    for i in from..to {
        let w = &given[i - from];
        let owed = t.wallets[i].accrued;
        let least = if cap == 0 { owed } else { least_paid(owed, cap) };
        if quote.native() {
            require_keys_eq!(w.key(), t.wallets[i].key, TokenomicsV2Error::NotTheAccount);
            // A payable wallet may not be named read-only to have its payout skipped.
            require!(writable_or_reserved(w), TokenomicsV2Error::NotTheAccount);
            // The least it could be paid: its share of the repayment is at most `cap_bps` of what it is
            // owed (rounded up), and the dust (under one lamport a wallet paid) may all come off it. A
            // wallet that takes that takes whatever it is paid, so no payout below can be refused.
            if owed == 0 || least == 0 || !takes_sol(w, least)? {
                continue;
            }
        } else {
            // The wallet's associated account for the asset; one that is missing, frozen, read-only
            // or carries an extension its holder enabled is passed over (the wallet keeps what it is
            // owed, to claim into any account of its own) -- never named read-only to skip it.
            require_keys_eq!(w.key(), quote.ata(&t.wallets[i].key), TokenomicsV2Error::NotTheAccount);
            require!(w.is_writable || *w.owner != quote.program, TokenomicsV2Error::NotTheAccount);
            if owed == 0 || least == 0 || !payable(w, &t.wallets[i].key, &quote) {
                continue;
            }
        }
        due[i] = owed;
        total += owed;
    }
    // A duplicate wallet in range (a slot handed to another slot's address) is paid both parts,
    // in one transfer each: `takes_sol` was asked of each part alone, which only ever errs low.
    require!(total >= minimum && total > 0, TokenomicsV2Error::NothingDue);
    // The operator's repayment (nothing for anybody else), pro rata off what each wallet is paid.
    let owed = match &extras {
        _ if !operator => 0,
        None => operator_repay(&a.instructions, 0, rules, total)?,
        Some(x) => operator_repay_quote(&a.instructions, 0, rules, total, x.rate)?,
    };
    let mut left = owed;
    for i in from..to {
        if due[i] == 0 {
            continue;
        }
        let share = ((owed as u128 * due[i] as u128) / total as u128) as u64;
        pay[i] = due[i] - share;
        left -= share;
    }
    for i in from..to {
        if left == 0 {
            break;
        }
        let d = left.min(pay[i]);
        pay[i] -= d;
        left -= d;
    }
    require!(left == 0, TokenomicsError::Overflow);
    for i in from..to {
        t.wallets[i].accrued -= due[i];
        t.wallets[i].paid += pay[i];
    }
    t.reimbursed += owed;
    let (hash, bump) = (t.config_hash, [t.bump]);
    let seeds: [&[u8]; 3] = [TOKENOMICS_V2_SEED, &hash, &bump];
    let mut all = ctx.accounts.to_account_infos();
    all.extend_from_slice(ctx.remaining_accounts);
    let tk_info = a.tokenomics.to_account_info();
    if quote.native() {
        unwrap_to(&all, &caller, &a.temp, ctx.bumps.temp, &tk_info, &seeds, &a.vault_wsol, total)?;
        for i in from..to {
            if pay[i] > 0 {
                let w = &given[i - from];
                anchor_lang::solana_program::program::invoke(&anchor_lang::solana_program::system_instruction::transfer(caller.key, w.key, pay[i]), &all)?;
                emit!(WalletPaid { tokenomics: tk, index: i as u8, to: w.key(), lamports: pay[i] });
            }
        }
    } else {
        let decimals = quote_decimals(&all, &quote)?;
        let vault = a.vault_wsol.key();
        for i in from..to {
            if pay[i] > 0 {
                let w = &given[i - from];
                send_quote(&all, &quote, &vault, &w.key(), &tk, &seeds, pay[i], decimals)?;
                emit!(WalletPaid { tokenomics: tk, index: i as u8, to: w.key(), lamports: pay[i] });
            }
        }
        if let Some(to) = repay_to {
            send_quote(&all, &quote, &vault, &to, &tk, &seeds, owed, decimals)?;
        }
    }
    emit!(TokenomicsReimbursed { tokenomics: tk, caller: caller.key(), lamports: owed });
    require!(balance(&a.vault_wsol)? >= t.tracked(), TokenomicsError::Overflow);
    **ctx.accounts.tokenomics = t;
    Ok(())
}

#[derive(Accounts)]
pub struct ClaimWallet<'info> {
    /// The slot's wallet.
    #[account(mut)]
    pub claimer: Signer<'info>,
    #[account(mut, constraint = tokenomics.bound @ TokenomicsError::NotBound)]
    pub tokenomics: Box<Account<'info, TokenomicsV2>>,
    /// CHECK: the vault.
    #[account(mut, address = vault_of(&tokenomics.to_account_info()) @ TokenomicsV2Error::NotTheAccount)]
    pub vault_wsol: UncheckedAccount<'info>,
    /// CHECK: `PDA(["tk-temp", tokenomics])`.
    #[account(mut, seeds = [TK_TEMP_SEED, tokenomics.key().as_ref()], bump)]
    pub temp: UncheckedAccount<'info>,
    /// CHECK: the quote mint.
    #[account(address = quote_of(&tokenomics.to_account_info()).mint @ TokenomicsV2Error::NotTheAccount)]
    pub wsol_mint: UncheckedAccount<'info>,
    /// CHECK: the quote's token program.
    #[account(address = quote_of(&tokenomics.to_account_info()).program @ TokenomicsV2Error::NotTheAccount)]
    pub token_program: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
    // A quote-asset account (v2.3): then any account of the claimer's for the asset, writable.
}

/// A wallet takes everything its slot is owed, at any size, as SOL, paying its own fee -- or, for a
/// quote-asset account, in the asset, into any account of its own for it (`payable`).
pub fn claim_wallet_handler<'info>(ctx: Context<'_, '_, 'info, 'info, ClaimWallet<'info>>, index: u8) -> Result<()> {
    let mut all = ctx.accounts.to_account_infos();
    all.extend_from_slice(ctx.remaining_accounts);
    let a = &ctx.accounts;
    let tk = a.tokenomics.key();
    let i = index as usize;
    let mut t: TokenomicsV2 = (**a.tokenomics).clone();
    require!(i < t.num_wallets as usize, TokenomicsV2Error::NoSuch);
    require_keys_eq!(a.claimer.key(), t.wallets[i].key, TokenomicsV2Error::NotTheRole);
    allocate_v2(&mut t, tk, balance(&a.vault_wsol)?);
    let amount = t.wallets[i].accrued;
    require!(amount > 0, TokenomicsError::NothingToClaim);
    t.wallets[i].accrued = 0;
    t.wallets[i].paid += amount;
    let (hash, bump) = (t.config_hash, [t.bump]);
    let seeds: [&[u8]; 3] = [TOKENOMICS_V2_SEED, &hash, &bump];
    let tk_info = a.tokenomics.to_account_info();
    let claimer = a.claimer.to_account_info();
    let quote = quote_of(&tk_info);
    if quote.native() {
        unwrap_to(&all, &claimer, &a.temp, ctx.bumps.temp, &tk_info, &seeds, &a.vault_wsol, amount)?;
    } else {
        let to = ctx.remaining_accounts.first().ok_or(TokenomicsV2Error::NotTheAccount)?;
        require!(payable(to, &claimer.key(), &quote), TokenomicsV2Error::NotTheAccount);
        send_quote(&all, &quote, &a.vault_wsol.key(), &to.key(), &tk, &seeds, amount, quote_decimals(&all, &quote)?)?;
    }
    emit!(WalletPaid { tokenomics: tk, index, to: claimer.key(), lamports: amount });
    **ctx.accounts.tokenomics = t;
    Ok(())
}

#[derive(Accounts)]
pub struct TokenomicsV2Signer<'info> {
    pub signer: Signer<'info>,
    #[account(mut)]
    pub tokenomics: Box<Account<'info, TokenomicsV2>>,
}

/// A wallet offers its own slot to `to`; it moves, with what the slot is owed, when `to` accepts.
pub fn propose_wallet_handler(ctx: Context<TokenomicsV2Signer>, index: u8, to: Pubkey) -> Result<()> {
    let who = ctx.accounts.signer.key();
    let tk = ctx.accounts.tokenomics.key();
    let t = &mut ctx.accounts.tokenomics;
    let i = index as usize;
    require!(i < t.num_wallets as usize, TokenomicsV2Error::NoSuch);
    require_keys_eq!(t.wallets[i].key, who, TokenomicsV2Error::NotTheRole);
    require!(to != Pubkey::default() && to != tk && !crate::is_reserved_account(&to), TokenomicsV2Error::BadConfig);
    t.wallets[i].pending = to;
    emit!(WalletProposed { tokenomics: tk, index, from: who, to });
    Ok(())
}

pub fn accept_wallet_handler(ctx: Context<TokenomicsV2Signer>, index: u8) -> Result<()> {
    let who = ctx.accounts.signer.key();
    let tk = ctx.accounts.tokenomics.key();
    let t = &mut ctx.accounts.tokenomics;
    let i = index as usize;
    require!(i < t.num_wallets as usize, TokenomicsV2Error::NoSuch);
    require!(t.wallets[i].pending != Pubkey::default(), TokenomicsV2Error::NotTheRole);
    require_keys_eq!(t.wallets[i].pending, who, TokenomicsV2Error::NotTheRole);
    let from = t.wallets[i].key;
    t.wallets[i].key = who;
    t.wallets[i].pending = Pubkey::default();
    emit!(WalletChanged { tokenomics: tk, index, from, to: who });
    Ok(())
}

// ------------------------------------------------------------------------------ roles

fn role_slots(t: &mut TokenomicsV2, role: u8) -> Result<(&mut Pubkey, &mut Pubkey)> {
    match role {
        ROLE_OWNER => Ok((&mut t.owner, &mut t.pending_owner)),
        ROLE_TREASURY => Ok((&mut t.treasury, &mut t.pending_treasury)),
        _ => err!(TokenomicsV2Error::NoSuch),
    }
}

/// v1's two-step hand-over for the owner (0) and the treasury (1), after the bind.
pub fn propose_role_v2_handler(ctx: Context<TokenomicsV2Signer>, role: u8, to: Pubkey) -> Result<()> {
    require!(ctx.accounts.tokenomics.bound, TokenomicsError::NotBound);
    let who = ctx.accounts.signer.key();
    let tk = ctx.accounts.tokenomics.key();
    require!(to != Pubkey::default() && to != tk && !crate::is_reserved_account(&to), TokenomicsV2Error::BadConfig);
    require!(!(role == ROLE_OWNER && to == incinerator::ID), TokenomicsV2Error::BadConfig);
    let t = &mut ctx.accounts.tokenomics;
    let (current, pending) = role_slots(t, role)?;
    require_keys_eq!(*current, who, TokenomicsV2Error::NotTheRole);
    *pending = to;
    emit!(TokenomicsRoleProposed { tokenomics: tk, role, from: who, to });
    Ok(())
}

pub fn accept_role_v2_handler(ctx: Context<TokenomicsV2Signer>, role: u8) -> Result<()> {
    require!(ctx.accounts.tokenomics.bound, TokenomicsError::NotBound);
    let who = ctx.accounts.signer.key();
    let tk = ctx.accounts.tokenomics.key();
    let t = &mut ctx.accounts.tokenomics;
    let (current, pending) = role_slots(t, role)?;
    require!(*pending != Pubkey::default(), TokenomicsV2Error::NotTheRole);
    require_keys_eq!(*pending, who, TokenomicsV2Error::NotTheRole);
    let from = *current;
    *current = who;
    *pending = Pubkey::default();
    emit!(TokenomicsRoleChanged { tokenomics: tk, role, from, to: who });
    Ok(())
}

/// The owner or the ADMIN sets the eligibility the payout service reads (min >= 0.1%).
pub fn set_eligibility_handler(ctx: Context<TokenomicsV2Signer>, min_holder_bps: u16, select_mode: u8, select_count: u32) -> Result<()> {
    let who = ctx.accounts.signer.key();
    require!(who == ctx.accounts.tokenomics.owner || who == ADMIN, TokenomicsV2Error::NotTheRole);
    require!(min_holder_bps >= MIN_HOLDER_BPS_FLOOR && min_holder_bps as u32 <= V2_BPS, TokenomicsV2Error::BadConfig);
    check_selection(select_mode, select_count)?;
    let tk = ctx.accounts.tokenomics.key();
    let t = &mut ctx.accounts.tokenomics;
    t.min_holder_bps = min_holder_bps;
    t.select_mode = select_mode;
    t.select_count = select_count;
    emit!(EligibilitySet { tokenomics: tk, by: who, min_holder_bps, select_mode, select_count });
    Ok(())
}

// ------------------------------------------------------------------------------ strays

#[derive(Accounts)]
pub struct SweepWsolV2<'info> {
    #[account(mut)]
    pub tokenomics: Box<Account<'info, TokenomicsV2>>,
    /// CHECK: a wrapped-SOL account the account owns, other than its vault.
    #[account(mut)]
    pub stray: UncheckedAccount<'info>,
    /// CHECK: the vault.
    #[account(mut, address = vault_of(&tokenomics.to_account_info()) @ TokenomicsV2Error::NotTheAccount)]
    pub vault_wsol: UncheckedAccount<'info>,
    /// CHECK: the quote mint.
    #[account(address = quote_of(&tokenomics.to_account_info()).mint @ TokenomicsV2Error::NotTheAccount)]
    pub wsol_mint: UncheckedAccount<'info>,
    /// CHECK: the quote's token program.
    #[account(address = quote_of(&tokenomics.to_account_info()).program @ TokenomicsV2Error::NotTheAccount)]
    pub token_program: UncheckedAccount<'info>,
}

/// v1's `sweep_tokenomics_wsol`: a stray account of the account's quote (wrapped SOL, or the
/// asset), into its vault (as fees) and closed.
pub fn sweep_wsol_v2_handler<'info>(ctx: Context<'_, '_, 'info, 'info, SweepWsolV2<'info>>) -> Result<()> {
    let all = ctx.accounts.to_account_infos();
    let a = &ctx.accounts;
    let tk = a.tokenomics.key();
    let quote = quote_of(&a.tokenomics.to_account_info());
    let vault = a.vault_wsol.key();
    require_keys_neq!(a.stray.key(), vault, TokenomicsV2Error::NotTheAccount);
    require_keys_eq!(*a.stray.owner, quote.program, TokenomicsV2Error::NotTheAccount);
    let (mint, owner, amount) = token_account(&a.stray).ok_or(TokenomicsV2Error::NotTheAccount)?;
    require_keys_eq!(mint, quote.mint, TokenomicsV2Error::NotTheAccount);
    require_keys_eq!(owner, tk, TokenomicsV2Error::NotTheAccount);
    let (hash, bump) = (a.tokenomics.config_hash, [a.tokenomics.bump]);
    let seeds: [&[u8]; 3] = [TOKENOMICS_V2_SEED, &hash, &bump];
    send_quote(&all, &quote, &a.stray.key(), &vault, &tk, &seeds, amount, quote_decimals(&all, &quote)?)?;
    let ix = if quote.program == spl_token::ID {
        spl_token::instruction::close_account(&spl_token::ID, &a.stray.key(), &tk, &tk, &[])?
    } else {
        anchor_spl::token_2022::spl_token_2022::instruction::close_account(&quote.program, &a.stray.key(), &tk, &tk, &[])?
    };
    invoke_signed(&ix, &all, &[&seeds])?;
    emit!(TokenomicsForwarded { tokenomics: tk, to: vault, lamports: 0, coins: amount });
    Ok(())
}

#[derive(Accounts)]
pub struct ClaimTreasuryCoinsV2<'info> {
    pub treasury: Signer<'info>,
    #[account(mut, has_one = treasury @ TokenomicsV2Error::NotTheRole, constraint = tokenomics.bound @ TokenomicsError::NotBound)]
    pub tokenomics: Box<Account<'info, TokenomicsV2>>,
    /// CHECK: the account's coin account.
    #[account(mut)]
    pub vault_coin: UncheckedAccount<'info>,
    /// CHECK: any account of the coin (Token-2022 checks it).
    #[account(mut)]
    pub to: UncheckedAccount<'info>,
    /// CHECK: the coin.
    #[account(address = tokenomics.mint @ TokenomicsV2Error::NotTheAccount)]
    pub mint: UncheckedAccount<'info>,
    pub token_2022_program: Program<'info, Token2022>,
}

/// v1's: the treasury takes the coins kept for it.
pub fn claim_treasury_coins_v2_handler<'info>(ctx: Context<'_, '_, 'info, 'info, ClaimTreasuryCoinsV2<'info>>) -> Result<()> {
    let all = ctx.accounts.to_account_infos();
    let a = &ctx.accounts;
    let tk = a.tokenomics.key();
    let mint = a.tokenomics.mint;
    require_keys_eq!(a.vault_coin.key(), get_associated_token_address_with_program_id(&tk, &mint, &anchor_spl::token_2022::ID), TokenomicsV2Error::NotTheAccount);
    let amount = a.tokenomics.treasury_coins;
    require!(amount > 0, TokenomicsError::NothingToClaim);
    let (hash, bump) = (a.tokenomics.config_hash, [a.tokenomics.bump]);
    let seeds: [&[u8]; 3] = [TOKENOMICS_V2_SEED, &hash, &bump];
    send_coins(&all, &a.vault_coin.key(), &mint, &a.to.key(), &tk, &seeds, amount)?;
    let treasury = a.treasury.key();
    ctx.accounts.tokenomics.treasury_coins = 0;
    emit!(TokenomicsSentToTreasury { tokenomics: tk, treasury, coins: amount });
    Ok(())
}
