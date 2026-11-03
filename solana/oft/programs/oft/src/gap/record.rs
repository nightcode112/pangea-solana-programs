//! The PriceLog writers' shared reads (BRIEF Amendment 4; the per-sender GapSendRecord two-step is
//! REMOVED) and the two PriceLog instructions:
//!
//!   * `init_gap_price_log`: permissionless, the payer pays the rent; creates the store's
//!     ["GapPriceLog", store] (gap/pricelog.rs). Once per v3 store, any time (the launcher puts it
//!     in an open_bridge transaction, which also extends the shared lookup table with it).
//!   * `record_price`: permissionless, the caller pays the fee; writes the current price (token USD
//!     through the full route, the pool price in its quote, SOL/USD through GapRoute(wSOL)) into the
//!     log, like a send's or a receive's own write. Top level only, refuses an earlier top-level
//!     instruction that lists a pool it reads, and is the transaction's only PriceLog write.
//!     Remaining accounts: [GapGlobal, GapRoute(quote), pool, hop0, hop1, instructions sysvar,
//!     GapRoute(wSOL), nhop0, nhop1]. Owner (A): the entry's writer is the signer (a reward a full
//!     reward table forfeits here is parked in the log for the next send, receive or claim).
use super::engine::{self, GapAccounts, GapData, GAP_ACCOUNTS};
use super::introspect;
use super::math::E18;
use super::pricelog::{self, Live};
use super::state::*;
use crate::*;
use anchor_lang::solana_program::{program::invoke_signed, rent::Rent, system_instruction};

pub const WSOL_MINT: Pubkey = pubkey!("So11111111111111111111111111111111111111112");
/// `record_price`'s gap accounts: the six, then GapRoute(wSOL), nhop0, nhop1.
pub const RECORD_GAP_ACCOUNTS: usize = GAP_ACCOUNTS + 3;
/// The send's gap accounts: the six, then the store's PriceLog.
pub const SEND_GAP_ACCOUNTS: usize = GAP_ACCOUNTS + 1;

/// Owner (A): the pool's flat fee as a PriceLog entry records it (fee_at_record); 0 = unreadable
/// (k_mode 1 then gives the entry no capacity).
pub fn fee_at_record(d: &GapData) -> u32 {
    engine::pool_fee_ppm(d).ok().filter(|f| (*f as u128) < super::math::PPM).unwrap_or(0)
}

// ------------------------------------------------------------------ prices

/// USD per whole `mint` (1e18) through `route`'s hops (`hops[i]` the account of hop i): E18 for a
/// stable, None on any failure. `up` rounds every factor up (a source's price), else down.
/// The walk the destination and the source both price through.
#[cfg(not(feature = "stock-hops"))] pub fn route_usd(global: &GapGlobal, route: Option<&GapRoute>, hops: [&AccountInfo; 2], mint: &Pubkey, up: bool) -> Option<u128> {
    if global.is_stable(mint) {
        return Some(E18);
    }
    let r = route?;
    if r.quote_mint != *mint || r.hop_count == 0 || r.hop_count > 2 || r.hops[0].token_in != *mint {
        return None;
    }
    let mut acc = E18;
    let mut last = *mint;
    for (i, (hop, dec_in, dec_out)) in r.used().enumerate() {
        if hop.kind != HOP_KIND_DAMM_V2 || hop.token_in != last {
            return None;
        }
        let hv = engine::read_pool(hops[i])?;
        let base_is_a = hv.side(&hop.token_in.to_bytes(), &hop.token_out.to_bytes())?;
        let hp = hv.price(base_is_a, dec_in, dec_out, up)?;
        acc = if up { super::math::mul_up(acc, hp) } else { super::math::mul_down(acc, hp) };
        if acc == 0 {
            return None;
        }
        last = hop.token_out;
    }
    global.is_stable(&last).then_some(acc)
}

/// The live prices one PriceLog write records (sol 0: only `record_price` reads it): the token's USD
/// price and its pool price in the quote, each rounded up and down; 0 where unreadable.
/// Each pool is read once per rounding: usd = pool price x the quote's route factor, exactly
/// the pool price times the route factor, with the same checks and roundings on both sides.
#[cfg(not(feature = "stock-hops"))] pub fn live_prices(a: &GapAccounts, d: &GapData, tail: &Tail, token_mint: &Pubkey) -> Live {
    let cls_up = engine::pool_price(d, tail, token_mint, true).unwrap_or(0);
    let cls_down = engine::pool_price(d, tail, token_mint, false).unwrap_or(0);
    let usd = |p: u128, up: bool| -> u128 {
        let Some(g) = d.global.as_ref() else { return 0 };
        if p == 0 {
            return 0;
        }
        match route_usd(g, d.route.as_ref(), [a.hop0, a.hop1], &tail.quote_mint, up) {
            Some(f) if up => super::math::mul_up(p, f),
            Some(f) => super::math::mul_down(p, f),
            None => 0,
        }
    };
    Live { usd_up: usd(cls_up, true), usd_down: usd(cls_down, false), cls_up, cls_down, sol: 0 }
}

/// min(a, b), 0 when either is 0.
pub fn min_known(a: u128, b: u128) -> u128 {
    if a == 0 || b == 0 { 0 } else { a.min(b) }
}

// ------------------------------------------------------------------ account checks

/// GapRoute(wSOL) and its hop accounts, checked as engine::check checks the quote's.
pub struct NativeRoute<'a, 'info> {
    pub route: Option<GapRoute>,
    pub hops: [&'a AccountInfo<'info>; 2],
}

pub fn check_native_route<'a, 'info>(rem: &'a [AccountInfo<'info>], at: usize, program_id: &Pubkey) -> Result<NativeRoute<'a, 'info>> {
    require!(rem.len() >= at + 3, OFTError::GapAccountMismatch);
    let info = &rem[at];
    let route: Option<GapRoute> = read_owned(info, program_id);
    require!(
        engine::pda_matches(info.key, &[GAP_ROUTE_SEED, WSOL_MINT.as_ref()], route.as_ref().map(|r| r.bump), program_id),
        OFTError::GapAccountMismatch
    );
    for i in 0..2 {
        let want = route.as_ref().map_or(*program_id, |r| r.hop_account(i, program_id));
        require_keys_eq!(*rem[at + 1 + i].key, want, OFTError::GapAccountMismatch);
    }
    Ok(NativeRoute { route, hops: [&rem[at + 1], &rem[at + 2]] })
}

/// Revert (PoolTouchedEarlier) if an earlier top-level instruction lists the official pool, a
/// used hop of the quote's route (unless the quote is stable), a used hop of the wSOL route
/// (unless wSOL is stable), or a vault of any of them.
#[cfg(not(feature = "stock-hops"))] pub fn refuse_earlier_touch(a: &GapAccounts, d: &GapData, tail: &Tail, native: Option<&NativeRoute>) -> Result<()> {
    let mut keys: Vec<[u8; 32]> = vec![a.pool.key.to_bytes()];
    if let Some(p) = d.pool {
        keys.push(p.vault_a);
        keys.push(p.vault_b);
    }
    let mut add_hops = |route: Option<&GapRoute>, hops: [&AccountInfo; 2], mint: &Pubkey| {
        let stable = d.global.as_ref().map_or(false, |g| g.is_stable(mint));
        if let (false, Some(r)) = (stable, route) {
            for info in hops.iter().take((r.hop_count as usize).min(2)) {
                keys.push(info.key.to_bytes());
                if let Some(p) = engine::read_pool(info) {
                    keys.push(p.vault_a);
                    keys.push(p.vault_b);
                }
            }
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

/// The checked accounts of a v3 store with its official pool set (GapPoolNotSet otherwise).
pub fn checked<'a, 'info>(a: &GapAccounts<'a, 'info>, tail: &Tail, program_id: &Pubkey) -> Result<GapData> {
    require!(tail.is_set(), OFTError::GapPoolNotSet);
    engine::check(a, tail, program_id)?.ok_or_else(|| error!(OFTError::GapPoolNotSet))
}

// ------------------------------------------------------------------ init_gap_price_log

#[derive(Accounts)]
pub struct InitGapPriceLog<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(seeds = [OFT_SEED, oft_store.token_escrow.as_ref()], bump = oft_store.bump)]
    pub oft_store: Account<'info, OFTStore>,
    /// CHECK: PDA(["GapPriceLog", oft_store]), created here (checked in apply)
    #[account(mut)]
    pub price_log: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

impl InitGapPriceLog<'_> {
    /// Lamports sent to the address beforehand do not block it (topped up, allocated, assigned).
    pub fn apply(ctx: &mut Context<InitGapPriceLog>) -> Result<()> {
        require!(is_v3_store(&ctx.accounts.oft_store.to_account_info()), OFTError::NotV3Store);
        let store = ctx.accounts.oft_store.key();
        let (key, bump) = pricelog::address(ctx.program_id, &store);
        let info = ctx.accounts.price_log.to_account_info();
        require_keys_eq!(*info.key, key, OFTError::PriceLogMismatch);
        require!(info.data_is_empty() && *info.owner == anchor_lang::system_program::ID, OFTError::PriceLogMismatch);
        let payer = ctx.accounts.payer.to_account_info();
        let system = ctx.accounts.system_program.to_account_info();
        let seeds: &[&[u8]] = &[pricelog::PRICE_LOG_SEED, store.as_ref(), &[bump]];
        let need = Rent::get()?.minimum_balance(pricelog::LEN);
        let have = info.lamports();
        if have == 0 {
            invoke_signed(
                &system_instruction::create_account(payer.key, info.key, need, pricelog::LEN as u64, ctx.program_id),
                &[payer.clone(), info.clone(), system.clone()],
                &[seeds],
            )?;
        } else {
            if have < need {
                anchor_lang::solana_program::program::invoke(
                    &system_instruction::transfer(payer.key, info.key, need - have),
                    &[payer.clone(), info.clone(), system.clone()],
                )?;
            }
            invoke_signed(&system_instruction::allocate(info.key, pricelog::LEN as u64), &[info.clone(), system.clone()], &[seeds])?;
            invoke_signed(&system_instruction::assign(info.key, ctx.program_id), &[info.clone(), system.clone()], &[seeds])?;
        }
        let mut d = info.try_borrow_mut_data()?;
        pricelog::init(&mut d, bump, &store);
        Ok(())
    }
}

// ------------------------------------------------------------------ record_price

#[derive(Accounts)]
pub struct RecordPrice<'info> {
    pub signer: Signer<'info>,
    #[account(seeds = [OFT_SEED, oft_store.token_escrow.as_ref()], bump = oft_store.bump)]
    pub oft_store: Account<'info, OFTStore>,
    #[account(address = oft_store.token_mint)]
    pub token_mint: InterfaceAccount<'info, anchor_spl::token_interface::Mint>,
    /// CHECK: the store's PriceLog (pricelog::open)
    #[account(mut)]
    pub price_log: UncheckedAccount<'info>,
}

impl RecordPrice<'_> {
    #[cfg(not(feature = "stock-hops"))] pub fn apply(ctx: &mut Context<RecordPrice>) -> Result<()> {
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
        let native = check_native_route(rem, GAP_ACCOUNTS, ctx.program_id)?;
        refuse_earlier_touch(&a, &d, &tail, Some(&native))?;
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

// stocks-d (v3.1): the hop readers of every kind (gap/hops.rs) replace the three above with the feature.
#[cfg(feature = "stock-hops")]
pub use super::hops::{live_prices, record_refuse_earlier_touch as refuse_earlier_touch, route_usd};
