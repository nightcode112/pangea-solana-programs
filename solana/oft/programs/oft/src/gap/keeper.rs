//! stocks-d (v3.1, MAIN Q93): the automatic re-anchor keeper of the concentrated (stock) gap routes.
//! Compiled only with `--features stock-hops` (docs/stocks-solana-gap-hop.md §4).
//!
//! * `set_stock_keeper(keeper)`: GapGlobal.admin sets or rotates the keeper key, kept in a NEW PDA
//!   ["StockKeeper"] (no GapGlobal layout change; the default key = no keeper).
//! * `set_route_anchor(quote_mint, expected_price)`: the keeper ONLY. Re-anchors an EXISTING
//!   concentrated route from the pool itself, refused when the pool's price is more than 2% from the
//!   keeper's expected price (its independent median, micro-USD, lead8 L119): the anchor moves toward
//!   the hop's current price by at most 1/8 (12.5%) of the old anchor per call, at most once per
//!   MIN_REANCHOR_SECS per route, and never outside [x0.6699, x1.4238] (343/512, 729/512) of the
//!   REGISTRATION anchor stored by `set_stock_route` (MAIN Q97, lead8 L152, stocks-d-a5 M1: a distance
//!   bound, not a call count; 7006). The keeper never changes the floors (only the
//!   registrar, `set_stock_route`: a4 L1 / L3), chooses no value, creates no route, moves no funds.
//!   Top level only; an earlier top-level instruction naming the pool or a vault is refused (as the
//!   price paths). Emits `RouteAnchorSet`.
use super::hops::{self, ANCHOR_AT, ANCHOR_UNIT};
use super::introspect;
use super::state::*;
use crate::*;
use anchor_lang::solana_program::sysvar::instructions::ID as INSTRUCTIONS_SYSVAR_ID;

pub const STOCK_KEEPER_SEED: &[u8] = b"StockKeeper";
/// Max anchor step per re-anchor: 1/2^REANCHOR_STEP_SHIFT of the old anchor (12.5%).
pub const REANCHOR_STEP_SHIFT: u32 = 3;
/// Min seconds between two re-anchors of one route.
pub const MIN_REANCHOR_SECS: u32 = 600;
/// The pool's price may differ from the keeper's expected price (micro-USD, its independent median)
/// by at most expected / EXPECTED_TOLERANCE_DIV (2%), else PriceMismatch (lead8 L119: a pump between
/// the keeper's off-chain check and its send fails on chain instead of pulling the anchor).
pub const EXPECTED_TOLERANCE_DIV: u64 = 50;
/// MAIN Q97 / lead8 L152 (stocks-d-a5 M1): the anchor never leaves [REG x 343/512, REG x 729/512] =
/// [x0.6699, x1.4238] of the REGISTRATION anchor REG (= (7/8)^3 and (9/8)^3: three 12.5% steps), REG
/// stored by `set_stock_route` (u64 LE in the first 8 bytes of hops[1].pool, an all-zero slot on a
/// 1-hop route; `reg_anchor_of`). A re-anchor outside -> 7006 NetStepCap (page; the registrar re-registers
/// after the Q86 tool). The bound is a DISTANCE, not a call count.
pub const BAND_UP_NUM: u128 = 729;
pub const BAND_DOWN_NUM: u128 = 343;
pub const BAND_DEN: u128 = 512;
/// GapRoute.reserved[LAST_AT..+4]: the unix time (u32 LE) of the route's last re-anchor (0 = never).
pub const LAST_AT: usize = 28;

#[account]
#[derive(InitSpace)]
pub struct StockKeeper {
    pub version: u8,
    pub bump: u8,
    /// The keeper key (the default key: none).
    pub keeper: Pubkey,
}

#[error_code(offset = 7000)]
pub enum StockKeeperError {
    #[msg("not the stock keeper")]
    NotStockKeeper,
    #[msg("re-anchored less than MIN_REANCHOR_SECS ago")]
    ReanchorTooSoon,
    #[msg("not a concentrated 1-hop route")]
    NotStockRoute,
    #[msg("the hop pool is unreadable or not the route's")]
    HopUnreadable,
    #[msg("the anchor or a floor would be 0")]
    ZeroAnchor,
    #[msg("the pool price differs from the keeper's expected price by more than 2%")]
    PriceMismatch,
    #[msg("the anchor would leave [x0.6699, x1.4238] of the registration anchor: the registrar re-registers")]
    NetStepCap,
    #[msg("a role key must differ from every other current or pending role key (admin, pending admin, registrar, delivery, co-sign, keeper)")]
    KeeperNotDistinct,
}

#[event]
pub struct StockKeeperSet {
    pub old: Pubkey,
    pub new: Pubkey,
}

#[event]
pub struct RouteAnchorSet {
    pub quote_mint: Pubkey,
    pub pool: Pubkey,
    /// micro-USD per whole quote token
    pub old_anchor: u64,
    pub new_anchor: u64,
    /// the pool's price now (micro-USD), before the step limit
    pub price: u64,
    /// the keeper's expected price (micro-USD)
    pub expected: u64,
    pub floor_b: u64,
    pub floor_a: u64,
    pub at: u32,
}

#[derive(Accounts)]
pub struct SetStockKeeper<'info> {
    pub admin: Signer<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(seeds = [GAP_GLOBAL_SEED], bump = gap_global.bump, has_one = admin @OFTError::NotGapAdmin)]
    pub gap_global: Box<Account<'info, GapGlobal>>,
    #[account(init_if_needed, payer = payer, space = 8 + StockKeeper::INIT_SPACE, seeds = [STOCK_KEEPER_SEED], bump)]
    pub stock_keeper: Account<'info, StockKeeper>,
    pub system_program: Program<'info, System>,
}

pub fn set_stock_keeper(ctx: &mut Context<SetStockKeeper>, keeper: Pubkey) -> Result<()> {
    // stocks-d-a4 I3 / a5 L1 / lead8 L152: a separate, narrow key (the default key = no keeper)
    let g = &ctx.accounts.gap_global;
    require!(keeper == Pubkey::default() || other_role(g, &keeper, Role::Keeper, &Pubkey::default()).is_none(), StockKeeperError::KeeperNotDistinct);
    let k = &mut ctx.accounts.stock_keeper;
    let old = k.keeper;
    k.version = 1;
    k.bump = ctx.bumps.stock_keeper;
    k.keeper = keeper;
    emit!(StockKeeperSet { old, new: keeper });
    Ok(())
}

#[derive(Accounts)]
#[instruction(quote_mint: Pubkey, expected_price: u64)]
pub struct SetRouteAnchor<'info> {
    pub keeper: Signer<'info>,
    #[account(seeds = [STOCK_KEEPER_SEED], bump = stock_keeper.bump, constraint = stock_keeper.keeper == keeper.key() && keeper.key() != Pubkey::default() @StockKeeperError::NotStockKeeper)]
    pub stock_keeper: Account<'info, StockKeeper>,
    #[account(mut, seeds = [GAP_ROUTE_SEED, quote_mint.as_ref()], bump = gap_route.bump)]
    pub gap_route: Account<'info, GapRoute>,
    /// CHECK: the route's hop 0 pool (checked against the route, read per its kind)
    pub pool: UncheckedAccount<'info>,
    /// CHECK: the instructions sysvar (address checked)
    #[account(address = INSTRUCTIONS_SYSVAR_ID)]
    pub instructions: UncheckedAccount<'info>,
}

fn u64_at(r: &[u8; 32], at: usize) -> u64 {
    u64::from_le_bytes(r[at..at + 8].try_into().unwrap())
}

/// REG x 343/512 <= a <= REG x 729/512 (exact, u128: a and REG are u64).
pub fn within_reg_band(a: u128, reg: u128) -> bool {
    a * BAND_DEN <= reg * BAND_UP_NUM && a * BAND_DEN >= reg * BAND_DOWN_NUM
}

/// |price - expected| <= expected / 50 (expected 0: never).
pub fn near_expected(price: u64, expected: u64) -> bool {
    expected != 0 && price.abs_diff(expected) <= expected / EXPECTED_TOLERANCE_DIV
}

pub fn set_route_anchor(ctx: &mut Context<SetRouteAnchor>, quote_mint: Pubkey, expected_price: u64) -> Result<()> {
    use anchor_lang::solana_program::instruction::{get_stack_height, TRANSACTION_LEVEL_STACK_HEIGHT};
    require!(get_stack_height() == TRANSACTION_LEVEL_STACK_HEIGHT, OFTError::SendViaCpi);
    let r = &ctx.accounts.gap_route;
    require!(r.quote_mint == quote_mint && r.hop_count == 1 && hops::floored(r.hops[0].kind), StockKeeperError::NotStockRoute);
    let hop = r.hops[0];
    let info = ctx.accounts.pool.to_account_info();
    require_keys_eq!(*info.key, hop.pool, StockKeeperError::HopUnreadable);
    let hv = hops::read_hop(hop.kind, &info).ok_or(StockKeeperError::HopUnreadable)?;
    // the pinned orientation: token_in is token A
    require!(hv.side(&hop.token_in.to_bytes(), &hop.token_out.to_bytes()) == Some(true), StockKeeperError::HopUnreadable);
    if let Some(d) = hv.decimals {
        require!(d == (r.reserved[0], r.reserved[1]), StockKeeperError::HopUnreadable);
    }
    // the same-transaction guard of the price paths: the pool and its vaults
    {
        let keys = [info.key.to_bytes(), hv.vault_a, hv.vault_b];
        let data = ctx.accounts.instructions.try_borrow_data()?;
        let touched = introspect::touched_earlier(&data, &keys).ok_or(OFTError::GapAccountMismatch)?;
        require!(!touched, OFTError::PoolTouchedEarlier);
    }
    let now = u32::try_from(Clock::get()?.unix_timestamp).unwrap_or(u32::MAX);
    let last = u32::from_le_bytes(r.reserved[LAST_AT..LAST_AT + 4].try_into().unwrap());
    require!(last == 0 || now.saturating_sub(last) >= MIN_REANCHOR_SECS, StockKeeperError::ReanchorTooSoon);
    // the price now (rounded down), micro-USD
    let p = hv.price(true, r.reserved[0], r.reserved[1], false).filter(|p| *p != super::math::PRICE_MAX).ok_or(StockKeeperError::HopUnreadable)?;
    let price = u64::try_from(p / ANCHOR_UNIT).unwrap_or(u64::MAX);
    require!(near_expected(price, expected_price), StockKeeperError::PriceMismatch);
    let old = u64_at(&r.reserved, ANCHOR_AT);
    // the step limit: at most old / 8 toward the price (an old anchor 0 never happens: set_gap_route refuses it)
    let step = old >> REANCHOR_STEP_SHIFT;
    let new = price.clamp(old.saturating_sub(step), old.saturating_add(step));
    require!(new != 0, StockKeeperError::ZeroAnchor);
    // the registration band (a5 M1 / Q97): REG x 343/512 <= new <= REG x 729/512
    let reg = hops::reg_anchor_of(r) as u128;
    require!(reg != 0 && within_reg_band(new as u128, reg), StockKeeperError::NetStepCap);
    // the floors are the registrar's (never changed here: a4 L1 / L3); reported in the event
    let (fb, fa) = hops::floors_of(r, 0);
    let r = &mut ctx.accounts.gap_route;
    r.reserved[ANCHOR_AT..ANCHOR_AT + 8].copy_from_slice(&new.to_le_bytes());
    r.reserved[LAST_AT..LAST_AT + 4].copy_from_slice(&now.max(1).to_le_bytes());
    emit!(RouteAnchorSet { quote_mint, pool: hop.pool, old_anchor: old, new_anchor: new, price, expected: expected_price, floor_b: fb, floor_a: fa, at: now });
    Ok(())
}

// ------------------------------------------------------------------ symmetric role keys (a5 L1, lead8 L152)

/// The roles whose keys must all differ (the default key is an empty slot, never a role).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    Admin,
    PendingAdmin,
    Registrar,
    Delivery,
    Cosigner,
    Keeper,
}

/// The first OTHER current or pending role that holds `key` (None: free), `keeper` the StockKeeper key.
/// `as_role` is the role being set (its own current holder does not count).
pub fn other_role(g: &GapGlobal, key: &Pubkey, as_role: Role, keeper: &Pubkey) -> Option<Role> {
    if *key == Pubkey::default() {
        return None;
    }
    let held = [
        (Role::Admin, *key == g.admin),
        (Role::PendingAdmin, *key == g.pending_admin),
        (Role::Registrar, *key == g.registrar),
        (Role::Delivery, g.is_delivery(key)),
        (Role::Cosigner, g.is_cosigner(key)),
        (Role::Keeper, *key == *keeper),
    ];
    // the admin and its own pending successor are one role (proposing the admin itself cancels)
    let same = |r: Role| r == as_role || (matches!(as_role, Role::Admin | Role::PendingAdmin) && matches!(r, Role::Admin | Role::PendingAdmin));
    held.iter().find(|(r, h)| *h && !same(*r)).map(|(r, _)| *r)
}

/// The StockKeeper key, from the PDA the feature build's role setters take as their FIRST remaining
/// account (it must be the PDA; a PDA not created yet = no keeper).
pub fn keeper_from(rem: &[AccountInfo], program_id: &Pubkey) -> Result<Pubkey> {
    let info = rem.first().ok_or(OFTError::GapAccountMismatch)?;
    require_keys_eq!(*info.key, Pubkey::find_program_address(&[STOCK_KEEPER_SEED], program_id).0, OFTError::GapAccountMismatch);
    Ok(read_owned::<StockKeeper>(info, program_id).map_or(Pubkey::default(), |k| k.keeper))
}

/// The feature build's role setters (the originals are cfg'd out on their fn line): every key distinct
/// from every OTHER current or pending role incl. the keeper (7007), plus the originals' own checks.
/// Accounts: the originals' + the StockKeeper PDA as the first remaining account.
impl crate::instructions::gap_admin::GapAdmin<'_> {
    pub fn propose_admin(ctx: &mut Context<crate::instructions::gap_admin::GapAdmin>, pending_admin: Pubkey) -> Result<()> {
        require!(pending_admin != Pubkey::default(), OFTError::DefaultKey);
        let keeper = keeper_from(ctx.remaining_accounts, ctx.program_id)?;
        let g = &mut ctx.accounts.gap_global;
        require!(!g.is_cosigner(&pending_admin), OFTError::BadCosigner);
        require!(other_role(g, &pending_admin, Role::PendingAdmin, &keeper).is_none(), StockKeeperError::KeeperNotDistinct);
        g.pending_admin = pending_admin;
        emit!(GapAdminProposed { admin: g.admin, pending_admin });
        Ok(())
    }
    pub fn set_registrar(ctx: &mut Context<crate::instructions::gap_admin::GapAdmin>, registrar: Pubkey) -> Result<()> {
        require!(registrar != Pubkey::default(), OFTError::DefaultKey);
        let keeper = keeper_from(ctx.remaining_accounts, ctx.program_id)?;
        require!(!ctx.accounts.gap_global.is_cosigner(&registrar), OFTError::BadCosigner);
        require!(other_role(&ctx.accounts.gap_global, &registrar, Role::Registrar, &keeper).is_none(), StockKeeperError::KeeperNotDistinct);
        ctx.accounts.gap_global.registrar = registrar;
        emit!(GapRegistrarSet { registrar });
        Ok(())
    }
    pub fn set_cosigners(ctx: &mut Context<crate::instructions::gap_admin::GapAdmin>, keys: [Pubkey; COSIGNER_SLOTS]) -> Result<()> {
        crate::instructions::gap_admin::require_distinct(&keys)?;
        let keeper = keeper_from(ctx.remaining_accounts, ctx.program_id)?;
        let g = &mut ctx.accounts.gap_global;
        for k in keys.iter().filter(|k| **k != Pubkey::default()) {
            require!(*k != g.admin && *k != g.pending_admin && *k != g.registrar && !g.is_delivery(k), OFTError::BadCosigner);
            require!(other_role(g, k, Role::Cosigner, &keeper).is_none(), StockKeeperError::KeeperNotDistinct);
        }
        g.cosigners = keys;
        emit!(GapCosignersSet { cosigners: keys });
        Ok(())
    }
    pub fn set_delivery(ctx: &mut Context<crate::instructions::gap_admin::GapAdmin>, keys: [Pubkey; DELIVERY_SLOTS]) -> Result<()> {
        crate::instructions::gap_admin::require_distinct(&keys)?;
        let keeper = keeper_from(ctx.remaining_accounts, ctx.program_id)?;
        // L-2: a delivery key is never a co-sign key
        require!(!keys.iter().any(|k| ctx.accounts.gap_global.is_cosigner(k)), OFTError::BadCosigner);
        for k in keys.iter() {
            require!(other_role(&ctx.accounts.gap_global, k, Role::Delivery, &keeper).is_none(), StockKeeperError::KeeperNotDistinct);
        }
        ctx.accounts.gap_global.delivery = keys;
        emit!(GapDeliverySet { keys });
        Ok(())
    }
}

impl crate::instructions::gap_admin::AcceptGapAdmin<'_> {
    /// The proposed admin takes over; it must still be distinct from every other role (the keeper too).
    pub fn apply(ctx: &mut Context<crate::instructions::gap_admin::AcceptGapAdmin>) -> Result<()> {
        let keeper = keeper_from(ctx.remaining_accounts, ctx.program_id)?;
        let g = &mut ctx.accounts.gap_global;
        let who = ctx.accounts.pending_admin.key();
        require!(g.pending_admin != Pubkey::default() && who == g.pending_admin, OFTError::NotPendingAdmin);
        require!(!g.is_cosigner(&who), OFTError::BadCosigner);
        require!(other_role(g, &who, Role::Admin, &keeper).is_none(), StockKeeperError::KeeperNotDistinct);
        g.admin = who;
        g.pending_admin = Pubkey::default();
        emit!(GapAdminSet { admin: who });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_step_clamp() {
        let clamp = |old: u64, price: u64| {
            let s = old >> REANCHOR_STEP_SHIFT;
            price.clamp(old.saturating_sub(s), old.saturating_add(s))
        };
        assert_eq!(clamp(800, 1_000), 900);
        assert_eq!(clamp(800, 100), 700);
        assert_eq!(clamp(800, 850), 850);
        assert_eq!(clamp(8, 0), 7);
        assert_eq!(clamp(u64::MAX, u64::MAX), u64::MAX);
        assert_eq!(STOCK_KEEPER_SEED, b"StockKeeper");
        assert!(LAST_AT + 4 <= 32 && ANCHOR_AT + 8 <= LAST_AT);
        // the band: (9/8)^3 = 729/512 up, (7/8)^3 = 343/512 down
        assert_eq!((BAND_UP_NUM, BAND_DOWN_NUM, BAND_DEN), (9 * 9 * 9, 7 * 7 * 7, 8 * 8 * 8));
        for (a, ok) in [(1_000_000u128, true), (1_423_828, true), (1_423_829, false), (669_922, true), (669_921, false)] {
            assert_eq!(within_reg_band(a, 1_000_000), ok, "{a}");
        }
        // 2%: 1,000,000 accepts 980,000..=1,020,000
        for (p, ok) in [(1_000_000u64, true), (980_000, true), (1_020_000, true), (979_999, false), (1_020_001, false), (0, false)] {
            assert_eq!(near_expected(p, 1_000_000), ok, "{p}");
        }
        assert!(!near_expected(0, 0) && !near_expected(5, 0));
    }
}
