//! The gap fee on accounts: the §10.4 account checks, the earlier-instruction check, the USD
//! price through the official pool and the route, and the destination's withholding. Every data
//! read is an Option. v3c (spec §3): on receive, an unreadable price, fee or pool HOLDS the
//! message (a retriable revert, `hold`), never fee 0; on send a failure is still a price of 0
//! (the send's builder owns that). The accounts the executor or sender chooses (keys) and Q3 revert.
use super::math;
use super::pool::{self, PoolView};
use super::state::*;
use super::introspect;
use super::pricelog;
use crate::*;
use anchor_lang::solana_program::sysvar::instructions::ID as INSTRUCTIONS_SYSVAR_ID;

/// The six gap accounts, in §10.4 order.
pub const GAP_ACCOUNTS: usize = 6;

pub struct GapAccounts<'a, 'info> {
    pub global: &'a AccountInfo<'info>,
    pub route: &'a AccountInfo<'info>,
    pub pool: &'a AccountInfo<'info>,
    pub hop0: &'a AccountInfo<'info>,
    pub hop1: &'a AccountInfo<'info>,
    pub ixs: &'a AccountInfo<'info>,
}

impl<'a, 'info> GapAccounts<'a, 'info> {
    pub fn at(rem: &'a [AccountInfo<'info>], at: usize) -> Result<Self> {
        require!(rem.len() >= at + GAP_ACCOUNTS, OFTError::GapAccountMismatch);
        Ok(GapAccounts { global: &rem[at], route: &rem[at + 1], pool: &rem[at + 2], hop0: &rem[at + 3], hop1: &rem[at + 4], ixs: &rem[at + 5] })
    }
}

/// What the checked accounts hold.
pub struct GapData {
    /// Boxed: GapGlobal is 912 bytes (8 + INIT_SPACE, state::GAP_GLOBAL_LEN) and the receive's frame is near the 4 KB limit.
    pub global: Option<Box<GapGlobal>>,
    pub route: Option<GapRoute>,
    pub pool: Option<PoolView>,
}

pub fn pda_matches(key: &Pubkey, seeds: &[&[u8]], bump: Option<u8>, program_id: &Pubkey) -> bool {
    if let Some(b) = bump {
        let mut s: Vec<&[u8]> = seeds.to_vec();
        let bb = [b];
        s.push(&bb);
        if let Ok(k) = Pubkey::create_program_address(&s, program_id) {
            return k == *key;
        }
    }
    Pubkey::find_program_address(seeds, program_id).0 == *key
}

pub fn read_pool(info: &AccountInfo) -> Option<PoolView> {
    if *info.owner != CP_AMM_ID {
        return None;
    }
    pool::read(&info.try_borrow_data().ok()?)
}

/// Whether a composed v1 arrival for `to` gets a `GapReceipt` (spec §10.5, audit round 1 Solana
/// L-1): only when `to` is an allowlisted composer (`GapGlobal.composers`). `global` must be the
/// `["GapGlobal"]` PDA (revert otherwise, retriable: the executor chose it); a GapGlobal that does
/// not exist lists no composer.
pub fn receipt_for(global: &AccountInfo, to: &Pubkey, program_id: &Pubkey) -> Result<bool> {
    Ok(read_global(global, program_id)?.map_or(false, |g| g.is_composer(to)))
}

/// §10.4: every gap account must be the derived or recorded key (revert otherwise, retriable on
/// receive). Nothing is read while the store has no official pool.
pub fn check(a: &GapAccounts, tail: &Tail, program_id: &Pubkey) -> Result<Option<GapData>> {
    if !tail.is_set() {
        return Ok(None);
    }
    let global = read_global(a.global, program_id)?;
    require_keys_eq!(*a.pool.key, tail.pool, OFTError::GapAccountMismatch);
    let route: Option<GapRoute> = read_owned(a.route, program_id);
    require!(
        pda_matches(a.route.key, &[GAP_ROUTE_SEED, tail.quote_mint.as_ref()], route.as_ref().map(|r| r.bump), program_id),
        OFTError::GapAccountMismatch
    );
    for (i, hop) in [a.hop0, a.hop1].iter().enumerate() {
        let want = route.as_ref().map_or(*program_id, |r| r.hop_account(i, program_id));
        require_keys_eq!(*hop.key, want, OFTError::GapAccountMismatch);
    }
    require_keys_eq!(*a.ixs.key, INSTRUCTIONS_SYSVAR_ID, OFTError::GapAccountMismatch);
    Ok(Some(GapData { global, route, pool: read_pool(a.pool) }))
}

/// LayerZero's Solana executor program (mainnet; `executor` in LayerZero-v2 c09287a's
/// Anchor.toml and `declare_id!`). Its `execute` CPIs `lz_receive`, gated to its own executor keys
/// (`ExecutorConfig.executors`, NotExecutor 6007 -- checked on the mainnet fork).
pub const LZ_EXECUTOR_ID: Pubkey = pubkey!("6doghB248px58JSSwG4qejQ46kFMW4AMj7vzJnWZHNZn");

/// A v3 `lz_receive` runs at the top level (our delivery keys; anyone for the escape, a refund or
/// SEED_NO_POOL) or directly under LayerZero's executor `execute` (stack height 2,
/// the current top-level instruction the executor's). Anything else could move a pool inside the
/// same top-level instruction, where the earlier-instruction check cannot see it (round 1, H-2).
pub fn refuse_foreign_cpi(ixs: &AccountInfo) -> Result<()> {
    use anchor_lang::solana_program::instruction::{get_stack_height, TRANSACTION_LEVEL_STACK_HEIGHT};
    let h = get_stack_height();
    if h == TRANSACTION_LEVEL_STACK_HEIGHT {
        return Ok(());
    }
    require!(h == TRANSACTION_LEVEL_STACK_HEIGHT + 1, OFTError::ReceiveViaCpi);
    require_keys_eq!(*ixs.key, INSTRUCTIONS_SYSVAR_ID, OFTError::GapAccountMismatch);
    let data = ixs.try_borrow_data()?;
    let program = introspect::current_program(&data).ok_or(OFTError::GapAccountMismatch)?;
    require!(program == LZ_EXECUTOR_ID.to_bytes(), OFTError::ReceiveViaCpi);
    Ok(())
}

/// Revert if an earlier top-level instruction lists a pool the price reads: the official pool,
/// and, when the quote is priced through the route, each used hop pool; each with both vaults.
#[cfg(not(feature = "stock-hops"))] pub fn refuse_earlier_touch(a: &GapAccounts, d: &GapData, tail: &Tail) -> Result<()> {
    let mut keys: Vec<[u8; 32]> = vec![a.pool.key.to_bytes()];
    if let Some(p) = d.pool {
        keys.push(p.vault_a);
        keys.push(p.vault_b);
    }
    let stable = d.global.as_ref().map_or(false, |g| g.is_stable(&tail.quote_mint));
    if let (false, Some(r)) = (stable, d.route.as_ref()) {
        // `check` made each hop account the route's pool for a used slot
        for info in [a.hop0, a.hop1].iter().take((r.hop_count as usize).min(2)) {
            keys.push(info.key.to_bytes());
            if let Some(p) = read_pool(info) {
                keys.push(p.vault_a);
                keys.push(p.vault_b);
            }
        }
    }
    let data = a.ixs.try_borrow_data()?;
    let touched = introspect::touched_earlier(&data, &keys).ok_or(OFTError::GapAccountMismatch)?;
    require!(!touched, OFTError::PoolTouchedEarlier);
    Ok(())
}

/// The official pool's fee, ppm, rounded up; Err(DST_FEE_FAILED) if unreadable,
/// Err(UNSUPPORTED_FEE_MODE) if it is not a flat base fee.
pub fn pool_fee_ppm(d: &GapData) -> core::result::Result<u32, u8> {
    d.pool.ok_or(math::DST_FEE_FAILED)?.flat_fee_ppm()
}

/// The destination's outcome for one receive that credits (v3c, spec §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub withheld: u64,
    pub reason: u8,
    /// The pair compared: the class prices (pair_class != 0) or the USD prices (pair_class 0).
    pub ps_e18: u128,
    pub pd_e18: u128,
    pub gap_ppm: u32,
    pub allow_ppm: u64,
    pub pair_class: u8,
    /// Amendment 6: the margin used (0 when the formula did not run).
    pub margin_ppm: u32,
    /// Amendment 6: the gas cover in the allowance, ppm (0 = none).
    pub cover_ppm: u32,
    /// Amendment 6: this store's own swap gas, floor(dstGasUsd / 1e12) micro-dollars (0 when not read).
    pub dst_gas_micro_usd: u32,
    /// Owner (A): a writer reward the PriceLog's full reward table forfeited at this receive's own
    /// write (the caller lowers the store's reserved total by it).
    pub forfeited: u64,
    /// Step 3: `land_held_receive` priced this arrival at r0 because the capacity walk could not
    /// cover it (no capacity consumed).
    pub oversized: bool,
    /// oft-q7 (owner Q7): the delivery cost withheld into the store's escrow (LD), charged on a
    /// price-path arrival our keys deliver (a GapGlobal.delivery key at the top level, or
    /// `land_held_receive`); 0 under LayerZero's executor and on the fee-0 paths.
    pub delivery_ld: u64,
    /// The GapGlobal.delivery_lamports it was priced from (0 when not charged).
    pub delivery_lamports: u32,
    /// The SOL/USD it was valued at (the whole window's minimum; 0 when not charged).
    pub delivery_sol_usd: u128,
    /// oft-fix M-1: the part of `delivery_lamports` that is the recipient token account's rent
    /// (oft-lows I-2: what its creation actually cost), when our keys' delivery created it and
    /// GapGlobal.ata_lamports is on; 0 otherwise.
    pub ata_lamports: u32,
}

impl Outcome {
    pub fn skipped(reason: u8) -> Self {
        Outcome { withheld: 0, reason, ps_e18: 0, pd_e18: 0, gap_ppm: 0, allow_ppm: 0, pair_class: 0, margin_ppm: 0, cover_ppm: 0, dst_gas_micro_usd: 0, forfeited: 0, oversized: false, delivery_ld: 0, delivery_lamports: 0, delivery_sol_usd: 0, ata_lamports: 0 }
    }
}

/// The official pool's price of the store's token in its quote (1e18 per whole token), rounded
/// up (`up`) or down; None when the pool is unreadable or does not hold the tail's side.
pub fn pool_price(d: &GapData, tail: &Tail, token_mint: &Pubkey, up: bool) -> Option<u128> {
    let pv = d.pool?;
    if pv.side(&token_mint.to_bytes(), &tail.quote_mint.to_bytes())? != tail.token_is_a {
        return None;
    }
    pv.price(tail.token_is_a, tail.token_decimals, tail.quote_decimals, up).filter(|p| *p != 0)
}

/// The `["GapGlobal"]` account as passed: None when it does not exist (yet); a wrong key reverts
/// (retriable: the executor chose it).
pub fn read_global(info: &AccountInfo, program_id: &Pubkey) -> Result<Option<Box<GapGlobal>>> {
    let g: Option<Box<GapGlobal>> = read_owned::<GapGlobal>(info, program_id).map(Box::new);
    require!(pda_matches(info.key, &[GAP_GLOBAL_SEED], g.as_ref().map(|g| g.bump), program_id), OFTError::GapAccountMismatch);
    Ok(g)
}

/// The destination's prices for the formula (v3c §3 with Amendment 4), each rounded down:
/// Pd = max(live, PriceLog window maximum) for the USD price and the pool price in the quote; the
/// live value 0 (unreadable) stays 0. (Amendment 6: no depth; the margin is fixed.)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DstPrices {
    pub pd_usd: u128,
    pub pd_quote: u128,
}

fn higher_known(live: u128, window: u128) -> u128 {
    if live == 0 { 0 } else { live.max(window) }
}

pub fn dst_prices(live: &pricelog::Live, win: &pricelog::Window) -> DstPrices {
    DstPrices { pd_usd: higher_known(live.usd_down, win.usd_max), pd_quote: higher_known(live.cls_down, win.cls_max) }
}

/// Spec §3 rules 4-6 for a store whose official pool is set, `d` from `check`, `p` the PriceLog
/// window prices: the outcome, or Err(reason) when the receive must hold (revert `GapUnreadable`,
/// retriable):
///   PS_ZERO           psUsd 0 and the class pair unusable;
///   DST_FEE_FAILED    the pool fee unreadable (or >= 1e6);
///   UNSUPPORTED_FEE_MODE  the pool fee is not a flat base fee;
///   DST_PRICE_FAILED  GapGlobal missing; no pair readable; or (Amendment 6, a CHARGED message
///                     whose source granted a cover, both caps and swap_lamports non-zero) the
///                     PriceLog window's SOL/USD minimum is 0.
/// The class pair: the message's class equals this store's quote class (non-zero) and both class
/// prices are known; Pd_class is the pool price in the quote (window maximum), no hop. Otherwise
/// the USD pair. Then Amendment 6 `math::gap_priced` at GapGlobal.margin_ppm: r0 without a cover;
/// only a CHARGED r0 with a source cover (srcCoverCapCents != 0) and a cover cap here reads
/// `sol_usd()` (the WHOLE window's SOL/USD minimum, never the consumed entries'), and only for
/// swap_lamports != 0. The cover is valued at the header's psUsd.
pub fn priced_outcome(amount_ld: u64, h: &math::Header, d: &GapData, tail: &Tail, p: &DstPrices, sol_usd: impl FnOnce() -> u128) -> core::result::Result<Outcome, u8> {
    let global = d.global.as_ref();
    let dst_class = global.map_or(0, |g| g.class_of(&tail.quote_mint));
    let pd_class = if h.price_class != 0 && h.price_class == dst_class && h.ps_class_e18 != 0 { p.pd_quote } else { 0 };
    // rule 4
    if h.ps_e18 == 0 && pd_class == 0 {
        return Err(math::PS_ZERO);
    }
    // rule 5
    let fee_dst = pool_fee_ppm(d)?;
    if fee_dst as u128 >= math::PPM {
        return Err(math::DST_FEE_FAILED);
    }
    let global = global.ok_or(math::DST_PRICE_FAILED)?;
    let (ps, pd, is_class) = math::pick_pair(h.price_class, h.ps_class_e18, h.ps_e18, dst_class, pd_class, p.pd_usd).ok_or(math::DST_PRICE_FAILED)?;
    // rule 6 (Amendment 6 §4)
    let margin = global.margin_ppm;
    let swap = global.swap_lamports;
    let r = math::gap_priced(amount_ld, ps, pd, h.ps_e18, h.fee_src_ppm, fee_dst, h.bridge_fee_ppm, margin, tail.token_decimals, h.src_gas_micro_usd, h.src_cover_cap_cents, global.cover_cap_cents, || math::solana_gas_usd_e18(swap as u64, sol_usd));
    if r.holds {
        return Err(math::DST_PRICE_FAILED);
    }
    let g = r.fee;
    match g.reason {
        math::CHARGED | math::NO_GAP | math::WITHIN_ALLOWANCE => {}
        // DEAD (round 2 A I-5, kept as a guard): unreachable -- both prices are non-zero and
        // fee_dst < 1e6 here, so math::gap_priced returns only the three reasons above
        other => return Err(other),
    }
    Ok(Outcome {
        withheld: g.withheld,
        reason: g.reason,
        ps_e18: ps,
        pd_e18: pd,
        gap_ppm: g.gap_ppm,
        allow_ppm: g.allow_ppm,
        pair_class: if is_class { dst_class } else { 0 },
        margin_ppm: margin,
        cover_ppm: r.cover_ppm,
        dst_gas_micro_usd: (r.dst_gas_usd_e18 / math::MICRO_USD_E18).min(u32::MAX as u128) as u32,
        forfeited: 0,
        oversized: false,
        delivery_ld: 0,
        delivery_lamports: 0,
        delivery_sol_usd: 0,
        ata_lamports: 0,
    })
}

/// A delivery key's (or the admin's) Pd floors from the receive's `extra_data` (LE): 16 bytes = the
/// USD floor (USD 1e18 per whole token) alone; 32 bytes = the USD floor | the class floor (the
/// store's quote units 1e18 per whole token, for a receive priced on the class pair). Any other
/// length: no floor. Round 2 (B L-3 / A I-3): a floor binds the pair the receive actually prices.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Floors {
    pub usd: u128,
    pub cls: u128,
}

impl Floors {
    pub fn read(extra_data: &[u8]) -> Floors {
        let at = |i: usize| u128::from_le_bytes(extra_data[i..i + 16].try_into().unwrap());
        match extra_data.len() {
            16 => Floors { usd: at(0), cls: 0 },
            32 => Floors { usd: at(0), cls: at(16) },
            _ => Floors::default(),
        }
    }

    /// The floor of the pair priced: class units for the class pair (pair_class != 0), else USD.
    pub fn for_pair(&self, pair_class: u8) -> u128 {
        if pair_class != 0 { self.cls } else { self.usd }
    }

    /// `p` with each Pd raised to its floor (a 0 Pd, unreadable, stays 0: never a new pair).
    pub fn raise(&self, p: &DstPrices) -> DstPrices {
        DstPrices { pd_usd: higher_known(p.pd_usd, self.usd), pd_quote: higher_known(p.pd_quote, self.cls) }
    }
}

/// Who runs a receive's price path (R1'). A key's floors always RAISE Pd (round 2 H-1 (3): the
/// receive is priced at max(Pd, floor) for the pair priced), never lower it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    /// (b) directly under LayerZero's executor `execute` (gated to ExecutorConfig.executors).
    ExecutorCpi,
    /// (c) a GapGlobal delivery key at the top level, or (d) `land_held_receive`'s payer (admin or
    /// delivery key, checked by the instruction), with the floors it passed.
    Key { floors: Floors, delivery: bool },
}

/// R1': who may run a receive's PRICE path. Err(GapReceiveNotAllowed) for anything but:
///   (b) directly under the executor's `execute` (stack height 2; `refuse_foreign_cpi` has checked
///       the top-level program is the executor, whose `execute` refuses any signer not in
///       ExecutorConfig.executors -- NotExecutor, checked on the mainnet fork);
///   (c) top level, `payer` (the account lz_receive_types lists first, the transaction's signer)
///       one of GapGlobal.delivery, with its floors;
///   (d) `land_held_receive` (top level, payer GapGlobal.admin or a delivery key, held_allowed).
/// Round 2 (R1'(a), lead #4/#5): the top-level `pre_execute` / `lz_receive` / `post_execute`
/// sandwich is NOT a shape any more and nothing here looks for it (the instructions-sysvar sandwich
/// check is removed): run on a mainnet-fork validator holding the live executor 6doghB24...
/// (solana/client/lz-executor-gating-fork.sh), a FRESH RANDOM key runs [pre_execute, anything,
/// post_execute] -- neither instruction checks ExecutorConfig.executors (their accounts are
/// [executor signer, context PDA, system, instructions sysvar]); only `execute` / `compose` /
/// `native_drop` take the config and refuse NotExecutor. So a top-level receive by anything but a
/// delivery key (or land_held_receive's payer) is refused GapReceiveNotAllowed (retriable, nothing
/// consumed), sandwiched or not. LayerZero's executor delivers a v3 price-path arrival through
/// `execute`, or our delivery keys do.
pub fn r1_allowed(payer: &Pubkey, global: Option<&GapGlobal>, extra_data: &[u8], admin_land: bool) -> Result<Gate> {
    use anchor_lang::solana_program::instruction::{get_stack_height, TRANSACTION_LEVEL_STACK_HEIGHT};
    if get_stack_height() != TRANSACTION_LEVEL_STACK_HEIGHT {
        return Ok(Gate::ExecutorCpi); // (b)
    }
    let delivery = global.map_or(false, |g| g.is_delivery(payer));
    // (d) land_held_receive: the instruction checked the payer (admin, or a delivery key)
    require!(admin_land || delivery, OFTError::GapReceiveNotAllowed);
    Ok(Gate::Key { floors: Floors::read(extra_data), delivery }) // (c) / (d)
}

/// Which receive this is: LayerZero's / a delivery key's (`Normal`), or GapGlobal.admin's
/// `land_held_receive` (`Held`; the instruction checked the payer is the admin -- or a delivery
/// key for the oversized case -- at the top level).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Land {
    Normal,
    /// Priced as a normal receive, except that an arrival the capacity walk cannot cover (any r0
    /// reason since round 2 H-1 (2)) is priced at r0 (raised to the lander's floor) consuming nothing
    /// (`Outcome::oversized`) instead of holding.
    Held,
}

/// A land must run the price path: never fee 0 (step 3).
fn refuse_unpriced_land(land: Land) -> Result<()> {
    match land {
        Land::Normal => Ok(()),
        Land::Held => err!(OFTError::NotHeldReceive),
    }
}

/// Where the receive's PriceLog sits: right after the six gap accounts.
pub const RECEIVE_LOG_AT: usize = GAP_ACCOUNTS;

/// The v3c receive's gap (spec §3 rules 2-6), out of line (the receive's own frame is near the
/// 4 KB SBF limit): Ok(the outcome that credits) or the retriable revert. `rem` holds the six gap
/// accounts then the store's PriceLog at `at`; `to` is the message's recipient; `payer` the
/// receive's payer (R1'). The escape, the refund marker and SEED_NO_POOL read no price, so they
/// stay permissionless and write nothing. The price path writes the live price into the PriceLog.
/// `ata_created`: the lamports this receive's payer put into the recipient's token account it
/// created (0: it existed) (oft-fix M-1; oft-lows I-2: the actual cost is charged).
#[allow(clippy::too_many_arguments)]
#[inline(never)]
pub fn receive_v3(rem: &[AccountInfo], at: usize, h: &math::Header, tail: &Tail, amount_ld: u64, to: &Pubkey, token_mint: &Pubkey, store: &Pubkey, payer: &Pubkey, extra_data: &[u8], program_id: &Pubkey, land: Land, ata_created: u64) -> Result<Outcome> {
    let gap = GapAccounts::at(rem, at)?;
    if tail.escape {
        // rule 2: nothing is read, so a store whose price can never be read still lands
        refuse_unpriced_land(land)?;
        return Ok(Outcome::skipped(math::ESCAPED));
    }
    // Amendment 2: an expired-compose refund (class 255, both prices 0) lands in full; class 255
    // with a price is not something our peers send
    match math::refund_marker(h) {
        Some(true) => {
            refuse_unpriced_land(land)?;
            return Ok(Outcome::skipped(math::REFUND));
        }
        Some(false) => return err!(OFTError::GapBadVersion),
        None => {}
    }
    require!(h.v1, OFTError::GapBadVersion);
    // only at the top level or directly under LayerZero's executor (round 1, H-2)
    refuse_foreign_cpi(gap.ixs)?;
    match check(&gap, tail, program_id)? {
        // rule 3: no official pool here yet
        None => {
            if read_global(gap.global, program_id)?.map_or(false, |g| g.is_seeder(to)) {
                refuse_unpriced_land(land)?;
                Ok(Outcome::skipped(math::SEED_NO_POOL))
            } else {
                Err(hold(math::DST_NO_POOL))
            }
        }
        Some(d) => {
            let gate = r1_allowed(payer, d.global.as_deref(), extra_data, land != Land::Normal)?;
            refuse_earlier_touch(&gap, &d, tail)?;
            let log = rem.get(at + RECEIVE_LOG_AT).ok_or(OFTError::GapAccountMismatch)?;
            if !pricelog::open(log, store, program_id)? {
                // no PriceLog yet: anyone can create it (init_gap_price_log), then this lands
                return Err(hold(math::DST_PRICE_FAILED));
            }
            pricelog::refuse_second_write(gap.ixs, log.key)?;
            let live = crate::gap::record::live_prices(&gap, &d, tail, token_mint);
            let now = Clock::get()?.slot;
            // GapGlobal is present here: priced_outcome holds DST_PRICE_FAILED without it (below)
            let w = d.global.as_ref().map_or(WINDOW_DEFAULT as u64, |g| g.window());
            let fee_now = crate::gap::record::fee_at_record(&d);
            // the WHOLE window [now - W, now - 1]: its extremes give r0, the most conservative
            // Pd = max(live, every in-window max)
            let whole = {
                let ld = log.try_borrow_data()?;
                pricelog::window(&ld, now, w)
            };
            // Amendment 6: the cover's SOL/USD is always the whole window's minimum
            let whole_sol = whole.sol_min; #[cfg(feature = "stock-hops")] let live = crate::gap::hops::collar_live(&d, tail, live, &whole);
            // an unreadable pool fee holds with its own reason, before any capacity
            pool_fee_ppm(&d).map_err(hold)?;
            // round 2 H-1 (3): a key's floors raise Pd from the start (max(Pd, floor) for the pair
            // priced; never a new pair: a 0 Pd stays 0), so r0 -- and an oversized land at r0 -- is
            // priced at max(r0, floor) in one pass
            let floors = match gate {
                Gate::Key { floors, .. } => Some(floors),
                Gate::ExecutorCpi => None,
            };
            let p0 = dst_prices(&live, &whole);
            let p0 = floors.map_or(p0, |f| f.raise(&p0));
            let r0 = priced_outcome(amount_ld, h, &d, tail, &p0, || whole_sol).map_err(hold)?;
            // Round 2 H-1 (1) (lead #4, = A L-2): EVERY price-path receive stands on the window,
            // never on the live price alone: at least one entry in [now - W, now - 1] with a non-zero
            // maximum for the pair priced (cls for the class pair, usd for the USD pair). An empty
            // window let a dump of this pool before the delivery set Pd (live) and land at fee 0.
            // Retriable: record_price is permissionless, and the retry after it lands.
            let max = if r0.pair_class != 0 { whole.cls_max } else { whole.usd_max };
            require!(whole.entries >= 1 && max != 0, OFTError::GapNeedRecords);
            // Round 2 H-1 (3): a delivery key's receive always names its own Pd floor for the pair
            // priced, independent of this pool (the bot's price history and the source price; docs
            // §8.9). (Its land_held_receive is the oversized case, whose floor is checked below,
            // OversizedLandNeedsFloor.)
            if let Gate::Key { floors, delivery: true } = gate {
                require!(land != Land::Normal || floors.for_pair(r0.pair_class) != 0, OFTError::DeliveryNeedsFloor);
            }
            // Round 2 H-1 (2) (lead #4): EVERY price-path receive consumes capacity, whatever r0's
            // reason, and is priced at the entries it consumes (Pd never above r0's). Before, an r0
            // that was NO_GAP / WITHIN_ALLOWANCE consumed nothing, so one planted low entry priced an
            // unbounded arrival. One the walk cannot cover holds (GapNeedRecords) unless
            // land_held_receive lands it at r0 (admin, or a delivery key) with a floor.
            let g = d.global.as_deref().ok_or_else(|| hold(math::DST_PRICE_FAILED))?;
            let n = receive_need(g, &d, tail, &live, amount_ld, fee_now);
            let found = {
                let ld = log.try_borrow_data()?;
                pricelog::plan(&ld, now, w, &n)
            };
            let (outcome, plan) = match found {
                Some(pl) => {
                    // round 2 H-1 (3) (lead #4): a key's floor prices the receive at max(Pd, floor)
                    // for the pair priced (before: a floor above Pd reverted, GapPdBelowFloor)
                    let p = dst_prices(&live, &pl.window);
                    let p = floors.map_or(p, |f| f.raise(&p));
                    let o = priced_outcome(amount_ld, h, &d, tail, &p, || whole_sol).map_err(hold)?;
                    (o, Some(pl))
                }
                None if land == Land::Held => {
                    // the lander's Pd floor for the pair priced, mandatory here (audit d784 I-1): a
                    // window entry planted at now - 1 at a dumped price cannot set the charge; and
                    // (round 2 H-1 (3)) the land is priced at max(r0, floor), never below the floor
                    let f = floors.unwrap_or_default();
                    require!(f.for_pair(r0.pair_class) != 0, OFTError::OversizedLandNeedsFloor);
                    // r0 is already priced at max(r0's Pd, floor) (p0 above)
                    (Outcome { oversized: true, ..r0 }, None)
                }
                None => return err!(OFTError::GapNeedRecords),
            };
            // oft-q7 (owner Q7, main 06:25Z): the delivery cost, beside the swap cover, when OUR keys
            // deliver -- a GapGlobal.delivery key at the top level (the user paid LayerZero nothing
            // for it) or `land_held_receive` (admin or a delivery key); never under LayerZero's
            // executor (the user paid it) and never on the fee-0 paths above (escape, refund,
            // SEED_NO_POOL: no price is read there, like the cover). Valued at the whole window's
            // SOL/USD minimum (the cover's read) and the header's psUsd (else the Pd USD r0 used);
            // unreadable holds (retriable): we never deliver unpaid.
            let ours = land == Land::Held || matches!(gate, Gate::Key { delivery: true, .. });
            // oft-fix M-1 (users pay): when OUR delivery created the recipient's token account, its
            // rent is part of this arrival's delivery cost, valued the same way; it must be paid IN
            // FULL (never capped at the credit): a credit too small refuses (GapAtaRentUnpaid,
            // retriable) -- so a dust arrival to a fresh key never costs us the rent. oft-lows I-2
            // (oft-r4-prog): charged at the ACTUAL creation cost `ata_created` (the lamports the
            // payer put in: the rent of the size this mint's token account needs, so a Token-2022
            // mint with account extensions pays its larger account, a legacy Token store its 165 B
            // one); GapGlobal.ata_lamports != 0 switches the charge on (0 = off, init / migration)
            // and stays the quote's figure for a plain Token-2022 account (170 B).
            let ata = if ours && ata_created > 0 && g.ata_lamports != 0 { u32::try_from(ata_created).unwrap_or(u32::MAX) } else { 0 };
            let lamports = if ours { g.delivery_lamports.saturating_add(ata) } else { 0 };
            let per_token = if h.ps_e18 != 0 { h.ps_e18 } else { p0.pd_usd };
            let avail = amount_ld - outcome.withheld;
            let delivery_ld = math::delivery_charge_ld(lamports, || whole_sol, per_token, tail.token_decimals, avail)
                .ok_or_else(|| hold(math::DST_PRICE_FAILED))?;
            if ata != 0 {
                let full = math::delivery_charge_ld(lamports, || whole_sol, per_token, tail.token_decimals, u64::MAX).unwrap_or(u64::MAX);
                require!(full <= avail, OFTError::GapAtaRentUnpaid);
            }
            let outcome = Outcome {
                delivery_ld,
                delivery_lamports: lamports,
                delivery_sol_usd: if lamports != 0 { whole_sol } else { 0 },
                ata_lamports: ata,
                ..outcome
            };
            let mut ld = log.try_borrow_mut_data()?;
            if let Some(p) = &plan {
                // a receive pays no writer reward: the bridge fee was collected (and accrues) on
                // the source chain, none on Solana (owner (A), docs §8.3)
                pricelog::apply(&mut ld, p, amount_ld, 0, 0);
            }
            // round 2 B I-3: a receive's own entry has NO writer (no reward accrues to whoever paid
            // the delivery: LayerZero's executor key or our delivery key); a later record_price in
            // the same slot takes the entry over
            let by = pricelog::Writer { key: pricelog::NO_WRITER, fee_ppm: fee_now };
            pricelog::write(&mut ld, now, w, &live, &by);
            // the caller lowers the store's reserved reward total by every parked forfeit
            let lost = pricelog::take_forfeit(&mut ld);
            Ok(Outcome { forfeited: lost, ..outcome })
        }
    }
}

/// Owner (B): what a receive asks of the PriceLog (capacity on): the arrival's amount at Pd (the
/// live price rounded down, raised by the consumed maximums).
pub fn receive_need(g: &GapGlobal, d: &GapData, tail: &Tail, live: &pricelog::Live, amount_ld: u64, fee_now: u32) -> pricelog::Need {
    pricelog::Need {
        receive: true,
        amount_ld,
        live_usd: live.usd_down,
        live_cls: live.cls_down,
        locked_l: d.pool.map_or(0, |p| p.locked_liquidity),
        quote_decimals: tail.quote_decimals,
        token_decimals: tail.token_decimals,
        k_mode: g.k_mode,
        k_flat_ppm: g.capacity_k_ppm,
        k_factor_ppm: g.k_factor_ppm,
        fee_now_ppm: fee_now,
        platform_floor_ppm: g.platform_floor_ppm,
    }
}

/// A receive that must wait (spec §3, 4a/4b): logs `"gap-hold" | reason u8` and returns the
/// error that reverts the transaction. Nothing is consumed: the endpoint's clear is undone with
/// it, so the same message is delivered again once the pool, the route, a reader or the escape
/// is in place.
pub fn hold(reason: u8) -> Error {
    anchor_lang::solana_program::log::sol_log_data(&[b"gap-hold", &[reason]]);
    if reason == math::DST_NO_POOL {
        error!(OFTError::GapNoPool)
    } else {
        error!(OFTError::GapUnreadable)
    }
}

/// The accounts `lz_receive_types` lists for the gap (§10.4), given the store's tail and the
/// `GapRoute` the executor passed (the `LzReceiveTypes` PDA's third key).
pub fn receive_type_accounts(tail: &Tail, route_info: Option<&AccountInfo>, program_id: &Pubkey) -> [Pubkey; GAP_ACCOUNTS] {
    let global = GapGlobal::address(program_id);
    if !tail.is_set() {
        return [global, *program_id, *program_id, *program_id, *program_id, INSTRUCTIONS_SYSVAR_ID];
    }
    let route_key = GapRoute::address(program_id, &tail.quote_mint);
    let route: Option<GapRoute> = route_info.filter(|i| *i.key == route_key).and_then(|i| read_owned(i, program_id));
    let hop = |i| route.as_ref().map_or(*program_id, |r| r.hop_account(i, program_id));
    [global, route_key, tail.pool, hop(0), hop(1), INSTRUCTIONS_SYSVAR_ID]
}

// stocks-d (v3.1): the hop vaults of every kind (gap/hops.rs) with the feature.
#[cfg(feature = "stock-hops")]
pub use super::hops::engine_refuse_earlier_touch as refuse_earlier_touch;
