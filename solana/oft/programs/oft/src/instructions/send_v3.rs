//! Pangea v3 `send` (docs/v3c-gap-spec.md §4, BRIEF Amendments 4 and 6): a v3 store's transfer out.
//! One step: the per-sender GapSendRecord two-step is REMOVED; the flash-proof source price comes
//! from the store's shared PriceLog (gap/pricelog.rs).
//!
//! The same accounts, parameters, token moves, fee and rate limits as LayerZero's `send`; what
//! differs:
//!   * it refuses to run under CPI (`SendViaCpi`), before the store's official pool is set
//!     (`GapPoolNotSet`), and when an earlier top-level instruction of the transaction lists a pool
//!     the price reads (the official pool, a used hop pool) or a vault of one (`PoolTouchedEarlier`);
//!   * Ps = min(live, the PriceLog minimum over the entries with slot in [now - W, now - 1]) for
//!     psUsd and psClass (rounded up; the current slot never counts; 0 on either side is 0; psUsd 0
//!     refuses, `GapSourceUnreadable`: Amendment 6 decision 8, the cover is USD); at least one
//!     window entry, else `GapNeedRecords`; below the sender's optional `min_ps_usd` refuses
//!     (`GapPsBelowMin`);
//!   * CAPACITY and CONSUMED-ENTRY PRICING (owner (B) 2026-10-30; MANDATORY since whole-diff M-1,
//!     GapGlobal.capacity_on is never read): the send consumes capacity newest first and Ps = min(live, the minimums of the entries
//!     it consumed) instead of the whole window's (docs/v3c-gap-spec.md §8.2), else
//!     `GapNeedRecords` with nothing moved; each consumed entry's writer is owed reward_bps of the
//!     LD it covered, out of this send's bridge fee (§8.3);
//!   * it writes the live price into the PriceLog (the transaction's only log write), the signer
//!     as the writer;
//!   * the message is gap codec v3 (96 B): psUsd, feeSrcPpm = the pool's fee + costPpm, bridgeFeePpm,
//!     minCreditedSD, priceClass, psClass, srcGasMicroUsd and srcCoverCapCents (Amendment 6 §3: the
//!     gas cover, (swap + send lamports) x the window's SOL/USD minimum / 1e9, at most once per
//!     (store, dst_eid) per window floor(slot / W) -- the PriceLog's cover table -- and (0, 0) for any
//!     other send; SOL/USD 0 when lamports are set refuses, GapSourceUnreadable);
//!   * costPpm prices LayerZero's quote (endpoint `quote` CPI) for the peer's ENFORCED send options
//!     and a header-only message at the window's SOL/USD minimum (0 = no SOL entry: cost 0), capped
//!     at GapGlobal's cost max (math::cost_ppm; Amendment 6: no gas allowance);
//!   * `remaining_accounts` = [GapGlobal, GapRoute(quote), pool, hop0, hop1, instructions sysvar,
//!     the store's PriceLog (writable), ...LayerZero's endpoint send accounts].
//!   * OWNER M-1 (2026-10-30, oft-m1), the CO-SIGNED send (trailing flags bit 1, send.rs
//!     SEND_FLAG_COSIGNED, 57 trailing bytes): `remaining_accounts` carry ONE more account, the
//!     co-signer, right after the PriceLog: [the 7 above, co-signer, ...endpoint accounts]. When it
//!     SIGNS and is one of the 2 GapGlobal.cosigners (oft-fix L-2: a dedicated co-sign key with no
//!     other role; GapGlobal.admin and the delivery keys are refused as co-signers), and the store's escape
//!     is off, the send is priced at the MOST CONSERVATIVE Ps: min(live, the minimum over EVERY
//!     entry with slot in [now - W, now - 1]) (never the current slot, never above live), for psUsd
//!     and psClass alike, and it CONSUMES NO CAPACITY (no writer reward is owed either): an
//!     oversized send lands at once. Any other co-signer (not signing, not a key) or the escape on
//!     is no co-sign: the send is an ordinary one (capacity walk, GapNeedRecords when oversized),
//!     so the path is never permissionless. Always top level (SendViaCpi), always at least one
//!     window entry (GapNeedRecords). The co-signer's ceilings (part of the signed data) refuse
//!     the send, `GapPsAboveCeiling`, when psUsd > ps_usd_max or psClass > ps_class_max (checked
//!     on every send that carries them). A co-signed send also logs
//!     "gap-cosign" | co-signer [32] | ps_usd_max u128 | ps_class_max u128 | honored u8.
use crate::gap::{
    engine::{GapAccounts, GAP_ACCOUNTS},
    math,
    pricelog,
    record::{self, SEND_GAP_ACCOUNTS},
    state::Tail,
};
use crate::*;
use anchor_lang::solana_program::{
    instruction::{get_stack_height, AccountMeta, Instruction, TRANSACTION_LEVEL_STACK_HEIGHT},
    program::{get_return_data, invoke},
};
use anchor_spl::token_interface::{self, Burn, TransferChecked};
use oapp::endpoint::{instructions::{QuoteParams, SendParams as EndpointSendParams}, MessagingReceipt};

/// The endpoint send's accounts (after its program) the endpoint `quote` takes, in its order:
/// send library, its config, the default config, the library info, the endpoint settings, the
/// nonce, then the ULN's settings, send config and default send config, then the workers (18..).
/// Indexes into the send's endpoint accounts (LayerZero's SDK order: endpoint, sender, send lib,
/// its config, default config, lib info, settings, nonce, event authority, endpoint, ULN settings,
/// send config, default send config, payer, treasury, system, ULN event authority, ULN, workers).
const QUOTE_FROM_SEND: [usize; 9] = [2, 3, 4, 5, 6, 7, 10, 11, 12];
const SEND_WORKERS_AT: usize = 18;
/// Anchor's discriminator of the endpoint's `quote` (sha256("global:quote")[..8]).
const QUOTE_DISCRIMINATOR: [u8; 8] = [149, 42, 109, 247, 134, 146, 213, 123];
pub const SOL_DECIMALS: u8 = 9;

/// LayerZero's native fee for `params`, asked of the endpoint with the send's own accounts, all
/// read-only (the endpoint's quote refuses a writable one). ON-CHAIN only, inside the v3 send (the
/// §2 source cost); off-chain callers simulate `quote_send` instead (round 2 C, docs). 0 when the accounts cannot be a send's
/// (too few, another endpoint) or the answer is not the endpoint's MessagingFee. A quote that fails
/// inside LayerZero fails the transaction, as the send right after it would with the same accounts.
#[inline(never)]
pub fn lz_quote(endpoint_program: &Pubkey, eps: &[AccountInfo], params: &QuoteParams) -> Result<u64> {
    if eps.len() < SEND_WORKERS_AT + 4 || eps[0].key != endpoint_program {
        return Ok(0);
    }
    let picked: Vec<&AccountInfo> = QUOTE_FROM_SEND.iter().map(|i| &eps[*i]).chain(eps[SEND_WORKERS_AT..].iter()).collect();
    let mut data = QUOTE_DISCRIMINATOR.to_vec();
    params.serialize(&mut data)?;
    let ix = Instruction {
        program_id: *endpoint_program,
        accounts: picked.iter().map(|a| AccountMeta::new_readonly(*a.key, false)).collect(),
        data,
    };
    let mut infos: Vec<AccountInfo> = picked.into_iter().cloned().collect();
    infos.push(eps[0].clone());
    invoke(&ix, &infos)?;
    Ok(match get_return_data() {
        Some((program, d)) if program == *endpoint_program && d.len() >= 16 => u64::from_le_bytes(d[..8].try_into().unwrap()),
        _ => 0,
    })
}

/// What the source carries, read in its own frame (the SBF stack is 4 KB per frame).
pub struct SourceGap {
    pub ps_usd: u128,
    pub ps_class: u128,
    pub price_class: u8,
    pub pool_fee_ppm: u32,
    pub sol_usd: u128,
    pub cost_max: u128,
    pub token_decimals: u8,
    /// Amendment 6: the header's cover fields.
    pub gas: math::SourceGas,
    /// The cover table slot this send records its window in (Some only when `gas.carried`).
    pub cover_slot: Option<usize>,
    pub cover_window: u64,
    pub window: u64,
    pub reward_bps: u16,
    /// The pool's flat fee now (the entry's fee_at_record; 0 = unreadable).
    pub fee_now: u32,
    /// oft-q7 (Q7-e): GapGlobal's delivery cost toward dst_eid (0 = LayerZero's executor delivers),
    /// and where it goes.
    pub dst_delivery: u64,
    pub dst_delivery_to: Pubkey,
}

/// oft-q7 (Q7-e): the executor option a KEYS-ONLY destination gets in place of the store's enforced
/// options (our keys deliver it; the user pays LayerZero no receive gas, as the EVM token's
/// `combineOptions`, KEYS_ONLY_LZ_RECEIVE_GAS_V3 = 1): type 3 | executor (worker 1) | size 17 |
/// lzReceive (1) | gas u128 BE = 1. The sender's own options are appended as for the enforced ones.
pub const KEYS_ONLY_OPTIONS: [u8; 22] = [0, 3, 1, 0, 17, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

/// The enforced options this send combines with the sender's: the store's (SEND or SEND_AND_CALL),
/// or KEYS_ONLY_OPTIONS toward a keys-only destination.
pub fn enforced_for(peer: &PeerConfig, compose: &Option<Vec<u8>>, keys_only: bool) -> Vec<u8> {
    if keys_only { KEYS_ONLY_OPTIONS.to_vec() } else { peer.enforced_options.get_enforced_options(compose) }
}

/// oft-q7 (Q7-e): the sender pays GapGlobal.dst_delivery_to the destination's delivery cost (a
/// system transfer; the signer and the system program are among the endpoint's send accounts).
#[inline(never)]
fn pay_dst_delivery<'info>(rem: &[AccountInfo<'info>], signer: &Pubkey, to_at: usize, lamports: u64) -> Result<()> {
    use anchor_lang::solana_program::system_instruction;
    let to = &rem[to_at];
    let from = rem.iter().find(|a| a.key == signer && a.is_signer && a.is_writable).ok_or(OFTError::GapDeliveryFeeUnpaid)?;
    let system = rem.iter().find(|a| *a.key == anchor_lang::system_program::ID).ok_or(OFTError::GapDeliveryFeeUnpaid)?;
    invoke(&system_instruction::transfer(signer, to.key, lamports), &[from.clone(), to.clone(), system.clone()])?;
    Ok(())
}

/// The gap accounts' checks, the earlier-touch refusal, the PriceLog (opened, one write) and
/// Ps = min(live, window minimum), or with capacity on min(live, the consumed entries' minimums)
/// for a send of `amount_ld` (the plan, applied in `log_send`).
#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn source_gap(rem: &[AccountInfo], tail: &Tail, store: &Pubkey, token_mint: &Pubkey, min_ps_usd: u128, amount_ld: u64, dst_eid: u32, program_id: &Pubkey, require_cover: bool, cosign: Option<&CosignCeiling>) -> Result<(SourceGap, pricelog::Live, Option<pricelog::Plan>, bool)> {
    let gap = GapAccounts::at(rem, 0)?;
    require!(rem.len() > SEND_GAP_ACCOUNTS, OFTError::GapAccountMismatch);
    let log = &rem[GAP_ACCOUNTS];
    let d = Box::new(record::checked(&gap, tail, program_id)?);
    record::refuse_earlier_touch(&gap, &d, tail, None)?;
    let global = d.global.as_ref().ok_or(OFTError::GapSourceUnreadable)?;
    require!(pricelog::open(log, store, program_id)?, OFTError::GapNeedRecords);
    pricelog::refuse_second_write(gap.ixs, log.key)?;
    let now = Clock::get()?.slot;
    let whole = {
        let ld = log.try_borrow_data()?;
        pricelog::window(&ld, now, global.window())
    };
    require!(whole.entries >= 1, OFTError::GapNeedRecords);
    let live = record::live_prices(&gap, &d, tail, token_mint); #[cfg(feature = "stock-hops")] let live = crate::gap::hops::collar_live(&d, tail, live, &whole);
    let fee_now = record::fee_at_record(&d);
    // owner M-1: a co-sign is honored only when the account after the PriceLog SIGNS and is
    // one of GapGlobal.cosigners (oft-fix L-2: a dedicated key with no other role -- never the admin
    // or a delivery key, whose signature over a user-built transaction would authorize the rest of
    // it), and the store's escape is off; otherwise the send is an ordinary one (never permissionless)
    let honored = cosign.is_some() && {
        let c = rem.get(SEND_GAP_ACCOUNTS).ok_or(OFTError::GapAccountMismatch)?;
        c.is_signer && global.is_cosigner(c.key) && !tail.escape
    };
    // whole-diff M-1: capacity is mandatory -- no admin setting reopens the window-minimum path
    // (a single pumped entry pricing an unbounded send); the flag can only be on. Owner M-1: the
    // honored co-signed send is the one exception: the WHOLE window's minimum, no capacity
    let plan = if honored {
        crate::gap::engine::pool_fee_ppm(&d).map_err(|_| error!(OFTError::GapSourceUnreadable))?;
        None
    } else {
        // an unreadable pool fee is not a readable source, before any capacity
        crate::gap::engine::pool_fee_ppm(&d).map_err(|_| error!(OFTError::GapSourceUnreadable))?;
        let n = pricelog::Need {
            receive: false,
            amount_ld,
            live_usd: live.usd_up,
            live_cls: live.cls_up,
            locked_l: d.pool.map_or(0, |p| p.locked_liquidity),
            quote_decimals: tail.quote_decimals,
            token_decimals: tail.token_decimals,
            k_mode: global.k_mode,
            k_flat_ppm: global.capacity_k_ppm,
            k_factor_ppm: global.k_factor_ppm,
            fee_now_ppm: fee_now,
            platform_floor_ppm: global.platform_floor_ppm,
        };
        let ld = log.try_borrow_data()?;
        Some(pricelog::plan(&ld, now, global.window(), &n).ok_or(OFTError::GapNeedRecords)?)
    };
    // the consumed entries' extremes (capacity on) or the whole window's; SOL/USD (the cost) is
    // the whole window's minimum either way
    let win = plan.as_ref().map_or(whole, |p| pricelog::Window { sol_min: whole.sol_min, ..p.window });
    let ps_usd = record::min_known(live.usd_up, win.usd_min);
    let ps_quote = record::min_known(live.cls_up, win.cls_min);
    let price_class = global.class_of(&tail.quote_mint);
    let ps_class = if price_class != 0 { ps_quote } else { 0 };
    // Amendment 6 decision 8: the cover is USD, so a send needs psUsd (a class-only send is refused)
    require!(ps_usd != 0, OFTError::GapSourceUnreadable);
    require!(min_ps_usd == 0 || ps_usd >= min_ps_usd, OFTError::GapPsBelowMin);
    // owner M-1: the co-signer's ceilings, on every send that carries them
    if let Some(c) = cosign {
        require!(ps_usd <= c.ps_usd_max && ps_class <= c.ps_class_max, OFTError::GapPsAboveCeiling);
    }
    // the source pool's fee: unreadable (not a flat fee) is not a readable source
    let pool_fee_ppm = crate::gap::engine::pool_fee_ppm(&d).map_err(|_| error!(OFTError::GapSourceUnreadable))?;
    // Amendment 6 §3/§3a: the cover, at most once per (store, dst_eid) per window floor(slot / W)
    let cover_window = math::cover_window_index(now, global.window());
    let cover_slot = {
        let ld = log.try_borrow_data()?;
        pricelog::cover_grant(&ld, dst_eid, cover_window)
    };
    let sol_min = whole.sol_min;
    if require_cover {
        // step 3: the sender asked for the cover; refuse, before anything moves, unless this send
        // carries it: a cap (GapGlobal.cover_cap_cents), this destination's window grant (the
        // PriceLog cover table) and, when lamports are counted, the window's SOL/USD minimum
        let lamports = global.swap_lamports as u64 + global.send_lamports as u64;
        let cap = global.cover_cap_cents.min(math::COVER_CAP_MAX_CENTS);
        require!(cap != 0 && cover_slot.is_some() && (lamports == 0 || sol_min != 0), OFTError::GapCoverNotGranted);
    }
    // whole-diff L-1: without REQUIRE_COVER, a window with no SOL/USD (a broken wSOL route) carries
    // no cover, (0, 0), instead of refusing every send; with it the send refused above
    let gas = math::source_gas_fields(global.cover_cap_cents, cover_slot.is_some(), global.swap_lamports, global.send_lamports, || sol_min).unwrap_or_default();
    Ok((
        SourceGap {
            ps_usd,
            ps_class,
            price_class,
            pool_fee_ppm,
            sol_usd: win.sol_min,
            cost_max: global.cost_max(),
            token_decimals: tail.token_decimals,
            gas,
            cover_slot: cover_slot.filter(|_| gas.carried),
            cover_window,
            window: global.window(),
            reward_bps: global.reward_bps,
            fee_now,
            dst_delivery: global.dst_delivery_of(dst_eid),
            dst_delivery_to: global.dst_delivery_to,
        },
        live,
        plan,
        honored,
    ))
}

/// The consumption (capacity on) with its writer rewards, then the send's own PriceLog write
/// (`log` already opened by `source_gap`) and, when this send carries a cover, its window in the
/// cover table: (the rewards now owed, what a full reward table forfeited). `fee_ld` is this
/// send's bridge fee, the rewards' cap.
#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn log_send(log: &AccountInfo, src: &SourceGap, live: &pricelog::Live, plan: Option<&pricelog::Plan>, amount_ld: u64, fee_ld: u64, dst_eid: u32, by: &pricelog::Writer) -> Result<(u64, u64)> {
    let now = Clock::get()?.slot;
    let mut ld = log.try_borrow_mut_data()?;
    let owed = match plan {
        Some(p) => pricelog::apply(&mut ld, p, amount_ld, src.reward_bps, fee_ld),
        None => 0,
    };
    pricelog::write(&mut ld, now, src.window, live, by);
    // Amendment 6 §3a: only a send that really carries a cover spends its window (a send that
    // reverts later writes nothing: the transaction is undone)
    if let Some(j) = src.cover_slot {
        pricelog::cover_write(&mut ld, j, dst_eid, src.cover_window);
    }
    // every parked forfeit (this write's and earlier record_price's) leaves the reserved total
    let lost = pricelog::take_forfeit(&mut ld);
    Ok((owed, lost))
}

/// (LayerZero's native fee, costPpm) for this send (spec §2).
#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn bridge_cost(endpoint_program: &Pubkey, eps: &[AccountInfo], store: &Pubkey, params: &SendParams, peer: &PeerConfig, amount_sd: u64, rate: u64, src: &SourceGap, bridge_fee_ppm: u32) -> Result<(u64, u32)> {
    // oft-q7 (Q7-e): toward a keys-only destination the enforced SEND options are the minimal
    // executor option, and our delivery cost is part of the bridge cost
    let q = Box::new(QuoteParams {
        sender: *store,
        dst_eid: params.dst_eid,
        receiver: peer.peer_address,
        message: math::encode(params.to, amount_sd, 0, 0, 0, 0, 0, 0, 0, 0, None),
        options: enforced_for(peer, &None, src.dst_delivery != 0),
        pay_in_lz_token: false,
    });
    let native_fee = lz_quote(endpoint_program, eps, &q)?.saturating_add(src.dst_delivery);
    let amount_net_ld = amount_sd.saturating_mul(rate);
    Ok((native_fee, math::cost_ppm(native_fee as u128, SOL_DECIMALS, src.sol_usd, src.ps_usd, src.token_decimals, amount_net_ld, bridge_fee_ppm, src.cost_max)))
}

impl Send<'_> {
    pub fn apply_v3(ctx: &mut Context<Send>, params: &SendParams) -> Result<(MessagingReceipt, OFTReceipt)> {
        // first, as when the strict parse ran at deserialization (audit r1 L-1)
        params.check_trailing()?;
        require!(!ctx.accounts.oft_store.paused, OFTError::Paused);
        require!(get_stack_height() == TRANSACTION_LEVEL_STACK_HEIGHT, OFTError::SendViaCpi);

        // ---- the gap header, read before anything moves
        let tail = {
            let info = ctx.accounts.oft_store.to_account_info();
            let d = info.try_borrow_data()?;
            Tail::read(&d).ok_or(OFTError::NotV3Store)?
        };
        // No official pool yet: nothing legitimate sends before `set_gap_pool`.
        require!(tail.is_set(), OFTError::GapPoolNotSet);
        let store_key = ctx.accounts.oft_store.key();
        // LayerZero's amounts (no side effects), first: the consumption needs the amount sent
        let (amount_sent_ld, amount_received_ld, oft_fee_ld) = compute_fee_and_adjust_amount(
            params.amount_ld,
            &ctx.accounts.oft_store,
            &ctx.accounts.token_mint,
            ctx.accounts.peer.fee_bps,
        )?;
        let (src, live, plan, honored) = source_gap(ctx.remaining_accounts, &tail, &store_key, &ctx.accounts.token_mint.key(), params.min_ps_usd, amount_received_ld, params.dst_eid, ctx.program_id, params.require_cover, params.cosign.as_ref())?;
        // owner M-1: a co-signed send's endpoint accounts start one later (after the co-signer)
        // oft-q7 (Q7-e): toward a keys-only destination one more, GapGlobal.dst_delivery_to (w)
        let keys_only = src.dst_delivery != 0;
        let fee_to_at = SEND_GAP_ACCOUNTS + params.cosign.is_some() as usize;
        let gap_len = fee_to_at + keys_only as usize;
        if keys_only {
            let to = ctx.remaining_accounts.get(fee_to_at).ok_or(OFTError::GapDeliveryFeeUnpaid)?;
            require!(*to.key == src.dst_delivery_to && to.is_writable && params.native_fee >= src.dst_delivery, OFTError::GapDeliveryFeeUnpaid);
        }
        let (ps_usd, ps_class, price_class) = (src.ps_usd, src.ps_class, src.price_class);
        let fee_bps = ctx.accounts.peer.fee_bps.unwrap_or(ctx.accounts.oft_store.default_fee_bps);
        let bridge_fee_ppm = fee_bps as u32 * 100;

        // ---- LayerZero's send, as in send.rs
        require!(amount_received_ld >= params.min_amount_ld, OFTError::SlippageExceeded);
        // the consumption, its writer rewards and the send's own PriceLog write, before anything
        // moves; the rewards are reserved out of this send's bridge fee (owner (A))
        let by = pricelog::Writer { key: ctx.accounts.signer.key().to_bytes(), fee_ppm: src.fee_now };
        let (owed, lost) = log_send(&ctx.remaining_accounts[GAP_ACCOUNTS], &src, &live, plan.as_ref(), amount_received_ld, oft_fee_ld, params.dst_eid, &by)?;
        if owed > 0 || lost > 0 {
            let info = ctx.accounts.oft_store.to_account_info();
            let mut d = info.try_borrow_mut_data()?;
            crate::gap::state::Tail::adjust_reward_owed(&mut d, owed, lost)?;
        }

        if let Some(rate_limiter) = ctx.accounts.peer.outbound_rate_limiter.as_mut() {
            rate_limiter.try_consume(amount_received_ld)?;
        }
        if let Some(rate_limiter) = ctx.accounts.peer.inbound_rate_limiter.as_mut() {
            rate_limiter.refill(amount_received_ld)?;
        }

        if ctx.accounts.oft_store.oft_type == OFTType::Adapter {
            ctx.accounts.oft_store.tvl_ld += amount_received_ld;
            token_interface::transfer_checked(
                CpiContext::new(
                    ctx.accounts.token_program.to_account_info(),
                    TransferChecked {
                        from: ctx.accounts.token_source.to_account_info(),
                        mint: ctx.accounts.token_mint.to_account_info(),
                        to: ctx.accounts.token_escrow.to_account_info(),
                        authority: ctx.accounts.signer.to_account_info(),
                    },
                ),
                amount_sent_ld,
                ctx.accounts.token_mint.decimals,
            )?;
        } else {
            token_interface::burn(
                CpiContext::new(
                    ctx.accounts.token_program.to_account_info(),
                    Burn {
                        mint: ctx.accounts.token_mint.to_account_info(),
                        from: ctx.accounts.token_source.to_account_info(),
                        authority: ctx.accounts.signer.to_account_info(),
                    },
                ),
                amount_sent_ld - oft_fee_ld,
            )?;
            if oft_fee_ld > 0 {
                token_interface::transfer_checked(
                    CpiContext::new(
                        ctx.accounts.token_program.to_account_info(),
                        TransferChecked {
                            from: ctx.accounts.token_source.to_account_info(),
                            mint: ctx.accounts.token_mint.to_account_info(),
                            to: ctx.accounts.token_escrow.to_account_info(),
                            authority: ctx.accounts.signer.to_account_info(),
                        },
                    ),
                    oft_fee_ld,
                    ctx.accounts.token_mint.decimals,
                )?;
            }
        }

        require!(ctx.remaining_accounts.len() > gap_len, OFTError::GapAccountMismatch);
        let endpoint_accounts = &ctx.remaining_accounts[gap_len..];
        require!(
            endpoint_accounts.len() > 1 && ctx.accounts.oft_store.key() == endpoint_accounts[1].key(),
            OFTError::InvalidSender
        );
        let amount_sd = ctx.accounts.oft_store.ld2sd(amount_received_ld);
        let compose = params.compose_msg.as_ref().filter(|m| !m.is_empty());
        let signer = ctx.accounts.signer.key().to_bytes();
        // The sender's least credited amount (spec §4), in shared decimals, rounded up: the
        // destination reverts (retriable) while it would credit less.
        let rate = ctx.accounts.oft_store.ld2sd_rate;
        let min_credited_sd = params.min_credited_ld.div_ceil(rate.max(1));
        // never more than is sent: such a message could never be credited (audit round 2, L-2)
        require!(min_credited_sd <= amount_sd, OFTError::MinCreditedAboveAmount);
        // ---- the bridge cost (spec §2): LayerZero's quote for THIS store's enforced SEND options and a
        // header-only message, never the sender's options, compose or native_fee
        let (native_fee, cost_ppm) = bridge_cost(&ctx.accounts.oft_store.endpoint_program, endpoint_accounts, &store_key, params, &ctx.accounts.peer, amount_sd, rate, &src, bridge_fee_ppm)?;
        let fee_src_ppm = src.pool_fee_ppm.saturating_add(cost_ppm);
        let message = math::encode(params.to, amount_sd, ps_usd, fee_src_ppm, bridge_fee_ppm, min_credited_sd, price_class, ps_class, src.gas.src_gas_micro_usd, src.gas.src_cover_cap_cents, compose.map(|m| (signer, m.as_slice())));
        let msg_receipt = oapp::endpoint_cpi::send(
            ctx.accounts.oft_store.endpoint_program,
            ctx.accounts.oft_store.key(),
            endpoint_accounts,
            &[OFT_SEED, ctx.accounts.token_escrow.key().as_ref(), &[ctx.accounts.oft_store.bump]],
            EndpointSendParams {
                dst_eid: params.dst_eid,
                receiver: ctx.accounts.peer.peer_address,
                message,
                options: oapp::options::combine_options(enforced_for(&ctx.accounts.peer, &compose.cloned(), keys_only), &params.options)?,
                // oft-q7 (Q7-e): LayerZero gets the rest, our delivery cost goes to dst_delivery_to
                native_fee: params.native_fee - src.dst_delivery,
                lz_token_fee: params.lz_token_fee,
            },
        )?;
        if keys_only {
            pay_dst_delivery(ctx.remaining_accounts, &ctx.accounts.signer.key(), fee_to_at, src.dst_delivery)?;
            emit!(GapDstDeliveryPaid { dst_eid: params.dst_eid, to: src.dst_delivery_to, lamports: src.dst_delivery });
        }

        emit_cpi!(OFTSent {
            guid: msg_receipt.guid,
            dst_eid: params.dst_eid,
            from: ctx.accounts.token_source.key(),
            amount_sent_ld,
            amount_received_ld
        });
        // what the header carries, for indexers and tests (LE):
        // "gap-send" | ps_usd u128 | fee_src u32 | bridge u32 | class u8 | ps_class u128 | cost_ppm u32 | native_fee u64 | sol_usd u128
        //   | src_gas_micro_usd u32 | src_cover_cap_cents u16
        anchor_lang::solana_program::log::sol_log_data(&[
            b"gap-send",
            &ps_usd.to_le_bytes(),
            &fee_src_ppm.to_le_bytes(),
            &bridge_fee_ppm.to_le_bytes(),
            &[price_class],
            &ps_class.to_le_bytes(),
            &cost_ppm.to_le_bytes(),
            &native_fee.to_le_bytes(),
            &src.sol_usd.to_le_bytes(),
            &src.gas.src_gas_micro_usd.to_le_bytes(),
            &src.gas.src_cover_cap_cents.to_le_bytes(),
        ]);
        if let Some(c) = params.cosign.as_ref() {
            anchor_lang::solana_program::log::sol_log_data(&[
                b"gap-cosign",
                ctx.remaining_accounts[SEND_GAP_ACCOUNTS].key.as_ref(),
                &c.ps_usd_max.to_le_bytes(),
                &c.ps_class_max.to_le_bytes(),
                &[honored as u8],
            ]);
        }

        Ok((msg_receipt, OFTReceipt { amount_sent_ld, amount_received_ld }))
    }
}
