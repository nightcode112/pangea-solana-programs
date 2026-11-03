//! Pangea v3 `lz_receive` (docs/v3-gap-fee-spec.md §4, §6, §10.4, §10.5; v3c: docs/v3c-gap-spec.md
//! §1, §3): a v3 store's arrival. The same accounts and token flow as LayerZero's `lz_receive`;
//! what differs:
//!   * v3c rules, in order (spec §3): the store's admin escape on -> credited in full, fee 0
//!     (ESCAPED); a message that is not codec v3 -> GapBadVersion; no official pool -> credited in
//!     full for a GapGlobal seeder (SEED_NO_POOL), else GapNoPool; psUsd 0 with no usable class
//!     pair, the pool fee, the margin, the pool price or the route unreadable -> GapUnreadable
//!     (`"gap-hold" | reason` logged); else the formula and the least credited amount. Every
//!     revert is retriable: nothing is consumed, the endpoint's clear is undone with it;
//!   * the gap accounts follow clear; a wrong key reverts (retriable), and so does an
//!     earlier top-level instruction listing a pool the price reads or a vault of one (Q3), and so
//!     does a v1 receive under any program but LayerZero's executor (`ReceiveViaCpi`);
//!   * `withheld` is never minted (Native) or is burned out of the escrow (Adapter, whose `tvl_ld`
//!     falls by the full amount), and is added to the tail's `gap_burned_ld`;
//!   * a composed v1 arrival is NOT handed to LayerZero's endpoint: its payload goes into the
//!     guid's `GapReceipt` with what was credited (spec §10.5), which the composer reads and closes,
//!     when `to` is in `GapGlobal.composers` and it credits more than 0. A composed arrival that
//!     credits more than 0 for a `to` NOT listed HOLDS (`GapComposerNotListed`, retriable; step 2,
//!     lead 2026-10-30: crediting it plain lost the compose for good, stranding FastBridge orders):
//!     listing the composer lets the retry land with its receipt. With the store's escape on an
//!     UNLISTED one is credited as an uncomposed arrival (the escape lands everything); a LISTED
//!     composer's arrival still writes its GapReceipt with the escape on (whole-diff I-1). A
//!     listed composer's arrival crediting 0 writes its receipt too (credited 0; oft-lows L-2 with
//!     the sender's prepay P at its GapPrepay PDA, oft-ret / oft-r5 L-1 also with nothing there yet,
//!     so a P that lands later has a receipt to go into); oft-lows2 (oft-r6 L-3): our delivery key
//!     does so only when the sender's prepay covers the receipt's rent (GapReceiveNotAllowed,
//!     retriable, otherwise). An UNLISTED `to`'s zero credit is credited as an uncomposed arrival.
//!     Every composed codec v3 arrival names its GapPrepay PDA (oft-lows L-3; GapAccountMismatch
//!     otherwise).
use crate::gap::{
    engine::{self, Land},
    math,
    state::{GapReceipt, Tail, GAP_RECEIPT_SEED, MAX_COMPOSE_MSG_LEN},
};
use crate::*;
use anchor_lang::solana_program::{self, program::invoke_signed, rent::Rent, system_instruction};
use anchor_spl::{
    token_2022::spl_token_2022,
    token_interface::{self, Burn, TransferChecked},
};
use oapp::endpoint::{cpi::accounts::Clear, instructions::ClearParams, ConstructCPIContext};

impl<'info> LzReceive<'info> {
    pub fn apply_v3(ctx: &mut Context<'_, '_, '_, 'info, LzReceive<'info>>, params: &LzReceiveParams) -> Result<()> {
        Self::receive_v3(ctx, params, Land::Normal)
    }

    /// Audit L-1 + the EVM audit (step 3, one instruction by the coordinator): `land_held_receive`.
    /// GapGlobal.admin (as `payer`, at the top level) lands an arrival the normal receive holds
    /// for good, for either reason or both:
    ///   * a composed codec v3 arrival crediting more than 0 for a `to` that is NOT a listed
    ///     composer (GapComposerNotListed): landed PLAIN, no receipt, the compose call dropped;
    ///   * capacity on and larger than the walk covers (GapNeedRecords), whatever r0's reason
    ///     (round 2 H-1 (2): every price-path receive consumes capacity, so an r0 the walk cannot
    ///     cover holds and is landable): priced at r0 (at max(r0, the lander's floor)), no capacity
    ///     consumed.
    /// Otherwise the normal gap fee and rules (the least-credited check, the PriceLog write, a
    /// listed composer's receipt). Event GapHeldLanded. Never fee 0: the escape, a refund and
    /// SEED_NO_POOL are refused, as is any arrival that is not held for one of these reasons
    /// (NotHeldReceive) and any CPI; NotGapAdmin for any payer but GapGlobal.admin -- except
    /// (owner decision 2026-10-30, "no cap, no queue") a GapGlobal.delivery key, which may land
    /// the OVERSIZED case only: same r0 pricing, the mandatory non-zero Pd floor, top level, no
    /// capacity consumed. An unlisted compose (plain, or oversized too) stays the admin's
    /// (NotGapAdmin for a delivery key). GapHeldLanded.admin is the payer that landed it.
    pub fn land_held_receive(ctx: &mut Context<'_, '_, '_, 'info, LzReceive<'info>>, params: &LzReceiveParams) -> Result<()> {
        require!(crate::gap::state::is_v3_store(&ctx.accounts.oft_store.to_account_info()), OFTError::NotV3Store);
        Self::receive_v3(ctx, params, Land::Held)
    }

    fn receive_v3(ctx: &mut Context<'_, '_, '_, 'info, LzReceive<'info>>, params: &LzReceiveParams, land: Land) -> Result<()> {
        require!(!ctx.accounts.oft_store.paused, OFTError::Paused);
        let h = math::decode(&params.message).ok_or(OFTError::GapMsgTooShort)?;
        let tail = {
            let info = ctx.accounts.oft_store.to_account_info();
            let d = info.try_borrow_data()?;
            Tail::read(&d).ok_or(OFTError::NotV3Store)?
        };
        // `land_held_receive`: its gate, and whether it lands this one plain (an unlisted
        // composer's compose is dropped: no hold, no receipt)
        let plain = match land {
            Land::Normal => false,
            Land::Held => held_allowed(ctx, &h, &tail)?,
        };
        // progs2 I-2: a composed tail is composeFrom (32) | composeMsg; one shorter than 32 bytes is
        // not the codec (a v3 peer never sends it) and is refused like any other version, so no
        // receipt can carry a zero compose_from (a later return would go to bytes32(0)); with the
        // escape on it lands plain (the escape lands everything), no receipt
        let short_tail = h.v1 && h.composed && params.message.len() < math::HEADER_LEN + 32;
        let composed = h.v1 && h.composed && !plain && !short_tail;
        // v3c rule 2 then the codec: only our v3 peers send here, so any other version is refused
        // (never credited at fee 0) unless the escape is on
        require!(tail.escape || (h.v1 && !short_tail), OFTError::GapBadVersion);

        let oft_store_seed = ctx.accounts.token_escrow.key();
        let seeds: &[&[u8]] = &[OFT_SEED, oft_store_seed.as_ref(), &[ctx.accounts.oft_store.bump]];

        // Validate and clear the payload, as LayerZero's
        let accounts_for_clear = &ctx.remaining_accounts[0..Clear::MIN_ACCOUNTS_LEN];
        let _ = oapp::endpoint_cpi::clear(
            ctx.accounts.oft_store.endpoint_program,
            ctx.accounts.oft_store.key(),
            accounts_for_clear,
            seeds,
            ClearParams {
                receiver: ctx.accounts.oft_store.key(),
                src_eid: params.src_eid,
                sender: params.sender,
                nonce: params.nonce,
                guid: params.guid,
                message: params.message.clone(),
            },
        )?;

        let amount_ld = ctx.accounts.oft_store.sd2ld(h.amount_sd);
        let gap_at = Clear::MIN_ACCOUNTS_LEN;
        let tail_bytes = math::compose_tail(&params.message);
        // composeFrom (32) | composeMsg; the source refuses a longer one
        require!(!composed || tail_bytes.len() <= 32 + MAX_COMPOSE_MSG_LEN, OFTError::ComposeTooLong);

        // oft-fix M-1: the recipient's token account (Anchor's init_if_needed, moved into the
        // handler): what THIS receive's payer paid to create it (0: it existed) -- users pay that
        // rent when our keys deliver (engine::receive_v3; oft-lows I-2: the actual cost)
        let ata_created = ctx.accounts.ensure_token_dest()?;

        // ---- the gap (v3c, spec §3)
        let outcome = engine::receive_v3(
            ctx.remaining_accounts,
            gap_at,
            &h,
            &tail,
            amount_ld,
            &ctx.accounts.to_address.key(),
            &ctx.accounts.token_mint.key(),
            &ctx.accounts.oft_store.key(),
            &ctx.accounts.payer.key(),
            &params.extra_data,
            ctx.program_id,
            land,
            ata_created,
        )?;
        let withheld = outcome.withheld;
        // oft-q7 (owner Q7): the delivery cost our keys' delivery withholds (<= amount - withheld by
        // math::delivery_charge_ld), into the store's escrow
        let delivery = outcome.delivery_ld;
        let credited = amount_ld - withheld - delivery; // withheld + delivery <= amount_ld
        // `land_held_receive` only for an arrival actually held: an unlisted compose that credits,
        // or one the capacity walk could not cover
        if land == Land::Held {
            require!((plain && amount_ld - withheld > 0) || outcome.oversized, OFTError::NotHeldReceive);
            // audit s3-delta I-3: a compose landed plain credits `to`'s ATA with its call dropped; only
            // a wallet (an ed25519 key, on the curve) can move tokens from it without that call, so a
            // PDA (a program's vault) is refused: list it as a composer instead
            if plain && credited > 0 {
                require!(on_curve(&ctx.accounts.to_address.key()), OFTError::HeldComposeToPda);
            }
        }
        // A composed arrival for a composer not (yet) listed waits (retriable), before anything
        // moves; the escape still lands it, plain.
        if composed && credited > 0 && !tail.escape {
            require!(engine::receipt_for(&ctx.remaining_accounts[gap_at], &ctx.accounts.to_address.key(), ctx.program_id)?, OFTError::GapComposerNotListed);
        }
        // The sender's least credited amount (spec §4, §6.2): below it the receive reverts, before
        // anything moves, and stays retriable in the endpoint (the clear above is undone with it).
        if h.v1 && h.min_credited_sd > 0 {
            require!(math::credit_meets_min(credited, h.min_credited_sd, ctx.accounts.oft_store.ld2sd_rate), OFTError::GapCreditBelowMin);
        }

        if let Some(rate_limiter) = ctx.accounts.peer.inbound_rate_limiter.as_mut() {
            rate_limiter.try_consume(amount_ld)?;
        }
        if let Some(rate_limiter) = ctx.accounts.peer.outbound_rate_limiter.as_mut() {
            rate_limiter.refill(amount_ld)?;
        }

        let mut amount_received_ld = credited;
        if ctx.accounts.oft_store.oft_type == OFTType::Adapter {
            // the full amount leaves the lock: `credited` to the user, `withheld` burned, `delivery`
            // stays in the escrow above tvl_ld (the bridge-fee accrual, withdraw_fee)
            ctx.accounts.oft_store.tvl_ld -= amount_ld;
            token_interface::transfer_checked(
                CpiContext::new(
                    ctx.accounts.token_program.to_account_info(),
                    TransferChecked {
                        from: ctx.accounts.token_escrow.to_account_info(),
                        mint: ctx.accounts.token_mint.to_account_info(),
                        to: ctx.accounts.token_dest.to_account_info(),
                        authority: ctx.accounts.oft_store.to_account_info(),
                    },
                )
                .with_signer(&[&seeds]),
                credited,
                ctx.accounts.token_mint.decimals,
            )?;
            if withheld > 0 {
                token_interface::burn(
                    CpiContext::new(
                        ctx.accounts.token_program.to_account_info(),
                        Burn {
                            mint: ctx.accounts.token_mint.to_account_info(),
                            from: ctx.accounts.token_escrow.to_account_info(),
                            authority: ctx.accounts.oft_store.to_account_info(),
                        },
                    )
                    .with_signer(&[&seeds]),
                    withheld,
                )?;
            }
            amount_received_ld = get_post_fee_amount_ld(&ctx.accounts.token_mint, credited)?;
        } else if let Some(mint_authority) = &ctx.accounts.mint_authority {
            let ix = spl_token_2022::instruction::mint_to(
                ctx.accounts.token_program.key,
                &ctx.accounts.token_mint.key(),
                &ctx.accounts.token_dest.key(),
                mint_authority.key,
                &[&ctx.accounts.oft_store.key()],
                credited,
            )?;
            solana_program::program::invoke_signed(
                &ix,
                &[
                    ctx.accounts.token_dest.to_account_info(),
                    ctx.accounts.token_mint.to_account_info(),
                    mint_authority.to_account_info(),
                    ctx.accounts.oft_store.to_account_info(),
                ],
                &[&seeds],
            )?;
            if delivery > 0 {
                // oft-q7: the delivery cost is minted into the store's escrow (the bridge-fee accrual)
                let ix = spl_token_2022::instruction::mint_to(
                    ctx.accounts.token_program.key,
                    &ctx.accounts.token_mint.key(),
                    &ctx.accounts.token_escrow.key(),
                    mint_authority.key,
                    &[&ctx.accounts.oft_store.key()],
                    delivery,
                )?;
                solana_program::program::invoke_signed(
                    &ix,
                    &[
                        ctx.accounts.token_escrow.to_account_info(),
                        ctx.accounts.token_mint.to_account_info(),
                        mint_authority.to_account_info(),
                        ctx.accounts.oft_store.to_account_info(),
                    ],
                    &[&seeds],
                )?;
            }
        } else {
            return Err(OFTError::InvalidMintAuthority.into());
        }

        if withheld > 0 {
            let info = ctx.accounts.oft_store.to_account_info();
            let mut d = info.try_borrow_mut_data()?;
            Tail::write_burned(&mut d, tail.burned_ld.saturating_add(withheld));
        }
        if outcome.forfeited > 0 {
            // owner (A): a full reward table forfeited a reward back to the bridge-fee accrual
            let info = ctx.accounts.oft_store.to_account_info();
            let mut d = info.try_borrow_mut_data()?;
            Tail::adjust_reward_owed(&mut d, 0, outcome.forfeited)?;
        }

        // A receipt only for an allowlisted composer (audit round 1 Solana, L-1), so nobody can make
        // the delivering payer fund receipts that only a never-signing `to` could close: any other
        // composed arrival has held above (GapComposerNotListed), or, with the escape on, is credited
        // as a plain one and its call dropped.
        // (audit round 2 Solana, L-1, superseded: a zero arrival was credited as a plain one, no
        // receipt. oft-lows L-2 wrote a listed composer's zero-credit receipt when the sender's prepay
        // is at its PDA, and oft-ret (oft-r5 L-1) ALWAYS writes a listed composer's receipt, a zero
        // credit too: a zero-credit receipt is released / settled like any other since oft-lows.
        // oft-lows2 (oft-r6 L-3): not with our delivery key fronting its rent -- see below.)
        // oft-lows L-3 (oft-r4-prog): every composed codec v3 arrival names its GapPrepay PDA (the
        // account after the receipt's; lz_receive_types always lists it). Before, a permissionless
        // receive with the escape on could omit it, land with no receipt and strand the sender's P
        // there (nothing could move it). Its address is checked where it is swept (prepay::sweep).
        let prepay_acc = if h.v1 && h.composed && !short_tail {
            Some(ctx.remaining_accounts.get(gap_at + engine::GAP_ACCOUNTS + 2).ok_or(OFTError::GapAccountMismatch)?)
        } else {
            None
        };
        // oft-lows L-2 (lead decision): a LISTED composer's arrival that credits 0 while the sender's
        // prepay P is at its PDA still writes its receipt (credited 0, prepaid = P): P is never swept
        // into the composer's own account (cheapest's composer PDA has no way to move it out); the
        // receipt's return path pays it to the refund party the composer names (receipt.refund_to:
        // cheapest's release_expired_v3 names the sender's box once the call can no longer be sold
        // -- after its deadline, like any other call (oft-r5 I-1); FastBridge's settle_v3 the order's
        // recipient). oft-ret (oft-r5 L-1): a listed composer's composed arrival ALWAYS writes its
        // receipt, also a zero credit with nothing at the PDA yet (the payer fronts the rent and gets it
        // back on the close: a zero-credit receipt is released / settled like any other since
        // oft-lows), so a P that lands after the receive always has a receipt to go into
        // (`sweep_gap_prepay`). Before, it had neither a receipt nor a late record: stranded.
        let listed = composed && engine::receipt_for(&ctx.remaining_accounts[gap_at], &ctx.accounts.to_address.key(), ctx.program_id)?;
        let write = listed;
        if write {
            let receipt = ctx.remaining_accounts.get(gap_at + engine::GAP_ACCOUNTS + 1).ok_or(OFTError::GapAccountMismatch)?;
            // composeFrom | composeMsg; a tail shorter than 32 bytes was refused above (progs2 I-2:
            // never a receipt with a zero compose_from)
            require!(tail_bytes.len() >= 32, OFTError::GapBadVersion);
            let (compose_from, compose_msg) = (<[u8; 32]>::try_from(&tail_bytes[..32]).unwrap(), tail_bytes[32..].to_vec());
            // L4: the sender's prepay (its native drop to the GapPrepay PDA, the account after the
            // receipt) moves into the receipt's address first, so the receipt's rent comes out of it
            // and the payer fronts only what it lacks; `prepaid` records the sender's part
            let prepaid = match prepay_acc {
                Some(pp) => crate::gap::prepay::sweep(pp, receipt, &ctx.accounts.system_program.to_account_info(), ctx.program_id, &ctx.accounts.oft_store.key(), params.src_eid, &compose_from, &compose_msg)?,
                None => 0,
            };
            // oft-lows2 (oft-r6 L-3, lead #6): OUR delivery key (a GapGlobal delivery key at the top
            // level, Land::Normal) never fronts a zero-credit receipt's rent: a listed composer's
            // arrival crediting 0 whose receipt the sender's prepay (now at the receipt's address)
            // does not cover is refused GapReceiveNotAllowed (retriable, nothing moves). It lands
            // with the receipt's rent out of the sender's P once P is at the PDA (our key's retry or
            // the bot's [fund P, lz_receive] -- P goes home on the close / return), or under
            // LayerZero's executor (its `execute` CPI; that payer fronts the rent and gets it back on
            // the close). So on a zero credit our key pays 0 and keeps 0. A credit > 0 is unchanged
            // (its receipt is closed by the composer's normal flow, rent back to the payer).
            // oft-lows3 (oft-lows2-r1 I-1): the same for `land_held_receive` (Land::Held): its payer is
            // always ours (GapGlobal.admin or a delivery key, at the top level: held_allowed), and a
            // listed composer's held land is the OVERSIZED case, which can credit 0 (the gap withholds
            // all of it). Refused GapReceiveNotAllowed until the sender's P covers the receipt's rent.
            if credited == 0 {
                use anchor_lang::solana_program::instruction::{get_stack_height, TRANSACTION_LEVEL_STACK_HEIGHT};
                let ours = land == Land::Held
                    || (get_stack_height() == TRANSACTION_LEVEL_STACK_HEIGHT
                        && engine::read_global(&ctx.remaining_accounts[gap_at], ctx.program_id)?.map_or(false, |g| g.is_delivery(&ctx.accounts.payer.key())));
                if ours {
                    let need = Rent::get()?.minimum_balance(GapReceipt::space(compose_msg.len()));
                    require!(receipt.lamports() >= need, OFTError::GapReceiveNotAllowed);
                }
            }
            write_receipt(
                receipt,
                &ctx.accounts.payer.to_account_info(),
                &ctx.accounts.system_program.to_account_info(),
                ctx.program_id,
                GapReceipt {
                    version: 1,
                    bump: 0,
                    oft_store: ctx.accounts.oft_store.key(),
                    guid: params.guid,
                    src_eid: params.src_eid,
                    nonce: params.nonce,
                    to: ctx.accounts.to_address.key(),
                    payer: ctx.accounts.payer.key(),
                    amount_ld,
                    // oft-q7: everything held back (gap fee + delivery cost), so amount = withheld + credited
                    withheld_ld: withheld + delivery,
                    credited_ld: amount_received_ld,
                    reason: outcome.reason,
                    created_at: Clock::get()?.unix_timestamp,
                    compose_from,
                    compose_msg,
                    prepaid,
                    refund_to: Pubkey::default(),
                },
            )?;
        }

        // oft-fix L-1: a composed codec v3 arrival that writes NO receipt -- `land_held_receive`'s plain
        // land of an unlisted composer, the escape with an unlisted composer, an unlisted composer's
        // zero credit -- would leave the sender's prepay P stranded at its GapPrepay PDA
        // (`sweep_gap_prepay` needs a receipt, `sweep_late_prepay` a record). It goes to `to` (the
        // credited party: for a plain land a wallet, checked on the curve above) when the PDA (required
        // above, oft-lows L-3) holds a drop; `to` must then be writable (lz_receive_types lists it so for
        // a composed message), else GapAccountMismatch (retriable). Never a LISTED composer's: with P
        // there its arrival wrote a receipt above (oft-lows L-2), so `listed` is false here whenever
        // the PDA holds lamports.
        // oft-ret (oft-r5 I-2): a `to` that cannot be credited lamports (an executable program account:
        // the runtime refuses ExecutableLamportChange) never blocks the arrival: the tokens land and P
        // (and any later drop) stays at the PDA -- the sender composed to a program id that is not a
        // listed composer; there is no Solana account of theirs to send it to. Before oft-lows L-3 such
        // an arrival could land by omitting the PDA; after it, it reverted on every attempt while the
        // PDA held lamports (anyone could top it up).
        // oft-ret (oft-r5 L-1): an arrival here with NOTHING at the PDA yet writes (or refreshes) the
        // PDA's GapLatePrepay record, refund_to = `to`, when the transaction names it (the remaining
        // account after the PDA; its rent is fronted by the payer, who takes it back with
        // `close_late_prepay`), so a drop that lands after the receive goes to `to` through
        // `sweep_late_prepay` (permissionless) instead of being stranded with no receipt and no record.
        // Optional, not in lz_receive_types: its list is at LayerZero's 30-account most already (4 + 34
        // x 30 <= 1,024 B of return data). Our builders name it (solana/client landHeldReceiveInstruction for
        // the admin's plain land; v3LzReceiveInstruction with the escape on; either when asked). A listed
        // composer's arrival never comes here (it always writes its receipt).
        if !write {
            if let Some(pp) = prepay_acc {
                let (compose_from, compose_msg) = (<[u8; 32]>::try_from(&tail_bytes[..32]).unwrap(), &tail_bytes[32..]);
                let to = ctx.accounts.to_address.to_account_info();
                if !to.executable {
                    if pp.lamports() > 0 {
                        require!(to.is_writable, OFTError::GapAccountMismatch);
                        let n = crate::gap::prepay::sweep(pp, &to, &ctx.accounts.system_program.to_account_info(), ctx.program_id, &ctx.accounts.oft_store.key(), params.src_eid, &compose_from, compose_msg)?;
                        if n > 0 {
                            emit!(GapPrepayReturnedUnreceipted { guid: params.guid, prepay: *pp.key, to: *to.key, lamports: n });
                        }
                    } else {
                        // the address is checked as the sweep checks it: this message's PDA
                        let (want, _) = crate::gap::state::prepay_address(ctx.program_id, &ctx.accounts.oft_store.key(), params.src_eid, &compose_from, compose_msg);
                        require_keys_eq!(*pp.key, want, OFTError::GapAccountMismatch);
                        if let Some(record) = ctx.remaining_accounts.get(gap_at + engine::GAP_ACCOUNTS + 3) {
                            crate::instructions::close_gap_receipt::record_late_prepay_paid(
                                &ctx.accounts.payer.to_account_info(),
                                record,
                                &ctx.accounts.system_program.to_account_info(),
                                ctx.program_id,
                                pp.key,
                                to.key,
                            )?;
                        }
                    }
                }
            }
        }

        // the outcome as one log, for indexers and tests (the events are self-CPIs):
        // "gap" | reason u8 | amount u64 | withheld u64 | pd u128 | gap_ppm u32 | allow_ppm u64 |
        // pair_class u8 | ps u128 | margin_ppm u32 | cover_ppm u32 | src_gas_micro_usd u32 | src_cover_cap_cents u16 |
        // dst_gas_micro_usd u32 | delivery_ld u64 | delivery_sol_usd u128 (oft-q7, appended) (LE; Amendment 6 §4);
        // ps/pd are the pair compared (class prices when pair_class != 0)
        solana_program::log::sol_log_data(&[
            b"gap",
            &[outcome.reason],
            &amount_ld.to_le_bytes(),
            &withheld.to_le_bytes(),
            &outcome.pd_e18.to_le_bytes(),
            &outcome.gap_ppm.to_le_bytes(),
            &outcome.allow_ppm.to_le_bytes(),
            &[outcome.pair_class],
            &outcome.ps_e18.to_le_bytes(),
            &outcome.margin_ppm.to_le_bytes(),
            &outcome.cover_ppm.to_le_bytes(),
            &h.src_gas_micro_usd.to_le_bytes(),
            &h.src_cover_cap_cents.to_le_bytes(),
            &outcome.dst_gas_micro_usd.to_le_bytes(),
            &delivery.to_le_bytes(),
            &outcome.delivery_sol_usd.to_le_bytes(),
        ]);
        if outcome.ata_lamports > 0 {
            emit!(GapAtaCharged { guid: params.guid, token_dest: ctx.accounts.token_dest.key(), ata_lamports: outcome.ata_lamports });
        }
        if delivery > 0 {
            emit!(GapDeliveryCharged {
                guid: params.guid,
                payer: ctx.accounts.payer.key(),
                delivery_ld: delivery,
                lamports: outcome.delivery_lamports,
                sol_usd_e18: outcome.delivery_sol_usd,
            });
        }
        if outcome.reason == math::CHARGED {
            emit_cpi!(GapCharged {
                guid: params.guid,
                src_eid: params.src_eid,
                to: ctx.accounts.to_address.key(),
                amount_ld,
                withheld_ld: withheld,
                ps_e18: outcome.ps_e18,
                pd_e18: outcome.pd_e18,
                gap_ppm: outcome.gap_ppm,
                allow_ppm: outcome.allow_ppm,
                pair_class: outcome.pair_class,
            });
        } else {
            emit_cpi!(GapSkipped { guid: params.guid, src_eid: params.src_eid, reason: outcome.reason });
        }
        emit_cpi!(OFTReceived {
            guid: params.guid,
            src_eid: params.src_eid,
            to: ctx.accounts.to_address.key(),
            amount_received_ld,
        });
        if land == Land::Held {
            emit_cpi!(GapHeldLanded {
                guid: params.guid,
                src_eid: params.src_eid,
                to: ctx.accounts.to_address.key(),
                admin: ctx.accounts.payer.key(),
                withheld_ld: withheld,
                compose_dropped: plain,
                oversized: outcome.oversized,
            });
        }
        Ok(())
    }
}

/// Whether `k` is a point on the ed25519 curve (a wallet's key; a PDA never is): the runtime's
/// curve25519 syscall on chain (Pubkey::is_on_curve is not available there), the same check off chain.
fn on_curve(k: &Pubkey) -> bool {
    #[cfg(target_os = "solana")]
    {
        let mut out = 0u8;
        // curve id 0 = CURVE25519_EDWARDS; the syscall returns 0 for a valid point
        let rc = unsafe { anchor_lang::solana_program::syscalls::sol_curve_validate_point(0, k.as_ref().as_ptr(), &mut out) };
        rc == 0
    }
    #[cfg(not(target_os = "solana"))]
    {
        k.is_on_curve()
    }
}

/// `land_held_receive`'s gate, before anything is cleared or read: `payer` = GapGlobal.admin or a
/// GapGlobal.delivery key (the GapGlobal PDA at the first gap account; NotGapAdmin; a delivery key
/// never for an unlisted compose), the store's escape off and the top level
/// (NotHeldReceive). Returns whether the arrival lands plain: a composed codec v3 message whose
/// `to` is not a listed composer. Whether it is actually held is checked once it is priced.
fn held_allowed(ctx: &Context<'_, '_, '_, '_, LzReceive<'_>>, h: &math::Header, tail: &Tail) -> Result<bool> {
    use anchor_lang::solana_program::instruction::{get_stack_height, TRANSACTION_LEVEL_STACK_HEIGHT};
    let info = ctx.remaining_accounts.get(Clear::MIN_ACCOUNTS_LEN).ok_or(OFTError::GapAccountMismatch)?;
    let g = engine::read_global(info, ctx.program_id)?.ok_or(OFTError::NotGapAdmin)?;
    let payer = ctx.accounts.payer.key();
    // owner decision 2026-10-30 (lead #3, "no cap, no queue"): a GapGlobal delivery key may land
    // the OVERSIZED case too (same r0 pricing, mandatory Pd floor, top level); the unlisted-compose
    // PLAIN land stays the admin's alone (it needs a human check that `to` is a spendable wallet)
    let admin = payer == g.admin;
    require!(admin || g.is_delivery(&payer), OFTError::NotGapAdmin);
    require!(!tail.escape, OFTError::NotHeldReceive);
    require!(get_stack_height() == TRANSACTION_LEVEL_STACK_HEIGHT, OFTError::NotHeldReceive);
    let unlisted_compose = h.v1 && h.composed && !g.is_composer(&ctx.accounts.to_address.key());
    // a delivery key never lands an unlisted compose, plain or oversized
    require!(admin || !unlisted_compose, OFTError::NotGapAdmin);
    Ok(unlisted_compose)
}

/// Create the guid's `GapReceipt` at `info` (it must be the PDA), paid by `payer`. Lamports sent
/// to the address beforehand do not block it (topped up, then allocated and assigned).
fn write_receipt<'info>(
    info: &AccountInfo<'info>,
    payer: &AccountInfo<'info>,
    system: &AccountInfo<'info>,
    program_id: &Pubkey,
    mut r: GapReceipt,
) -> Result<()> {
    let (key, bump) = GapReceipt::address(program_id, &r.guid);
    require_keys_eq!(*info.key, key, OFTError::GapAccountMismatch);
    r.bump = bump;
    let space = GapReceipt::space(r.compose_msg.len());
    let seeds: &[&[u8]] = &[GAP_RECEIPT_SEED, &r.guid, &[bump]];
    let need = Rent::get()?.minimum_balance(space);
    // never over an existing record: a guid arrives once (the endpoint's clear), and a closed
    // receipt's address is empty again
    require!(info.data_is_empty() && *info.owner == anchor_lang::system_program::ID, OFTError::GapAccountMismatch);
    let have = info.lamports();
    if have == 0 {
        invoke_signed(
            &system_instruction::create_account(payer.key, info.key, need, space as u64, program_id),
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
        invoke_signed(&system_instruction::allocate(info.key, space as u64), &[info.clone(), system.clone()], &[seeds])?;
        invoke_signed(&system_instruction::assign(info.key, program_id), &[info.clone(), system.clone()], &[seeds])?;
    }
    let mut d = info.try_borrow_mut_data()?;
    r.try_serialize(&mut &mut d[..])?;
    Ok(())
}
