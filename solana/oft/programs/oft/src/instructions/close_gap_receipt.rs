//! Pangea v3 `close_gap_receipt` (spec §10.5): only the composer (the receipt's `to`, signing
//! through CPI with its PDA when it acts on the receipt) closes the guid's receipt; otherwise only
//! `return_expired_compose` does (§10.7). Nobody else, at any age: a stranger's close would leave
//! the credited tokens with no record. The rent goes back to whoever paid it.
use crate::gap::state::*;
use crate::*;

#[derive(Accounts)]
pub struct CloseGapReceipt<'info> {
    pub closer: Signer<'info>,
    #[account(
        mut,
        close = payer,
        has_one = payer,
        seeds = [GAP_RECEIPT_SEED, gap_receipt.guid.as_ref()],
        bump = gap_receipt.bump
    )]
    pub gap_receipt: Account<'info, GapReceipt>,
    /// CHECK: the receipt's payer (has_one), who gets the rent back
    #[account(mut)]
    pub payer: UncheckedAccount<'info>,
}

impl<'info> CloseGapReceipt<'info> {
    /// L4: the sender's prepaid lamports (`prepaid`) go to the refund account the composer names as
    /// the first remaining account (cheapest: the sale's proceeds box, home with the proceeds);
    /// required when anything is prepaid. The rest -- rent the payer fronted -- goes to the payer
    /// (`close = payer`), as before.
    ///
    /// Q7-c (oft-q7): an UNFUNDED receipt (prepaid 0: the sender's native drop has not landed --
    /// LayerZero's executor drops in its own instruction, unordered with our delivery) may name
    /// remaining [refund (w), GapLatePrepay PDA (w), system program]: the close then keeps the refund
    /// party in PDA(["GapLatePrepay", the receipt's GapPrepay PDA]) (rent out of the payer's part of
    /// the receipt, given back to the payer by `close_late_prepay`), so `sweep_late_prepay` sends a
    /// drop that lands after the close to it. oft-lows L-1: an existing record (an earlier identical,
    /// unsalted message's: they share the GapPrepay PDA) is REFRESHED -- created_at = now and refund_to
    /// = this close's refund party, its payer (who fronted its rent) unchanged -- so the 1-day TTL runs
    /// from THIS close and the later message's late drop is never stranded.
    ///
    /// oft-lows2 (oft-r6 L-1): the record is written (or refreshed) ALSO when something is prepaid.
    /// `prepaid > 0` does not prove the sender's P is in: dust sent to the public PDA before the
    /// receive is swept as `prepaid` too, and a LayerZero native drop is unordered with the receive
    /// and the close, so P can still land after the close (the PoC: dust 890,880, close, then P =
    /// 3,949,188 left at the PDA for good). The record's rent comes out of the payer's part of the
    /// receipt (lamports - prepaid) when that covers it (record payer = the receipt's payer, as for
    /// an unfunded receipt); otherwise out of the sender's `prepaid` (the refund is that much less)
    /// and the record's payer is the REFUND PARTY, whose lamports it then are: `close_late_prepay`
    /// gives them back to it (signed, or by anyone once the record's TTL has passed). So the
    /// delivery payer never pays for a record it does not get back, and never keeps a sender's lamport.
    ///
    /// oft-lows3 (oft-lows2-r1 L-3, users-pay): when BOTH the payer's part and `prepaid` are below the
    /// record's rent (a short compose_msg, < 97 B, with dust inside a narrow band at the public PDA:
    /// the dust paid part of the receipt's rent), NO record is made and the prepaid is refunded in
    /// full -- the payer never tops up a record that belongs to the refund party (before: the record
    /// took its rent out of the receipt, need - prepaid of it the payer's, which went to the refund
    /// party on close_late_prepay: up to (97 - len) x 6,960 lamports of ours per close).
    ///
    /// oft-lows3 (oft-lows2-r1 I-4): a refund the refund account cannot hold (it would be left below
    /// its rent-exempt minimum: a fresh 0-lamport wallet given less than 890,880) never reverts the
    /// close -- before, a sub-rent remainder (prepaid - record rent) or a griefer's dust failed the
    /// whole transaction (InsufficientFundsForRent), and FastBridge's settle_v3, which must name the
    /// order's recipient, could not settle at all. Such a remainder is paid INTO THE RECORD when the
    /// record is the refund party's (its rent came out of the prepaid, or an earlier close made it so):
    /// close_late_prepay gives the record's lamports, all of them, to the refund party. Otherwise
    /// (no record, or one our payer fronted) it is dust below the rent-exempt minimum that nobody can
    /// hold at that address: it stays in the receipt and goes with the close to the receipt's payer.
    ///
    /// oft-lows4 (oft-lows3-r1 M-1, lead8: "user gets all of P"): when the sender's prepaid paid the
    /// whole receipt rent (P at the PDA before the receive -- the bot's [fund P, lz_receive] or
    /// LayerZero's executor dropping first -- so payer_part is 0) NO record is made from the prepaid:
    /// the full P goes to the refund party (box / recipient) at once, as before oft-lows3. A record out
    /// of the prepaid is made only in the dust case 0 < payer_part < need <= prepaid < receipt rent
    /// (the payer fronted part of the receipt's rent, so a late P is plausible). Lamports anyone gives
    /// the receipt's address count as the payer's part but never re-open that arm: the test is that
    /// `prepaid` covers the receipt's rent, not payer_part alone.
    ///
    /// oft-lows5 (xd-solevm L-1, lead8 option (a)): an EXECUTABLE refund account (a program id named
    /// as a FastBridge order's recipient: settle_v3 must name the order's `to`) cannot be credited
    /// lamports -- the runtime refuses ExecutableLamportChange on every try, so the close, and with it
    /// the settle, could never land (the relayer never repaid, an unfilled order's tokens left in the
    /// vault). It is treated as an account that cannot hold: NO late record is made or refreshed (a
    /// sweep or a close_late_prepay to it would fail the same way), nothing moves to it, and the
    /// prepaid stays in the receipt and goes with the close to the receipt's payer, named by
    /// GapPrepaidRefundToExecutable (receipt, recipient, payer, amount) for a manual return.
    ///
    /// oft-lows6 (oft-lows5-r1 L-1, lead8): the same for a refund account the runtime makes READ-ONLY in
    /// every transaction (`gap::prepay::cannot_hold`: a sysvar, a builtin or other reserved key, the called
    /// program's own id), which can never be credited either (ReadonlyLamportChange): the same event, no
    /// record, nothing to it. A read-only account the runtime would let be written (a wallet passed
    /// read-only) is refused (RefundNotWritable): its refund never goes to anyone else.
    pub fn apply(ctx: &mut Context<'_, '_, '_, 'info, CloseGapReceipt<'info>>) -> Result<()> {
        require_keys_eq!(ctx.accounts.closer.key(), ctx.accounts.gap_receipt.to, OFTError::ReceiptNotClosable);
        let info = ctx.accounts.gap_receipt.to_account_info();
        let mut prepaid = ctx.accounts.gap_receipt.prepaid.min(info.lamports());
        let set = ctx.accounts.gap_receipt.refund_to;
        if prepaid > 0 || ctx.remaining_accounts.len() >= 3 {
            let refund = ctx.remaining_accounts.first().ok_or(OFTError::GapAccountMismatch)?;
            require!(set == Pubkey::default() || *refund.key == set, OFTError::GapAccountMismatch);
            let rent = Rent::get()?;
            // the late record when it is the refund party's (I-4: a remainder it cannot hold goes there)
            let mut refunds_record: Option<&AccountInfo<'info>> = None;
            // oft-lows5: an executable refund holds nothing: no record, no move (the payer keeps it, named).
            // oft-lows6: nor does one the runtime keeps read-only (reserved / sysvar / invoked program).
            let unpayable = crate::gap::prepay::cannot_hold(refund)?;
            if ctx.remaining_accounts.len() >= 3 && !unpayable {
                let (record, system) = (&ctx.remaining_accounts[1], &ctx.remaining_accounts[2]);
                let r = &ctx.accounts.gap_receipt;
                let (prepay, _) = prepay_address(ctx.program_id, &r.oft_store, r.src_eid, &r.compose_from, &r.compose_msg);
                let need = rent.minimum_balance(GapLatePrepay::LEN).saturating_sub(record.lamports());
                let payer_part = info.lamports() - prepaid;
                // oft-lows4 (oft-lows3-r1 M-1): the sender's prepaid paid the WHOLE receipt rent (P was at
                // the PDA before the receive: the bot's [fund P, lz_receive], or LayerZero's executor
                // dropping first), so the receipt's payer fronted nothing (payer_part 0, or only lamports
                // someone gave the receipt's address) and P is in: no late P to record.
                let funded = prepaid >= info.lamports().min(rent.minimum_balance(info.data_len()));
                // who fronts a NEW record's rent: the payer's part when it covers it (the receipt's payer
                // owns the record, as before); else the sender's prepaid when IT covers it AND the payer
                // fronted part of the receipt's rent (0 < payer_part < need <= prepaid < receipt rent: the
                // dust case, a late P plausible; the refund party owns the record); else nobody -- L-3 and
                // oft-lows4 M-1: no record, the prepaid refunded in full.
                // An existing record is refreshed (no rent; its payer unchanged).
                let plan = if *record.owner == *ctx.program_id || payer_part >= need {
                    Some((r.payer, 0))
                } else if payer_part > 0 && !funded && prepaid >= need {
                    Some((*refund.key, need))
                } else {
                    None
                };
                if let Some((owner, from_prepaid)) = plan {
                    let record_payer = record_late_prepay(&info, record, system, ctx.program_id, &prepay, refund.key, &owner)?;
                    prepaid -= from_prepaid;
                    if record_payer == *refund.key {
                        refunds_record = Some(record);
                    }
                }
            }
            if prepaid > 0 && unpayable {
                let r = &ctx.accounts.gap_receipt;
                emit!(GapPrepaidRefundToExecutable { guid: r.guid, receipt: *info.key, recipient: *refund.key, payer: r.payer, lamports: prepaid });
            } else if prepaid > 0 {
                let holds = refund.lamports().saturating_add(prepaid) >= rent.minimum_balance(refund.data_len());
                let to = if holds { Some(refund) } else { refunds_record };
                if let Some(to) = to {
                    crate::gap::prepay::move_lamports(&info, to, prepaid)?;
                    emit!(GapPrepaidRefunded { guid: ctx.accounts.gap_receipt.guid, to: *to.key, lamports: prepaid });
                }
            }
            ctx.accounts.gap_receipt.prepaid = 0;
        }
        Ok(())
    }
}

/// Q7-c: create PDA(["GapLatePrepay", prepay]) = {prepay, refund_to, payer}, its rent moved out of
/// `from` (the closing receipt, this program's). oft-lows L-1 (oft-r4-prog): an existing record is
/// refreshed (created_at = now, refund_to = `refund_to`; payer and rent unchanged) instead of being
/// left as it is: with the I-3 TTL a kept record stranded a later identical message's late drop
/// (sweep_late_prepay LatePrepayExpired, sweep_gap_prepay with no receipt).
/// Returns the record's payer (who gets its lamports back on `close_late_prepay`).
fn record_late_prepay<'info>(from: &AccountInfo<'info>, record: &AccountInfo<'info>, system: &AccountInfo<'info>, program_id: &Pubkey, prepay: &Pubkey, refund_to: &Pubkey, payer: &Pubkey) -> Result<Pubkey> {
    use anchor_lang::solana_program::{program::invoke_signed, system_instruction};
    let (key, bump) = GapLatePrepay::address(program_id, prepay);
    require_keys_eq!(*record.key, key, OFTError::GapAccountMismatch);
    require_keys_eq!(*system.key, anchor_lang::system_program::ID, OFTError::GapAccountMismatch);
    if *record.owner == *program_id {
        // already recorded (two identical unsalted messages share one prepay PDA): refresh it
        let mut rec = {
            let d = record.try_borrow_data()?;
            GapLatePrepay::try_deserialize(&mut &d[..])?
        };
        require_keys_eq!(rec.prepay, *prepay, OFTError::GapAccountMismatch);
        rec.refund_to = *refund_to;
        rec.created_at = Clock::get()?.unix_timestamp;
        let mut d = record.try_borrow_mut_data()?;
        rec.try_serialize(&mut &mut d[..])?;
        emit!(GapLatePrepayRecorded { prepay: *prepay, refund_to: *refund_to, payer: rec.payer });
        return Ok(rec.payer);
    }
    require!(record.data_is_empty() && *record.owner == anchor_lang::system_program::ID, OFTError::GapAccountMismatch);
    let seeds: &[&[u8]] = &[GAP_LATE_PREPAY_SEED, prepay.as_ref(), &[bump]];
    // allocate and assign FIRST (the system program's CPIs), then move the rent between this
    // program's own accounts: a lamport move before a CPI that does not name `from` would leave the
    // runtime's view unbalanced (UnbalancedInstruction)
    invoke_signed(&system_instruction::allocate(record.key, GapLatePrepay::LEN as u64), &[record.clone(), system.clone()], &[seeds])?;
    invoke_signed(&system_instruction::assign(record.key, program_id), &[record.clone(), system.clone()], &[seeds])?;
    let need = Rent::get()?.minimum_balance(GapLatePrepay::LEN).saturating_sub(record.lamports());
    crate::gap::prepay::move_lamports(from, record, need)?;
    let rec = GapLatePrepay { version: 1, bump, prepay: *prepay, refund_to: *refund_to, payer: *payer, created_at: Clock::get()?.unix_timestamp };
    let mut d = record.try_borrow_mut_data()?;
    rec.try_serialize(&mut &mut d[..])?;
    emit!(GapLatePrepayRecorded { prepay: *prepay, refund_to: *refund_to, payer: *payer });
    Ok(*payer)
}

/// oft-ret (oft-r5 L-1): the same record for a composed arrival that wrote no receipt and found
/// nothing at its GapPrepay PDA (lz_receive_v3): refund_to = the arrival's `to`, its rent fronted by
/// the receive's `payer` (a signer; `close_late_prepay` gives it back to that payer). An existing
/// record is refreshed as above (payer and rent unchanged).
pub fn record_late_prepay_paid<'info>(payer: &AccountInfo<'info>, record: &AccountInfo<'info>, system: &AccountInfo<'info>, program_id: &Pubkey, prepay: &Pubkey, refund_to: &Pubkey) -> Result<()> {
    use anchor_lang::solana_program::{program::{invoke, invoke_signed}, system_instruction};
    let (key, bump) = GapLatePrepay::address(program_id, prepay);
    require_keys_eq!(*record.key, key, OFTError::GapAccountMismatch);
    require_keys_eq!(*system.key, anchor_lang::system_program::ID, OFTError::GapAccountMismatch);
    if *record.owner == *program_id {
        let mut rec = {
            let d = record.try_borrow_data()?;
            GapLatePrepay::try_deserialize(&mut &d[..])?
        };
        require_keys_eq!(rec.prepay, *prepay, OFTError::GapAccountMismatch);
        rec.refund_to = *refund_to;
        rec.created_at = Clock::get()?.unix_timestamp;
        let mut d = record.try_borrow_mut_data()?;
        rec.try_serialize(&mut &mut d[..])?;
        emit!(GapLatePrepayRecorded { prepay: *prepay, refund_to: *refund_to, payer: rec.payer });
        return Ok(());
    }
    require!(record.data_is_empty() && *record.owner == anchor_lang::system_program::ID, OFTError::GapAccountMismatch);
    let need = Rent::get()?.minimum_balance(GapLatePrepay::LEN).saturating_sub(record.lamports());
    if need > 0 {
        invoke(&system_instruction::transfer(payer.key, record.key, need), &[payer.clone(), record.clone(), system.clone()])?;
    }
    let seeds: &[&[u8]] = &[GAP_LATE_PREPAY_SEED, prepay.as_ref(), &[bump]];
    invoke_signed(&system_instruction::allocate(record.key, GapLatePrepay::LEN as u64), &[record.clone(), system.clone()], &[seeds])?;
    invoke_signed(&system_instruction::assign(record.key, program_id), &[record.clone(), system.clone()], &[seeds])?;
    let rec = GapLatePrepay { version: 1, bump, prepay: *prepay, refund_to: *refund_to, payer: *payer.key, created_at: Clock::get()?.unix_timestamp };
    let mut d = record.try_borrow_mut_data()?;
    rec.try_serialize(&mut &mut d[..])?;
    emit!(GapLatePrepayRecorded { prepay: *prepay, refund_to: *refund_to, payer: *payer.key });
    Ok(())
}

/// Q7-c: permissionless. A drop at the GapPrepay PDA of (oft_store, src_eid, compose_from,
/// sha256(composeMsg) = msg_hash) that landed after its receipt closed goes, all of it, to the
/// refund party the close recorded. The record stays (a second drop is swept the same way) until its
/// payer closes it (`close_late_prepay`). Refused: nothing at the PDA, or a PDA that is not the
/// record's (GapAccountMismatch); oft-fix I-3: more than LATE_PREPAY_TTL_SECS (1 day) after the close
/// that made the record (LatePrepayExpired), so a record never serves the drop of a LATER identical
/// (unsalted) message, which its own receive sweeps into its own receipt; oft-lows L-1: or, when that
/// later message's receipt closed unfunded too, the record its close refreshed (created_at = then).
#[derive(Accounts)]
#[instruction(oft_store: Pubkey, src_eid: u32, compose_from: [u8; 32], msg_hash: [u8; 32])]
pub struct SweepLatePrepay<'info> {
    /// CHECK: the GapPrepay PDA of the arguments (checked in `apply`)
    #[account(mut)]
    pub prepay: UncheckedAccount<'info>,
    #[account(seeds = [GAP_LATE_PREPAY_SEED, prepay.key().as_ref()], bump = late.bump, has_one = prepay, has_one = refund_to)]
    pub late: Account<'info, GapLatePrepay>,
    /// CHECK: the recorded refund party (has_one)
    #[account(mut)]
    pub refund_to: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

impl SweepLatePrepay<'_> {
    pub fn apply(ctx: &mut Context<SweepLatePrepay>, oft_store: Pubkey, src_eid: u32, compose_from: [u8; 32], msg_hash: [u8; 32]) -> Result<()> {
        use anchor_lang::solana_program::{program::invoke_signed, system_instruction};
        let prepay = ctx.accounts.prepay.to_account_info();
        let (key, bump) = prepay_address_of_hash(ctx.program_id, &oft_store, src_eid, &compose_from, &msg_hash);
        require_keys_eq!(*prepay.key, key, OFTError::GapAccountMismatch);
        let n = prepay.lamports();
        require!(n > 0 && *prepay.owner == anchor_lang::system_program::ID && prepay.data_is_empty(), OFTError::GapAccountMismatch);
        let age = Clock::get()?.unix_timestamp.saturating_sub(ctx.accounts.late.created_at);
        require!(age <= LATE_PREPAY_TTL_SECS, OFTError::LatePrepayExpired);
        let eid = src_eid.to_be_bytes();
        let seeds: &[&[u8]] = &[GAP_PREPAY_SEED, oft_store.as_ref(), &eid, &compose_from, &msg_hash, &[bump]];
        let to = ctx.accounts.refund_to.to_account_info();
        invoke_signed(&system_instruction::transfer(prepay.key, to.key, n), &[prepay.clone(), to.clone(), ctx.accounts.system_program.to_account_info()], &[seeds])?;
        emit!(GapLatePrepaySwept { prepay: *prepay.key, to: *to.key, lamports: n });
        Ok(())
    }
}

/// Q7-c: the record's payer takes its rent back (giving up drops that land later). oft-lows2
/// (oft-r6 I-4, L-1): the payer signs, OR anyone closes it once LATE_PREPAY_TTL_SECS have passed
/// since it was made or refreshed (`sweep_late_prepay` refuses it then anyway): the rent still goes
/// to the record's payer, so a record our keys fronted (the admin's plain land, an escape receive)
/// comes back without that key's signature, and one a refund party owns (oft-lows2 L-1: rent out of
/// the sender's prepaid) comes back to it even when it cannot sign (a program's PDA).
/// NotLatePrepayPayer: `payer` is not the record's, or it did not sign within the TTL.
#[derive(Accounts)]
pub struct CloseLatePrepay<'info> {
    /// CHECK: the record's payer (checked in `apply`), who gets the rent
    #[account(mut)]
    pub payer: UncheckedAccount<'info>,
    #[account(mut, close = payer, seeds = [GAP_LATE_PREPAY_SEED, late.prepay.as_ref()], bump = late.bump)]
    pub late: Account<'info, GapLatePrepay>,
}

impl CloseLatePrepay<'_> {
    pub fn apply(ctx: &mut Context<CloseLatePrepay>) -> Result<()> {
        require_keys_eq!(ctx.accounts.payer.key(), ctx.accounts.late.payer, OFTError::NotLatePrepayPayer);
        if !ctx.accounts.payer.is_signer {
            let age = Clock::get()?.unix_timestamp.saturating_sub(ctx.accounts.late.created_at);
            require!(age > LATE_PREPAY_TTL_SECS, OFTError::NotLatePrepayPayer);
        }
        Ok(())
    }
}

/// L4: the receipt's `to` (the composer, signing through CPI with its PDA) names the account the
/// sender's prepaid lamports go to on a return; on close it names it again (remaining account).
#[derive(Accounts)]
pub struct SetGapReceiptRefund<'info> {
    pub closer: Signer<'info>,
    #[account(mut, seeds = [GAP_RECEIPT_SEED, gap_receipt.guid.as_ref()], bump = gap_receipt.bump)]
    pub gap_receipt: Account<'info, GapReceipt>,
}

impl SetGapReceiptRefund<'_> {
    pub fn apply(ctx: &mut Context<SetGapReceiptRefund>, refund_to: Pubkey) -> Result<()> {
        require_keys_eq!(ctx.accounts.closer.key(), ctx.accounts.gap_receipt.to, OFTError::ReceiptNotClosable);
        ctx.accounts.gap_receipt.refund_to = refund_to;
        emit!(GapReceiptRefundSet { guid: ctx.accounts.gap_receipt.guid, refund_to });
        Ok(())
    }
}

/// L4: anyone moves a prepay that landed after the receive (the executor's native drop ordering
/// is not ours) into the guid's receipt; it counts as the sender's (`prepaid`). oft-lows (q7b-r2 M-3,
/// lead5 M131) and oft-ret (oft-r5 M-1): the caller states the prepay it expects the receipt to
/// count now (`expect_prepaid`); a receipt counting anything else refuses GapPrepayAlreadyCounted
/// (6079: "the receipt's prepaid is not the expected figure", NOT "already funded") and nothing
/// moves. Our delivery bot's late funding is [fund P, sweep(expect 0)]: a duplicate (the receipt
/// already counts P) reverts whole, its funding with it, so it never leaves the funder (no 2P). A
/// permissionless sweep of a real late drop passes the receipt's current `prepaid` (read just
/// before) and adds to it -- so dust sent to the PDA before the receive (swept by the receive:
/// prepaid = dust > 0) can no longer strand the sender's later P (oft-r5 M-1: before, every later
/// sweep refused and the close made no late record). A drop that is not this receipt's (an
/// identical unsalted message's own) stays at the PDA for that message's receive.
#[derive(Accounts)]
pub struct SweepGapPrepay<'info> {
    #[account(mut, seeds = [GAP_RECEIPT_SEED, gap_receipt.guid.as_ref()], bump = gap_receipt.bump)]
    pub gap_receipt: Account<'info, GapReceipt>,
    /// CHECK: the guid's GapPrepay PDA (address checked in `prepay::sweep`)
    #[account(mut)]
    pub prepay: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

impl SweepGapPrepay<'_> {
    pub fn apply(ctx: &mut Context<SweepGapPrepay>, expect_prepaid: u64) -> Result<()> {
        let r = &ctx.accounts.gap_receipt;
        let (store, eid, from, msg) = (r.oft_store, r.src_eid, r.compose_from, r.compose_msg.clone());
        // the PDA must be this receipt's (GapAccountMismatch, as prepay::sweep checks), then one prepay per receipt
        let (want, _) = prepay_address(ctx.program_id, &store, eid, &from, &msg);
        require_keys_eq!(ctx.accounts.prepay.key(), want, OFTError::GapAccountMismatch);
        require!(r.prepaid == expect_prepaid, OFTError::GapPrepayAlreadyCounted);
        let n = crate::gap::prepay::sweep(&ctx.accounts.prepay.to_account_info(), &ctx.accounts.gap_receipt.to_account_info(), &ctx.accounts.system_program.to_account_info(), ctx.program_id, &store, eid, &from, &msg)?;
        ctx.accounts.gap_receipt.prepaid = ctx.accounts.gap_receipt.prepaid.saturating_add(n);
        Ok(())
    }
}
