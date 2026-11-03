//! Pangea v3 `return_expired_compose` (docs/v3-gap-fee-spec.md §10.7): sends an expired composed
//! sale's tokens back to its sender, with no trust in anyone.
//!
//! A composed v1 arrival on a v3 store credits the composer (`receipt.to`) and writes the guid's
//! `GapReceipt` (§10.5). When the composer gives up on the call (cheapest's `release_expired_v3`),
//! it approves `PDA(["GapReturn", guid])` as the delegate of its token account for what it
//! returns. Then anyone may call this instruction (and pay LayerZero's fee): it takes
//! `min(delegated, credited)` rounded down to the shared-decimals unit (the dust stays with the
//! composer), burns it (Native) or locks it in the escrow (Adapter: what the escrow receives, net of
//! a Token-2022 transfer fee and dust; round 2 B I-1), sends it to `compose_from`
//! on the source chain as an uncomposed codec-v3 refund (amendment 2: price class 255, psUsd =
//! psClass = 0, which every v3 receive credits in full as REFUND; no bridge fee), and closes the receipt to its payer. The delegate PDA is per guid, so an approval
//! for one sale can never return another. A sale credited below one shared-decimals unit cannot
//! cross: with the approval, its receipt is closed with a zero return and no message (the credit
//! stays with the composer), so an expired receipt can always be closed. Only receipts whose `to` is in `GapGlobal.composers`
//! (the admin's allowlist; empty refuses all) can be returned.
use crate::gap::{
    math,
    state::{read_owned, GapGlobal, GapReceipt, GAP_GLOBAL_SEED, GAP_RECEIPT_SEED},
};
use crate::*;
use anchor_lang::solana_program::instruction::{get_stack_height, TRANSACTION_LEVEL_STACK_HEIGHT};
use anchor_spl::{
    associated_token::get_associated_token_address_with_program_id,
    token_2022::spl_token_2022::solana_program::program_option::COption,
    token_interface::{self, Burn, Mint, TokenAccount, TokenInterface, TransferChecked},
};
use oapp::endpoint::{instructions::SendParams as EndpointSendParams, MessagingReceipt};

pub const GAP_RETURN_SEED: &[u8] = b"GapReturn";

/// oft-ret (cheapest-r4 M-1 (a)): the options a refund marker is sent home with: type 3 | executor
/// (worker 1) | size 17 | lzReceive (1) | gas u128 BE = `gas` (GapGlobal.refund_lz_gas) -- the same
/// shape as send_v3's KEYS_ONLY_OPTIONS, no value. A class-255 REFUND receive on EVM is uncharged and
/// permissionless (PangeaOFTV3GapModule.gapReceive: GapUntrustedExecutor gates only CHARGED
/// live-price receives), so LayerZero's executor, paid for exactly this gas out of the caller's fee
/// (reimbursed from the sender's prepay), lands it on every EVM chain, keys-only Ethereum included.
pub fn refund_options(gas: u32) -> [u8; 22] {
    let mut o = [0u8; 22];
    o[..6].copy_from_slice(&[0, 3, 1, 0, 17, 1]);
    o[6..].copy_from_slice(&(gas as u128).to_be_bytes());
    o
}

#[derive(Clone, AnchorSerialize, AnchorDeserialize)]
pub struct ReturnComposeParams {
    pub guid: [u8; 32],
    pub native_fee: u64,
    pub lz_token_fee: u64,
}

#[event]
pub struct GapComposeReturned {
    pub guid: [u8; 32],
    pub dst_eid: u32,
    /// The original sender (the receipt's compose_from), who gets the tokens back.
    pub to: [u8; 32],
    /// What crosses (round 2 B I-1: for an Adapter, what the escrow received, net of a Token-2022
    /// transfer fee, dust removed).
    pub amount_ld: u64,
    /// What stayed with the composer: min(delegated, credited) below the shared-decimals unit.
    pub dust_ld: u64,
}

#[event_cpi]
#[derive(Accounts)]
#[instruction(params: ReturnComposeParams)]
pub struct ReturnExpiredCompose<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    /// Writable in the transaction; not `mut` here: a fifth `Account<PeerConfig>` exit made the
    /// compiler stop inlining its serialiser and cost `set_peer_config` ~3,000 CU. The rate
    /// limiters it changes are written back by hand (`write_limiters`).
    #[account(
        seeds = [PEER_SEED, oft_store.key().as_ref(), &gap_receipt.src_eid.to_be_bytes()],
        bump = peer.bump,
        constraint = peer.peer_address != [0u8; 32] @OFTError::InvalidSender
    )]
    pub peer: Account<'info, PeerConfig>,
    #[account(mut, seeds = [OFT_SEED, oft_store.token_escrow.as_ref()], bump = oft_store.bump)]
    pub oft_store: Account<'info, OFTStore>,
    #[account(
        mut,
        close = receipt_payer,
        seeds = [GAP_RECEIPT_SEED, params.guid.as_ref()],
        bump = gap_receipt.bump,
        constraint = gap_receipt.version == 1 @OFTError::GapAccountMismatch,
        constraint = gap_receipt.guid == params.guid @OFTError::GapAccountMismatch,
        constraint = gap_receipt.oft_store == oft_store.key() @OFTError::GapAccountMismatch
    )]
    pub gap_receipt: Account<'info, GapReceipt>,
    #[account(
        mut,
        address = get_associated_token_address_with_program_id(&gap_receipt.to, &oft_store.token_mint, &token_program.key()) @OFTError::GapAccountMismatch,
        token::mint = token_mint,
        token::token_program = token_program
    )]
    pub composer_token: InterfaceAccount<'info, TokenAccount>,
    /// CHECK: the per-guid delegate PDA; the program signs as it
    #[account(seeds = [GAP_RETURN_SEED, params.guid.as_ref()], bump)]
    pub return_delegate: UncheckedAccount<'info>,
    /// CHECK: the receipt's payer, who gets its rent back (address checked)
    #[account(mut, address = gap_receipt.payer @OFTError::GapAccountMismatch)]
    pub receipt_payer: UncheckedAccount<'info>,
    #[account(
        mut,
        address = oft_store.token_escrow,
        token::authority = oft_store,
        token::mint = token_mint,
        token::token_program = token_program
    )]
    pub token_escrow: InterfaceAccount<'info, TokenAccount>,
    #[account(mut, address = oft_store.token_mint, mint::token_program = token_program)]
    pub token_mint: InterfaceAccount<'info, Mint>,
    pub token_program: Interface<'info, TokenInterface>,
    /// The receipt's `to` must be an allowlisted composer (`GapGlobal.composers`): a composer
    /// program that only approves a return for a sale it gave up on. A wallet as `to` could
    /// approve its own return and bridge home with Ps = 0 and no bridge fee (audit round 1, H-1).
    /// Read by hand in `apply` (owner, PDA, then `is_composer`): an `Account<GapGlobal>` here took
    /// `try_accounts` 128 bytes over the 4,096-byte stack frame.
    /// CHECK: owner = this program, the `["GapGlobal"]` PDA, deserialised in `apply`
    pub gap_global: UncheckedAccount<'info>,
    /// L4: where the sender's prepaid lamports left after the caller's reimbursement go: must be
    /// receipt.refund_to when it is set; when it is not, the caller gets them (pass `payer`).
    /// CHECK: address checked in `apply`; only credited. Writable in the transaction; not `mut` here
    /// (oft-lows6, oft-lows5-r1 L-1): a refund_to the runtime makes read-only (a reserved key, a sysvar)
    /// would fail Anchor's mut check on every try and block the return for good; `settle_prepaid` gives
    /// its part to the caller instead (`cannot_hold`), and refuses one passed read-only by choice.
    pub refund_to: UncheckedAccount<'info>,
}

impl ReturnExpiredCompose<'_> {
    pub fn apply(ctx: &mut Context<ReturnExpiredCompose>, params: &ReturnComposeParams) -> Result<MessagingReceipt> {
        require!(get_stack_height() == TRANSACTION_LEVEL_STACK_HEIGHT, OFTError::SendViaCpi);
        require!(crate::gap::state::is_v3_store(&ctx.accounts.oft_store.to_account_info()), OFTError::NotV3Store);
        require!(!ctx.accounts.oft_store.paused, OFTError::Paused);
        // only an allowlisted composer's receipt goes home (round 1, H-1)
        let g: GapGlobal = read_owned(&ctx.accounts.gap_global, ctx.program_id).ok_or(OFTError::GapAccountMismatch)?;
        let want = Pubkey::create_program_address(&[GAP_GLOBAL_SEED, &[g.bump]], ctx.program_id).map_err(|_| OFTError::GapAccountMismatch)?;
        require_keys_eq!(ctx.accounts.gap_global.key(), want, OFTError::GapAccountMismatch);
        require!(g.is_composer(&ctx.accounts.gap_receipt.to), OFTError::ComposerNotAllowed);

        let delegate = ctx.accounts.return_delegate.key();
        require!(ctx.accounts.composer_token.delegate == COption::Some(delegate), OFTError::ReturnNotApproved);
        let credited = ctx.accounts.gap_receipt.credited_ld;
        let wanted = ctx.accounts.composer_token.delegated_amount.min(credited);
        let amount_ld = ctx.accounts.oft_store.remove_dust(wanted);
        let dust_ld = wanted - amount_ld;
        let guid = params.guid;
        if amount_ld == 0 {
            // Nothing can cross: a sale credited below one shared-decimals unit (audit round 1
            // Solana, I-1). The approval still says the composer gave up; the receipt closes with
            // a zero return and no message, the sub-unit credit stays with the composer (no
            // Solana account of the source-chain sender to send it to). A receipt credited at
            // least one unit still needs an approval of at least one unit.
            require!(ctx.accounts.oft_store.remove_dust(credited) == 0, OFTError::ReturnNotApproved);
            let dst_eid = ctx.accounts.gap_receipt.src_eid;
            let to = ctx.accounts.gap_receipt.compose_from;
            settle_prepaid(ctx, 0, g.return_gas_lamports as u64)?;
            emit_cpi!(GapComposeReturned { guid, dst_eid, to, amount_ld: 0, dust_ld });
            anchor_lang::solana_program::log::sol_log_data(&[
                b"gap-return",
                &guid,
                &dst_eid.to_le_bytes(),
                &0u64.to_le_bytes(),
                &dust_ld.to_le_bytes(),
            ]);
            return Ok(MessagingReceipt::default());
        }


        let bump = [ctx.bumps.return_delegate];
        let delegate_seeds: &[&[u8]] = &[GAP_RETURN_SEED, &guid, &bump];
        // what crosses: round 2 B I-1 -- an Adapter's escrow receives `amount_ld` less the mint's
        // Token-2022 transfer fee (none for Pangea mints), so only that, dust removed, is locked
        // (tvl_ld) and sent home; the rest stays in the escrow as fees. Before, tvl_ld grew by the
        // full amount, so the escrow held less than its TVL and the refund minted more on the other
        // side than this side had locked.
        let sent_ld = if ctx.accounts.oft_store.oft_type == OFTType::Adapter {
            token_interface::transfer_checked(
                CpiContext::new(
                    ctx.accounts.token_program.to_account_info(),
                    TransferChecked {
                        from: ctx.accounts.composer_token.to_account_info(),
                        mint: ctx.accounts.token_mint.to_account_info(),
                        to: ctx.accounts.token_escrow.to_account_info(),
                        authority: ctx.accounts.return_delegate.to_account_info(),
                    },
                )
                .with_signer(&[delegate_seeds]),
                amount_ld,
                ctx.accounts.token_mint.decimals,
            )?;
            let locked = ctx.accounts.oft_store.remove_dust(get_post_fee_amount_ld(&ctx.accounts.token_mint, amount_ld)?);
            ctx.accounts.oft_store.tvl_ld += locked;
            locked
        } else {
            token_interface::burn(
                CpiContext::new(
                    ctx.accounts.token_program.to_account_info(),
                    Burn {
                        mint: ctx.accounts.token_mint.to_account_info(),
                        from: ctx.accounts.composer_token.to_account_info(),
                        authority: ctx.accounts.return_delegate.to_account_info(),
                    },
                )
                .with_signer(&[delegate_seeds]),
                amount_ld,
            )?;
            amount_ld
        };

        // rate limiters as in send: outbound consume, inbound refill
        let mut outbound = ctx.accounts.peer.outbound_rate_limiter.clone();
        let mut inbound = ctx.accounts.peer.inbound_rate_limiter.clone();
        if let Some(l) = outbound.as_mut() {
            l.try_consume(sent_ld)?;
        }
        if let Some(l) = inbound.as_mut() {
            l.refill(sent_ld)?;
        }
        if outbound.is_some() || inbound.is_some() {
            write_limiters(&ctx.accounts.peer.to_account_info(), outbound.as_ref(), inbound.as_ref())?;
        }

        // the refund (amendment 2): uncomposed codec v3 with the refund marker -- class 255, psUsd =
        // psClass = 0 -- which every v3 receive credits in full (REFUND); no bridge fee
        let to = ctx.accounts.gap_receipt.compose_from;
        let dst_eid = ctx.accounts.gap_receipt.src_eid;
        let amount_sd = ctx.accounts.oft_store.ld2sd(sent_ld);
        let message = math::encode(to, amount_sd, 0, 0, 0, 0, math::REFUND_CLASS, 0, 0, 0, None);
        require!(
            ctx.remaining_accounts.len() > 1 && ctx.accounts.oft_store.key() == ctx.remaining_accounts[1].key(),
            OFTError::InvalidSender
        );
        // L4: LayerZero's fee as the caller actually paid it (its balance before and after the CPI)
        let before = ctx.accounts.payer.lamports();
        let receipt = oapp::endpoint_cpi::send(
            ctx.accounts.oft_store.endpoint_program,
            ctx.accounts.oft_store.key(),
            ctx.remaining_accounts,
            &[OFT_SEED, ctx.accounts.token_escrow.key().as_ref(), &[ctx.accounts.oft_store.bump]],
            EndpointSendParams {
                dst_eid,
                receiver: ctx.accounts.peer.peer_address,
                message,
                // oft-ret (cheapest-r4 M-1 (a)): a refund-sized lzReceive gas (GapGlobal.refund_lz_gas),
                // not the store's 1.27M price-path enforced options; out of range: the enforced ones
                options: match g.refund_gas() {
                    Some(gas) => refund_options(gas).to_vec(),
                    None => ctx.accounts.peer.enforced_options.combine_options(&None, &Vec::new())?,
                },
                native_fee: params.native_fee,
                lz_token_fee: params.lz_token_fee,
            },
        )?;

        let spent = before.saturating_sub(ctx.accounts.payer.lamports());
        settle_prepaid(ctx, spent, g.return_gas_lamports as u64)?;
        emit_cpi!(GapComposeReturned { guid, dst_eid, to, amount_ld: sent_ld, dust_ld });
        // "gap-return" | guid | dst_eid u32 | amount u64 | dust u64 (LE)
        anchor_lang::solana_program::log::sol_log_data(&[
            b"gap-return",
            &guid,
            &dst_eid.to_le_bytes(),
            &sent_ld.to_le_bytes(),
            &dust_ld.to_le_bytes(),
        ]);
        // the receipt is closed to its payer by `close = receipt_payer` when the instruction exits
        Ok(receipt)
    }
}

/// Write the peer's two rate limiters back in place (Borsh, as Anchor would): after the
/// discriminator, the address and the two enforced-option blobs come `Option<RateLimiter>` twice
/// (tag u8, then capacity, tokens, refill_per_second, last_refill_time as u64 LE). Only a limiter
/// that exists is written, so the record's length never changes.
fn write_limiters(peer: &AccountInfo, outbound: Option<&RateLimiter>, inbound: Option<&RateLimiter>) -> Result<()> {
    require!(peer.is_writable, OFTError::RateLimitExceeded);
    let mut d = peer.try_borrow_mut_data()?;
    let blob = |d: &[u8], at: usize| -> Option<usize> { Some(at + 4 + u32::from_le_bytes(d.get(at..at + 4)?.try_into().ok()?) as usize) };
    let mut at = 8 + 32;
    at = blob(&d, at).ok_or(OFTError::RateLimitExceeded)?;
    at = blob(&d, at).ok_or(OFTError::RateLimitExceeded)?;
    for l in [outbound, inbound] {
        let tag = *d.get(at).ok_or(OFTError::RateLimitExceeded)?;
        at += 1;
        if tag == 1 {
            let l = l.ok_or(OFTError::RateLimitExceeded)?;
            let out = d.get_mut(at..at + 32).ok_or(OFTError::RateLimitExceeded)?;
            for (i, v) in [l.capacity, l.tokens, l.refill_per_second, l.last_refill_time].iter().enumerate() {
                out[8 * i..8 * i + 8].copy_from_slice(&v.to_le_bytes());
            }
            at += 32;
        }
    }
    Ok(())
}

/// L4: the receipt's prepaid lamports (the sender's) on a return: the caller (`payer`) is reimbursed
/// LayerZero's fee as spent plus the return gas, at most `prepaid`; the rest goes to receipt.refund_to
/// (the account must be it), or to the caller when none is set or when refund_to could not hold it
/// rent-exempt. The receipt's other lamports (rent a payer fronted) go to receipt.payer by
/// `close = receipt_payer`.
fn settle_prepaid(ctx: &mut Context<ReturnExpiredCompose>, spent: u64, gas: u64) -> Result<()> {
    let info = ctx.accounts.gap_receipt.to_account_info();
    let prepaid = ctx.accounts.gap_receipt.prepaid.min(info.lamports());
    if prepaid == 0 {
        return Ok(());
    }
    let (pay, rest) = crate::gap::prepay::return_split(prepaid, spent, gas);
    let payer = ctx.accounts.payer.to_account_info();
    crate::gap::prepay::move_lamports(&info, &payer, pay)?;
    let set = ctx.accounts.gap_receipt.refund_to;
    if set == Pubkey::default() {
        crate::gap::prepay::move_lamports(&info, &payer, rest)?;
    } else {
        require_keys_eq!(ctx.accounts.refund_to.key(), set, OFTError::GapAccountMismatch);
        let refund = ctx.accounts.refund_to.to_account_info();
        // A refund account that could not hold the rest rent-exempt (an empty box given a crumb:
        // the transfer would fail the runtime's rent check and block the return for good -- anyone
        // can grief that by dropping ~X + Y + 1 at the prepay PDA) gives way: the caller takes it.
        // oft-lows5 (xd-solevm L-1, lead8 option (a)): an EXECUTABLE refund_to (a program id) can never
        // be credited (ExecutableLamportChange on every try): the caller takes the rest too, named by
        // GapPrepaidRefundToExecutable for a manual return.
        // oft-lows6 (oft-lows5-r1 L-1): the same for a refund_to the runtime keeps READ-ONLY (a reserved key,
        // a sysvar: ReadonlyLamportChange); one passed read-only by choice is refused (RefundNotWritable).
        let min = Rent::get()?.minimum_balance(refund.data_len());
        if rest > 0 && crate::gap::prepay::cannot_hold(&refund)? {
            crate::gap::prepay::move_lamports(&info, &payer, rest)?;
            emit!(GapPrepaidRefundToExecutable { guid: ctx.accounts.gap_receipt.guid, receipt: *info.key, recipient: *refund.key, payer: *payer.key, lamports: rest });
        } else if rest > 0 && refund.lamports().saturating_add(rest) < min {
            crate::gap::prepay::move_lamports(&info, &payer, rest)?;
        } else {
            crate::gap::prepay::move_lamports(&info, &refund, rest)?;
        }
    }
    ctx.accounts.gap_receipt.prepaid = 0;
    anchor_lang::solana_program::log::sol_log_data(&[b"gap-prepaid", &ctx.accounts.gap_receipt.guid, &pay.to_le_bytes(), &rest.to_le_bytes()]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_refund_options_are_one_executor_lz_receive_option_of_the_refund_gas() {
        let o = refund_options(740_000);
        assert_eq!(&o[..6], &[0, 3, 1, 0, 17, 1]);
        assert_eq!(u128::from_be_bytes(o[6..].try_into().unwrap()), 740_000);
        // gas 1 is exactly send_v3's KEYS_ONLY_OPTIONS (the same shape)
        assert_eq!(refund_options(1), crate::instructions::send_v3::KEYS_ONLY_OPTIONS);
    }
}
