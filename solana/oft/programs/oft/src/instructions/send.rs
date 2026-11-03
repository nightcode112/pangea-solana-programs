use crate::*;
use anchor_spl::token_interface::{
    self, Burn, Mint, TokenAccount, TokenInterface, TransferChecked,
};
use oapp::endpoint::{instructions::SendParams as EndpointSendParams, MessagingReceipt};

#[event_cpi]
#[derive(Accounts)]
#[instruction(params: SendParams)]
pub struct Send<'info> {
    pub signer: Signer<'info>,
    #[account(
        mut,
        seeds = [
            PEER_SEED,
            oft_store.key().as_ref(),
            &params.dst_eid.to_be_bytes()
        ],
        bump = peer.bump
    )]
    pub peer: Account<'info, PeerConfig>,
    #[account(
        mut,
        seeds = [OFT_SEED, oft_store.token_escrow.as_ref()],
        bump = oft_store.bump
    )]
    pub oft_store: Account<'info, OFTStore>,
    #[account(
        mut,
        token::authority = signer,
        token::mint = token_mint,
        token::token_program = token_program
    )]
    pub token_source: InterfaceAccount<'info, TokenAccount>,
    #[account(
        mut,
        address = oft_store.token_escrow,
        token::authority = oft_store.key(),
        token::mint = token_mint,
        token::token_program = token_program
    )]
    pub token_escrow: InterfaceAccount<'info, TokenAccount>,
    #[account(
        mut,
        address = oft_store.token_mint,
        mint::token_program = token_program
    )]
    pub token_mint: InterfaceAccount<'info, Mint>,
    pub token_program: Interface<'info, TokenInterface>,
}

impl Send<'_> {
    pub fn apply(
        ctx: &mut Context<Send>,
        params: &SendParams,
    ) -> Result<(MessagingReceipt, OFTReceipt)> {
        // Pangea v3: a store made by `init_oft_v3` sends the gap codec (send_v3.rs). Live stores
        // run LayerZero's code below, unchanged.
        if crate::gap::state::is_v3_store(&ctx.accounts.oft_store.to_account_info()) {
            return Send::apply_v3(ctx, params);
        }
        require!(!ctx.accounts.oft_store.paused, OFTError::Paused);

        let (amount_sent_ld, amount_received_ld, oft_fee_ld) = compute_fee_and_adjust_amount(
            params.amount_ld,
            &ctx.accounts.oft_store,
            &ctx.accounts.token_mint,
            ctx.accounts.peer.fee_bps,
        )?;
        require!(amount_received_ld >= params.min_amount_ld, OFTError::SlippageExceeded);

        if let Some(rate_limiter) = ctx.accounts.peer.outbound_rate_limiter.as_mut() {
            rate_limiter.try_consume(amount_received_ld)?;
        }
        if let Some(rate_limiter) = ctx.accounts.peer.inbound_rate_limiter.as_mut() {
            rate_limiter.refill(amount_received_ld)?;
        }

        if ctx.accounts.oft_store.oft_type == OFTType::Adapter {
            // transfer all tokens to escrow with fee
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
            // Native type
            // burn
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

            // transfer fee to escrow
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

        // send message to endpoint
        require!(
            ctx.accounts.oft_store.key() == ctx.remaining_accounts[1].key(),
            OFTError::InvalidSender
        );
        let amount_sd = ctx.accounts.oft_store.ld2sd(amount_received_ld);
        let msg_receipt = oapp::endpoint_cpi::send(
            ctx.accounts.oft_store.endpoint_program,
            ctx.accounts.oft_store.key(),
            ctx.remaining_accounts,
            &[OFT_SEED, ctx.accounts.token_escrow.key().as_ref(), &[ctx.accounts.oft_store.bump]],
            EndpointSendParams {
                dst_eid: params.dst_eid,
                receiver: ctx.accounts.peer.peer_address,
                message: msg_codec::encode(
                    params.to,
                    amount_sd,
                    ctx.accounts.signer.key(),
                    &params.compose_msg,
                ),
                options: ctx
                    .accounts
                    .peer
                    .enforced_options
                    .combine_options(&params.compose_msg, &params.options)?,
                native_fee: params.native_fee,
                lz_token_fee: params.lz_token_fee,
            },
        )?;

        emit_cpi!(OFTSent {
            guid: msg_receipt.guid,
            dst_eid: params.dst_eid,
            from: ctx.accounts.token_source.key(),
            amount_sent_ld,
            amount_received_ld
        });

        Ok((msg_receipt, OFTReceipt { amount_sent_ld, amount_received_ld }))
    }
}

/// LayerZero's `SendParams`, Borsh, field for field -- and then, Pangea v3, an OPTIONAL trailing
/// `min_credited_ld` (u64 LE): the least the destination may credit, in this store's local
/// decimals, carried in the gap message as `ceil(min_credited_ld / ld2sd_rate)` shared decimals
/// (docs/v3-gap-fee-spec.md §4). Absent (LayerZero's SDK and every client before it) is 0, no
/// minimum, and the bytes are exactly LayerZero's; it is written only when non-zero. A live store's
/// send ignores it.
///
/// Amendment 4: then an OPTIONAL `min_ps_usd` (u128 LE, USD 1e18 per whole token): a v3 send refuses
/// (GapPsBelowMin) when the Ps it would carry is below it. The trailing bytes are therefore 0 (none),
/// 8 (min_credited_ld, non-zero) or 24 (min_credited_ld, any, then min_ps_usd, non-zero); 9..23
/// read the 8 and ignore the rest (Anchor ignores trailing data).
/// Step 3 (lead, coordinator-approved): or 25 = min_credited_ld u64 (any; 0 = none) | min_ps_usd u128
/// (any; 0 = none) | flags u8, bit 0 = REQUIRE_COVER (the send refuses GapCoverNotGranted unless it
/// carries the gas cover); flags 0 or any other bit is malformed. Past 25 is ignored. That strict
/// reading is the v3 send's only (`check_trailing`); a LEGACY store's send ignores every trailing
/// byte, as LayerZero's build does (audit r1 L-1).
/// Owner M-1 (2026-10-30, oft-m1): or 57 = the 25 above with flags bit 1 = COSIGNED set (bit 0 may
/// be set too), then the co-signer's Ps ceilings: ps_usd_max u128 (non-zero) | ps_class_max u128
/// (any; a class-priced send refuses unless its psClass is at most it). A COSIGNED send's
/// remaining accounts carry ONE more account, the co-signer, right after the PriceLog (before
/// LayerZero's endpoint accounts); when it signs and is one of GapGlobal.cosigners (oft-fix L-2: a
/// dedicated key with no other role -- the admin, pending admin, registrar and delivery keys are
/// refused as co-signers; sol-lows I-2: this text said "GapGlobal.admin or a delivery key") and the
/// store's escape is off, the send is priced at the WHOLE window's minimum and consumes no
/// capacity (send_v3.rs). Flags 2 or 3 with fewer than 57 bytes, or a ps_usd_max of 0, is malformed.
/// Past 57 is ignored.
/// Step 3: the send's trailing flags byte (the 25th), bit 0.
pub const SEND_FLAG_REQUIRE_COVER: u8 = 1;
/// Owner M-1: the trailing flags byte's bit 1: a co-signed send (57 trailing bytes).
pub const SEND_FLAG_COSIGNED: u8 = 2;
/// Owner M-1: the trailing length of a co-signed send's tail.
pub const SEND_COSIGNED_TAIL: usize = 57;

/// Owner M-1: the co-signer's Ps ceilings (USD 1e18 per whole token; psClass in the store's quote
/// units), part of the signed instruction data.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CosignCeiling {
    pub ps_usd_max: u128,
    pub ps_class_max: u128,
}

#[derive(Clone)]
pub struct SendParams {
    pub dst_eid: u32,
    pub to: [u8; 32],
    pub amount_ld: u64,
    pub min_amount_ld: u64,
    pub options: Vec<u8>,
    pub compose_msg: Option<Vec<u8>>,
    pub native_fee: u64,
    pub lz_token_fee: u64,
    pub min_credited_ld: u64,
    pub min_ps_usd: u128,
    /// Step 3: the 25th trailing byte's bit 0: refuse unless this send carries the gas cover.
    pub require_cover: bool,
    /// Owner M-1: the 25th trailing byte's bit 1 and the two ceilings after it (57 bytes).
    pub cosign: Option<CosignCeiling>,
    /// The trailing bytes are not 0, 8, 24 or >= 25 well-formed ones (cut short, or a written minimum
    /// of 0). Never serialized; only the v3 send acts on it (`check_trailing`).
    pub trailing_bad: bool,
}

impl SendParams {
    /// The v3 send's strict reading of the optional minimums (audit r1 L-1): a malformed tail is
    /// InstructionDidNotDeserialize, as the strict parse returned before this fix. A legacy
    /// store never calls this, so its send ignores trailing bytes as LayerZero's build does.
    pub fn check_trailing(&self) -> Result<()> {
        if self.trailing_bad {
            return Err(anchor_lang::error::ErrorCode::InstructionDidNotDeserialize.into());
        }
        Ok(())
    }
}

impl AnchorSerialize for SendParams {
    fn serialize<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
        self.dst_eid.serialize(w)?;
        self.to.serialize(w)?;
        self.amount_ld.serialize(w)?;
        self.min_amount_ld.serialize(w)?;
        self.options.serialize(w)?;
        self.compose_msg.serialize(w)?;
        self.native_fee.serialize(w)?;
        self.lz_token_fee.serialize(w)?;
        if let Some(c) = self.cosign {
            self.min_credited_ld.serialize(w)?;
            self.min_ps_usd.serialize(w)?;
            let flags = SEND_FLAG_COSIGNED | if self.require_cover { SEND_FLAG_REQUIRE_COVER } else { 0 };
            flags.serialize(w)?;
            c.ps_usd_max.serialize(w)?;
            c.ps_class_max.serialize(w)?;
        } else if self.require_cover {
            self.min_credited_ld.serialize(w)?;
            self.min_ps_usd.serialize(w)?;
            SEND_FLAG_REQUIRE_COVER.serialize(w)?;
        } else if self.min_ps_usd != 0 {
            self.min_credited_ld.serialize(w)?;
            self.min_ps_usd.serialize(w)?;
        } else if self.min_credited_ld != 0 {
            self.min_credited_ld.serialize(w)?;
        }
        Ok(())
    }
}

impl AnchorDeserialize for SendParams {
    fn deserialize_reader<R: std::io::Read>(r: &mut R) -> std::io::Result<Self> {
        let mut p = SendParams {
            dst_eid: u32::deserialize_reader(r)?,
            to: <[u8; 32]>::deserialize_reader(r)?,
            amount_ld: u64::deserialize_reader(r)?,
            min_amount_ld: u64::deserialize_reader(r)?,
            options: Vec::<u8>::deserialize_reader(r)?,
            compose_msg: Option::<Vec<u8>>::deserialize_reader(r)?,
            native_fee: u64::deserialize_reader(r)?,
            lz_token_fee: u64::deserialize_reader(r)?,
            min_credited_ld: 0,
            min_ps_usd: 0,
            require_cover: false,
            cosign: None,
            trailing_bad: false,
        };
        // the optional minimums: nothing, eight bytes (min_credited_ld), 24 (then min_ps_usd) or 25
        // (then the flags); bytes past what is read are ignored, as Anchor ignores trailing data
        // (b902271a)
        let mut b = [0u8; SEND_COSIGNED_TAIL];
        let mut got = 0;
        while got < SEND_COSIGNED_TAIL {
            let n = r.read(&mut b[got..])?;
            if n == 0 {
                break;
            }
            got += n;
        }
        // Audit r1 L-1: this never fails here. A LEGACY store's send ignores trailing bytes exactly
        // as LayerZero's build (live) does; only the v3 send refuses a malformed tail
        // (`check_trailing`), with the same InstructionDidNotDeserialize as before.
        match got {
            0 => {}
            8..=23 => {
                p.min_credited_ld = u64::from_le_bytes(b[..8].try_into().unwrap());
                p.trailing_bad = p.min_credited_ld == 0; // a written min_credited_ld of 0
            }
            24 => {
                p.min_credited_ld = u64::from_le_bytes(b[..8].try_into().unwrap());
                p.min_ps_usd = u128::from_le_bytes(b[8..24].try_into().unwrap());
                p.trailing_bad = p.min_ps_usd == 0; // a written min_ps_usd of 0
            }
            25.. => {
                // step 3: both minimums any (0 = none), then the flags: exactly REQUIRE_COVER (past
                // 25 ignored, as before), or (owner M-1) COSIGNED with or without REQUIRE_COVER and
                // the two ceilings (57 bytes, ps_usd_max non-zero; past 57 ignored)
                p.min_credited_ld = u64::from_le_bytes(b[..8].try_into().unwrap());
                p.min_ps_usd = u128::from_le_bytes(b[8..24].try_into().unwrap());
                let flags = b[24];
                if flags == SEND_FLAG_REQUIRE_COVER {
                    p.require_cover = true;
                } else if flags & !(SEND_FLAG_REQUIRE_COVER | SEND_FLAG_COSIGNED) == 0 && flags & SEND_FLAG_COSIGNED != 0 && got == SEND_COSIGNED_TAIL {
                    p.require_cover = flags & SEND_FLAG_REQUIRE_COVER != 0;
                    let c = CosignCeiling {
                        ps_usd_max: u128::from_le_bytes(b[25..41].try_into().unwrap()),
                        ps_class_max: u128::from_le_bytes(b[41..57].try_into().unwrap()),
                    };
                    p.trailing_bad = c.ps_usd_max == 0;
                    p.cosign = Some(c);
                } else {
                    // another flags byte, or COSIGNED cut short
                    p.trailing_bad = true;
                }
            }
            _ => p.trailing_bad = true, // min_credited_ld cut short
        }
        Ok(p)
    }
}
