use crate::*;

#[derive(Accounts)]
#[instruction(params: SetPeerConfigParams)]
pub struct SetPeerConfig<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,
    #[account(
        init_if_needed,
        payer = admin,
        // Pangea (PANGEA-PATCH.md, patch 2): created at its smallest layout, grown by `grow`.
        // `peer` here is still the raw AccountInfo: Anchor evaluates `space` before it wraps it.
        space = PeerConfig::space_for(peer),
        seeds = [PEER_SEED, oft_store.key().as_ref(), &params.remote_eid.to_be_bytes()],
        bump
    )]
    pub peer: Account<'info, PeerConfig>,
    #[account(
        seeds = [OFT_SEED, oft_store.token_escrow.as_ref()],
        bump = oft_store.bump,
        has_one = admin @OFTError::Unauthorized
    )]
    pub oft_store: Account<'info, OFTStore>,
    pub system_program: Program<'info, System>,
}

impl SetPeerConfig<'_> {
    pub fn apply(ctx: &mut Context<SetPeerConfig>, params: &SetPeerConfigParams) -> Result<()> {
        match params.config.clone() {
            PeerConfigParam::PeerAddress(peer_address) => {
                ctx.accounts.peer.peer_address = peer_address;
            },
            PeerConfigParam::FeeBps(fee_bps) => {
                if let Some(fee_bps) = fee_bps {
                    require!(fee_bps < MAX_FEE_BASIS_POINTS, OFTError::InvalidFee);
                }
                ctx.accounts.peer.fee_bps = fee_bps;
            },
            PeerConfigParam::EnforcedOptions { send, send_and_call } => {
                oapp::options::assert_type_3(&send)?;
                ctx.accounts.peer.enforced_options.send = send;
                oapp::options::assert_type_3(&send_and_call)?;
                ctx.accounts.peer.enforced_options.send_and_call = send_and_call;
            },
            PeerConfigParam::OutboundRateLimit(rate_limit_params) => {
                Self::update_rate_limiter(
                    &mut ctx.accounts.peer.outbound_rate_limiter,
                    &rate_limit_params,
                )?;
            },
            PeerConfigParam::InboundRateLimit(rate_limit_params) => {
                Self::update_rate_limiter(
                    &mut ctx.accounts.peer.inbound_rate_limiter,
                    &rate_limit_params,
                )?;
            },
        }
        ctx.accounts.peer.bump = ctx.bumps.peer;
        Self::grow(ctx)
    }

    /// Pangea (PANGEA-PATCH.md, patch 2): make the peer's account big enough for what was just
    /// written, before Anchor serialises it back on exit. Only ever grows; the store's admin (the
    /// signer this instruction already requires) tops the rent up to exemption at the new size.
    /// Never past LayerZero's own 1,654 bytes: a record that would not fit there is refused with
    /// the error LayerZero's program gives it (`AccountDidNotSerialize`).
    fn grow(ctx: &mut Context<SetPeerConfig>) -> Result<()> {
        let need = ctx.accounts.peer.serialized_len()?;
        let info = ctx.accounts.peer.to_account_info();
        if need <= info.data_len() {
            return Ok(());
        }
        require!(need <= PEER_CONFIG_MAX_LEN, anchor_lang::error::ErrorCode::AccountDidNotSerialize);
        let short = Rent::get()?.minimum_balance(need).saturating_sub(info.lamports());
        if short > 0 {
            anchor_lang::system_program::transfer(
                CpiContext::new(
                    ctx.accounts.system_program.to_account_info(),
                    anchor_lang::system_program::Transfer {
                        from: ctx.accounts.admin.to_account_info(),
                        to: info.clone(),
                    },
                ),
                short,
            )?;
        }
        info.resize(need)?;
        Ok(())
    }

    fn update_rate_limiter(
        rate_limiter: &mut Option<RateLimiter>,
        params: &Option<RateLimitParams>,
    ) -> Result<()> {
        if let Some(param) = params {
            let mut limiter = rate_limiter.clone().unwrap_or_default();
            if let Some(capacity) = param.capacity {
                limiter.set_capacity(capacity)?;
            }
            if let Some(refill_rate) = param.refill_per_second {
                limiter.set_rate(refill_rate)?;
            }
            *rate_limiter = Some(limiter);
        } else {
            *rate_limiter = None;
        }
        Ok(())
    }
}

#[derive(Clone, AnchorSerialize, AnchorDeserialize)]
pub struct SetPeerConfigParams {
    pub remote_eid: u32,
    pub config: PeerConfigParam,
}

#[derive(Clone, AnchorSerialize, AnchorDeserialize)]
pub enum PeerConfigParam {
    PeerAddress([u8; 32]),
    FeeBps(Option<u16>),
    EnforcedOptions { send: Vec<u8>, send_and_call: Vec<u8> },
    OutboundRateLimit(Option<RateLimitParams>),
    InboundRateLimit(Option<RateLimitParams>),
}

#[derive(Clone, AnchorSerialize, AnchorDeserialize)]
pub struct RateLimitParams {
    pub refill_per_second: Option<u64>,
    pub capacity: Option<u64>,
}
