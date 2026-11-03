//! Pangea's one addition to LayerZero's OFT program (owner decision, 2026-10-24).
//!
//! An Adapter store starts with `tvl_ld` at zero, so an Adapter cannot be PRE-FUNDED: tokens put
//! in its escrow before any transfer out are not counted as locked, an arrival's
//! `tvl_ld -= amount` overflows (and reverts), and `withdraw_fee` -- which takes anything above
//! `tvl_ld` -- would sweep them as fees. `init_tvl` is the counter: once, for a store that has
//! never locked or released anything, the store's admin declares what its escrow holds to be
//! locked value. Nothing else in the program changes: no instruction, account or layout of
//! LayerZero's is touched, and after this call the store behaves exactly as an Adapter that had
//! locked that amount by `send`.
//!
//! The rules, all of them checked here:
//!   * the store's admin signs (`has_one = admin`);
//!   * the store is an Adapter (a Native store has no locked value: `tvl_ld` is always zero);
//!   * `tvl_ld` is zero -- nothing has been locked by a `send` yet;
//!   * the amount is not zero and is EXACTLY what the escrow holds now -- so no fee already in it,
//!     and nothing that is not in it, can be declared locked;
//!   * once per store, ever: the call creates the store's `TvlMark`, `PDA(["TvlMark", store])`,
//!     with `init`, which fails if it exists. Even a store whose locked value has gone back to zero
//!     cannot be given a new one.
//!
//! The mark records WHO declared the lock: the admin that signed. A store's admin can be handed on
//! afterwards (`set_oft_config` `Admin`), so "the store has a mark and its admin is X" proves
//! nothing about X; "the mark's admin is X" proves X signed it. Pangea's other programs read the
//! mark that way (pangea-cheapest `check_store`: a lockbox store is the launch's when its mark's
//! admin is the splitter's AUTHORITY, which signs `init_tvl` only inside the launch).
use crate::*;
use anchor_spl::token_interface::{TokenAccount, TokenInterface};

pub const TVL_MARK_SEED: &[u8] = b"TvlMark";

/// The proof that a store's `init_tvl` has been made, and by which admin.
#[account]
#[derive(InitSpace)]
pub struct TvlMark {
    /// The store's admin that signed `init_tvl`.
    pub admin: Pubkey,
}

#[event]
pub struct TvlInitialized {
    pub oft_store: Pubkey,
    pub admin: Pubkey,
    pub tvl_ld: u64,
}

#[derive(Accounts)]
pub struct InitTvl<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    pub admin: Signer<'info>,
    #[account(
        mut,
        seeds = [OFT_SEED, oft_store.token_escrow.as_ref()],
        bump = oft_store.bump,
        has_one = admin @OFTError::Unauthorized,
        constraint = oft_store.oft_type == OFTType::Adapter @OFTError::NotAdapter
    )]
    pub oft_store: Account<'info, OFTStore>,
    #[account(
        address = oft_store.token_escrow,
        token::authority = oft_store,
        token::token_program = token_program
    )]
    pub token_escrow: InterfaceAccount<'info, TokenAccount>,
    #[account(
        init,
        payer = payer,
        space = 8 + TvlMark::INIT_SPACE,
        seeds = [TVL_MARK_SEED, oft_store.key().as_ref()],
        bump
    )]
    pub tvl_mark: Account<'info, TvlMark>,
    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}

impl InitTvl<'_> {
    pub fn apply(ctx: &mut Context<InitTvl>, params: &InitTvlParams) -> Result<()> {
        require!(ctx.accounts.oft_store.tvl_ld == 0, OFTError::TvlAlreadySet);
        require!(params.tvl_ld > 0, OFTError::InvalidTvl);
        require!(params.tvl_ld == ctx.accounts.token_escrow.amount, OFTError::InvalidTvl);
        ctx.accounts.oft_store.tvl_ld = params.tvl_ld;
        ctx.accounts.tvl_mark.admin = ctx.accounts.admin.key();
        emit!(TvlInitialized { oft_store: ctx.accounts.oft_store.key(), admin: ctx.accounts.admin.key(), tvl_ld: params.tvl_ld });
        Ok(())
    }
}

#[derive(Clone, AnchorSerialize, AnchorDeserialize)]
pub struct InitTvlParams {
    pub tvl_ld: u64,
}
