//! Pangea v3 `init_oft_v3` (spec §10.3): `init_oft` for a v3 token. Same accounts and params;
//! the store is created at 319 bytes (`tail_ver = 0`: no official pool yet), which is what makes
//! it a v3 store, and the `LzReceiveTypes` PDA at 104 bytes with a third key (the program id
//! until `set_gap_pool` writes the store's `GapRoute` there). `init_oft` is unchanged.
use crate::gap::state::{LZ_RECEIVE_TYPES_SLOT, V3_LZ_RECEIVE_TYPES_LEN, V3_STORE_LEN};
use crate::*;
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface};
use oapp::endpoint::{instructions::RegisterOAppParams, ID as ENDPOINT_ID};

#[derive(Accounts)]
pub struct InitOFTV3<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        init,
        payer = payer,
        space = V3_STORE_LEN,
        seeds = [OFT_SEED, token_escrow.key().as_ref()],
        bump
    )]
    pub oft_store: Account<'info, OFTStore>,
    #[account(
        init,
        payer = payer,
        space = V3_LZ_RECEIVE_TYPES_LEN,
        seeds = [LZ_RECEIVE_TYPES_SEED, oft_store.key().as_ref()],
        bump
    )]
    pub lz_receive_types_accounts: Account<'info, LzReceiveTypesAccounts>,
    #[account(mint::token_program = token_program)]
    pub token_mint: InterfaceAccount<'info, Mint>,
    #[account(
        init,
        payer = payer,
        token::authority = oft_store,
        token::mint = token_mint,
        token::token_program = token_program,
    )]
    pub token_escrow: InterfaceAccount<'info, TokenAccount>,
    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}

impl InitOFTV3<'_> {
    pub fn apply(ctx: &mut Context<InitOFTV3>, params: &InitOFTParams) -> Result<()> {
        // as init_oft
        ctx.accounts.oft_store.oft_type = params.oft_type.clone();
        require!(ctx.accounts.token_mint.decimals >= params.shared_decimals, OFTError::InvalidDecimals);
        ctx.accounts.oft_store.ld2sd_rate = 10u64.pow((ctx.accounts.token_mint.decimals - params.shared_decimals) as u32);
        ctx.accounts.oft_store.token_mint = ctx.accounts.token_mint.key();
        ctx.accounts.oft_store.token_escrow = ctx.accounts.token_escrow.key();
        ctx.accounts.oft_store.endpoint_program = params.endpoint_program.unwrap_or(ENDPOINT_ID);
        ctx.accounts.oft_store.bump = ctx.bumps.oft_store;
        ctx.accounts.oft_store.tvl_ld = 0;
        ctx.accounts.oft_store.admin = params.admin;
        ctx.accounts.oft_store.default_fee_bps = 0;
        ctx.accounts.oft_store.paused = false;
        ctx.accounts.oft_store.pauser = None;
        ctx.accounts.oft_store.unpauser = None;

        ctx.accounts.lz_receive_types_accounts.oft_store = ctx.accounts.oft_store.key();
        ctx.accounts.lz_receive_types_accounts.token_mint = ctx.accounts.token_mint.key();
        {
            // the third key: the GapRoute slot, the program id until set_gap_pool
            let info = ctx.accounts.lz_receive_types_accounts.to_account_info();
            let mut d = info.try_borrow_mut_data()?;
            d[LZ_RECEIVE_TYPES_SLOT..LZ_RECEIVE_TYPES_SLOT + 32].copy_from_slice(ctx.program_id.as_ref());
        }

        oapp::endpoint_cpi::register_oapp(
            ctx.accounts.oft_store.endpoint_program,
            ctx.accounts.oft_store.key(),
            ctx.remaining_accounts,
            &[OFT_SEED, ctx.accounts.token_escrow.key().as_ref(), &[ctx.bumps.oft_store]],
            RegisterOAppParams { delegate: params.admin },
        )
    }
}
