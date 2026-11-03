//! Pangea v3 `set_gap_pool` (spec §10.3): once per v3 store, the registrar (or the admin) names
//! the token's official Meteora DAMM v2 pool. Recorded in the store tail with the quote mint, the
//! side and both decimals; the store's `GapRoute` PDA goes into its `LzReceiveTypes` slot so the
//! executor hands it to `lz_receive_types`. Never reallocs: a live (223-byte) store is refused.
//!
//! Step 2 (constants audit, no-rug): the pool must be the LAUNCH'S OWN pool, never one the signer
//! picks. The splitter's `launch_v2` / `launch_self` open it in the launch transaction as Meteora's
//! customizable pool of the two mints, `PDA(cp-amm, ["cpool", max(mint, quote), min(mint, quote)])`
//! (no config account: a customizable pool has none), against the quote its `LaunchRecord` names.
//! So the instruction takes the launch's `launch_seed` and `mint_nonce` and its record, and
//! refuses (NotLaunchPool) unless:
//!   * the store's mint is the splitter's `PDA(["mint", launch_seed, mint_nonce LE])`;
//!   * the record is owned by the splitter, carries `LaunchRecord`'s discriminator, sits at
//!     `PDA(["splitter", PDA(["position", launch_seed])])` (its own bump) and names that position
//!     NFT mint, and its `quote_mint` is the quote passed;
//!   * the pool is the cpool of (mint, quote).
//! The record is read only. A pool anyone opens for the mint against another quote is refused, and
//! so is any other pool of the right mints (there is only one cpool per pair).
use crate::gap::{
    engine,
    state::*,
};
use crate::instructions::gap_admin::mint_decimals;
use crate::*;
use anchor_spl::token_interface::Mint;

/// The Pangea splitter (solana/programs/pangea-splitter, `declare_id!`).
pub const SPLITTER_ID: Pubkey = pubkey!("Hb5uTppRbNxc3RjVRqTWqfdU3E3GiZyGYKccxYf9tUej");
pub const SPLITTER_MINT_SEED: &[u8] = b"mint";
pub const SPLITTER_POSITION_SEED: &[u8] = b"position";
pub const SPLITTER_RECORD_SEED: &[u8] = b"splitter";
pub const CPOOL_SEED: &[u8] = b"cpool";
/// sha256("account:LaunchRecord")[..8] (pinned by a test).
pub const LAUNCH_RECORD_DISCRIMINATOR: [u8; 8] = [146, 240, 197, 204, 6, 6, 87, 75];
/// LaunchRecord (Anchor, after the discriminator): creator @8, pending_creator @40, position @72,
/// position_nft_mint @104, quote_mint @136, fee_bps u16 @168, venue_lp_share_bps u16 @170, bump @172.
pub const LR_POSITION_NFT_MINT: usize = 104;
pub const LR_QUOTE_MINT: usize = 136;
pub const LR_BUMP: usize = 172;

/// Meteora's customizable pool of two mints: the larger key first (cp-amm `customizable_pool_pda`,
/// as pangea-cheapest `pool_address` and solana/client/launch-leg.mjs).
pub fn launch_pool_address(mint: &Pubkey, quote: &Pubkey) -> Pubkey {
    let (first, second) = if mint.to_bytes() > quote.to_bytes() { (mint, quote) } else { (quote, mint) };
    Pubkey::find_program_address(&[CPOOL_SEED, first.as_ref(), second.as_ref()], &CP_AMM_ID).0
}

/// The quote the launch of (`launch_seed`, `mint_nonce`) paired `mint` against, read from its
/// splitter record `info`; Err(NotLaunchPool) if `mint` or `info` is not that launch's.
pub fn launch_quote(info: &AccountInfo, mint: &Pubkey, launch_seed: &[u8; 32], mint_nonce: u32) -> Result<Pubkey> {
    let want_mint = Pubkey::find_program_address(&[SPLITTER_MINT_SEED, launch_seed.as_ref(), &mint_nonce.to_le_bytes()], &SPLITTER_ID).0;
    require_keys_eq!(*mint, want_mint, OFTError::NotLaunchPool);
    require_keys_eq!(*info.owner, SPLITTER_ID, OFTError::NotLaunchPool);
    let d = info.try_borrow_data()?;
    require!(d.len() > LR_BUMP && d[..8] == LAUNCH_RECORD_DISCRIMINATOR, OFTError::NotLaunchPool);
    let nft = Pubkey::find_program_address(&[SPLITTER_POSITION_SEED, launch_seed.as_ref()], &SPLITTER_ID).0;
    require!(d[LR_POSITION_NFT_MINT..LR_POSITION_NFT_MINT + 32] == nft.to_bytes(), OFTError::NotLaunchPool);
    let rec = Pubkey::create_program_address(&[SPLITTER_RECORD_SEED, nft.as_ref(), &[d[LR_BUMP]]], &SPLITTER_ID).map_err(|_| error!(OFTError::NotLaunchPool))?;
    require_keys_eq!(*info.key, rec, OFTError::NotLaunchPool);
    Ok(Pubkey::new_from_array(d[LR_QUOTE_MINT..LR_QUOTE_MINT + 32].try_into().unwrap()))
}

#[derive(Accounts)]
pub struct SetGapPool<'info> {
    pub signer: Signer<'info>,
    #[account(seeds = [GAP_GLOBAL_SEED], bump = gap_global.bump)]
    pub gap_global: Box<Account<'info, GapGlobal>>,
    #[account(mut, seeds = [OFT_SEED, oft_store.token_escrow.as_ref()], bump = oft_store.bump)]
    pub oft_store: Account<'info, OFTStore>,
    /// CHECK: the store's `LzReceiveTypes` PDA (seeds), ours, 104 bytes (checked in apply)
    #[account(mut, seeds = [LZ_RECEIVE_TYPES_SEED, oft_store.key().as_ref()], bump, owner = crate::ID)]
    pub lz_receive_types_accounts: UncheckedAccount<'info>,
    #[account(address = oft_store.token_mint)]
    pub token_mint: InterfaceAccount<'info, Mint>,
    /// CHECK: the launch's own cp-amm pool (checked in apply)
    pub pool: UncheckedAccount<'info>,
    /// CHECK: the pool's other mint, the launch record's quote (checked in apply)
    pub quote_mint: UncheckedAccount<'info>,
    /// CHECK: the splitter's LaunchRecord of this launch, read only (checked in apply)
    pub launch_record: UncheckedAccount<'info>,
}

impl SetGapPool<'_> {
    pub fn apply(ctx: &mut Context<SetGapPool>, launch_seed: [u8; 32], mint_nonce: u32) -> Result<()> {
        let g = &ctx.accounts.gap_global;
        let who = ctx.accounts.signer.key();
        require!(who == g.registrar || who == g.admin, OFTError::NotGapRegistrar);

        let store_info = ctx.accounts.oft_store.to_account_info();
        let tail = {
            let d = store_info.try_borrow_data()?;
            Tail::read(&d).ok_or(OFTError::NotV3Store)?
        };
        require!(!tail.is_set(), OFTError::GapPoolAlreadySet);
        require!(ctx.accounts.lz_receive_types_accounts.data_len() == V3_LZ_RECEIVE_TYPES_LEN, OFTError::NotV3Store);

        let mint = ctx.accounts.token_mint.key();
        let quote = ctx.accounts.quote_mint.key();
        // the launch's own pool, never one the signer picks (step 2, no-rug)
        let launch_quote = launch_quote(&ctx.accounts.launch_record.to_account_info(), &mint, &launch_seed, mint_nonce)?;
        require_keys_eq!(quote, launch_quote, OFTError::NotLaunchPool);
        require_keys_eq!(*ctx.accounts.pool.key, launch_pool_address(&mint, &quote), OFTError::NotLaunchPool);

        let pv = engine::read_pool(&ctx.accounts.pool).ok_or(OFTError::BadGapPool)?;
        // audit L-1: the official pool is set once and never replaced, so a fee the receive cannot
        // read (not a flat base fee, or >= 1e6) would hold every arrival for good: refused here
        let fee = pv.flat_fee_ppm().map_err(|_| error!(OFTError::BadGapPool))?;
        require!((fee as u128) < crate::gap::math::PPM, OFTError::BadGapPool);
        // audit r1 I-3: the PriceLog capacity rule uses the pool's permanently locked liquidity; a
        // pool with none is refused here (the launch locks its whole position)
        require!(pv.locked_liquidity != 0, OFTError::BadGapPool);
        let token_is_a = pv.side(&mint.to_bytes(), &quote.to_bytes()).ok_or(OFTError::BadGapPool)?;
        let quote_decimals = mint_decimals(&ctx.accounts.quote_mint).ok_or(OFTError::BadGapPool)?;
        let token_decimals = ctx.accounts.token_mint.decimals;
        require!(token_decimals <= MAX_DECIMALS, OFTError::BadGapPool);

        {
            let mut d = store_info.try_borrow_mut_data()?;
            Tail::write_pool(&mut d, ctx.accounts.pool.key, &quote, token_is_a, quote_decimals, token_decimals);
        }
        {
            let info = ctx.accounts.lz_receive_types_accounts.to_account_info();
            let mut d = info.try_borrow_mut_data()?;
            let route = GapRoute::address(ctx.program_id, &quote);
            d[LZ_RECEIVE_TYPES_SLOT..LZ_RECEIVE_TYPES_SLOT + 32].copy_from_slice(route.as_ref());
        }
        msg!("gap pool {} quote {} token_is_a {}", ctx.accounts.pool.key(), quote, token_is_a);
        emit!(GapPoolSet { oft_store: store_info.key(), pool: ctx.accounts.pool.key(), quote_mint: quote, launch_record: ctx.accounts.launch_record.key() });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_launch_record_discriminator_is_anchors() {
        let h = anchor_lang::solana_program::hash::hash(b"account:LaunchRecord");
        assert_eq!(&h.to_bytes()[..8], &LAUNCH_RECORD_DISCRIMINATOR);
    }

    #[test]
    fn the_launch_pool_is_the_cpool_of_the_two_mints_larger_first() {
        let (a, b) = (Pubkey::new_from_array([9; 32]), Pubkey::new_from_array([1; 32]));
        let want = Pubkey::find_program_address(&[b"cpool", a.as_ref(), b.as_ref()], &CP_AMM_ID).0;
        assert_eq!(launch_pool_address(&a, &b), want);
        assert_eq!(launch_pool_address(&b, &a), want);
    }
}
