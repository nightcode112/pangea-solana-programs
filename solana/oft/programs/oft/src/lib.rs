use anchor_lang::prelude::*;

pub mod compose_msg_codec;
pub mod errors;
pub mod events;
pub mod gap;
pub mod instructions;
pub mod msg_codec;
pub mod state;

use errors::*;
use gap::record::*;
use events::*;
use instructions::*;
use oapp::{
    endpoint::{MessagingFee, MessagingReceipt},
    LzReceiveParams,
};
use solana_helper::program_id_from_env;
use state::*;

declare_id!(Pubkey::new_from_array(program_id_from_env!(
    "OFT_ID",
    "9UovNrJD8pQyBLheeHNayuG1wJSEAoxkmM14vw5gcsTT"
)));

pub const OFT_SEED: &[u8] = b"OFT";
pub const PEER_SEED: &[u8] = b"Peer";
pub const ENFORCED_OPTIONS_SEED: &[u8] = b"EnforcedOptions";
pub const LZ_RECEIVE_TYPES_SEED: &[u8] = oapp::LZ_RECEIVE_TYPES_SEED;

#[program]
pub mod oft {
    use super::*;

    pub fn oft_version(_ctx: Context<OFTVersion>) -> Result<Version> {
        Ok(Version { interface: 2, message: 1 })
    }

    pub fn init_oft(mut ctx: Context<InitOFT>, params: InitOFTParams) -> Result<()> {
        InitOFT::apply(&mut ctx, &params)
    }

    // ============================== Admin ==============================
    pub fn set_oft_config(
        mut ctx: Context<SetOFTConfig>,
        params: SetOFTConfigParams,
    ) -> Result<()> {
        SetOFTConfig::apply(&mut ctx, &params)
    }

    pub fn set_peer_config(
        mut ctx: Context<SetPeerConfig>,
        params: SetPeerConfigParams,
    ) -> Result<()> {
        SetPeerConfig::apply(&mut ctx, &params)
    }

    pub fn set_pause(mut ctx: Context<SetPause>, params: SetPauseParams) -> Result<()> {
        SetPause::apply(&mut ctx, &params)
    }

    pub fn withdraw_fee(mut ctx: Context<WithdrawFee>, params: WithdrawFeeParams) -> Result<()> {
        WithdrawFee::apply(&mut ctx, &params)
    }

    /// Pangea: once, an Adapter store's admin declares its pre-funded escrow locked. See `init_tvl`.
    pub fn init_tvl(mut ctx: Context<InitTvl>, params: InitTvlParams) -> Result<()> {
        InitTvl::apply(&mut ctx, &params)
    }

    // ============================== Pangea v3 gap fee ==============================
    /// `init_oft` for a v3 token: a 319-byte store (spec §10.3).
    pub fn init_oft_v3(mut ctx: Context<InitOFTV3>, params: InitOFTParams) -> Result<()> {
        InitOFTV3::apply(&mut ctx, &params)
    }

    /// Once per program, by its upgrade authority.
    pub fn init_gap_global(mut ctx: Context<InitGapGlobal>, params: InitGapGlobalParams) -> Result<()> {
        InitGapGlobal::apply(&mut ctx, &params)
    }

    /// Step 2 (constants audit): the gap admin rotates in two steps, never to the default key.
    pub fn propose_gap_admin(mut ctx: Context<GapAdmin>, pending_admin: Pubkey) -> Result<()> {
        GapAdmin::propose_admin(&mut ctx, pending_admin)
    }

    pub fn accept_gap_admin(mut ctx: Context<AcceptGapAdmin>) -> Result<()> {
        AcceptGapAdmin::apply(&mut ctx)
    }

    /// Amendment 6: the fixed margin (0..=100,000 ppm), the gas cover and the LayerZero cost max.
    pub fn set_gap_margin(mut ctx: Context<GapAdmin>, margin_ppm: u32) -> Result<()> {
        GapAdmin::set_margin(&mut ctx, margin_ppm)
    }

    pub fn set_gap_gas_cover(mut ctx: Context<GapAdmin>, swap_lamports: u32, send_lamports: u32, cover_cap_cents: u16) -> Result<()> {
        GapAdmin::set_gas_cover(&mut ctx, swap_lamports, send_lamports, cover_cap_cents)
    }

    pub fn set_gap_cost_max(mut ctx: Context<GapAdmin>, usd_e18: u128) -> Result<()> {
        GapAdmin::set_cost_max(&mut ctx, usd_e18)
    }

    pub fn set_gap_registrar(mut ctx: Context<GapAdmin>, registrar: Pubkey) -> Result<()> {
        GapAdmin::set_registrar(&mut ctx, registrar)
    }

    pub fn set_gap_stables(mut ctx: Context<GapAdmin>, stables: [Pubkey; 4]) -> Result<()> {
        GapAdmin::set_stables(&mut ctx, stables)
    }

    /// The composers whose receipts `return_expired_compose` may send home (spec §10.1, §10.7).
    pub fn set_gap_composers(mut ctx: Context<GapAdmin>, composers: [Pubkey; 2]) -> Result<()> {
        GapAdmin::set_composers(&mut ctx, composers)
    }

    // ---- v3c (spec §6): GapGlobal.admin

    /// The PriceLog window W (slots).
    pub fn set_gap_window(mut ctx: Context<GapAdmin>, slots: u32) -> Result<()> {
        GapAdmin::set_window(&mut ctx, slots)
    }

    // ---- the PriceLog capacity rule (MANDATORY for v3 stores: on from init_gap_global, `false` is
    // refused CapacityMandatory) and R1' delivery keys
    pub fn set_gap_capacity(mut ctx: Context<GapAdmin>, on: bool) -> Result<()> {
        GapAdmin::set_capacity(&mut ctx, on)
    }

    pub fn set_gap_capacity_k(mut ctx: Context<GapAdmin>, k_ppm: u32) -> Result<()> {
        GapAdmin::set_capacity_k(&mut ctx, k_ppm)
    }

    pub fn set_gap_delivery(mut ctx: Context<GapAdmin>, keys: [Pubkey; 2]) -> Result<()> {
        GapAdmin::set_delivery(&mut ctx, keys)
    }

    // ---- owner (A) / (B) 2026-10-30: k per entry and the writer reward
    pub fn set_gap_k_mode(mut ctx: Context<GapAdmin>, k_mode: u8) -> Result<()> {
        GapAdmin::set_k_mode(&mut ctx, k_mode)
    }

    pub fn set_gap_k_factor(mut ctx: Context<GapAdmin>, k_factor_ppm: u32) -> Result<()> {
        GapAdmin::set_k_factor(&mut ctx, k_factor_ppm)
    }

    /// Step 3: k_mode 1's fee cap (a creator's own trades get part of the pool fee back).
    pub fn set_gap_platform_floor(mut ctx: Context<GapAdmin>, platform_floor_ppm: u32) -> Result<()> {
        GapAdmin::set_platform_floor(&mut ctx, platform_floor_ppm)
    }

    pub fn set_gap_reward_bps(mut ctx: Context<GapAdmin>, reward_bps: u16) -> Result<()> {
        GapAdmin::set_reward_bps(&mut ctx, reward_bps)
    }

    pub fn set_gap_class(mut ctx: Context<GapAdmin>, slot: u8, mint: Pubkey, class: u8) -> Result<()> {
        GapAdmin::set_class(&mut ctx, slot, mint, class)
    }

    pub fn set_gap_seeders(mut ctx: Context<GapAdmin>, seeders: [Pubkey; 2]) -> Result<()> {
        GapAdmin::set_seeders(&mut ctx, seeders)
    }

    /// The per-store escape (store tail byte 299): on, every receive credits in full at fee 0.
    pub fn set_gap_escape(mut ctx: Context<SetGapEscape>, on: bool) -> Result<()> {
        SetGapEscape::apply(&mut ctx, on)
    }

    pub fn set_gap_route(mut ctx: Context<SetGapRoute>, params: SetGapRouteParams) -> Result<()> {
        SetGapRoute::apply(&mut ctx, &params)
    }

    pub fn clear_gap_route(mut ctx: Context<ClearGapRoute>) -> Result<()> {
        ClearGapRoute::apply(&mut ctx)
    }

    pub fn set_gap_pool(mut ctx: Context<SetGapPool>, launch_seed: [u8; 32], mint_nonce: u32) -> Result<()> {
        SetGapPool::apply(&mut ctx, launch_seed, mint_nonce)
    }

    /// Amendment 4: the store's shared PriceLog, once, by anyone (the payer pays the rent).
    pub fn init_gap_price_log(mut ctx: Context<InitGapPriceLog>) -> Result<()> {
        InitGapPriceLog::apply(&mut ctx)
    }

    /// Amendment 4: permissionless; writes the current price into the store's PriceLog.
    pub fn record_price(mut ctx: Context<RecordPrice>) -> Result<()> {
        RecordPrice::apply(&mut ctx)
    }

    /// Owner (A): permissionless; the signing writer gets what the PriceLog entries at `indices`,
    /// its reward-table slot and its GapReward ledger owe it, from the store's escrow.
    pub fn claim_writer_rewards(mut ctx: Context<ClaimWriterRewards>, indices: Vec<u8>) -> Result<()> {
        ClaimWriterRewards::apply(&mut ctx, &indices)
    }

    /// Owner (A): permissionless (the payer pays the ledger's rent); moves `writer`'s reward-table
    /// slot into its GapReward ledger, where nothing can forfeit it.
    pub fn settle_writer_rewards(mut ctx: Context<SettleWriterRewards>, writer: Pubkey) -> Result<()> {
        SettleWriterRewards::apply(&mut ctx, writer)
    }

    pub fn close_gap_receipt<'info>(mut ctx: Context<'_, '_, '_, 'info, CloseGapReceipt<'info>>) -> Result<()> {
        CloseGapReceipt::apply(&mut ctx)
    }

    /// L4: the receipt's `to` (the composer) names where the sender's prepaid lamports go on a return.
    pub fn set_gap_receipt_refund(mut ctx: Context<SetGapReceiptRefund>, refund_to: Pubkey) -> Result<()> {
        SetGapReceiptRefund::apply(&mut ctx, refund_to)
    }

    /// L4: anyone sweeps a prepay drop that landed after the receive into the guid's receipt.
    /// oft-ret (oft-r5 M-1): only when the receipt counts exactly `expect_prepaid` now (the bot's
    /// [fund, sweep] passes 0; a late drop's sweep the current value), else GapPrepayAlreadyCounted.
    pub fn sweep_gap_prepay(mut ctx: Context<SweepGapPrepay>, expect_prepaid: u64) -> Result<()> {
        SweepGapPrepay::apply(&mut ctx, expect_prepaid)
    }

    pub fn set_gap_return_gas(mut ctx: Context<GapAdmin>, return_gas_lamports: u32) -> Result<()> {
        GapAdmin::set_return_gas(&mut ctx, return_gas_lamports)
    }

    /// oft-ret (cheapest-r4 M-1 (a)): the lzReceive gas of the refund marker `return_expired_compose`
    /// sends home to an EVM chain, 100,000..=1,400,000 (BadReturnGas).
    pub fn set_gap_refund_gas(mut ctx: Context<GapAdmin>, refund_lz_gas: u32) -> Result<()> {
        GapAdmin::set_refund_gas(&mut ctx, refund_lz_gas)
    }

    /// oft-q7 (owner Q7): what one delivery by our keys costs, 0..=1,000,000 lamports per message.
    pub fn set_gap_delivery_cost(mut ctx: Context<GapAdmin>, delivery_lamports: u32) -> Result<()> {
        GapAdmin::set_delivery_cost(&mut ctx, delivery_lamports)
    }

    /// oft-q7 (Q7-e): a keys-only destination's delivery cost (0 frees its slot).
    pub fn set_gap_dst_delivery(mut ctx: Context<GapAdmin>, eid: u32, lamports: u64) -> Result<()> {
        GapAdmin::set_dst_delivery(&mut ctx, eid, lamports)
    }

    /// oft-q7 (Q7-e): where the per-destination delivery cost goes.
    pub fn set_gap_dst_delivery_to(mut ctx: Context<GapAdmin>, to: Pubkey) -> Result<()> {
        GapAdmin::set_dst_delivery_to(&mut ctx, to)
    }

    /// oft-fix M-1: the rent of a recipient token account our keys' delivery creates (users pay).
    pub fn set_gap_ata_cost(mut ctx: Context<GapAdmin>, ata_lamports: u32) -> Result<()> {
        GapAdmin::set_ata_cost(&mut ctx, ata_lamports)
    }

    /// oft-fix L-2: the co-sign keys (no other role).
    pub fn set_gap_cosigners(mut ctx: Context<GapAdmin>, keys: [Pubkey; 2]) -> Result<()> {
        GapAdmin::set_cosigners(&mut ctx, keys)
    }

    /// oft-q7: grows the live 760-byte GapGlobal to the current layout (admin; pays the rent).
    pub fn migrate_gap_global(mut ctx: Context<MigrateGapGlobal>) -> Result<()> {
        MigrateGapGlobal::apply(&mut ctx)
    }

    /// oft-q7 (Q7-c): permissionless; a prepay drop that landed after its receipt closed goes to
    /// the refund party the close recorded.
    pub fn sweep_late_prepay(mut ctx: Context<SweepLatePrepay>, oft_store: Pubkey, src_eid: u32, compose_from: [u8; 32], msg_hash: [u8; 32]) -> Result<()> {
        SweepLatePrepay::apply(&mut ctx, oft_store, src_eid, compose_from, msg_hash)
    }

    /// oft-q7 (Q7-c): the late-prepay record's payer takes its rent back.
    pub fn close_late_prepay(mut ctx: Context<CloseLatePrepay>) -> Result<()> {
        CloseLatePrepay::apply(&mut ctx)
    }

    /// An expired composed sale's tokens back to its sender (spec §10.7); anyone may call it
    /// once the composer has approved the guid's return delegate.
    pub fn return_expired_compose(
        mut ctx: Context<ReturnExpiredCompose>,
        params: ReturnComposeParams,
    ) -> Result<MessagingReceipt> {
        ReturnExpiredCompose::apply(&mut ctx, &params)
    }

    // ============================== Public ==============================

    /// OFF-CHAIN helper (simulate it; round 2 C, docs): LayerZero's OFT quote, unchanged. On a v3
    /// store `amount_received_ld` is what leaves THIS chain (net of the bridge fee and a Token-2022
    /// transfer fee), NOT what the destination credits: the destination withholds the gap fee at
    /// delivery (spec §2), which no Solana quote can know in advance (it depends on the destination's
    /// price at landing). Estimate it off chain (web/lib gap-estimate, script/gap/gap-math.mjs).
    pub fn quote_oft(ctx: Context<QuoteOFT>, params: QuoteOFTParams) -> Result<QuoteOFTResult> {
        QuoteOFT::apply(&ctx, &params)
    }

    /// OFF-CHAIN helper (simulate it; round 2 C, docs): LayerZero's messaging fee for the send. On a
    /// v3 store it quotes the message the v3 send will carry (codec v3 header, the enforced options
    /// with the FILTERED compose, spec §8.8), but not what the send costs beyond LayerZero's fee: the
    /// source cost of §2 is quoted INSIDE `send` by `send_v3::lz_quote` (an on-chain CPI to the
    /// endpoint's quote with the send's own accounts, header-only message, enforced SEND options) and
    /// is not an instruction anyone calls.
    pub fn quote_send(ctx: Context<QuoteSend>, params: QuoteSendParams) -> Result<MessagingFee> {
        QuoteSend::apply(&ctx, &params)
    }

    pub fn send(
        mut ctx: Context<Send>,
        params: SendParams,
    ) -> Result<(MessagingReceipt, OFTReceipt)> {
        Send::apply(&mut ctx, &params)
    }

    pub fn lz_receive<'info>(mut ctx: Context<'_, '_, '_, 'info, LzReceive<'info>>, params: LzReceiveParams) -> Result<()> {
        LzReceive::apply(&mut ctx, &params)
    }

    /// Step 3: lands an arrival the normal receive holds for good -- an unlisted composer's compose
    /// (landed plain, the compose dropped: GapGlobal.admin ONLY), one larger than the PriceLog's
    /// free capacity (GapGlobal.admin OR a GapGlobal.delivery key: priced at r0 = the whole
    /// window's Pd, raised to the lander's mandatory Pd floor -- round 2 H-1 (3): max(r0, floor) --,
    /// nothing consumed), or both (admin only); never fee 0. The accounts are `lz_receive`'s (the
    /// same remaining accounts) with `payer` = the lander, the floor in `extra_data` (16 B usd or
    /// 32 B usd | class, LE).
    pub fn land_held_receive<'info>(mut ctx: Context<'_, '_, '_, 'info, LzReceive<'info>>, params: LzReceiveParams) -> Result<()> {
        LzReceive::land_held_receive(&mut ctx, &params)
    }

    pub fn lz_receive_types(
        ctx: Context<LzReceiveTypes>,
        params: LzReceiveParams,
    ) -> Result<Vec<oapp::endpoint_cpi::LzAccount>> {
        LzReceiveTypes::apply(&ctx, &params)
    } #[cfg(feature = "stock-hops")] pub fn set_stock_keeper(mut ctx: Context<SetStockKeeper>, keeper: Pubkey) -> Result<()> { crate::gap::keeper::set_stock_keeper(&mut ctx, keeper) } #[cfg(feature = "stock-hops")] pub fn set_route_anchor(mut ctx: Context<SetRouteAnchor>, quote_mint: Pubkey, expected_price: u64) -> Result<()> { crate::gap::keeper::set_route_anchor(&mut ctx, quote_mint, expected_price) } #[cfg(feature = "stock-hops")] pub fn set_stock_route(mut ctx: Context<SetGapRoute>, params: SetGapRouteParams, min_depth_b: u64, min_depth_a: u64) -> Result<()> { crate::gap::hops::set_stock_route(&mut ctx, &params, min_depth_b, min_depth_a) }
}

#[derive(Accounts)]
pub struct OFTVersion {}

#[derive(Clone, AnchorSerialize, AnchorDeserialize)]
pub struct Version {
    pub interface: u64,
    pub message: u64,
}

// stocks-d (v3.1, MAIN Q93): the stock-route keeper (gap/keeper.rs) and its two instructions above (same line).
#[cfg(feature = "stock-hops")]
use gap::keeper::*;
