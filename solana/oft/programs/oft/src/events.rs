use crate::*;

#[event]
pub struct OFTSent {
    pub guid: [u8; 32],
    pub dst_eid: u32,
    pub from: Pubkey,
    pub amount_sent_ld: u64,
    pub amount_received_ld: u64,
}

#[event]
pub struct OFTReceived {
    pub guid: [u8; 32],
    pub src_eid: u32,
    pub to: Pubkey,
    pub amount_received_ld: u64,
}

/// Pangea v3 gap fee: a v1 receive where the formula ran (`withheld_ld` may be 0 by rounding).
#[event]
pub struct GapCharged {
    pub guid: [u8; 32],
    pub src_eid: u32,
    pub to: Pubkey,
    pub amount_ld: u64,
    pub withheld_ld: u64,
    pub ps_e18: u128,
    pub pd_e18: u128,
    pub gap_ppm: u32,
    pub allow_ppm: u64,
    /// v3c: 0 = the USD pair (routes); else the price class both quotes share (no hop).
    pub pair_class: u8,
}

/// Pangea v3 gap fee: a receive charged 0 for `reason` (gap::math: NO_GAP, WITHIN_ALLOWANCE, and v3c
/// ESCAPED, SEED_NO_POOL).
#[event]
pub struct GapSkipped {
    pub guid: [u8; 32],
    pub src_eid: u32,
    pub reason: u8,
}

// ---- v3c admin settings (spec §6)

#[event]
pub struct GapWindowSet {
    pub slots: u32,
}

// Amendment 6 (GapMarginKSet / GapMarginBoundsSet / GapArbGasSet / GapGasAllowanceSet are gone)
#[event]
pub struct GapMarginSet {
    pub margin_ppm: u32,
}

#[event]
pub struct GapGasCoverSet {
    pub swap_lamports: u32,
    pub send_lamports: u32,
    pub cover_cap_cents: u16,
}

/// The LayerZero cost term's cap (USD 1e18), constants audit.
#[event]
pub struct GapCostMaxSet {
    pub usd_e18: u128,
}

/// The first step of the admin rotation; GapAdminSet follows on `accept_gap_admin`.
#[event]
pub struct GapAdminProposed {
    pub admin: Pubkey,
    pub pending_admin: Pubkey,
}

/// L4: the sender's prepaid lamports paid out on close (to the composer's refund account).
#[event]
pub struct GapPrepaidRefunded {
    pub guid: [u8; 32],
    pub to: Pubkey,
    pub lamports: u64,
}

/// oft-lows5 (xd-solevm L-1, lead8 option (a)), "refund-to-executable": the sender's prepaid could not
/// go to the refund account named because it is EXECUTABLE (a program id: the runtime refuses any
/// lamport change to it). `lamports` stayed in `receipt` and went, with the close, to its `payer` (on a
/// return: to the caller, `payer` here), which holds it for a manual return (Q56-style alert).
/// oft-lows6 (oft-lows5-r1 L-1): also emitted when the refund account is one the runtime keeps
/// READ-ONLY (a sysvar, a builtin or other reserved key, the called program's own id): it cannot be
/// credited either. The name is kept (one event for "the refund account cannot take lamports").
#[event]
pub struct GapPrepaidRefundToExecutable {
    pub guid: [u8; 32],
    pub receipt: Pubkey,
    pub recipient: Pubkey,
    pub payer: Pubkey,
    pub lamports: u64,
}

/// L4: `set_gap_return_gas`.
#[event]
pub struct GapReturnGasSet {
    pub return_gas_lamports: u32,
}

/// oft-ret (cheapest-r4 M-1 (a)): `set_gap_refund_gas`.
#[event]
pub struct GapRefundGasSet {
    pub refund_lz_gas: u32,
}

/// L4: `set_gap_receipt_refund` (by the receipt's `to`).
#[event]
pub struct GapReceiptRefundSet {
    pub guid: [u8; 32],
    pub refund_to: Pubkey,
}

#[event]
pub struct GapCapacitySet {
    pub on: bool,
}

#[event]
pub struct GapCapacityKSet {
    pub k_ppm: u32,
}

#[event]
pub struct GapDeliverySet {
    pub keys: [Pubkey; 2],
}

#[event]
pub struct GapClassSet {
    pub slot: u8,
    pub mint: Pubkey,
    pub class: u8,
}

#[event]
pub struct GapSeedersSet {
    pub seeders: [Pubkey; 2],
}

/// `set_gap_pool`: the store's official pool, the launch's own (its splitter record).
#[event]
pub struct GapPoolSet {
    pub oft_store: Pubkey,
    pub pool: Pubkey,
    pub quote_mint: Pubkey,
    pub launch_record: Pubkey,
}

#[event]
pub struct GapEscapeSet {
    pub oft_store: Pubkey,
    pub on: bool,
}

// audit r1 I-5: the remaining GapGlobal setters emit too
#[event]
pub struct GapAdminSet {
    pub admin: Pubkey,
}

#[event]
pub struct GapRegistrarSet {
    pub registrar: Pubkey,
}

#[event]
pub struct GapStablesSet {
    pub stables: [Pubkey; 4],
}

#[event]
pub struct GapComposersSet {
    pub composers: [Pubkey; 2],
}

/// `set_gap_route` (audit L-2): the registrar's route for a quote mint, as stored.
#[event]
pub struct GapRouteSet {
    pub quote_mint: Pubkey,
    pub hop_count: u8,
    pub hops: [crate::gap::state::GapHop; 2],
}

/// `clear_gap_route` (audit L-2): the quote mint's route is closed.
#[event]
pub struct GapRouteCleared {
    pub quote_mint: Pubkey,
}

/// `land_held_receive` (step 3): the admin landed a held arrival. `compose_dropped`: an unlisted
/// composer's compose, landed plain; `oversized`: priced at the whole window's Pd, no capacity
/// consumed. Both may be set.
#[event]
pub struct GapHeldLanded {
    pub guid: [u8; 32],
    pub src_eid: u32,
    pub to: Pubkey,
    pub admin: Pubkey,
    pub withheld_ld: u64,
    pub compose_dropped: bool,
    pub oversized: bool,
}

// owner (A) / (B) 2026-10-30
#[event]
pub struct GapKModeSet {
    pub k_mode: u8,
}

#[event]
pub struct GapKFactorSet {
    pub k_factor_ppm: u32,
}

/// Step 3: `set_gap_platform_floor`.
#[event]
pub struct GapPlatformFloorSet {
    pub platform_floor_ppm: u32,
}

#[event]
pub struct GapRewardBpsSet {
    pub reward_bps: u16,
}

/// A writer's rewards paid to its token account (`claim_writer_rewards`).
#[event]
pub struct GapRewardClaimed {
    pub oft_store: Pubkey,
    pub writer: Pubkey,
    pub amount_ld: u64,
}

/// A writer's reward-table slot moved into its GapReward ledger (`settle_writer_rewards`).
#[event]
pub struct GapRewardSettled {
    pub oft_store: Pubkey,
    pub writer: Pubkey,
    pub amount_ld: u64,
}

// ---- oft-q7 (owner Q7 / Q7-c / Q7-e)

/// Q7: GapGlobal.delivery_lamports changed (`set_gap_delivery_cost`, every change).
#[event]
pub struct GapDeliveryCostSet {
    pub delivery_lamports: u32,
}

/// Q7: a price-path v3 arrival our keys delivered withheld the delivery cost into the store's escrow.
#[event]
pub struct GapDeliveryCharged {
    pub guid: [u8; 32],
    pub payer: Pubkey,
    pub delivery_ld: u64,
    pub lamports: u32,
    pub sol_usd_e18: u128,
}

/// Q7-e: a keys-only destination's delivery cost (0 frees the slot).
#[event]
pub struct GapDstDeliveryCostSet {
    pub eid: u32,
    pub lamports: u64,
}

/// Q7-e: where the per-destination delivery cost goes.
#[event]
pub struct GapDstDeliveryToSet {
    pub to: Pubkey,
}

/// Q7-e: a Solana-source v3 send paid the destination's delivery cost.
#[event]
pub struct GapDstDeliveryPaid {
    pub dst_eid: u32,
    pub to: Pubkey,
    pub lamports: u64,
}

/// GapGlobal grew to the current layout (`migrate_gap_global`).
#[event]
pub struct GapGlobalMigrated {
    pub from_len: u32,
    pub to_len: u32,
}

/// Q7-c: a closed receipt's refund party, kept for a prepay drop that lands later.
#[event]
pub struct GapLatePrepayRecorded {
    pub prepay: Pubkey,
    pub refund_to: Pubkey,
    pub payer: Pubkey,
}

/// Q7-c: a prepay drop that landed after the close went to the recorded refund party.
#[event]
pub struct GapLatePrepaySwept {
    pub prepay: Pubkey,
    pub to: Pubkey,
    pub lamports: u64,
}

/// oft-fix M-1: GapGlobal.ata_lamports set (the value stored).
#[event]
pub struct GapAtaCostSet {
    pub ata_lamports: u32,
}

/// oft-fix M-1: a v3 arrival our keys delivered created the recipient's token account; its rent
/// (`ata_lamports`) is in the delivery charge of the same arrival (GapDeliveryCharged.lamports).
#[event]
pub struct GapAtaCharged {
    pub guid: [u8; 32],
    pub token_dest: Pubkey,
    pub ata_lamports: u32,
}

/// oft-fix L-2: GapGlobal.cosigners set.
#[event]
pub struct GapCosignersSet {
    pub cosigners: [Pubkey; 2],
}

/// oft-fix L-1: a composed arrival that writes no receipt (a plain land of an unlisted composer,
/// the escape with an unlisted composer, a zero credit) sent the sender's prepay to `to`.
#[event]
pub struct GapPrepayReturnedUnreceipted {
    pub guid: [u8; 32],
    pub prepay: Pubkey,
    pub to: Pubkey,
    pub lamports: u64,
}
