use anchor_lang::prelude::error_code;

#[error_code]
pub enum OFTError {
    Unauthorized,
    InvalidSender,
    InvalidDecimals,
    SlippageExceeded,
    InvalidTokenDest,
    RateLimitExceeded,
    InvalidFee,
    InvalidMintAuthority,
    Paused,
    // Pangea's `init_tvl` (appended: every LayerZero error keeps its code)
    NotAdapter,
    TvlAlreadySet,
    InvalidTvl,
    // Pangea v3 gap fee (appended: every earlier code is unchanged)
    NotV3Store,
    GapPoolAlreadySet,
    BadGapPool,
    BadGapRoute,
    /// 6016 (was BadMargin; Amendment 6 renames in place): the margin above 100,000 ppm (10%)
    MarginTooHigh,
    NotGapAdmin,
    NotGapRegistrar,
    NotUpgradeAuthority,
    SendViaCpi,
    PoolTouchedEarlier,
    GapAccountMismatch,
    GapMsgTooShort,
    ReceiptNotClosable,
    ComposeTooLong,
    ReturnNotApproved,
    // round 1 fixes (appended)
    ReceiveViaCpi,
    ComposerNotAllowed,
    GapPoolNotSet,
    // gap codec version 2 (appended)
    GapCreditBelowMin,
    MinCreditedAboveAmount,
    // gap v3c (appended; codes stable from here: 6032..6046)
    GapBadVersion,
    GapNoPool,
    GapUnreadable,
    GapSourceUnreadable,
    /// 6036 (was GapRecordMissing): no PriceLog entry in the send's window, or not enough unused
    /// capacity; or the store's PriceLog does not exist yet. On a receive (retriable: it holds;
    /// round 2 H-1): no window entry with a non-zero maximum for the pair priced (record_price, then
    /// retry), or more than the window's free capacity covers (land_held_receive)
    GapNeedRecords,
    /// 6037 (was GapRecordTooFresh): the Ps the send would carry is below the sender's minPsUsd
    GapPsBelowMin,
    /// 6038 (was GapRecordExpired): R1', the receive's price path run by anything but LayerZero's
    /// executor `execute` CPI, a GapGlobal delivery key or land_held_receive. Round 2: the
    /// executor's top-level pre/post_execute sandwich is refused too (any key can build it)
    GapReceiveNotAllowed,
    /// 6039 (was GapRecordMismatch): not the store's PriceLog PDA / layout
    PriceLogMismatch,
    /// 6040 (was BadRecordTtl): the window W outside 3..=1500 slots
    BadWindow,
    BadGapClass,
    /// 6042: unused since Amendment 6 (the gas allowance is removed); the code stays
    GasAllowanceTooHigh,
    // PriceLog / R1' / Amendment 5 (appended)
    /// 6043: a second PriceLog write in one transaction (another instruction lists the log)
    OneLogWritePerTx,
    /// 6044: DEAD since round 2 (H-1 (3), lead #4; kept for the numbering): a key's Pd floor now
    /// raises Pd (the receive is priced at max(Pd, floor) for the pair priced) instead of reverting
    GapPdBelowFloor,
    /// 6045 (was BadArbGas): a gas cover figure above its hard cap (swap or send lamports above
    /// 100,000, the cover cap above 20,000 cents)
    BadGasCover,
    /// 6046: capacity k outside 100..=100,000 ppm
    BadCapacityK,
    // audit r1 (appended)
    /// 6047: `set_gap_stables` names the wSOL mint: SOL is never $1 (its USD price comes only
    /// through GapRoute(wSOL))
    WsolNotStable,
    // owner (A) / (B) 2026-10-30 (appended)
    /// 6048: k_mode not 0 or 1
    BadKMode,
    /// 6049: k_factor outside 1..=333,333 ppm (whole-diff I-3: at most a third of the fee)
    BadKFactor,
    /// 6050: reward_bps above 20 (the 0.2% bridge fee)
    BadRewardBps,
    /// 6051: the reserved writer-reward total would go negative, or a claim is more than the fees
    /// in the escrow (never out of the TVL); refuses the tx
    RewardAccounting,
    /// 6052: not the writer's associated token account, or a wrong GapReward ledger
    RewardAccountMismatch,
    // step 2 (appended)
    /// 6053: a composed v3 arrival for a `to` not in GapGlobal.composers (retriable: list the
    /// composer, or turn the store's escape on, and the retry lands)
    GapComposerNotListed,
    /// 6054: `accept_gap_admin` signed by anyone but GapGlobal.pending_admin (or nothing proposed)
    NotPendingAdmin,
    /// 6055: the default key where a real key is required (an admin, a registrar)
    DefaultKey,
    /// 6056: the same key twice in one list (stables, seeders, delivery keys, composers)
    DuplicateKey,
    /// 6057: the LayerZero cost max outside 1..=$50 (USD 1e18)
    BadCostMax,
    /// 6058: `set_gap_pool`'s pool, quote or launch record is not this launch's own: the pool must
    /// be Meteora's customizable pool of the store's mint and the quote its splitter LaunchRecord names
    NotLaunchPool,
    // step 3 (appended)
    /// 6059: `land_held_receive` on an arrival that is not held (neither an unlisted composer's
    /// compose that credits nor one larger than the PriceLog's capacity), a fee-0 outcome (the
    /// escape on, a refund, SEED_NO_POOL), or not at the top level
    NotHeldReceive,
    /// 6060: platform_floor_ppm outside 300..=2,600
    BadPlatformFloor,
    /// 6061: unused (land_oversized_receive was merged into land_held_receive before any deploy);
    /// kept so that the codes after it stay as given to the clients
    Reserved6061,
    /// 6062: a send with the REQUIRE_COVER trailing flag that would not carry the gas cover (cover
    /// cap 0, this destination's window cover already spent or no cover-table slot free, or
    /// lamports counted with no SOL/USD in the window); nothing moves
    GapCoverNotGranted,
    /// 6063: `land_held_receive` would land an unlisted compose PLAIN to a `to` off the ed25519 curve
    /// (a PDA: nothing could move its tokens without the dropped call); list it as a composer
    HeldComposeToPda,
    /// 6064: an OVERSIZED `land_held_receive` without a non-zero Pd floor for the pair priced in
    /// extra_data (16 B LE USD 1e18, or 32 B USD | class; round 2 B L-3): the lander names the least
    /// fair Pd the land may charge at (it is priced at max(r0, floor))
    OversizedLandNeedsFloor,
    /// 6065: `set_gap_capacity(false)`: capacity is mandatory for v3 stores (whole-diff M-1)
    CapacityMandatory,
    // round 2 (appended)
    /// 6066: a delivery key's receive without a non-zero Pd floor (extra_data, 16 B usd or 32 B
    /// usd | class, LE) for the pair priced; retriable (round 2 H-1 (3): the key always names a
    /// floor of its own, independent of this pool)
    DeliveryNeedsFloor,
    // owner M-1 (oft-m1, appended)
    /// 6067: a send carrying the co-signer's Ps ceilings (trailing flags bit 1, COSIGNED) whose
    /// psUsd is above ps_usd_max or psClass above ps_class_max; nothing moves. The co-signer names
    /// the most Ps it agreed to (the window's minimum it saw); ask it again for a fresh co-sign
    GapPsAboveCeiling,
    // L4 (oft-l4, appended; 6066 on v3c-oft-l4, after the round-2 codes since oft-merge)
    /// 6068: `set_gap_return_gas` above RETURN_GAS_MAX_LAMPORTS (1,000,000) (L4); oft-ret:
    /// `set_gap_refund_gas` outside REFUND_LZ_GAS_MIN..=REFUND_LZ_GAS_MAX (100,000..=1,400,000)
    BadReturnGas,
    // oft-q7 (owner Q7 / Q7-c / Q7-e, appended)
    /// 6069: `set_gap_delivery_cost` above DELIVERY_LAMPORTS_MAX (1,000,000 lamports per message)
    BadDeliveryCost,
    /// 6070: `set_gap_dst_delivery` for eid 0 / 30168 / 40168, above DST_DELIVERY_LAMPORTS_MAX, or
    /// non-zero while `dst_delivery_to` is unset; `set_gap_dst_delivery_to` of the default key
    BadDstDelivery,
    /// 6071: `set_gap_dst_delivery`: every slot holds another destination
    GapDstDeliverySlotsFull,
    /// 6072: a Solana-source v3 send toward a keys-only destination whose native_fee does not cover
    /// the delivery cost, or without GapGlobal.dst_delivery_to as the writable account after the
    /// gap accounts; nothing moves
    GapDeliveryFeeUnpaid,
    /// 6073: `migrate_gap_global` on an account that is not the 760-byte (L4) GapGlobal PDA
    BadGapGlobalMigration,
    /// 6074: `close_late_prepay` signed by anyone but the record's payer (oft-lows2: within the
    /// record's TTL; after it anyone may close it, the rent still to its payer)
    NotLatePrepayPayer,
    // oft-fix (oft-r3-prog M-1 / L-2 / I-3, appended)
    /// 6075: `set_gap_ata_cost` above ATA_LAMPORTS_MAX (10,000,000) (and not ATA_LAMPORTS_RENT)
    BadAtaCost,
    /// 6076: a v3 arrival our keys deliver had to create the recipient's token account and its
    /// credit cannot pay that rent (GapGlobal.ata_lamports) with the delivery cost in full;
    /// retriable: nothing moves (the creation is undone); once the recipient's account exists (anyone
    /// may create it) the arrival lands with the delivery cost alone
    GapAtaRentUnpaid,
    /// 6077: `set_gap_cosigners` naming GapGlobal.admin, the registrar or a delivery key; or
    /// `set_gap_delivery` / `set_gap_registrar` / `propose_gap_admin` naming a co-sign key (L-2: the
    /// co-sign key has no other role)
    BadCosigner,
    /// 6078: `sweep_late_prepay` more than LATE_PREPAY_TTL_SECS after the record was made (I-3)
    LatePrepayExpired,
    // oft-lows (q7b-r2 M-3, lead5 M131, appended)
    /// 6079: `sweep_gap_prepay` into a receipt whose `prepaid` is not the caller's `expect_prepaid`
    /// (oft-ret, oft-r5 M-1). Nothing moves; in the bot's [fund, sweep(expect 0)] transaction the
    /// funding reverts with it, so a duplicate late funding never leaves the funder. It does NOT
    /// mean "already funded": the receipt may count only dust; read `prepaid` and compare with P.
    GapPrepayAlreadyCounted,
    // oft-lows6 (oft-lows5-r1 L-1, appended)
    /// 6080: a refund account (close_gap_receipt's remaining[0], return_expired_compose's refund_to) passed
    /// READ-ONLY although the runtime would let it be written: only an account the runtime itself makes
    /// read-only (`gap::prepay::runtime_read_only`: a reserved key, a sysvar, a program) may stand in for
    /// one that cannot hold -- a caller can never turn a holder's refund into the payer's by passing it
    /// read-only. Pass it writable.
    RefundNotWritable,
}
