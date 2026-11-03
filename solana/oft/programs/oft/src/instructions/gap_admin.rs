//! Pangea v3 gap administration (spec §10.1, §10.2): `GapGlobal` (created once by the program's
//! upgrade authority; then its `admin`) and the registrar's `GapRoute`s.
use crate::gap::{
    math::{self, COST_MAX_CAP_USD_E18, COST_MAX_USD_E18, MARGIN_DEFAULT_PPM},
    state::*,
};
use crate::*;

/// No-rug (constants audit): a list setter's keys are each listed at most once; the default key is
/// the empty slot (allowed any number of times), never a listed key.
pub(crate) fn require_distinct(keys: &[Pubkey]) -> Result<()> {
    for (i, k) in keys.iter().enumerate() {
        if *k == Pubkey::default() {
            continue;
        }
        require!(!keys[..i].contains(k), OFTError::DuplicateKey);
    }
    Ok(())
}

// ------------------------------------------------------------------ init_gap_global

#[derive(Clone, AnchorSerialize, AnchorDeserialize)]
pub struct InitGapGlobalParams {
    pub admin: Pubkey,
    pub registrar: Pubkey,
}

#[derive(Accounts)]
pub struct InitGapGlobal<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(init, payer = authority, space = 8 + GapGlobal::INIT_SPACE, seeds = [GAP_GLOBAL_SEED], bump)]
    pub gap_global: Box<Account<'info, GapGlobal>>,
    #[account(constraint = program.programdata_address()? == Some(program_data.key()) @OFTError::NotUpgradeAuthority)]
    pub program: Program<'info, crate::program::Oft>,
    #[account(constraint = program_data.upgrade_authority_address == Some(authority.key()) @OFTError::NotUpgradeAuthority)]
    pub program_data: Account<'info, ProgramData>,
    pub system_program: Program<'info, System>,
}

impl InitGapGlobal<'_> {
    pub fn apply(ctx: &mut Context<InitGapGlobal>, params: &InitGapGlobalParams) -> Result<()> {
        require!(params.admin != Pubkey::default() && params.registrar != Pubkey::default(), OFTError::DefaultKey);
        let g = &mut ctx.accounts.gap_global;
        g.version = 1;
        g.bump = ctx.bumps.gap_global;
        g.admin = params.admin;
        g.registrar = params.registrar;
        g.stables = [Pubkey::default(); STABLE_SLOTS];
        g.composers = [Pubkey::default(); COMPOSER_SLOTS];
        // oft-ret: the refund receive gas (the retired allowance's bytes)
        g.refund_lz_gas = REFUND_LZ_GAS_DEFAULT;
        g.reserved_270 = [0; 12];
        g.window_slots = WINDOW_DEFAULT;
        g.classes = [GapClass::default(); CLASS_SLOTS];
        g.seeders = [Pubkey::default(); SEEDER_SLOTS];
        // Amendment 6: the fixed margin and no gas cover (the owner sets the measured lamports and cap)
        g.margin_ppm = MARGIN_DEFAULT_PPM;
        g.swap_lamports = 0;
        g.send_lamports = 0;
        g.cover_cap_cents = 0;
        // whole-diff M-1 (lead): capacity is MANDATORY for v3 stores, on from the start with the
        // go-live defaults (k_mode 1, factor 1/3, the platform floor 2,000)
        g.capacity_on = true;
        g.capacity_k_ppm = CAPACITY_K_DEFAULT_PPM;
        g.delivery = [Pubkey::default(); DELIVERY_SLOTS];
        g.k_mode = 1;
        g.k_factor_ppm = K_FACTOR_DEFAULT_PPM;
        g.reward_bps = REWARD_BPS_DEFAULT;
        g.pending_admin = Pubkey::default();
        g.cost_max_usd_e18 = COST_MAX_USD_E18;
        g.platform_floor_ppm = PLATFORM_FLOOR_DEFAULT_PPM;
        g.return_gas_lamports = RETURN_GAS_DEFAULT_LAMPORTS;
        // oft-q7: nothing is charged until the admin sets the measured figures (go-live)
        g.delivery_lamports = 0;
        g.dst_delivery = [GapDstDelivery::default(); DST_DELIVERY_SLOTS];
        g.dst_delivery_to = Pubkey::default();
        // oft-fix: no ATA rent charged and no co-sign key until the admin sets them (go-live)
        g.ata_lamports = 0;
        g.cosigners = [Pubkey::default(); COSIGNER_SLOTS];
        Ok(())
    }
}

// ------------------------------------------------------------------ the admin rotation (two steps)

#[derive(Accounts)]
pub struct AcceptGapAdmin<'info> {
    pub pending_admin: Signer<'info>,
    #[account(mut, seeds = [GAP_GLOBAL_SEED], bump = gap_global.bump)]
    pub gap_global: Box<Account<'info, GapGlobal>>,
}

impl AcceptGapAdmin<'_> {
    /// The proposed admin takes over (NotPendingAdmin for anyone else, or with nothing proposed).
    #[cfg(not(feature = "stock-hops"))] pub fn apply(ctx: &mut Context<AcceptGapAdmin>) -> Result<()> {
        let g = &mut ctx.accounts.gap_global;
        let who = ctx.accounts.pending_admin.key();
        require!(g.pending_admin != Pubkey::default() && who == g.pending_admin, OFTError::NotPendingAdmin);
        // L-2: a co-sign key never takes another role
        require!(!g.is_cosigner(&who), OFTError::BadCosigner);
        g.admin = who;
        g.pending_admin = Pubkey::default();
        emit!(GapAdminSet { admin: who });
        Ok(())
    }
}

// ------------------------------------------------------------------ admin setters

#[derive(Accounts)]
pub struct GapAdmin<'info> {
    pub admin: Signer<'info>,
    #[account(mut, seeds = [GAP_GLOBAL_SEED], bump = gap_global.bump, has_one = admin @OFTError::NotGapAdmin)]
    pub gap_global: Box<Account<'info, GapGlobal>>,
}

impl GapAdmin<'_> {
    /// The admin rotation's first step (constants audit: two steps, never the default key): the
    /// proposed key becomes the admin only when it signs `accept_gap_admin`. A new proposal replaces
    /// the last; proposing the current admin cancels a pending one in effect.
    #[cfg(not(feature = "stock-hops"))] pub fn propose_admin(ctx: &mut Context<GapAdmin>, pending_admin: Pubkey) -> Result<()> {
        require!(pending_admin != Pubkey::default(), OFTError::DefaultKey);
        let g = &mut ctx.accounts.gap_global;
        require!(!g.is_cosigner(&pending_admin), OFTError::BadCosigner);
        g.pending_admin = pending_admin;
        emit!(GapAdminProposed { admin: g.admin, pending_admin });
        Ok(())
    }
    /// Never the default key (a registrar of the default key would make set_gap_pool and the
    /// routes unreachable for the registrar role).
    #[cfg(not(feature = "stock-hops"))] pub fn set_registrar(ctx: &mut Context<GapAdmin>, registrar: Pubkey) -> Result<()> {
        require!(registrar != Pubkey::default(), OFTError::DefaultKey);
        require!(!ctx.accounts.gap_global.is_cosigner(&registrar), OFTError::BadCosigner);
        ctx.accounts.gap_global.registrar = registrar;
        emit!(GapRegistrarSet { registrar });
        Ok(())
    }
    /// Replaces the whole list; `Pubkey::default()` is an empty slot, any other key at most once
    /// (DuplicateKey). The wSOL mint is refused (WsolNotStable): SOL/USD comes only through
    /// GapRoute(wSOL), never as a $1 stable.
    pub fn set_stables(ctx: &mut Context<GapAdmin>, stables: [Pubkey; STABLE_SLOTS]) -> Result<()> {
        require!(!stables.contains(&crate::gap::record::WSOL_MINT), OFTError::WsolNotStable);
        require_distinct(&stables)?;
        ctx.accounts.gap_global.stables = stables;
        emit!(GapStablesSet { stables });
        Ok(())
    }
    /// The composers a composed arrival's receipt (and `return_expired_compose`) serves; replaces the
    /// whole list; the default key is an empty slot, any other key at most once (DuplicateKey).
    pub fn set_composers(ctx: &mut Context<GapAdmin>, composers: [Pubkey; COMPOSER_SLOTS]) -> Result<()> {
        require_distinct(&composers)?;
        ctx.accounts.gap_global.composers = composers;
        emit!(GapComposersSet { composers });
        Ok(())
    }

    // ---- Amendment 6 (AMENDMENT-6.md §2) and the cost max

    /// The fixed margin, 0..=100,000 ppm (MarginTooHigh).
    pub fn set_margin(ctx: &mut Context<GapAdmin>, margin_ppm: u32) -> Result<()> {
        require!(math::check_margin(margin_ppm), OFTError::MarginTooHigh);
        ctx.accounts.gap_global.margin_ppm = margin_ppm;
        emit!(GapMarginSet { margin_ppm });
        Ok(())
    }

    /// The gas cover: swap / send signature lamports (each 0..=100,000) and the per-message cap
    /// (0..=20,000 cents, $200; 0 = no cover). BadGasCover above a hard cap.
    pub fn set_gas_cover(ctx: &mut Context<GapAdmin>, swap_lamports: u32, send_lamports: u32, cover_cap_cents: u16) -> Result<()> {
        require!(math::check_solana_gas_cover(swap_lamports, send_lamports, cover_cap_cents), OFTError::BadGasCover);
        let g = &mut ctx.accounts.gap_global;
        g.swap_lamports = swap_lamports;
        g.send_lamports = send_lamports;
        g.cover_cap_cents = cover_cap_cents;
        emit!(GapGasCoverSet { swap_lamports, send_lamports, cover_cap_cents });
        Ok(())
    }

    /// The LayerZero cost term's cap (USD 1e18): 1..=$50 (BadCostMax). Default $20.
    pub fn set_cost_max(ctx: &mut Context<GapAdmin>, usd_e18: u128) -> Result<()> {
        require!(usd_e18 != 0 && usd_e18 <= COST_MAX_CAP_USD_E18, OFTError::BadCostMax);
        ctx.accounts.gap_global.cost_max_usd_e18 = usd_e18;
        emit!(GapCostMaxSet { usd_e18 });
        Ok(())
    }

    /// The PriceLog window W, 3..=1500 slots (BadWindow).
    pub fn set_window(ctx: &mut Context<GapAdmin>, slots: u32) -> Result<()> {
        require!((WINDOW_MIN..=WINDOW_MAX).contains(&slots), OFTError::BadWindow);
        ctx.accounts.gap_global.window_slots = slots;
        emit!(GapWindowSet { slots });
        Ok(())
    }

    // ---- the PriceLog capacity rule (MANDATORY since whole-diff M-1) and R1' delivery keys

    /// The capacity switch: always on (init_gap_global writes it on); `true` is a no-op kept for
    /// its event, `false` is refused (CapacityMandatory).
    pub fn set_capacity(ctx: &mut Context<GapAdmin>, on: bool) -> Result<()> {
        // whole-diff M-1: capacity can never be switched off (CapacityMandatory); `true` is a no-op
        require!(on, OFTError::CapacityMandatory);
        ctx.accounts.gap_global.capacity_on = true;
        emit!(GapCapacitySet { on });
        Ok(())
    }

    /// k (k_mode 0): each window entry's capacity, 100..=100,000 ppm of the locked depth AND at most
    /// a third of the platform floor (whole-diff I-3: so a bundle that pumps, records and sends
    /// never gains more than the pool fees it pays; BadCapacityK).
    pub fn set_capacity_k(ctx: &mut Context<GapAdmin>, k_ppm: u32) -> Result<()> {
        require!((CAPACITY_K_MIN_PPM..=CAPACITY_K_MAX_PPM).contains(&k_ppm), OFTError::BadCapacityK);
        require!(k_ppm as u64 * 3 <= ctx.accounts.gap_global.platform_floor_ppm as u64, OFTError::BadCapacityK);
        ctx.accounts.gap_global.capacity_k_ppm = k_ppm;
        emit!(GapCapacityKSet { k_ppm });
        Ok(())
    }

    /// Owner (B): 0 = flat k (capacity_k_ppm), 1 = fee-based k (BadKMode otherwise).
    pub fn set_k_mode(ctx: &mut Context<GapAdmin>, k_mode: u8) -> Result<()> {
        require!(k_mode <= 1, OFTError::BadKMode);
        ctx.accounts.gap_global.k_mode = k_mode;
        emit!(GapKModeSet { k_mode });
        Ok(())
    }

    /// Owner (B): k_mode 1's factor, 1..=333,333 ppm of the fee (BadKFactor; whole-diff I-3).
    pub fn set_k_factor(ctx: &mut Context<GapAdmin>, k_factor_ppm: u32) -> Result<()> {
        // whole-diff I-3: at most 1/3 (333,333 ppm) of the fee
        require!((1..=K_FACTOR_MAX_PPM).contains(&k_factor_ppm), OFTError::BadKFactor);
        ctx.accounts.gap_global.k_factor_ppm = k_factor_ppm;
        emit!(GapKFactorSet { k_factor_ppm });
        Ok(())
    }

    /// Step 3: k_mode 1's fee cap, 300..=2,600 ppm (BadPlatformFloor; audit s3 I-1, s3-delta).
    pub fn set_platform_floor(ctx: &mut Context<GapAdmin>, platform_floor_ppm: u32) -> Result<()> {
        require!((PLATFORM_FLOOR_MIN_PPM..=PLATFORM_FLOOR_MAX_PPM).contains(&platform_floor_ppm), OFTError::BadPlatformFloor);
        // whole-diff I-3: the flat k stays at most a third of the floor
        require!(ctx.accounts.gap_global.capacity_k_ppm as u64 * 3 <= platform_floor_ppm as u64, OFTError::BadPlatformFloor);
        ctx.accounts.gap_global.platform_floor_ppm = platform_floor_ppm;
        emit!(GapPlatformFloorSet { platform_floor_ppm });
        Ok(())
    }

    /// L4: the return gas a `return_expired_compose` caller is reimbursed from the receipt's
    /// prepaid lamports, 0..=1,000,000 lamports (BadReturnGas).
    pub fn set_return_gas(ctx: &mut Context<GapAdmin>, return_gas_lamports: u32) -> Result<()> {
        require!(return_gas_lamports <= RETURN_GAS_MAX_LAMPORTS, OFTError::BadReturnGas);
        ctx.accounts.gap_global.return_gas_lamports = return_gas_lamports;
        emit!(GapReturnGasSet { return_gas_lamports });
        Ok(())
    }

    /// oft-ret (cheapest-r4 M-1 (a)): the lzReceive gas of the refund marker `return_expired_compose`
    /// sends home to an EVM chain, REFUND_LZ_GAS_MIN..=REFUND_LZ_GAS_MAX (0 and anything out of range:
    /// BadReturnGas); event on every change.
    pub fn set_refund_gas(ctx: &mut Context<GapAdmin>, refund_lz_gas: u32) -> Result<()> {
        require!((REFUND_LZ_GAS_MIN..=REFUND_LZ_GAS_MAX).contains(&refund_lz_gas), OFTError::BadReturnGas);
        ctx.accounts.gap_global.refund_lz_gas = refund_lz_gas;
        emit!(GapRefundGasSet { refund_lz_gas });
        Ok(())
    }

    /// Q7 (main 06:25Z): what one delivery by our keys costs, 0..=1,000,000 lamports per message
    /// (BadDeliveryCost); event on every change.
    pub fn set_delivery_cost(ctx: &mut Context<GapAdmin>, delivery_lamports: u32) -> Result<()> {
        require!(delivery_lamports <= DELIVERY_LAMPORTS_MAX, OFTError::BadDeliveryCost);
        ctx.accounts.gap_global.delivery_lamports = delivery_lamports;
        emit!(GapDeliveryCostSet { delivery_lamports });
        Ok(())
    }

    /// oft-fix M-1 (users pay): the rent of a recipient token account our keys' delivery creates,
    /// 0..=ATA_LAMPORTS_MAX lamports (BadAtaCost); ATA_LAMPORTS_RENT (u32::MAX) stores the rent-exempt
    /// minimum of a Token-2022 ATA (170 B) read now (2,074,080 at today's rent). Event on every call
    /// with the value stored.
    pub fn set_ata_cost(ctx: &mut Context<GapAdmin>, ata_lamports: u32) -> Result<()> {
        let v = if ata_lamports == ATA_LAMPORTS_RENT {
            u32::try_from(Rent::get()?.minimum_balance(ATA_TOKEN_2022_LEN)).map_err(|_| error!(OFTError::BadAtaCost))?
        } else {
            ata_lamports
        };
        require!(v <= ATA_LAMPORTS_MAX, OFTError::BadAtaCost);
        ctx.accounts.gap_global.ata_lamports = v;
        emit!(GapAtaCostSet { ata_lamports: v });
        Ok(())
    }

    /// oft-fix L-2: replaces both co-sign keys; `Pubkey::default()` is an empty slot, any other key
    /// at most once (DuplicateKey), never GapGlobal.admin, the pending admin, the registrar or a
    /// delivery key (BadCosigner). Event on every call.
    #[cfg(not(feature = "stock-hops"))] pub fn set_cosigners(ctx: &mut Context<GapAdmin>, keys: [Pubkey; COSIGNER_SLOTS]) -> Result<()> {
        require_distinct(&keys)?;
        let g = &mut ctx.accounts.gap_global;
        for k in keys.iter().filter(|k| **k != Pubkey::default()) {
            require!(*k != g.admin && *k != g.pending_admin && *k != g.registrar && !g.is_delivery(k), OFTError::BadCosigner);
        }
        g.cosigners = keys;
        emit!(GapCosignersSet { cosigners: keys });
        Ok(())
    }

    /// Q7-e (eth-fallback §5): a keys-only destination's delivery cost, lamports, upserted into its
    /// slot; 0 frees it. Refused (BadDstDelivery): eid 0 / 30168 / 40168, above
    /// DST_DELIVERY_LAMPORTS_MAX, non-zero while dst_delivery_to is unset; a new eid with every slot
    /// taken is GapDstDeliverySlotsFull. Event on every change.
    pub fn set_dst_delivery(ctx: &mut Context<GapAdmin>, eid: u32, lamports: u64) -> Result<()> {
        require!(!DST_DELIVERY_REFUSED_EIDS.contains(&eid) && lamports <= DST_DELIVERY_LAMPORTS_MAX, OFTError::BadDstDelivery);
        let g = &mut ctx.accounts.gap_global;
        require!(lamports == 0 || g.dst_delivery_to != Pubkey::default(), OFTError::BadDstDelivery);
        if let Some(i) = g.dst_delivery.iter().position(|s| s.eid == eid) {
            g.dst_delivery[i] = if lamports == 0 { GapDstDelivery::default() } else { GapDstDelivery { eid, lamports } };
        } else if lamports != 0 {
            let i = g.dst_delivery.iter().position(|s| s.eid == 0).ok_or(OFTError::GapDstDeliverySlotsFull)?;
            g.dst_delivery[i] = GapDstDelivery { eid, lamports };
        }
        emit!(GapDstDeliveryCostSet { eid, lamports });
        Ok(())
    }

    /// Q7-e: where the per-destination delivery cost goes; never the default key (BadDstDelivery).
    pub fn set_dst_delivery_to(ctx: &mut Context<GapAdmin>, to: Pubkey) -> Result<()> {
        require!(to != Pubkey::default(), OFTError::BadDstDelivery);
        ctx.accounts.gap_global.dst_delivery_to = to;
        emit!(GapDstDeliveryToSet { to });
        Ok(())
    }

    /// Owner (A): the writer reward, 0..=20 bps (BadRewardBps): never above the 0.2% bridge fee.
    pub fn set_reward_bps(ctx: &mut Context<GapAdmin>, reward_bps: u16) -> Result<()> {
        require!(reward_bps <= REWARD_BPS_MAX, OFTError::BadRewardBps);
        ctx.accounts.gap_global.reward_bps = reward_bps;
        emit!(GapRewardBpsSet { reward_bps });
        Ok(())
    }

    /// Replaces both delivery keys; `Pubkey::default()` is an empty slot, any other key at most once
    /// (DuplicateKey).
    #[cfg(not(feature = "stock-hops"))] pub fn set_delivery(ctx: &mut Context<GapAdmin>, keys: [Pubkey; DELIVERY_SLOTS]) -> Result<()> {
        require_distinct(&keys)?;
        // L-2: a delivery key is never a co-sign key
        require!(!keys.iter().any(|k| ctx.accounts.gap_global.is_cosigner(k)), OFTError::BadCosigner);
        ctx.accounts.gap_global.delivery = keys;
        emit!(GapDeliverySet { keys });
        Ok(())
    }

    /// Slot `slot` (< 8) becomes `mint` in class `class`; class 0 empties the slot. As the EVM
    /// registry's `setQuoteClass`: class 1 is refused (stables are class 1 by `set_gap_stables`),
    /// 255 is refused (the refund marker, amendment 2), 2..254 allowed. Also refused: a non-zero class for the default key, and a mint another slot
    /// already classes (one class per mint). BadGapClass for each.
    pub fn set_class(ctx: &mut Context<GapAdmin>, slot: u8, mint: Pubkey, class: u8) -> Result<()> {
        let i = slot as usize;
        // 255 is the expired-compose refund marker (amendment 2): never a quote's class
        require!(i < CLASS_SLOTS && class != STABLE_CLASS && class != crate::gap::math::REFUND_CLASS, OFTError::BadGapClass);
        let g = &mut ctx.accounts.gap_global;
        let entry = if class == 0 {
            GapClass::default()
        } else {
            require!(mint != Pubkey::default(), OFTError::BadGapClass);
            require!(!g.classes.iter().enumerate().any(|(j, c)| j != i && c.class != 0 && c.mint == mint), OFTError::BadGapClass);
            GapClass { mint, class }
        };
        g.classes[i] = entry;
        emit!(GapClassSet { slot, mint: entry.mint, class });
        Ok(())
    }

    /// Replaces the whole list; `Pubkey::default()` is an empty slot, any other key at most once
    /// (DuplicateKey).
    pub fn set_seeders(ctx: &mut Context<GapAdmin>, seeders: [Pubkey; SEEDER_SLOTS]) -> Result<()> {
        require_distinct(&seeders)?;
        ctx.accounts.gap_global.seeders = seeders;
        emit!(GapSeedersSet { seeders });
        Ok(())
    }
}

// ------------------------------------------------------------------ migrate_gap_global (oft-q7)

#[derive(Accounts)]
pub struct MigrateGapGlobal<'info> {
    /// GapGlobal.admin (read from the old layout), who pays the extra rent.
    #[account(mut)]
    pub admin: Signer<'info>,
    /// CHECK: the ["GapGlobal"] PDA in its 760-byte L4 or 844-byte oft-q7 layout (checked in `apply`):
    /// `Account<GapGlobal>` cannot deserialize the shorter account, which is why every other GapGlobal
    /// instruction refuses it until this runs
    #[account(mut, seeds = [GAP_GLOBAL_SEED], bump)]
    pub gap_global: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

impl MigrateGapGlobal<'_> {
    /// The upgrade path for the live GapGlobal: grows a 760-byte (L4) or 844-byte (oft-q7) account
    /// to GAP_GLOBAL_LEN in place; the new fields read 0 (delivery_lamports 0, no keys-only
    /// destination, no dst_delivery_to; oft-fix: ata_lamports 0, no co-sign key), so nothing changes
    /// until the admin sets them. Admin only (NotGapAdmin); anything but this program's 760- or
    /// 844-byte GapGlobal is BadGapGlobalMigration (a second run too).
    pub fn apply(ctx: &mut Context<MigrateGapGlobal>) -> Result<()> {
        let info = ctx.accounts.gap_global.to_account_info();
        let from_len = info.data_len();
        {
            let d = info.try_borrow_data()?;
            require!(
                *info.owner == crate::ID && (d.len() == GAP_GLOBAL_LEN_L4 || d.len() == GAP_GLOBAL_LEN_Q7) && d[..8] == *GapGlobal::DISCRIMINATOR,
                OFTError::BadGapGlobalMigration
            );
            // admin @10 (spec §8.5), the same offset in every layout
            require!(d[10..42] == ctx.accounts.admin.key().to_bytes(), OFTError::NotGapAdmin);
        }
        let need = Rent::get()?.minimum_balance(GAP_GLOBAL_LEN);
        let have = info.lamports();
        if need > have {
            anchor_lang::system_program::transfer(
                CpiContext::new(
                    ctx.accounts.system_program.to_account_info(),
                    anchor_lang::system_program::Transfer { from: ctx.accounts.admin.to_account_info(), to: info.clone() },
                ),
                need - have,
            )?;
        }
        info.resize(GAP_GLOBAL_LEN)?;
        // oft-ret: the retired allowance's 16 bytes @266 become refund_lz_gas = the default + 12 zero
        // bytes, whatever the old allowance held (nothing has read it since Amendment 6)
        {
            let mut d = info.try_borrow_mut_data()?;
            d[GAP_GLOBAL_REFUND_LZ_GAS_AT..GAP_GLOBAL_REFUND_LZ_GAS_AT + 4].copy_from_slice(&REFUND_LZ_GAS_DEFAULT.to_le_bytes());
            d[GAP_GLOBAL_REFUND_LZ_GAS_AT + 4..GAP_GLOBAL_REFUND_LZ_GAS_AT + 16].fill(0);
        }
        // the grown bytes are zero (resize zero-fills), i.e. the fields' 0 / empty values; checked
        let g = read_owned::<GapGlobal>(&info, &crate::ID).ok_or(OFTError::BadGapGlobalMigration)?;
        require!(g.ata_lamports == 0 && g.cosigners == [Pubkey::default(); COSIGNER_SLOTS], OFTError::BadGapGlobalMigration);
        require!(g.refund_gas() == Some(REFUND_LZ_GAS_DEFAULT), OFTError::BadGapGlobalMigration);
        if from_len == GAP_GLOBAL_LEN_L4 {
            require!(g.delivery_lamports == 0 && g.dst_delivery_to == Pubkey::default(), OFTError::BadGapGlobalMigration);
        }
        emit!(GapGlobalMigrated { from_len: from_len as u32, to_len: GAP_GLOBAL_LEN as u32 });
        Ok(())
    }
}

// ------------------------------------------------------------------ the per-store escape (v3c)

#[derive(Accounts)]
pub struct SetGapEscape<'info> {
    pub admin: Signer<'info>,
    #[account(seeds = [GAP_GLOBAL_SEED], bump = gap_global.bump, has_one = admin @OFTError::NotGapAdmin)]
    pub gap_global: Box<Account<'info, GapGlobal>>,
    #[account(mut, seeds = [OFT_SEED, oft_store.token_escrow.as_ref()], bump = oft_store.bump)]
    pub oft_store: Account<'info, OFTStore>,
}

impl SetGapEscape<'_> {
    /// Spec §3 rule 2: on, every receive on this store credits in full at fee 0 (ESCAPED). A v3
    /// store only (its tail byte 299); a live store is refused (NotV3Store), never resized.
    pub fn apply(ctx: &mut Context<SetGapEscape>, on: bool) -> Result<()> {
        let info = ctx.accounts.oft_store.to_account_info();
        {
            let mut d = info.try_borrow_mut_data()?;
            require!(d.len() >= V3_STORE_LEN, OFTError::NotV3Store);
            Tail::write_escape(&mut d, on);
        }
        emit!(GapEscapeSet { oft_store: info.key(), on });
        Ok(())
    }
}

// ------------------------------------------------------------------ routes

#[derive(Clone, AnchorSerialize, AnchorDeserialize)]
pub struct SetGapRouteParams {
    pub quote_mint: Pubkey,
    pub hop_count: u8,
    pub hops: [GapHop; 2],
}

#[derive(Accounts)]
#[instruction(params: SetGapRouteParams)]
pub struct SetGapRoute<'info> {
    pub registrar: Signer<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(seeds = [GAP_GLOBAL_SEED], bump = gap_global.bump, has_one = registrar @OFTError::NotGapRegistrar)]
    pub gap_global: Box<Account<'info, GapGlobal>>,
    #[account(
        init_if_needed,
        payer = payer,
        space = 8 + GapRoute::INIT_SPACE,
        seeds = [GAP_ROUTE_SEED, params.quote_mint.as_ref()],
        bump
    )]
    pub gap_route: Account<'info, GapRoute>,
    pub system_program: Program<'info, System>,
}

/// A mint's decimals if `info` is an initialised SPL Token / Token-2022 mint.
pub fn mint_decimals(info: &AccountInfo) -> Option<u8> {
    if *info.owner != anchor_spl::token::ID && *info.owner != anchor_spl::token_2022::ID {
        return None;
    }
    let d = info.try_borrow_data().ok()?;
    if d.len() < 82 || d[45] != 1 {
        return None;
    }
    Some(d[44]).filter(|x| *x <= MAX_DECIMALS)
}

impl SetGapRoute<'_> {
    /// remaining_accounts: the hop pools, then the mints hops[0].token_in, hops[0].token_out
    /// [, hops[1].token_out]. Each pool is cp-amm's and holds exactly its hop's two mints; the
    /// mints' decimals are recorded.
    #[cfg(not(feature = "stock-hops"))] pub fn apply(ctx: &mut Context<SetGapRoute>, params: &SetGapRouteParams) -> Result<()> {
        let n = params.hop_count as usize;
        require!((1..=2).contains(&n), OFTError::BadGapRoute);
        let rem = ctx.remaining_accounts;
        require!(rem.len() == 2 * n + 1, OFTError::BadGapRoute);
        require!(params.hops[0].token_in == params.quote_mint, OFTError::BadGapRoute);
        if n == 1 {
            require!(params.hops[1] == GapHop::default(), OFTError::BadGapRoute);
        } else {
            require!(params.hops[1].token_in == params.hops[0].token_out, OFTError::BadGapRoute);
        }
        let mut reserved = [0u8; 32];
        for (i, hop) in params.hops[..n].iter().enumerate() {
            require!(hop.kind == HOP_KIND_DAMM_V2 && hop.token_in != hop.token_out, OFTError::BadGapRoute);
            require_keys_eq!(*rem[i].key, hop.pool, OFTError::BadGapRoute);
            let pv = crate::gap::engine::read_pool(&rem[i]).ok_or(OFTError::BadGapRoute)?;
            require!(pv.side(&hop.token_in.to_bytes(), &hop.token_out.to_bytes()).is_some(), OFTError::BadGapRoute);
        }
        let mints = [params.hops[0].token_in, params.hops[0].token_out, params.hops[1].token_out];
        for j in 0..=n {
            let m = &rem[n + j];
            require_keys_eq!(*m.key, mints[j], OFTError::BadGapRoute);
            reserved[j] = mint_decimals(m).ok_or(OFTError::BadGapRoute)?;
        }
        require!(ctx.accounts.gap_global.is_stable(&params.hops[n - 1].token_out), OFTError::BadGapRoute);

        let r = &mut ctx.accounts.gap_route;
        r.version = 1;
        r.bump = ctx.bumps.gap_route;
        r.quote_mint = params.quote_mint;
        r.hop_count = n as u8;
        r.hops = params.hops;
        r.reserved = reserved;
        emit!(GapRouteSet { quote_mint: params.quote_mint, hop_count: n as u8, hops: params.hops });
        Ok(())
    }
}

impl ClearGapRoute<'_> {
    pub fn apply(ctx: &mut Context<ClearGapRoute>) -> Result<()> {
        emit!(GapRouteCleared { quote_mint: ctx.accounts.gap_route.quote_mint });
        Ok(())
    }
}

#[derive(Accounts)]
pub struct ClearGapRoute<'info> {
    #[account(mut)]
    pub registrar: Signer<'info>,
    #[account(seeds = [GAP_GLOBAL_SEED], bump = gap_global.bump, has_one = registrar @OFTError::NotGapRegistrar)]
    pub gap_global: Box<Account<'info, GapGlobal>>,
    #[account(mut, close = registrar, seeds = [GAP_ROUTE_SEED, gap_route.quote_mint.as_ref()], bump = gap_route.bump)]
    pub gap_route: Account<'info, GapRoute>,
}
