//! The v3 gap accounts (docs/v3-gap-fee-spec.md §10): `GapGlobal`, `GapRoute`, `GapReceipt`, and
//! the store tail. Live stores (223 bytes) have no tail and never reach any of this.
use crate::*;

pub const GAP_GLOBAL_SEED: &[u8] = b"GapGlobal";
pub const GAP_ROUTE_SEED: &[u8] = b"GapRoute";
pub const GAP_RECEIPT_SEED: &[u8] = b"GapReceipt";

/// Meteora DAMM v2 (cp-amm), as `pangea-cheapest` `CP_AMM_ID` and the splitter's fixtures.
pub const CP_AMM_ID: Pubkey = pubkey!("cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG");
pub const HOP_KIND_DAMM_V2: u8 = 1;
pub const STABLE_SLOTS: usize = 4;
/// The composer allowlist's slots (GapGlobal's former 64 reserved bytes).
pub const COMPOSER_SLOTS: usize = 2;
/// Decimals above this are refused at registration (10^18 is the largest factor the reader uses).
pub const MAX_DECIMALS: u8 = 18;

// ------------------------------------------------------------------ the store tail

/// `8 + OFTStore::INIT_SPACE`: where LayerZero's store ends and the tail starts.
pub const TAIL_OFFSET: usize = 223;
/// A v3 store is at least this long (`init_oft_v3`).
pub const V3_STORE_LEN: usize = 319;
pub const TAIL_VER_SET: u8 = 1;
const T_VER: usize = 223;
const T_POOL: usize = 224;
const T_QUOTE: usize = 256;
const T_TOKEN_IS_A: usize = 288;
const T_BURNED: usize = 289;
const T_QUOTE_DEC: usize = 297;
const T_TOKEN_DEC: usize = 298;
/// v3c: the store's admin escape (`set_gap_escape`, GapGlobal.admin): 1 = on, the receive credits
/// in full at fee 0 (spec §3 rule 2). Inside the 319-byte store (`V3_STORE_LEN`), so never a realloc.
pub const T_ESCAPE: usize = 299;
const _: () = assert!(T_ESCAPE < V3_STORE_LEN);
/// Owner (A) 2026-10-30: the writer rewards this store still owes (u64 LE @300..308), reserved out
/// of the bridge-fee accrual: `withdraw_fee` never takes them, `claim_writer_rewards` pays them.
/// It equals the PriceLog's owed (entries + reward table) plus every GapReward ledger's owed.
pub const T_REWARD_OWED: usize = 300;
const _: () = assert!(T_REWARD_OWED + 8 <= V3_STORE_LEN);

/// The `LzReceiveTypes` PDA of a v3 store: `[oft_store, token_mint, GapRoute or the program id]`.
pub const V3_LZ_RECEIVE_TYPES_LEN: usize = 8 + 3 * 32;
pub const LZ_RECEIVE_TYPES_SLOT: usize = 8 + 2 * 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tail {
    pub ver: u8,
    pub pool: Pubkey,
    pub quote_mint: Pubkey,
    pub token_is_a: bool,
    pub burned_ld: u64,
    pub quote_decimals: u8,
    pub token_decimals: u8,
    /// v3c: the admin escape (byte 299).
    pub escape: bool,
    /// Owner (A): the writer rewards still owed (bytes 300..308).
    pub reward_owed_ld: u64,
}

fn key_at(d: &[u8], at: usize) -> Pubkey {
    Pubkey::new_from_array(d[at..at + 32].try_into().unwrap())
}

impl Tail {
    pub fn is_set(&self) -> bool {
        self.ver == TAIL_VER_SET
    }

    /// None for a live (legacy) store: shorter than 319 bytes.
    pub fn read(store_data: &[u8]) -> Option<Tail> {
        if store_data.len() < V3_STORE_LEN {
            return None;
        }
        let d = store_data;
        Some(Tail {
            ver: d[T_VER],
            pool: key_at(d, T_POOL),
            quote_mint: key_at(d, T_QUOTE),
            token_is_a: d[T_TOKEN_IS_A] == 1,
            burned_ld: u64::from_le_bytes(d[T_BURNED..T_BURNED + 8].try_into().unwrap()),
            quote_decimals: d[T_QUOTE_DEC],
            token_decimals: d[T_TOKEN_DEC],
            escape: d[T_ESCAPE] == 1,
            reward_owed_ld: u64::from_le_bytes(d[T_REWARD_OWED..T_REWARD_OWED + 8].try_into().unwrap()),
        })
    }

    pub fn write_escape(d: &mut [u8], on: bool) {
        d[T_ESCAPE] = on as u8;
    }

    pub fn write_pool(d: &mut [u8], pool: &Pubkey, quote: &Pubkey, token_is_a: bool, quote_decimals: u8, token_decimals: u8) {
        d[T_VER] = TAIL_VER_SET;
        d[T_POOL..T_POOL + 32].copy_from_slice(pool.as_ref());
        d[T_QUOTE..T_QUOTE + 32].copy_from_slice(quote.as_ref());
        d[T_TOKEN_IS_A] = token_is_a as u8;
        d[T_QUOTE_DEC] = quote_decimals;
        d[T_TOKEN_DEC] = token_decimals;
    }

    /// The reserved reward total of a v3 store's data (0 for a shorter account).
    pub fn reward_owed(d: &[u8]) -> u64 {
        if d.len() < V3_STORE_LEN {
            return 0;
        }
        u64::from_le_bytes(d[T_REWARD_OWED..T_REWARD_OWED + 8].try_into().unwrap())
    }

    /// Add `add` and take `sub` (forfeited or paid) from the reserved reward total; Err when it
    /// would go below 0 (an accounting bug: never pay what was not reserved).
    pub fn adjust_reward_owed(d: &mut [u8], add: u64, sub: u64) -> Result<()> {
        let v = Self::reward_owed(d).checked_add(add).and_then(|v| v.checked_sub(sub)).ok_or(OFTError::RewardAccounting)?;
        d[T_REWARD_OWED..T_REWARD_OWED + 8].copy_from_slice(&v.to_le_bytes());
        Ok(())
    }

    pub fn write_burned(d: &mut [u8], burned_ld: u64) {
        d[T_BURNED..T_BURNED + 8].copy_from_slice(&burned_ld.to_le_bytes());
    }
}

/// True for a store made by `init_oft_v3`.
pub fn is_v3_store(store: &AccountInfo) -> bool {
    store.data_len() >= V3_STORE_LEN
}

// ------------------------------------------------------------------ GapGlobal

#[account]
#[derive(InitSpace)]
pub struct GapGlobal {
    pub version: u8,
    pub bump: u8,
    /// The owner: margin, stables, registrar, admin (rotated in two steps, `pending_admin`).
    pub admin: Pubkey,
    /// Our server key: routes and `set_gap_pool`.
    pub registrar: Pubkey,
    // (the fixed margin is `margin_ppm` @614, Amendment 6)
    /// `Pubkey::default()` is an empty slot; each listed mint is $1.
    pub stables: [Pubkey; STABLE_SLOTS],
    /// The composers `return_expired_compose` serves (spec §10.7): a receipt's `to` must be one of
    /// them. `Pubkey::default()` is an empty slot; all empty refuses every return. Set by `admin`
    /// (`set_gap_composers`). Was `reserved: [u8; 64]` (zero, so a fresh GapGlobal lists none).
    pub composers: [Pubkey; COMPOSER_SLOTS],
    // ---- v3c (spec §6), appended
    // @266..282: Amendment 6's retired gas_allowance_usd_e18 (u128, unused since then), reused in
    // place by oft-ret (cheapest-r4 M-1 (a)) so no offset and no size changes (FastBridge pins 912 B):
    /// oft-ret: the lzReceive gas `return_expired_compose` asks LayerZero's executor for when it sends
    /// a refund marker home to an EVM chain (a class-255 REFUND receive: uncharged, permissionless,
    /// PangeaOFTV3GapModule.gapReceive), in place of the store's 1.27M price-path enforced options.
    /// REFUND_LZ_GAS_MIN..=REFUND_LZ_GAS_MAX (`set_gap_refund_gas`, event GapRefundGasSet; 0 and
    /// anything out of range refused, BadReturnGas). Init and `migrate_gap_global` write
    /// REFUND_LZ_GAS_DEFAULT. A value out of range (a live account's old allowance bytes before the
    /// migration or the setter) is never used: the return then sends with the enforced options.
    pub refund_lz_gas: u32,
    /// The rest of the retired allowance's 16 bytes; zero (init and migration write 0).
    pub reserved_270: [u8; 12],
    /// The PriceLog window W (slots): a send's Ps is the minimum and a receive's Pd the maximum over
    /// the entries with slot in [now - W, now - 1]; 3..=1500, default 150 (`set_gap_window`).
    pub window_slots: u32,
    /// Admin price classes of quote mints (2 = ETH-class, 3..255 canonical assets); class 0 is an
    /// empty slot. Stables are class 1 automatically and never listed here (`set_gap_class`).
    pub classes: [GapClass; CLASS_SLOTS],
    /// The seeders (spec §3 rule 3): an arrival for one of them on a store with no official pool
    /// yet is credited in full (SEED_NO_POOL). `Pubkey::default()` is an empty slot.
    pub seeders: [Pubkey; SEEDER_SLOTS],
    // ---- Amendment 6 (in place of Amendment 5's margin_k_milli / margin_min_ppm / margin_max_ppm /
    // arb_gas_cents: the same 14 bytes at the same offsets, @614..628)
    /// The fixed margin this destination allows, ppm, 0..=100,000, default 1,000 (`set_gap_margin`).
    pub margin_ppm: u32,
    /// The signature lamports of one swap tx (5,000 per signature), 0..=100,000: the source counts
    /// it with its send, the destination for its own swap (`set_gap_gas_cover`). Default 0.
    pub swap_lamports: u32,
    /// The signature lamports of the send tx, 0..=100,000. Default 0.
    pub send_lamports: u32,
    /// The per-message cover cap, cents, 0..=20,000 ($200). 0 = no cover (the default).
    pub cover_cap_cents: u16,
    /// The PriceLog capacity rule and with it consumed-entry pricing (owner (B) 2026-10-30):
    /// MANDATORY (whole-diff M-1) -- init_gap_global writes it on, `set_gap_capacity(false)` is
    /// refused, and the send and the receive never read it (the capacity-off path is gone).
    pub capacity_on: bool,
    /// Each window entry's capacity (k_mode 0), ppm of the locked depth; 100..=100,000 and at most a
    /// third of platform_floor_ppm, default 666 (CAPACITY_K_DEFAULT_PPM; `set_gap_capacity_k`).
    pub capacity_k_ppm: u32,
    /// R1' (c): the two delivery keys that may run a receive's price path at the top level, each
    /// receive with its own mandatory Pd floor (round 2: DeliveryNeedsFloor), and land an oversized
    /// arrival (`set_gap_delivery`). Default empty.
    pub delivery: [Pubkey; DELIVERY_SLOTS],
    // ---- owner (A) and (B) 2026-10-30, appended
    /// Each PriceLog entry's capacity k: 0 = flat, `capacity_k_ppm` for every entry; 1 = fee-based
    /// (the default, init_gap_global, whole-diff M-1), floor(min(entry fee, pool fee now,
    /// platform_floor_ppm) * k_factor_ppm / 1e6) ppm of the locked depth, at least 100
    /// (`set_gap_k_mode`).
    pub k_mode: u8,
    /// k_mode 1's factor, ppm of the fee, 1..=333,333 (K_FACTOR_MAX_PPM: at most 1/3), default
    /// 333,333 (`set_gap_k_factor`).
    pub k_factor_ppm: u32,
    /// The writer reward, bps of the LD an entry's capacity covered on a send, 0..=20 (never above
    /// the 0.2% bridge fee), default 1 (`set_gap_reward_bps`).
    pub reward_bps: u16,
    // ---- step 2 (constants audit), appended
    /// The admin rotation's second step: `propose_gap_admin` writes it, `accept_gap_admin` (signed by
    /// it) makes it the admin. `Pubkey::default()` = nothing proposed.
    pub pending_admin: Pubkey,
    /// The LayerZero cost term's cap, USD 1e18: costUsd = min(lzUsd, this). Default $20
    /// (COST_MAX_USD_E18), 1..=$50 (`set_gap_cost_max`); a 0 reads as the default.
    pub cost_max_usd_e18: u128,
    // ---- step 3 (lead, from the EVM audit), appended: GapGlobal grows 752 -> 756
    /// k_mode 1's fee is capped at this, ppm of volume (`set_gap_platform_floor`, 300..=2,600,
    /// default 2,000): the part of the pool fee a creator's own trades can never get back. On our Solana
    /// launches (pangea-splitter `platform_share_at`, lib.rs) Meteora keeps 20% of the DAMM v2 fee
    /// and the platform max(20% of the fee, 0.2% of volume); the creator gets the rest of the
    /// position's 80%: 0.8 f - max(0.2 f, 0.002) of volume, i.e. 0.04% at the 0.3% floor fee, 0.4% at
    /// 1%, 2% at 5%. So a creator's own pump-record-dump really pays f - that = max(0.4 f, 0.2 f +
    /// 0.002) >= 0.26% (at f = 0.3%), never the full fee; 0.2% is below that at every allowed fee.
    pub platform_floor_ppm: u32,
    // ---- L4 (owner 2026-10-30, user-prepaid compose returns), appended: GapGlobal grows 756 -> 760
    /// The Solana gas a `return_expired_compose` caller is reimbursed from the receipt's prepaid
    /// lamports, on top of LayerZero's fee (`set_gap_return_gas`, 0..=RETURN_GAS_MAX, init 25,000).
    pub return_gas_lamports: u32,
    // ---- oft-q7 (owner Q7, main 06:25Z; eth-fallback §5 Solana-source spec), appended: GapGlobal
    // grows 760 -> 844 (one layout change; `migrate_gap_global` reallocs a live 760-byte account)
    /// Q7: what one delivery by OUR keys costs on Solana, lamports (tx fee + priority at the
    /// delivery compute limit), 0..=DELIVERY_LAMPORTS_MAX (`set_gap_delivery_cost`, event
    /// GapDeliveryCostSet). A price-path v3 arrival delivered by a GapGlobal.delivery key (or landed
    /// by `land_held_receive`) withholds it, valued at the window's SOL/USD minimum (the cover's read)
    /// and converted to tokens at the header's psUsd, into the store's escrow (the bridge-fee accrual,
    /// `withdraw_fee`). Init and migration write 0: nothing is charged until the admin sets it (go-live
    /// sets DELIVERY_LAMPORTS_DEFAULT, script/golive/v3c-gap.json).
    pub delivery_lamports: u32,
    /// Q7-e: the per-destination delivery cost of a Solana-source v3 send toward a keys-only
    /// destination (our keys deliver it: Ethereum), lamports, paid by the sender on top of
    /// LayerZero's fee to `dst_delivery_to` (`set_gap_dst_delivery`; eid 0 = an empty slot).
    pub dst_delivery: [GapDstDelivery; DST_DELIVERY_SLOTS],
    /// Q7-e: where the per-destination delivery cost goes (`set_gap_dst_delivery_to`, never the
    /// default key once set; a non-zero cost needs it).
    pub dst_delivery_to: Pubkey,
    // ---- oft-fix (oft-r3-prog M-1 / L-2), appended: GapGlobal grows 844 -> 912 (`migrate_gap_global`
    // grows a live 760- or 844-byte account)
    /// M-1 (users pay): the rent of the recipient's token account (ATA) when a v3 arrival OUR keys
    /// deliver (a GapGlobal.delivery key at the top level, or `land_held_receive`) has to CREATE it,
    /// lamports, 0..=ATA_LAMPORTS_MAX (`set_gap_ata_cost`, event GapAtaCostSet; the argument
    /// ATA_LAMPORTS_RENT stores the rent-exempt minimum of a Token-2022 ATA read at set time, 2,074,080
    /// today). Added to `delivery_lamports` for that arrival only (valued and withheld the same way,
    /// into the store's escrow); an arrival whose credit cannot pay it in full is refused
    /// (GapAtaRentUnpaid, retriable: the recipient's own account, created by anyone, lets it land).
    /// Init and migration write 0: nothing is charged until the admin sets it (go-live).
    /// oft-lows I-2 (oft-r4-prog): non-zero switches the charge ON and is the quote's figure for a
    /// plain Token-2022 account; what is charged is the creation's ACTUAL cost (the lamports the
    /// payer put into the new account: a legacy Token account's 165-byte rent, a Token-2022 mint with
    /// account extensions its larger account's), so our key never pays a difference and nobody is
    /// over-charged.
    pub ata_lamports: u32,
    /// L-2: the co-sign keys (`set_gap_cosigners`, event GapCosignersSet): a COSIGNED send is honored
    /// only for one of these, signing. Never GapGlobal.admin, the registrar or a delivery key (and a
    /// delivery key / admin / registrar is never one of them), so the co-sign service holds a key with
    /// no other role and no funds. `Pubkey::default()` is an empty slot. Default empty.
    pub cosigners: [Pubkey; COSIGNER_SLOTS],
}

/// Q7-e: one keys-only destination's delivery cost (eid 0 = an empty slot).
#[derive(InitSpace, Clone, Copy, Debug, Default, PartialEq, Eq, AnchorSerialize, AnchorDeserialize)]
pub struct GapDstDelivery {
    pub eid: u32,
    pub lamports: u64,
}

pub const DST_DELIVERY_SLOTS: usize = 4;
/// L-2: the co-sign key slots.
pub const COSIGNER_SLOTS: usize = 2;
/// M-1: the ATA rent bound (about 4.8 x a Token-2022 ATA's 2,074,080).
pub const ATA_LAMPORTS_MAX: u32 = 10_000_000;
/// M-1: `set_gap_ata_cost(ATA_LAMPORTS_RENT)` stores Rent::minimum_balance(ATA_TOKEN_2022_LEN) read then.
pub const ATA_LAMPORTS_RENT: u32 = u32::MAX;
/// A Token-2022 associated token account (account 165 + account type 1 + ImmutableOwner TLV 4).
pub const ATA_TOKEN_2022_LEN: usize = 170;
/// Q7: the per-message bound (main 06:25Z: <= 1,000,000 lamports).
pub const DELIVERY_LAMPORTS_MAX: u32 = 1_000_000;
/// Q7: the measured delivery cost by our key: the 5,000-lamport signature + the priority at the
/// delivery compute limit (solana/client gap-v3.mjs V3_DELIVERY_COMPUTE_UNITS 650,000 since oft-ret, oft-r5 L-2) at
/// the bot's DELIVERY_SOLANA_MICROLAMPORTS default 20,000: 5,000 + ceil(650,000 x 20,000 / 1e6) = 18,000 (17,800 at
/// 640,000).
pub const DELIVERY_LAMPORTS_DEFAULT: u32 = 18_000;
/// Q7-e: the per-destination bound: 0.0064 ETH (DELIVERY_MAX_TX_COST_ETHEREUM) at $3,000 / $93 SOL,
/// rounded down: 0.0064 x 3,000 / 93 x 1e9 = 206,451,612.9.
pub const DST_DELIVERY_LAMPORTS_MAX: u64 = 206_451_612;
/// Q7-e: the go-live figure: owner Q39's 2 gwei x 1.31M gas = 0.00262 ETH at $3,000 / $93, rounded up.
pub const DST_DELIVERY_LAMPORTS_DEFAULT: u64 = 84_516_130;
/// Q7-e: never a keys-only destination: no eid, Solana's own (mainnet / devnet).
pub const DST_DELIVERY_REFUSED_EIDS: [u32; 3] = [0, 30168, 40168];

/// oft-ret (cheapest-r4 M-1 (a)): GapGlobal.refund_lz_gas's byte offset (the retired allowance's).
pub const GAP_GLOBAL_REFUND_LZ_GAS_AT: usize = 266;
/// oft-ret: the refund receive's lzReceive gas toward an EVM chain: the least gas a REFUND lands with
/// through the live EndpointV2 on our Robinhood and Base forks (test/v3/integration/
/// GapRefundGas.fork.t.sol; worst = a new holder; the receive's GAP_READ_GAS guard binds), x 1.2,
/// rounded up to 10,000.
pub const REFUND_LZ_GAS_DEFAULT: u32 = 740_000;
/// oft-ret: `set_gap_refund_gas` bounds: below any OFT credit nothing could land; the top is the v3
/// gas cap (src/v3/GasFloorV3.sol MAX_LZ_RECEIVE_GAS_V3).
pub const REFUND_LZ_GAS_MIN: u32 = 100_000;
pub const REFUND_LZ_GAS_MAX: u32 = 1_400_000;

pub const RETURN_GAS_DEFAULT_LAMPORTS: u32 = 25_000;
pub const RETURN_GAS_MAX_LAMPORTS: u32 = 1_000_000;
/// L4: PDA(["GapPrepay", oft_store, src_eid BE, compose_from, sha256(composeMsg)]) under this
/// program: a 0-data system account the sender's LayerZero native drop funds with its prepaid
/// return (receipt rent + 1.1 x LayerZero's fee home + return gas). Only this program signs for it.
pub const GAP_PREPAY_SEED: &[u8] = b"GapPrepay";

pub fn prepay_address(program_id: &Pubkey, store: &Pubkey, src_eid: u32, compose_from: &[u8; 32], compose_msg: &[u8]) -> (Pubkey, u8) {
    let h = anchor_lang::solana_program::hash::hash(compose_msg).to_bytes();
    prepay_address_of_hash(program_id, store, src_eid, compose_from, &h)
}

/// The GapPrepay PDA from sha256(composeMsg) (Q7-c: `sweep_late_prepay` takes the hash, not the message).
pub fn prepay_address_of_hash(program_id: &Pubkey, store: &Pubkey, src_eid: u32, compose_from: &[u8; 32], msg_hash: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[GAP_PREPAY_SEED, store.as_ref(), &src_eid.to_be_bytes(), compose_from, msg_hash], program_id)
}

/// GapGlobal's size with its discriminator; every offset (docs/v3c-gap-spec.md §8.5) is pinned by
/// the tests. Step 3: 752 -> 756 (platform_floor_ppm u32 @752). L4: 756 -> 760 (return_gas_lamports u32 @756).
/// oft-q7: 760 -> 844 (delivery_lamports u32 @760, dst_delivery 4 x {eid u32, lamports u64} @764,
/// dst_delivery_to @812). oft-fix: 844 -> 912 (ata_lamports u32 @844, cosigners 2 x Pubkey @848).
pub const GAP_GLOBAL_LEN: usize = 912;
const _: () = assert!(8 + GapGlobal::INIT_SPACE == GAP_GLOBAL_LEN);
/// The L4 layout `migrate_gap_global` grows (the live account before oft-q7).
pub const GAP_GLOBAL_LEN_L4: usize = 760;
/// The oft-q7 layout `migrate_gap_global` grows too.
pub const GAP_GLOBAL_LEN_Q7: usize = 844;
pub const GAP_GLOBAL_ATA_AT: usize = 844;
pub const GAP_GLOBAL_COSIGNERS_AT: usize = 848;
pub const GAP_GLOBAL_DELIVERY_AT: usize = 760;
pub const GAP_GLOBAL_DST_DELIVERY_AT: usize = 764;
pub const GAP_GLOBAL_DST_DELIVERY_TO_AT: usize = 812;

impl GapGlobal {
    /// oft-ret: the refund receive gas `return_expired_compose` uses, or None (out of range: the
    /// enforced options are used, as before oft-ret).
    pub fn refund_gas(&self) -> Option<u32> {
        (REFUND_LZ_GAS_MIN..=REFUND_LZ_GAS_MAX).contains(&self.refund_lz_gas).then_some(self.refund_lz_gas)
    }

    /// Q7-e: the delivery cost toward `dst_eid` (0 = LayerZero's executor delivers: nothing extra).
    pub fn dst_delivery_of(&self, dst_eid: u32) -> u64 {
        if dst_eid == 0 {
            return 0;
        }
        self.dst_delivery.iter().find(|s| s.eid == dst_eid).map_or(0, |s| s.lamports)
    }
}

// ------------------------------------------------------------------ Q7-c: a prepay drop after the close

/// Q7-c: PDA(["GapLatePrepay", the GapPrepay PDA]) under this program: the refund party a closed
/// receipt's composer named, kept so a LayerZero native drop that lands at the GapPrepay PDA AFTER
/// the receipt closed still reaches the sender's side (`sweep_late_prepay`, permissionless). Its rent
/// comes out of the closed receipt's payer part; only the payer's own `close_late_prepay` gives it
/// back (`sweep_late_prepay` leaves the record in place). oft-fix I-3: `sweep_late_prepay` serves a
/// record for LATE_PREPAY_TTL_SECS after its receipt closed (`created_at`), never later, so a record
/// cannot catch the drop of a later identical message; the payer closes it after that. oft-lows
/// L-1: a later identical (unsalted) message's unfunded close REFRESHES the record (created_at,
/// refund_to), so that message's own late drop is served for a day after ITS close.
pub const GAP_LATE_PREPAY_SEED: &[u8] = b"GapLatePrepay";
/// oft-fix I-3: how long after the close a late drop is still swept to the recorded party (1 day;
/// LayerZero's executor drops within minutes when it drops separately).
pub const LATE_PREPAY_TTL_SECS: i64 = 86_400;

#[account]
#[derive(InitSpace)]
pub struct GapLatePrepay {
    pub version: u8,
    pub bump: u8,
    /// The GapPrepay PDA it serves.
    pub prepay: Pubkey,
    /// Where a late drop goes (the close's refund account).
    pub refund_to: Pubkey,
    /// The closed receipt's payer: it fronted this record's rent and gets it back.
    pub payer: Pubkey,
    pub created_at: i64,
}

impl GapLatePrepay {
    pub fn address(program_id: &Pubkey, prepay: &Pubkey) -> (Pubkey, u8) {
        Pubkey::find_program_address(&[GAP_LATE_PREPAY_SEED, prepay.as_ref()], program_id)
    }
    pub const LEN: usize = 8 + GapLatePrepay::INIT_SPACE;
}

/// One admin class slot: `mint` is in price class `class` (0 = empty).
#[derive(InitSpace, Clone, Copy, Debug, Default, PartialEq, Eq, AnchorSerialize, AnchorDeserialize)]
pub struct GapClass {
    pub mint: Pubkey,
    pub class: u8,
}

pub const CLASS_SLOTS: usize = 8;
pub const SEEDER_SLOTS: usize = 2;
/// Every stable is in this class (spec §6); `set_gap_class` refuses it.
pub const STABLE_CLASS: u8 = 1;
pub const WINDOW_DEFAULT: u32 = 150;
pub const WINDOW_MIN: u32 = 3;
pub const WINDOW_MAX: u32 = 1_500;
pub const DELIVERY_SLOTS: usize = 2;
/// whole-diff I-3: at most a third of the default platform floor (2,000 / 3 = 666).
pub const CAPACITY_K_DEFAULT_PPM: u32 = 666;
/// Flat k bounds (lead audit 2026-10-30): 0.01%..10% of the locked depth per entry.
pub const CAPACITY_K_MIN_PPM: u32 = 100;
pub const CAPACITY_K_MAX_PPM: u32 = 100_000;
pub const K_FACTOR_DEFAULT_PPM: u32 = 333_333;
/// whole-diff I-3: k_mode 1's factor is at most 1/3 of the fee.
pub const K_FACTOR_MAX_PPM: u32 = 333_333;
/// Step 3: k_mode 1's fee cap (GapGlobal.platform_floor_ppm), default 0.2% of volume. Audit s3
/// I-1: at most 2,600 ppm, the creator's net cost at the 0.3% minimum fee (0.2 f + 0.2% = 0.26%):
/// above it the creator's rebate would come back inside the capacity at a 0.3% pool; at least 300
/// (s3-delta: with the default factor 1/3, k then stays at about 100 ppm or more; the 100 ppm
/// minimum in pricelog::entry_k_ppm covers any factor).
pub const PLATFORM_FLOOR_DEFAULT_PPM: u32 = 2_000;
pub const PLATFORM_FLOOR_MIN_PPM: u32 = 300;
pub const PLATFORM_FLOOR_MAX_PPM: u32 = 2_600;
pub const REWARD_BPS_DEFAULT: u16 = 1;
pub const REWARD_BPS_MAX: u16 = 20;

impl GapGlobal {
    pub fn is_stable(&self, mint: &Pubkey) -> bool {
        *mint != Pubkey::default() && self.stables.iter().any(|s| s == mint)
    }

    /// The price class of a quote mint: 1 for a stable, else its admin slot's class, else 0.
    pub fn class_of(&self, mint: &Pubkey) -> u8 {
        if *mint == Pubkey::default() {
            return 0;
        }
        if self.is_stable(mint) {
            return STABLE_CLASS;
        }
        self.classes.iter().find(|c| c.class != 0 && c.mint == *mint).map_or(0, |c| c.class)
    }

    pub fn is_seeder(&self, key: &Pubkey) -> bool {
        *key != Pubkey::default() && self.seeders.iter().any(|s| s == key)
    }

    pub fn is_delivery(&self, key: &Pubkey) -> bool {
        *key != Pubkey::default() && self.delivery.iter().any(|c| c == key)
    }

    /// L-2: one of the co-sign keys (never the default key).
    pub fn is_cosigner(&self, key: &Pubkey) -> bool {
        *key != Pubkey::default() && self.cosigners.iter().any(|c| c == key)
    }

    /// W in slots (a 0, never set, is the default).
    pub fn window(&self) -> u64 {
        if self.window_slots == 0 { WINDOW_DEFAULT as u64 } else { self.window_slots as u64 }
    }

    /// The LayerZero cost cap in force (a 0, never set, is the $20 default).
    pub fn cost_max(&self) -> u128 {
        if self.cost_max_usd_e18 == 0 { super::math::COST_MAX_USD_E18 } else { self.cost_max_usd_e18 }
    }

    pub fn is_composer(&self, key: &Pubkey) -> bool {
        *key != Pubkey::default() && self.composers.iter().any(|c| c == key)
    }

    pub fn address(program_id: &Pubkey) -> Pubkey {
        Pubkey::find_program_address(&[GAP_GLOBAL_SEED], program_id).0
    }
}

// ------------------------------------------------------------------ GapRoute

#[derive(InitSpace, Clone, Copy, Debug, Default, PartialEq, Eq, AnchorSerialize, AnchorDeserialize)]
pub struct GapHop {
    /// 1 = Meteora DAMM v2.
    pub kind: u8,
    pub pool: Pubkey,
    pub token_in: Pubkey,
    pub token_out: Pubkey,
}

#[account]
#[derive(InitSpace)]
pub struct GapRoute {
    pub version: u8,
    pub bump: u8,
    pub quote_mint: Pubkey,
    pub hop_count: u8,
    pub hops: [GapHop; 2],
    /// [0] decimals of hops[0].token_in, [1] of hops[0].token_out, [2] of hops[1].token_out.
    pub reserved: [u8; 32],
}

impl GapRoute {
    pub fn address(program_id: &Pubkey, quote_mint: &Pubkey) -> Pubkey {
        Pubkey::find_program_address(&[GAP_ROUTE_SEED, quote_mint.as_ref()], program_id).0
    }

    /// The hops in use, with (decimals in, decimals out).
    pub fn used(&self) -> impl Iterator<Item = (&GapHop, u8, u8)> {
        let n = (self.hop_count as usize).min(2);
        self.hops[..n].iter().enumerate().map(move |(i, h)| (h, self.reserved[i], self.reserved[i + 1]))
    }

    /// Hop `i`'s pool, or the program id for an unused slot (the placeholder in §10.4).
    pub fn hop_account(&self, i: usize, program_id: &Pubkey) -> Pubkey {
        if i < self.hop_count as usize && i < 2 {
            self.hops[i].pool
        } else {
            *program_id
        }
    }
}

// ------------------------------------------------------------------ GapReceipt

/// The longest `composeMsg` a v3 message may carry to Solana (the EVM source refuses longer),
/// which bounds a receipt's rent. The receipt holds composeFrom (32) and composeMsg.
pub const MAX_COMPOSE_MSG_LEN: usize = 512;

/// A composed v1 arrival on a v3 store (spec §10.5): what arrived and the compose payload. On
/// Solana a v3 store does not hand the compose to LayerZero's endpoint; the composer reads this
/// record (owner = this program, PDA(["GapReceipt", guid]), `oft_store` = its launch's store) and
/// closes it.
#[account]
#[derive(InitSpace)]
pub struct GapReceipt {
    pub version: u8,
    pub bump: u8,
    pub oft_store: Pubkey,
    pub guid: [u8; 32],
    pub src_eid: u32,
    pub nonce: u64,
    /// The compose recipient (the message's sendTo): the composer, which may close it at any time.
    pub to: Pubkey,
    /// Paid the rent; gets it back.
    pub payer: Pubkey,
    /// What the destination would have credited without the gap fee.
    pub amount_ld: u64,
    pub withheld_ld: u64,
    /// What `to` received (amount_ld - withheld_ld; less a token transfer fee on an Adapter, none
    /// for Pangea mints).
    pub credited_ld: u64,
    pub reason: u8,
    pub created_at: i64,
    pub compose_from: [u8; 32],
    #[max_len(MAX_COMPOSE_MSG_LEN)]
    pub compose_msg: Vec<u8>,
    // ---- L4 (owner 2026-10-30), appended after compose_msg (no earlier offset moves): +40 B
    /// The lamports in this account that are the SENDER's: its prepay, swept from the guid's
    /// GapPrepay PDA at the receive or later (`sweep_gap_prepay`). The rest (rent the payer fronted,
    /// lamports anyone sent beforehand) is the payer's. On close it goes to the composer's refund
    /// account; on a return it pays the caller LayerZero's fee + the return gas, the rest to refund_to.
    pub prepaid: u64,
    /// Where the sender's lamports go on a return (`set_gap_receipt_refund`, by `to`); default: none
    /// (the caller gets the rest).
    pub refund_to: Pubkey,
}

impl GapReceipt {
    pub fn address(program_id: &Pubkey, guid: &[u8; 32]) -> (Pubkey, u8) {
        Pubkey::find_program_address(&[GAP_RECEIPT_SEED, guid], program_id)
    }

    /// The account size for a `compose_msg` of `len` bytes.
    pub fn space(len: usize) -> usize {
        8 + GapReceipt::INIT_SPACE - MAX_COMPOSE_MSG_LEN + len
    }
}

/// Read an Anchor account we own from an `AccountInfo`, None if it is anything else.
pub fn read_owned<T: AccountDeserialize>(info: &AccountInfo, program_id: &Pubkey) -> Option<T> {
    if info.owner != program_id || info.data_is_empty() {
        return None;
    }
    let d = info.try_borrow_data().ok()?;
    T::try_deserialize(&mut &d[..]).ok()
}
