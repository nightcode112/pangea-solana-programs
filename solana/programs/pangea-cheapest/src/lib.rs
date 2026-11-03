//! # Pangea Cheapest chain: Solana as the far chain
//!
//! The trade card's "Cheapest chain" route lets a user on an EVM chain pay and be paid on their own
//! chain while the trade is made in the pool of whichever chain prices it best. On the EVM chains
//! that is `PangeaCheapestChain.sol`. This program is the same route when the best pool is the
//! token's Meteora DAMM v2 pool on Solana. It is its own program, not instructions in the
//! splitter, for one reason above the others: every instruction of the splitter runs in a program
//! that can sign as `AUTHORITY`, the admin and endpoint delegate of every Pangea token's bridge.
//! Nothing here can, so no mistake here can reach a bridge, a launch, a position or a fee.
//!
//! Two things shape everything below:
//!
//!   * **Relay cannot call a program on Solana.** Its quote API takes only `0x` call targets. So a
//!     buy cannot be "Relay delivers and calls"; Relay delivers SOL to an address -- an ORDER, a
//!     program-derived address that is a function of the order's terms -- and somebody else makes
//!     the trade.
//!   * **No program can call the OFT program's `send`.** It runs at the bottom of the call-depth
//!     limit already (OFT -> endpoint -> library -> workers), and SIMD-0268 is not active. So the
//!     tokens are sent home by a top-level `send`, in the same transaction as the trade, and this
//!     program checks that transaction's other instructions (the instructions sysvar) instead.
//!
//! ## A buy (`buy`, `finish_send`, `refund`)
//!
//! The web quotes an order: the user's EVM address and chain, the mint, the lamports Relay will
//! deliver, the fewest tokens that must ARRIVE, a deadline, a cap on LayerZero's fee and the
//! runner's fee. Their hash is the order's address (`order_address`), and Relay delivers there.
//! Nothing else can be read into the address, and nothing but these terms can spend from it.
//!
//! A runner -- pangea-delivery by default, anyone at all -- then sends ONE transaction:
//!
//!   1. `buy`: the order's lamports, less LayerZero's fee and the runner's, buy the token in the
//!      launch's own pool, into the runner's token account; the runner is paid the two fees;
//!   2. the OFT program's `send` of what was bought (up to a fiftieth less: the rest is sold back
//!      to SOL into the box by `buy` itself), from the runner, to the user's address
//!      on their chain, with the order's minimum as `min_amount_ld` -- which the OFT program
//!      enforces against what will arrive -- and LayerZero's fee as the runner stated it;
//!   3. `finish_send`: the runner's token account holds no more than it did before the buy, but for
//!      the sub-unit dust no bridge can carry.
//!
//! `buy` refuses to run unless instructions 2 and 3 are exactly those, so the tokens cannot stop
//! anywhere on the way, and the transaction lands whole or not at all.
//!
//! After the deadline the order cannot buy. `refund` moves whatever it holds into the user's
//! BOX, and the box pays out through Relay (`pay_out`).
//!
//! ## A sale (`sell_composed`, `return_composed`)
//!
//! The user sends the tokens from their chain to this program's COMPOSER address with the OFT's
//! send-and-call. LayerZero mints them into the composer's token account and records the call at
//! the endpoint. `sell_composed` clears that record (the endpoint checks it byte for byte), sells
//! exactly what arrived in the launch's pool with the user's minimum, pays the runner its fee and
//! puts the rest in the user's box, for `pay_out`. Anyone may run it, until the call's deadline.
//!
//! After the deadline -- or for a call that is malformed -- the sale is not made:
//! `return_composed` sells only a slice of the tokens, enough to pay LayerZero's fee home and the
//! runner, and sends the rest home to the sender on the chain they came from, with the same
//! three-instruction transaction as a buy. The user pays for it out of their own tokens; Pangea
//! pays nothing.
//!
//! ## Pangea v3 tokens (docs/v3-gap-fee-spec.md, owner decision Q5)
//!
//! A v3 token's OFT store (`init_oft_v3`, at least 319 bytes: `parse::is_v3_store`) refuses its
//! `send` under CPI and after any earlier instruction of the transaction touched its official pool.
//! The buy's three instructions (swap in the pool, then `send`) and a failed sale's way home
//! (`return_composed`: a slice sold, then `send`) can therefore never land for it: Solana as the
//! far chain is OFF for v3 tokens. `buy` and `return_composed` refuse a v3 store up front
//! (`V3SolanaFarOff`) instead of failing at the send. `sell_composed` alone stays: a v3 composed
//! arrival makes no LayerZero compose record; it leaves a `GapReceipt` (`PDA(["GapReceipt",
//! guid])` under the OFT program) holding what was CREDITED after the gap fee, and the call.
//! `sell_composed` reads that receipt instead of the endpoint's record -- owned by the OFT
//! program, at the guid's address, naming this store and the composer -- sells exactly
//! `credited_ld`, and closes the receipt in the same instruction (`close_gap_receipt`, signed by
//! the composer), so no call is taken twice. Its accounts are `Compose`'s with the receipt in the
//! `compose_message` place, then two remaining accounts: the receipt's payer (its rent goes back
//! there) and the OFT program. L4 (owner 2026-10-30): the close also passes the seller's box (the
//! Compose's `user_box`, no new account) as the OFT close's refund account, so the sender's prepaid
//! return lamports (`receipt.prepaid`) go to the box with the proceeds. The web must not offer the route for v3 tokens. Live (v1/v2) tokens
//! are unchanged.
//!
//! **A v3 sale that cannot be made goes home whole** (owner decision 2026-10-28):
//! `release_expired_v3`, permissionless, once the call can no longer be sold (past its deadline, a
//! deadline beyond the horizon, a call or sender that cannot be read), approves exactly the
//! receipt's `credited_ld` on the composer's token account to `PDA(["GapReturn", guid])` under the
//! OFT program -- a delegate that names the guid, so the consent is for that receipt and no other.
//! The OFT program's top-level `return_expired_compose(guid)` then sends that amount back to the
//! receipt's `compose_from` on its `src_eid` -- the original owner, never an address anyone picks
//! -- and closes the receipt in the same instruction (docs/v3-gap-fee-spec.md §10.7). oft-lows L-2:
//! a receipt crediting 0 (the OFT writes one only when the sender's prepay sits at its GapPrepay
//! PDA, so that prepay is never swept into this composer's PDA, which cannot move it out) is never
//! sold and is released the same way (approve 0), its prepay then going to the seller's box. L4: the
//! release also names the seller's box as the receipt's refund_to (the OFT program's
//! `set_gap_receipt_refund`, signed by the composer), so what is left of the sender's prepaid
//! return lamports after the caller's reimbursement goes to the box; its accounts end with the OFT
//! program. Nothing here
//! chooses where the tokens go, and nothing is sold on the way: whoever sends the return pays
//! LayerZero's fee. The OFT program serves only the composers its admin lists
//! (`GapGlobal.composers`, spec §10.1): this program's composer PDA must be on that list.
//!
//! **The release and the return must be ONE transaction** (release first, both top level; the
//! client's `v3ReturnExpiredInstructions` builds exactly that). Two expired sales of the same mint
//! share this composer's token account, and an SPL token account has one delegate: a second
//! release replaces the first's approval with its own guid's delegate, and the first sale's
//! return then fails with `ReturnNotApproved` until it is released again. In one transaction
//! nothing can come between the approval and the return that spends it.
//!
//! **A sale from a keys-only chain** (Q59, owner 2026-10-31; Ethereum at go-live: the OFT program's
//! `GapGlobal.dst_delivery` toward it is > 0, our keys deliver there): the sale is the same 26-key
//! `sell_composed` and nothing in it is capped. Its way home costs LayerZero's fee with executor gas
//! on that chain (or LayerZero's part plus our delivery cost), about `dst_delivery`, above the 50M
//! every other route is capped at; so the cap on the fee home toward such a chain is read per chain
//! from that same figure (`parse::home_fee_cap_for`: dst_delivery + max(dst_delivery, 50M)), by
//! `return_composed` from GapGlobal and by the web and the runner (the call's `home_fee_cap`, the
//! runner's v3 return cap) from the same account.
//!
//! ## The box, and paying out (`pay_out`)
//!
//! Every lamport owed to a user waits in their box, `PDA(["box", chain, address])`, a plain system
//! account only this program can sign for. `pay_out` sends all of it to a Relay deposit address
//! that pays the user on their chain. Which address that is cannot be known on chain, and must be
//! FRESH -- Relay has not said its deposit addresses take late deposits -- so it is named at the
//! moment of paying, by a quote the web makes then, and signed by the payout signer
//! (`Config::payout_signer`) over this box, this user, this chain, the box's payout count, the amount
//! it holds, that address, the runner's fee and an expiry, for a few
//! minutes. Relay refunds a payout it cannot fill to the same box (the quote's `refundTo`), and the
//! next `pay_out` tries again with a new quote. Nothing leaves a box any other way.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    hash,
    instruction::{get_stack_height, AccountMeta, Instruction, TRANSACTION_LEVEL_STACK_HEIGHT},
    keccak,
    program::{invoke, invoke_signed},
    secp256k1_recover::secp256k1_recover,
    system_instruction,
    sysvar::instructions as sysvar_instructions,
};
use anchor_lang::Discriminator;

pub mod parse;
use parse::*;

declare_id!("HQ6RgB3GGJvrkpj4dRiVMEQJAcEq4bAwtmaH6swnvDQC");

/// The admin of the splitter, and of this program's one setting: who signs payouts.
#[cfg(not(feature = "rehearsal-admin"))] pub const ADMIN: Pubkey = pubkey!("7rYog4JusTy4CpwvFGPrRvWtcDrWatnA3SN3DRPuf6kM"); #[cfg(feature = "rehearsal-admin")] pub const ADMIN: Pubkey = rehearsal_admin::ADMIN; #[cfg(any(feature = "rehearsal-admin", test))] pub mod rehearsal_admin; // rehearsal builds only (feature rehearsal-admin): the throwaway admin PANGEA_REHEARSAL_ADMIN named at build time, src/rehearsal_admin.rs
/// The launch program. Its `PDA(["authority"])` is the admin of every Pangea token's OFT store.
pub const SPLITTER_ID: Pubkey = pubkey!("Hb5uTppRbNxc3RjVRqTWqfdU3E3GiZyGYKccxYf9tUej");
/// Meteora DAMM v2.
pub const CP_AMM_ID: Pubkey = pubkey!("cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG");
/// Our deployment of LayerZero's OFT program.
pub const OFT_PROGRAM_ID: Pubkey = pubkey!("SNyKyiZYU4R54SF9sYLmjCaCUsa1sC6QouNAj3x3Zzf");
/// LayerZero's endpoint.
pub const LZ_ENDPOINT_ID: Pubkey = pubkey!("76y77prsiCMvXMjuoZ5VRrhG5qYBrUMYTE5WgHqgjEn6");
pub const WSOL: Pubkey = anchor_spl::token::spl_token::native_mint::ID;
pub const TOKEN_2022_ID: Pubkey = anchor_spl::token_2022::ID;
pub const TOKEN_ID: Pubkey = anchor_spl::token::ID;
pub const ATA_PROGRAM_ID: Pubkey = anchor_spl::associated_token::ID;

/// Solana's LayerZero endpoint id: never a destination for a user's payout or tokens here.
pub const SOLANA_EID: u32 = 30168;

pub const CONFIG_SEED: &[u8] = b"config";
pub const ORDER_SEED: &[u8] = b"order";
pub const BOX_SEED: &[u8] = b"box";
pub const COMPOSER_SEED: &[u8] = b"composer";
pub const TEMP_SEED: &[u8] = b"wsol";
pub const SEQ_SEED: &[u8] = b"seq";
pub const LEDGER_SEED: &[u8] = b"ledger";

/// What an order's hash begins with.
pub const ORDER_DOMAIN: &[u8] = b"pangea cheapest order v1";
/// What a payout's signed message begins with.
pub const PAYOUT_DOMAIN: &[u8] = b"pangea cheapest payout v1";

/// A token account's size (SPL Token and Token-2022 without extensions).
pub const TOKEN_ACCOUNT_LEN: usize = 165;

/// The OFT carries six decimals of a nine-decimal token: what is finer than 1,000 base units stays
/// where it was sent from (`finish_send` allows it).
pub const DUST: u64 = 1_000;

/// The least a box pays out at once: 0.005 SOL. Relay leaves a deposit worth $0.05 or less waiting
/// for good, so a smaller payout could be stranded; this keeps every payout well above that, and a
/// box under it simply waits for more.
pub const MIN_PAYOUT: u64 = 5_000_000;
/// The most a runner may be paid for one payout: two signatures and a priority fee, with room.
pub const MAX_PAYOUT_RUNNER_FEE: u64 = 100_000;
/// The longest a payout signature may be good for. The address it names is a quote's, and a quote
/// is only fresh for minutes.
pub const MAX_PAYOUT_TTL: i64 = 900;

/// A failed sale's fees when its call cannot be read (it names none): the runner's, and the most
/// LayerZero's fee home may be (Q59: toward a keys-only chain, read per chain: `parse::home_fee_cap_for`).
pub const DEFAULT_RUNNER_FEE: u64 = 2_000_000;
pub const DEFAULT_HOME_FEE_CAP: u64 = 50_000_000;

/// How far over what it needs a failed sale's slice may fetch: a tenth, and this many lamports.
/// The runner picks the slice from a simulation; this keeps it a slice.
pub const SLICE_SLACK: u64 = 50_000;

/// How long after its deadline a failed sale is held to the seller's own terms on its way home: their
/// cap on LayerZero's fee home, their runner fee, and a floor on the slice's price (a quarter of the
/// price their minimum named). After it -- a week -- the call goes home on the defaults, so that no
/// fee cap or call can keep the tokens away for good. The floor does not end with the grace: it
/// halves every further RETURN_GRACE (so no price keeps the tokens away for good either, only for a
/// while), for a slice of a tenth at most: a larger slice after the grace keeps the grace's floor,
/// never faded, so a runner who crushes the price cannot sell most of the amount for the fee home,
/// and a call whose tenth cannot pay its way home still goes at the grace's price. A whole sale's
/// floor never fades (owner decision
/// 2026-10-26): it is always the grace's, and the sale is dust besides (no more than the whole-sale
/// cap), so a runner who crushes the price cannot take the whole amount, however long it has waited.
pub const RETURN_GRACE: i64 = 7 * 86_400;
/// After the grace, a readable call's slice with a fading floor is at most this part of what
/// arrived (a larger one keeps the unfaded floor); a call that cannot be read is held to UNREADABLE_SLICE_DIVISOR.
pub const LATE_SLICE_DIVISOR: u64 = 10;
/// A failed sale's cap on LayerZero's fee home after the grace: what any route costs, many times over.
/// Q59 (owner 2026-10-31): toward a KEYS-ONLY chain (the OFT program's GapGlobal.dst_delivery > 0)
/// this and DEFAULT_HOME_FEE_CAP are raised per chain to `parse::home_fee_cap_for(cap, dst_delivery)`
/// = dst_delivery + max(dst_delivery, 50,000,000) (169,032,260 toward Ethereum at go-live), read from
/// GapGlobal, which `return_composed` takes as its one optional remaining account.
pub const GRACE_HOME_FEE_CAP: u64 = 50_000_000;
/// The slice's floor during the grace: its price at least 1/RETURN_FLOOR_DIVISOR of the minimum's.
pub const RETURN_FLOOR_DIVISOR: u128 = 4;
/// The most a call may fetch to be sold whole on its way home (when it is worth no more than the
/// way home would cost): a cap of its own, so a generous cap on LayerZero's fee is not also a
/// licence to sell a call worth that much whole.
pub const WHOLE_SALE_CAP: u64 = 5_000_000;
/** The most of what a buy bought that may be kept from the send and sold back (one part in this). */
pub const LEFTOVER_DIVISOR: u64 = 50;
/** The leftover is never sold back below this part of the price the buy paid. */
pub const LEFTOVER_FLOOR_DIVISOR: u128 = 2;
/** A leftover worth less than this at the price paid is not sold back; the runner keeps it. */
pub const LEFTOVER_MIN_LAMPORTS: u64 = 10_000;
/// What LayerZero may charge below the fee a runner was paid, with nowhere to put the rest: the
/// larger of this and a fiftieth of the fee (its quote moving between simulation and landing).
pub const UNPLACED_FEE_SLACK: u64 = 20_000;
pub const UNPLACED_FEE_DIVISOR: u64 = 50;
/// The cap on the fee home for a call whose sender has no box (not an EVM address).
pub const NO_BOX_HOME_FEE_CAP: u64 = 5_000_000;
/// A call that cannot be read names no floor: its slice is at most this part of what arrived, and it
/// is never sold whole -- what a whole sale fetches is no bound when the runner sets the price -- so
/// a runner crushing the price cannot sell more than a tenth of it for nothing.
pub const UNREADABLE_SLICE_DIVISOR: u64 = 10;
/// The furthest ahead a deadline may be. An order or a call whose deadline is further than this
/// (no quote writes one) is treated as past it: refunded, or sent home, without waiting.
pub const MAX_HORIZON: i64 = 2 * 86_400;

#[program]
pub mod pangea_cheapest {
    use super::*;

    /// Make the program's settings, naming the payout signer. ADMIN only, once.
    pub fn init_config(ctx: Context<InitConfig>, payout_signer: [u8; 20]) -> Result<()> {
        require!(payout_signer != [0u8; 20], CheapestError::ZeroSigner);
        ctx.accounts.config.payout_signer = payout_signer;
        ctx.accounts.config.bump = ctx.bumps.config;
        emit!(PayoutSignerSet { payout_signer });
        Ok(())
    }

    /// Name another payout signer. ADMIN only.
    pub fn set_payout_signer(ctx: Context<SetPayoutSigner>, payout_signer: [u8; 20]) -> Result<()> {
        require!(payout_signer != [0u8; 20], CheapestError::ZeroSigner);
        ctx.accounts.config.payout_signer = payout_signer;
        emit!(PayoutSignerSet { payout_signer });
        Ok(())
    }

    /// The first of a buy's three instructions. See the module documentation.
    ///
    /// `leftover_price`: the least the tokens bought above what is sent may be sold back for, in
    /// lamports per 10^9 base units -- the runner's simulation of that sale.
    pub fn buy<'info>(ctx: Context<'_, '_, 'info, 'info, Buy<'info>>, terms: OrderTerms, lz_fee: u64, leftover_price: u64) -> Result<()> {
        buy_handler(ctx, terms, lz_fee, leftover_price)
    }

    /// The last of the three instructions of a buy or of a failed sale's way home: the runner's
    /// token account holds no more than `before` and the dust no bridge can carry.
    pub fn finish_send(ctx: Context<FinishSend>, before: u64) -> Result<()> {
        finish_handler(ctx, before)
    }

    /// After its deadline, an order's lamports go to the user's box. Anyone may send it.
    pub fn refund(ctx: Context<Refund>, terms: OrderTerms) -> Result<()> {
        refund_handler(ctx, terms)
    }

    /// A sale that arrived with its call: sold, the runner paid, the rest into the seller's box.
    pub fn sell_composed<'info>(ctx: Context<'_, '_, 'info, 'info, Compose<'info>>, params: ComposeParams) -> Result<()> {
        sell_handler(ctx, params)
    }

    /// A sale that cannot be made -- past its deadline, or a call that cannot be read -- sent home:
    /// `slice_in` of the tokens sold to pay LayerZero's fee home (`home_fee`) and the runner, the
    /// rest sent back to the seller by the OFT `send` that must follow, and `finish_send` after it.
    /// When the whole amount is worth no more than the way home would cost, all of it is sold
    /// (`slice_in` = everything, `home_fee` = 0) and what is left after the runner goes to the box.
    /// Q59: one optional remaining account, the OFT program's GapGlobal (read only), raises the cap on
    /// `home_fee` toward a keys-only source chain to `parse::home_fee_cap_for` (absent: today's caps).
    pub fn return_composed<'info>(
        ctx: Context<'_, '_, 'info, 'info, Compose<'info>>,
        params: ComposeParams,
        slice_in: u64,
        home_fee: u64,
    ) -> Result<()> {
        return_handler(ctx, params, slice_in, home_fee)
    }

    /// A v3 sale that can no longer be made: consent for the OFT program to send its credited
    /// amount home (see "Pangea v3 tokens"). Anyone may send it, always in the same transaction
    /// as the OFT program's `return_expired_compose` (one delegate per token account).
    pub fn release_expired_v3(ctx: Context<ReleaseV3>, params: ComposeParams) -> Result<()> {
        release_handler(ctx, params)
    }

    /// A box paid out, all of it, to the Relay deposit address the payout signer names for it.
    pub fn pay_out(ctx: Context<PayOut>, user: [u8; 20], eid: u32, amount: u64, runner_fee: u64, expires: i64, signature: [u8; 65]) -> Result<()> {
        pay_out_handler(ctx, user, eid, amount, runner_fee, expires, signature)
    }
}

// ================================================================================== state

#[account]
#[derive(InitSpace)]
pub struct Config {
    /// The EVM-style address (keccak of the secp256k1 key) whose signature names a payout's
    /// deposit address.
    pub payout_signer: [u8; 20],
    pub bump: u8,
}

/// A box's payout count: `PDA(["seq", box])`. A payout's signature names the count it is for, and
/// the payout moves it on, so a signature pays once. Made by the box's first payout, out of the box.
#[account]
#[derive(InitSpace)]
pub struct PayoutSeq {
    pub next: u64,
}

/// A runner's ledger, `PDA(["ledger", runner])`: what `buy` or `return_composed` paid it for
/// LayerZero's fee home and where it stood afterwards, for `finish_send` to measure what the send
/// really cost and hand the rest back to the user's box. Made by the runner's first use, at its own
/// rent, and kept.
#[account]
#[derive(InitSpace)]
pub struct Ledger {
    /// The runner's lamports when the instruction before the send ended.
    pub runner_after: u64,
    /// What it was paid for LayerZero's fee (the send's `native_fee`: a ceiling, not the charge).
    pub fee: u64,
    /// The runner's token balance before the instruction (what the finish holds it to): read on
    /// chain, so a balance the runner read a moment earlier cannot make the transaction fail.
    pub before: u64,
    /// Where the part of it LayerZero did not charge goes; default when nowhere.
    pub user_box: Pubkey,
    pub armed: bool,
    pub bump: u8,
}

/// An order, as the user was quoted it. Its hash is the order's address.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct OrderTerms {
    /// The user's address on their chain: where the tokens go, and whose box a refund fills.
    pub user: [u8; 20],
    /// The user's chain.
    pub dst_eid: u32,
    /// The token.
    pub mint: Pubkey,
    /// The lamports Relay delivers: everything the buy spends, LayerZero's fee and the runner's.
    pub amount: u64,
    /// The fewest tokens that must ARRIVE on the user's chain, in base units.
    pub min_out: u64,
    /// Unix seconds: the last moment the order buys.
    pub deadline: i64,
    /// The most LayerZero's fee home may be.
    pub lz_fee_cap: u64,
    /// What the runner is paid, for the transaction and its own account's rent.
    pub runner_fee: u64,
    /// Makes two otherwise equal orders two addresses.
    pub salt: [u8; 16],
}

impl OrderTerms {
    pub fn hash(&self) -> [u8; 32] {
        hash::hashv(&[ORDER_DOMAIN, &self.try_to_vec().expect("fixed-size terms")]).to_bytes()
    }
}

/// The endpoint's `ClearComposeParams`: what the call is, as LayerZero recorded it.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct ComposeParams {
    /// The OFT store that minted the tokens and queued the call.
    pub from: Pubkey,
    pub guid: [u8; 32],
    pub index: u16,
    pub message: Vec<u8>,
}

// ================================================================================== addresses

pub fn order_address(terms: &OrderTerms) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[ORDER_SEED, &terms.hash()], &crate::ID)
}

pub fn box_address(eid: u32, user: &[u8; 20]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[BOX_SEED, &eid.to_le_bytes(), user], &crate::ID)
}

pub fn composer_address() -> (Pubkey, u8) {
    Pubkey::find_program_address(&[COMPOSER_SEED], &crate::ID)
}

/// The composer's associated Token-2022 account for `mint`: where an arrival for it is minted.
pub fn composer_token_address(mint: &Pubkey) -> Pubkey {
    let composer = composer_address().0;
    Pubkey::find_program_address(&[composer.as_ref(), TOKEN_2022_ID.as_ref(), mint.as_ref()], &ATA_PROGRAM_ID).0
}

pub fn temp_address(runner: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[TEMP_SEED, runner.as_ref()], &crate::ID)
}

/// The launch's pool: Meteora's one customizable pool of the token and wrapped SOL, which `launch`
/// opened in the instruction that created the mint (so nobody could have opened it first) -- for a
/// launch paired against SOL. A launch paired against another asset has no such pool of its own, and
/// one anybody opens at this address is not the launch's: the site routes only launches the
/// splitter's record says are paired against SOL (cheapest-solana-io.mjs, solanaLaunchTradable), so
/// no order or call for another is made through it.
pub fn pool_address(mint: &Pubkey) -> Pubkey {
    let (first, second) = if mint.to_bytes() > WSOL.to_bytes() { (*mint, WSOL) } else { (WSOL, *mint) };
    Pubkey::find_program_address(&[b"cpool", first.as_ref(), second.as_ref()], &CP_AMM_ID).0
}

pub fn splitter_authority() -> Pubkey {
    Pubkey::find_program_address(&[b"authority"], &SPLITTER_ID).0
}

/// The digest a payout signature is over.
#[allow(clippy::too_many_arguments)]
pub fn payout_digest(box_key: &Pubkey, user: &[u8; 20], eid: u32, seq: u64, amount: u64, deposit: &Pubkey, runner_fee: u64, expires: i64) -> [u8; 32] {
    keccak::hashv(&[
        PAYOUT_DOMAIN,
        crate::ID.as_ref(),
        box_key.as_ref(),
        user,
        &eid.to_le_bytes(),
        &seq.to_le_bytes(),
        &amount.to_le_bytes(),
        deposit.as_ref(),
        &runner_fee.to_le_bytes(),
        &expires.to_le_bytes(),
    ])
    .0
}

pub fn ledger_address(runner: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[LEDGER_SEED, runner.as_ref()], &crate::ID)
}

pub fn seq_address(box_key: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[SEQ_SEED, box_key.as_ref()], &crate::ID)
}

// ================================================================================== accounts

#[derive(Accounts)]
pub struct InitConfig<'info> {
    #[account(mut, address = ADMIN @ CheapestError::NotAdmin)]
    pub admin: Signer<'info>,
    #[account(init, payer = admin, space = 8 + Config::INIT_SPACE, seeds = [CONFIG_SEED], bump)]
    pub config: Account<'info, Config>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SetPayoutSigner<'info> {
    #[account(address = ADMIN @ CheapestError::NotAdmin)]
    pub admin: Signer<'info>,
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
}

/// What a swap through the launch's pool needs beside the two token accounts and the signer.
#[derive(Accounts)]
pub struct Venue<'info> {
    /// CHECK: the launch's pool (`pool_address`), checked in the handler; Meteora checks the rest.
    #[account(mut)]
    pub pool: UncheckedAccount<'info>,
    /// CHECK: Meteora checks it.
    pub pool_authority: UncheckedAccount<'info>,
    /// CHECK: Meteora checks it against the pool.
    #[account(mut)]
    pub token_a_vault: UncheckedAccount<'info>,
    /// CHECK: Meteora checks it against the pool.
    #[account(mut)]
    pub token_b_vault: UncheckedAccount<'info>,
    /// CHECK: Meteora's event authority; Meteora checks it.
    pub cp_amm_event_authority: UncheckedAccount<'info>,
    /// CHECK: pinned.
    #[account(address = CP_AMM_ID @ CheapestError::WrongProgram)]
    pub cp_amm_program: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct Buy<'info> {
    #[account(mut)]
    pub runner: Signer<'info>,
    /// CHECK: the order's address, derived from the terms in the handler.
    #[account(mut)]
    pub order: UncheckedAccount<'info>,
    /// CHECK: the user's box, derived from the terms in the handler.
    #[account(mut)]
    pub user_box: UncheckedAccount<'info>,
    /// CHECK: `PDA(["wsol", runner])`, made and closed inside the instruction.
    #[account(mut, seeds = [TEMP_SEED, runner.key().as_ref()], bump)]
    pub temp: UncheckedAccount<'info>,
    /// CHECK: the runner's token account for the mint; read and checked in the handler.
    #[account(mut)]
    pub runner_token: UncheckedAccount<'info>,
    /// CHECK: the runner's ledger, `PDA(["ledger", runner])`; made here the first time.
    #[account(mut, seeds = [LEDGER_SEED, runner.key().as_ref()], bump)]
    pub ledger: UncheckedAccount<'info>,

    /// CHECK: the order's mint, checked against the terms and the store.
    pub mint: UncheckedAccount<'info>,
    /// CHECK: the mint's OFT store, read in the handler.
    pub oft_store: UncheckedAccount<'info>,
    /// CHECK: the mint's mint authority: the store itself, or the multisig the store signs for
    /// (a launch from before the reserve was dropped) -- or, a lockbox's mint having none, the
    /// store's TvlMark (`check_store`). Checked against the mint in the handler.
    pub mint_authority: UncheckedAccount<'info>,
    pub venue: Venue<'info>,
    /// CHECK: pinned.
    #[account(address = WSOL @ CheapestError::WrongMint)]
    pub wsol_mint: UncheckedAccount<'info>,
    /// CHECK: pinned.
    #[account(address = TOKEN_2022_ID @ CheapestError::WrongProgram)]
    pub token_2022_program: UncheckedAccount<'info>,
    /// CHECK: pinned.
    #[account(address = TOKEN_ID @ CheapestError::WrongProgram)]
    pub token_program: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
    /// CHECK: pinned.
    #[account(address = sysvar_instructions::ID @ CheapestError::WrongProgram)]
    pub instructions: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct FinishSend<'info> {
    /// CHECK: read only; `buy` and `return_composed` check it is the account their send left.
    pub runner_token: UncheckedAccount<'info>,
    #[account(mut)]
    pub runner: Signer<'info>,
    #[account(mut, seeds = [LEDGER_SEED, runner.key().as_ref()], bump = ledger.bump)]
    pub ledger: Account<'info, Ledger>,
    /// CHECK: the box the ledger names (checked in the handler), or anything when it names none.
    #[account(mut)]
    pub user_box: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Refund<'info> {
    /// Whoever sends it, paid the order's runner fee for it.
    #[account(mut)]
    pub runner: Signer<'info>,
    /// CHECK: the order's address, derived from the terms in the handler.
    #[account(mut)]
    pub order: UncheckedAccount<'info>,
    /// CHECK: the user's box, derived from the terms in the handler.
    #[account(mut)]
    pub user_box: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Compose<'info> {
    #[account(mut)]
    pub runner: Signer<'info>,
    /// CHECK: the composer: the address the tokens were sent to, which signs the clear.
    #[account(seeds = [COMPOSER_SEED], bump)]
    pub composer: UncheckedAccount<'info>,
    /// CHECK: the endpoint's record of the call; the endpoint checks it against the call.
    #[account(mut)]
    pub compose_message: UncheckedAccount<'info>,
    /// CHECK: the endpoint's event authority; the endpoint checks it.
    pub endpoint_event_authority: UncheckedAccount<'info>,
    /// CHECK: pinned.
    #[account(address = LZ_ENDPOINT_ID @ CheapestError::WrongProgram)]
    pub endpoint_program: UncheckedAccount<'info>,
    /// CHECK: the store that queued the call: `params.from`, read in the handler.
    pub oft_store: UncheckedAccount<'info>,
    /// CHECK: the mint's mint authority: the store itself, or the multisig the store signs for
    /// (a launch from before the reserve was dropped) -- or, a lockbox's mint having none, the
    /// store's TvlMark (`check_store`). Checked against the mint in the handler.
    pub mint_authority: UncheckedAccount<'info>,
    /// CHECK: the store's mint.
    pub mint: UncheckedAccount<'info>,
    /// CHECK: the composer's token account for the mint, which the arrival minted into.
    #[account(mut)]
    pub composer_token: UncheckedAccount<'info>,
    /// CHECK: the seller's box, derived from the call in the handler.
    #[account(mut)]
    pub user_box: UncheckedAccount<'info>,
    /// CHECK: `PDA(["wsol", runner])`, made and closed inside the instruction.
    #[account(mut, seeds = [TEMP_SEED, runner.key().as_ref()], bump)]
    pub temp: UncheckedAccount<'info>,
    /// CHECK: the runner's token account for the mint, used only on the way home.
    #[account(mut)]
    pub runner_token: UncheckedAccount<'info>,
    /// CHECK: the runner's ledger, `PDA(["ledger", runner])`; made here the first time.
    #[account(mut, seeds = [LEDGER_SEED, runner.key().as_ref()], bump)]
    pub ledger: UncheckedAccount<'info>,

    pub venue: Venue<'info>,
    /// CHECK: pinned.
    #[account(address = WSOL @ CheapestError::WrongMint)]
    pub wsol_mint: UncheckedAccount<'info>,
    /// CHECK: pinned.
    #[account(address = TOKEN_2022_ID @ CheapestError::WrongProgram)]
    pub token_2022_program: UncheckedAccount<'info>,
    /// CHECK: pinned.
    #[account(address = TOKEN_ID @ CheapestError::WrongProgram)]
    pub token_program: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
    /// CHECK: pinned.
    #[account(address = sysvar_instructions::ID @ CheapestError::WrongProgram)]
    pub instructions: UncheckedAccount<'info>,
}

/// `release_expired_v3`'s accounts.
#[derive(Accounts)]
pub struct ReleaseV3<'info> {
    /// Anyone; pays the transaction.
    pub caller: Signer<'info>,
    /// CHECK: the composer, which owns the tokens and signs the approval.
    #[account(seeds = [COMPOSER_SEED], bump)]
    pub composer: UncheckedAccount<'info>,
    /// CHECK: the guid's GapReceipt, checked in the handler (`read_receipt`). Writable since L4:
    /// the release names the seller's box as its refund_to (`set_gap_receipt_refund`).
    #[account(mut)]
    pub gap_receipt: UncheckedAccount<'info>,
    /// CHECK: the store that made the receipt: `params.from`, checked in the handler.
    pub oft_store: UncheckedAccount<'info>,
    /// CHECK: the mint's mint authority, as for `Compose` (`check_store`).
    pub mint_authority: UncheckedAccount<'info>,
    /// CHECK: the store's mint.
    pub mint: UncheckedAccount<'info>,
    /// CHECK: the composer's token account for the mint.
    #[account(mut)]
    pub composer_token: UncheckedAccount<'info>,
    /// CHECK: `PDA(["GapReturn", guid])` under the OFT program, checked in the handler.
    pub return_delegate: UncheckedAccount<'info>,
    /// CHECK: pinned.
    #[account(address = TOKEN_2022_ID @ CheapestError::WrongProgram)]
    pub token_2022_program: UncheckedAccount<'info>,
    /// CHECK: L4: the OFT program, for the `set_gap_receipt_refund` CPI (pinned).
    #[account(address = OFT_PROGRAM_ID @ CheapestError::WrongProgram)]
    pub oft_program: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct PayOut<'info> {
    #[account(mut)]
    pub runner: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
    /// CHECK: the box, derived from the user and chain in the handler.
    #[account(mut)]
    pub user_box: UncheckedAccount<'info>,
    /// CHECK: the Relay deposit address; it is what the payout signer signed.
    #[account(mut)]
    pub deposit: UncheckedAccount<'info>,
    /// CHECK: the box's payout count, `PDA(["seq", box])`; made by the box's first payout.
    #[account(mut)]
    pub payout_seq: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

// ================================================================================== events

#[event]
pub struct PayoutSignerSet {
    pub payout_signer: [u8; 20],
}

#[event]
pub struct OrderBought {
    pub order: Pubkey,
    pub mint: Pubkey,
    pub user: [u8; 20],
    pub dst_eid: u32,
    pub spent: u64,
    pub bought: u64,
    pub lz_fee: u64,
    pub runner_fee: u64,
    pub to_box: u64,
    /// What was sent to the user (at most a fiftieth below `bought`, never below their minimum).
    pub sent: u64,
    /// What the rest of `bought` was sold back for, into the box.
    pub leftover_sol: u64,
}

#[event]
pub struct OrderRefunded {
    pub order: Pubkey,
    pub user: [u8; 20],
    pub dst_eid: u32,
    pub lamports: u64,
}

#[event]
pub struct ComposeSold {
    pub guid: [u8; 32],
    pub mint: Pubkey,
    pub src_eid: u32,
    pub seller: [u8; 20],
    pub amount: u64,
    pub proceeds: u64,
    pub runner_fee: u64,
}

/// A v3 call that cannot be sold, released for the OFT program to send home whole to `to`
/// (the receipt's compose_from) on `src_eid`. `reason` as `ComposeReturned`'s.
#[event]
pub struct ComposeReleased {
    pub guid: [u8; 32],
    pub mint: Pubkey,
    pub src_eid: u32,
    pub to: [u8; 32],
    pub amount: u64,
    pub reason: u8,
}

/// `reason`: 1 past the deadline, 2 a call that cannot be read or a sender that is not an EVM
/// address.
#[event]
pub struct ComposeReturned {
    pub guid: [u8; 32],
    pub mint: Pubkey,
    pub src_eid: u32,
    pub to: [u8; 32],
    pub amount: u64,
    pub slice_in: u64,
    pub slice_out: u64,
    pub sent_home: u64,
    pub home_fee: u64,
    pub runner_fee: u64,
    pub to_box: u64,
    pub reason: u8,
}

#[event]
pub struct PaidOut {
    pub user_box: Pubkey,
    pub user: [u8; 20],
    pub eid: u32,
    pub deposit: Pubkey,
    pub lamports: u64,
    pub runner_fee: u64,
    pub seq: u64,
}

// ================================================================================== errors

#[error_code]
pub enum CheapestError {
    #[msg("only the admin may do this")]
    NotAdmin,
    #[msg("the payout signer cannot be zero")]
    ZeroSigner,
    #[msg("a pinned program or sysvar is not the one given")]
    WrongProgram,
    #[msg("not the mint this needs")]
    WrongMint,
    #[msg("the account is not the address these terms derive")]
    WrongAddress,
    #[msg("the order's deadline has passed")]
    PastDeadline,
    #[msg("the order's deadline has not passed")]
    NotPastDeadline,
    #[msg("the order does not hold what it was quoted")]
    OrderNotFunded,
    #[msg("nothing to refund")]
    NothingToRefund,
    #[msg("LayerZero's fee is above the order's cap")]
    FeeAboveCap,
    FeeAboveCharge,
    LeftoverUnplaceable,
    #[msg("the amount does not cover the fees")]
    AmountBelowFees,
    #[msg("the order's terms are not well formed")]
    BadTerms,
    #[msg("not a Pangea token's OFT store, or not this mint's")]
    NotOurStore,
    #[msg("not the launch's pool")]
    NotOurPool,
    #[msg("not a token account of the right mint and owner")]
    BadTokenAccount,
    #[msg("the instruction after this one is not the OFT send it must be")]
    SendNotFollowing,
    #[msg("the instruction after the send is not the finish it must be")]
    FinishNotFollowing,
    #[msg("tokens were left behind in the runner's account")]
    TokensLeftBehind,
    #[msg("the swap returned less than its minimum")]
    BelowMinimum,
    #[msg("the compose message cannot be read")]
    BadComposeMessage,
    #[msg("the call cannot be read: the sale must go home")]
    MalformedSale,
    #[msg("the sale is still open: it may not go home yet")]
    SaleStillOpen,
    #[msg("the slice is not the size it may be")]
    BadSlice,
    #[msg("the payout signature is not the payout signer's")]
    BadSignature,
    #[msg("the payout signature has expired or lives too long")]
    BadExpiry,
    #[msg("the runner's fee for a payout is above the most it may be")]
    RunnerFeeTooHigh,
    #[msg("the box holds too little to pay out")]
    BoxTooSmall,
    #[msg("a temporary account is in the way")]
    TempInUse,
    #[msg("arithmetic out of range")]
    Overflow,
    #[msg("this instruction must be sent on its own, not called by another program")]
    NotTopLevel,
    #[msg("the store is not the one that mints this token")]
    NotTheMintsStore,
    #[msg("the box does not hold what the payout was signed for")]
    BoxChanged,
    #[msg("the swap left some of what it was given unspent")]
    PartialSwap,
    #[msg("the slice sells below the floor its call allows")]
    SliceBelowFloor,
    #[msg("a v3 token: Solana as the far chain is off (its OFT send refuses a pool touched earlier in the transaction); only sell_composed runs")]
    V3SolanaFarOff,
    #[msg("not the v3 store's GapReceipt for this guid and composer")]
    BadGapReceipt,
    #[msg("not a v3 store: its sale goes home by return_composed")]
    NotV3Store,
    #[msg("not the OFT program's GapGlobal (Q59: the per-chain cap on the fee home is read from it)")]
    BadGapGlobal,
}

// ================================================================================== helpers

/// A token account's mint, owner and balance, held to `program`'s ownership and, when given, to a
/// mint and an owner.
fn token_account(account: &AccountInfo, mint: Option<&Pubkey>, owner: Option<&Pubkey>) -> Result<(Pubkey, Pubkey, u64)> {
    require!(*account.owner == TOKEN_2022_ID || *account.owner == TOKEN_ID, CheapestError::BadTokenAccount);
    let data = account.try_borrow_data()?;
    let (m, o, amount) = read_token_account(&data).ok_or(CheapestError::BadTokenAccount)?;
    if let Some(want) = mint {
        require_keys_eq!(m, *want, CheapestError::BadTokenAccount);
    }
    if let Some(want) = owner {
        require_keys_eq!(o, *want, CheapestError::BadTokenAccount);
    }
    Ok((m, o, amount))
}

/// A Pangea token's OFT store for `mint`: owned by the OFT program, of the store's kind, holding
/// this mint, with the splitter's AUTHORITY as its admin (the admin every launch gives its store).
///
/// And the store that MINTS it: the mint's authority, or one of the signers of the Token-2022
/// multisig that is, beside the splitter's AUTHORITY (an armed launch from before the reserve was
/// dropped). Or, for a mint with NO authority, the launch's LOCKBOX (SUPPLY_TOTAL since
/// 2026-10-24): an Adapter store whose `TvlMark`, `PDA(["TvlMark", store])` under the OFT program,
/// given in the mint authority's place, names the splitter's AUTHORITY as the admin that SIGNED its
/// `init_tvl`. AUTHORITY signs `init_tvl` in exactly one place, the launch's own instruction, for
/// the store that launch created -- so it proves the store is the launch's as the mint authority
/// does for the others. (The store's CURRENT admin proves nothing here: anybody can make an Adapter
/// store, declare its escrow locked as its admin, then hand the admin to AUTHORITY; its mark then
/// names the attacker, and is refused. Audit round 1, 2026-10-24.) Anybody can make another OFT store for a mint in the OFT program and hand its admin to
/// AUTHORITY afterwards, with peers of their own choosing; only the launch's own store is the
/// mint's authority, which nobody can change.
/// The seed of a lockbox store's one-shot `init_tvl` record under the OFT program (solana/oft).
pub const TVL_MARK_SEED: &[u8] = b"TvlMark";

fn check_store(store: &AccountInfo, mint: &AccountInfo, mint_authority: &AccountInfo) -> Result<()> {
    require_keys_eq!(*store.owner, OFT_PROGRAM_ID, CheapestError::NotOurStore);
    let view = read_store(&store.try_borrow_data()?).ok_or(CheapestError::NotOurStore)?;
    require_keys_eq!(view.token_mint, mint.key(), CheapestError::NotOurStore);
    require_keys_eq!(view.admin, splitter_authority(), CheapestError::NotOurStore);
    require_keys_eq!(*mint.owner, TOKEN_2022_ID, CheapestError::WrongMint);
    let Some(authority) = read_mint_authority(&mint.try_borrow_data()?) else {
        require!(view.oft_type == crate::parse::OFT_TYPE_ADAPTER, CheapestError::NotTheMintsStore);
        let mark = Pubkey::find_program_address(&[TVL_MARK_SEED, store.key().as_ref()], &OFT_PROGRAM_ID).0;
        require_keys_eq!(mint_authority.key(), mark, CheapestError::NotTheMintsStore);
        require_keys_eq!(*mint_authority.owner, OFT_PROGRAM_ID, CheapestError::NotTheMintsStore);
        let signed_by = crate::parse::read_tvl_mark(&mint_authority.try_borrow_data()?).ok_or(CheapestError::NotTheMintsStore)?;
        require_keys_eq!(signed_by, splitter_authority(), CheapestError::NotTheMintsStore);
        return Ok(());
    };
    require_keys_eq!(mint_authority.key(), authority, CheapestError::NotTheMintsStore);
    if authority == store.key() {
        return Ok(());
    }
    require_keys_eq!(*mint_authority.owner, TOKEN_2022_ID, CheapestError::NotTheMintsStore);
    let signers = read_multisig(&mint_authority.try_borrow_data()?).ok_or(CheapestError::NotTheMintsStore)?;
    require!(signers.contains(&store.key()) && signers.contains(&splitter_authority()), CheapestError::NotTheMintsStore);
    Ok(())
}

/// This instruction is the transaction's own, not a call from another program: only then are the
/// instructions after it in the transaction the ones that run after it.
fn require_top_level(sysvar: &AccountInfo) -> Result<()> {
    require!(get_stack_height() == TRANSACTION_LEVEL_STACK_HEIGHT, CheapestError::NotTopLevel);
    let here = sysvar_instructions::load_current_index_checked(sysvar)? as usize;
    let me = sysvar_instructions::load_instruction_at_checked(here, sysvar)?;
    require_keys_eq!(me.program_id, crate::ID, CheapestError::NotTopLevel);
    Ok(())
}

fn check_pool(venue: &Venue, mint: &Pubkey) -> Result<()> {
    require_keys_eq!(venue.pool.key(), pool_address(mint), CheapestError::NotOurPool);
    require_keys_eq!(*venue.pool.owner, CP_AMM_ID, CheapestError::NotOurPool);
    Ok(())
}

/// Make `PDA(["wsol", runner])` a wrapped-SOL token account owned by `owner`, with `fund` lamports
/// counted into it from `funder` (signed by `funder_seeds`). The runner pays its rent and has it
/// back when it is closed. Lamports somebody sent to the address beforehand are tolerated: they
/// end in the account's balance and go to the runner when it is closed.
#[allow(clippy::too_many_arguments)]
fn open_temp<'info>(
    runner: &AccountInfo<'info>,
    temp: &AccountInfo<'info>,
    temp_bump: u8,
    owner: &Pubkey,
    fund: Option<(&AccountInfo<'info>, &[&[u8]], u64)>,
    wsol: &AccountInfo<'info>,
    token_program: &AccountInfo<'info>,
    system: &AccountInfo<'info>,
) -> Result<()> {
    require_keys_eq!(*temp.owner, System::id(), CheapestError::TempInUse);
    require!(temp.data_is_empty(), CheapestError::TempInUse);
    let runner_key = runner.key();
    let seeds: &[&[u8]] = &[TEMP_SEED, runner_key.as_ref(), &[temp_bump]];
    let rent = Rent::get()?.minimum_balance(TOKEN_ACCOUNT_LEN);
    let have = temp.lamports();
    if have < rent {
        invoke(&system_instruction::transfer(&runner_key, temp.key, rent - have), &[runner.clone(), temp.clone(), system.clone()])?;
    }
    invoke_signed(&system_instruction::allocate(temp.key, TOKEN_ACCOUNT_LEN as u64), &[temp.clone(), system.clone()], &[seeds])?;
    invoke_signed(&system_instruction::assign(temp.key, &TOKEN_ID), &[temp.clone(), system.clone()], &[seeds])?;
    if let Some((from, from_seeds, lamports)) = fund {
        if lamports > 0 {
            invoke_signed(&system_instruction::transfer(from.key, temp.key, lamports), &[from.clone(), temp.clone(), system.clone()], &[from_seeds])?;
        }
    }
    let init = anchor_spl::token::spl_token::instruction::initialize_account3(&TOKEN_ID, temp.key, &WSOL, owner)?;
    invoke(&init, &[temp.clone(), wsol.clone(), token_program.clone()])?;
    Ok(())
}

/// Close the temporary account: everything in it, rent and wrapped SOL alike, to the runner.
fn close_temp<'info>(temp: &AccountInfo<'info>, runner: &AccountInfo<'info>, owner: &AccountInfo<'info>, owner_seeds: &[&[u8]], token_program: &AccountInfo<'info>) -> Result<()> {
    let ix = anchor_spl::token::spl_token::instruction::close_account(&TOKEN_ID, temp.key, runner.key, owner.key, &[])?;
    invoke_signed(&ix, &[temp.clone(), runner.clone(), owner.clone(), token_program.clone()], &[owner_seeds])?;
    Ok(())
}

/// One exact-input swap through the launch's pool, signed by `signer`.
#[allow(clippy::too_many_arguments)]
fn swap<'info>(
    venue: &Venue<'info>,
    input: &AccountInfo<'info>,
    output: &AccountInfo<'info>,
    mint: &AccountInfo<'info>,
    wsol: &AccountInfo<'info>,
    signer: &AccountInfo<'info>,
    signer_seeds: &[&[u8]],
    token_2022: &AccountInfo<'info>,
    token: &AccountInfo<'info>,
    amount_in: u64,
    minimum_out: u64,
) -> Result<()> {
    let ro = |k: &Pubkey| AccountMeta::new_readonly(*k, false);
    let rw = |k: &Pubkey| AccountMeta::new(*k, false);
    let mut data = CP_AMM_SWAP_DISCRIMINATOR.to_vec();
    data.extend_from_slice(&amount_in.to_le_bytes());
    data.extend_from_slice(&minimum_out.to_le_bytes());
    let ix = Instruction {
        program_id: CP_AMM_ID,
        accounts: vec![
            ro(venue.pool_authority.key),
            rw(venue.pool.key),
            rw(input.key),
            rw(output.key),
            rw(venue.token_a_vault.key),
            rw(venue.token_b_vault.key),
            ro(mint.key),
            ro(wsol.key),
            AccountMeta::new_readonly(*signer.key, true),
            ro(&TOKEN_2022_ID),
            ro(&TOKEN_ID),
            ro(&CP_AMM_ID), // no referral: Anchor spells "none" as the program's own id
            ro(venue.cp_amm_event_authority.key),
            ro(&CP_AMM_ID),
        ],
        data,
    };
    // No seeds when the signer signs the transaction itself.
    let held = [signer_seeds];
    let seeds: &[&[&[u8]]] = if signer_seeds.is_empty() { &[] } else { &held };
    invoke_signed(
        &ix,
        &[
            venue.pool_authority.to_account_info(),
            venue.pool.to_account_info(),
            input.clone(),
            output.clone(),
            venue.token_a_vault.to_account_info(),
            venue.token_b_vault.to_account_info(),
            mint.clone(),
            wsol.clone(),
            signer.clone(),
            token_2022.clone(),
            token.clone(),
            venue.cp_amm_event_authority.to_account_info(),
            venue.cp_amm_program.to_account_info(),
        ],
        seeds,
    )?;
    Ok(())
}

/// The composer's balance of the call's token.
fn composer_balance(account: &AccountInfo) -> Result<u64> {
    Ok(token_account(account, None, None)?.2)
}

/// The balance of the wrapped-SOL temporary account.
fn temp_balance(temp: &AccountInfo) -> Result<u64> {
    Ok(token_account(temp, Some(&WSOL), None)?.2)
}

/// Lamports a user is owed that are too few to sit in an empty box on their own (a system account
/// must hold its rent-exempt minimum or nothing) go to the runner instead. Everything else goes to
/// the box. Returns what went to the box.
fn place_from_runner<'info>(amount: u64, runner: &AccountInfo<'info>, user_box: &AccountInfo<'info>, system: &AccountInfo<'info>) -> Result<u64> {
    if amount == 0 {
        return Ok(0);
    }
    let floor = Rent::get()?.minimum_balance(0);
    if user_box.lamports().saturating_add(amount) < floor {
        return Ok(0);
    }
    invoke(&system_instruction::transfer(runner.key, user_box.key, amount), &[runner.clone(), user_box.clone(), system.clone()])?;
    Ok(amount)
}

/// The instructions at `at` in this transaction, or an error naming what was expected there.
fn instruction_at(sysvar: &AccountInfo, at: usize, missing: CheapestError) -> Result<Instruction> {
    sysvar_instructions::load_instruction_at_checked(at, sysvar).map_err(|_| error!(missing))
}

/// The two instructions after the current one must be the OFT `send` described and this program's
/// `finish_send` over `runner_token` with `before`.
#[allow(clippy::too_many_arguments)]
fn require_send_and_finish(
    sysvar: &AccountInfo,
    runner: &Pubkey,
    ledger: &Pubkey,
    user_box: &Pubkey,
    runner_token: &Pubkey,
    store: &Pubkey,
    mint: &Pubkey,
    dst_eid: u32,
    to: &[u8; 32],
    amount: SendAmount,
    min_amount_ld: u64,
    native_fee: u64,
) -> Result<u64> {
    let here = sysvar_instructions::load_current_index_checked(sysvar)? as usize;
    let send = instruction_at(sysvar, here + 1, CheapestError::SendNotFollowing)?;
    let s = read_send_ix(&send, &OFT_PROGRAM_ID).ok_or(CheapestError::SendNotFollowing)?;
    require!(
        s.signer == *runner
            && s.signer_signs
            && s.store == *store
            && s.source == *runner_token
            && s.mint == *mint
            && s.params.dst_eid == dst_eid
            && s.params.to == *to
            && amount.allows(s.params.amount_ld)
            && s.params.min_amount_ld >= min_amount_ld
            && s.params.native_fee == native_fee
            && s.params.lz_token_fee == 0,
        CheapestError::SendNotFollowing
    );
    let finish = instruction_at(sysvar, here + 2, CheapestError::FinishNotFollowing)?;
    let want = instruction::FinishSend::DISCRIMINATOR.to_vec();
    require!(
        finish.program_id == crate::ID
            && finish.data.len() == 16
            && finish.data[..8] == want[..]
            && finish.accounts.len() == 5
            && finish.accounts[0].pubkey == *runner_token
            && finish.accounts[1].pubkey == *runner
            && finish.accounts[2].pubkey == *ledger
            && finish.accounts[3].pubkey == *user_box,
        CheapestError::FinishNotFollowing
    );
    Ok(s.params.amount_ld)
}

/// What the send after a buy or a way home must carry.
#[derive(Clone, Copy)]
enum SendAmount {
    /// Exactly this (a way home: what is left of the call).
    Exact(u64),
    /// Between `least` and `most` (a buy: what was bought, less at most a fiftieth of it).
    Within { least: u64, most: u64 },
}

impl SendAmount {
    fn allows(&self, amount: u64) -> bool {
        match *self {
            SendAmount::Exact(x) => amount == x,
            SendAmount::Within { least, most } => amount >= least && amount <= most,
        }
    }
}

fn finish_handler(ctx: Context<FinishSend>, before: u64) -> Result<()> {
    let a = &ctx.accounts;
    let (_, _, now) = token_account(&a.runner_token, None, None)?;
    // Armed: the balance the instruction before the send read on chain; the argument is ignored.
    let before = if a.ledger.armed { a.ledger.before } else { before };
    require!(now < before.saturating_add(DUST), CheapestError::TokensLeftBehind);
    // A ledger is armed only by the instruction two before this one, which checked this is its
    // finish; a finish of nothing is a check of the tokens alone.
    if !a.ledger.armed {
        return Ok(());
    }
    // What the send cost the runner, measured: LayerZero charges its quote and no more, whatever
    // ceiling the runner named. What it was paid above that is the user's.
    let spent = a.ledger.runner_after.saturating_sub(a.runner.lamports());
    let over = a.ledger.fee.saturating_sub(spent);
    let target = a.ledger.user_box;
    let ledger = &mut ctx.accounts.ledger;
    ledger.armed = false;
    let fee = ledger.fee;
    // The runner names LayerZero's quote, not the order's cap: a ceiling above what is charged by
    // more than a fee's slack (its quote moving between simulation and landing) is refused, so a
    // swap is never cut to pad the box.
    require!(over <= UNPLACED_FEE_SLACK.max(fee / UNPLACED_FEE_DIVISOR), CheapestError::FeeAboveCharge);
    // The slack itself goes to the box when the box can hold it; otherwise it stays with the runner.
    if over > 0 && target != Pubkey::default() {
        require_keys_eq!(ctx.accounts.user_box.key(), target, CheapestError::WrongAddress);
        let floor = Rent::get()?.minimum_balance(0);
        if ctx.accounts.user_box.lamports().saturating_add(over) >= floor {
            invoke(
                &system_instruction::transfer(ctx.accounts.runner.key, &target, over),
                &[ctx.accounts.runner.to_account_info(), ctx.accounts.user_box.to_account_info(), ctx.accounts.system_program.to_account_info()],
            )?;
        }
    }
    Ok(())
}

/// Arm the runner's ledger for the finish two instructions on: where the runner stands now, what
/// it was paid for LayerZero's fee, and the box the rest goes to (default: nowhere).
#[allow(clippy::too_many_arguments)]
fn arm_ledger<'info>(ledger: &AccountInfo<'info>, ledger_bump: u8, runner: &AccountInfo<'info>, system: &AccountInfo<'info>, fee: u64, before: u64, user_box: Pubkey) -> Result<()> {
    let space = 8 + Ledger::INIT_SPACE;
    let runner_key = runner.key();
    let seeds: &[&[u8]] = &[LEDGER_SEED, runner_key.as_ref(), &[ledger_bump]];
    if *ledger.owner != crate::ID {
        let rent = Rent::get()?.minimum_balance(space);
        let have = ledger.lamports();
        if have < rent {
            invoke(&system_instruction::transfer(&runner_key, ledger.key, rent - have), &[runner.clone(), ledger.clone(), system.clone()])?;
        }
        invoke_signed(&system_instruction::allocate(ledger.key, space as u64), &[ledger.clone(), system.clone()], &[seeds])?;
        invoke_signed(&system_instruction::assign(ledger.key, &crate::ID), &[ledger.clone(), system.clone()], &[seeds])?;
    }
    // Measured after the ledger's own rent: what the runner stands at as the send begins.
    let l = Ledger { runner_after: runner.lamports(), fee, before, user_box, armed: true, bump: ledger_bump };
    let mut out: Vec<u8> = Ledger::DISCRIMINATOR.to_vec();
    l.serialize(&mut out)?;
    ledger.try_borrow_mut_data()?[..out.len()].copy_from_slice(&out);
    Ok(())
}

// ================================================================================== buy

fn buy_handler<'info>(ctx: Context<'_, '_, 'info, 'info, Buy<'info>>, terms: OrderTerms, lz_fee: u64, leftover_price: u64) -> Result<()> {
    let a = &ctx.accounts;
    let (order, order_bump) = order_address(&terms);
    require_keys_eq!(a.order.key(), order, CheapestError::WrongAddress);
    let (user_box, _) = box_address(terms.dst_eid, &terms.user);
    require_keys_eq!(a.user_box.key(), user_box, CheapestError::WrongAddress);
    require!(terms.user != [0u8; 20] && terms.dst_eid != SOLANA_EID && terms.min_out > 0, CheapestError::BadTerms);
    let now = Clock::get()?.unix_timestamp;
    require!(now <= terms.deadline && terms.deadline <= now.saturating_add(MAX_HORIZON), CheapestError::PastDeadline);
    require!(lz_fee <= terms.lz_fee_cap, CheapestError::FeeAboveCap);
    let spend = terms
        .amount
        .checked_sub(lz_fee)
        .and_then(|v| v.checked_sub(terms.runner_fee))
        .filter(|v| *v > 0)
        .ok_or(CheapestError::AmountBelowFees)?;
    let held = a.order.lamports();
    require!(held >= terms.amount, CheapestError::OrderNotFunded);
    require_keys_eq!(*a.order.owner, System::id(), CheapestError::WrongAddress);

    require_top_level(&a.instructions)?;
    require_keys_eq!(a.mint.key(), terms.mint, CheapestError::WrongMint);
    check_store(&a.oft_store, &a.mint, &a.mint_authority)?;
    // A v3 token's send cannot follow the swap (see "Pangea v3 tokens"): refused before anything.
    require!(!is_v3_store(&a.oft_store.try_borrow_data()?), CheapestError::V3SolanaFarOff);
    check_pool(&a.venue, &terms.mint)?;
    let (_, _, before) = token_account(&a.runner_token, Some(&terms.mint), Some(&a.runner.key()))?;
    require_keys_eq!(*a.runner_token.owner, TOKEN_2022_ID, CheapestError::BadTokenAccount);

    // Before anything moves: what must follow, with the amount that will be bought checked after.
    let order_hash = terms.hash();
    let order_seeds: &[&[u8]] = &[ORDER_SEED, &order_hash, &[order_bump]];

    let runner = a.runner.to_account_info();
    let temp = a.temp.to_account_info();
    let order_ai = a.order.to_account_info();
    let token_program = a.token_program.to_account_info();
    let system = a.system_program.to_account_info();
    let wsol = a.wsol_mint.to_account_info();
    open_temp(&runner, &temp, ctx.bumps.temp, &order, Some((&order_ai, order_seeds, spend)), &wsol, &token_program, &system)?;
    let funded = temp_balance(&temp)?;
    swap(
        &a.venue,
        &temp,
        &a.runner_token.to_account_info(),
        &a.mint.to_account_info(),
        &wsol,
        &order_ai,
        order_seeds,
        &a.token_2022_program.to_account_info(),
        &token_program,
        spend,
        terms.min_out,
    )?;
    // All of the order's SOL was spent: what the temporary account still holds is what somebody
    // sent its address beforehand, never the user's.
    require!(funded.checked_sub(temp_balance(&temp)?) == Some(spend), CheapestError::PartialSwap);
    let (_, _, after) = token_account(&a.runner_token, None, None)?;
    let bought = after.checked_sub(before).ok_or(CheapestError::Overflow)?;
    require!(bought >= terms.min_out, CheapestError::BelowMinimum);

    let sent = require_send_and_finish(
        &a.instructions,
        &a.runner.key(),
        &a.ledger.key(),
        &a.user_box.key(),
        &a.runner_token.key(),
        &a.oft_store.key(),
        &terms.mint,
        terms.dst_eid,
        &left_pad(&terms.user),
        // What is sent may fall short of what was bought by at most a fiftieth, and never below the
        // user's minimum: the pool may move between the runner's quote and its landing.
        SendAmount::Within { least: (bought - bought / LEFTOVER_DIVISOR).max(terms.min_out), most: bought },
        terms.min_out,
        lz_fee,
    )?;

    // What was bought above what is sent: sold back at once, into the order, so it goes to the box
    // with the rest -- no token stays with the runner. Nothing runs between the buy and this sale
    // (one instruction), at no less than the runner's simulated price and half the price paid.
    let leftover = bought - sent;
    let mut leftover_sol = 0;
    // A leftover worth less than LEFTOVER_MIN_LAMPORTS at the price paid cannot be sold (a swap of
    // it fetches nothing): the runner keeps it, as it keeps the dust no bridge carries.
    let tiny = (leftover as u128) * (spend as u128) / (bought as u128) < LEFTOVER_MIN_LAMPORTS as u128;
    let kept = if tiny { leftover } else { 0 };
    if leftover == 0 || tiny {
        close_temp(&temp, &runner, &order_ai, order_seeds, &token_program)?;
    } else {
        let least_sim = u64::try_from((leftover as u128) * (leftover_price as u128) / 1_000_000_000u128).unwrap_or(u64::MAX);
        let least_paid = ((leftover as u128) * (spend as u128) / (bought as u128) / LEFTOVER_FLOOR_DIVISOR) as u64;
        let start = temp_balance(&temp)?;
        swap(
            &a.venue,
            &a.runner_token.to_account_info(),
            &temp,
            &a.mint.to_account_info(),
            &wsol,
            &runner,
            &[],
            &a.token_2022_program.to_account_info(),
            &token_program,
            leftover,
            least_sim.max(least_paid).max(1),
        )?;
        let (_, _, now_held) = token_account(&a.runner_token, None, None)?;
        require!(now_held == before + sent, CheapestError::PartialSwap);
        leftover_sol = temp_balance(&temp)?.checked_sub(start).ok_or(CheapestError::Overflow)?;
        close_temp(&temp, &runner, &order_ai, order_seeds, &token_program)?;
        // The temporary account was closed to the runner (its rent and the sale); the runner
        // hands the sale to the order.
        invoke(&system_instruction::transfer(runner.key, &order, leftover_sol), &[runner.clone(), order_ai.clone(), system.clone()])?;
    }

    // The runner: LayerZero's fee, which it pays in the send, and its own. Then the order is
    // emptied: what Relay delivered above the quote, and the leftover's sale, are the user's, in
    // their box.
    let pay = lz_fee + terms.runner_fee;
    if pay > 0 {
        invoke_signed(&system_instruction::transfer(&order, runner.key, pay), &[order_ai.clone(), runner.clone(), system.clone()], &[order_seeds])?;
    }
    let rest = order_ai.lamports();
    let mut to_box = 0;
    if rest > 0 {
        let floor = Rent::get()?.minimum_balance(0);
        let fits = a.user_box.lamports().saturating_add(rest) >= floor;
        // A leftover's sale is the runner's choice (what it names short of what was bought): it is
        // never one more crumb for the runner. When the box cannot hold it, the buy is refused and
        // the runner sends all it bought.
        require!(fits || leftover_sol == 0, CheapestError::LeftoverUnplaceable);
        let dest = if fits { a.user_box.to_account_info() } else { runner.clone() };
        invoke_signed(&system_instruction::transfer(&order, dest.key, rest), &[order_ai.clone(), dest.clone(), system.clone()], &[order_seeds])?;
        if dest.key == a.user_box.key {
            to_box = rest;
        }
    }
    arm_ledger(&a.ledger.to_account_info(), ctx.bumps.ledger, &runner, &system, lz_fee, before + kept, user_box)?;
    emit!(OrderBought {
        order,
        mint: terms.mint,
        user: terms.user,
        dst_eid: terms.dst_eid,
        spent: spend,
        bought,
        lz_fee,
        runner_fee: terms.runner_fee,
        to_box,
        sent,
        leftover_sol,
    });
    Ok(())
}

fn refund_handler(ctx: Context<Refund>, terms: OrderTerms) -> Result<()> {
    let a = &ctx.accounts;
    let (order, order_bump) = order_address(&terms);
    require_keys_eq!(a.order.key(), order, CheapestError::WrongAddress);
    let (user_box, _) = box_address(terms.dst_eid, &terms.user);
    require_keys_eq!(a.user_box.key(), user_box, CheapestError::WrongAddress);
    let now = Clock::get()?.unix_timestamp;
    require!(now > terms.deadline || terms.deadline > now.saturating_add(MAX_HORIZON), CheapestError::NotPastDeadline);
    require_keys_eq!(*a.order.owner, System::id(), CheapestError::WrongAddress);
    let held = a.order.lamports();
    require!(held > 0, CheapestError::NothingToRefund);
    let order_hash = terms.hash();
    let seeds: &[&[u8]] = &[ORDER_SEED, &order_hash, &[order_bump]];
    let system = a.system_program.to_account_info();
    // The refund's own runner is paid as the buy's would have been: the user's, as every fee.
    let fee = terms.runner_fee.min(held);
    if fee > 0 {
        invoke_signed(&system_instruction::transfer(&order, a.runner.key, fee), &[a.order.to_account_info(), a.runner.to_account_info(), system.clone()], &[seeds])?;
    }
    let mut lamports = held - fee;
    if lamports > 0 {
        // Too little to sit in an empty box on its own goes to the runner, as everywhere.
        let floor = Rent::get()?.minimum_balance(0);
        let dest = if a.user_box.lamports().saturating_add(lamports) >= floor { a.user_box.to_account_info() } else { a.runner.to_account_info() };
        invoke_signed(&system_instruction::transfer(&order, dest.key, lamports), &[a.order.to_account_info(), dest.clone(), system], &[seeds])?;
        if dest.key != a.user_box.key {
            lamports = 0;
        }
    }
    emit!(OrderRefunded { order, user: terms.user, dst_eid: terms.dst_eid, lamports });
    Ok(())
}

// ================================================================================== sale

/// What every compose instruction checks and does before deciding anything: the call is the one
/// the endpoint recorded for the composer, from a Pangea token's store, and is cleared -- once.
/// A call as taken: what arrived (for a v3 store, what was CREDITED after the gap fee) and the
/// call's payload, owned.
pub struct TakenCall {
    pub src_eid: u32,
    pub amount_ld: u64,
    pub from: [u8; 32],
    pub payload: Vec<u8>,
}

fn take_call<'info>(a: &Compose<'info>, rem: &[AccountInfo<'info>], params: &ComposeParams, composer_bump: u8) -> Result<TakenCall> {
    require_keys_eq!(a.oft_store.key(), params.from, CheapestError::NotOurStore);
    check_store(&a.oft_store, &a.mint, &a.mint_authority)?;
    check_pool(&a.venue, &a.mint.key())?;
    if is_v3_store(&a.oft_store.try_borrow_data()?) {
        return take_receipt(a, rem, params, composer_bump);
    }
    let c = read_composed(&params.message).ok_or(CheapestError::BadComposeMessage)?;
    require!(c.amount_ld > 0, CheapestError::BadComposeMessage);
    require_keys_eq!(a.composer_token.key(), composer_token_address(&a.mint.key()), CheapestError::BadTokenAccount);
    let (_, _, held) = token_account(&a.composer_token, Some(&a.mint.key()), Some(&a.composer.key()))?;
    require!(held >= c.amount_ld, CheapestError::BadComposeMessage);

    // The endpoint's `clear_compose`, signed by the composer: it holds the record to the hash of
    // exactly this message from exactly this store for exactly this composer, and marks it
    // received, so no call is ever taken twice.
    let mut data = CLEAR_COMPOSE_DISCRIMINATOR.to_vec();
    params.serialize(&mut data)?;
    let ix = Instruction {
        program_id: LZ_ENDPOINT_ID,
        accounts: vec![
            AccountMeta::new_readonly(a.composer.key(), true),
            AccountMeta::new(a.compose_message.key(), false),
            AccountMeta::new_readonly(a.endpoint_event_authority.key(), false),
            AccountMeta::new_readonly(LZ_ENDPOINT_ID, false),
        ],
        data,
    };
    invoke_signed(
        &ix,
        &[
            a.composer.to_account_info(),
            a.compose_message.to_account_info(),
            a.endpoint_event_authority.to_account_info(),
            a.endpoint_program.to_account_info(),
        ],
        &[&[COMPOSER_SEED, &[composer_bump]]],
    )?;
    Ok(TakenCall { src_eid: c.src_eid, amount_ld: c.amount_ld, from: c.from, payload: c.payload.to_vec() })
}

/// A v3 store's composed arrival (docs/v3-gap-fee-spec.md §4, §10.5): no compose record at the
/// endpoint, its `GapReceipt` instead, in the `compose_message` place. Held to: owned by the OFT
/// program, at `PDA(["GapReceipt", params.guid])` there, this store's, this guid's, sent to the
/// composer, and the composer holding at least what it says was CREDITED -- the amount acted on,
/// never the amount before the gap fee. Then closed, signed by the composer, in this same
/// instruction, so no call is taken twice (`params.message` is not used and must be empty).
/// `rem`: [0] the receipt's payer (its rent goes back there), [1] the OFT program, [2] the seller's box,
/// [3] the OFT's GapLatePrepay record (oft-lows3 L-2; see take_receipt).
/// A v3 store's receipt for `params.guid`, held to: owned by the OFT program, at the guid's PDA
/// there, this store's, this guid's, sent to the composer, crediting something; and the composer
/// holding at least what it credited. Returns the call and the receipt's payer.
/// `allow_zero` (the release only; OFT oft-lows L-2): a receipt crediting 0 -- the OFT writes one for
/// a zero-credit arrival only when the sender's prepay was at its GapPrepay PDA -- is released like
/// any call that can no longer be sold (approve 0, refund_to = the seller's box), so the OFT's
/// zero-amount return pays the sender's prepaid lamports to the box. It is never sold.
fn read_receipt(receipt: &AccountInfo, store: &Pubkey, composer: &Pubkey, mint: &Pubkey, composer_token: &AccountInfo, params: &ComposeParams, allow_zero: bool) -> Result<(TakenCall, Pubkey)> {
    require!(params.message.is_empty() && params.index == 0, CheapestError::BadGapReceipt);
    require_keys_eq!(*receipt.owner, OFT_PROGRAM_ID, CheapestError::BadGapReceipt);
    let (key, _) = Pubkey::find_program_address(&[GAP_RECEIPT_SEED, &params.guid], &OFT_PROGRAM_ID);
    require_keys_eq!(receipt.key(), key, CheapestError::BadGapReceipt);
    let (call, payer) = {
        let d = receipt.try_borrow_data()?;
        let r = read_gap_receipt(&d).ok_or(CheapestError::BadGapReceipt)?;
        require_keys_eq!(r.oft_store, *store, CheapestError::BadGapReceipt);
        require!(r.guid == params.guid, CheapestError::BadGapReceipt);
        require_keys_eq!(r.to, *composer, CheapestError::BadGapReceipt);
        require!(allow_zero || r.credited_ld > 0, CheapestError::BadComposeMessage);
        (TakenCall { src_eid: r.src_eid, amount_ld: r.credited_ld, from: r.compose_from, payload: r.compose_msg.to_vec() }, r.payer)
    };
    require_keys_eq!(composer_token.key(), composer_token_address(mint), CheapestError::BadTokenAccount);
    let (_, _, held) = token_account(composer_token, Some(mint), Some(composer))?;
    require!(held >= call.amount_ld, CheapestError::BadComposeMessage);
    Ok((call, payer))
}

fn take_receipt<'info>(a: &Compose<'info>, rem: &[AccountInfo<'info>], params: &ComposeParams, composer_bump: u8) -> Result<TakenCall> {
    let receipt = a.compose_message.to_account_info();
    let (call, payer) = read_receipt(&receipt, &a.oft_store.key(), &a.composer.key(), &a.mint.key(), &a.composer_token, params, false)?;

    let payer_info = rem.first().ok_or(CheapestError::BadGapReceipt)?;
    let oft = rem.get(1).ok_or(CheapestError::BadGapReceipt)?;
    require_keys_eq!(payer_info.key(), payer, CheapestError::BadGapReceipt);
    require_keys_eq!(oft.key(), OFT_PROGRAM_ID, CheapestError::WrongProgram);
    let mut accounts = vec![
        AccountMeta::new_readonly(a.composer.key(), true),
        AccountMeta::new(receipt.key(), false),
        AccountMeta::new(payer, false),
    ];
    let mut infos = vec![a.composer.to_account_info(), receipt, payer_info.clone()];
    // L4 (owner 2026-10-30): the sender's prepaid return lamports (receipt.prepaid) go home with the
    // proceeds: the close's refund account (its first remaining account) is the seller's box, the
    // Compose's `user_box` (no new account). A sender that is not an EVM address has no box: no
    // refund account is passed, and such a call is never sold (MalformedSale) anyway.
    // oft-lows3 (oft-lows2-r1 L-2, oft-q7 OPEN 1): with the box, the close names [the box, the OFT's
    // GapLatePrepay record, the system program] -- always, prepaid or not (a prepaid figure may be a
    // griefer's dust) -- so a LayerZero native drop of the sender's P that lands after the sale is
    // recorded for the box and `sweep_late_prepay` sends it there (before: stranded at the PDA for
    // good). `rem`: [0] the receipt's payer, [1] the OFT program, [2] the seller's box (the trailing
    // refund key of gap-v3.mjs `v3SellComposedKeys`; held to the Compose's `user_box`), [3] the
    // record, PDA(["GapLatePrepay", the receipt's GapPrepay PDA]) under the OFT program, whose
    // address the OFT's close checks (GapAccountMismatch); the system program is the Compose's.
    if let Some(seller) = evm_address(&call.from) {
        require_keys_eq!(a.user_box.key(), box_address(call.src_eid, &seller).0, CheapestError::WrongAddress);
        let named_box = rem.get(2).ok_or(CheapestError::BadGapReceipt)?;
        require_keys_eq!(named_box.key(), a.user_box.key(), CheapestError::WrongAddress);
        let record = rem.get(3).ok_or(CheapestError::BadGapReceipt)?;
        accounts.push(AccountMeta::new(a.user_box.key(), false));
        accounts.push(AccountMeta::new(record.key(), false));
        accounts.push(AccountMeta::new_readonly(a.system_program.key(), false));
        infos.push(a.user_box.to_account_info());
        infos.push(record.clone());
        infos.push(a.system_program.to_account_info());
    }
    infos.push(oft.clone());
    let ix = Instruction { program_id: OFT_PROGRAM_ID, accounts, data: CLOSE_GAP_RECEIPT_DISCRIMINATOR.to_vec() };
    invoke_signed(&ix, &infos, &[&[COMPOSER_SEED, &[composer_bump]]])?;
    Ok(call)
}

fn sell_handler<'info>(ctx: Context<'_, '_, 'info, 'info, Compose<'info>>, params: ComposeParams) -> Result<()> {
    let a = &ctx.accounts;
    let c = take_call(a, ctx.remaining_accounts, &params, ctx.bumps.composer)?;
    let p = read_sell_payload(&c.payload).ok_or(CheapestError::MalformedSale)?;
    let seller = evm_address(&c.from).ok_or(CheapestError::MalformedSale)?;
    require!(c.src_eid != SOLANA_EID, CheapestError::MalformedSale);
    let now = Clock::get()?.unix_timestamp;
    require!(now <= p.deadline && p.deadline <= now.saturating_add(MAX_HORIZON), CheapestError::PastDeadline);
    let (user_box, _) = box_address(c.src_eid, &seller);
    require_keys_eq!(a.user_box.key(), user_box, CheapestError::WrongAddress);

    let runner = a.runner.to_account_info();
    let temp = a.temp.to_account_info();
    let composer = a.composer.to_account_info();
    let token_program = a.token_program.to_account_info();
    let system = a.system_program.to_account_info();
    let wsol = a.wsol_mint.to_account_info();
    let composer_seeds: &[&[u8]] = &[COMPOSER_SEED, &[ctx.bumps.composer]];
    open_temp(&runner, &temp, ctx.bumps.temp, &composer.key(), None, &wsol, &token_program, &system)?;
    let start = temp_balance(&temp)?;
    let held = composer_balance(&a.composer_token)?;
    swap(
        &a.venue,
        &a.composer_token.to_account_info(),
        &temp,
        &a.mint.to_account_info(),
        &wsol,
        &composer,
        composer_seeds,
        &a.token_2022_program.to_account_info(),
        &token_program,
        c.amount_ld,
        p.min_sol_out,
    )?;
    // Exactly what arrived left the composer: nothing of this call stays behind with no record.
    require!(held.checked_sub(composer_balance(&a.composer_token)?) == Some(c.amount_ld), CheapestError::PartialSwap);
    let proceeds = temp_balance(&temp)?.checked_sub(start).ok_or(CheapestError::Overflow)?;
    require!(proceeds >= p.min_sol_out && proceeds > p.runner_fee, CheapestError::BelowMinimum);
    close_temp(&temp, &runner, &composer, composer_seeds, &token_program)?;
    // Everything but the runner's fee is the seller's, and it must reach the box: a sale whose
    // proceeds could not sit there is refused, so the call waits for the way home instead.
    let owed = proceeds - p.runner_fee;
    invoke(&system_instruction::transfer(runner.key, &user_box, owed), &[runner.clone(), a.user_box.to_account_info(), system.clone()])?;
    emit!(ComposeSold {
        guid: params.guid,
        mint: a.mint.key(),
        src_eid: c.src_eid,
        seller,
        amount: c.amount_ld,
        proceeds,
        runner_fee: p.runner_fee,
    });
    Ok(())
}

fn return_handler<'info>(ctx: Context<'_, '_, 'info, 'info, Compose<'info>>, params: ComposeParams, slice_in: u64, home_fee: u64) -> Result<()> {
    let a = &ctx.accounts;
    require_top_level(&a.instructions)?;
    // A v3 token's way home cannot be sent after the slice is sold (see "Pangea v3 tokens").
    require!(!is_v3_store(&a.oft_store.try_borrow_data()?), CheapestError::V3SolanaFarOff);
    let c = take_call(a, ctx.remaining_accounts, &params, ctx.bumps.composer)?;
    let payload = read_sell_payload(&c.payload);
    let seller = evm_address(&c.from);
    let readable = payload.is_some() && seller.is_some() && c.src_eid != SOLANA_EID;
    let now = Clock::get()?.unix_timestamp;
    let reason = match payload {
        _ if !readable => 2,
        Some(p) if now > p.deadline || p.deadline > now.saturating_add(MAX_HORIZON) => 1,
        _ => return err!(CheapestError::SaleStillOpen),
    };
    // A deadline beyond the horizon is no deadline at all: such a call is read as one that cannot
    // be read (its own grace would never end).
    let far = payload.map(|p| p.deadline > now.saturating_add(MAX_HORIZON)).unwrap_or(false);
    let unread = payload.is_none() || far;
    // The seller's own fees while the grace lasts; after it, the defaults, so that nothing in a call
    // can hold its tokens for good (the floor fades after it, below).
    let terms = payload.filter(|p| !far && now <= p.deadline.saturating_add(RETURN_GRACE));
    // Q59 (owner 2026-10-31): toward a KEYS-ONLY source chain (the OFT program's GapGlobal.dst_delivery
    // > 0, Ethereum at go-live) the caps are read per chain from that figure (`home_fee_cap_for`);
    // elsewhere, and without GapGlobal given, they are today's.
    let dst_delivery = keys_only_delivery(ctx.remaining_accounts, c.src_eid)?;
    let (runner_fee, cap) = match terms {
        // The seller's own cap, never above the grace's: a call cannot license a larger slice.
        Some(p) => (p.runner_fee, p.home_fee_cap.min(home_fee_cap_for(GRACE_HOME_FEE_CAP, dst_delivery))),
        None if !unread => (DEFAULT_RUNNER_FEE, home_fee_cap_for(GRACE_HOME_FEE_CAP, dst_delivery)),
        None => (DEFAULT_RUNNER_FEE, home_fee_cap_for(DEFAULT_HOME_FEE_CAP, dst_delivery)),
    };
    require!(home_fee <= cap, CheapestError::FeeAboveCap);
    require!(slice_in > 0 && slice_in <= c.amount_ld, CheapestError::BadSlice);
    // No floor without a call to read one from: then a small slice only, never the whole (a call
    // whose tenth cannot pay its way home waits in the composer: stuck while fees are high, not lost).
    if unread {
        require!(slice_in <= c.amount_ld / UNREADABLE_SLICE_DIVISOR, CheapestError::BadSlice);
    }
    let all = slice_in == c.amount_ld;
    // After the grace (the seller's own terms gone), a runner who crushes the price could sell most of
    // the amount for the fee home. So a readable call's slice above a tenth keeps the grace's floor
    // for good, as a whole sale does (owner decision 2026-10-26); only a tenth at most has the fading
    // one. A call whose tenth cannot pay its way home then goes at the grace's price, and waits only
    // while the price is below it.
    let held_floor = all || (!unread && terms.is_none() && slice_in > c.amount_ld / LATE_SLICE_DIVISOR);
    // The floor on the price, from the seller's minimum: out / slice_in >= (min_sol_out / amount) / 4.
    // A slice's floor holds while the grace lasts, then -- for a slice of a tenth at most -- halves for
    // each further RETURN_GRACE begun: every call that can be read has one, and that one only fades,
    // so a price that stays low delays the way home and does not lock the tokens (a larger slice keeps
    // the grace's floor, above). A WHOLE sale's floor never fades (owner decision
    // 2026-10-26): with it faded, a runner who moved the pool's price in the same transaction could
    // take a large call whole for no more than the whole-sale cap -- that cap limits what the runner
    // is paid, not what the seller loses. So a dust call whose price has fallen below the grace's
    // floor waits (in the composer, as a call whose way home cannot be paid waits), and goes when the
    // price comes back. (A minimum under RETURN_FLOOR_DIVISOR lamports names no floor at all.)
    let floor: Option<u128> = payload.filter(|_| !unread).map(|p| {
        let base = (p.min_sol_out as u128) * (slice_in as u128) / (c.amount_ld as u128) / RETURN_FLOOR_DIVISOR;
        if held_floor {
            return base;
        }
        let end = p.deadline.saturating_add(RETURN_GRACE);
        let halvings = if now <= end { 0 } else { now.saturating_sub(end).saturating_sub(1) / RETURN_GRACE + 1 };
        base.checked_shr(halvings.min(127) as u32).unwrap_or(0)
    });
    // Where a refund or a slice's surplus waits: the seller's box when the sender is an EVM
    // address, and otherwise nowhere -- the runner keeps such crumbs.
    let box_key = seller.map(|s| box_address(c.src_eid, &s).0);
    if box_key.is_none() {
        require!(home_fee <= NO_BOX_HOME_FEE_CAP, CheapestError::FeeAboveCap);
    }
    if let Some(k) = box_key {
        require_keys_eq!(a.user_box.key(), k, CheapestError::WrongAddress);
    }

    let runner = a.runner.to_account_info();
    let temp = a.temp.to_account_info();
    let composer = a.composer.to_account_info();
    let token_program = a.token_program.to_account_info();
    let system = a.system_program.to_account_info();
    let wsol = a.wsol_mint.to_account_info();
    let composer_seeds: &[&[u8]] = &[COMPOSER_SEED, &[ctx.bumps.composer]];
    let need = home_fee.checked_add(runner_fee).ok_or(CheapestError::Overflow)?;
    let ceiling = need.saturating_add(need / 10).saturating_add(SLICE_SLACK);

    open_temp(&runner, &temp, ctx.bumps.temp, &composer.key(), None, &wsol, &token_program, &system)?;
    let start = temp_balance(&temp)?;
    let held = composer_balance(&a.composer_token)?;
    swap(
        &a.venue,
        &a.composer_token.to_account_info(),
        &temp,
        &a.mint.to_account_info(),
        &wsol,
        &composer,
        composer_seeds,
        &a.token_2022_program.to_account_info(),
        &token_program,
        slice_in,
        if all { 0 } else { need },
    )?;
    require!(held.checked_sub(composer_balance(&a.composer_token)?) == Some(slice_in), CheapestError::PartialSwap);
    let out = temp_balance(&temp)?.checked_sub(start).ok_or(CheapestError::Overflow)?;
    close_temp(&temp, &runner, &composer, composer_seeds, &token_program)?;
    // Not sold below its floor (a quarter of the price the seller's minimum named; for a slice,
    // fading after the grace; for the whole, never). A runner cannot crush the price and sell the
    // tokens that should go home for nothing.
    if let Some(f) = floor {
        require!(out as u128 >= f, CheapestError::SliceBelowFloor);
    }

    let mut sent_home = 0;
    let mut finish_before = 0u64;
    let surplus;
    if all {
        // Everything sold: only when going home could not be paid for (the whole amount fetches no
        // more than the way home would cost), and then nothing goes home.
        // With no box to hold the rest, only what the runner is owed may be sold this way.
        // With a box, the rest of a small call waits there, read or not; with none, only what the
        // runner is owed may be sold this way.
        let whole_cap = if box_key.is_some() { runner_fee.saturating_add(cap.min(WHOLE_SALE_CAP)) } else { runner_fee };
        require!(home_fee == 0 && out <= whole_cap.saturating_add(SLICE_SLACK), CheapestError::BadSlice);
        surplus = out.saturating_sub(runner_fee);
    } else {
        require!(out >= need && out <= ceiling, CheapestError::BadSlice);
        surplus = out - need;
        sent_home = c.amount_ld - slice_in;
        let (_, _, before) = token_account(&a.runner_token, Some(&a.mint.key()), Some(&a.runner.key()))?;
        finish_before = before;
        require_keys_eq!(*a.runner_token.owner, TOKEN_2022_ID, CheapestError::BadTokenAccount);
        let decimals = {
            let d = a.mint.try_borrow_data()?;
            require!(d.len() >= 45 && *a.mint.owner == TOKEN_2022_ID, CheapestError::WrongMint);
            d[44]
        };
        let ix = anchor_spl::token_2022::spl_token_2022::instruction::transfer_checked(
            &TOKEN_2022_ID,
            &a.composer_token.key(),
            &a.mint.key(),
            &a.runner_token.key(),
            &composer.key(),
            &[],
            sent_home,
            decimals,
        )?;
        invoke_signed(
            &ix,
            &[
                a.composer_token.to_account_info(),
                a.mint.to_account_info(),
                a.runner_token.to_account_info(),
                composer.clone(),
                a.token_2022_program.to_account_info(),
            ],
            &[composer_seeds],
        )?;
        require!(held.checked_sub(composer_balance(&a.composer_token)?) == Some(c.amount_ld), CheapestError::PartialSwap);
        require_send_and_finish(
            &a.instructions,
            &a.runner.key(),
            &a.ledger.key(),
            &a.user_box.key(),
            &a.runner_token.key(),
            &a.oft_store.key(),
            &a.mint.key(),
            c.src_eid,
            &c.from,
            SendAmount::Exact(sent_home),
            0,
            home_fee,
        )?;
    }
    let to_box = match box_key {
        Some(_) => place_from_runner(surplus, &runner, &a.user_box.to_account_info(), &system)?,
        None => 0,
    };
    if !all {
        arm_ledger(&a.ledger.to_account_info(), ctx.bumps.ledger, &runner, &system, home_fee, finish_before, box_key.unwrap_or_default())?;
    }
    emit!(ComposeReturned {
        guid: params.guid,
        mint: a.mint.key(),
        src_eid: c.src_eid,
        to: c.from,
        amount: c.amount_ld,
        slice_in,
        slice_out: out,
        sent_home,
        home_fee,
        runner_fee,
        to_box,
        reason,
    });
    Ok(())
}

/// Q59: `return_composed`'s one optional remaining account, the OFT program's GapGlobal (read only):
/// its `dst_delivery` toward `eid`, or 0 when none is given. One that is given must be THE GapGlobal
/// (the OFT program's, at its PDA, readable as one), or the way home is refused (BadGapGlobal): a
/// look-alike could raise the cap. (A live store's call takes nothing else from the remaining
/// accounts; a v3 store never comes here.)
fn keys_only_delivery(rem: &[AccountInfo], eid: u32) -> Result<u64> {
    let Some(g) = rem.first() else { return Ok(0) };
    require_keys_eq!(*g.owner, OFT_PROGRAM_ID, CheapestError::BadGapGlobal);
    let (key, _) = Pubkey::find_program_address(&[GAP_GLOBAL_SEED], &OFT_PROGRAM_ID);
    require_keys_eq!(g.key(), key, CheapestError::BadGapGlobal);
    let d = g.try_borrow_data()?;
    gap_global_dst_delivery(&d, eid).ok_or_else(|| error!(CheapestError::BadGapGlobal))
}

// ================================================================================== payout

/// The seed of the OFT program's per-guid return delegate, `PDA(["GapReturn", guid])`.
pub const GAP_RETURN_SEED: &[u8] = b"GapReturn";

/// The delegate a v3 call's way home is approved to: it names the guid.
pub fn return_delegate(guid: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(&[GAP_RETURN_SEED, guid], &OFT_PROGRAM_ID).0
}

/// Why a v3 call can no longer be sold, or None while its sale is open (the same judgement as
/// `return_composed`'s: past the deadline 1; a call, sender or source that cannot be read, or a
/// deadline beyond the horizon, 2).
pub fn release_reason(payload: &[u8], from: &[u8; 32], src_eid: u32, now: i64) -> Option<u8> {
    let p = read_sell_payload(payload);
    let readable = p.is_some() && evm_address(from).is_some() && src_eid != SOLANA_EID;
    match p {
        _ if !readable => Some(2),
        Some(p) if p.deadline > now.saturating_add(MAX_HORIZON) => Some(2),
        Some(p) if now > p.deadline => Some(1),
        _ => None,
    }
}

fn release_handler(ctx: Context<ReleaseV3>, params: ComposeParams) -> Result<()> {
    let a = &ctx.accounts;
    require_keys_eq!(a.oft_store.key(), params.from, CheapestError::NotOurStore);
    check_store(&a.oft_store, &a.mint, &a.mint_authority)?;
    require!(is_v3_store(&a.oft_store.try_borrow_data()?), CheapestError::NotV3Store);
    let (call, _) = read_receipt(&a.gap_receipt, &a.oft_store.key(), &a.composer.key(), &a.mint.key(), &a.composer_token, &params, true)?;
    let reason = release_reason(&call.payload, &call.from, call.src_eid, Clock::get()?.unix_timestamp).ok_or(CheapestError::SaleStillOpen)?;
    require_keys_eq!(a.return_delegate.key(), return_delegate(&params.guid), CheapestError::WrongAddress);
    // Exactly what the receipt credited, to the guid's own delegate: the OFT program's
    // return_expired_compose takes it for this receipt and no other, once. A receipt crediting 0
    // (oft-lows L-2: the sender's prepay only) is approved for 0: the delegate is still the guid's,
    // which the OFT's zero-amount return requires, and nothing can be taken with it.
    let ix = anchor_spl::token_2022::spl_token_2022::instruction::approve(&TOKEN_2022_ID, &a.composer_token.key(), &a.return_delegate.key(), &a.composer.key(), &[], call.amount_ld)?;
    invoke_signed(
        &ix,
        &[a.composer_token.to_account_info(), a.return_delegate.to_account_info(), a.composer.to_account_info(), a.token_2022_program.to_account_info()],
        &[&[COMPOSER_SEED, &[ctx.bumps.composer]]],
    )?;
    // L4 (owner 2026-10-30): the sender's prepaid lamports left after the return's caller is
    // reimbursed go to the seller's box, beside any proceeds: the OFT program's
    // set_gap_receipt_refund(box), signed by the composer (the receipt's `to`). A sender that is not
    // an EVM address has no box: nothing is set, and the rest goes to the return's caller.
    if let Some(seller) = evm_address(&call.from) {
        require_keys_eq!(a.oft_program.key(), OFT_PROGRAM_ID, CheapestError::WrongProgram);
        let mut data = SET_GAP_RECEIPT_REFUND_DISCRIMINATOR.to_vec();
        data.extend_from_slice(box_address(call.src_eid, &seller).0.as_ref());
        let ix = Instruction {
            program_id: OFT_PROGRAM_ID,
            accounts: vec![AccountMeta::new_readonly(a.composer.key(), true), AccountMeta::new(a.gap_receipt.key(), false)],
            data,
        };
        invoke_signed(&ix, &[a.composer.to_account_info(), a.gap_receipt.to_account_info(), a.oft_program.to_account_info()], &[&[COMPOSER_SEED, &[ctx.bumps.composer]]])?;
    }
    emit!(ComposeReleased { guid: params.guid, mint: a.mint.key(), src_eid: call.src_eid, to: call.from, amount: call.amount_ld, reason });
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn pay_out_handler(ctx: Context<PayOut>, user: [u8; 20], eid: u32, amount: u64, runner_fee: u64, expires: i64, signature: [u8; 65]) -> Result<()> {
    let a = &ctx.accounts;
    let (user_box, box_bump) = box_address(eid, &user);
    require_keys_eq!(a.user_box.key(), user_box, CheapestError::WrongAddress);
    let now = Clock::get()?.unix_timestamp;
    require!(now <= expires && expires <= now + MAX_PAYOUT_TTL, CheapestError::BadExpiry);
    require!(runner_fee <= MAX_PAYOUT_RUNNER_FEE, CheapestError::RunnerFeeTooHigh);
    let deposit = a.deposit.key();
    require!(deposit != user_box && deposit != a.runner.key(), CheapestError::WrongAddress);
    let (seq_key, seq_bump) = seq_address(&user_box);
    require_keys_eq!(a.payout_seq.key(), seq_key, CheapestError::WrongAddress);
    let seeds: &[&[u8]] = &[BOX_SEED, &eid.to_le_bytes(), &user, &[box_bump]];
    let system = a.system_program.to_account_info();
    let box_ai = a.user_box.to_account_info();
    let seq_ai = a.payout_seq.to_account_info();
    // The count this payout is for: 0 for a box's first, whose count is made here.
    let seq = if *seq_ai.owner == crate::ID {
        PayoutSeq::try_deserialize(&mut &seq_ai.try_borrow_data()?[..])?.next
    } else {
        0
    };
    let digest = payout_digest(&user_box, &user, eid, seq, amount, &deposit, runner_fee, expires);
    require!(recover_signer(&digest, &signature)? == a.config.payout_signer, CheapestError::BadSignature);
    // What was signed for: a box that took less since, or a whole account's worth more, is quoted
    // again. Less than that more goes out with the rest -- so a stranger cannot hold a payout off
    // with a lamport, only by giving the user an account's rent each time.
    let floor = Rent::get()?.minimum_balance(0);
    let now_held = a.user_box.lamports();
    require!(now_held >= amount && now_held - amount < floor, CheapestError::BoxChanged);

    // A box's first payout makes its count, out of the box (the user's, once per box).
    if *seq_ai.owner != crate::ID {
        let space = 8 + PayoutSeq::INIT_SPACE;
        let rent = Rent::get()?.minimum_balance(space);
        let have = seq_ai.lamports();
        let seq_seeds: &[&[u8]] = &[SEQ_SEED, user_box.as_ref(), &[seq_bump]];
        if have < rent {
            invoke_signed(&system_instruction::transfer(&user_box, &seq_key, rent - have), &[box_ai.clone(), seq_ai.clone(), system.clone()], &[seeds])?;
        }
        invoke_signed(&system_instruction::allocate(&seq_key, space as u64), &[seq_ai.clone(), system.clone()], &[seq_seeds])?;
        invoke_signed(&system_instruction::assign(&seq_key, &crate::ID), &[seq_ai.clone(), system.clone()], &[seq_seeds])?;
    }
    {
        let mut data = seq_ai.try_borrow_mut_data()?;
        let next = PayoutSeq { next: seq.checked_add(1).ok_or(CheapestError::Overflow)? };
        let mut out: Vec<u8> = PayoutSeq::DISCRIMINATOR.to_vec();
        next.serialize(&mut out)?;
        data[..out.len()].copy_from_slice(&out);
    }

    let held = a.user_box.lamports();
    require!(amount >= MIN_PAYOUT && held > runner_fee, CheapestError::BoxTooSmall);
    if runner_fee > 0 {
        invoke_signed(&system_instruction::transfer(&user_box, a.runner.key, runner_fee), &[box_ai.clone(), a.runner.to_account_info(), system.clone()], &[seeds])?;
    }
    let lamports = held - runner_fee;
    invoke_signed(&system_instruction::transfer(&user_box, &deposit, lamports), &[box_ai, a.deposit.to_account_info(), system], &[seeds])?;
    emit!(PaidOut { user_box, user, eid, deposit, lamports, runner_fee, seq });
    Ok(())
}

/// The secp256k1 order's half: a signature's `s` above it is the malleable twin of another.
const HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46,
    0x68, 0x1b, 0x20, 0xa0,
];

/// The EVM-style address that signed `digest` (r || s || v, v 27 or 28, low s).
pub fn recover_signer(digest: &[u8; 32], signature: &[u8; 65]) -> Result<[u8; 20]> {
    let v = signature[64];
    require!(v == 27 || v == 28, CheapestError::BadSignature);
    require!(signature[32..64] <= HALF_ORDER[..], CheapestError::BadSignature);
    let key = secp256k1_recover(digest, v - 27, &signature[..64]).map_err(|_| error!(CheapestError::BadSignature))?;
    let h = keccak::hash(&key.to_bytes()).0;
    let mut address = [0u8; 20];
    address.copy_from_slice(&h[12..]);
    Ok(address)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terms_hash_over_their_fixed_bytes() {
        let t = OrderTerms {
            user: [0x11; 20],
            dst_eid: 30184,
            mint: Pubkey::new_from_array([0x22; 32]),
            amount: 1,
            min_out: 2,
            deadline: 3,
            lz_fee_cap: 4,
            runner_fee: 5,
            salt: [0x33; 16],
        };
        let bytes = t.try_to_vec().unwrap();
        assert_eq!(bytes.len(), 20 + 4 + 32 + 8 * 5 + 16);
        assert_eq!(t.hash(), hash::hashv(&[ORDER_DOMAIN, &bytes]).to_bytes());
    }

    #[test]
    fn the_finish_discriminator_is_anchors() {
        assert_eq!(&hash::hash(b"global:finish_send").to_bytes()[..8], &instruction::FinishSend::DISCRIMINATOR);
    }
}
