//! # Factory v2's Solana leg: `launch_v2` and `launch_self`
//!
//! The same launch as `launch` (see `launch_leg`): one instruction, every address the seed's, the
//! same calls in the same order. What is new (docs/factory-v2.md §4-§6):
//!
//! **The snapshot is v2's.** It signs the opening market cap the creator chose, the supply mode
//! and the launch's TERMS -- `keccak256(abi.encode(payeeEvm, payeeSolana, feeEid, feeMin))`, which
//! the program rebuilds from its arguments -- in PriceAttestorV2's domain (`price`, "snapshot v2").
//! The price is still derived here and never sent.
//!
//! **A payee apart from the creator.** The record's `creator` is the PAYEE: the fee stream, which
//! only the admin may move afterwards (D10). The real creator keeps the dev buy and the credit, and
//! is recorded in the v2 tail after the peers (`crate::read_v2_tail`). The payee may be the
//! incinerator: "burn the fees".
//!
//! **No free launches (D5).** The terms name the chain the fee is paid on and its least amount.
//! When that chain is Solana the launch is handed the payment for this launch id and refused
//! unless it holds at least that (`LaunchUnpaid`); it is settled in this instruction, as today.
//!
//! **SUPPLY_TOTAL: the lockbox** (owner, 2026-10-24). The mint is given the whole launch total,
//! `slice x chains`: the slice goes into the pool and the rest -- the other chains' share -- into
//! the escrow of the launch's OFT store, which is an ADAPTER: bridging out of Solana locks into that
//! escrow, bridging in releases from it. The share is declared locked by `init_tvl`, the one
//! instruction our deployment of LayerZero's OFT program adds (solana/oft/PANGEA-PATCH.md), and the
//! mint's authority is then revoked: nothing can ever mint, and Solana's supply is the total for
//! good, with no `rebalance` (`launch_leg::lock_in_escrow`). The record's tail keeps the TOTAL
//! layout, the escrow in the reserve's place and the zero key in the minter's
//! (`ReserveV2::is_lockbox`). Launches made before kept a reserve in their `token_a` account,
//! a minter multisig and `rebalance` (see `reserve`), and keep them.
//!
//! **The dev buy** is made from the creator's wallet when the creator signs (always, in
//! `launch_self`), and otherwise from the creator's payment, as `launch` makes it -- but without
//! asking for the creator's wrapped-SOL account, which a v2 launch never needs: its fees are paid
//! out natively (`claim_fees_native`). Unticked by default (D7): `expected_dev_buy` zero buys
//! nothing. In either mode the tokens go into the slice's account, which becomes the creator's.
//! (The `dev_buy_account` place is kept and, in a v2 launch, never read: a reserve-era SUPPLY_TOTAL launch paid its
//! buy into `PDA(["dev_buy", seed])`.)
//!
//! **`launch_self` (D6)** is the launch sent by its creator alone: the creator is the payer and the
//! only signer, pays every lamport of rent, and names no launcher -- the seed is the creator's own
//! (derived off chain from their wallet's signature), so nobody else can send this launch. What a
//! launcher provided is the creator's: the wrapped-SOL account the pool's opening unit is drawn
//! from -- an account of the seed's, `PDA(["wsol", seed])`, wrapping the creator's lamports and
//! left open, the creator's (`SELF_WSOL_SEED`, `self_wrapped_sol`) -- or their
//! own account for an allowlisted asset, holding at least one base unit.
//!
//! **A creator self-launch across chains (owner 2026-10-28, option b; per-leg mask, option C,
//! 2026-10-29).** Terms with `selfUntil != 0` carry `TermsV3.legFees`: one `LegFee` for each
//! FLAGGED leg, strictly ascending by eid -- a non-empty subset of the legs, which is the signed
//! self mask. A flagged leg is paid on its own chain with its own fee; an unflagged leg takes the
//! normal path (the terms' `feeMin` by the terms' payer on the fee chain, nothing elsewhere). When
//! the subset is strict the fee chain must be unflagged (EVM BadTerms 16; here `BadSelfTerms`).
//! Every leg flagged is option b exactly: the same hash, wire and behaviour. The Solana leg is still
//! sent by our launcher through `launch_v2` (never `launch_self`: `SelfTermsNeedTheLauncher`).
//! When the Solana leg is flagged it is paid on Solana before the creator signs: the launch requires this launch id's payment,
//! holding at least the Solana leg's `fee_min`, made by the Solana leg's payer -- which is the
//! payment's own payer, read from it and hashed into the leg fees, so a payment by anybody else
//! does not match the signed hash. The payment is settled here, as any Solana-paid launch's, so it
//! can never pay again. The program rebuilds the ten-word terms hash
//! (`price::terms_hash_self`) and checks EVM's `checkSelfLaunch` rules: `selfUntil` at least
//! `SELF_LAUNCH_TAKEOVER_MARGIN_S` before the snapshot's deadline, at least one leg flagged, the
//! flagged legs in the legs' order (by construction of the wire), each flagged fee and EVM payer
//! non-zero and each unflagged payer zero, the fee chain unflagged in a strict subset
//! (`BadSelfTerms`), and the hash signed. When the Solana leg is unflagged it is exactly the normal
//! path: a payment is due only when the fee chain is Solana, holding the terms' `fee_min`. The EVM factories' "the platform waits until selfUntil" gate does not apply here:
//! on Solana the launcher is the sender either way. The terms' own payer word when the fee chain
//! is Solana is, as ever, the payment's payer: a self-launch whose terms name Solana as the fee
//! chain names its Solana leg's payer there too.
//!
//! ## The byte budget
//!
//! A launch is one transaction of at most 1,232 bytes, and this one carries more than v1's. It
//! fits by a compact wire form (`LaunchV2Args`): one-byte name and symbol lengths, a flags byte
//! for the URI form, supply mode, Solana payee and fee chain (named by its place among the legs),
//! no leg count (the peer mask says it), the deadline in four bytes (signed as eight), each leg's
//! price in four (`price::WIRE_PRICE_LEN`), each leg's pool fee in nine bits (`price::WIRE_FEE_BITS`),
//! amounts in five, a 64-byte compact signature, and the peers either as
//! one EVM address for every chain or one each (the same address everywhere stays optional, D12).
//! And by accounts: no creator wrapped-SOL account; SUPPLY_TOTAL's one account more, the store's
//! `TvlMark`, in the place its minter took. tests/launch_v2.rs pins every
//! worst case.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::{program::invoke_signed, system_instruction};
use anchor_spl::{
    associated_token::AssociatedToken,
    token::{self, Token},
};

use crate::launch_leg::{
    can_take_back, create_token, wire_bridge, check_asset_dev_buy, check_dev_buy, check_launch_args, check_launch_args_before_price, check_wallet_dev_buy, excess_back_to_creator,
    launch_liquidity, launch_total, lock_in_escrow, open_pool, resolve_quote, Calls, DevBuy, Finish, LaunchAccounts, PoolPlan, ESCROW_SEED, MAX_UNPOOLED, POSITION_SEED, TOKEN_A_SEED,
};
use crate::price::{SignedPriceV2, SnapshotTerms, V2Price, SOLANA_EID, SUPPLY_SLICE, SUPPLY_TOTAL};
use crate::{
    buy_output, dev_buy_minimum, has_pangea_ending, launch_id_of, minter_of, Excess, FeePayment, LaunchArgs, LaunchRecord, Launcher, Peers,
    ReserveV2, SplitterError, V2Tail, ADMIN, AUTHORITY_SEED, CP_AMM_ID, FEES_SEED, LAUNCHER_SEED, LZ_ENDPOINT_ID, MINT_SEED, OFT_PROGRAM_ID, PEER_CHAINS,
    SPLITTER_SEED,
};

/// The account a reserve-era SUPPLY_TOTAL launch's dev buy was paid into: `PDA(["dev_buy", seed])`,
/// a plain Token-2022 account of the launched token owned by the creator (its slice's account was
/// the bridge reserve). A lockbox launch pays the buy into the slice's account, as SUPPLY_SLICE
/// does; the address is still one no payee may be (`v2_held`).
pub const DEV_BUY_SEED: &[u8] = b"dev_buy";

/* ------------------------------------------------------------------------------ the arguments */

/// How much of a v2 launch's seed is secret, and sent: 128 bits. The seed every address derives
/// from is these sixteen bytes and sixteen zeros -- the same 32-byte derivations as v1's, so
/// `launch_id_of`, the escrow, the store and the mint are computed as ever. 128 bits is as far
/// past guessing as 256 is; the sixteen bytes saved pay for an asset launch's Solana payee.
pub const V2_SEED_LEN: usize = 16;

/// The account a self-launch against wrapped SOL wraps the creator's lamports in, for the pool's
/// opening unit and the dev buy: `PDA(["wsol", seed])`, made in the launch and left open, owned
/// by the creator (see `self_wrapped_sol`).
pub const SELF_WSOL_SEED: &[u8] = b"wsol";

/// The wire's code for each URI form, in the flags byte's low two bits.
const URI_FORMS: [u8; 3] = [crate::CID_V0, crate::CID_V1_RAW, crate::CID_V1_DAG_PB];

const FLAG_TOTAL: u8 = 1 << 2;
const FLAG_PAYEE: u8 = 1 << 3;
const FEE_LEG_SHIFT: u8 = 4;
/// The top bit of the flags is not a v2 form (factory v3's moon, never shipped): refused.
const FLAG_UNUSED: u8 = 1 << 7;
/// The peer mask's top bit: one EVM address for every chain named.
pub const PEERS_SHARED: u8 = 0x80;
const _: () = assert!(PEER_CHAINS.len() <= 7, "a v2 peer mask keeps its top bit for the shared form");

/// What a v2 launch states. On the wire, in this order (every integer little-endian):
///
/// ```text
///   launch_seed       16 (the seed is these and sixteen zero bytes: `V2_SEED_LEN`)
///   mint_nonce        u24 (three bytes; a nonce past 2^24 is not one a launch uses)
///   name              u8 length, bytes
///   symbol            u8 length, bytes
///   flags             u8: bits 0-1 the URI form (0 CIDv0, 1 CIDv1 raw, 2 CIDv1 dag-pb);
///                         bit 2 SUPPLY_TOTAL; bit 3 a Solana payee follows;
///                         bits 4-6 the fee chain, as its place among the legs (ascending eid,
///                         Solana's included); bit 7 unused (refused)
///   uri_digest        32
///   slice             amount (5 bytes: e u8, m u32; value = m x 10^e -- `price::WIRE_AMOUNT_LEN`)
///   expected_dev_buy  amount
///   market_cap_usd    u24
///   payee_evm         20
///   payee_solana      32, when flagged (none: the creator; hashed as 32 zero bytes)
///   fee_min           amount
///   peers             u8 mask over PEER_CHAINS (bit 7: one address for all), then 20 bytes per
///                     chain named -- or 20 once, for the shared form
///   payer             20, only when the fee chain is not Solana: the EVM address that pays the
///                     fee there (hashed left-padded to 32). On Solana it is the fee payment's own
///                     payer, read from the payment, not sent
///   fees              each leg's pool fee in bps, nine bits each, legs ascending by eid (Solana's
///                     is `fee_bps`, the peers' `peer_fee_bps`), packed least-significant bit
///                     first into ceil(9 x legs / 8) bytes, the bits past the last zero
///                     (`price::encode_fees`): six bytes for five legs
///   deadline          u32 (signed as uint64)
///   prices            4 bytes per leg, legs ascending by eid: a u32, e its low 5 bits and m its
///                     high 27; usdPerQuote = m x 10^e
///   signature         64, compact (EIP-2098): r, then s with yParity in its top bit
///   self terms        ONLY for a creator self-launch (`selfUntil != 0`); nothing at all otherwise,
///                     so every other launch's wire is byte for byte as before:
///                       self_until  u32 (never 0)
///                       per leg, ascending by eid: an EVM leg's fee_min RAW as u128 LE (16; wei, any
///                       value -- audit round 2, M-1: a compact amount could not carry every fee EVM
///                       accepts), then its payer (20; hashed left-padded); the Solana leg's fee_min
///                       raw as u64 LE (8; lamports -- EVM caps it at a u64), no payer: it is the fee
///                       payment's own payer. Every leg has its entry (the byte budget is the same
///                       whatever the mask); an UNFLAGGED leg (option C: no LegFee in the signed
///                       list) is a fee_min of 0 and, for an EVM leg, a payer of 20 zero bytes. A
///                       flagged leg's fee is never 0 (EVM BadTerms 13), so 0 is never ambiguous
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaunchV2Args {
    pub launch_seed: [u8; 32],
    pub mint_nonce: u32,
    pub name: String,
    pub symbol: String,
    pub uri_form: u8,
    pub uri_digest: [u8; 32],
    pub supply_mode: u8,
    /// The Solana pool's fee: Meteora's base fee here, and the Solana leg's signed fee.
    pub fee_bps: u16,
    /// Each peer's pool fee, in the peers' order: signed in its leg, opened on its own chain.
    pub peer_fee_bps: Vec<u16>,
    pub slice: u64,
    pub expected_dev_buy: u64,
    pub market_cap_usd: u32,
    pub payee_evm: [u8; 20],
    /// The fee stream's address on Solana. None: the creator (the EVM side hashes zero).
    pub payee_solana: Option<Pubkey>,
    /// The chain the launch fee is paid on: one of the launch's legs.
    pub fee_eid: u32,
    /// The least that must be held for the launch on `fee_eid`, in its native coin. Never zero.
    pub fee_min: u64,
    pub peers: Peers,
    /// Who pays the fee, as the terms hash it -- given only when the fee is paid on another chain
    /// (on Solana it is the payment's own payer, read from the fee account).
    pub payer: Option<[u8; 20]>,
    pub price: SignedPriceV2,
    /// A creator self-launch's own terms (`selfUntil` and an entry per leg, the flagged legs' fees); None for every other
    /// launch (`selfUntil` 0, nothing on the wire).
    pub self_terms: Option<SelfTerms>,
}

/// A creator self-launch's `selfUntil` and leg fees (`TermsV3.selfUntil`, `LegFee[]`), one entry
/// per leg, legs ascending by eid; an entry whose `fee_min` is 0 is an UNFLAGGED leg (option C: it
/// has no `LegFee` in the signed list and takes the normal path; its payer is zero -- an EVM leg's
/// `Some([0; 20])`, Solana's None). Each flagged leg's `fee_min` in its chain's native unit, exactly as signed: wei for an
/// EVM leg (up to a u128 on the wire), lamports for Solana's (at most a u64, as EVM's
/// `checkSelfLaunch` requires); an EVM leg's payer is its 20-byte address, the Solana leg's is None
/// (the fee payment's payer).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelfTerms {
    pub self_until: u32,
    pub fees: Vec<SelfLegFee>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelfLegFee {
    pub fee_min: u128,
    pub payer: Option<[u8; 20]>,
}

impl SelfLegFee {
    /// Whether this leg is in the signed self mask (has a `LegFee`): a non-zero fee.
    pub fn flagged(&self) -> bool {
        self.fee_min != 0
    }
}

/// `UniswapLaunchFactoryV3Checks.SELF_LAUNCH_TAKEOVER_MARGIN_S`: a self-launch's `selfUntil` is at
/// least this long before the snapshot's deadline.
pub const SELF_LAUNCH_TAKEOVER_MARGIN_S: u64 = 300;

fn bad(why: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, why.to_string())
}

/// The legs' endpoint ids, ascending: the peers' and Solana's.
pub fn leg_eids(peers: &Peers) -> Vec<u32> {
    let mut eids: Vec<u32> = peers.eids().collect();
    eids.push(SOLANA_EID);
    eids.sort_unstable();
    eids
}

impl LaunchV2Args {
    /// The 32 bytes the EVM side hashes for the Solana payee: zero for "the creator".
    pub fn payee_solana_bytes(&self) -> [u8; 32] {
        self.payee_solana.map(|k| k.to_bytes()).unwrap_or([0u8; 32])
    }

    /// `TermsV3.termsHash` for these arguments, the fee paid by `b.payer`. A self-launch hashes its
    /// ten words, the leg fees with `solana_leg_payer` as the Solana leg's payer (the fee
    /// payment's); every other launch ignores it.
    pub fn terms(&self, b: &crate::price::TermsBinding, solana_leg_payer: &[u8; 32]) -> [u8; 32] {
        self.terms_for(b, solana_leg_payer, false)
    }

    /// `terms` for a v2 launch (`gap_v3` false: the live hash, unchanged) or a v3 one (`gap_v3`
    /// true: `price::terms_hash_v3`, the same words and the version word after them).
    pub fn terms_for(&self, b: &crate::price::TermsBinding, solana_leg_payer: &[u8; 32], gap_v3: bool) -> [u8; 32] {
        let (self_until, leg_fees) = match &self.self_terms {
            None => (0, [0u8; 32]),
            Some(st) => {
                // An impossible list (it is built leg for leg below, ascending) hashes as zero,
                // which no signed terms carry.
                let legs = self.leg_fee_entries(st, solana_leg_payer);
                (st.self_until, legs.as_deref().and_then(crate::price::leg_fees_hash).unwrap_or([0u8; 32]))
            }
        };
        if gap_v3 {
            return crate::price::terms_hash_v3(&self.payee_evm, &self.payee_solana_bytes(), self.fee_eid, self.fee_min, b, self_until, &leg_fees);
        }
        match &self.self_terms {
            None => crate::price::terms_hash(&self.payee_evm, &self.payee_solana_bytes(), self.fee_eid, self.fee_min, b),
            Some(_) => crate::price::terms_hash_self(&self.payee_evm, &self.payee_solana_bytes(), self.fee_eid, self.fee_min, b, self_until, &leg_fees),
        }
    }

    /// The self-launch's `LegFee[]`: the FLAGGED legs only (option C's mask), ascending by eid.
    /// None when there is not one entry per leg, no leg is flagged, a flagged EVM leg lacks its
    /// payer (or a flagged Solana leg names one), or an unflagged leg's payer is not zero.
    pub fn leg_fee_entries(&self, st: &SelfTerms, solana_leg_payer: &[u8; 32]) -> Option<Vec<crate::price::LegFeeEntry>> {
        let eids = leg_eids(&self.peers);
        if st.fees.len() != eids.len() {
            return None;
        }
        let mut out = Vec::with_capacity(eids.len());
        for (eid, f) in eids.iter().zip(&st.fees) {
            let solana = *eid == SOLANA_EID;
            if !f.flagged() {
                match (solana, f.payer) {
                    (true, None) => {}
                    (false, Some(p)) if p == [0u8; 20] => {}
                    _ => return None,
                }
                continue;
            }
            let payer = match (solana, f.payer) {
                (true, None) => *solana_leg_payer,
                (false, Some(p)) => {
                    let mut w = [0u8; 32];
                    w[12..].copy_from_slice(&p);
                    w
                }
                _ => return None,
            };
            out.push(crate::price::LegFeeEntry { eid: *eid, fee_min: f.fee_min, payer });
        }
        if out.is_empty() {
            return None;
        }
        Some(out)
    }

    /// The Solana leg's self entry, when this is a self-launch and it is flagged.
    fn solana_self_leg(&self) -> Option<&SelfLegFee> {
        let st = self.self_terms.as_ref()?;
        let at = leg_eids(&self.peers).iter().position(|e| *e == SOLANA_EID)?;
        st.fees.get(at).filter(|f| f.flagged())
    }

    /// Whether the Solana leg is a self-launch leg: self terms with the Solana leg FLAGGED (paid
    /// here with its own fee, by the payment's payer). An unflagged Solana leg is the normal path.
    pub fn solana_leg_flagged(&self) -> bool {
        self.solana_self_leg().is_some()
    }

    /// The Solana leg's own fee in a self-launch whose Solana leg is flagged.
    pub fn solana_leg_fee(&self) -> Option<u64> {
        self.solana_self_leg().and_then(|f| u64::try_from(f.fee_min).ok())
    }

    /// Whether this launch's fee is paid here, on Solana: the Solana leg is a flagged self-launch
    /// leg (paid on its own chain), or the terms' fee chain is Solana.
    pub fn fee_due_here(&self) -> bool {
        self.solana_leg_flagged() || self.fee_eid == SOLANA_EID
    }

    /// `metadata_hash` of the name, symbol and the URI the program writes for this launch.
    pub fn metadata(&self) -> Result<[u8; 32]> {
        let uri = crate::ipfs_uri(self.uri_form, &self.uri_digest)?;
        Ok(crate::price::metadata_hash(&self.name, &self.symbol, &uri))
    }

    /// Every leg's pool fee, legs ascending by eid: Solana's `fee_bps` among the peers'. None when
    /// there is not one fee per peer, or a peer is not in the legs.
    pub fn leg_fees(&self) -> Option<Vec<u16>> {
        if self.peer_fee_bps.len() != self.peers.len() {
            return None;
        }
        leg_eids(&self.peers)
            .iter()
            .map(|e| if *e == SOLANA_EID { Some(self.fee_bps) } else { self.peers.0.iter().position(|(p, _)| *p as u32 == *e).map(|i| self.peer_fee_bps[i]) })
            .collect()
    }

    /// The fee this launch settles here: a flagged Solana self leg's fee; otherwise `fee_min` when
    /// the terms' fee chain is Solana, else nothing.
    pub fn fee_here(&self) -> u64 {
        if self.solana_leg_flagged() {
            self.solana_leg_fee().unwrap_or(0)
        } else if self.fee_eid == SOLANA_EID {
            self.fee_min
        } else {
            0
        }
    }

    /// The v1 arguments the shared steps take (`launch_leg`): the same launch, the fee it settles
    /// here as its `launch_fee`. The price is v2's and is checked apart (`price`).
    pub fn as_v1(&self) -> LaunchArgs {
        LaunchArgs {
            launch_seed: self.launch_seed,
            mint_nonce: self.mint_nonce,
            name: self.name.clone(),
            symbol: self.symbol.clone(),
            uri_form: self.uri_form,
            uri_digest: self.uri_digest,
            fee_bps: self.fee_bps,
            slice: self.slice,
            init_sqrt_price: 0,
            launch_fee: self.fee_here(),
            expected_dev_buy: self.expected_dev_buy,
            peers: self.peers.clone(),
            price: Default::default(),
        }
    }
}

impl AnchorSerialize for LaunchV2Args {
    fn serialize<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
        let invalid = |why: &str| std::io::Error::new(std::io::ErrorKind::InvalidInput, why.to_string());
        // The seed's first sixteen bytes: a v2 seed is 128 secret bits, the rest zero.
        if self.launch_seed[V2_SEED_LEN..] != [0u8; 32 - V2_SEED_LEN] {
            return Err(invalid("a v2 seed is sixteen bytes and sixteen zeros"));
        }
        w.write_all(&self.launch_seed[..V2_SEED_LEN])?;
        if self.mint_nonce >> 24 != 0 {
            return Err(invalid("a mint nonce past 2^24"));
        }
        w.write_all(&self.mint_nonce.to_le_bytes()[..3])?;
        for s in [&self.name, &self.symbol] {
            let len = u8::try_from(s.len()).map_err(|_| invalid("a name or symbol past 255 bytes"))?;
            w.write_all(&[len])?;
            w.write_all(s.as_bytes())?;
        }
        let form = URI_FORMS.iter().position(|f| *f == self.uri_form).ok_or_else(|| invalid("an unknown URI form"))? as u8;
        let eids = leg_eids(&self.peers);
        let fee_leg = eids.iter().position(|e| *e == self.fee_eid).ok_or_else(|| invalid("the fee chain is not a leg"))? as u8;
        let mode = match self.supply_mode {
            SUPPLY_SLICE => 0,
            SUPPLY_TOTAL => FLAG_TOTAL,
            _ => return Err(invalid("an unknown supply mode")),
        };
        let payee = if self.payee_solana.is_some() { FLAG_PAYEE } else { 0 };
        w.write_all(&[form | mode | payee | (fee_leg << FEE_LEG_SHIFT)])?;
        w.write_all(&self.uri_digest)?;
        let amount = |v: u64| crate::price::encode_amount(v).ok_or_else(|| invalid("an amount with more than nine significant digits"));
        w.write_all(&amount(self.slice)?)?;
        w.write_all(&amount(self.expected_dev_buy)?)?;
        if self.market_cap_usd >> 24 != 0 {
            return Err(invalid("a market cap past 2^24"));
        }
        w.write_all(&self.market_cap_usd.to_le_bytes()[..3])?;
        w.write_all(&self.payee_evm)?;
        if let Some(p) = self.payee_solana {
            w.write_all(p.as_ref())?;
        }
        w.write_all(&amount(self.fee_min)?)?;
        // The peers: shared when every chain names one address.
        let mut mask = 0u8;
        for (eid, _) in &self.peers.0 {
            let bit = PEER_CHAINS.iter().position(|c| c == eid).ok_or_else(|| invalid("a peer that is not one of PEER_CHAINS"))?;
            if mask >> bit != 0 {
                return Err(invalid("peers not strictly ascending"));
            }
            mask |= 1 << bit;
        }
        let shared = self.peers.len() > 1 && self.peers.0.windows(2).all(|p| p[0].1 == p[1].1);
        if shared {
            w.write_all(&[mask | PEERS_SHARED])?;
            w.write_all(&self.peers.0[0].1)?;
        } else {
            w.write_all(&[mask])?;
            for (_, token) in &self.peers.0 {
                w.write_all(token)?;
            }
        }
        match (self.fee_eid == SOLANA_EID, self.payer) {
            (true, None) => {}
            (false, Some(p)) => w.write_all(&p)?,
            _ => return Err(invalid("the payer is sent when, and only when, the fee is not paid on Solana")),
        }
        let fees = self.leg_fees().ok_or_else(|| invalid("one fee per peer"))?;
        w.write_all(&crate::price::encode_fees(&fees).ok_or_else(|| invalid("a fee past 2^9 - 1 bps"))?)?;
        let deadline = u32::try_from(self.price.deadline).map_err(|_| invalid("a deadline past 2106"))?;
        w.write_all(&deadline.to_le_bytes())?;
        if self.price.usd_per_quote.len() != eids.len() {
            return Err(invalid("one price per leg"));
        }
        for usd in &self.price.usd_per_quote {
            w.write_all(&crate::price::encode_usd_per_quote(*usd).ok_or_else(|| invalid("a price with more than a 32-bit mantissa"))?)?;
        }
        let sig: [u8; 65] = self.price.signature.as_slice().try_into().map_err(|_| invalid("a 65-byte signature"))?;
        w.write_all(&crate::price::compact_signature(&sig).ok_or_else(|| invalid("a signature with v not 27 or 28, or a high s"))?)?;
        // A creator self-launch's terms; nothing for any other launch.
        if let Some(st) = &self.self_terms {
            if st.self_until == 0 {
                return Err(invalid("a self-launch's selfUntil is not 0 (0 is no self terms at all)"));
            }
            if st.fees.len() != eids.len() {
                return Err(invalid("one self-launch fee per leg"));
            }
            w.write_all(&st.self_until.to_le_bytes())?;
            for (eid, f) in eids.iter().zip(&st.fees) {
                match (*eid == SOLANA_EID, f.payer) {
                    (true, None) => {
                        let lamports = u64::try_from(f.fee_min).map_err(|_| invalid("the Solana leg's fee is at most a u64"))?;
                        w.write_all(&lamports.to_le_bytes())?;
                    }
                    (false, Some(p)) => {
                        w.write_all(&f.fee_min.to_le_bytes())?;
                        w.write_all(&p)?;
                    }
                    _ => return Err(invalid("an EVM leg's payer is sent; the Solana leg's is the payment's")),
                }
            }
        }
        Ok(())
    }
}

impl AnchorDeserialize for LaunchV2Args {
    fn deserialize_reader<R: std::io::Read>(r: &mut R) -> std::io::Result<Self> {
        let mut take = |n: usize| -> std::io::Result<Vec<u8>> {
            let mut b = vec![0u8; n];
            r.read_exact(&mut b)?;
            Ok(b)
        };
        let mut launch_seed = [0u8; 32];
        launch_seed[..V2_SEED_LEN].copy_from_slice(&take(V2_SEED_LEN)?);
        let three = |b: Vec<u8>| u32::from_le_bytes([b[0], b[1], b[2], 0]);
        let mint_nonce = three(take(3)?);
        let text = |take: &mut dyn FnMut(usize) -> std::io::Result<Vec<u8>>| -> std::io::Result<String> {
            let len = take(1)?[0] as usize;
            String::from_utf8(take(len)?).map_err(|_| bad("not UTF-8"))
        };
        let name = text(&mut take)?;
        let symbol = text(&mut take)?;
        let flags = take(1)?[0];
        if flags & FLAG_UNUSED != 0 {
            return Err(bad("a flag bit past the v2 form"));
        }
        let uri_form = *URI_FORMS.get((flags & 3) as usize).ok_or_else(|| bad("an unknown URI form"))?;
        let supply_mode = if flags & FLAG_TOTAL != 0 { SUPPLY_TOTAL } else { SUPPLY_SLICE };
        let fee_leg = ((flags >> FEE_LEG_SHIFT) & 7) as usize;
        let uri_digest: [u8; 32] = take(32)?.try_into().unwrap();
        let mut amount = |take: &mut dyn FnMut(usize) -> std::io::Result<Vec<u8>>| -> std::io::Result<u64> {
            let b: [u8; crate::price::WIRE_AMOUNT_LEN] = take(crate::price::WIRE_AMOUNT_LEN)?.try_into().unwrap();
            crate::price::decode_amount(&b).ok_or_else(|| bad("an amount past 64 bits"))
        };
        let slice = amount(&mut take)?;
        let expected_dev_buy = amount(&mut take)?;
        let market_cap_usd = three(take(3)?);
        let payee_evm: [u8; 20] = take(20)?.try_into().unwrap();
        let payee_solana = if flags & FLAG_PAYEE != 0 { Some(Pubkey::new_from_array(take(32)?.try_into().unwrap())) } else { None };
        let fee_min = amount(&mut take)?;
        let mask = take(1)?[0];
        let chains = mask & !PEERS_SHARED;
        if (chains as u16) >> PEER_CHAINS.len() != 0 {
            return Err(bad("a peer mask bit past PEER_CHAINS"));
        }
        let shared = if mask & PEERS_SHARED != 0 { Some(<[u8; 20]>::try_from(take(20)?).unwrap()) } else { None };
        let mut peers = Vec::with_capacity(chains.count_ones() as usize);
        for (bit, eid) in PEER_CHAINS.iter().enumerate() {
            if chains & (1 << bit) != 0 {
                let token = match shared {
                    Some(t) => t,
                    None => take(20)?.try_into().unwrap(),
                };
                peers.push((*eid, token));
            }
        }
        let peers = Peers(peers);
        let eids = leg_eids(&peers);
        let fee_eid = *eids.get(fee_leg).ok_or_else(|| bad("the fee chain is not a leg"))?;
        let payer = if fee_eid == SOLANA_EID { None } else { Some(take(20)?.try_into().unwrap()) };
        let fees = crate::price::decode_fees(&take(crate::price::fees_wire_len(eids.len()))?, eids.len()).ok_or_else(|| bad("a fee bit past the last leg's"))?;
        let mut fee_bps = 0u16;
        let mut peer_fee_bps = Vec::with_capacity(peers.len());
        for (eid, fee) in eids.iter().zip(&fees) {
            if *eid == SOLANA_EID {
                fee_bps = *fee;
            } else {
                // Ascending: the peers' fees come in the peers' order.
                peer_fee_bps.push(*fee);
            }
        }
        let deadline = u32::from_le_bytes(take(4)?.try_into().unwrap()) as u64;
        let mut usd_per_quote = Vec::with_capacity(eids.len());
        for _ in 0..eids.len() {
            let b: [u8; crate::price::WIRE_PRICE_LEN] = take(crate::price::WIRE_PRICE_LEN)?.try_into().unwrap();
            usd_per_quote.push(crate::price::decode_usd_per_quote(&b).ok_or_else(|| bad("a price past 128 bits"))?);
        }
        let compact: [u8; 64] = take(64)?.try_into().unwrap();
        let signature = crate::price::widen_signature(&compact).to_vec();
        // A creator self-launch's terms follow, or nothing: read what is there.
        let self_terms = {
            let mut until = [0u8; 4];
            let mut got = 0;
            while got < 4 {
                let n = r.read(&mut until[got..])?;
                if n == 0 {
                    break;
                }
                got += n;
            }
            match got {
                0 => None,
                4 => {
                    let self_until = u32::from_le_bytes(until);
                    if self_until == 0 {
                        return Err(bad("a self-launch's selfUntil of 0"));
                    }
                    let mut fees = Vec::with_capacity(eids.len());
                    for eid in &eids {
                        fees.push(if *eid == SOLANA_EID {
                            let mut b = [0u8; 8];
                            r.read_exact(&mut b)?;
                            SelfLegFee { fee_min: u64::from_le_bytes(b) as u128, payer: None }
                        } else {
                            let mut b = [0u8; 16];
                            r.read_exact(&mut b)?;
                            let mut p = [0u8; 20];
                            r.read_exact(&mut p)?;
                            SelfLegFee { fee_min: u128::from_le_bytes(b), payer: Some(p) }
                        });
                    }
                    Some(SelfTerms { self_until, fees })
                }
                _ => return Err(bad("a self-launch's selfUntil cut short")),
            }
        };
        Ok(LaunchV2Args {
            launch_seed,
            mint_nonce,
            name,
            symbol,
            uri_form,
            uri_digest,
            supply_mode,
            fee_bps,
            peer_fee_bps,
            slice,
            expected_dev_buy,
            market_cap_usd,
            payee_evm,
            payee_solana,
            fee_eid,
            fee_min,
            peers,
            payer,
            price: SignedPriceV2 { deadline, usd_per_quote, signature },
            self_terms,
        })
    }
}

/// The terms' own rules, before anything is created: a fee is named (D5), on one of the launch's
/// chains, and the market cap is one a launch may open at. And every peer has a pool fee every
/// chain takes (30-500 bps; Solana's own is `check_fee`'s, in `check_launch_args_before_price`).
/// A v2 launch's: v2's floor, either supply mode. See `check_terms_for` for a v3 launch's.
pub fn check_terms(a: &LaunchV2Args) -> Result<()> {
    check_terms_for(a, None)
}

/// `check_terms` for a v2 launch (`v3_min` None: v2's `MIN_MARKET_CAP_USD`, SLICE or TOTAL, as
/// live) or a v3 one (`v3_min` Some(the admin's minimum per chain, `price::gap_v3_config`)): v3 is
/// SUPPLY_SLICE only (owner 2026-10-31, as `PriceAttestorV3`) and its cap is at least that minimum.
pub fn check_terms_for(a: &LaunchV2Args, v3_min: Option<u32>) -> Result<()> {
    if v3_min.is_some() {
        require!(a.supply_mode == SUPPLY_SLICE, SplitterError::SupplyTotalNotInV3);
    }
    let min = v3_min.unwrap_or(crate::price::MIN_MARKET_CAP_USD);
    require!(a.fee_min > 0, SplitterError::FeeMinZero);
    require!(
        a.peer_fee_bps.len() == a.peers.len() && a.peer_fee_bps.iter().all(|f| (crate::MIN_FEE_BPS..=crate::MAX_FEE_BPS).contains(f)),
        SplitterError::FeeOutOfRange
    );
    require!(leg_eids(&a.peers).contains(&a.fee_eid), SplitterError::FeeChainNotALeg);
    require!(a.supply_mode == SUPPLY_SLICE || a.supply_mode == SUPPLY_TOTAL, SplitterError::UnknownSupplyMode);
    require!(
        (min..=crate::price::MAX_MARKET_CAP_USD).contains(&a.market_cap_usd),
        SplitterError::MarketCapOutOfRange
    );
    check_self_terms(a)
}

/// A creator self-launch's own rules, as EVM's `checkSelfLaunch` (BadTerms 11-13; 12's order and
/// count and 14's hash hold by the wire and the signature): `selfUntil` at least
/// `SELF_LAUNCH_TAKEOVER_MARGIN_S` before the snapshot's deadline; one entry per leg and at least
/// one leg flagged (a non-zero fee: option C's mask); each flagged EVM leg's payer named and
/// non-zero, the flagged Solana leg's the payment's; each unflagged leg's payer zero; and when not
/// every leg is flagged, the fee chain unflagged (EVM BadTerms 16). Nothing for any other launch.
pub fn check_self_terms(a: &LaunchV2Args) -> Result<()> {
    let Some(st) = &a.self_terms else { return Ok(()) };
    require!(st.self_until != 0, SplitterError::BadSelfTerms);
    require!((st.self_until as u64) + SELF_LAUNCH_TAKEOVER_MARGIN_S < a.price.deadline, SplitterError::BadSelfTerms);
    let eids = leg_eids(&a.peers);
    require!(st.fees.len() == eids.len(), SplitterError::BadSelfTerms);
    let mut flagged = 0usize;
    let mut fee_chain_flagged = false;
    for (eid, f) in eids.iter().zip(&st.fees) {
        let solana = *eid == SOLANA_EID;
        if !f.flagged() {
            match (solana, f.payer) {
                (true, None) => {}
                (false, Some(p)) => require!(p == [0u8; 20], SplitterError::BadSelfTerms),
                _ => return err!(SplitterError::BadSelfTerms),
            }
            continue;
        }
        flagged += 1;
        fee_chain_flagged |= *eid == a.fee_eid;
        match (solana, f.payer) {
            (true, None) => require!(f.fee_min <= u64::MAX as u128, SplitterError::BadSelfTerms),
            (false, Some(p)) => require!(p != [0u8; 20], SplitterError::BadSelfTerms),
            _ => return err!(SplitterError::BadSelfTerms),
        }
    }
    require!(flagged > 0, SplitterError::BadSelfTerms);
    require!(flagged == eids.len() || !fee_chain_flagged, SplitterError::BadSelfTerms);
    Ok(())
}

/* ------------------------------------------------------------------------------- the accounts */

/// `launch`'s accounts, as `launch_v2` and `launch_self` take them. The same roles in the same
/// order, but: the launcher's listing is optional (`launch_v2` needs it; `launch_self` names none);
/// the creator's quote account comes after the payment and is optional (only an asset dev buy out
/// of an allowance reads it); and after it, optional too, the dev-buy account's place, never
/// read. An optional account not given is the program's own id.
#[derive(Accounts)]
#[instruction(args: LaunchV2Args)]
pub struct LaunchV2<'info> {
    /// The launcher (`launch_v2`), or the creator (`launch_self`): pays all of the launch's rent.
    #[account(mut)]
    pub payer: Signer<'info>,

    /// The payer's listing, in `launch_v2`. None in `launch_self`.
    pub launcher: Option<Box<Account<'info, Launcher>>>,

    /// CHECK: who launched: the dev buy's owner and the launch's credit. A signer in `launch_self`
    /// (it is the payer) and whenever its dev buy is from its wallet. Writable, for what goes back
    /// to it.
    #[account(mut)]
    pub creator: UncheckedAccount<'info>,

    /// CHECK: as in `launch`.
    #[account(
        mut,
        seeds = [MINT_SEED, args.launch_seed.as_ref(), &args.mint_nonce.to_le_bytes()],
        bump,
        constraint = has_pangea_ending(&mint.key()) @ SplitterError::MintAddressLacksPangeaEnding
    )]
    pub mint: UncheckedAccount<'info>,
    /// CHECK: the slice's account (`launch_leg::TOKEN_A_SEED`): SUPPLY_TOTAL's whole total is
    /// minted into it and the other chains' share moved on to the escrow.
    #[account(mut, seeds = [TOKEN_A_SEED, args.launch_seed.as_ref()], bump)]
    pub token_a_account: UncheckedAccount<'info>,

    /// CHECK: as in `launch`.
    #[account(mut)]
    pub oft_store: UncheckedAccount<'info>,
    /// CHECK: as in `launch`.
    #[account(mut)]
    pub lz_receive_types: UncheckedAccount<'info>,
    /// CHECK: as in `launch`.
    #[account(mut, seeds = [ESCROW_SEED, args.launch_seed.as_ref()], bump)]
    pub escrow: UncheckedAccount<'info>,
    /// CHECK: as in `launch`.
    #[account(mut)]
    pub oapp_registry: UncheckedAccount<'info>,
    /// CHECK: as in `launch`.
    pub endpoint_event_authority: UncheckedAccount<'info>,
    /// CHECK: as in `launch`.
    #[account(mut, seeds = [AUTHORITY_SEED], bump)]
    pub authority: UncheckedAccount<'info>,

    /// The launch's record, with the v2 tail after its peers.
    #[account(
        init,
        payer = payer,
        space = 8 + LaunchRecord::INIT_SPACE + crate::launch_record_len(args.peers.len()) + crate::v2_tail_len(args.supply_mode),
        seeds = [SPLITTER_SEED, position_nft_mint.key().as_ref()],
        bump
    )]
    pub record: Box<Account<'info, LaunchRecord>>,
    /// CHECK: as in `launch`.
    #[account(seeds = [FEES_SEED], bump)]
    pub fee_owner: UncheckedAccount<'info>,

    /// CHECK: as in `launch`.
    #[account(mut, seeds = [POSITION_SEED, args.launch_seed.as_ref()], bump)]
    pub position_nft_mint: UncheckedAccount<'info>,
    /// CHECK: as in `launch`.
    #[account(mut)]
    pub position_nft_account: UncheckedAccount<'info>,
    /// CHECK: as in `launch`.
    pub pool_authority: UncheckedAccount<'info>,
    /// CHECK: as in `launch`.
    #[account(mut)]
    pub pool: UncheckedAccount<'info>,
    /// CHECK: as in `launch`.
    #[account(mut)]
    pub position: UncheckedAccount<'info>,
    /// CHECK: as in `launch`.
    pub quote_mint: UncheckedAccount<'info>,
    /// CHECK: as in `launch`.
    #[account(mut)]
    pub token_a_vault: UncheckedAccount<'info>,
    /// CHECK: as in `launch`.
    #[account(mut)]
    pub token_b_vault: UncheckedAccount<'info>,
    /// CHECK: the payer's quote account, which the pool's opening unit is drawn from: the
    /// launcher's own (`launch_v2`, as in `launch`), or the creator's own -- for wrapped SOL their
    /// associated account, made here when it is missing (`launch_self`).
    #[account(mut)]
    pub payer_token_b: UncheckedAccount<'info>,
    /// CHECK: as in `launch`.
    pub cp_amm_event_authority: UncheckedAccount<'info>,

    /// The launch's fee payment: required when the fee is due on Solana. As in `launch`.
    #[account(
        mut,
        constraint = fee.launch_id == launch_id_of(&args.launch_seed) @ SplitterError::NotThisLaunch,
        constraint = !fee.settled @ SplitterError::AlreadySettled
    )]
    pub fee: Option<Box<Account<'info, FeePayment>>>,
    /// CHECK: the creator's own account for an allowlisted asset, for a dev buy out of the
    /// allowance they gave AUTHORITY (`launch_v2`). Checked where it is read.
    #[account(mut)]
    pub creator_token_b: Option<UncheckedAccount<'info>>,
    /// CHECK: a v2 launch names none (the program's own id) and it is never read -- a reserve-era
    /// SUPPLY_TOTAL launch paid its dev buy into `PDA(["dev_buy", seed])` here. A v3 (gap fee)
    /// launch names `PDA(["gap_v3"])` here (`gap_v3_named`; audit r1 L-1, L-3): it is then hashed
    /// with the v3 terms and needs v3 launches enabled. Checked in `price::gap_v3_enabled`.
    /// READ-ONLY (Lead #3 I-3): nothing writes it, and the gap_v3 PDA is one account for every v3
    /// launch -- writable, it would write-lock every launch of a block onto it. Same place, same order.
    pub dev_buy_account: Option<UncheckedAccount<'info>>,
    /// CHECK: a SUPPLY_TOTAL launch's store's `TvlMark`, `PDA(["TvlMark", store])` under the OFT
    /// program: made by its `init_tvl`, once (`launch_leg::lock_in_escrow`). Checked there. (The
    /// place a SUPPLY_TOTAL launch's minter took before the lockbox.)
    #[account(mut)]
    pub tvl_mark: Option<UncheckedAccount<'info>>,

    pub token_program: Program<'info, Token>,
    /// CHECK: pinned.
    #[account(address = anchor_spl::token_2022::ID @ SplitterError::WrongProgram)]
    pub token_2022_program: UncheckedAccount<'info>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
    /// CHECK: pinned.
    #[account(address = OFT_PROGRAM_ID @ SplitterError::WrongProgram)]
    pub oft_program: UncheckedAccount<'info>,
    /// CHECK: pinned.
    #[account(address = LZ_ENDPOINT_ID @ SplitterError::WrongProgram)]
    pub endpoint_program: UncheckedAccount<'info>,
    /// CHECK: pinned.
    #[account(address = CP_AMM_ID @ SplitterError::WrongProgram)]
    pub cp_amm_program: UncheckedAccount<'info>,
    #[account(seeds = [crate::price::PRICE_SIGNER_SEED], bump = price_signer.bump)]
    pub price_signer: Box<Account<'info, crate::price::PriceSigner>>,
}

/// A v3 (gap fee) launch names `PDA(["gap_v3"])` in its `dev_buy_account` place: Some(the admin's
/// switch) then. Any other account there, or none, is a v2 launch exactly as before: None.
pub fn gap_v3_named(a: &LaunchV2) -> Option<bool> {
    gap_v3_named_config(a).map(|(enabled, _)| enabled)
}

/// `gap_v3_named` with the v3 minimum opening market cap per chain the account holds.
pub fn gap_v3_named_config(a: &LaunchV2) -> Option<(bool, u32)> {
    a.dev_buy_account.as_ref().and_then(|d| crate::price::gap_v3_config(d.as_ref()))
}

impl<'a, 'info> LaunchAccounts<'a, 'info> {
    pub fn of_v2(a: &'a LaunchV2<'info>) -> Self {
        LaunchAccounts {
            payer: a.payer.as_ref(),
            creator: a.creator.as_ref(),
            mint: a.mint.as_ref(),
            token_a_account: a.token_a_account.as_ref(),
            oft_store: a.oft_store.as_ref(),
            lz_receive_types: a.lz_receive_types.as_ref(),
            escrow: a.escrow.as_ref(),
            oapp_registry: a.oapp_registry.as_ref(),
            endpoint_event_authority: a.endpoint_event_authority.as_ref(),
            authority: a.authority.as_ref(),
            fee_owner: a.fee_owner.as_ref(),
            creator_token_b: a.creator_token_b.as_ref().map(|c| c.as_ref()),
            position_nft_mint: a.position_nft_mint.as_ref(),
            position_nft_account: a.position_nft_account.as_ref(),
            pool_authority: a.pool_authority.as_ref(),
            pool: a.pool.as_ref(),
            position: a.position.as_ref(),
            quote_mint: a.quote_mint.as_ref(),
            token_a_vault: a.token_a_vault.as_ref(),
            token_b_vault: a.token_b_vault.as_ref(),
            payer_token_b: a.payer_token_b.as_ref(),
            cp_amm_event_authority: a.cp_amm_event_authority.as_ref(),
            fee: a.fee.as_ref().map(|f| AsRef::<AccountInfo<'info>>::as_ref(&**f)),
            fee_payer: a.fee.as_ref().map(|f| f.payer),
            token_program: a.token_program.as_ref(),
            token_2022_program: a.token_2022_program.as_ref(),
            associated_token_program: a.associated_token_program.as_ref(),
            system_program: a.system_program.as_ref(),
            native_band: (a.price_signer.native_min_usd_per_quote, a.price_signer.native_max_usd_per_quote),
        }
    }
}

/// The v2 launch's terms, as its log states them: what the snapshot signed besides its price.
#[event]
pub struct LaunchedV2 {
    pub launch_id: [u8; 32],
    pub creator: Pubkey,
    pub payee: Pubkey,
    pub supply_mode: u8,
    pub market_cap_usd: u32,
    pub terms: [u8; 32],
    pub fee_eid: u32,
    pub fee_min: u64,
}

/* ---------------------------------------------------------------------------- the instruction */

/// The dev buy a self-launch against an allowlisted asset makes: `expected_dev_buy`, or what the
/// creator's own account for the asset holds less the one base unit the pool's opening draws,
/// whichever is less, swapped with the creator's own signature. None when that is nothing or the
/// pool cannot price or sell it.
fn check_payer_asset_dev_buy(a: &LaunchAccounts<'_, '_>, args: &LaunchArgs, liquidity: u128) -> Result<Option<DevBuy>> {
    if args.expected_dev_buy == 0 {
        return Ok(None);
    }
    let Some(account) = crate::read_token_account_view(&a.payer_token_b.try_borrow_data()?) else { return Ok(None) };
    let amount = args.expected_dev_buy.min(account.amount.saturating_sub(1));
    if amount == 0 {
        return Ok(None);
    }
    Ok(match buy_output(liquidity, args.init_sqrt_price, args.fee_bps, amount) {
        Some(expect) if expect.tokens > 0 && expect.sqrt_price <= crate::CP_AMM_MAX_SQRT_PRICE => Some(DevBuy::FromPayerAccount {
            amount,
            least: dev_buy_minimum(expect.tokens),
        }),
        _ => None,
    })
}

/// A self-launch against wrapped SOL: the account the pool's opening unit, and a dev buy, are
/// drawn from -- `PDA(["wsol", seed])`, a wrapped-SOL account of the creator's made here, given
/// `lamports` (the unit and the buy) out of the creator's wallet. Nothing of the creator's own (no
/// associated account of theirs) is needed or touched.
///
/// LEFT OPEN after the launch (owner, 2026-10-27): closing it here was one instruction, and that one
/// is what a SUPPLY_TOTAL self-launch with its public addresses pre-funded runs out of (65 of 64).
/// The account is a plain wrapped-SOL token account whose owner (authority) is the creator, holding
/// its rent-exempt minimum (2,039,280 lamports) and nothing else -- or, if somebody sent lamports
/// to its address first, those too, as its wrapped balance. The creator gets all of it back
/// whenever they like with the SPL Token program's `CloseAccount` (instruction 9), signed by
/// themselves, the destination any account of theirs: a native account may be closed holding a
/// balance, which goes with the rent. Nothing of this program's reads it again.
///
/// Made HOLDING the lamports -- its rent, the unit and the buy at once: the token program's
/// `InitializeAccount` counts what a native account holds above its rent as its balance, so no
/// transfer and no `sync_native` follow (two calls fewer, which a dusted launch spends). Lamports
/// somebody sent the address first count too: the account holds at least what the launch draws,
/// and what is left is the creator's, in the account, for when they close it.
#[inline(never)]
fn self_wrapped_sol<'info>(a: &LaunchAccounts<'_, 'info>, calls: &Calls<'_, 'info>, seed: &[u8; 32], lamports: u64) -> Result<()> {
    let (expected, bump) = Pubkey::find_program_address(&[SELF_WSOL_SEED, seed.as_ref()], &crate::ID);
    require_keys_eq!(a.payer_token_b.key(), expected, SplitterError::MissingQuoteAccount);
    let seeds: &[&[u8]] = &[SELF_WSOL_SEED, seed.as_ref(), &[bump]];
    make_token_account(a, calls, a.payer_token_b, seeds, &token::ID, lamports)?;
    token::initialize_account3(CpiContext::new(
        a.token_program.clone(),
        token::InitializeAccount3 { account: a.payer_token_b.clone(), mint: a.quote_mint.clone(), authority: a.creator.clone() },
    ))?;
    Ok(())
}

/// Allocate a token account at one of our addresses for `program`, paid by the payer, whether or
/// not somebody sent lamports there first, holding `above` lamports past its rent.
fn make_token_account<'info>(a: &LaunchAccounts<'_, 'info>, calls: &Calls<'_, 'info>, account: &AccountInfo<'info>, seeds: &[&[u8]], program: &Pubkey, above: u64) -> Result<()> {
    let rent = Rent::get()?.minimum_balance(crate::TOKEN_ACCOUNT_LEN).checked_add(above).ok_or(SplitterError::Overflow)?;
    let held = account.lamports();
    if held == 0 {
        invoke_signed(&system_instruction::create_account(&a.payer.key(), account.key, rent, crate::TOKEN_ACCOUNT_LEN as u64, program), calls.all, &[seeds])?;
    } else {
        require!(account.data_is_empty() && *account.owner == anchor_lang::system_program::ID, SplitterError::WrongDevBuyAccount);
        if held < rent {
            invoke_signed(&system_instruction::transfer(&a.payer.key(), account.key, rent - held), calls.all, &[])?;
        }
        invoke_signed(&system_instruction::allocate(account.key, crate::TOKEN_ACCOUNT_LEN as u64), calls.all, &[seeds])?;
        invoke_signed(&system_instruction::assign(account.key, program), calls.all, &[seeds])?;
    }
    Ok(())
}

#[inline(never)]
pub fn launch_v2_handler<'info>(ctx: Context<'_, '_, 'info, 'info, LaunchV2<'info>>, args: LaunchV2Args, self_launch: bool) -> Result<()> {
    // ---- who sends it
    {
        let a = &ctx.accounts;
        if self_launch {
            // The creator alone: the payer, the only signer, with no launcher named. A self-launch
            // needs nobody's listing because its seed is the creator's own.
            require!(a.launcher.is_none() && a.payer.key() == a.creator.key(), SplitterError::SelfLaunchSigner);
            // A creator self-launch across chains is sent here by our launcher (owner, option b).
            require!(args.self_terms.is_none(), SplitterError::SelfTermsNeedTheLauncher);
        } else {
            let listed = a.launcher.as_ref().ok_or(SplitterError::NotALauncher)?;
            let entry = Pubkey::create_program_address(&[LAUNCHER_SEED, a.payer.key().as_ref(), &[listed.bump]], &crate::ID)
                .map_err(|_| error!(SplitterError::NotALauncher))?;
            require!(listed.key() == entry && listed.launcher == a.payer.key(), SplitterError::NotALauncher);
            // The launcher's own quote account, as `launch` requires it.
            require!(!a.payer_token_b.data_is_empty(), SplitterError::MissingQuoteAccount);
        }
    }

    // ---- the arguments, the terms and the price, before anything is created
    // v3 or v2 is the signed snapshot's (audit r1 L-3): a v3 launch names PDA(["gap_v3"]), which also
    // holds the admin's v3 minimum opening market cap per chain (owner 2026-10-31).
    let v3_config = gap_v3_named_config(&ctx.accounts);
    let v3_min = v3_config.map(|(_, min)| min);
    let mut v1 = args.as_v1();
    check_launch_args_before_price(&v1)?;
    check_terms_for(&args, v3_min)?;
    let total = launch_total(&v1)?;
    let total_mode = args.supply_mode == SUPPLY_TOTAL;
    // Who pays the fee, as the terms name it: on Solana the payment's own payer -- so only that
    // payer's payment for this id counts, and a stranger's cannot stand in for it -- elsewhere the
    // address the launch states.
    // A self-launch whose Solana leg is flagged pays that leg here whatever the terms' fee chain
    // (its own fee, by its own payer: the payment's, hashed into the leg fees). An unflagged Solana
    // leg is the normal path: due here only when the fee chain is Solana.
    let fee_here = args.fee_due_here();
    if args.solana_leg_flagged() {
        // Before the hash, whose Solana leg payer is the payment's: no payment, no self-launch.
        require!(ctx.accounts.fee.is_some(), SplitterError::LaunchUnpaid);
    }
    let payment_payer: [u8; 32] = match ctx.accounts.fee.as_ref() {
        Some(f) => f.payer.to_bytes(),
        None => [0u8; 32],
    };
    let payer: [u8; 32] = if args.fee_eid == SOLANA_EID {
        ctx.accounts.fee.as_ref().ok_or(SplitterError::LaunchUnpaid)?.payer.to_bytes()
    } else {
        let evm = args.payer.ok_or(SplitterError::LaunchUnpaid)?;
        let mut padded = [0u8; 32];
        padded[12..].copy_from_slice(&evm);
        padded
    };
    require!(payer != [0u8; 32], SplitterError::ZeroAddress);
    // And what else the terms bind (Solana audit round 1): the name, symbol and URI; the Solana
    // creator -- so a seed that leaks cannot be launched by anybody else, as themselves; and the
    // quote asset, so a snapshot priced for one asset cannot open a pool against another.
    // v3 or v2 is the signed snapshot's (audit r1 L-3): a v3 launch names PDA(["gap_v3"]) and its
    // terms carry the version word, so a signature made for one version never verifies as the
    // other. v3 launches also need the admin's switch (L-1: its own account, PriceSigner untouched).
    let v3_switch = v3_config.map(|(enabled, _)| enabled);
    require!(v3_switch != Some(false), SplitterError::GapV3NotEnabled);
    let v3_store = v3_switch.is_some();
    let terms = args.terms_for(
        &crate::price::TermsBinding {
            payer,
            metadata: args.metadata()?,
            creator_solana: ctx.accounts.creator.key().to_bytes(),
            quote_solana: ctx.accounts.quote_mint.key().to_bytes(),
        },
        &payment_payer,
        v3_store,
    );
    let quote = resolve_quote(&LaunchAccounts::of_v2(&ctx.accounts), ctx.remaining_accounts)?;
    {
        let a = &ctx.accounts;
        let quote_decimals = *a.quote_mint.try_borrow_data()?.get(44).ok_or(error!(SplitterError::QuoteAssetUnsupported))?;
        let peers = v1.peers.pairs();
        let snapshot = V2Price {
            price: &args.price,
            terms: SnapshotTerms { market_cap_usd: args.market_cap_usd, supply_mode: args.supply_mode, terms },
            min_market_cap_usd: v3_min.unwrap_or(crate::price::MIN_MARKET_CAP_USD),
        };
        v1.init_sqrt_price = crate::price::verified_opening_price_v2(
            &snapshot,
            &a.price_signer.address,
            &launch_id_of(&args.launch_seed),
            args.fee_bps,
            &args.peer_fee_bps,
            &peers,
            &a.oft_store.key(),
            args.slice,
            quote_decimals,
            quote.usd_band,
            Clock::get()?.unix_timestamp,
        )?;
    }
    check_launch_args(&v1)?;
    let liquidity = launch_liquidity(&v1)?;
    // ---- the fee (D5): due here, a payment holding at least `fee_min`; due elsewhere, a payment
    // only as the creator's own, for a dev buy. Then what it holds above the fee, as `launch`.
    let above_fee = match ctx.accounts.fee.as_ref() {
        Some(fee) => {
            require!(Clock::get()?.unix_timestamp < crate::settleable_until(fee.at), SplitterError::PaymentTooOldToSettle);
            if fee_here {
                // The fee due here: the terms' `fee_min`, or a self-launch's Solana leg fee.
                require!(fee.amount >= v1.launch_fee && v1.launch_fee > 0, SplitterError::LaunchUnpaid);
            } else {
                require_keys_eq!(fee.payer, ctx.accounts.creator.key(), SplitterError::PaymentNotTheCreators);
            }
            fee.amount - v1.launch_fee
        }
        None => {
            require!(!fee_here, SplitterError::LaunchUnpaid);
            0
        }
    };
    let creator_signs = ctx.accounts.creator.is_signer;
    // Every dev buy, in every asset and from every source, is bound to the creator's OWN payment
    // for this launch id, as v1's are: without it, no buy is made.
    let bound = ctx.accounts.fee.as_ref().map(|f| f.payer) == Some(ctx.accounts.creator.key());
    let (excess, dev_buy) = {
        let leg = LaunchAccounts::of_v2(&ctx.accounts);
        let mut excess = match (above_fee > 0, creator_signs) {
            (false, _) => Excess::Nothing,
            // A creator who signs buys from their wallet, never from a payment: theirs goes back.
            (true, true) => excess_back_to_creator(&leg, above_fee)?,
            (true, false) => check_dev_buy(&leg, &v1, above_fee, liquidity, false)?,
        };
        // What is not bought goes back: a buy out of a payment that is not the creator's own (a
        // tokenomics account's owner's: `check_dev_buy` already buys nothing then; held here too,
        // so no `buy` is ever left in the payment to be swept to the admin as fee).
        if !bound {
            if let Excess::Creators { buy, back, .. } = excess {
                excess = Excess::Creators { buy: 0, least: 0, back: back.checked_add(buy).ok_or(SplitterError::Overflow)? };
            }
        }
        let dev_buy = match excess {
            _ if !bound => None,
            Excess::Creators { buy, least, .. } if buy > 0 => Some(DevBuy::FromPayment { lamports: buy, least }),
            _ if !quote.native && self_launch => check_payer_asset_dev_buy(&leg, &v1, liquidity)?,
            _ if !quote.native => check_asset_dev_buy(&leg, &v1, &quote, liquidity, true)?,
            _ if creator_signs => check_wallet_dev_buy(&leg, &v1, liquidity),
            _ => None,
        };
        (excess, dev_buy)
    };

    // ---- the launch
    let record_key = ctx.accounts.record.key();
    let locked = {
        let mut all = ctx.accounts.to_account_infos();
        all.extend_from_slice(ctx.remaining_accounts);
        let calls = Calls { all: &all };
        let a = &ctx.accounts;
        let leg = LaunchAccounts::of_v2(a);
        let seed = args.launch_seed;
        let mint_nonce = args.mint_nonce.to_le_bytes();
        let mint_seeds: &[&[u8]] = &[MINT_SEED, seed.as_ref(), &mint_nonce, &[ctx.bumps.mint]];
        let escrow_seeds: &[&[u8]] = &[ESCROW_SEED, seed.as_ref(), &[ctx.bumps.escrow]];
        let nft_seeds: &[&[u8]] = &[POSITION_SEED, seed.as_ref(), &[ctx.bumps.position_nft_mint]];
        let fee_owner_seeds: &[&[u8]] = &[FEES_SEED, &[ctx.bumps.fee_owner]];
        let token_a_seeds: &[&[u8]] = &[TOKEN_A_SEED, seed.as_ref(), &[ctx.bumps.token_a_account]];

        // The slice -- or, SUPPLY_TOTAL, the whole total -- minted by the payer, the mint's
        // authority for the length of this instruction. Then the store: a Native one, given the
        // mint's authority by `wire_bridge` -- or, SUPPLY_TOTAL, an Adapter (the LOCKBOX), into
        // whose escrow the other chains' share is moved and locked, the mint's authority revoked
        // for good (`lock_in_escrow`).
        create_token(&leg, &calls, &v1, if total_mode { total } else { v1.slice }, mint_seeds, token_a_seeds)?;
        // Pangea v3 gap fee: a v3 store when the launch was signed and sent as v3 (`v3_store` above).
        wire_bridge(&leg, &calls, &v1, escrow_seeds, ctx.bumps.authority, (!total_mode).then_some(a.oft_store.key()), total_mode, v3_store)?;
        if total_mode {
            let mark = a.tvl_mark.as_ref().ok_or(SplitterError::LockboxMarkNotGiven)?;
            lock_in_escrow(&leg, &calls, mark.as_ref(), total - v1.slice, ctx.bumps.authority)?;
        }
        // A self-launch against wrapped SOL: the creator's lamports for the opening unit and the
        // buy, wrapped in an account of the seed's; the buy is then a plain swap out of it.
        let made_wsol = self_launch && quote.native;
        let dev_buy = match dev_buy {
            Some(DevBuy::FromWallet { lamports, least }) if made_wsol => Some(DevBuy::FromPayerAccount { amount: lamports, least }),
            d => d,
        };
        if made_wsol {
            let buy = match dev_buy {
                Some(DevBuy::FromPayerAccount { amount, .. }) => amount,
                _ => 0,
            };
            self_wrapped_sol(&leg, &calls, &seed, buy.checked_add(1).ok_or(SplitterError::Overflow)?)?;
        }

        // The slice's account holds the slice alone once the lock is out of it, in either mode: a
        // dev buy is paid into it and it becomes the creator's, as v1's rule has it.
        let finish = Finish { buy_into: leg.token_a_account, may_remain: MAX_UNPOOLED, keep_for: None };
        let plan = PoolPlan { liquidity, quote, authority_bump: ctx.bumps.authority };
        let locked = open_pool(&leg, &calls, &v1, nft_seeds, fee_owner_seeds, dev_buy, &plan, &finish)?;
        // A self-launch's wrapped-SOL account is left open, the creator's to close (`self_wrapped_sol`).
        locked
    };

    // ---- the record: the PAYEE is paid; the creator, in the tail, launched
    let creator = ctx.accounts.creator.key();
    let payee = args.payee_solana.unwrap_or(creator);
    // A payee the launch is given the account of -- its creator -- is held to its owner as
    // `admin_set_payee` holds one (audit round 6): no account of the token programs, cp-amm, the
    // OFT program or LayerZero's endpoint, and a tokenomics account only one made for this launch
    // and only when the pool pairs against wrapped SOL, the one asset it is paid in. A separate
    // `payee_solana` is not in the transaction (a self-launch has no room for it) and may not exist
    // yet; it is held at claim time instead: `claim_fees` never pays an account of this program
    // outside wrapped SOL (`PayeeCannotSpendAsset`), and `claim_fees_native` keeps the share of one
    // that cannot hold it pending (`can_hold`), for the admin to move.
    if payee == creator {
        let native = ctx.accounts.quote_mint.key() == anchor_spl::token::spl_token::native_mint::ID;
        require!(payee_owner_allowed(&ctx.accounts.creator, &args.launch_seed, &record_key, native), SplitterError::PartyIsSplitter);
    }
    let nft_key = ctx.accounts.position_nft_mint.key();
    {
        let r = &mut ctx.accounts.record;
        r.creator = payee;
        r.pending_creator = Pubkey::default();
        r.position = ctx.accounts.position.key();
        r.position_nft_mint = nft_key;
        r.quote_mint = ctx.accounts.quote_mint.key();
        r.fee_bps = args.fee_bps;
        r.venue_lp_share_bps = crate::venue::VENUE_LP_SHARE_BPS;
        r.bump = ctx.bumps.record;
        r.dev_buy_made = dev_buy.is_some();
    }
    // Every address this program holds or this launch made (Solana audit A1 L-1): a fee stream
    // paid to one of them could be spent by whoever cranks it, or by nobody.
    // And this program's own accounts the launch is handed (Solana audit round 2, A L-1): its fee
    // payment -- settled here, then swept to the admin by `withdraw_fee` -- the price signer and the
    // launcher's listing. Any other account of this program's is caught when a claim would pay it
    // (`fees::can_hold`): its share waits for the admin.
    let a = &ctx.accounts;
    let mut held = v2_held(&record_key, &a.quote_mint.key(), &args.launch_seed);
    held.extend([crate::tvl_mark_of(&a.oft_store.key()), a.fee_owner.key(), a.authority.key(), a.token_a_account.key(), a.escrow.key(), a.oft_store.key(), a.mint.key(), a.pool.key(), a.position.key(), a.position_nft_mint.key(), a.position_nft_account.key(), a.token_a_vault.key(), a.token_b_vault.key(), a.lz_receive_types.key(), a.oapp_registry.key(), a.price_signer.key()]);
    held.extend(a.fee.as_ref().map(|f| f.key()));
    held.extend(a.launcher.as_ref().map(|l| l.key()));
    crate::check_parties(&payee, &ADMIN, &held)?;
    {
        let info = ctx.accounts.record.to_account_info();
        let mut data = info.try_borrow_mut_data()?;
        let at = crate::LAUNCHED_SLOT_AT;
        data[at..at + crate::LAUNCH_RECORD_LEN].copy_from_slice(&Clock::get()?.slot.to_le_bytes());
        crate::write_peer_record(&mut data, &v1.peers.0);
        let tail_at = crate::peer_record_end(&data).ok_or(SplitterError::NotThisLaunch)?;
        // SUPPLY_TOTAL: the lockbox -- the store's escrow in the reserve's place and no minter
        // (`ReserveV2::is_lockbox`). `rebalance` refuses it.
        let reserve = total_mode.then_some(ReserveV2 { total, reserve: ctx.accounts.escrow.key(), minter: Pubkey::default(), reserve_bump: 0, minter_bump: 0 });
        crate::write_v2_tail(&mut data, tail_at, &V2Tail { creator, supply_mode: args.supply_mode, market_cap_usd: args.market_cap_usd, reserve, pending_native: 0 });
    }

    // ---- the payment, settled as `launch` settles it
    if let Some(fee) = ctx.accounts.fee.as_mut() {
        let mut settle = true;
        if let Excess::Creators { back, .. } = excess {
            let creator_info = ctx.accounts.creator.to_account_info();
            if back == 0 || can_take_back(&creator_info, back)? {
                let payment = fee.to_account_info();
                **payment.try_borrow_mut_lamports()? -= back;
                **creator_info.try_borrow_mut_lamports()? += back;
                fee.amount = v1.launch_fee;
            } else if fee_here {
                fee.amount = v1.launch_fee + back;
            } else {
                // The fee due elsewhere (factory v2 audit round 8, L): nothing of this payment is a
                // fee, so a refund the creator's wallet cannot take yet is not settled as one. The
                // payment stays UNSETTLED, holding the refund, which is the creator's: `reclaim_fee`
                // (their signature, after `RECLAIM_AFTER`) or the admin's `refund_fee` closes it to
                // them; `withdraw_fee` takes only a settled payment. It cannot pay for another
                // launch: this launch's id is spent (its record exists).
                fee.amount = back;
                settle = false;
            }
        }
        // The fee due elsewhere (audit round 7, I): this payment was the creator's own and carried
        // only a dev buy. What it holds now is its rent, which no fee is owed from: closed, to the
        // creator who put it up (`fee.payer` is the creator, checked above), rather than left for
        // `withdraw_fee` to sweep to the admin. A refund the creator could not take is left with it,
        // unsettled (above).
        if settle {
            fee.settled = true;
            emit!(crate::FeeSettled { launch_id: fee.launch_id, payer: fee.payer, lamports: fee.amount });
        }
        if settle && !fee_here && fee.amount == 0 {
            let creator_info = ctx.accounts.creator.to_account_info();
            if can_take_back(&creator_info, fee.to_account_info().lamports())? {
                fee.close(creator_info)?;
            }
        }
    }

    let id = launch_id_of(&args.launch_seed);
    emit!(LaunchedV2 {
        launch_id: id,
        creator,
        payee,
        supply_mode: args.supply_mode,
        market_cap_usd: args.market_cap_usd,
        terms,
        fee_eid: args.fee_eid,
        fee_min: args.fee_min,
    });
    emit!(crate::LaunchedOnSolana {
        launch_id: id,
        mint: ctx.accounts.mint.key(),
        oft_store: ctx.accounts.oft_store.key(),
        pool: ctx.accounts.pool.key(),
        position: ctx.accounts.position.key(),
        splitter: record_key,
        creator,
        fee_bps: args.fee_bps,
        locked_liquidity: locked,
    });
    Ok(())
}

/// The program's own addresses a v2 launch's payee may not be, derivable from its record, quote
/// and seed: the record, the platform record, the program's fee account for the quote, the native
/// claim's temporary account, the minter, the dev-buy account and the self-launch's wrapped SOL.
/// (`launch_v2` adds the launch's other accounts; `admin_set_payee` checks these.)
pub fn v2_held(record: &Pubkey, quote_mint: &Pubkey, seed: &[u8; 32]) -> Vec<Pubkey> {
    let at = |s: &[&[u8]]| Pubkey::find_program_address(s, &crate::ID).0;
    vec![
        *record,
        at(&[crate::PLATFORM_SEED]),
        at(&[crate::FEES_SEED]),
        at(&[crate::FEES_SEED, quote_mint.as_ref()]),
        at(&[crate::UNWRAP_SEED, record.as_ref()]),
        minter_of(record).0,
        at(&[DEV_BUY_SEED, seed.as_ref()]),
        at(&[SELF_WSOL_SEED, seed.as_ref()]),
        at(&[TOKEN_A_SEED, seed.as_ref()]),
        at(&[AUTHORITY_SEED]),
        at(&[crate::price::PRICE_SIGNER_SEED]),
        crate::native_transit(),
    ]
}

/* --------------------------------------------------------------------------- admin_set_payee */

#[derive(Accounts)]
#[instruction(launch_seed: [u8; 32], to: Pubkey)]
pub struct AdminSetPayee<'info> {
    #[account(mut, seeds = [SPLITTER_SEED, record.position_nft_mint.as_ref()], bump = record.bump)]
    pub record: Box<Account<'info, LaunchRecord>>,
    #[account(address = ADMIN @ SplitterError::NotAdmin)]
    pub admin: Signer<'info>,
    /// CHECK: the new payee, `to`, read only for who owns it (`payee_owner_allowed`).
    #[account(address = to @ SplitterError::NotThisLaunch)]
    pub payee: UncheckedAccount<'info>,
}

/// Whether an account owned by `owner` may be a v2 launch's payee (`admin_set_payee`, and the
/// launch's own creator when it is the payee): not one of the programs that own a launch's own
/// accounts -- the token programs (its mint, reserve, minter, dev-buy account, the pool's vaults,
/// the position's NFT account), Meteora (its pool and position), the OFT program and LayerZero's
/// endpoint (its store and LayerZero accounts): `fees::owner_refused` -- nor this program's, but for
/// a tokenomics account made for this launch, and only when the launch pairs against wrapped SOL
/// (`native`): `claim_fees_native` pays it in wrapped SOL into its vault (`fees::tokenomics_vault`),
/// and it can move no other asset (`bind` needs a wrapped-SOL pool; audit round 6, L). A wallet, a
/// PDA that holds nothing yet, the incinerator, or another program's account may be.
fn payee_owner_allowed(payee: &AccountInfo, launch_seed: &[u8; 32], record: &Pubkey, native: bool) -> bool {
    let owner = *payee.owner;
    if owner == crate::ID {
        let Ok(data) = payee.try_borrow_data() else { return false };
        return native
            && match crate::Tokenomics::try_deserialize(&mut &data[..]) {
                Ok(t) => t.launch_id == launch_id_of(launch_seed) && (!t.bound || t.record == *record),
                // A v2 account (`tokenomics_v2`) by the same rule.
                Err(_) => crate::TokenomicsV2::try_deserialize(&mut &data[..]).is_ok_and(|t| t.launch_id == launch_id_of(launch_seed) && (!t.bound || t.record == *record)),
            };
    }
    !crate::fees::owner_refused(&owner)
}

/// Point a v2 launch's fee stream at `to` directly, as the admin (D10: only the admin moves a v2
/// payee). For a payee that cannot sign, which `admin_propose_creator` and `accept_creator` cannot
/// reach: a tokenomics account made for this launch -- paid in wrapped SOL into its vault by
/// `claim_fees_native`, once bound to this launch, and owed until then -- or another program's
/// PDA, paid lamports when it can hold them. `launch_seed` names the launch so the payee can be
/// held to the addresses `launch_v2` refuses: by address those it derives or the record names
/// (`v2_held`, the store, the escrow, the position and its NFT mint) -- which may not exist yet --
/// and every other by its owner (`payee_owner_allowed`: the mint, the pool, its vaults, the NFT
/// account, LayerZero's accounts, a fee payment, a listing). Anything pending for
/// the old payee goes with the stream.
pub fn admin_set_payee_handler(ctx: Context<AdminSetPayee>, launch_seed: [u8; 32], to: Pubkey) -> Result<()> {
    let record_key = ctx.accounts.record.key();
    require_keys_eq!(crate::splitter_of_launch(&launch_seed), record_key, SplitterError::NotThisLaunch);
    {
        let info = ctx.accounts.record.to_account_info();
        let data = info.try_borrow_data()?;
        crate::read_v2_tail(&data).ok_or(SplitterError::NotV2Record)?;
    }
    let r = &ctx.accounts.record;
    let store = crate::store_of_launch(&launch_seed);
    let mut held = v2_held(&record_key, &r.quote_mint, &launch_seed);
    held.extend([
        store,
        Pubkey::find_program_address(&[ESCROW_SEED, launch_seed.as_ref()], &crate::ID).0,
        r.position,
        r.position_nft_mint,
    ]);
    crate::check_parties(&to, &ADMIN, &held)?;
    let native = r.quote_mint == anchor_spl::token::spl_token::native_mint::ID;
    require!(payee_owner_allowed(&ctx.accounts.payee, &launch_seed, &record_key, native), SplitterError::PartyIsSplitter);
    let r = &mut ctx.accounts.record;
    let from = r.creator;
    r.creator = to;
    r.pending_creator = Pubkey::default();
    emit!(crate::AdminProposedCreator { record: record_key, admin: ADMIN, from, to });
    emit!(crate::CreatorChanged { record: record_key, from, to });
    Ok(())
}

/* ------------------------------------------------------------------------------ add_peer_v2 */

#[derive(Accounts)]
pub struct AddPeerV2<'info> {
    /// CHECK: a v2 launch's record: this program's, read and grown in the handler.
    #[account(mut, owner = crate::ID @ SplitterError::NotThisLaunch)]
    pub record: UncheckedAccount<'info>,
    #[account(mut, address = ADMIN @ SplitterError::NotAdmin)]
    pub admin: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[event]
pub struct PeerAddedV2 {
    pub record: Pubkey,
    pub eid: u32,
    pub token: [u8; 20],
}

/// Record one more peer for a v2 launch: a chain of `PEER_CHAINS` it does not name yet, and the
/// token's address there. Inserted in its place (ascending), the v2 tail moved along by one entry;
/// no recorded peer changes. `open_bridge` then opens the route to it as to any other.
pub fn add_peer_v2_handler(ctx: Context<AddPeerV2>, eid: u32, token: [u8; 20]) -> Result<()> {
    require!(token != [0u8; 20], SplitterError::ZeroAddress);
    let eid16 = u16::try_from(eid).map_err(|_| error!(SplitterError::PeerNotAddable))?;
    require!(PEER_CHAINS.contains(&eid16), SplitterError::PeerNotAddable);
    let info = ctx.accounts.record.to_account_info();
    let (old_len, insert_at) = {
        let data = info.try_borrow_data()?;
        require!(data.get(..8) == Some(&<LaunchRecord as anchor_lang::Discriminator>::discriminator()[..]), SplitterError::NotThisLaunch);
        crate::read_v2_tail(&data).ok_or(SplitterError::NotV2Record)?;
        let at = crate::PEER_RECORD_AT;
        let count = data[at + 20] as usize;
        require!(count < u8::MAX as usize, SplitterError::PeerNotAddable);
        let entries = &data[at + crate::PEER_RECORD_HEAD..at + crate::PEER_RECORD_HEAD + crate::PEER_ENTRY_LEN * count];
        let mut place = count;
        for (i, e) in entries.chunks(crate::PEER_ENTRY_LEN).enumerate() {
            let recorded = u16::from_le_bytes([e[0], e[1]]);
            require!(recorded != eid16, SplitterError::PeerNotAddable);
            if recorded > eid16 && place == count {
                place = i;
            }
        }
        (data.len(), at + crate::PEER_RECORD_HEAD + crate::PEER_ENTRY_LEN * place)
    };
    let new_len = old_len + crate::PEER_ENTRY_LEN;
    // What the record holds above its rent is the payees' pending ledger, not rent: it is not spent.
    let pending = {
        let data = info.try_borrow_data()?;
        crate::read_v2_tail(&data).map(|t| t.pending_native).unwrap_or(0)
    };
    let more = Rent::get()?.minimum_balance(new_len).saturating_add(pending).saturating_sub(info.lamports());
    if more > 0 {
        anchor_lang::system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::Transfer { from: ctx.accounts.admin.to_account_info(), to: info.clone() },
            ),
            more,
        )?;
    }
    info.realloc(new_len, false)?;
    {
        let mut data = info.try_borrow_mut_data()?;
        data.copy_within(insert_at..old_len, insert_at + crate::PEER_ENTRY_LEN);
        data[insert_at..insert_at + 2].copy_from_slice(&eid16.to_le_bytes());
        data[insert_at + 2..insert_at + crate::PEER_ENTRY_LEN].copy_from_slice(&token);
        data[crate::PEER_RECORD_AT + 20] += 1;
        require!(crate::read_v2_tail(&data).is_some(), SplitterError::NotV2Record);
    }
    emit!(PeerAddedV2 { record: info.key(), eid, token });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn sample() -> LaunchV2Args {
        LaunchV2Args {
            launch_seed: { let mut s = [0u8; 32]; s[..V2_SEED_LEN].fill(7); s },
            mint_nonce: 0x02_0304,
            name: "N".repeat(32),
            symbol: "S".repeat(10),
            uri_form: crate::CID_V1_DAG_PB,
            uri_digest: [9; 32],
            supply_mode: SUPPLY_TOTAL,
            fee_bps: 100,
            peer_fee_bps: vec![30, 250, 500, 75],
            slice: 1_000_000_000_000_000_000,
            expected_dev_buy: 5,
            market_cap_usd: 15_000,
            payee_evm: [0xee; 20],
            payee_solana: Some(Pubkey::new_from_array([0x55; 32])),
            fee_eid: SOLANA_EID,
            fee_min: 12_345,
            payer: None,
            peers: Peers(PEER_CHAINS.iter().map(|e| (*e, [*e as u8; 20])).collect()),
            price: SignedPriceV2 { deadline: 1_800_000_000, usd_per_quote: vec![2_500 * crate::WAD; PEER_CHAINS.len() + 1], signature: { let mut s = vec![0x11u8; 65]; s[32] = 0x22; s[64] = 28; s } },
            self_terms: None,
        }
    }

    fn wire(a: &LaunchV2Args) -> Vec<u8> {
        let mut out = Vec::new();
        a.serialize(&mut out).unwrap();
        out
    }

    #[test]
    fn the_wire_form_round_trips_and_is_as_long_as_documented() {
        let a = sample();
        let w = wire(&a);
        let legs = PEER_CHAINS.len() + 1;
        assert_eq!(w.len(), 16 + 3 + 33 + 11 + 1 + 32 + 5 + 5 + 3 + 20 + 32 + 5 + 1 + 20 * PEER_CHAINS.len() + 6 + 4 + 4 * legs + 64);
        assert_eq!(LaunchV2Args::deserialize(&mut w.as_slice()).unwrap(), a);
        // The fees: nine bits a leg, legs ascending (Solana's 100 third, between 30102 and 30184).
        assert_eq!(a.leg_fees().unwrap(), vec![30, 250, 100, 500, 75]);
        let at = w.len() - 64 - 4 * legs - 4 - 6;
        assert_eq!(crate::price::decode_fees(&w[at..at + 6], legs).unwrap(), vec![30, 250, 100, 500, 75]);
        // A bit past the last fee is not a wire form.
        let mut x = w.clone();
        x[at + 5] |= 0x80;
        assert!(LaunchV2Args::deserialize(&mut x.as_slice()).is_err());
        // Every fee a chain takes travels, on every leg.
        for f in [30u16, 31, 255, 256, 499, 500, 511] {
            for i in 0..PEER_CHAINS.len() {
                let mut b = a.clone();
                b.peer_fee_bps[i] = f;
                b.fee_bps = 530 - f;
                assert_eq!(LaunchV2Args::deserialize(&mut wire(&b).as_slice()).unwrap(), b, "{f} on peer {i}");
            }
        }
        let mut b = a.clone();
        b.peer_fee_bps[2] = 512;
        assert!(b.serialize(&mut Vec::new()).is_err(), "a fee past nine bits");
        let mut b = a.clone();
        b.peer_fee_bps.pop();
        assert!(b.serialize(&mut Vec::new()).is_err(), "a peer without a fee");
        // One address for every chain: twenty bytes, once.
        let mut shared = a.clone();
        shared.peers = Peers(PEER_CHAINS.iter().map(|e| (*e, [0xab; 20])).collect());
        shared.payee_solana = None;
        let ws = wire(&shared);
        assert_eq!(ws.len(), w.len() - 32 - 20 * (PEER_CHAINS.len() - 1));
        assert_eq!(LaunchV2Args::deserialize(&mut ws.as_slice()).unwrap(), shared);
        // The fee on each leg, by its place.
        for (i, eid) in leg_eids(&a.peers).iter().enumerate() {
            let mut b = a.clone();
            b.fee_eid = *eid;
            b.payer = (*eid != SOLANA_EID).then_some([0x77; 20]);
            let wb = wire(&b);
            assert_eq!((wb[16 + 3 + 33 + 11] >> FEE_LEG_SHIFT) as usize, i);
            assert_eq!(LaunchV2Args::deserialize(&mut wb.as_slice()).unwrap(), b);
        }
        // What the form cannot say.
        let mut b = a.clone();
        b.fee_eid = 1;
        assert!(b.serialize(&mut Vec::new()).is_err(), "a fee chain that is not a leg");
        let mut b = a.clone();
        b.price.usd_per_quote[0] = (1u128 << 27) + 1;
        assert!(b.serialize(&mut Vec::new()).is_err(), "a price needing more than 32 bits of mantissa");
        let mut b = a.clone();
        b.launch_seed[31] = 1;
        assert!(b.serialize(&mut Vec::new()).is_err(), "a seed past sixteen bytes");
        // The top bit of the flags is refused (factory v3's moon, never shipped; live launch_v2
        // refuses it too). A fee place past the legs, a peer bit past the list.
        let flags = 16 + 3 + 33 + 11;
        let mut x = w.clone();
        x[flags] |= 1 << 7;
        assert!(LaunchV2Args::deserialize(&mut x.as_slice()).is_err(), "flag bit 7");
        let mut x = w.clone();
        x[flags] |= 7 << FEE_LEG_SHIFT;
        assert!(LaunchV2Args::deserialize(&mut x.as_slice()).is_err());
        let mut x = w.clone();
        x[flags] |= 3;
        assert!(LaunchV2Args::deserialize(&mut x.as_slice()).is_err(), "URI form code 3");
    }

    #[test]
    fn prices_and_signatures_travel_compact_and_come_back_exact() {
        for v in [1u128, 2_500 * crate::WAD, 200 * crate::WAD, 3_000_123_400_000_000_000_000, (1u128 << 27) - 1, 12_345_678 * 10u128.pow(20)] {
            let e = crate::price::encode_usd_per_quote(v).unwrap();
            assert_eq!(crate::price::decode_usd_per_quote(&e), Some(v), "{v}");
        }
        assert!(crate::price::encode_usd_per_quote((1u128 << 27) * 10 + 1).is_none());
        for v in [0u64, 1, 200_000_000_000_000_000, 500_000_000, 12_300_000_000_000_000, u32::MAX as u64, u64::MAX / 10_000_000_000 * 10_000_000_000] {
            let e = crate::price::encode_amount(v);
            if let Some(e) = e {
                assert_eq!(crate::price::decode_amount(&e), Some(v), "{v}");
            }
        }
        assert!(crate::price::encode_amount(123_456_789_012).is_none(), "twelve digits");
        assert_eq!(crate::price::decode_usd_per_quote(&((1u32 << 5) | 31).to_le_bytes()).map(|v| v > 0), Some(true));
        assert_eq!(crate::price::decode_amount(&[255, 1, 0, 0, 0]), None, "10^255 does not fit");
        let mut sig = [0x33u8; 65];
        sig[32] = 0x7f;
        for v in [27u8, 28] {
            sig[64] = v;
            assert_eq!(crate::price::widen_signature(&crate::price::compact_signature(&sig).unwrap()), sig);
        }
        sig[32] = 0x80;
        assert!(crate::price::compact_signature(&sig).is_none(), "a high s has no compact form");
    }

    #[test]
    fn the_fee_wire_is_nine_bits_a_leg() {
        for legs in 0..=8usize {
            assert_eq!(crate::price::fees_wire_len(legs), (9 * legs).div_ceil(8));
            let fees: Vec<u16> = (0..legs).map(|i| [30u16, 100, 250, 500, 75, 511, 0, 300][i]).collect();
            let w = crate::price::encode_fees(&fees).unwrap();
            assert_eq!(crate::price::decode_fees(&w, legs).unwrap(), fees);
            assert!(crate::price::decode_fees(&w, legs + 1).is_none() || crate::price::fees_wire_len(legs + 1) == w.len());
        }
        // 30, 100, 250, 500, 75 -- bit by bit, least significant first.
        assert_eq!(crate::price::encode_fees(&[30, 100, 250, 500, 75]).unwrap(), vec![0x1e, 0xc8, 0xe8, 0xa3, 0xbf, 0x04]);
        assert!(crate::price::encode_fees(&[512]).is_none());
    }

    #[test]
    fn the_terms_are_checked_before_anything_is_created() {
        assert!(check_terms(&sample()).is_ok());
        for (i, f) in [(0usize, 29u16), (3, 501), (1, 0)] {
            let mut a = sample();
            a.peer_fee_bps[i] = f;
            assert!(check_terms(&a).is_err(), "a peer fee of {f}");
        }
        let mut a = sample();
        a.peer_fee_bps.push(100);
        assert!(check_terms(&a).is_err(), "more fees than peers");
        let mut a = sample();
        a.fee_min = 0;
        assert!(check_terms(&a).is_err());
        let mut a = sample();
        a.fee_eid = 30110;
        assert!(check_terms(&a).is_err());
        for cap in [0, 2_999, 500_001, u32::MAX] {
            let mut a = sample();
            a.market_cap_usd = cap;
            assert!(check_terms(&a).is_err(), "{cap}");
        }
        for cap in [3_000, 500_000] {
            let mut a = sample();
            a.market_cap_usd = cap;
            assert!(check_terms(&a).is_ok(), "{cap}");
        }
    }

    /// v3 (owner 2026-10-31): the admin's minimum per chain, SUPPLY_SLICE only; v2 unchanged.
    #[test]
    fn a_v3_launch_is_held_to_the_admins_minimum_and_slice_only() {
        let at = |cap: u32, mode: u8, v3_min: Option<u32>| {
            let mut a = sample();
            a.market_cap_usd = cap;
            a.supply_mode = mode;
            check_terms_for(&a, v3_min)
        };
        // v2: $3,000 a chain at least, either mode -- as live.
        assert!(at(600, SUPPLY_SLICE, None).is_err());
        assert!(at(2_999, SUPPLY_SLICE, None).is_err());
        assert!(at(3_000, SUPPLY_TOTAL, None).is_ok());
        // v3 at the initial $600: $600 opens, $599 does not, $500,000 still the most.
        assert!(at(600, SUPPLY_SLICE, Some(600)).is_ok());
        assert!(at(599, SUPPLY_SLICE, Some(600)).is_err());
        assert!(at(500_000, SUPPLY_SLICE, Some(600)).is_ok());
        assert!(at(500_001, SUPPLY_SLICE, Some(600)).is_err());
        // The minimum moved to $1,000: $999 no longer opens.
        assert!(at(999, SUPPLY_SLICE, Some(1_000)).is_err());
        assert!(at(1_000, SUPPLY_SLICE, Some(1_000)).is_ok());
        // SUPPLY_TOTAL is not a v3 launch, at any cap.
        for cap in [600, 3_000, 15_000] {
            let e = at(cap, SUPPLY_TOTAL, Some(600)).unwrap_err();
            assert_eq!(e, error!(SplitterError::SupplyTotalNotInV3), "{cap}");
        }
        // The stored value is held to the bounds when read.
        assert_eq!(crate::price::v3_min_market_cap(0), 600);
        assert_eq!(crate::price::v3_min_market_cap(599), 600);
        assert_eq!(crate::price::v3_min_market_cap(3_001), 600);
        assert_eq!(crate::price::v3_min_market_cap(1_234), 1_234);
        assert_eq!(crate::price::v3_min_market_cap(3_000), 3_000);
    }
}
