//! Pangea's fast bridge on Solana: ONE program for every Pangea token, the Solana side of the
//! shared `PangeaFastBridge` on the EVM chains (script/fastbridge/INTERFACE.md).
//!
//! ## What it does
//!
//! * **Solana -> EVM** (`post_order`): the sender's tokens come here, this program keeps the fast
//!   lane's own fee for the platform, and sends the rest over the token's canonical OFT with a
//!   compose to the EVM bridge on the destination. A relayer there may deliver early; the EVM
//!   bridge settles when the canonical message lands. Nothing more happens here.
//! * **EVM -> Solana** (`fill_order`, `lz_compose`, `claim`): an order posted on an EVM chain may be
//!   filled here by anyone, out of their own tokens, until its canonical message has been verified
//!   on Solana. When the message lands, the OFT mints to this program's vault and records a compose
//!   for it; `lz_compose` (permissionless -- the endpoint vouches for the message) settles: an
//!   unfilled order pays the recipient everything; a filled one books the relayer's repayment on the
//!   fill, which the relayer takes with `claim`.
//!
//! ## Only Pangea tokens
//!
//! A token is one of ours when its OFT store is the one the splitter's launch seed derives
//! (`PDA(["OFT", PDA(["escrow", seed], splitter)], OFT)`): only the splitter can sign for that
//! escrow, so only a launch can have made that store. `register_launch` checks this once, from the
//! seed, and records `store -> (mint, launch id)` at `PDA(["launch", store])`. Everything after that
//! is keyed by the store: a compose whose `from` (written by the endpoint, not by any caller) has no
//! such record is refused, so a token that is not ours can neither settle an order nor reach the
//! vault's tokens. No instruction takes a mint from its caller as the order's token.
//!
//! ## Encodings shared with the EVM chains
//!
//! Solidity ABI words, big-endian, exactly as `PangeaFastBridge.sol`:
//!
//!   compose payload = abi.encode(bytes32 launchId, bytes32 sender, uint64 senderNonce, bytes32 to,
//!                                uint256 relayerFee)
//!   orderId         = keccak256(abi.encode(uint32 srcEid, bytes32 srcBridge, bytes32 launchId,
//!                       bytes32 sender, uint64 senderNonce, uint32 dstEid, bytes32 to,
//!                       uint256 amount, uint256 relayerFee))
//!
//! where `amount` is what ARRIVES on the destination, in base units (nine decimals on every chain).
//! This program's own address on the EVM side (its `remoteBridge[30168]`) is the vault, the PDA
//! that sends and receives.
//!
//! ## v3 (gap-fee) tokens
//!
//! A v3 token's destination withholds the price gap from what it credits (docs/v3-gap-fee-spec.md).
//! The order id always names the GROSS amount -- what the source's OFT says arrives before the
//! gap, `amount_ld` -- so a fill made against the posted order is found; the settlement pays out
//! what was CREDITED. Who bears the gap (owner decision (b)): a relayer whose fill EARNED (it
//! fronted the gross order on time) is owed `credited`; otherwise the recipient ends with
//! `credited` in total, as on the slow bridge, and a fill that did not earn is made whole out of
//! what arrived (`min(credited, gross - fee)`). The table is in src/v3/PangeaFastBridgeV3.sol.
//!
//! * **EVM -> Solana, v3 store** (`settle_v3`): a v3 store makes NO LayerZero compose. Its
//!   `lz_receive` mints `credited_ld` to the vault and writes a `GapReceipt` at
//!   `PDA(["GapReceipt", guid], OFT)` (spec §10.5). `settle_v3` takes that receipt instead of the
//!   endpoint's compose record: owned by the OFT program, at the guid's PDA, naming this launch's
//!   store and the vault, from an accepted EVM bridge; it settles on `credited_ld` and closes the
//!   receipt (`close_gap_receipt`, signed by the vault) in the same instruction, so a receipt
//!   settles once.
//! * **Solana -> EVM, v3 store** (`post_order_v3`): the order goes to the EVM chain's
//!   `PangeaFastBridgeV3` (`set_remote_v3`, `PDA(["remote_v3", eid])`, passed as the first
//!   remaining account), never to the v1/v2 bridge, which cannot settle a charged arrival.
//!   `post_order` refuses a v3 store and `post_order_v3` a live one. Live (v1/v2) stores are
//!   unchanged: the same instruction, accounts and remote.
//! * **minCredited** (owner, 2026-10-28): every v3 order names the least its destination may
//!   CREDIT. It travels three ways that must agree: in the gap message's header (the OFT send's
//!   trailing `min_credited_ld`; the destination's receive reverts, retriable, below it), in the
//!   order's payload (EVM -> Solana `encode_v3_payload`, 120 bytes; Solana -> EVM
//!   `encode_v3_solana_payload`, 76 bytes) and in the order id (`order_id_v3`, ten words), so no
//!   fill or settlement can name another minimum. `post_order_v3` takes the minimum from the
//!   send's trailing `min_credited_ld` itself (v3c AMENDMENT 1: no argument of its own) and checks
//!   the payload carries the same. The send's trailing bytes are the OFT's: none, 8
//!   (`min_credited_ld`, non-zero), 24 (`min_credited_ld`, any, then `min_ps_usd` u128, non-zero;
//!   BRIEF Amendment 4: the send refuses a Ps below it) or 25 (v3c-oft-s3: `min_credited_ld` any,
//!   `min_ps_usd` any, then the flags byte 0x01 = REQUIRE_COVER: the send refuses unless it carries
//!   the gas cover, so a fast order can require it). An arrival below it settles nothing: the
//!   message waits in the endpoint for a retry at a better price (no receipt, no fill repaid), and
//!   an order cannot be filled once its message is verified.
//! * The Cheapest chain route's Solana-far leg is off for v3 (owner Q5); nothing here routes.
//!
//! ## What is not here
//!
//! No instruction lets the admin move a token. The admin names counterparts, gas and fees.

use anchor_lang::prelude::*;
use anchor_lang::Discriminator;
use anchor_lang::solana_program::{
    hash::hashv as sha256v,
    instruction::{AccountMeta, Instruction},
    keccak::hashv as keccak256v,
    program::{invoke, invoke_signed},
    sysvar::instructions as sysvar_instructions,
    system_instruction,
};
use anchor_spl::token_interface::{self, Mint, TokenAccount, TokenInterface, TransferChecked};

declare_id!("7YNA5pg5sxmKxma7XiKDJnpWgyF5VPc7SaqyuzNhqZtw");

// ---------------------------------------------------------------------------- pinned addresses

/// The splitter: whose launch seeds define which tokens are Pangea's.
pub const SPLITTER_ID: Pubkey = pubkey!("Hb5uTppRbNxc3RjVRqTWqfdU3E3GiZyGYKccxYf9tUej");
/// LayerZero's OFT program every launch's store belongs to.
pub const OFT_PROGRAM_ID: Pubkey = pubkey!("SNyKyiZYU4R54SF9sYLmjCaCUsa1sC6QouNAj3x3Zzf");
/// LayerZero's endpoint on Solana.
pub const LZ_ENDPOINT_ID: Pubkey = pubkey!("76y77prsiCMvXMjuoZ5VRrhG5qYBrUMYTE5WgHqgjEn6");
/// Who may initialise the program: the splitter's admin, the Solana platform key.
#[cfg(not(feature = "rehearsal-admin"))] pub const INIT_AUTHORITY: Pubkey = pubkey!("7rYog4JusTy4CpwvFGPrRvWtcDrWatnA3SN3DRPuf6kM"); #[cfg(feature = "rehearsal-admin")] pub const INIT_AUTHORITY: Pubkey = rehearsal_admin::ADMIN; #[cfg(any(feature = "rehearsal-admin", test))] pub mod rehearsal_admin; // rehearsal builds only (feature rehearsal-admin): the throwaway admin PANGEA_REHEARSAL_ADMIN named at build time, src/rehearsal_admin.rs
/// Solana's LayerZero endpoint id: the destination of every order filled here.
pub const SOLANA_EID: u32 = 30168;

pub const LAUNCH_ID_DOMAIN: &[u8] = b"pangea launch id";
const SPLITTER_ESCROW_SEED: &[u8] = b"escrow";
const SPLITTER_PLATFORM_SEED: &[u8] = b"platform";
const OFT_STORE_SEED: &[u8] = b"OFT";
const OFT_PEER_SEED: &[u8] = b"Peer";
const OFT_STORE_DISCRIMINATOR: [u8; 8] = [195, 215, 104, 134, 185, 195, 240, 114];
const OFT_STORE_TOKEN_MINT: usize = 17;
/// OFT `send`.
const OFT_SEND_DISCRIMINATOR: [u8; 8] = [102, 251, 20, 187, 65, 75, 12, 69];

pub const CONFIG_SEED: &[u8] = b"config";
pub const VAULT_SEED: &[u8] = b"vault";
pub const LAUNCH_SEED: &[u8] = b"launch";
pub const REMOTE_SEED: &[u8] = b"remote";
pub const LAUNCH_FEES_SEED: &[u8] = b"fees";
pub const SENDER_SEED: &[u8] = b"sender";
pub const FILL_SEED: &[u8] = b"fill";
/// `PDA(["accepted", eid, bridge])`: a counterpart once set for `eid`. Append-only, like the EVM side's
/// accepted list: re-pointing a remote never orphans an order already in flight through the old one.
pub const ACCEPTED_SEED: &[u8] = b"accepted";
pub const LZ_COMPOSE_TYPES_SEED: &[u8] = b"LzComposeTypes";

/// The most the fast lane's own fee can ever be: 1%.
pub const MAX_FAST_FEE_BPS: u16 = 100;
pub const DEFAULT_FAST_FEE_BPS: u16 = 20;
pub const DEFAULT_MAX_RELAYER_FEE_BPS: u16 = 1000;
/// The most an order may ever pay a relayer: 10% of what arrives, the owner's ceiling.
pub const MAX_RELAYER_FEE_CAP_BPS: u16 = 1000;
/// The most lzReceive / lzCompose gas a remote may make an order pay for on the EVM side.
pub const MAX_REMOTE_GAS: u128 = 1_000_000;
/// The OFT's rounding unit: base units below one bridged (shared-decimal) unit.
pub const DUST: u64 = 1_000;
const OFT_STORE_DEFAULT_FEE_BPS: usize = 154;
/// What the compose payload is: five ABI words.
pub const PAYLOAD_LEN: usize = 160;
/// A v3 order's packed payload -- launchId (32), sender (32), senderNonce (8, big-endian), to (32),
/// relayerFee (8, big-endian), minCredited (8, big-endian) -- what `PangeaFastBridgeV3` sends toward
/// Solana (its gap message, codec v3: 96 + 32 + 120 = 248 bytes, under the v3 tokens' 256-byte
/// executor cap toward Solana) and what `post_order_v3` sends to it. Six ABI words would be 314.
pub const V3_PAYLOAD_LEN: usize = 120;
/// The v3 gap codec's header (_v3/gapcost/SPEC-gap-v3c.md §1, codec v3 = 0x03): sendTo 32 |
/// amountSD 8 | ver 1 | psUsd 16 | feeSrcPpm 4 | bridgeFeePpm 4 | minCreditedSD 8 | priceClass 1 |
/// psClass 16 | srcGasMicroUsd 4 @90 | srcCoverCapCents 2 @94 (Amendment 6, in place of Amendment
/// 5's srcDepthUsd / srcGasCents: 96 bytes, the compose tail from byte 96). This program never parses it (the OFT does, and leaves a GapReceipt); it is here for
/// the size of what FastBridge V3 sends toward Solana.
pub const V3_GAP_HEADER_LEN: usize = 96;
/// The longest message the v3 tokens' executor config carries toward Solana.
pub const V3_EXECUTOR_MSG_CAP: usize = 256;
/// What an order from FastBridge V3 toward Solana is on the wire: header, composeFrom, payload.
pub const V3_ORDER_MESSAGE_LEN: usize = V3_GAP_HEADER_LEN + 32 + V3_PAYLOAD_LEN;
const _: () = assert!(V3_ORDER_MESSAGE_LEN == 248 && V3_ORDER_MESSAGE_LEN <= V3_EXECUTOR_MSG_CAP);
/// A v3 order's payload from Solana (`post_order_v3`) -- launchId (32), senderNonce (8, BE), to
/// (the EVM address, 20), relayerFee (8, BE), minCredited (8, BE): 76 bytes. The sender is not in
/// it: on the EVM side a Solana order's sender is the compose's `composeFrom`, the signer of the
/// send (PangeaFastBridgeV3 uses nothing else). The 44 bytes it saves over the 120-byte form are
/// what keep the v3 fast order, minimum and all, in one transaction.
pub const V3_SOLANA_PAYLOAD_LEN: usize = 76;
/// The packed payload a v1/v2 order may carry toward Solana -- launchId (32), sender (32), senderNonce
/// (8, big-endian), to (32), relayerFee (8, big-endian) -- because the EVM tokens' executor config
/// toward Solana caps a message at 200 bytes, and the OFT header plus five ABI words is 232.
/// `lz_compose` (live stores) reads it or the ABI words; a v3 order never takes this form.
pub const PACKED_PAYLOAD_LEN: usize = 112;
/// The OFT's compose header: nonce (8), source eid (4), amount (8), composeFrom (32).
const COMPOSE_HEADER_LEN: usize = 52;
/// Where `send`'s accounts put the endpoint's `Nonce` for the route (the OFT's own `send` layout).
const SEND_STORE_AT: usize = 2;
const SEND_SOURCE_AT: usize = 3;

/// The v3 remote of an EVM chain: its `PangeaFastBridgeV3`, where v3 tokens' orders go.
pub const REMOTE_V3_SEED: &[u8] = b"remote_v3";
/// A v3 OFT store is at least this long (`init_oft_v3`, spec §10.3); a live store is 223.
pub const V3_STORE_LEN: usize = 319;
/// `PDA(["GapReceipt", guid])` under the OFT program: a composed v1 arrival on a v3 store.
pub const GAP_RECEIPT_SEED: &[u8] = b"GapReceipt";
/// The OFT program's GapPrepay PDA (["GapPrepay", store, src_eid BE, compose_from, sha256(compose_msg)])
/// and its GapLatePrepay record (["GapLatePrepay", prepay]): oft-q7 Q7-c, wired here by oft-lows3 (L-2).
pub const GAP_PREPAY_SEED: &[u8] = b"GapPrepay";
pub const GAP_LATE_PREPAY_SEED: &[u8] = b"GapLatePrepay";

/// The OFT's GapLatePrepay record for a receipt's (store, src_eid, compose_from, compose_msg): the
/// account `settle_v3` names after the system program (`gap_late_prepay`).
pub fn late_prepay_address(store: &Pubkey, src_eid: u32, compose_from: &[u8; 32], compose_msg: &[u8]) -> Pubkey {
    let h = anchor_lang::solana_program::hash::hash(compose_msg).to_bytes();
    let prepay = Pubkey::find_program_address(&[GAP_PREPAY_SEED, store.as_ref(), &src_eid.to_be_bytes(), compose_from, &h], &OFT_PROGRAM_ID).0;
    Pubkey::find_program_address(&[GAP_LATE_PREPAY_SEED, prepay.as_ref()], &OFT_PROGRAM_ID).0
}
/// `PDA(["GapGlobal"])` under the OFT program: the gap settings, whose `composers` (two slots at
/// `GAP_GLOBAL_COMPOSERS_AT` of its `GAP_GLOBAL_LEN` bytes, OFT gap/state.rs) are the only `to`s a
/// composed v3 arrival leaves a GapReceipt for. Any other `to` is credited as a plain arrival and
/// its compose dropped, so a v3 order to Solana whose vault is not listed could never settle
/// (audit r1 L-2): `set_remote_v3` refuses until the vault is listed.
pub const GAP_GLOBAL_SEED: &[u8] = b"GapGlobal";
/// An order's Fill (98 bytes) at rent exemption: (128 + 98) x 6,960 lamports.
pub const SOLANA_FILL_RENT: u64 = 1_572_960;
/// A Token-2022 associated account of a launched mint (170 bytes): (128 + 170) x 6,960 lamports.
pub const SOLANA_ATA_RENT: u64 = 2_074_080;
/// What an EVM -> Solana v3 order drops (LayerZero lzNativeDrop) on its own Fill PDA,
/// `PDA(["fill", order id])`, so that settling it costs the settler nothing net (audit r1 I-1):
/// `PangeaFastBridgeV3.SOLANA_ORDER_RENT_DROP`, in the user's quoted fee.
pub const SOLANA_ORDER_RENT_DROP: u64 = SOLANA_FILL_RENT + SOLANA_ATA_RENT;

/// Move `amount` lamports from `from` (owned by this program) to `to`.
fn move_lamports(from: &AccountInfo, to: &AccountInfo, amount: u64) -> Result<()> {
    if amount == 0 {
        return Ok(());
    }
    let have = from.lamports();
    **from.try_borrow_mut_lamports()? = have.checked_sub(amount).ok_or(error!(FastBridgeError::Overflow))?;
    let to_have = to.lamports();
    **to.try_borrow_mut_lamports()? = to_have.checked_add(amount).ok_or(error!(FastBridgeError::Overflow))?;
    Ok(())
}

/// oft-lows6 (oft-lows5-r1 L-1): the runtime's RESERVED account keys -- agave-reserved-account-keys 4.3.2
/// `RESERVED_ACCOUNTS`, all 31 (builtin programs, sysvars, the native loader, the sysvar owner), which every
/// transaction gets READ-ONLY whatever it asks for. The same list as the OFT's `gap::prepay`,
/// script/fastbridge/solana-recipient.mjs and web/lib/chain/solana-route-open.mjs (compared by
/// script/fastbridge/solana-recipient.test.mjs).
pub const RESERVED_ACCOUNT_KEYS: [Pubkey; 31] = [
    pubkey!("11111111111111111111111111111111"),
    pubkey!("AddressLookupTab1e1111111111111111111111111"),
    pubkey!("BPFLoader1111111111111111111111111111111111"),
    pubkey!("BPFLoader2111111111111111111111111111111111"),
    pubkey!("BPFLoaderUpgradeab1e11111111111111111111111"),
    pubkey!("ComputeBudget111111111111111111111111111111"),
    pubkey!("Config1111111111111111111111111111111111111"),
    pubkey!("Ed25519SigVerify111111111111111111111111111"),
    pubkey!("Feature111111111111111111111111111111111111"),
    pubkey!("KeccakSecp256k11111111111111111111111111111"),
    pubkey!("LoaderV411111111111111111111111111111111111"),
    pubkey!("NativeLoader1111111111111111111111111111111"),
    pubkey!("Secp256r1SigVerify1111111111111111111111111"),
    pubkey!("Stake11111111111111111111111111111111111111"),
    pubkey!("StakeConfig11111111111111111111111111111111"),
    pubkey!("Sysvar1111111111111111111111111111111111111"),
    pubkey!("Sysvar1nstructions1111111111111111111111111"),
    pubkey!("SysvarC1ock11111111111111111111111111111111"),
    pubkey!("SysvarEpochRewards1111111111111111111111111"),
    pubkey!("SysvarEpochSchedu1e111111111111111111111111"),
    pubkey!("SysvarFees111111111111111111111111111111111"),
    pubkey!("SysvarLastRestartS1ot1111111111111111111111"),
    pubkey!("SysvarRecentB1ockHashes11111111111111111111"),
    pubkey!("SysvarRent111111111111111111111111111111111"),
    pubkey!("SysvarRewards111111111111111111111111111111"),
    pubkey!("SysvarS1otHashes111111111111111111111111111"),
    pubkey!("SysvarS1otHistory11111111111111111111111111"),
    pubkey!("SysvarStakeHistory1111111111111111111111111"),
    pubkey!("Vote111111111111111111111111111111111111111"),
    pubkey!("ZkE1Gama1Proof11111111111111111111111111111"),
    pubkey!("ZkTokenProof1111111111111111111111111111111"),
];

/// The owner of every sysvar account.
pub const SYSVAR_OWNER: Pubkey = pubkey!("Sysvar1111111111111111111111111111111111111");

/// oft-lows6 (oft-lows5-r1 L-1): whether settle_v3's recipient CANNOT be credited lamports: an executable account
/// (ExecutableLamportChange) or one this transaction has read-only (ReadonlyLamportChange) because the runtime
/// makes it so -- a sysvar, a builtin or other reserved key, a key called as a program (this program's own id).
/// A recipient passed read-only that the runtime would let be written (a wallet, a PDA) is refused
/// (RecipientNotWritable): a settler can never move a wallet's refund or rent drop elsewhere by passing it
/// read-only -- passed writable, the order settles to it.
fn recipient_cannot_hold(r: &AccountInfo) -> Result<bool> {
    if r.executable {
        return Ok(true);
    }
    if r.is_writable {
        return Ok(false);
    }
    require!(*r.owner == SYSVAR_OWNER || RESERVED_ACCOUNT_KEYS.contains(r.key), FastBridgeError::RecipientNotWritable);
    Ok(true)
}

/// The lamports a Fill holds above its rent-exempt minimum: the order's rent drop not spent yet.
fn fill_spare(fill: &AccountInfo) -> Result<u64> {
    Ok(fill.lamports().saturating_sub(Rent::get()?.minimum_balance(8 + Fill::INIT_SPACE)))
}
/// The OFT GapGlobal size (v3c-oft-s3 layout + L4's return_gas_lamports @756 + oft-q7's
/// delivery_lamports @760, dst_delivery @764, dst_delivery_to @812 + oft-fix's ata_lamports @844 and
/// cosigners @848: 912 bytes with its discriminator, OFT gap/state.rs `GAP_GLOBAL_LEN`); a different
/// size is not a GapGlobal this build knows, so `set_remote_v3` refuses. (oft-merge: was 756, which
/// refused every L4 GapGlobal; oft-q7: was 760; oft-fix: was 844.) Go-live order (oft-r3-prog I-4):
/// OFT upgrade -> `migrate_gap_global` (to 912) -> this program's upgrade; until the FastBridge
/// upgrade `set_remote_v3` refuses (nothing else here reads GapGlobal).
pub const GAP_GLOBAL_LEN: usize = 912;
pub const GAP_GLOBAL_COMPOSERS_AT: usize = 202;
/// The OFT GapGlobal's keys-only destinations (oft-q7 Q7-e): 4 x {eid u32, lamports u64} @764.
pub const GAP_GLOBAL_DST_DELIVERY_AT: usize = 764;
pub const GAP_DST_DELIVERY_SLOTS: usize = 4;

/// web-r3-a M-2: the OFT's per-destination delivery cost for `eid` in a GapGlobal's bytes (0 = LayerZero's
/// executor delivers there; > 0 = a keys-only destination, our keys deliver and the OFT's send pays LayerZero
/// lzReceive gas 1 only, KEYS_ONLY_OPTIONS).
pub fn gap_global_dst_delivery(data: &[u8], eid: u32) -> u64 {
    if data.len() != GAP_GLOBAL_LEN || eid == 0 {
        return 0;
    }
    (0..GAP_DST_DELIVERY_SLOTS)
        .map(|i| GAP_GLOBAL_DST_DELIVERY_AT + 12 * i)
        .find(|&at| u32::from_le_bytes(data[at..at + 4].try_into().unwrap()) == eid)
        .map_or(0, |at| u64::from_le_bytes(data[at + 4..at + 12].try_into().unwrap()))
}
pub const GAP_COMPOSER_SLOTS: usize = 2;

/// sol-lows (xa-final-sol L-1): `post_order_v3`'s second remaining account, the OFT program's GapGlobal (read
/// only): its `dst_delivery` toward `eid`. The account must be THE GapGlobal -- the OFT program's, at its PDA, with
/// this build's length and Anchor discriminator -- or the order is refused (BadGapGlobal), as pangea-cheapest reads
/// it for Q59 (`keys_only_delivery`).
fn gap_global_dst_delivery_for(g: &AccountInfo, eid: u32) -> Result<u64> {
    require_keys_eq!(*g.owner, OFT_PROGRAM_ID, FastBridgeError::BadGapGlobal);
    let (key, _) = Pubkey::find_program_address(&[GAP_GLOBAL_SEED], &OFT_PROGRAM_ID);
    require_keys_eq!(g.key(), key, FastBridgeError::BadGapGlobal);
    let d = g.try_borrow_data()?;
    let disc = anchor_lang::solana_program::hash::hash(b"account:GapGlobal").to_bytes();
    require!(d.len() == GAP_GLOBAL_LEN && d[..8] == disc[..8], FastBridgeError::BadGapGlobal);
    Ok(gap_global_dst_delivery(&d, eid))
}

/// Whether `data` is a GapGlobal (its length and Anchor discriminator) listing `who` as a composer.
pub fn gap_global_lists(data: &[u8], who: &Pubkey) -> bool {
    let disc = anchor_lang::solana_program::hash::hash(b"account:GapGlobal").to_bytes();
    data.len() == GAP_GLOBAL_LEN
        && data[..8] == disc[..8]
        && *who != Pubkey::default()
        && (0..GAP_COMPOSER_SLOTS).any(|i| data[GAP_GLOBAL_COMPOSERS_AT + 32 * i..GAP_GLOBAL_COMPOSERS_AT + 32 * (i + 1)] == who.to_bytes())
}
/// sha256("account:GapReceipt")[..8].
pub const GAP_RECEIPT_DISCRIMINATOR: [u8; 8] = [0x58, 0x38, 0x01, 0xa7, 0x0e, 0xa2, 0x1f, 0x1e];
/// sha256("global:close_gap_receipt")[..8].
pub const CLOSE_GAP_RECEIPT_DISCRIMINATOR: [u8; 8] = [0x2a, 0xf6, 0x72, 0x5a, 0x73, 0x18, 0xa0, 0x01];
/// The receipt's fixed part: the discriminator and every field up to compose_msg's length.
pub const GAP_RECEIPT_FIXED_LEN: usize = 219;
/// The longest compose_msg a receipt holds (the OFT program's `MAX_COMPOSE_MSG_LEN`).
pub const GAP_RECEIPT_MAX_MSG: usize = 512;

#[program]
pub mod pangea_fastbridge {
    use super::*;

    /// One-time setup by the platform key: the config, the vault (funded to rent-exemption so it
    /// can pay LayerZero's fees as a system account), and the compose-types record.
    pub fn initialize(ctx: Context<Initialize>, admin: Pubkey) -> Result<()> {
        require!(admin != Pubkey::default(), FastBridgeError::ZeroAddress);
        let c = &mut ctx.accounts.config;
        c.admin = admin;
        c.pending_admin = Pubkey::default();
        c.fast_fee_bps = DEFAULT_FAST_FEE_BPS;
        c.max_relayer_fee_bps = DEFAULT_MAX_RELAYER_FEE_BPS;
        c.bump = ctx.bumps.config;
        c.vault_bump = ctx.bumps.vault;
        ctx.accounts.compose_types.vault = ctx.accounts.vault.key();
        let rent = Rent::get()?.minimum_balance(0);
        let have = ctx.accounts.vault.lamports();
        if have < rent {
            invoke(
                &system_instruction::transfer(&ctx.accounts.payer.key(), &ctx.accounts.vault.key(), rent - have),
                &[ctx.accounts.payer.to_account_info(), ctx.accounts.vault.to_account_info(), ctx.accounts.system_program.to_account_info()],
            )?;
        }
        Ok(())
    }

    /// Record that `store` is a Pangea launch's, from the launch's seed. Anyone, once per store.
    pub fn register_launch(ctx: Context<RegisterLaunch>, seed: [u8; 32]) -> Result<()> {
        let store = ctx.accounts.store.key();
        require_keys_eq!(store, store_of_launch(&seed), FastBridgeError::NotOurToken);
        require_keys_eq!(*ctx.accounts.store.owner, OFT_PROGRAM_ID, FastBridgeError::NotOurToken);
        let data = ctx.accounts.store.try_borrow_data()?;
        require!(data.len() >= OFT_STORE_TOKEN_MINT + 32 && data[..8] == OFT_STORE_DISCRIMINATOR, FastBridgeError::NotOurToken);
        // Nine local decimals over six shared, as every launch: amounts here and on the EVM side are
        // the same base units only at this rate.
        require!(u64::from_le_bytes(data[9..17].try_into().unwrap()) == DUST, FastBridgeError::NotOurToken);
        let mint = Pubkey::new_from_array(data[OFT_STORE_TOKEN_MINT..OFT_STORE_TOKEN_MINT + 32].try_into().unwrap());
        drop(data);
        // A launch of the current model only: its mint answers to its store alone (no reserve
        // minter). An older launch's token is not one the EVM bridges accept, so an order for it
        // would be refused there and its tokens stranded.
        require_keys_eq!(ctx.accounts.mint.key(), mint, FastBridgeError::NotOurToken);
        {
            let m = ctx.accounts.mint.try_borrow_data()?;
            require!(m.len() >= 36 && m[0..4] == [1, 0, 0, 0] && m[4..36] == store.to_bytes(), FastBridgeError::NotOurToken);
        }
        let l = &mut ctx.accounts.launch;
        l.store = store;
        l.mint = mint;
        l.launch_id = launch_id_of(&seed);
        l.bump = ctx.bumps.launch;
        emit!(LaunchRegistered { store, mint, launch_id: l.launch_id });
        Ok(())
    }

    // ------------------------------------------------------------------------ Solana -> EVM

    /// Post a transfer to an EVM chain that a relayer there may deliver early.
    ///
    /// ## Why the send is the NEXT instruction and not a call from here
    ///
    /// LayerZero's OFT `send` already uses Solana's whole call depth (OFT -> endpoint -> ULN ->
    /// executor/verifier -> price feed), so no program can call it. The order is therefore two
    /// instructions in one transaction: this one, which takes the fast fee and the sender's nonce
    /// and checks that the very next instruction is the OFT send that carries the order -- this
    /// launch's store, from the sender's own account, to our bridge on `dst_eid`, of exactly the
    /// amount left after the fast fee, promising at least the amount the order is for, with the
    /// order's compose payload and the route's executor options -- and then that send, signed by
    /// the sender.
    ///
    /// On the destination the compose comes FROM the sender (they called `send`), so the EVM bridge
    /// names a Solana order's source by its sender: `srcBridge = sender`, and requires the payload's
    /// `sender` to be the same.
    ///
    /// What this cannot stop: somebody calling the OFT send themselves, without this instruction,
    /// with a compose to our EVM bridge. That is an order that skipped the fast fee here; the relayer
    /// risk is unchanged (a fill is repaid only by the canonical message, of exactly the order's
    /// amount), so it costs the platform its fee on that order and nobody anything else.
    pub fn post_order(
        ctx: Context<PostOrder>,
        dst_eid: u32,
        to: [u8; 32],
        amount: u64,
        relayer_fee: u64,
        min_received: u64,
    ) -> Result<()> {
        post_order_any(ctx, dst_eid, to, amount, relayer_fee, min_received, false)
    }

    /// `post_order` for a v3 (gap-fee) store, with the order's least credited amount
    /// (`min_credited`, base units, at most what arrives; 0 = none): the next instruction must be
    /// the OFT send carrying it as its trailing `min_credited_ld` (absent when 0), the payload is
    /// the 120-byte v3 form and the order id `order_id_v3`. Refuses a live store.
    ///
    /// v3c (BRIEF AMENDMENT 1, 2026-10-30): the minimum is NOT an argument any more. It is read from
    /// the following OFT send's trailing `min_credited_ld` (absent = 0), which the send's gap header
    /// carries -- one source, so the payload, the order id and the header cannot disagree. The send
    /// may also carry the OFT's trailing `min_ps_usd` (24 trailing bytes in all, BRIEF Amendment 4);
    /// the order is then min_credited_ld's (0 allowed there). The fast order is ONE transaction with
    /// the store's shared PriceLog in a lookup table (web/lib/chain/fastbridge-v3c-packet.test.mjs).
    ///
    /// Remaining accounts: `PDA(["remote_v3", dst_eid])`, then the OFT program's `PDA(["GapGlobal"])` (read only;
    /// sol-lows, xa-final-sol L-1). The order is refused (`KeysOnlyGas`) unless the remote's receive gas is 0 exactly
    /// when GapGlobal.dst_delivery(dst_eid) > 0 (a keys-only eid), read at every order, not only at `set_remote_v3`.
    pub fn post_order_v3(
        ctx: Context<PostOrder>,
        dst_eid: u32,
        to: [u8; 32],
        amount: u64,
        relayer_fee: u64,
        min_received: u64,
    ) -> Result<()> {
        post_order_any(ctx, dst_eid, to, amount, relayer_fee, min_received, true)
    }

    // ------------------------------------------------------------------------ EVM -> Solana

    /// Deliver an order posted on an EVM chain now, out of the relayer's own tokens; claim the
    /// arriving tokens after the canonical message settles it. Refused once that message has been
    /// verified on Solana.
    pub fn fill_order(
        ctx: Context<FillOrder>,
        src_eid: u32,
        src_bridge: [u8; 32],
        sender: [u8; 32],
        sender_nonce: u64,
        amount: u64,
        relayer_fee: u64,
        lz_nonce: u64,
    ) -> Result<()> {
        fill_order_any(ctx, src_eid, src_bridge, sender, sender_nonce, amount, relayer_fee, None, lz_nonce)
    }

    /// `fill_order` of an order a `PangeaFastBridgeV3` posted toward a v3 store: the id is
    /// `order_id_v3`, with the order's `min_credited` (what `settle_v3` reads from the payload).
    /// Its `remote` is the eid's v3 remote or its v1 remote (audit L-3).
    /// Filling a v3 order with `fill_order`, or a live one with this, makes a fill under an id no
    /// settlement names: the relayer's own loss (the recipient is paid by the arrival as unfilled).
    #[allow(clippy::too_many_arguments)]
    pub fn fill_order_v3(
        ctx: Context<FillOrder>,
        src_eid: u32,
        src_bridge: [u8; 32],
        sender: [u8; 32],
        sender_nonce: u64,
        amount: u64,
        relayer_fee: u64,
        min_credited: u64,
        lz_nonce: u64,
    ) -> Result<()> {
        fill_order_any(ctx, src_eid, src_bridge, sender, sender_nonce, amount, relayer_fee, Some(min_credited), lz_nonce)
    }

    /// The canonical message arriving: called with the parameters the endpoint recorded for the
    /// vault; `clear_compose` (the endpoint's own check of those parameters against the record)
    /// is what makes them trustworthy, and it is sent here, in this instruction, signed as the vault.
    pub fn lz_compose<'info>(ctx: Context<'_, '_, 'info, 'info, LzCompose<'info>>, params: LzComposeParams) -> Result<()> {
        let a = &ctx.accounts;
        require_keys_eq!(params.to, a.vault.key(), FastBridgeError::NotOurMessage);
        require_keys_eq!(params.from, a.launch.store, FastBridgeError::NotOurToken);
        let m = &params.message;
        require!(m.len() == COMPOSE_HEADER_LEN + PAYLOAD_LEN || m.len() == COMPOSE_HEADER_LEN + PACKED_PAYLOAD_LEN, FastBridgeError::BadPayload);
        let lz_nonce = u64::from_be_bytes(m[0..8].try_into().unwrap());
        let src_eid = u32::from_be_bytes(m[8..12].try_into().unwrap());
        let amount = u64::from_be_bytes(m[12..20].try_into().unwrap());
        let from: [u8; 32] = m[20..52].try_into().unwrap();
        let remote_key = Pubkey::find_program_address(&[REMOTE_SEED, &src_eid.to_be_bytes()], &crate::ID).0;
        require!(a.remote.key() == remote_key && a.remote.eid == src_eid, FastBridgeError::NoRemote);
        require!(is_accepted(&a.remote, &a.accepted, src_eid, &from), FastBridgeError::NotOurBridge);
        // A v1/v2 order's five fields, packed or as ABI words; the order id is the ABI hash either
        // way. (A v3 store makes no compose: its orders settle with settle_v3.)
        let (launch_id, sender, sender_nonce, to, relayer_fee) = decode_payload(&m[COMPOSE_HEADER_LEN..])?;
        require!(launch_id == a.launch.launch_id, FastBridgeError::OrderMismatch);
        let id = order_id(src_eid, &from, &launch_id, &sender, sender_nonce, SOLANA_EID, &to, amount, relayer_fee);
        require_keys_eq!(a.recipient.key(), Pubkey::new_from_array(to), FastBridgeError::OrderMismatch);
        let (fill_key, _) = Pubkey::find_program_address(&[FILL_SEED, &id], &crate::ID);
        require_keys_eq!(a.fill.key(), fill_key, FastBridgeError::OrderMismatch);

        let vault_seeds: &[&[u8]] = &[VAULT_SEED, &[a.config.vault_bump]];
        let decimals = a.mint.decimals;
        let pay = |amount: u64, dest: &AccountInfo<'info>| -> Result<()> {
            if amount == 0 {
                return Ok(());
            }
            token_interface::transfer_checked(
                CpiContext::new_with_signer(a.token_program.to_account_info(), TransferChecked {
                    from: a.vault_ata.to_account_info(),
                    mint: a.mint.to_account_info(),
                    to: dest.clone(),
                    authority: a.vault.to_account_info(),
                }, &[vault_seeds]),
                amount,
                decimals,
            )
        };

        let filled = *a.fill.owner == crate::ID && !a.fill.data_is_empty();
        if filled {
            let mut fill = Fill::try_deserialize(&mut &a.fill.try_borrow_data()?[..])?;
            require!(!fill.settled, FastBridgeError::AlreadySettled);
            // The fee is for filling before THIS message arrived, and not in the slot that settles
            // it: a fill naming another message, or made in this very slot, is repaid what it laid
            // out and the fee goes to the recipient.
            let earned = fill.lz_nonce == lz_nonce && fill.slot != Clock::get()?.slot;
            let fee = if earned { 0 } else { relayer_fee };
            fill.owed = amount - fee;
            fill.settled = true;
            let mut d = a.fill.try_borrow_mut_data()?;
            fill.serialize(&mut &mut d[8..])?;
            drop(d);
            if fee > 0 {
                pay(fee, &a.recipient_ata.to_account_info())?;
                emit!(FeeReturned { order_id: id, to: a.recipient.key(), fee });
            }
            emit!(RelayerOwed { order_id: id, relayer: fill.relayer, amount: amount - fee, earned });
        } else {
            // A tombstone at the order's fill address, so no fill can be made of it afterwards.
            let (_, fill_bump) = Pubkey::find_program_address(&[FILL_SEED, &id], &crate::ID);
            require!(*a.fill.owner == anchor_lang::system_program::ID && a.fill.data_is_empty(), FastBridgeError::AlreadySettled);
            create_pda(&a.payer.to_account_info(), &a.fill, &a.system_program.to_account_info(), 8 + Fill::INIT_SPACE, &[FILL_SEED, &id, &[fill_bump]])?;
            let tomb = Fill { relayer: Pubkey::default(), mint: a.launch.mint, lz_nonce, slot: Clock::get()?.slot, owed: 0, settled: true, bump: fill_bump };
            let mut d = a.fill.try_borrow_mut_data()?;
            d[..8].copy_from_slice(&Fill::DISCRIMINATOR);
            tomb.serialize(&mut &mut d[8..])?;
            drop(d);
            pay(amount, &a.recipient_ata.to_account_info())?;
            emit!(SettledSlow { order_id: id, to: a.recipient.key(), amount });
        }

        // The endpoint's check that these parameters are the ones it recorded, and that they have not
        // been settled before.
        let ra = ctx.remaining_accounts;
        require!(ra.len() >= 5, FastBridgeError::BadPayload);
        require_keys_eq!(ra[0].key(), LZ_ENDPOINT_ID, FastBridgeError::NotOurMessage);
        require_keys_eq!(ra[1].key(), a.vault.key(), FastBridgeError::NotOurMessage);
        let mut data = anchor_disc("global:clear_compose").to_vec();
        params.from.serialize(&mut data)?;
        data.extend_from_slice(&params.guid);
        data.extend_from_slice(&params.index.to_le_bytes());
        params.message.serialize(&mut data)?;
        let ix = Instruction {
            program_id: LZ_ENDPOINT_ID,
            accounts: vec![
                AccountMeta::new_readonly(a.vault.key(), true),
                AccountMeta::new(ra[2].key(), false),
                AccountMeta::new_readonly(ra[3].key(), false),
                AccountMeta::new_readonly(ra[4].key(), false),
            ],
            data,
        };
        invoke_signed(&ix, &[ra[1].clone(), ra[2].clone(), ra[3].clone(), ra[4].clone(), ra[0].clone()], &[vault_seeds])?;
        Ok(())
    }

    /// The relayer takes what a settled fill is owed, and the fill's rent back.
    pub fn claim(ctx: Context<Claim>) -> Result<()> {
        let a = &ctx.accounts;
        require!(a.fill.settled, FastBridgeError::NotSettled);
        require!(a.fill.owed > 0, FastBridgeError::NothingOwed);
        require_keys_eq!(a.fill.mint, a.mint.key(), FastBridgeError::OrderMismatch);
        let vault_seeds: &[&[u8]] = &[VAULT_SEED, &[a.config.vault_bump]];
        if a.fill.owed > 0 {
            token_interface::transfer_checked(
                CpiContext::new_with_signer(a.token_program.to_account_info(), TransferChecked {
                    from: a.vault_ata.to_account_info(),
                    mint: a.mint.to_account_info(),
                    to: a.relayer_ata.to_account_info(),
                    authority: a.vault.to_account_info(),
                }, &[vault_seeds]),
                a.fill.owed,
                a.mint.decimals,
            )?;
        }
        let owed = a.fill.owed;
        // A relayer that made the Fill before the order's rent drop landed (audit r1 I-1): its
        // rent back out of the drop, at most SOLANA_FILL_RENT, never below the Fill's rent minimum.
        // (A live order's Fill holds no drop: nothing moves.)
        let fill_info = ctx.accounts.fill.to_account_info();
        let back = fill_spare(&fill_info)?.min(SOLANA_FILL_RENT);
        move_lamports(&fill_info, &ctx.accounts.relayer.to_account_info(), back)?;
        // Kept, as a tombstone: the order can never be filled or claimed again.
        ctx.accounts.fill.owed = 0;
        emit!(RelayerPaid { fill: ctx.accounts.fill.key(), relayer: ctx.accounts.relayer.key(), amount: owed });
        Ok(())
    }

    /// A v3 store's arrival (spec §4, §10.5): there is no compose record; the OFT's `GapReceipt`
    /// for `guid` stands in for it. Held to: owned by the OFT program, at `PDA(["GapReceipt",
    /// guid])` there, naming this launch's store, the guid and the vault (`to`), sent by an
    /// accepted EVM bridge (`compose_from`), `credited + withheld == amount`. The order id uses
    /// the GROSS `amount_ld`; the payout is `credited_ld`, what the vault received. The receipt is
    /// closed in this instruction, signed by the vault (its rent to its payer), so it settles once.
    /// Permissionless, as `lz_compose`: the OFT program vouches for the receipt.
    pub fn settle_v3<'info>(ctx: Context<'_, '_, 'info, 'info, SettleV3<'info>>, guid: [u8; 32]) -> Result<()> {
        let a = &ctx.accounts;
        let receipt = a.gap_receipt.to_account_info();
        require_keys_eq!(*receipt.owner, OFT_PROGRAM_ID, FastBridgeError::BadGapReceipt);
        let (receipt_key, _) = Pubkey::find_program_address(&[GAP_RECEIPT_SEED, &guid], &OFT_PROGRAM_ID);
        require_keys_eq!(receipt.key(), receipt_key, FastBridgeError::BadGapReceipt);
        let (src_eid, lz_nonce, from, gross, withheld, credited, receipt_payer, payload) = {
            let d = receipt.try_borrow_data()?;
            let r = read_gap_receipt(&d).ok_or(FastBridgeError::BadGapReceipt)?;
            require!(r.guid == guid, FastBridgeError::BadGapReceipt);
            require_keys_eq!(r.oft_store, a.launch.store, FastBridgeError::NotOurToken);
            require_keys_eq!(r.to, a.vault.key(), FastBridgeError::NotOurMessage);
            require!(r.credited_ld.checked_add(r.withheld_ld) == Some(r.amount_ld), FastBridgeError::BadGapReceipt);
            (r.src_eid, r.nonce, r.compose_from, r.amount_ld, r.withheld_ld, r.credited_ld, r.payer, r.compose_msg.to_vec())
        };
        require_keys_eq!(a.receipt_payer.key(), receipt_payer, FastBridgeError::BadGapReceipt);
        // The eid's v3 remote, or its v1 remote as before (audit L-3): an eid with only a v3 remote settles.
        require!(remote_slot_ok(&a.remote.key(), a.remote.bump, src_eid, true) && a.remote.eid == src_eid, FastBridgeError::NoRemote);
        require!(is_accepted(&a.remote, &a.accepted, src_eid, &from), FastBridgeError::NotOurBridge);
        // The v3 payload (120 bytes): its minCredited is in the id, so this settles exactly the
        // order that was posted and filled. The receive that wrote this receipt already held
        // credited >= that minimum (the OFT reverts below it, retriable, writing nothing).
        let (launch_id, sender, sender_nonce, to, relayer_fee, min_credited) = decode_v3_payload(&payload)?;
        require!(launch_id == a.launch.launch_id, FastBridgeError::OrderMismatch);
        let id = order_id_v3(src_eid, &from, &launch_id, &sender, sender_nonce, SOLANA_EID, &to, gross, relayer_fee, min_credited);
        require_keys_eq!(a.recipient.key(), Pubkey::new_from_array(to), FastBridgeError::OrderMismatch);
        // oft-lows6 (oft-lows5-r1 L-1): a recipient that can never be credited (a program, or one the runtime keeps
        // read-only) settles all the same; one passed read-only by choice is refused here.
        let unpayable = recipient_cannot_hold(&a.recipient.to_account_info())?;
        let (fill_key, fill_bump) = Pubkey::find_program_address(&[FILL_SEED, &id], &crate::ID);
        require_keys_eq!(a.fill.key(), fill_key, FastBridgeError::OrderMismatch);
        require!(a.vault_ata.amount >= credited, FastBridgeError::BadGapReceipt);
        if withheld > 0 {
            emit!(GapBorne { order_id: id, guid, gross, withheld });
        }
        // The recipient's account: made here when missing, by the payer (audit r1 I-1: the order's
        // rent drop pays it back below), else held to the recipient's ATA of this mint.
        let want_ata = anchor_spl::associated_token::get_associated_token_address_with_program_id(&a.recipient.key(), &a.mint.key(), &a.token_program.key());
        require_keys_eq!(a.recipient_ata.key(), want_ata, FastBridgeError::OrderMismatch);
        let ata_made_here = a.recipient_ata.data_is_empty();
        if ata_made_here {
            anchor_spl::associated_token::create(CpiContext::new(a.associated_token_program.to_account_info(), anchor_spl::associated_token::Create {
                payer: a.payer.to_account_info(),
                associated_token: a.recipient_ata.to_account_info(),
                authority: a.recipient.to_account_info(),
                mint: a.mint.to_account_info(),
                system_program: a.system_program.to_account_info(),
                token_program: a.token_program.to_account_info(),
            }))?;
        } else {
            require_keys_eq!(*a.recipient_ata.owner, a.token_program.key(), FastBridgeError::OrderMismatch);
        }

        let vault_seeds: &[&[u8]] = &[VAULT_SEED, &[a.config.vault_bump]];
        let decimals = a.mint.decimals;
        let pay = |amount: u64, dest: &AccountInfo<'info>| -> Result<()> {
            if amount == 0 {
                return Ok(());
            }
            token_interface::transfer_checked(
                CpiContext::new_with_signer(a.token_program.to_account_info(), TransferChecked {
                    from: a.vault_ata.to_account_info(),
                    mint: a.mint.to_account_info(),
                    to: dest.clone(),
                    authority: a.vault.to_account_info(),
                }, &[vault_seeds]),
                amount,
                decimals,
            )
        };

        let filled = *a.fill.owner == crate::ID && !a.fill.data_is_empty();
        if filled {
            let mut fill = Fill::try_deserialize(&mut &a.fill.try_borrow_data()?[..])?;
            require!(!fill.settled, FastBridgeError::AlreadySettled);
            // Owner decision (b): an EARNED fill (this message, an earlier slot) fronted on time
            // and bears the gap: owed credited. One that did not earn is made whole out of what
            // arrived, min(credited, gross - fee), and the recipient gets the rest, so its total
            // is credited. Exactly credited is paid out either way.
            let earned = fill.lz_nonce == lz_nonce && fill.slot != Clock::get()?.slot;
            let owed = if earned { credited } else { credited.min(gross - relayer_fee) };
            let fee = credited - owed;
            fill.owed = owed;
            fill.settled = true;
            let mut d = a.fill.try_borrow_mut_data()?;
            fill.serialize(&mut &mut d[8..])?;
            drop(d);
            if fee > 0 {
                pay(fee, &a.recipient_ata.to_account_info())?;
                emit!(FeeReturned { order_id: id, to: a.recipient.key(), fee });
            }
            emit!(RelayerOwed { order_id: id, relayer: fill.relayer, amount: credited - fee, earned });
        } else {
            require!(*a.fill.owner == anchor_lang::system_program::ID && a.fill.data_is_empty(), FastBridgeError::AlreadySettled);
            create_pda(&a.payer.to_account_info(), &a.fill, &a.system_program.to_account_info(), 8 + Fill::INIT_SPACE, &[FILL_SEED, &id, &[fill_bump]])?;
            let tomb = Fill { relayer: Pubkey::default(), mint: a.launch.mint, lz_nonce, slot: Clock::get()?.slot, owed: 0, settled: true, bump: fill_bump };
            let mut d = a.fill.try_borrow_mut_data()?;
            d[..8].copy_from_slice(&Fill::DISCRIMINATOR);
            tomb.serialize(&mut &mut d[8..])?;
            drop(d);
            pay(credited, &a.recipient_ata.to_account_info())?;
            emit!(SettledSlow { order_id: id, to: a.recipient.key(), amount: credited });
        }

        // The receipt, closed by its composer (the vault signs) in this instruction. L4 (owner
        // 2026-10-30): the sender's prepaid lamports (its native drop for the way home, which the
        // settled order no longer needs) go to the order's recipient, named as the close's refund
        // account. Always passed: anyone can fund a receipt's prepay PDA, and a close with a
        // prepay and no refund account is refused, which would block the settle for good.
        // oft-lows3 (oft-lows2-r1 L-2, oft-q7 OPEN 1): the close also names [the GapLatePrepay
        // record, the system program] -- always, prepaid or not (a prepaid figure may be a griefer's
        // dust) -- so a LayerZero native drop of the sender's P that lands after this settle is
        // recorded for the recipient and `sweep_late_prepay` sends it there (before: stranded at the
        // PDA for good). The OFT checks the record's address (GapAccountMismatch) and decides who
        // fronts its rent (never our payer for a record that is the recipient's: OFT oft-lows3 L-3).
        let ix = Instruction {
            program_id: OFT_PROGRAM_ID,
            accounts: vec![
                AccountMeta::new_readonly(a.vault.key(), true),
                AccountMeta::new(receipt.key(), false),
                AccountMeta::new(receipt_payer, false),
                // oft-lows6: writable only when it is (a read-only recipient named writable would escalate the
                // CPI's privileges); the OFT's close then gives what it would get to the receipt's payer, named.
                AccountMeta { pubkey: a.recipient.key(), is_signer: false, is_writable: a.recipient.is_writable },
                AccountMeta::new(a.gap_late_prepay.key(), false),
                AccountMeta::new_readonly(a.system_program.key(), false),
            ],
            data: CLOSE_GAP_RECEIPT_DISCRIMINATOR.to_vec(),
        };
        invoke_signed(
            &ix,
            &[
                a.vault.to_account_info(),
                receipt,
                a.receipt_payer.to_account_info(),
                a.recipient.to_account_info(),
                a.gap_late_prepay.to_account_info(),
                a.system_program.to_account_info(),
                a.oft_program.to_account_info(),
            ],
            &[vault_seeds],
        )?;

        // oft-merge: the rent drop moves AFTER the close CPI. The close names the recipient (L4's refund account), and
        // a CPI syncs the caller's direct lamport edits only for the accounts it names: a drop moved before it (the
        // Fill debited, not named; the recipient credited, named) made the caller's instruction unbalanced
        // (UnbalancedInstruction). After the CPI both edits land together at the instruction's end.
        // The order's rent drop (audit r1 I-1): the tombstone above was made out of it (create_pda
        // tops up only a shortfall, the settler's). What is left above the Fill's rent minimum pays
        // the recipient's account -- back to the payer when it was made here, else to the recipient
        // -- at most SOLANA_ATA_RENT; a relayer's own Fill rent stays for its claim. Only this order's
        // Fill is drawn, and never below its rent minimum.
        let ata_part = fill_spare(&a.fill)?.min(SOLANA_ATA_RENT);
        if ata_part > 0 {
            // To the recipient only when it stays rent-exempt with it (an empty wallet given a sliver
            // of a short drop could not hold it, and the settle must not fail): else to the payer.
            let r = a.recipient.to_account_info();
            if !ata_made_here && unpayable {
                // oft-lows5 (xd-solevm L-1) / oft-lows6 (oft-lows5-r1 L-1, I-1; decision "lead8: oft-lows5-r1
                // L-1/I-1/I-3"): a recipient that can never be credited (a program, or one the runtime keeps
                // read-only) cannot take the sender's unused ATA part either. It goes to the RECEIPT'S PAYER --
                // who already holds the sender's prepaid from this close for a manual return -- never to
                // whoever settles first, named by RentDropToReceiptPayer for the same return.
                let holder = a.receipt_payer.to_account_info();
                move_lamports(&a.fill, &holder, ata_part)?;
                emit!(RentDropToReceiptPayer { order_id: id, guid, recipient: *r.key, receipt_payer: *holder.key, lamports: ata_part });
            } else {
                let recipient_ok = !unpayable && r.lamports().saturating_add(ata_part) >= Rent::get()?.minimum_balance(r.data_len());
                let to = if ata_made_here || !recipient_ok { a.payer.to_account_info() } else { r };
                move_lamports(&a.fill, &to, ata_part)?;
                emit!(RentDropPaid { order_id: id, to: *to.key, lamports: ata_part });
            }
        }
        Ok(())
    }

    /// Not supported for LayerZero's own executor: settling needs the launch record and the mint,
    /// which a types call (handed only its own record) cannot read. Our delivery bot runs
    /// `lz_compose` instead; anyone may.
    pub fn lz_compose_types(_ctx: Context<LzComposeTypes>, _params: LzComposeParams) -> Result<Vec<LzAccount>> {
        err!(FastBridgeError::ComposeTypesUnsupported)
    }

    // ------------------------------------------------------------------------ admin

    /// Name the EVM chain's `PangeaFastBridge`, ONCE: a remote is where every order's tokens go, so
    /// it is never re-pointed. Called again with the SAME bridge it only updates the gas (each at
    /// most `MAX_REMOTE_GAS`); with another bridge, or after `revoke_remote`, it is refused
    /// (`RemoteAlreadySet`). A live remote set before this rule keeps working as it is. A bridge
    /// that already has a marker without this remote naming it -- the eid's v3 remote names it, or
    /// named it and was revoked or stopped -- is refused too (`RemoteAlreadySet`, audit I-2): a
    /// bridge revoked on one kind is never set again through the other.
    pub fn set_remote(ctx: Context<SetRemote>, eid: u32, bridge: [u8; 32], receive_gas: u128, compose_gas: u128) -> Result<()> {
        require!(eid != SOLANA_EID && eid != 0, FastBridgeError::NoRemote);
        require!(bridge != [0u8; 32], FastBridgeError::ZeroAddress);
        check_remote_gas(receive_gas, compose_gas)?;
        check_marker_not_stopped(&ctx.accounts.accepted)?;
        let r = &mut ctx.accounts.remote;
        check_set_once(r, eid, &bridge)?;
        check_marker_new_or_ours(&ctx.accounts.accepted, r, eid, &bridge)?;
        r.eid = eid;
        r.bridge = bridge;
        r.receive_gas = receive_gas;
        r.compose_gas = compose_gas;
        r.bump = ctx.bumps.remote;
        let m = &mut ctx.accounts.accepted;
        m.eid = eid;
        m.bridge = bridge;
        m.bump = ctx.bumps.accepted;
        emit!(RemoteSet { eid, bridge, receive_gas, compose_gas });
        Ok(())
    }

    /// Name the EVM chain's `PangeaFastBridgeV3`: where v3 tokens' orders go (`post_order`), and an
    /// accepted source of arrivals for good (the same `accepted` marker as `set_remote` writes).
    /// `receive_gas` must cover the v3 receive's gap reads (GapMath.GAP_READ_GAS) on top of the
    /// token's enforced options.
    ///
    /// Refused (`VaultNotComposer`) unless the OFT's `GapGlobal.composers` lists this program's
    /// vault (audit r1 L-2): otherwise a v3 order to Solana would be credited to the vault with no
    /// GapReceipt and could never settle. (The EVM side's V3 remote to Solana is held to the same
    /// by script/fastbridge/check-v3-remotes.mjs, deploy/setup.mjs and the go-live dry run.)
    ///
    /// Set ONCE, like `set_remote`: the same bridge again only updates the gas (bounded); another
    /// bridge, or one after `revoke_remote`, is refused -- and so is a bridge the eid's v1 remote
    /// names or named (its marker exists without this remote naming it; audit I-2), whether it was
    /// revoked or stopped there or is still the v1 remote.
    pub fn set_remote_v3(ctx: Context<SetRemoteV3>, eid: u32, bridge: [u8; 32], receive_gas: u128, compose_gas: u128) -> Result<()> {
        require!(eid != SOLANA_EID && eid != 0, FastBridgeError::NoRemote);
        require!(bridge != [0u8; 32], FastBridgeError::ZeroAddress);
        check_remote_gas(receive_gas, compose_gas)?;
        check_marker_not_stopped(&ctx.accounts.accepted)?;
        {
            let g = ctx.accounts.gap_global.to_account_info();
            require_keys_eq!(*g.owner, OFT_PROGRAM_ID, FastBridgeError::VaultNotComposer);
            let vault = Pubkey::create_program_address(&[VAULT_SEED, &[ctx.accounts.config.vault_bump]], &crate::ID).map_err(|_| error!(FastBridgeError::VaultNotComposer))?;
            let d = g.try_borrow_data()?;
            require!(gap_global_lists(&d, &vault), FastBridgeError::VaultNotComposer);
            // web-r3-a M-2 (pay once): toward a keys-only eid (GapGlobal.dst_delivery(eid) > 0) the OFT's send pays our
            // keys dst_delivery and LayerZero lzReceive gas 1 (KEYS_ONLY_OPTIONS); an order's own options must then carry
            // NO lzReceive gas (receive_gas 0: lzCompose only), else LayerZero is paid for a receive it never runs.
            // Elsewhere the receive gas is required as before. Set again (same bridge) when the OFT's setting changes.
            let keys_only = gap_global_dst_delivery(&d, eid) > 0;
            require!(keys_only == (receive_gas == 0) && compose_gas > 0, FastBridgeError::KeysOnlyGas);
        }
        let r = &mut ctx.accounts.remote_v3;
        check_set_once(r, eid, &bridge)?;
        check_marker_new_or_ours(&ctx.accounts.accepted, r, eid, &bridge)?;
        r.eid = eid;
        r.bridge = bridge;
        r.receive_gas = receive_gas;
        r.compose_gas = compose_gas;
        r.bump = ctx.bumps.remote_v3;
        let m = &mut ctx.accounts.accepted;
        m.eid = eid;
        m.bridge = bridge;
        m.bump = ctx.bumps.accepted;
        emit!(RemoteV3Set { eid, bridge, receive_gas, compose_gas });
        Ok(())
    }

    /// Step 1 of 2 of retiring a (wrong) counterpart `bridge` on `eid` (audit L-1): REVOKE. The v1
    /// and/or v3 remote that names it is cleared (bridge zero, eid kept), so no new order or quote
    /// goes to it (`NoRemote`) and it can never be set again (`RemoteAlreadySet`, set-once): fixing
    /// it means a new FastBridge. Arrivals composed by `bridge` are STILL accepted: its `accepted`
    /// marker stays, and is created here when the remote never got one (audit I-2), so an order in
    /// flight across the revocation still settles and the relayer who fronted it is repaid.
    /// Refusing its arrivals is the separate step 2, `stop_accepting`.
    ///
    /// Safe order across chains: revoke on the SOURCE chain(s) first, wait until every message
    /// already sent has landed (and settled) on the destination, then `stop_accepting` there. Both
    /// steps are irreversible. Refused (`NoRemote`) when no remote names `bridge` and it has no
    /// live marker: a revocation never makes an unknown bridge accepted.
    pub fn revoke_remote(ctx: Context<RevokeRemote>, eid: u32, bridge: [u8; 32]) -> Result<()> {
        require!(eid != 0 && bridge != [0u8; 32], FastBridgeError::NoRemote);
        let (v1, v3) = clear_remotes_naming(&ctx.accounts.remote.to_account_info(), &ctx.accounts.remote_v3.to_account_info(), eid, &bridge)?;
        let m = &mut ctx.accounts.accepted;
        if m.eid == 0 {
            // A fresh marker (the remote never got one): only for a bridge a remote named.
            require!(v1 || v3, FastBridgeError::NoRemote);
            m.eid = eid;
            m.bridge = bridge;
            m.bump = ctx.bumps.accepted;
        } else {
            // A live marker keeps accepting; a stopped one (bridge zero) stays stopped.
            require!(v1 || v3 || m.bridge == bridge, FastBridgeError::NoRemote);
        }
        emit!(RemoteRevoked { eid, bridge, v1, v3 });
        Ok(())
    }

    /// Step 2 of 2 (audit L-1): STOP ACCEPTING arrivals composed by `bridge` on `eid`: `lz_compose`,
    /// `settle_v3` and fills naming it are refused (`NotOurBridge`). Also revokes (step 1) any
    /// remote still naming it, since a current remote is itself an accepted source. The marker is
    /// kept as a tombstone (eid kept, bridge zero), never closed, so neither `set_remote` nor
    /// `set_remote_v3` can accept the bridge again. Irreversible. Run it only after the source
    /// chain(s) revoked and every in-flight message from `bridge` has landed: an arrival refused
    /// here waits in the endpoint for good. Refused (`NoRemote`) for a bridge no remote names and
    /// with no marker, and (`AlreadyStopped`) a second time.
    pub fn stop_accepting(ctx: Context<RevokeRemote>, eid: u32, bridge: [u8; 32]) -> Result<()> {
        require!(eid != 0 && bridge != [0u8; 32], FastBridgeError::NoRemote);
        let (v1, v3) = clear_remotes_naming(&ctx.accounts.remote.to_account_info(), &ctx.accounts.remote_v3.to_account_info(), eid, &bridge)?;
        let m = &mut ctx.accounts.accepted;
        if m.eid == 0 {
            require!(v1 || v3, FastBridgeError::NoRemote);
        } else {
            require!(m.bridge == bridge, FastBridgeError::AlreadyStopped);
        }
        m.eid = eid;
        m.bridge = [0u8; 32];
        m.bump = ctx.bumps.accepted;
        if v1 || v3 {
            emit!(RemoteRevoked { eid, bridge, v1, v3 });
        }
        emit!(RemoteStopped { eid, bridge });
        Ok(())
    }

    pub fn set_fees(ctx: Context<AdminOnly>, fast_fee_bps: u16, max_relayer_fee_bps: u16) -> Result<()> {
        require!(fast_fee_bps <= MAX_FAST_FEE_BPS, FastBridgeError::FastFeeTooHigh);
        require!(max_relayer_fee_bps <= MAX_RELAYER_FEE_CAP_BPS, FastBridgeError::NotAShare);
        let c = &mut ctx.accounts.config;
        c.fast_fee_bps = fast_fee_bps;
        c.max_relayer_fee_bps = max_relayer_fee_bps;
        emit!(FeesSet { launch_id: [0u8; 32], fast_fee_bps, max_relayer_fee_bps });
        Ok(())
    }

    pub fn set_launch_fees(ctx: Context<SetLaunchFees>, launch_id: [u8; 32], fast_fee_bps: u16, max_relayer_fee_bps: u16) -> Result<()> {
        require!(fast_fee_bps <= MAX_FAST_FEE_BPS, FastBridgeError::FastFeeTooHigh);
        require!(max_relayer_fee_bps <= MAX_RELAYER_FEE_CAP_BPS, FastBridgeError::NotAShare);
        let f = &mut ctx.accounts.launch_fees;
        f.launch_id = launch_id;
        f.fast_fee_bps = fast_fee_bps;
        f.max_relayer_fee_bps = max_relayer_fee_bps;
        f.bump = ctx.bumps.launch_fees;
        emit!(FeesSet { launch_id, fast_fee_bps, max_relayer_fee_bps });
        Ok(())
    }

    pub fn propose_admin(ctx: Context<AdminOnly>, to: Pubkey) -> Result<()> {
        require!(to != Pubkey::default(), FastBridgeError::ZeroAddress);
        ctx.accounts.config.pending_admin = to;
        Ok(())
    }

    pub fn accept_admin(ctx: Context<AcceptAdmin>) -> Result<()> {
        let c = &mut ctx.accounts.config;
        require_keys_eq!(c.pending_admin, ctx.accounts.new_admin.key(), FastBridgeError::NotPending);
        c.admin = c.pending_admin;
        c.pending_admin = Pubkey::default();
        Ok(())
    }
}

// ---------------------------------------------------------------------------- pure helpers

/// `post_order` (`v3_order` false, a live store) and `post_order_v3` (true, a v3 store; its
/// minimum is the following send's trailing min_credited_ld).
fn post_order_any(
    ctx: Context<PostOrder>,
    dst_eid: u32,
    to: [u8; 32],
    amount: u64,
    relayer_fee: u64,
    min_received: u64,
    v3_order: bool,
) -> Result<()> {
    require!(amount > 0, FastBridgeError::ZeroAmount);
    require!(dst_eid != SOLANA_EID, FastBridgeError::NoRemote);
    require!(to != [0u8; 32], FastBridgeError::ZeroAddress);
    // Every destination but Solana is an EVM chain, whose bridge refuses a recipient that is not
    // an address: refused here, before anything moves, rather than stranded there.
    require!(to[..12] == [0u8; 12], FastBridgeError::NotAnEvmAddress);

    let sender_nonce = {
        let r = &mut ctx.accounts.sender_nonce;
        let n = r.next;
        r.next = n.checked_add(1).ok_or(FastBridgeError::Overflow)?;
        r.bump = ctx.bumps.sender_nonce;
        n
    };
    let a = &ctx.accounts;
    // A v3 store's order goes to the EVM chain's FastBridge V3 (the first remaining account,
    // `PDA(["remote_v3", dst_eid])`); a live store's to the remote, exactly as before.
    let v3 = is_v3_store(&a.store.try_borrow_data()?);
    // A v3 store's orders are post_order_v3's (they carry a least credited amount), a live store's
    // post_order's: never the other way round, so a v3 order id always names its minimum.
    require!(v3 == v3_order, FastBridgeError::WrongOrderKind);
    // `post_order` names the eid's v1 remote, exactly as before; `post_order_v3` that or the eid's
    // v3 remote (audit L-3: an eid with only a v3 remote takes v3 orders). Its order still goes to
    // the v3 remote, the first remaining account.
    require!(remote_slot_ok(&a.remote.key(), a.remote.bump, dst_eid, v3), FastBridgeError::NoRemote);
    let (remote_bridge, receive_gas, compose_gas) = if v3 {
        let info = ctx.remaining_accounts.first().ok_or(FastBridgeError::NoRemote)?;
        let expected = Pubkey::find_program_address(&[REMOTE_V3_SEED, &dst_eid.to_be_bytes()], &crate::ID).0;
        require_keys_eq!(info.key(), expected, FastBridgeError::NoRemote);
        require_keys_eq!(*info.owner, crate::ID, FastBridgeError::NoRemote);
        let r = Remote::try_deserialize(&mut &info.try_borrow_data()?[..])?;
        require!(r.eid == dst_eid, FastBridgeError::NoRemote);
        // sol-lows (xa-final-sol L-1, pay once): set_remote_v3 checks the receive gas against the OFT's keys-only
        // setting only when the remote is set, and GapGlobal.dst_delivery(eid) is an OFT admin setting that can change
        // later (set_gap_dst_delivery). So every v3 order reads it again: the OFT's GapGlobal is the SECOND remaining
        // account (read only), and the order is refused (KeysOnlyGas) unless (dst_delivery(eid) > 0) == (receive_gas
        // == 0) -- else, toward an eid made keys-only after its remote was set, the user would pay LayerZero for an
        // lzReceive its executor never runs on top of our delivery. Go-live: set_gap_dst_delivery BEFORE set_remote_v3
        // (and set_remote_v3 again whenever an eid's keys-only setting changes).
        let g = ctx.remaining_accounts.get(1).ok_or(FastBridgeError::BadGapGlobal)?;
        let keys_only = gap_global_dst_delivery_for(g, dst_eid)? > 0;
        require!(keys_only == (r.receive_gas == 0), FastBridgeError::KeysOnlyGas);
        (r.bridge, r.receive_gas, r.compose_gas)
    } else {
        (a.remote.bridge, a.remote.receive_gas, a.remote.compose_gas)
    };
    require!(remote_bridge != [0u8; 32], FastBridgeError::NoRemote);
    // web-r3-a M-2: a v3 remote with receive_gas 0 is a keys-only destination's (set_remote_v3 checked it against the
    // OFT's GapGlobal.dst_delivery): its orders carry lzCompose gas only
    require!((receive_gas > 0 || v3) && compose_gas > 0, FastBridgeError::NoGasLimits);
    let (fast_bps, max_relayer_bps) = fees_for(&a.config, &a.launch_fees, &a.launch.launch_id)?;
    require_keys_eq!(a.store.key(), a.launch.store, FastBridgeError::NotOurToken);

    // Where the fast fee goes: the platform the splitter records, as for every other fee.
    let platform = platform_of(&a.platform_config)?;
    require_keys_eq!(a.platform_ata.owner, platform, FastBridgeError::WrongPlatform);
    let fast_fee = ((amount as u128) * (fast_bps as u128) / 10_000) as u64;
    if fast_fee > 0 {
        token_interface::transfer_checked(
            CpiContext::new(a.token_program.to_account_info(), TransferChecked {
                from: a.user_ata.to_account_info(),
                mint: a.mint.to_account_info(),
                to: a.platform_ata.to_account_info(),
                authority: a.user.to_account_info(),
            }),
            fast_fee,
            a.mint.decimals,
        )?;
    }
    let to_send = amount - fast_fee;

    // What the OFT will deliver of `to_send`, by its own rule for a Native store -- the dust
    // stays with the sender, the fee is the store's, rounded down to a whole bridged unit -- and
    // so what the send below must promise at least (`min_amount_ld`): a different outcome reverts it.
    // The OFT's rule exactly: `peer.fee_bps.unwrap_or(store.default_fee_bps)`.
    let fee_bps = match peer_fee_bps(&a.peer, &a.launch.store, dst_eid)? {
        Some(bps) => bps,
        None => store_fee_bps(&a.store)?,
    };
    let sent = to_send - to_send % DUST;
    let raw = ((sent as u128) * (fee_bps as u128) / 10_000) as u64;
    let token_fee = raw - raw % DUST;
    let arriving = sent - token_fee;
    require!(relayer_fee < arriving, FastBridgeError::FeeExceedsAmount);
    let most = ((arriving as u128) * (max_relayer_bps as u128) / 10_000) as u64;
    require!(relayer_fee <= most, FastBridgeError::RelayerFeeTooHigh);
    require!(arriving - relayer_fee >= min_received, FastBridgeError::ReceivesTooLittle);
    // A v3 order's least credited amount: the following OFT send's trailing min_credited_ld (u64
    // LE; absent = none, a written 0 refused as the OFT refuses it). Its place is known before the
    // minimum is: the send's data up to the 76-byte payload and the 16-byte fee tail has a fixed
    // length. Everything else about that send is checked below, the payload's minimum against it.
    let (min_credited_ld, send_tail) = if v3 {
        let base = 8 + 4 + 32 + 8 + 8 + 4 + executor_options(receive_gas, compose_gas).len() + 1 + 4 + V3_SOLANA_PAYLOAD_LEN + 16; // (compose-only when receive_gas 0)
        let ixs = a.instructions.to_account_info();
        let here = sysvar_instructions::load_current_index_checked(&ixs)? as usize;
        let next = sysvar_instructions::load_instruction_at_checked(here + 1, &ixs).map_err(|_| error!(FastBridgeError::SendNotNext))?;
        require_keys_eq!(next.program_id, OFT_PROGRAM_ID, FastBridgeError::SendNotNext);
        v3_send_minimum(&next.data, base)?
    } else {
        (0, 0)
    };
    // The least the destination may credit is at most what arrives (the OFT refuses a minimum
    // above the amount it sends: such a message could never land).
    require!(min_credited_ld <= arriving, FastBridgeError::MinCreditedTooHigh);

    // The message the send will make, by the endpoint's count.
    let peer = read_peer(&a.peer, &a.launch.store, dst_eid)?;
    let nonce_key = Pubkey::find_program_address(&[b"Nonce", a.launch.store.as_ref(), &dst_eid.to_be_bytes(), &peer], &LZ_ENDPOINT_ID).0;
    require_keys_eq!(a.endpoint_nonce.key(), nonce_key, FastBridgeError::NoRoute);
    let lz_nonce = outbound_nonce(&a.endpoint_nonce)?.checked_add(1).ok_or(FastBridgeError::Overflow)?;

    // The next instruction is that send, and nothing else.
    let sender = a.user.key().to_bytes();
    // A v3 store's order carries the compact v3 payload (76 bytes, minCredited last; the sender is
    // the send's signer, composeFrom): what lets the fast order fit one transaction once the send
    // carries the gap accounts and the minimum. A live store's goes to the v1/v2 bridge: ABI, as
    // ever. The order id is an ABI hash either way.
    let payload = if v3 {
        encode_v3_solana_payload(&a.launch.launch_id, sender_nonce, &to, relayer_fee, min_credited_ld)
    } else {
        encode_payload(&a.launch.launch_id, &sender, sender_nonce, &to, relayer_fee)
    };
    let options = executor_options(receive_gas, compose_gas);
    let ixs = a.instructions.to_account_info();
    let here = sysvar_instructions::load_current_index_checked(&ixs)? as usize;
    let next = sysvar_instructions::load_instruction_at_checked(here + 1, &ixs).map_err(|_| error!(FastBridgeError::SendNotNext))?;
    require_keys_eq!(next.program_id, OFT_PROGRAM_ID, FastBridgeError::SendNotNext);
    require!(next.accounts.len() > SEND_SOURCE_AT, FastBridgeError::SendNotNext);
    require!(next.accounts[0].pubkey == a.user.key() && next.accounts[0].is_signer, FastBridgeError::SendNotNext);
    require_keys_eq!(next.accounts[SEND_STORE_AT].pubkey, a.launch.store, FastBridgeError::SendNotNext);
    require_keys_eq!(next.accounts[SEND_SOURCE_AT].pubkey, a.user_ata.key(), FastBridgeError::SendNotNext);
    let mut want = OFT_SEND_DISCRIMINATOR.to_vec();
    want.extend_from_slice(&dst_eid.to_le_bytes());
    want.extend_from_slice(&remote_bridge);
    want.extend_from_slice(&to_send.to_le_bytes());
    want.extend_from_slice(&arriving.to_le_bytes());
    want.extend_from_slice(&(options.len() as u32).to_le_bytes());
    want.extend_from_slice(&options);
    want.push(1);
    want.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    want.extend_from_slice(&payload);
    // Then native_fee (the sender's business) and lz_token_fee (none): 16 bytes; then, for a v3
    // order, the v3 OFT's trailing bytes as read above (v3_send_minimum): min_credited_ld, exactly
    // this order's (absent when 0 and no min_ps_usd follows, as the OFT requires), then the
    // optional min_ps_usd (the sender's, not part of the order): the gap header then carries the
    // same minimum the payload and the order id name.
    let tail = send_tail;
    require!(next.data.len() == want.len() + 16 + tail && next.data[..want.len()] == want[..], FastBridgeError::SendNotNext);
    require!(next.data[want.len() + 8..want.len() + 16] == [0u8; 8], FastBridgeError::SendNotNext);
    if tail != 0 {
        require!(next.data[want.len() + 16..want.len() + 24] == min_credited_ld.to_le_bytes(), FastBridgeError::SendNotNext);
    }

    // A Solana order's source on the EVM side is its sender (see above).
    if v3 {
        let order_id = order_id_v3(SOLANA_EID, &sender, &a.launch.launch_id, &sender, sender_nonce, dst_eid, &to, arriving, relayer_fee, min_credited_ld);
        emit!(OrderPostedV3 {
            order_id,
            launch_id: a.launch.launch_id,
            dst_eid,
            sender,
            sender_nonce,
            to,
            amount: arriving,
            relayer_fee,
            min_credited: min_credited_ld,
            lz_nonce,
        });
        return Ok(());
    }
    let order_id = order_id(SOLANA_EID, &sender, &a.launch.launch_id, &sender, sender_nonce, dst_eid, &to, arriving, relayer_fee);
    emit!(OrderPosted {
        order_id,
        launch_id: a.launch.launch_id,
        dst_eid,
        sender,
        sender_nonce,
        to,
        amount: arriving,
        relayer_fee,
        lz_nonce,
    });
    Ok(())
}

/// `fill_order` (`min_credited` None: a v1/v2 order's id) and `fill_order_v3` (Some: a v3 order's).
#[allow(clippy::too_many_arguments)]
fn fill_order_any(
    ctx: Context<FillOrder>,
    src_eid: u32,
    src_bridge: [u8; 32],
    sender: [u8; 32],
    sender_nonce: u64,
    amount: u64,
    relayer_fee: u64,
    min_credited: Option<u64>,
    lz_nonce: u64,
) -> Result<()> {
    let a = &ctx.accounts;
    require!(relayer_fee < amount, FastBridgeError::FeeExceedsAmount);
    // `fill_order` names the eid's v1 remote, exactly as before; `fill_order_v3` that or the eid's
    // v3 remote (audit L-3: an eid with only a v3 remote is filled).
    require!(remote_slot_ok(&a.remote.key(), a.remote.bump, src_eid, min_credited.is_some()), FastBridgeError::NoRemote);
    // The bridge the order was posted through: the current counterpart or one set before.
    require!(is_accepted(&a.remote, &a.accepted, src_eid, &src_bridge), FastBridgeError::NotOurBridge);
    let to = a.recipient.key().to_bytes();
    let id = match min_credited {
        Some(m) => {
            require!(m <= amount, FastBridgeError::MinCreditedTooHigh);
            order_id_v3(src_eid, &src_bridge, &a.launch.launch_id, &sender, sender_nonce, SOLANA_EID, &to, amount, relayer_fee, m)
        }
        None => order_id(src_eid, &src_bridge, &a.launch.launch_id, &sender, sender_nonce, SOLANA_EID, &to, amount, relayer_fee),
    };

    // Not yet arrived: the route exists, the message under `lz_nonce` is neither verified and
    // waiting nor already past the endpoint's inbound nonce.
    let peer = read_peer(&a.peer, &a.launch.store, src_eid)?;
    let nonce_key = Pubkey::find_program_address(&[b"Nonce", a.launch.store.as_ref(), &src_eid.to_be_bytes(), &peer], &LZ_ENDPOINT_ID).0;
    require_keys_eq!(a.endpoint_nonce.key(), nonce_key, FastBridgeError::TooLateToFill);
    require_keys_eq!(*a.endpoint_nonce.owner, LZ_ENDPOINT_ID, FastBridgeError::TooLateToFill);
    let inbound = inbound_nonce(&a.endpoint_nonce)?;
    require!(lz_nonce > inbound, FastBridgeError::TooLateToFill);
    let hash_key = Pubkey::find_program_address(
        &[b"PayloadHash", a.launch.store.as_ref(), &src_eid.to_be_bytes(), &peer, &lz_nonce.to_be_bytes()],
        &LZ_ENDPOINT_ID,
    )
    .0;
    require_keys_eq!(a.payload_hash.key(), hash_key, FastBridgeError::TooLateToFill);
    if *a.payload_hash.owner == LZ_ENDPOINT_ID {
        let d = a.payload_hash.try_borrow_data()?;
        require!(d.len() < 40 || d[8..40] == [0u8; 32], FastBridgeError::TooLateToFill);
    }

    // The fill's record, at the order's own address: one fill per order.
    let (fill_key, fill_bump) = Pubkey::find_program_address(&[FILL_SEED, &id], &crate::ID);
    require_keys_eq!(a.fill.key(), fill_key, FastBridgeError::OrderMismatch);
    require!(a.fill.data_is_empty() && *a.fill.owner == anchor_lang::system_program::ID, FastBridgeError::AlreadyFilled);
    create_pda(&a.relayer.to_account_info(), &a.fill, &a.system_program.to_account_info(), 8 + Fill::INIT_SPACE, &[FILL_SEED, &id, &[fill_bump]])?;
    let slot = Clock::get()?.slot;
    let record = Fill { relayer: a.relayer.key(), mint: a.launch.mint, lz_nonce, slot, owed: 0, settled: false, bump: fill_bump };
    let mut d = a.fill.try_borrow_mut_data()?;
    d[..8].copy_from_slice(&Fill::DISCRIMINATOR);
    record.serialize(&mut &mut d[8..])?;
    drop(d);

    let paid = amount - relayer_fee;
    token_interface::transfer_checked(
        CpiContext::new(a.token_program.to_account_info(), TransferChecked {
            from: a.relayer_ata.to_account_info(),
            mint: a.mint.to_account_info(),
            to: a.recipient_ata.to_account_info(),
            authority: a.relayer.to_account_info(),
        }),
        paid,
        a.mint.decimals,
    )?;
    emit!(OrderFilled { order_id: id, relayer: a.relayer.key(), to: a.recipient.key(), paid });
    Ok(())
}

/// The v3 OFT send's 25th trailing byte with only REQUIRE_COVER set (OFT send.rs
/// SEND_FLAG_REQUIRE_COVER).
pub const OFT_SEND_FLAG_REQUIRE_COVER: u8 = 1;

/// The v3 OFT send's optional trailing minimums after its fee tail (`base` = where they start), as
/// the OFT reads them (SendParams, BRIEF Amendment 4, v3c-oft-s3): (min_credited_ld, trailing length).
///   0 bytes  no minimum;
///   8 bytes  min_credited_ld, non-zero (a written 0 the OFT refuses);
///   24 bytes min_credited_ld (any, 0 included) then min_ps_usd u128 LE, non-zero;
///   25 bytes min_credited_ld (any) | min_ps_usd u128 LE (any) | flags = OFT_SEND_FLAG_REQUIRE_COVER.
/// Anything else (the OFT would read 9..23 as 8 and ignore the rest, refuse another flags byte, or
/// ignore what is past 25) is not a send this program knows: SendNotNext.

pub fn v3_send_minimum(data: &[u8], base: usize) -> Result<(u64, usize)> {
    require!(data.len() >= base, FastBridgeError::SendNotNext);
    let t = &data[base..];
    match t.len() {
        0 => Ok((0, 0)),
        8 => {
            let m = u64::from_le_bytes(t.try_into().unwrap());
            require!(m != 0, FastBridgeError::SendNotNext);
            Ok((m, 8))
        }
        24 => {
            let m = u64::from_le_bytes(t[..8].try_into().unwrap());
            let ps = u128::from_le_bytes(t[8..].try_into().unwrap());
            require!(ps != 0, FastBridgeError::SendNotNext);
            Ok((m, 24))
        }
        // the OFT's step-3 tail: min_credited_ld (any) | min_ps_usd (any) | flags = REQUIRE_COVER
        // exactly, so a fast order can require the gas cover (the OFT refuses any other flags byte)
        25 => {
            require!(t[24] == OFT_SEND_FLAG_REQUIRE_COVER, FastBridgeError::SendNotNext);
            Ok((u64::from_le_bytes(t[..8].try_into().unwrap()), 25))
        }
        _ => err!(FastBridgeError::SendNotNext),
    }
}

/// Whether an OFT store is a v3 store (`init_oft_v3`: at least 319 bytes; a live store is 223).
pub fn is_v3_store(store_data: &[u8]) -> bool {
    store_data.len() >= V3_STORE_LEN
}

/// A v3 store's record of one composed arrival (spec §10.5, f364d1da), as the OFT program writes
/// it: discriminator 8 | version @8 | bump @9 | oft_store @10 | guid @42 | src_eid u32 LE @74 |
/// nonce u64 LE @78 | to @86 | payer @118 | amount_ld @150 | withheld_ld @158 | credited_ld @166 |
/// reason @174 | created_at i64 @175 | compose_from @183 | compose_msg (u32 LE length @215, bytes
/// @219), at most 512 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GapReceiptView<'a> {
    pub oft_store: Pubkey,
    pub guid: [u8; 32],
    pub src_eid: u32,
    pub nonce: u64,
    pub to: Pubkey,
    pub payer: Pubkey,
    pub amount_ld: u64,
    pub withheld_ld: u64,
    pub credited_ld: u64,
    pub reason: u8,
    pub created_at: i64,
    pub compose_from: [u8; 32],
    pub compose_msg: &'a [u8],
}

/// A receipt's fields, or None if `d` is not one (discriminator, version 1, lengths).
pub fn read_gap_receipt(d: &[u8]) -> Option<GapReceiptView<'_>> {
    if d.len() < GAP_RECEIPT_FIXED_LEN || d[..8] != GAP_RECEIPT_DISCRIMINATOR || d[8] != 1 {
        return None;
    }
    let key = |at: usize| -> Option<Pubkey> { Some(Pubkey::new_from_array(d.get(at..at + 32)?.try_into().ok()?)) };
    let u64_at = |at: usize| -> Option<u64> { Some(u64::from_le_bytes(d.get(at..at + 8)?.try_into().ok()?)) };
    let len = u32::from_le_bytes(d[215..219].try_into().ok()?) as usize;
    if len > GAP_RECEIPT_MAX_MSG {
        return None;
    }
    Some(GapReceiptView {
        oft_store: key(10)?,
        guid: d[42..74].try_into().ok()?,
        src_eid: u32::from_le_bytes(d[74..78].try_into().ok()?),
        nonce: u64_at(78)?,
        to: key(86)?,
        payer: key(118)?,
        amount_ld: u64_at(150)?,
        withheld_ld: u64_at(158)?,
        credited_ld: u64_at(166)?,
        reason: d[174],
        created_at: i64::from_le_bytes(d[175..183].try_into().ok()?),
        compose_from: d[183..215].try_into().ok()?,
        compose_msg: d.get(219..219 + len)?,
    })
}

/// Every account `settle_v3` takes, in order: what a delivery bot sends for the receipt of `guid`
/// on the launch whose store is `store` and mint `mint`, from `src_eid` and `compose_from`,
/// for the recipient `to`, with the order's fill address `fill`. (pubkey, is_signer, is_writable).
#[allow(clippy::too_many_arguments)]
/// oft-lows3 (L-2): `compose_msg` (the receipt's) names the OFT's GapLatePrepay record, the last account.
pub fn settle_v3_accounts(payer: Pubkey, store: Pubkey, mint: Pubkey, src_eid: u32, compose_from: &[u8; 32], compose_msg: &[u8], fill: Pubkey, to: Pubkey, guid: &[u8; 32], receipt_payer: Pubkey) -> Vec<(Pubkey, bool, bool)> {
    let token_2022 = anchor_spl::token_2022::ID;
    let ata = |owner: &Pubkey| anchor_spl::associated_token::get_associated_token_address_with_program_id(owner, &mint, &token_2022);
    let vault = Pubkey::find_program_address(&[VAULT_SEED], &crate::ID).0;
    vec![
        (payer, true, true),
        (Pubkey::find_program_address(&[CONFIG_SEED], &crate::ID).0, false, false),
        (vault, false, false),
        (Pubkey::find_program_address(&[LAUNCH_SEED, store.as_ref()], &crate::ID).0, false, false),
        (mint, false, false),
        (ata(&vault), false, true),
        // The v3 remote (audit L-3): an eid with no v1 remote settles too.
        (Pubkey::find_program_address(&[REMOTE_V3_SEED, &src_eid.to_be_bytes()], &crate::ID).0, false, false),
        (Pubkey::find_program_address(&[ACCEPTED_SEED, &src_eid.to_be_bytes(), compose_from], &crate::ID).0, false, false),
        (fill, false, true),
        // Writable: the order's unused ATA rent drop goes back to the recipient (audit r1 I-1), and
        // the receipt's prepaid lamports are paid to it on close (L4).
        (to, false, true),
        (ata(&to), false, true),
        (Pubkey::find_program_address(&[GAP_RECEIPT_SEED, guid], &OFT_PROGRAM_ID).0, false, true),
        (receipt_payer, false, true),
        (OFT_PROGRAM_ID, false, false),
        (token_2022, false, false),
        (anchor_spl::associated_token::ID, false, false),
        (anchor_lang::system_program::ID, false, false),
        // oft-lows3 (L-2): the OFT's GapLatePrepay record of the receipt's prepay PDA (written by the close)
        (late_prepay_address(&store, src_eid, compose_from, compose_msg), false, true),
    ]
}

/// The splitter's derivation of a launch's OFT store from its seed.
pub fn store_of_launch(seed: &[u8; 32]) -> Pubkey {
    let escrow = Pubkey::find_program_address(&[SPLITTER_ESCROW_SEED, seed.as_ref()], &SPLITTER_ID).0;
    Pubkey::find_program_address(&[OFT_STORE_SEED, escrow.as_ref()], &OFT_PROGRAM_ID).0
}

/// The launch id every chain names a launch by: sha256("pangea launch id" || seed), as the splitter.
pub fn launch_id_of(seed: &[u8; 32]) -> [u8; 32] {
    sha256v(&[LAUNCH_ID_DOMAIN, seed.as_ref()]).to_bytes()
}

fn word_u32(v: u32) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[28..].copy_from_slice(&v.to_be_bytes());
    w
}

fn word_u64(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

/// An ABI word that must hold a uint64.
pub fn word_to_u64(w: &[u8]) -> Option<u64> {
    if w.len() != 32 || w[..24] != [0u8; 24] {
        return None;
    }
    Some(u64::from_be_bytes(w[24..].try_into().unwrap()))
}

fn word_u64_checked(w: &[u8]) -> Result<u64> {
    word_to_u64(w).ok_or(error!(FastBridgeError::BadPayload))
}

/// A v1/v2 order's five fields, from either encoding: the packed 112 bytes, or the 160 bytes of ABI
/// words. A v3 order's payload is `decode_v3_payload`'s.
pub fn decode_payload(p: &[u8]) -> Result<([u8; 32], [u8; 32], u64, [u8; 32], u64)> {
    match p.len() {
        PACKED_PAYLOAD_LEN => Ok((
            p[0..32].try_into().unwrap(),
            p[32..64].try_into().unwrap(),
            u64::from_be_bytes(p[64..72].try_into().unwrap()),
            p[72..104].try_into().unwrap(),
            u64::from_be_bytes(p[104..112].try_into().unwrap()),
        )),
        PAYLOAD_LEN => Ok((
            p[0..32].try_into().unwrap(),
            p[32..64].try_into().unwrap(),
            word_u64_checked(&p[64..96])?,
            p[96..128].try_into().unwrap(),
            word_u64_checked(&p[128..160])?,
        )),
        _ => err!(FastBridgeError::BadPayload),
    }
}

/// A v3 order's payload arriving on Solana from an EVM chain: 120 bytes (`V3_PAYLOAD_LEN`).
pub fn decode_v3_payload(p: &[u8]) -> Result<([u8; 32], [u8; 32], u64, [u8; 32], u64, u64)> {
    require!(p.len() == V3_PAYLOAD_LEN, FastBridgeError::BadPayload);
    Ok((
        p[0..32].try_into().unwrap(),
        p[32..64].try_into().unwrap(),
        u64::from_be_bytes(p[64..72].try_into().unwrap()),
        p[72..104].try_into().unwrap(),
        u64::from_be_bytes(p[104..112].try_into().unwrap()),
        u64::from_be_bytes(p[112..120].try_into().unwrap()),
    ))
}

/// launchId (32) | sender (32) | senderNonce (8, BE) | to (32) | relayerFee (8, BE): a v1/v2 order's
/// packed form (`PACKED_PAYLOAD_LEN`).
pub fn encode_packed_payload(launch_id: &[u8; 32], sender: &[u8; 32], sender_nonce: u64, to: &[u8; 32], relayer_fee: u64) -> Vec<u8> {
    let mut p = Vec::with_capacity(PACKED_PAYLOAD_LEN);
    p.extend_from_slice(launch_id);
    p.extend_from_slice(sender);
    p.extend_from_slice(&sender_nonce.to_be_bytes());
    p.extend_from_slice(to);
    p.extend_from_slice(&relayer_fee.to_be_bytes());
    p
}

/// launchId (32) | senderNonce (8, BE) | to (20: the EVM address) | relayerFee (8, BE) | minCredited
/// (8, BE): a v3 order's payload from Solana (`V3_SOLANA_PAYLOAD_LEN`). `to` is a left-padded
/// EVM address (post_order refuses any other).
pub fn encode_v3_solana_payload(launch_id: &[u8; 32], sender_nonce: u64, to: &[u8; 32], relayer_fee: u64, min_credited: u64) -> Vec<u8> {
    let mut p = Vec::with_capacity(V3_SOLANA_PAYLOAD_LEN);
    p.extend_from_slice(launch_id);
    p.extend_from_slice(&sender_nonce.to_be_bytes());
    p.extend_from_slice(&to[12..]);
    p.extend_from_slice(&relayer_fee.to_be_bytes());
    p.extend_from_slice(&min_credited.to_be_bytes());
    p
}

/// launchId (32) | sender (32) | senderNonce (8, BE) | to (32) | relayerFee (8, BE) | minCredited
/// (8, BE): a v3 order's payload from an EVM chain to Solana (what settle_v3 reads).
pub fn encode_v3_payload(launch_id: &[u8; 32], sender: &[u8; 32], sender_nonce: u64, to: &[u8; 32], relayer_fee: u64, min_credited: u64) -> Vec<u8> {
    let mut p = Vec::with_capacity(V3_PAYLOAD_LEN);
    p.extend_from_slice(launch_id);
    p.extend_from_slice(sender);
    p.extend_from_slice(&sender_nonce.to_be_bytes());
    p.extend_from_slice(to);
    p.extend_from_slice(&relayer_fee.to_be_bytes());
    p.extend_from_slice(&min_credited.to_be_bytes());
    p
}

/// abi.encode(bytes32 launchId, bytes32 sender, uint64 senderNonce, bytes32 to, uint256 relayerFee)
pub fn encode_payload(launch_id: &[u8; 32], sender: &[u8; 32], sender_nonce: u64, to: &[u8; 32], relayer_fee: u64) -> Vec<u8> {
    let mut p = Vec::with_capacity(PAYLOAD_LEN);
    p.extend_from_slice(launch_id);
    p.extend_from_slice(sender);
    p.extend_from_slice(&self::word_u64_raw(sender_nonce));
    p.extend_from_slice(to);
    p.extend_from_slice(&self::word_u64_raw(relayer_fee));
    p
}

fn word_u64_raw(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

/// keccak256(abi.encode(uint32 srcEid, bytes32 srcBridge, bytes32 launchId, bytes32 sender,
/// uint64 senderNonce, uint32 dstEid, bytes32 to, uint256 amount, uint256 relayerFee))
#[allow(clippy::too_many_arguments)]
pub fn order_id(
    src_eid: u32,
    src_bridge: &[u8; 32],
    launch_id: &[u8; 32],
    sender: &[u8; 32],
    sender_nonce: u64,
    dst_eid: u32,
    to: &[u8; 32],
    amount: u64,
    relayer_fee: u64,
) -> [u8; 32] {
    keccak256v(&[
        &word_u32(src_eid),
        src_bridge,
        launch_id,
        sender,
        &word_u64(sender_nonce),
        &word_u32(dst_eid),
        to,
        &word_u64(amount),
        &word_u64(relayer_fee),
    ])
    .to_bytes()
}

/// A v3 order's id, as `PangeaFastBridgeV3.orderId`: keccak256(abi.encode(uint32 srcEid, bytes32
/// srcBridge, bytes32 launchId, bytes32 sender, uint64 senderNonce, uint32 dstEid, bytes32 to,
/// uint256 amount, uint256 relayerFee, uint256 minCredited)), `amount` the GROSS arriving amount.
#[allow(clippy::too_many_arguments)]
pub fn order_id_v3(
    src_eid: u32,
    src_bridge: &[u8; 32],
    launch_id: &[u8; 32],
    sender: &[u8; 32],
    sender_nonce: u64,
    dst_eid: u32,
    to: &[u8; 32],
    amount: u64,
    relayer_fee: u64,
    min_credited: u64,
) -> [u8; 32] {
    keccak256v(&[
        &word_u32(src_eid),
        src_bridge,
        launch_id,
        sender,
        &word_u64(sender_nonce),
        &word_u32(dst_eid),
        to,
        &word_u64(amount),
        &word_u64(relayer_fee),
        &word_u64(min_credited),
    ])
    .to_bytes()
}

/// Executor options, type 3, as `PangeaFastBridge.optionsFor`: lzReceive gas, then lzCompose
/// (index 0) gas. web-r3-a M-2: `receive_gas` 0 (a keys-only destination's v3 remote) gives the lzCompose
/// option ALONE: the OFT adds KEYS_ONLY_OPTIONS (lzReceive gas 1), so LayerZero is paid for one receive gas.
pub fn executor_options(receive_gas: u128, compose_gas: u128) -> Vec<u8> {
    let mut o = Vec::with_capacity(2 + 20 + 22);
    o.extend_from_slice(&3u16.to_be_bytes());
    if receive_gas > 0 {
        o.push(1);
        o.extend_from_slice(&17u16.to_be_bytes());
        o.push(1);
        o.extend_from_slice(&receive_gas.to_be_bytes());
    }
    o.push(1);
    o.extend_from_slice(&19u16.to_be_bytes());
    o.push(3);
    o.extend_from_slice(&0u16.to_be_bytes());
    o.extend_from_slice(&compose_gas.to_be_bytes());
    o
}

fn anchor_disc(name: &str) -> [u8; 8] {
    let h = sha256v(&[name.as_bytes()]).to_bytes();
    h[..8].try_into().unwrap()
}

fn token_amount(info: &AccountInfo) -> Result<u64> {
    let d = info.try_borrow_data()?;
    require!(d.len() >= 72, FastBridgeError::BadSendAccounts);
    Ok(u64::from_le_bytes(d[64..72].try_into().unwrap()))
}

/// The OFT store's peer on `eid`, from the OFT's own account.
fn read_peer(info: &AccountInfo, store: &Pubkey, eid: u32) -> Result<[u8; 32]> {
    let expected = Pubkey::find_program_address(&[OFT_PEER_SEED, store.as_ref(), &eid.to_be_bytes()], &OFT_PROGRAM_ID).0;
    require_keys_eq!(info.key(), expected, FastBridgeError::NoRoute);
    require_keys_eq!(*info.owner, OFT_PROGRAM_ID, FastBridgeError::NoRoute);
    let d = info.try_borrow_data()?;
    require!(d.len() >= 40, FastBridgeError::NoRoute);
    Ok(d[8..40].try_into().unwrap())
}

/// The peer's own bridge fee, if it has one: `PeerConfig` is peer_address (32), enforced_options
/// (two Borsh `Vec<u8>`), two `Option<RateLimiter>` (32 bytes each when present), then
/// `fee_bps: Option<u16>`.
fn peer_fee_bps(info: &AccountInfo, store: &Pubkey, eid: u32) -> Result<Option<u16>> {
    read_peer(info, store, eid)?;
    let d = info.try_borrow_data()?;
    let mut at = 40usize;
    let take = |at: &mut usize, n: usize| -> Result<usize> {
        let start = *at;
        *at = at.checked_add(n).ok_or(error!(FastBridgeError::NoRoute))?;
        require!(*at <= d.len(), FastBridgeError::NoRoute);
        Ok(start)
    };
    for _ in 0..2 {
        let p = take(&mut at, 4)?;
        let len = u32::from_le_bytes(d[p..p + 4].try_into().unwrap()) as usize;
        take(&mut at, len)?;
    }
    for _ in 0..2 {
        let p = take(&mut at, 1)?;
        match d[p] {
            0 => {}
            1 => {
                take(&mut at, 32)?;
            }
            _ => return err!(FastBridgeError::NoRoute),
        }
    }
    let p = take(&mut at, 1)?;
    match d[p] {
        0 => Ok(None),
        1 => {
            let q = take(&mut at, 2)?;
            Ok(Some(u16::from_le_bytes(d[q..q + 2].try_into().unwrap())))
        }
        _ => err!(FastBridgeError::NoRoute),
    }
}

/// The store's default bridge fee, from the OFT's own account.
fn store_fee_bps(info: &AccountInfo) -> Result<u16> {
    require_keys_eq!(*info.owner, OFT_PROGRAM_ID, FastBridgeError::NotOurToken);
    let d = info.try_borrow_data()?;
    require!(d.len() >= OFT_STORE_DEFAULT_FEE_BPS + 2 && d[..8] == OFT_STORE_DISCRIMINATOR, FastBridgeError::NotOurToken);
    Ok(u16::from_le_bytes(d[OFT_STORE_DEFAULT_FEE_BPS..OFT_STORE_DEFAULT_FEE_BPS + 2].try_into().unwrap()))
}

fn outbound_nonce(info: &AccountInfo) -> Result<u64> {
    require_keys_eq!(*info.owner, LZ_ENDPOINT_ID, FastBridgeError::NoRoute);
    let d = info.try_borrow_data()?;
    require!(d.len() >= 25, FastBridgeError::NoRoute);
    Ok(u64::from_le_bytes(d[9..17].try_into().unwrap()))
}

fn inbound_nonce(info: &AccountInfo) -> Result<u64> {
    let d = info.try_borrow_data()?;
    require!(d.len() >= 25, FastBridgeError::NoRoute);
    Ok(u64::from_le_bytes(d[17..25].try_into().unwrap()))
}

/// Whether `bridge` is our counterpart on `eid`: the current one, or one set before whose marker
/// is live (names `bridge`). A revoked remote's marker stays live (`revoke_remote`) until
/// `stop_accepting` tombstones it (bridge zero); a tombstone accepts nothing.
fn is_accepted(remote: &Remote, marker: &AccountInfo, eid: u32, bridge: &[u8; 32]) -> bool {
    if *bridge == [0u8; 32] || remote.eid != eid {
        return false;
    }
    if *bridge == remote.bridge {
        return true;
    }
    let expected = Pubkey::find_program_address(&[ACCEPTED_SEED, &eid.to_be_bytes(), bridge], &crate::ID).0;
    if marker.key() != expected || *marker.owner != crate::ID || marker.data_is_empty() {
        return false;
    }
    let Ok(d) = marker.try_borrow_data() else { return false };
    match Accepted::try_deserialize(&mut &d[..]) {
        Ok(m) => m.eid == eid && m.bridge == *bridge,
        Err(_) => false,
    }
}

/// Whether `key` is the remote account an instruction may name for `eid`: the v1 remote
/// `PDA(["remote", eid])` always (unchanged), and -- for a v3 instruction (`v3`: post_order_v3,
/// fill_order_v3, settle_v3) -- the v3 remote `PDA(["remote_v3", eid])` too (audit L-3), so an eid
/// with no v1 remote is still served. `bump` is the account's own (a Remote is only ever created
/// at its canonical address); the account's owner and type are the caller's `Account<Remote>`.
fn remote_slot_ok(key: &Pubkey, bump: u8, eid: u32, v3: bool) -> bool {
    let at = |seed: &[u8]| Pubkey::create_program_address(&[seed, &eid.to_be_bytes(), &[bump]], &crate::ID).ok();
    at(REMOTE_SEED) == Some(*key) || (v3 && at(REMOTE_V3_SEED) == Some(*key))
}

/// Audit I-2: a bridge whose marker existed before this call (it was named by a remote of the
/// other kind, or by one since revoked or re-pointed) is never named by a remote that does not
/// already name it -- so a bridge revoked on one kind is not set again through the other, and a
/// bridge is never the v1 and the v3 remote of an eid at once. `m` is the marker as found (eid 0:
/// made by this call), `r` the remote being set.
fn check_marker_new_or_ours(m: &Accepted, r: &Remote, eid: u32, bridge: &[u8; 32]) -> Result<()> {
    require!(m.eid == 0 || (r.eid == eid && r.bridge == *bridge), FastBridgeError::RemoteAlreadySet);
    Ok(())
}

/// A remote is set once: a fresh account (eid 0) takes any bridge; one already set takes only
/// the same bridge again (a gas update); a revoked one (bridge zero) takes none. Eid 0 is refused
/// (audit I-3): a remote written with eid 0 would read as fresh and could be re-pointed.
fn check_set_once(r: &Remote, eid: u32, bridge: &[u8; 32]) -> Result<()> {
    require!(eid != 0, FastBridgeError::NoRemote);
    if r.eid != 0 {
        require!(r.eid == eid && r.bridge != [0u8; 32] && r.bridge == *bridge, FastBridgeError::RemoteAlreadySet);
    }
    Ok(())
}

/// A marker `stop_accepting` tombstoned (eid kept, bridge zero) is never accepted again: setting a
/// remote, v1 or v3, to that bridge is refused.
fn check_marker_not_stopped(m: &Accepted) -> Result<()> {
    require!(!(m.eid != 0 && m.bridge == [0u8; 32]), FastBridgeError::RemoteAlreadySet);
    Ok(())
}

/// Clear the v1 and/or v3 remote of `eid` that names `bridge` (bridge zero, eid kept); returns which
/// were cleared. Each account must be its PDA; one that does not exist is skipped.
fn clear_remotes_naming<'a>(remote: &AccountInfo<'a>, remote_v3: &AccountInfo<'a>, eid: u32, bridge: &[u8; 32]) -> Result<(bool, bool)> {
    let mut hits = [false; 2];
    for (k, (info, seed)) in [(remote, REMOTE_SEED), (remote_v3, REMOTE_V3_SEED)].into_iter().enumerate() {
        let expected = Pubkey::find_program_address(&[seed, &eid.to_be_bytes()], &crate::ID).0;
        require_keys_eq!(info.key(), expected, FastBridgeError::NoRemote);
        if *info.owner != crate::ID || info.data_is_empty() {
            continue;
        }
        let mut r = Remote::try_deserialize(&mut &info.try_borrow_data()?[..])?;
        if r.eid == eid && r.bridge == *bridge {
            r.bridge = [0u8; 32];
            let mut d = info.try_borrow_mut_data()?;
            r.try_serialize(&mut &mut d[..])?;
            hits[k] = true;
        }
    }
    Ok((hits[0], hits[1]))
}

/// Each of a remote's gas limits is at most `MAX_REMOTE_GAS`.
fn check_remote_gas(receive_gas: u128, compose_gas: u128) -> Result<()> {
    require!(receive_gas <= MAX_REMOTE_GAS && compose_gas <= MAX_REMOTE_GAS, FastBridgeError::GasLimitTooHigh);
    Ok(())
}

/// The platform the splitter records; its admin while there is no record.
fn platform_of(config: &AccountInfo) -> Result<Pubkey> {
    let expected = Pubkey::find_program_address(&[SPLITTER_PLATFORM_SEED], &SPLITTER_ID).0;
    require_keys_eq!(config.key(), expected, FastBridgeError::WrongPlatform);
    if config.data_is_empty() {
        return Ok(INIT_AUTHORITY);
    }
    require_keys_eq!(*config.owner, SPLITTER_ID, FastBridgeError::WrongPlatform);
    let d = config.try_borrow_data()?;
    require!(d.len() >= 40, FastBridgeError::WrongPlatform);
    let p = Pubkey::new_from_array(d[8..40].try_into().unwrap());
    Ok(if p == Pubkey::default() { INIT_AUTHORITY } else { p })
}

/// The launch's own fee setting, or the program's.
fn fees_for(config: &Config, launch_fees: &AccountInfo, launch_id: &[u8; 32]) -> Result<(u16, u16)> {
    let expected = Pubkey::find_program_address(&[LAUNCH_FEES_SEED, launch_id], &crate::ID).0;
    require_keys_eq!(launch_fees.key(), expected, FastBridgeError::OrderMismatch);
    if *launch_fees.owner == crate::ID && !launch_fees.data_is_empty() {
        let f = LaunchFees::try_deserialize(&mut &launch_fees.try_borrow_data()?[..])?;
        return Ok((f.fast_fee_bps, f.max_relayer_fee_bps));
    }
    Ok((config.fast_fee_bps, config.max_relayer_fee_bps))
}

fn create_pda<'info>(payer: &AccountInfo<'info>, target: &AccountInfo<'info>, system: &AccountInfo<'info>, space: usize, seeds: &[&[u8]]) -> Result<()> {
    let rent = Rent::get()?.minimum_balance(space);
    let have = target.lamports();
    if have > 0 {
        // Someone sent lamports to the address first: top up, allocate and assign instead.
        if have < rent {
            invoke(&system_instruction::transfer(payer.key, target.key, rent - have), &[payer.clone(), target.clone(), system.clone()])?;
        }
        invoke_signed(&system_instruction::allocate(target.key, space as u64), &[target.clone(), system.clone()], &[seeds])?;
        invoke_signed(&system_instruction::assign(target.key, &crate::ID), &[target.clone(), system.clone()], &[seeds])?;
    } else {
        invoke_signed(
            &system_instruction::create_account(payer.key, target.key, rent, space as u64, &crate::ID),
            &[payer.clone(), target.clone(), system.clone()],
            &[seeds],
        )?;
    }
    Ok(())
}

/// Every account `lz_compose` takes, in order, for an order arriving from `src_eid` whose fill
/// address is `fill`, for the recipient `to`, on the launch whose store is `from` and mint
/// `mint` -- what a delivery bot sends. (pubkey, is_signer, is_writable). `payer` pays the
/// recipient's token account and, for an unfilled order, the order's tombstone.
pub fn lz_compose_accounts(payer: Pubkey, from: Pubkey, mint: Pubkey, src_eid: u32, fill: Pubkey, to: Pubkey, guid: &[u8; 32], message: &[u8]) -> Vec<(Pubkey, bool, bool)> {
    let token_2022 = anchor_spl::token_2022::ID;
    let ata = |owner: &Pubkey| anchor_spl::associated_token::get_associated_token_address_with_program_id(owner, &mint, &token_2022);
    let vault = Pubkey::find_program_address(&[VAULT_SEED], &crate::ID).0;
    let record = Pubkey::find_program_address(
        &[b"ComposedMessageHash", from.as_ref(), vault.as_ref(), guid, &0u16.to_be_bytes(), &keccak256v(&[message]).to_bytes()],
        &LZ_ENDPOINT_ID,
    )
    .0;
    vec![
        (payer, true, true),
        (Pubkey::find_program_address(&[CONFIG_SEED], &crate::ID).0, false, false),
        (vault, false, false),
        (Pubkey::find_program_address(&[LAUNCH_SEED, from.as_ref()], &crate::ID).0, false, false),
        (mint, false, false),
        (ata(&vault), false, true),
        (Pubkey::find_program_address(&[REMOTE_SEED, &src_eid.to_be_bytes()], &crate::ID).0, false, false),
        (Pubkey::find_program_address(&[ACCEPTED_SEED, &src_eid.to_be_bytes(), &message[20..52]], &crate::ID).0, false, false),
        (fill, false, true),
        (to, false, false),
        (ata(&to), false, true),
        (token_2022, false, false),
        (anchor_spl::associated_token::ID, false, false),
        (anchor_lang::system_program::ID, false, false),
        (LZ_ENDPOINT_ID, false, false),
        (vault, false, false),
        (record, false, true),
        (Pubkey::find_program_address(&[b"__event_authority"], &LZ_ENDPOINT_ID).0, false, false),
        (LZ_ENDPOINT_ID, false, false),
    ]
}

// ---------------------------------------------------------------------------- state

#[account]
#[derive(InitSpace)]
pub struct Config {
    pub admin: Pubkey,
    pub pending_admin: Pubkey,
    pub fast_fee_bps: u16,
    pub max_relayer_fee_bps: u16,
    pub bump: u8,
    pub vault_bump: u8,
}

/// `store` is a Pangea launch's: its mint and launch id.
#[account]
#[derive(InitSpace)]
pub struct Launch {
    pub store: Pubkey,
    pub mint: Pubkey,
    pub launch_id: [u8; 32],
    pub bump: u8,
}

/// This program's counterpart on an EVM chain, and the gas a settlement there needs.
#[account]
#[derive(InitSpace)]
pub struct Remote {
    pub eid: u32,
    pub bridge: [u8; 32],
    pub receive_gas: u128,
    pub compose_gas: u128,
    pub bump: u8,
}

/// A counterpart once set for `eid`: kept for good. Live while `bridge` names it; `stop_accepting`
/// leaves a tombstone (`eid` kept, `bridge` zero) that accepts nothing and blocks any re-set.
#[account]
#[derive(InitSpace)]
pub struct Accepted {
    pub eid: u32,
    pub bridge: [u8; 32],
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct LaunchFees {
    pub launch_id: [u8; 32],
    pub fast_fee_bps: u16,
    pub max_relayer_fee_bps: u16,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct SenderNonce {
    pub next: u64,
    pub bump: u8,
}

/// One order's fill: who fronted it, for which message and in which slot, and -- once the message
/// has settled it -- what they are owed.
#[account]
#[derive(InitSpace)]
pub struct Fill {
    pub relayer: Pubkey,
    pub mint: Pubkey,
    pub lz_nonce: u64,
    pub slot: u64,
    pub owed: u64,
    pub settled: bool,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct ComposeTypes {
    pub vault: Pubkey,
}

#[derive(Clone, AnchorSerialize, AnchorDeserialize)]
pub struct LzComposeParams {
    pub from: Pubkey,
    pub to: Pubkey,
    pub guid: [u8; 32],
    pub index: u16,
    pub message: Vec<u8>,
    pub extra_data: Vec<u8>,
}

#[derive(Clone, AnchorSerialize, AnchorDeserialize)]
pub struct LzAccount {
    pub pubkey: Pubkey,
    pub is_signer: bool,
    pub is_writable: bool,
}

// ---------------------------------------------------------------------------- accounts

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut, address = INIT_AUTHORITY @ FastBridgeError::NotAdmin)]
    pub payer: Signer<'info>,
    #[account(init, payer = payer, space = 8 + Config::INIT_SPACE, seeds = [CONFIG_SEED], bump)]
    pub config: Account<'info, Config>,
    /// CHECK: the vault: a system account this program signs for.
    #[account(mut, seeds = [VAULT_SEED], bump)]
    pub vault: UncheckedAccount<'info>,
    #[account(init, payer = payer, space = 8 + ComposeTypes::INIT_SPACE, seeds = [LZ_COMPOSE_TYPES_SEED, vault.key().as_ref()], bump)]
    pub compose_types: Account<'info, ComposeTypes>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(seed: [u8; 32])]
pub struct RegisterLaunch<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    /// CHECK: the launch's OFT store; derived from `seed` and checked in the handler.
    pub store: UncheckedAccount<'info>,
    /// CHECK: the store's mint; must be the store's and answer to the store alone.
    #[account(owner = anchor_spl::token_2022::ID @ FastBridgeError::NotOurToken)]
    pub mint: UncheckedAccount<'info>,
    #[account(init, payer = payer, space = 8 + Launch::INIT_SPACE, seeds = [LAUNCH_SEED, store.key().as_ref()], bump)]
    pub launch: Account<'info, Launch>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(dst_eid: u32)]
pub struct PostOrder<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Box<Account<'info, Config>>,
    #[account(seeds = [LAUNCH_SEED, launch.store.as_ref()], bump = launch.bump)]
    pub launch: Box<Account<'info, Launch>>,
    #[account(address = launch.mint @ FastBridgeError::NotOurToken, mint::token_program = token_program)]
    pub mint: Box<InterfaceAccount<'info, Mint>>,
    #[account(mut, token::mint = mint, token::authority = user, token::token_program = token_program)]
    pub user_ata: Box<InterfaceAccount<'info, TokenAccount>>,
    /// CHECK: the launch's own fee setting, which may not exist; read by `fees_for`.
    pub launch_fees: UncheckedAccount<'info>,
    /// `PDA(["remote", dst_eid])`; for `post_order_v3` that or `PDA(["remote_v3", dst_eid])`
    /// (audit L-3). Checked in the handler (`remote_slot_ok`).
    pub remote: Box<Account<'info, Remote>>,
    /// CHECK: the launch's OFT store, for its fee; checked against the launch record.
    pub store: UncheckedAccount<'info>,
    /// CHECK: the store's peer on `dst_eid`; read by `read_peer`.
    pub peer: UncheckedAccount<'info>,
    /// CHECK: the endpoint's `Nonce` for the route; checked in the handler.
    pub endpoint_nonce: UncheckedAccount<'info>,
    /// CHECK: the splitter's platform record; read by `platform_of`.
    pub platform_config: UncheckedAccount<'info>,
    #[account(mut, token::mint = mint, token::token_program = token_program)]
    pub platform_ata: Box<InterfaceAccount<'info, TokenAccount>>,
    #[account(init_if_needed, payer = user, space = 8 + SenderNonce::INIT_SPACE, seeds = [SENDER_SEED, user.key().as_ref()], bump)]
    pub sender_nonce: Box<Account<'info, SenderNonce>>,
    /// CHECK: the instructions sysvar.
    #[account(address = sysvar_instructions::ID)]
    pub instructions: UncheckedAccount<'info>,
    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(src_eid: u32)]
pub struct FillOrder<'info> {
    #[account(mut)]
    pub relayer: Signer<'info>,
    #[account(seeds = [LAUNCH_SEED, launch.store.as_ref()], bump = launch.bump)]
    pub launch: Box<Account<'info, Launch>>,
    #[account(address = launch.mint @ FastBridgeError::NotOurToken, mint::token_program = token_program)]
    pub mint: Box<InterfaceAccount<'info, Mint>>,
    #[account(mut, token::mint = mint, token::authority = relayer, token::token_program = token_program)]
    pub relayer_ata: Box<InterfaceAccount<'info, TokenAccount>>,
    /// `PDA(["remote", src_eid])`; for `fill_order_v3` that or `PDA(["remote_v3", src_eid])`
    /// (audit L-3). Checked in the handler (`remote_slot_ok`).
    pub remote: Box<Account<'info, Remote>>,
    /// CHECK: `PDA(["accepted", src_eid, src_bridge])`, which may not exist when the bridge is the
    /// current one; read by `is_accepted`.
    pub accepted: UncheckedAccount<'info>,
    /// CHECK: the OFT store's peer on `src_eid`; read by `read_peer`.
    pub peer: UncheckedAccount<'info>,
    /// CHECK: the endpoint's `Nonce` for the route; checked in the handler.
    pub endpoint_nonce: UncheckedAccount<'info>,
    /// CHECK: the endpoint's `PayloadHash` for `lz_nonce`; checked in the handler.
    pub payload_hash: UncheckedAccount<'info>,
    /// CHECK: the recipient, named by the order.
    pub recipient: UncheckedAccount<'info>,
    #[account(
        init_if_needed, payer = relayer,
        associated_token::mint = mint, associated_token::authority = recipient, associated_token::token_program = token_program
    )]
    pub recipient_ata: Box<InterfaceAccount<'info, TokenAccount>>,
    /// CHECK: the order's fill record, `PDA(["fill", id])`; created in the handler.
    #[account(mut)]
    pub fill: UncheckedAccount<'info>,
    pub token_program: Interface<'info, TokenInterface>,
    pub associated_token_program: Program<'info, anchor_spl::associated_token::AssociatedToken>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(params: LzComposeParams)]
pub struct LzCompose<'info> {
    /// Whoever runs it: pays the recipient's account if it has none.
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Box<Account<'info, Config>>,
    /// CHECK: the vault.
    #[account(seeds = [VAULT_SEED], bump = config.vault_bump)]
    pub vault: UncheckedAccount<'info>,
    /// The record that `from` is a Pangea launch's store.
    #[account(seeds = [LAUNCH_SEED, params.from.as_ref()], bump = launch.bump)]
    pub launch: Box<Account<'info, Launch>>,
    #[account(address = launch.mint @ FastBridgeError::NotOurToken, mint::token_program = token_program)]
    pub mint: Box<InterfaceAccount<'info, Mint>>,
    #[account(mut, associated_token::mint = mint, associated_token::authority = vault, associated_token::token_program = token_program)]
    pub vault_ata: Box<InterfaceAccount<'info, TokenAccount>>,
    pub remote: Box<Account<'info, Remote>>,
    /// CHECK: `PDA(["accepted", src_eid, composeFrom])`; read by `is_accepted`.
    pub accepted: UncheckedAccount<'info>,
    /// CHECK: the order's fill record, if any; checked in the handler.
    #[account(mut)]
    pub fill: UncheckedAccount<'info>,
    /// CHECK: the order's recipient; checked against the payload in the handler.
    pub recipient: UncheckedAccount<'info>,
    #[account(
        init_if_needed, payer = payer,
        associated_token::mint = mint, associated_token::authority = recipient, associated_token::token_program = token_program
    )]
    pub recipient_ata: Box<InterfaceAccount<'info, TokenAccount>>,
    pub token_program: Interface<'info, TokenInterface>,
    pub associated_token_program: Program<'info, anchor_spl::associated_token::AssociatedToken>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SettleV3<'info> {
    /// Whoever runs it: pays the recipient's account if it has none, and an unfilled order's
    /// tombstone.
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Box<Account<'info, Config>>,
    /// CHECK: the vault: the receipt's composer, and its closer.
    #[account(seeds = [VAULT_SEED], bump = config.vault_bump)]
    pub vault: UncheckedAccount<'info>,
    /// The record that the receipt's store is a Pangea launch's.
    #[account(seeds = [LAUNCH_SEED, launch.store.as_ref()], bump = launch.bump)]
    pub launch: Box<Account<'info, Launch>>,
    #[account(address = launch.mint @ FastBridgeError::NotOurToken, mint::token_program = token_program)]
    pub mint: Box<InterfaceAccount<'info, Mint>>,
    #[account(mut, associated_token::mint = mint, associated_token::authority = vault, associated_token::token_program = token_program)]
    pub vault_ata: Box<InterfaceAccount<'info, TokenAccount>>,
    /// The receipt's source eid's `PDA(["remote_v3", eid])` (what `settle_v3_accounts` names) or
    /// its `PDA(["remote", eid])` (audit L-3). Checked in the handler (`remote_slot_ok`).
    pub remote: Box<Account<'info, Remote>>,
    /// CHECK: `PDA(["accepted", src_eid, compose_from])`; read by `is_accepted`.
    pub accepted: UncheckedAccount<'info>,
    /// CHECK: the order's fill record, if any; checked in the handler.
    #[account(mut)]
    pub fill: UncheckedAccount<'info>,
    /// CHECK: the order's recipient; checked against the payload in the handler. Sent writable (the
    /// order's unused ATA rent drop goes back to it (audit r1 I-1), and (L4) the receipt's prepaid
    /// lamports, if any, are paid to it on close), but not `mut` here (oft-lows6, oft-lows5-r1 L-1): a
    /// recipient the runtime makes read-only in every transaction (a sysvar, a builtin or other reserved
    /// key, this program's own id) failed Anchor's mut check on every try, so its order never settled.
    /// The handler names it to the close as writable only when it is (`recipient_cannot_hold`), and
    /// refuses one passed read-only that the runtime would let be written (RecipientNotWritable).
    pub recipient: UncheckedAccount<'info>,
    /// CHECK: the recipient's associated account of the mint: made in the handler when missing
    /// (by the payer, repaid from the order's rent drop), else held to that address and owner.
    #[account(mut)]
    pub recipient_ata: UncheckedAccount<'info>,
    /// CHECK: the OFT program's `GapReceipt` for the guid; checked in the handler, closed by CPI.
    #[account(mut)]
    pub gap_receipt: UncheckedAccount<'info>,
    /// CHECK: the receipt's payer, who gets its rent back; checked against the receipt.
    #[account(mut)]
    pub receipt_payer: UncheckedAccount<'info>,
    /// CHECK: the OFT program, for `close_gap_receipt`.
    #[account(address = OFT_PROGRAM_ID @ FastBridgeError::BadGapReceipt)]
    pub oft_program: UncheckedAccount<'info>,
    pub token_program: Interface<'info, TokenInterface>,
    pub associated_token_program: Program<'info, anchor_spl::associated_token::AssociatedToken>,
    pub system_program: Program<'info, System>,
    /// CHECK: oft-lows3 (oft-lows2-r1 L-2): the OFT's GapLatePrepay record of the receipt's GapPrepay PDA,
    /// PDA(["GapLatePrepay", PDA(["GapPrepay", store, src_eid BE, compose_from, sha256(compose_msg)])]) under
    /// the OFT program (`late_prepay_address`); its address is checked by the OFT's close
    /// (GapAccountMismatch), which writes or refreshes it.
    #[account(mut)]
    pub gap_late_prepay: UncheckedAccount<'info>,
}

#[derive(Accounts)]
#[instruction(eid: u32, bridge: [u8; 32])]
pub struct SetRemoteV3<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump, has_one = admin @ FastBridgeError::NotAdmin)]
    pub config: Account<'info, Config>,
    #[account(init_if_needed, payer = admin, space = 8 + Remote::INIT_SPACE, seeds = [REMOTE_V3_SEED, &eid.to_be_bytes()], bump)]
    pub remote_v3: Account<'info, Remote>,
    #[account(init_if_needed, payer = admin, space = 8 + Accepted::INIT_SPACE, seeds = [ACCEPTED_SEED, &eid.to_be_bytes(), &bridge], bump)]
    pub accepted: Account<'info, Accepted>,
    pub system_program: Program<'info, System>,
    /// CHECK: the OFT's `PDA(["GapGlobal"])`; owner, layout and its composers checked in the handler.
    #[account(seeds = [GAP_GLOBAL_SEED], bump, seeds::program = OFT_PROGRAM_ID)]
    pub gap_global: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct Claim<'info> {
    #[account(mut)]
    pub relayer: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Box<Account<'info, Config>>,
    /// CHECK: the vault.
    #[account(seeds = [VAULT_SEED], bump = config.vault_bump)]
    pub vault: UncheckedAccount<'info>,
    #[account(mut, has_one = relayer @ FastBridgeError::NotTheRelayer)]
    pub fill: Box<Account<'info, Fill>>,
    #[account(address = fill.mint @ FastBridgeError::OrderMismatch, mint::token_program = token_program)]
    pub mint: Box<InterfaceAccount<'info, Mint>>,
    #[account(mut, associated_token::mint = mint, associated_token::authority = vault, associated_token::token_program = token_program)]
    pub vault_ata: Box<InterfaceAccount<'info, TokenAccount>>,
    #[account(mut, token::mint = mint, token::authority = relayer, token::token_program = token_program)]
    pub relayer_ata: Box<InterfaceAccount<'info, TokenAccount>>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct LzComposeTypes<'info> {
    pub compose_types: Account<'info, ComposeTypes>,
}

#[derive(Accounts)]
pub struct AdminOnly<'info> {
    pub admin: Signer<'info>,
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump, has_one = admin @ FastBridgeError::NotAdmin)]
    pub config: Account<'info, Config>,
}

#[derive(Accounts)]
#[instruction(eid: u32, bridge: [u8; 32])]
pub struct SetRemote<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump, has_one = admin @ FastBridgeError::NotAdmin)]
    pub config: Account<'info, Config>,
    #[account(init_if_needed, payer = admin, space = 8 + Remote::INIT_SPACE, seeds = [REMOTE_SEED, &eid.to_be_bytes()], bump)]
    pub remote: Account<'info, Remote>,
    #[account(init_if_needed, payer = admin, space = 8 + Accepted::INIT_SPACE, seeds = [ACCEPTED_SEED, &eid.to_be_bytes(), &bridge], bump)]
    pub accepted: Account<'info, Accepted>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(eid: u32, bridge: [u8; 32])]
pub struct RevokeRemote<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump, has_one = admin @ FastBridgeError::NotAdmin)]
    pub config: Account<'info, Config>,
    /// CHECK: `PDA(["remote", eid])`; cleared when it names `bridge`. May not exist.
    #[account(mut)]
    pub remote: UncheckedAccount<'info>,
    /// CHECK: `PDA(["remote_v3", eid])`; cleared when it names `bridge`. May not exist.
    #[account(mut)]
    pub remote_v3: UncheckedAccount<'info>,
    /// `bridge`'s marker: created by `revoke_remote` when the remote never got one (audit I-2) and
    /// tombstoned (bridge zero) by `stop_accepting`; never closed, so it can never be re-created.
    #[account(init_if_needed, payer = admin, space = 8 + Accepted::INIT_SPACE, seeds = [ACCEPTED_SEED, &eid.to_be_bytes(), &bridge], bump)]
    pub accepted: Account<'info, Accepted>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(launch_id: [u8; 32])]
pub struct SetLaunchFees<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump, has_one = admin @ FastBridgeError::NotAdmin)]
    pub config: Account<'info, Config>,
    #[account(init_if_needed, payer = admin, space = 8 + LaunchFees::INIT_SPACE, seeds = [LAUNCH_FEES_SEED, &launch_id], bump)]
    pub launch_fees: Account<'info, LaunchFees>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AcceptAdmin<'info> {
    pub new_admin: Signer<'info>,
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
}

// ---------------------------------------------------------------------------- events

#[event]
pub struct LaunchRegistered {
    pub store: Pubkey,
    pub mint: Pubkey,
    pub launch_id: [u8; 32],
}

#[event]
pub struct OrderPosted {
    pub order_id: [u8; 32],
    pub launch_id: [u8; 32],
    pub dst_eid: u32,
    pub sender: [u8; 32],
    pub sender_nonce: u64,
    pub to: [u8; 32],
    pub amount: u64,
    pub relayer_fee: u64,
    pub lz_nonce: u64,
}

/// A v3 order posted (`post_order_v3`): `OrderPosted`'s fields and the order's least credited amount.
#[event]
pub struct OrderPostedV3 {
    pub order_id: [u8; 32],
    pub launch_id: [u8; 32],
    pub dst_eid: u32,
    pub sender: [u8; 32],
    pub sender_nonce: u64,
    pub to: [u8; 32],
    pub amount: u64,
    pub relayer_fee: u64,
    pub min_credited: u64,
    pub lz_nonce: u64,
}

#[event]
pub struct OrderFilled {
    pub order_id: [u8; 32],
    pub relayer: Pubkey,
    pub to: Pubkey,
    pub paid: u64,
}

#[event]
pub struct RelayerOwed {
    pub order_id: [u8; 32],
    pub relayer: Pubkey,
    pub amount: u64,
    pub earned: bool,
}

#[event]
pub struct RelayerPaid {
    pub fill: Pubkey,
    pub relayer: Pubkey,
    pub amount: u64,
}

#[event]
pub struct SettledSlow {
    pub order_id: [u8; 32],
    pub to: Pubkey,
    pub amount: u64,
}

#[event]
pub struct FeeReturned {
    pub order_id: [u8; 32],
    pub to: Pubkey,
    pub fee: u64,
}

/// A v3 arrival's destination withheld `withheld` of the order's `gross`: it settled on the rest.
#[event]
pub struct GapBorne {
    pub order_id: [u8; 32],
    pub guid: [u8; 32],
    pub gross: u64,
    pub withheld: u64,
}

#[event]
pub struct RentDropPaid {
    pub order_id: [u8; 32],
    pub to: Pubkey,
    pub lamports: u64,
}

/// oft-lows6 (oft-lows5-r1 I-1, lead8): settle_v3's unused ATA part of the order's rent drop could not go to the
/// recipient (a program, or a key the runtime keeps read-only) and its account was already there: `lamports`
/// went to the receipt's payer, which holds them -- with the sender's prepaid named by the OFT's
/// GapPrepaidRefundToExecutable -- for a manual return to the order's sender.
#[event]
pub struct RentDropToReceiptPayer {
    pub order_id: [u8; 32],
    pub guid: [u8; 32],
    pub recipient: Pubkey,
    pub receipt_payer: Pubkey,
    pub lamports: u64,
}

#[event]
pub struct RemoteV3Set {
    pub eid: u32,
    pub bridge: [u8; 32],
    pub receive_gas: u128,
    pub compose_gas: u128,
}

#[event]
pub struct RemoteRevoked {
    pub eid: u32,
    pub bridge: [u8; 32],
    /// The v1 remote named it and was cleared.
    pub v1: bool,
    /// The v3 remote named it and was cleared.
    pub v3: bool,
}

/// `stop_accepting`: arrivals composed by `bridge` on `eid` are refused from now on, for good.
#[event]
pub struct RemoteStopped {
    pub eid: u32,
    pub bridge: [u8; 32],
}

#[event]
pub struct RemoteSet {
    pub eid: u32,
    pub bridge: [u8; 32],
    pub receive_gas: u128,
    pub compose_gas: u128,
}

#[event]
pub struct FeesSet {
    pub launch_id: [u8; 32],
    pub fast_fee_bps: u16,
    pub max_relayer_fee_bps: u16,
}

// ---------------------------------------------------------------------------- errors

#[error_code]
pub enum FastBridgeError {
    #[msg("only the admin")]
    NotAdmin,
    #[msg("not the pending admin")]
    NotPending,
    #[msg("zero address")]
    ZeroAddress,
    #[msg("zero amount")]
    ZeroAmount,
    #[msg("not a Pangea launch's token")]
    NotOurToken,
    #[msg("the message is not this program's")]
    NotOurMessage,
    #[msg("the compose was not sent by our bridge on that chain")]
    NotOurBridge,
    #[msg("no counterpart on that chain")]
    NoRemote,
    #[msg("no gas limits for that chain")]
    NoGasLimits,
    #[msg("the route is not open")]
    NoRoute,
    #[msg("the recipient is not an EVM address")]
    NotAnEvmAddress,
    #[msg("the relayer's fee is not less than the amount")]
    FeeExceedsAmount,
    #[msg("the relayer's fee is over the ceiling")]
    RelayerFeeTooHigh,
    #[msg("the recipient would receive less than the minimum")]
    ReceivesTooLittle,
    #[msg("the fast fee is over 1%")]
    FastFeeTooHigh,
    #[msg("not a share of 10000")]
    NotAShare,
    #[msg("the message has already arrived")]
    TooLateToFill,
    #[msg("already filled")]
    AlreadyFilled,
    #[msg("already settled")]
    AlreadySettled,
    #[msg("not settled yet")]
    NotSettled,
    #[msg("nothing owed")]
    NothingOwed,
    #[msg("not the fill's relayer")]
    NotTheRelayer,
    #[msg("the order does not match")]
    OrderMismatch,
    #[msg("a malformed compose payload")]
    BadPayload,
    #[msg("the OFT send's accounts are not this launch's")]
    BadSendAccounts,
    #[msg("the platform's account is not the platform's")]
    WrongPlatform,
    #[msg("overflow")]
    Overflow,
    #[msg("the next instruction is not this order's OFT send")]
    SendNotNext,
    #[msg("compose types are not supported; run lz_compose directly")]
    ComposeTypesUnsupported,
    #[msg("not the v3 store's GapReceipt for this guid and the vault")]
    BadGapReceipt,
    #[msg("a v3 store's order is post_order_v3's, a live store's post_order's")]
    WrongOrderKind,
    #[msg("the least credited amount is above what arrives")]
    MinCreditedTooHigh,
    #[msg("the OFT's GapGlobal.composers does not list the fast bridge's vault: v3 orders to Solana could not settle")]
    VaultNotComposer,
    #[msg("the remote is set once: another bridge, or one after revoke_remote, is refused")]
    RemoteAlreadySet,
    #[msg("a remote's gas limit is over 1,000,000")]
    GasLimitTooHigh,
    #[msg("arrivals from this bridge are already refused (stop_accepting)")]
    AlreadyStopped,
    #[msg("a v3 remote's receive gas must be 0 exactly when the OFT's GapGlobal makes its eid keys-only (dst_delivery > 0), and its compose gas non-zero")]
    KeysOnlyGas,
    #[msg("not the OFT program's GapGlobal (post_order_v3's second remaining account: the eid's keys-only setting is read from it)")]
    BadGapGlobal,
    // oft-lows6 (oft-lows5-r1 L-1, appended)
    #[msg("settle_v3's recipient was passed read-only but the runtime lets it be written: pass it writable (only a program, sysvar or reserved key stands in read-only)")]
    RecipientNotWritable,
}
