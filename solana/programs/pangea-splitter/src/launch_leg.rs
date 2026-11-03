//! # The whole Solana leg of a launch, as one instruction
//!
//! A launch on Solana used to be five transactions sent by a script: the mint and its metadata,
//! the OFT store and its peers, the token accounts, the splitter, and the pool. Every gap between
//! two of them was a state somebody could observe and act on -- a mint with no pool, a store whose
//! admin was still a hot key, a pool address anyone could take first -- and two safety mechanisms
//! existed only to guard those gaps.
//!
//! `launch` is all of it in one instruction, so there is no gap. Either the token exists with its
//! metadata, its whole supply locked in a pool, its bridge created belonging to no key with its
//! peers named and its fee set, its fee split recorded and its launch fee settled -- or the
//! transaction failed and none of that is true. (The routes to those peers are opened afterwards;
//! see `bridge`. The mint authority is the token's OFT store from the end of this instruction, as
//! for any Native OFT, so the mint's supply is the token's real supply on Solana; no reserve and
//! no `arm` step follow. See `reserve` for the launches made before.)
//!
//! ## How it fits, when the script's version did not
//!
//! The same steps sent as separate instructions are 19 instructions, three signatures and about
//! 2,200 bytes, against a limit of 1,232. Two things change here.
//!
//! **The program makes the calls, so the transaction does not have to describe them.** An
//! instruction in a transaction costs its account list and its data; a call made by a program
//! costs the transaction nothing. Fifteen calls to five other programs become one instruction's
//! worth of bytes.
//!
//! **Nothing here has a keypair.** The mint, the OFT escrow and the position NFT mint each had one,
//! solely to sign for the creation of an account at their address -- 96 bytes apiece of key and
//! signature that no lookup table can compress. They are program-derived addresses of the launch's
//! seed now, and this program signs for them. The position is held by the program's fee owner
//! from the instant it exists: there is no handover, because it was never anybody else's.
//!
//! And a third: the metadata URI is not in the transaction, only the 32-byte hash it is made from
//! -- see "the metadata's address". Between them these bring a launch to 1,224 bytes at the very
//! worst with ONE lookup table, made once for the addresses no launch changes, and nothing at all
//! to send before the launch itself.
//!
//! That second change is also why every address a launch will use is a function of one value --
//! its SEED, 32 bytes -- and so is known to whoever holds the seed before anything is sent. That
//! is what lets the four EVM chains seal the Solana peer without it existing yet.
//!
//! **And the seed is a secret until the launch lands.** A launch's public name, the launch id the
//! EVM chains sign over and a creator pays a fee against, is the seed's hash (`launch_id_of`),
//! not the seed. So nobody who sees a launch coming can compute where on Solana it will be --
//! which matters, because anyone can send lamports to an address, an address that already holds
//! some costs two more instructions to create, and a launch has eight to spare. With addresses
//! derived from the public id, a few thousandths of a SOL sent to four of them stopped a launch
//! for good. See `MINT_SEED`.
//!
//! ## What the caller chooses, and what it cannot
//!
//! Only a listed launcher may call this. It supplies the name, symbol and metadata URI, the
//! creator, the fee, the price signer's snapshot (NOT an opening price: the program derives that,
//! see `price`), and the bridge's peers: which chains, and the one EVM token that is the peer on each. It does NOT supply the platform, which is whoever the
//! program's platform record names (`platform_of`), or the bridge's fee, which the program writes (20 bps; on a v3 store the
//! platform admin may later set it from 0 to 50 bps, `set_bridge_fee`), or the OFT admin and the endpoint
//! delegate, which are an address only this program signs for -- and are that address from the
//! instant the store exists, not after a handover.
//!
//! So a launcher DOES choose the peers, and a peer is a contract that can make this token's
//! store mint: that is the trust placed in a launcher, and it is why launching is gated. But it
//! chooses them once, in the instruction that creates the store, as arguments anyone can read
//! afterwards. The launcher's key is never the store's admin, so it cannot name a peer, change
//! one, change the fee or replace a verifier at any later time -- and no other key can name or
//! change a peer or replace a pinned verifier either, the platform admin's included (its only
//! reach into a store that exists is a v3 store's fee, 0 to 50 bps, and an open route's gas floor,
//! gas only: `set_bridge_fee`, `set_gas_floor`). What mints is the store, on a message its pinned
//! verifiers attest came from one of those peers, and nothing else.
//!
//! ## A co-signed launch
//!
//! `launch_cosigned` is the same launch started from the creator's own wallet. Same accounts in
//! the same order, same arguments, same checks, same calls; three things differ.
//!
//! **Two signers.** The CREATOR signs (`CreatorMustSign`) and is the transaction's fee payer. The
//! listed launcher signs too, in the `payer` slot, exactly as it signs a plain launch -- so the
//! listing check is the one `launch` makes, and nothing about what a launcher may decide is new.
//! A Solana signature covers the whole message: every account, every argument, every other
//! instruction and the blockhash. So a creator handed a transaction the launcher has signed can
//! sign it or not, and can change nothing in it -- not the price, the supply, the mint, the fee,
//! the split, the peers, the dev buy or the compute budget -- without the launcher's signature
//! failing. The creator may be anybody but the launcher itself (`CreatorIsLauncher`).
//!
//! **The creator pays, and the launcher ends exactly where it began.** Every call below still
//! draws rent from the launcher, as in a plain launch: nothing about Meteora's, LayerZero's or
//! Token-2022's accounts changes. Then, after the last of them, the program measures what the
//! launcher is down -- its wallet and its quote account together, plus the rent of the launch's
//! record, which Anchor drew from it before the handler ran -- and moves that many lamports from
//! the creator to the launcher, a system transfer the creator's signature authorises. The launch
//! fails unless the launcher holds at least what it held (`LauncherNotRepaid`). So the creator
//! pays the transaction's fees (as its fee payer) and all of the launch's rent, and the launcher
//! is lent nothing past the instruction. What the launcher is handed back by the calls (the
//! slice's account closed, lamports a stranger sent to `AUTHORITY`) is counted, so nothing is
//! paid twice. Two exact edges: against wrapped SOL, the lamport Meteora rounds a pool's opening
//! up to leaves the launcher's wrapped-SOL account and is repaid into the launcher's WALLET (the
//! account's balance drifts down a unit a launch, as it does for a plain launch, and is topped up
//! with the rest of the launcher's float); against an allowlisted asset that unit is one base unit
//! of the asset, not lamports, and is the launcher's, as in a plain launch. And the record's rent
//! is repaid whole: should somebody who learned the seed have sent lamports to the record's
//! address first, Anchor drew that much less from the launcher, and the creator pays it anyway.
//!
//! **The dev buy is the creator's own lamports.** `expected_dev_buy` lamports leave the
//! creator's wallet, signed for by the creator, pass through the launcher's wrapped-SOL account
//! and are swapped through the pool just opened, as the launch's first trade; the tokens are the
//! creator's (`DevBuy::FromWallet`). Not a lamport more: the amount is an argument the launcher
//! signed. It is made only against wrapped SOL and only when the pool can sell that much, and is
//! otherwise not made, the lamports never leaving the wallet. A payment handed to a co-signed
//! launch is settled as in any launch, and what the CREATOR's payment holds above the fee goes
//! back to them whole, before they repay the launcher (so it can pay the rent: `refund_excess_first`)
//! -- a co-signed launch buys out of the wallet, never out of a payment.
//! (An allowlisted asset's dev buy, out of the creator's approved account, is as in `launch`.)
//!
//! The dev buy is made only when the wallet holds it with `COSIGNED_LAUNCH_RENT_BOUND` and a
//! wallet's rent-exempt minimum to spare, so that a buy never leaves the wallet short of the rent
//! it repays afterwards: a dev buy never stops a launch. A launch that makes one does not make
//! the creator's quote account either (its five instructions pay for most of the buy's six), as in a plain launch.
//!
//! The creator's quote account may be given as the creator's own address. Then the launch does
//! not make it -- that is 32 bytes the second signature needs -- and the creator's share of the
//! fees waits in the pool until the creator has one, as for any creator without one.
//!
//! What a co-signed launch does NOT keep secret is the seed. It is in the transaction the creator
//! holds before it lands -- and so with whatever sees that transaction on its way: the web page,
//! the wallet and the service it simulates with, and, if the wallet sends it itself, its RPC and
//! the leaders. Anyone among them can send lamports to the launch's addresses ahead of it, and
//! each address so funded costs the launch two more instructions: the worst co-signed launch has
//! room for five (tests/cosigned.rs), and past that it lands, fails, and its seed is spent -- a
//! launch to start over, not money lost: every address is still one only `launch` or
//! `launch_cosigned` can create, with the launcher's signature, at the arguments it signed. So the
//! wallet should only SIGN, and the transaction go out privately (to Jito, first in its group,
//! which its jitodontfront marker requires), as a plain launch goes.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    instruction::{AccountMeta, Instruction},
    program::invoke_signed,
    program_pack::Pack,
    system_instruction,
};
use anchor_spl::{
    associated_token::{self, AssociatedToken},
    token::{self, spl_token, Token},
    token_2022,
};

use crate::{
    buy_output, check_fee, cp_amm_swap_data, dev_buy_minimum, has_pangea_ending, launch_id_of, read_position, Excess, FeePayment, LaunchRecord,
    Launcher, SplitterError, ADMIN, AUTHORITY_SEED, CP_AMM_ID, FEES_SEED, LAUNCHER_SEED, MINT_SEED, SPLITTER_SEED, TOKEN_DECIMALS,
};

/// Our deployment of LayerZero's OFT program. Every launch's store, peers and escrow are its.
pub const OFT_PROGRAM_ID: Pubkey = pubkey!("SNyKyiZYU4R54SF9sYLmjCaCUsa1sC6QouNAj3x3Zzf");
/// LayerZero's endpoint on Solana.
pub const LZ_ENDPOINT_ID: Pubkey = pubkey!("76y77prsiCMvXMjuoZ5VRrhG5qYBrUMYTE5WgHqgjEn6");

/// The OFT escrow's seed. `PDA([b"escrow", launch_seed])` is the token account LayerZero's program
/// derives the launch's OFT STORE from -- and the store is what the EVM chains seal as their peer.
///
/// It was a keypair, generated per launch and kept in a file until the store existed, because
/// whoever held it first could create the store for a mint of their own at that address. As a
/// PDA of this program there is nothing to hold: only `launch` can sign for it, only for this
/// launch's seed, and only a listed launcher can call `launch`.
pub const ESCROW_SEED: &[u8] = b"escrow";

/// The position NFT mint's seed. `PDA([b"position", launch_seed])`.
///
/// Meteora requires the position's NFT mint to sign the pool's creation. It was a keypair too,
/// written to disk before the first transaction that depended on it; now this program signs.
pub const POSITION_SEED: &[u8] = b"position";

/// The account the slice is minted into: `PDA([b"token_a", launch_seed])`, a plain token account at
/// an address of this program's rather than an associated one, because the associated-token
/// program spends five of a transaction's sixty-four instructions making one where allocating and
/// initialising directly spends two.
///
/// The slice is minted into it while the payer owns it and the pool takes the slice out of it.
/// Then the payer ends the launch owning none of the supply: the account is closed when nothing is
/// left in it, and is otherwise the creator's -- with the dev buy in it, or the few base units of
/// the pool's rounding. None of the supply ever reaches the platform's hot key.
pub const TOKEN_A_SEED: &[u8] = b"token_a";

/// The precision a token bridges at, on every chain. LayerZero's default, and `PangeaOFT`'s.
pub const OFT_SHARED_DECIMALS: u8 = 6;

/// What bridging out of Solana costs: 0.2% of the amount, the same as on the four EVM chains and
/// the same as the platform's cut of trading volume.
///
/// LayerZero's OFT program has the fee built in. A store has a `default_fee_bps`; `send` takes
/// that share of what is sent, rounded DOWN to the unit a token bridges in, burns the rest and
/// moves the fee into the store's own token escrow, where it waits for `withdraw_bridge_fee`.
/// (Rounded down to that unit means an amount under 500,000 base units -- 0.0005 of a token --
/// pays no fee at all; LayerZero's own charge for the message is many times what that saves.)
///
/// `launch` sets it in the instruction that creates the store -- so there is no moment in which
/// a transfer could leave free -- signing as the store's admin, which is `AUTHORITY` from the
/// store's creation and never the launcher. For a live (v1/v2) store nothing can change it
/// afterwards; a v3 store's is the admin's, 0 to 50 bps (`set_bridge_fee`, no-rug 2026-10-30).
/// Never on a peer, and no key is the store's admin. See `bridge`.
pub const BRIDGE_FEE_BPS: u16 = 20;

/// The top of Meteora's price range (`MAX_SQRT_PRICE`), Q64.64. A launch's position runs from the
/// opening price to here, which with the whole supply on one side is what "single-sided" means.
pub const CP_AMM_MAX_SQRT_PRICE: u128 = 79_226_673_521_066_979_257_578_248_091;

/// The most of a slice a launch may leave outside its pool, in base units: a thousandth of one
/// token. An honest launch leaves what the pool's rounding does -- a few hundred units at most.
///
/// Without a bound the pool takes whatever `liquidity` implies, which need not be the slice: a
/// launcher could mint a slice, pool a sliver of it, and leave the rest in the account that then
/// becomes the creator's -- supply that is neither locked nor in any pool, on a token whose peers
/// will mint against it.
pub const MAX_UNPOOLED: u64 = 1_000_000;

pub const MAX_NAME_LEN: usize = 32;
pub const MAX_SYMBOL_LEN: usize = 10;

/* ------------------------------------------------------------- the metadata's address

   A launch's metadata lives on IPFS, and its URI is `ipfs://` followed by a content identifier.
   The transaction does not carry that text. It carries the 32 bytes the identifier is made from --
   the sha-256 of the content -- and one byte saying which of the three forms the identifier
   takes, and the URI is written out here.

   That is 33 bytes where the text was up to 204, and it is what lets a launch fit in a
   transaction with ONE lookup table, made once, instead of needing a second made for every
   launch: with the URI as text, a launch with a fee to settle was three bytes over the limit at
   an ordinary name, and 157 over at the longest one. Nothing is lost for it. The string written
   below is byte for byte the one the EVM chains store, because it is derived from the same hash
   by the same rules, and a metadata URI that is not an IPFS hash was never what a launch used. */

/// CIDv0: the multihash alone, in base58 -- `Qm...`, 46 characters. What Pinata returns by default.
pub const CID_V0: u8 = 0;
/// CIDv1 of a raw block, in base32 -- `bafkrei...`.
pub const CID_V1_RAW: u8 = 0x55;
/// CIDv1 of a dag-pb node, in base32 -- `bafybei...`. The same content as a CIDv0, written anew.
pub const CID_V1_DAG_PB: u8 = 0x70;

/// sha2-256, 32 bytes: the multihash header every one of the three forms carries.
const MULTIHASH_SHA256: [u8; 2] = [0x12, 0x20];

const BASE58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Base58, Bitcoin's alphabet, as IPFS writes a CIDv0.
fn base58(bytes: &[u8]) -> String {
    // Long division of the whole input by 58, a digit at a time. 34 bytes in, 46 digits out.
    let mut digits: Vec<u8> = Vec::with_capacity(bytes.len() * 138 / 100 + 1);
    for &byte in bytes {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let zeros = bytes.iter().take_while(|b| **b == 0).count();
    let mut out = String::with_capacity(zeros + digits.len());
    out.extend(core::iter::repeat('1').take(zeros));
    out.extend(digits.iter().rev().map(|d| BASE58[*d as usize] as char));
    out
}

/// Base32, RFC 4648's lower-case alphabet with no padding, as IPFS writes a CIDv1.
fn base32(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 8 / 5 + 1);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &byte in bytes {
        buffer = (buffer << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            out.push(BASE32[((buffer >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(BASE32[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// The metadata URI for a content hash: `ipfs://` and the identifier, in the form `form` names.
pub fn ipfs_uri(form: u8, digest: &[u8; 32]) -> Result<String> {
    let mut cid = Vec::with_capacity(36);
    let text = match form {
        CID_V0 => {
            cid.extend_from_slice(&MULTIHASH_SHA256);
            cid.extend_from_slice(digest);
            base58(&cid)
        }
        CID_V1_RAW | CID_V1_DAG_PB => {
            cid.push(1); // the version
            cid.push(form); // the codec
            cid.extend_from_slice(&MULTIHASH_SHA256);
            cid.extend_from_slice(digest);
            // The leading `b` is the identifier saying "what follows is base32".
            let mut text = String::from("b");
            text.push_str(&base32(&cid));
            text
        }
        _ => return err!(SplitterError::BadMetadata),
    };
    Ok(format!("ipfs://{text}"))
}

/// What a launcher says about a launch. Everything else is derived, or is a constant.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct LaunchArgs {
    /// The launch's seed: what every address this instruction creates is derived from, and what
    /// hashes to the launch id the four EVM chains sign their price snapshot over. Secret until
    /// this transaction lands, public in it. See `MINT_SEED`.
    pub launch_seed: [u8; 32],
    /// The number that makes this seed's mint end in `6ea` (`MINT_ENDING`): the mint is
    /// `PDA(["mint", launch_seed, mint_nonce as 4 little-endian bytes])`, and a launch whose mint
    /// does not end that way is refused. Found by search (`solana/tools/mint-grind`); it changes
    /// the mint's address and nothing else. See `has_pangea_ending`.
    pub mint_nonce: u32,
    pub name: String,
    pub symbol: String,
    /// Which form of IPFS content identifier the metadata URI takes: `CID_V0`, `CID_V1_RAW` or
    /// `CID_V1_DAG_PB`. See "the metadata's address".
    pub uri_form: u8,
    /// The sha-256 that identifier is made from. The URI itself is written out by the program.
    pub uri_digest: [u8; 32],
    /// The pool's fee, 0.3% to 5%. Nothing here changes it afterwards; Meteora's operator can, and the
    /// fee split then follows the pool's current fee (`venue::current_fee`).
    pub fee_bps: u16,
    /// This chain's share of the supply, in base units. All of it goes into the pool.
    pub slice: u64,
    /// The opening price, as Meteora's Q64.64 square root, and the bottom of the position. NOT on
    /// the wire: the program computes it from the signed price snapshot (`price`) -- a $3,000
    /// market cap against the signed price of the quote asset -- and fills it in before anything
    /// reads it.
    ///
    /// The liquidity the slice is between here and the top of the range is not an argument either:
    /// the program computes it, by Meteora's own arithmetic (`single_sided_liquidity`).
    #[borsh_skip]
    pub init_sqrt_price: u128,
    /// The launch fee this launch expects to settle, in lamports: what the creator was quoted.
    ///
    /// WITH a payment handed to the launch (`Launch::fee`), the payment must hold at least this
    /// much or the launch is refused before anything is created (`PaymentBelowLaunchFee`), and
    /// it must be more than nothing (`LaunchFeeNotNamed`): a launch may not settle "whatever is
    /// there". That is what a launcher's own reading of the payment, a moment before it sends,
    /// could not promise: between the reading and the landing a payer whose payment had aged
    /// past the reclaim window could take it back and put one lamport in its place. See
    /// `SETTLE_MARGIN`.
    ///
    /// What a payment holds above it depends on whose payment it is (see `dev_buy`, "a dev buy
    /// never stops a launch"), and is never a reason for the launch to fail:
    ///
    ///  * the CREATOR's payment: the excess is theirs, and is not the platform's. Up to
    ///    `expected_dev_buy` of it is their dev buy: this instruction swaps it for the new token
    ///    through the pool it has just opened and the tokens are the creator's. The rest -- all of
    ///    it, when the buy cannot be made here (no wrapped-SOL account, more than the pool sells,
    ///    an amount that cannot be priced, a quote asset that is not wrapped SOL) -- goes straight
    ///    back to the creator's wallet. Either way it leaves the payment's account, which is
    ///    settled holding exactly this fee, and `amount` records this fee -- so `withdraw_fee`
    ///    takes the fee, the account's rent and any lamports a stranger sent to the address, and
    ///    not a lamport of the creator's. (The one exception: a creator whose wallet is EMPTY,
    ///    owed back less than its rent-exempt minimum, cannot be handed it without the runtime
    ///    refusing the launch, and that part settles as the fee.)
    ///  * anybody else's payment: there is no dev buy, and the WHOLE payment is the fee, settled
    ///    and recorded as such. A friend who pays 10,000,001 lamports against a fee of 10,000,000
    ///    has paid a fee of 10,000,001. This is a floor, as it always was.
    ///
    /// WITHOUT a payment -- the fee was paid on another chain, so there is nothing here to
    /// settle -- this must be ZERO (`LaunchFeeWithoutPayment`). A launch that names a fee and is
    /// handed no payment is a launcher's mistake, and it would launch for free: the payment
    /// stays unsettled and its payer takes it back in a week. Refusing it costs an honest
    /// launcher nothing, since a launch that settles nothing has no fee to name.
    pub launch_fee: u64,
    /// The dev buy the creator was QUOTED, in the quote asset's base units: lamports when the
    /// launch pairs against wrapped SOL, where it is the most of the creator's payment the launch
    /// may spend; the asset's base units when it pairs against an allowlisted asset, where it is
    /// the most the launch may spend out of the creator's own account for it, as the delegate
    /// they approved (`check_asset_dev_buy`). Zero when there is none.
    ///
    /// The launch spends `min(excess, expected_dev_buy)` on the buy, and hands the rest of the
    /// creator's excess back to their wallet (see `dev_buy`). Without this bound a creator who
    /// topped their payment up after the launcher looked would be bought tokens nobody quoted
    /// -- and, a dev buy being what leaves the splitter needing an account for the token, cost
    /// the platform that account's rent. Above the fee in a payment that is NOT the creator's,
    /// this is not read: that excess is the fee.
    pub expected_dev_buy: u64,
    /// The chains this token is on besides Solana, ascending by LayerZero endpoint id, each with
    /// the token's address THERE: every EVM chain has its own. Recorded, not created: see
    /// `PEER_RECORD_AT`. Each is also a leg of the signed price snapshot (`price::launch_legs`).
    pub peers: Peers,
    /// The price snapshot the four EVM chains verify, as much of it as the program does not know
    /// already: its deadline, each leg's quote price, and the price signer's signature. See `price`.
    pub price: crate::price::SignedPrice,
}

/// The EVM chains a launch can name as its peers, by LayerZero endpoint id, ascending: bit `i` of
/// a launch's peer mask (see `Peers`) is `PEER_CHAINS[i]`. On mainnet: bit 0 Ethereum (30101),
/// bit 1 BNB Chain (30102), bit 2 Base (30184), bit 3 Robinhood (30416) -- the four chains every
/// launch is on. A chain added here is added at the END, so that no bit already used changes
/// meaning; at most eight, one byte's worth.
#[cfg(feature = "mainnet")]
pub const PEER_CHAINS: &[u16] = &[30101, 30102, 30184, 30416];
/// On devnet: bit 0 BNB Chain testnet (40102), bit 1 Sepolia (40161), bit 2 Base Sepolia (40245).
#[cfg(all(feature = "devnet", not(feature = "mainnet")))]
pub const PEER_CHAINS: &[u16] = &[40102, 40161, 40245];
const _: () = assert!(PEER_CHAINS.len() <= 8, "a peer mask is one byte");

/// A launch's peers as the transaction carries them: ONE byte, a mask over `PEER_CHAINS` (bit
/// `i` set: the launch is on `PEER_CHAINS[i]`), then the token's 20-byte address on each chain
/// whose bit is set, in `PEER_CHAINS`' order -- 81 bytes for four chains.
///
/// The transaction has no room for the chains' ids: four tokens of 20 bytes are what it carries
/// where it carried one, and the eight bytes the ids took (a count and two bytes an id) are part
/// of what pays for them. So a launch names a chain by its place in the program's own list, and
/// cannot name one that is not on it. The order is the list's, so it is ascending by construction
/// and no chain can be named twice. A mask with a bit past the list is refused when the arguments
/// are read; a mask with no bit set, by `check_launch_args_before_price` (`NoPeers`).
///
/// In memory it is each chain's id and token, ascending, as it always was.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Peers(pub Vec<(u16, [u8; 20])>);

impl Peers {
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    /// The ids as LayerZero's programs take them.
    pub fn eids(&self) -> impl Iterator<Item = u32> + '_ {
        self.0.iter().map(|(eid, _)| *eid as u32)
    }
    /// Each chain's id, as LayerZero's programs take it, and the token there.
    pub fn pairs(&self) -> Vec<(u32, [u8; 20])> {
        self.0.iter().map(|(eid, token)| (*eid as u32, *token)).collect()
    }
}

impl AnchorSerialize for Peers {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let invalid = |why: &str| std::io::Error::new(std::io::ErrorKind::InvalidInput, why.to_string());
        let mut mask = 0u8;
        let mut last: Option<usize> = None;
        for (eid, _) in &self.0 {
            let bit = PEER_CHAINS.iter().position(|c| c == eid).ok_or_else(|| invalid("a peer that is not one of PEER_CHAINS"))?;
            if last.is_some_and(|l| bit <= l) {
                return Err(invalid("peers not strictly ascending"));
            }
            last = Some(bit);
            mask |= 1 << bit;
        }
        writer.write_all(&[mask])?;
        for (_, token) in &self.0 {
            writer.write_all(token)?;
        }
        Ok(())
    }
}

impl AnchorDeserialize for Peers {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut mask = [0u8; 1];
        reader.read_exact(&mut mask)?;
        let mask = mask[0];
        if (mask as u16) >> PEER_CHAINS.len() != 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "a peer mask bit past PEER_CHAINS"));
        }
        let mut peers = Vec::with_capacity(mask.count_ones() as usize);
        for (bit, eid) in PEER_CHAINS.iter().enumerate() {
            if mask & (1 << bit) != 0 {
                let mut token = [0u8; 20];
                reader.read_exact(&mut token)?;
                peers.push((*eid, token));
            }
        }
        Ok(Peers(peers))
    }
}

// ------------------------------------------------------------ what the other programs are sent
//
// Each function below is the exact bytes one of the programs we call expects, and each is pinned
// in the tests against what that program's own SDK produces for the same inputs. They are kept
// apart from the instruction itself so that they can be: a wrong byte here is a pool with the
// wrong fee or a store with the wrong admin, and it would not fail -- it would work, wrongly.

/// The launched token's mint under Token-2022 before its metadata is written: the base mint padded
/// to an account's length (165), the account-type byte, and the metadata pointer's TLV entry (2 + 2
/// + 64). Token-2022's `InitializeMint2` wants exactly this; the metadata is written after it and
/// grows the account (`TokenMetadata` `Initialize` reallocates), so the account is created holding
/// the rent of its final size (`mint_len_with_metadata`).
pub const MINT_WITH_POINTER_LEN: usize = 234;

/// The mint's size once its metadata is written: the TLV entry (2 + 2) and Token-2022's
/// `TokenMetadata` -- update authority (32), mint (32), name, symbol and URI (each 4 + its length),
/// and an empty list of additional fields (4).
pub fn mint_len_with_metadata(name: &str, symbol: &str, uri: &str) -> usize {
    MINT_WITH_POINTER_LEN + 4 + 32 + 32 + 4 + name.len() + 4 + symbol.len() + 4 + uri.len() + 4
}

/// Token-2022 `InitializeMetadataPointer`: no authority -- nobody can ever point the mint's
/// metadata anywhere else -- and the metadata in the mint itself.
pub fn metadata_pointer_init_data(mint: &Pubkey) -> Vec<u8> {
    let mut d = Vec::with_capacity(66);
    d.push(39); // TokenInstruction::MetadataPointerExtension
    d.push(0); // MetadataPointerInstruction::Initialize
    d.extend_from_slice(&[0u8; 32]); // authority: None
    d.extend_from_slice(mint.as_ref()); // metadata address: the mint
    d
}

/// Token-2022's `TokenMetadata` `Initialize` (the SPL token-metadata interface): name, symbol, URI.
pub fn token_metadata_init_data(name: &str, symbol: &str, uri: &str) -> Vec<u8> {
    let mut d = Vec::with_capacity(8 + 12 + name.len() + symbol.len() + uri.len());
    // sha256("spl_token_metadata_interface:initialize_account")[..8]
    d.extend_from_slice(&[210, 225, 30, 162, 88, 184, 77, 141]);
    for s in [name, symbol, uri] {
        d.extend_from_slice(&(s.len() as u32).to_le_bytes());
        d.extend_from_slice(s.as_bytes());
    }
    d
}

/// The metadata interface's `UpdateAuthority` to nobody: from this instruction on, nothing about
/// the token's name, symbol or URI can change, by any key.
pub fn token_metadata_drop_authority_data() -> Vec<u8> {
    let mut d = Vec::with_capacity(40);
    // sha256("spl_token_metadata_interface:update_the_authority")[..8]
    d.extend_from_slice(&[215, 228, 166, 228, 84, 100, 86, 123]);
    d.extend_from_slice(&[0u8; 32]); // new authority: None
    d
}

/// Our OFT program's `init_oft_v3` (docs/v3-gap-fee-spec.md §10.3): `init_oft`'s accounts and
/// params, a 319-byte store (the gap tail) and a 104-byte `LzReceiveTypes` record.
/// sha256("global:init_oft_v3")[..8].
pub const OFT_INIT_V3_DISCRIMINATOR: [u8; 8] = [0xa3, 0xe1, 0xf7, 0x5d, 0xa3, 0x0c, 0xa0, 0x0b];

/// `oft_init_data_of`, as `init_oft_v3` when `v3`: the same bytes after the discriminator.
pub fn oft_init_data_for(admin: &Pubkey, adapter: bool, v3: bool) -> Vec<u8> {
    let mut d = oft_init_data_of(admin, adapter);
    if v3 {
        d[..8].copy_from_slice(&OFT_INIT_V3_DISCRIMINATOR);
    }
    d
}

/// OFT `init_oft` for a Native (mint-and-burn) store.
pub fn oft_init_data(admin: &Pubkey) -> Vec<u8> {
    oft_init_data_of(admin, false)
}

/// OFT `init_oft` for a Native store, or -- `adapter` -- an Adapter (lock-and-release) store: a
/// SUPPLY_TOTAL launch's lockbox (`crate::lockbox`).
pub fn oft_init_data_of(admin: &Pubkey, adapter: bool) -> Vec<u8> {
    let mut d = Vec::with_capacity(75);
    d.extend_from_slice(&[0xb6, 0xa9, 0x93, 0x10, 0xc9, 0x2d, 0x4c, 0x17]);
    // OFTType::Native (0): bridging out burns here and bridging in mints, which is what conserves
    // the global supply. OFTType::Adapter (1): bridging out locks into the escrow and bridging in
    // releases from it -- a SUPPLY_TOTAL launch, whose escrow holds the other chains' share.
    d.push(adapter as u8);
    d.extend_from_slice(admin.as_ref());
    d.push(OFT_SHARED_DECIMALS);
    d.push(1); // endpoint_program: Some
    d.extend_from_slice(LZ_ENDPOINT_ID.as_ref());
    d
}

/// OFT `set_peer_config(PeerAddress)`: the EVM token as a 32-byte LayerZero address.
pub fn oft_set_peer_data(eid: u32, evm_token: &[u8; 20]) -> Vec<u8> {
    let mut d = Vec::with_capacity(45);
    d.extend_from_slice(&[0x4f, 0xbb, 0xa8, 0x39, 0x8b, 0x8c, 0x5d, 0x2f]);
    d.extend_from_slice(&eid.to_le_bytes());
    d.push(0); // PeerConfigParam::PeerAddress
    d.extend_from_slice(&[0u8; 12]);
    d.extend_from_slice(evm_token);
    d
}

/// The size of LayerZero's record of one peer, in bytes: `8 + PeerConfig::INIT_SPACE`, room for
/// enforced options and two rate limiters. What `AUTHORITY` is lent the rent of, per peer, to
/// create them with. tests/launch.rs pins the rent this comes to (12,402,720 lamports), so a
/// different size in the OFT program's binary fails there rather than in a launch.
pub const OFT_PEER_SPACE: usize = 1_654;

/// OFT `set_oft_config(DefaultFee(bps))`: the share of every transfer out that the store keeps.
pub fn oft_set_default_fee_data(bps: u16) -> Vec<u8> {
    let mut d = Vec::with_capacity(11);
    d.extend_from_slice(&[0x37, 0x7e, 0x57, 0xd9, 0x9f, 0x42, 0x18, 0xc2]);
    d.push(2); // SetOFTConfigParams::DefaultFee
    d.extend_from_slice(&bps.to_le_bytes());
    d
}

/// The launch's total across chains: a slice for Solana and one for each peer. Checked to fit a
/// u64 (the whole of it could bridge to Solana); the price is signed per chain's slice
/// (`price::usd_per_token`).
pub fn launch_total(a: &LaunchArgs) -> Result<u64> {
    a.slice.checked_mul(a.peers.len() as u64 + 1).ok_or_else(|| error!(SplitterError::Overflow))
}

/// Meteora `initialize_customizable_pool`: a flat fee taken in the quote asset only, one position
/// from the opening price to the top of the range, trading from the block it is created in.
pub fn cp_amm_init_pool_data(fee_bps: u16, init_sqrt_price: u128, liquidity: u128) -> Vec<u8> {
    let mut d = Vec::with_capacity(107);
    d.extend_from_slice(&[0x14, 0xa1, 0xf1, 0x18, 0xbd, 0xdd, 0xb4, 0x02]);
    // The base fee: a numerator over 1e9, and nothing else -- no schedule, no periods, mode 0.
    // 30 bytes in all, of which only the first eight are not zero.
    d.extend_from_slice(&(fee_bps as u64 * 100_000).to_le_bytes());
    d.extend_from_slice(&[0u8; 22]);
    d.push(0); // dynamic fee: None. The fee is fixed at launch, as on every other chain.
    d.extend_from_slice(&init_sqrt_price.to_le_bytes()); // sqrt_min_price: the position starts here
    d.extend_from_slice(&CP_AMM_MAX_SQRT_PRICE.to_le_bytes());
    d.push(0); // has_alpha_vault
    d.extend_from_slice(&liquidity.to_le_bytes());
    d.extend_from_slice(&init_sqrt_price.to_le_bytes()); // sqrt_price: and the pool opens here
    d.push(1); // activation_type: Timestamp
    d.push(1); // collect_fee_mode: OnlyB, so a creator is never paid in their own token
    d.push(0); // activation_point: None, tradeable at once
    d
}

/// Meteora `permanent_lock_position`.
pub fn cp_amm_lock_data(liquidity: u128) -> Vec<u8> {
    let mut d = Vec::with_capacity(24);
    d.extend_from_slice(&[0xa5, 0xb0, 0x7d, 0x06, 0xe7, 0xab, 0xba, 0xd5]);
    d.extend_from_slice(&liquidity.to_le_bytes());
    d
}

/// The liquidity the launch's slice is, from its opening price to the top of the range: what
/// Meteora's SDK computes for a single-sided position (`single_sided_liquidity`), and so what the
/// pool takes the whole slice for. Refused when it is nothing or does not fit.
pub fn launch_liquidity(a: &LaunchArgs) -> Result<u128> {
    crate::single_sided_liquidity(a.slice, a.init_sqrt_price, CP_AMM_MAX_SQRT_PRICE)
        .filter(|l| *l > 0)
        .ok_or_else(|| error!(SplitterError::NothingToLaunch))
}

/// What is wrong with a launch's arguments, before anything is created: those that do not depend
/// on the price, then the price the program derived.
pub fn check_launch_args(a: &LaunchArgs) -> Result<()> {
    check_launch_args_before_price(a)?;
    require!(
        a.init_sqrt_price > 0 && a.init_sqrt_price < CP_AMM_MAX_SQRT_PRICE,
        SplitterError::PriceOutOfRange
    );
    // A price in range whose liquidity does not fit Meteora's 128 bits is a price the pool cannot
    // take, and is named as that.
    launch_liquidity(a).map_err(|_| error!(SplitterError::PriceOutOfRange))?;
    Ok(())
}

/// The checks that do not need the opening price.
pub fn check_launch_args_before_price(a: &LaunchArgs) -> Result<()> {
    check_fee(a.fee_bps, crate::venue::VENUE_LP_SHARE_BPS)?;
    require!(
        !a.name.is_empty() && a.name.len() <= MAX_NAME_LEN,
        SplitterError::BadMetadata
    );
    require!(
        !a.symbol.is_empty() && a.symbol.len() <= MAX_SYMBOL_LEN,
        SplitterError::BadMetadata
    );
    // A form this program cannot write out is refused here, before anything is created.
    ipfs_uri(a.uri_form, &a.uri_digest)?;
    require!(a.slice > 0, SplitterError::NothingToLaunch);
    // The whole of it -- a slice on each chain -- is what Solana's supply is held to, so it has to
    // be a token amount.
    launch_total(a)?;
    // A launch is on at least one EVM chain: the mask names one.
    require!(!a.peers.is_empty(), SplitterError::NoPeers);
    // Every chain names a token: a zero peer is a route that delivers to nobody.
    require!(a.peers.0.iter().all(|(_, token)| *token != [0u8; 20]), SplitterError::ZeroAddress);
    // Strictly ascending, and each one of the program's chains: what the mask can carry, and
    // nothing else (the arguments as they arrive cannot be otherwise; this holds them to it
    // however they were made).
    require!(
        a.peers.0.windows(2).all(|w| w[0].0 < w[1].0) && a.peers.0.iter().all(|(eid, _)| PEER_CHAINS.contains(eid)),
        SplitterError::PeersNotAscending
    );
    Ok(())
}

// ------------------------------------------------------------------------------- the accounts

#[derive(Accounts)]
#[instruction(args: LaunchArgs)]
pub struct Launch<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    /// The payer's listing. See `LAUNCHER_SEED`: without one, nothing below happens.
    #[account(seeds = [LAUNCHER_SEED, payer.key().as_ref()], bump = launcher.bump)]
    pub launcher: Box<Account<'info, Launcher>>,

    /// CHECK: who the fees are for, who may edit the metadata, and who is named as its creator.
    /// Not a signer in `launch`: the platform launches on a creator's behalf. A signer in
    /// `launch_cosigned`, which it pays for (see "a co-signed launch"). Writable, because a dev
    /// buy that cannot be made goes back to this wallet in this instruction (`dev_buy`). That
    /// costs the transaction nothing: whether an account is writable is a count in the
    /// message's header, not a byte per account.
    #[account(mut)]
    pub creator: UncheckedAccount<'info>,

    // ------------------------------------------------------------------ the token
    /// CHECK: created here, at the address the launch's seed and nonce derive -- which must end
    /// in `6ea` (`MINT_ENDING`). Checked here, in the accounts, so that a mint that does not is refused before
    /// the handler runs: before the mint, the store, the pool or anything else of the launch is
    /// created. (Not quite before EVERYTHING. Anchor creates an `init` account while it reads the
    /// accounts and checks the other constraints afterwards, so the launch's record has been
    /// allocated by the time this refuses -- one call to the system program, undone with the
    /// rest of the transaction, as tests/bridge_adversarial.rs shows.) See `MINT_SEED` and
    /// `has_pangea_ending`.
    #[account(
        mut,
        seeds = [MINT_SEED, args.launch_seed.as_ref(), &args.mint_nonce.to_le_bytes()],
        bump,
        constraint = has_pangea_ending(&mint.key()) @ SplitterError::MintAddressLacksPangeaEnding
    )]
    pub mint: UncheckedAccount<'info>,

    /// CHECK: where the slice is minted and what the pool takes it from; closed, or the creator's,
    /// by the end. See `TOKEN_A_SEED`.
    #[account(mut, seeds = [TOKEN_A_SEED, args.launch_seed.as_ref()], bump)]
    pub token_a_account: UncheckedAccount<'info>,

    // ------------------------------------------------------------------ the bridge
    /// CHECK: the OFT store, which LayerZero's program derives from the escrow and creates.
    #[account(mut)]
    pub oft_store: UncheckedAccount<'info>,
    /// CHECK: LayerZero's `lz_receive_types` account for the store.
    #[account(mut)]
    pub lz_receive_types: UncheckedAccount<'info>,
    /// CHECK: the escrow, at the address the launch's seed derives. See `ESCROW_SEED`.
    #[account(mut, seeds = [ESCROW_SEED, args.launch_seed.as_ref()], bump)]
    pub escrow: UncheckedAccount<'info>,
    /// CHECK: the endpoint's registry entry for the store.
    #[account(mut)]
    pub oapp_registry: UncheckedAccount<'info>,
    /// CHECK: the endpoint's event authority.
    pub endpoint_event_authority: UncheckedAccount<'info>,
    /// CHECK: the admin and endpoint delegate of the store, from the instruction that creates it:
    /// the address only this program signs for. Here it signs to set the bridge's fee. It holds no
    /// data and, when the instruction ends, no lamports. See `bridge`.
    #[account(mut, seeds = [AUTHORITY_SEED], bump)]
    pub authority: UncheckedAccount<'info>,

    // ------------------------------------------------------------------ the fees
    /// The launch's record: who its fees are paid to, at what fee, out of which position (see
    /// `fees`); after it, the slot it landed in (`LAUNCH_RECORD_LEN`) and the peers its routes will
    /// be opened to (`PEER_RECORD_AT`). At the address the launch's splitter had.
    #[account(
        init,
        payer = payer,
        space = 8 + LaunchRecord::INIT_SPACE + crate::launch_record_len(args.peers.len()),
        seeds = [SPLITTER_SEED, position_nft_mint.key().as_ref()],
        bump
    )]
    pub record: Box<Account<'info, LaunchRecord>>,
    /// CHECK: the program's fee owner, which holds every launch's position (see `fees`). It signs
    /// here to lock this launch's.
    #[account(seeds = [FEES_SEED], bump)]
    pub fee_owner: UncheckedAccount<'info>,
    /// CHECK: the creator's own quote account, their associated one. Created here if nothing
    /// is at its address yet, because the sweep creates nothing and a creator without one is not
    /// paid. It is the one address of a launch that is public beforehand; see
    /// `create_quote_accounts` for what that means. A launch that makes a dev buy does NOT
    /// create it, having no instructions to spare: it makes the buy only when this account is
    /// already there, and otherwise returns the buy's lamports to the creator (`dev_buy`). (A
    /// co-signed launch's buy is out of the wallet and needs no such account; it makes none
    /// either. A co-signed launch may name the creator's own address here: "none given".)
    #[account(mut)]
    pub creator_token_b: UncheckedAccount<'info>,

    // ------------------------------------------------------------------ the pool
    /// CHECK: the position's NFT mint, at the address the launch's seed derives. See
    /// `POSITION_SEED`.
    #[account(mut, seeds = [POSITION_SEED, args.launch_seed.as_ref()], bump)]
    pub position_nft_mint: UncheckedAccount<'info>,
    /// CHECK: Meteora's token account for the position NFT.
    #[account(mut)]
    pub position_nft_account: UncheckedAccount<'info>,
    /// CHECK: Meteora's pool authority.
    pub pool_authority: UncheckedAccount<'info>,
    /// CHECK: the pool, which Meteora derives from the two mints and creates.
    #[account(mut)]
    pub pool: UncheckedAccount<'info>,
    /// CHECK: the position, which Meteora derives from the NFT mint and creates.
    #[account(mut)]
    pub position: UncheckedAccount<'info>,
    /// CHECK: what the pool is paired against: wrapped SOL, or an asset on the admin's allowlist,
    /// whose entry (and Meteora's badge, when it needs one) follows the peers in the remaining
    /// accounts. A classic token or a Token-2022 mint; see `quote` and `resolve_quote`.
    pub quote_mint: UncheckedAccount<'info>,
    /// CHECK: the pool's vault for the launched token.
    #[account(mut)]
    pub token_a_vault: UncheckedAccount<'info>,
    /// CHECK: the pool's vault for the quote asset.
    #[account(mut)]
    pub token_b_vault: UncheckedAccount<'info>,
    /// CHECK: the payer's quote account, under the quote mint's program. Nothing moves through it
    /// but the unit Meteora rounds a single-sided pool's quote up to, but Meteora requires one, and
    /// it has to exist already: it is the launcher's own, made once per quote asset, and not worth
    /// five of a launch's sixty-four instructions every time.
    #[account(mut, constraint = !payer_token_b.data_is_empty() @ SplitterError::MissingQuoteAccount)]
    pub payer_token_b: UncheckedAccount<'info>,
    /// CHECK: Meteora's event authority.
    pub cp_amm_event_authority: UncheckedAccount<'info>,

    /// The creator's launch fee, when it was paid on Solana. Settled by this instruction, which
    /// is the whole of what makes the fee atomic with the launch -- and the only thing that
    /// settles one. It was paid under the launch's public id, which is this seed's hash. A
    /// payment within a day of being its payer's to reclaim is refused by the handler
    /// (`SETTLE_MARGIN`), and so is one that holds less than the fee the launch names
    /// (`LaunchArgs::launch_fee`). What the creator's own payment holds ABOVE the fee is their
    /// dev buy, and leaves this account in this instruction -- for the pool, or back to the
    /// creator when the buy cannot be made; above the fee in anybody else's, it is the fee
    /// (`dev_buy`).
    #[account(
        mut,
        constraint = fee.launch_id == launch_id_of(&args.launch_seed) @ SplitterError::NotThisLaunch,
        constraint = !fee.settled @ SplitterError::AlreadySettled
    )]
    pub fee: Option<Box<Account<'info, FeePayment>>>,

    // ------------------------------------------------------------------ the programs
    /// The classic token program: wrapped SOL's, and a classic quote asset's.
    pub token_program: Program<'info, Token>,
    /// CHECK: Token-2022: the launched token's program, with its metadata in the mint; a Token-2022
    /// quote asset's; and the one Meteora mints the position NFT under.
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
    /// Who signs launch prices, as the admin set it. A launch opens only at a price it signed.
    #[account(seeds = [crate::price::PRICE_SIGNER_SEED], bump = price_signer.bump)]
    pub price_signer: Box<Account<'info, crate::price::PriceSigner>>,
}

#[event]
pub struct LaunchedOnSolana {
    pub launch_id: [u8; 32],
    pub mint: Pubkey,
    pub oft_store: Pubkey,
    pub pool: Pubkey,
    pub position: Pubkey,
    pub splitter: Pubkey,
    pub creator: Pubkey,
    pub fee_bps: u16,
    pub locked_liquidity: u128,
}

// --------------------------------------------------------------------------- the instruction

/// Every account the instruction was given, once, for every call to borrow.
///
/// A call into another program takes the accounts it touches as a slice, and the runtime picks
/// the ones it needs out of it by address. Building a fresh slice per call would be fifteen of
/// them on a heap that is 32 kB and never freed, so there is one, and it is all of them.
pub(crate) struct Calls<'a, 'info> {
    pub(crate) all: &'a [AccountInfo<'info>],
}

impl<'a, 'info> Calls<'a, 'info> {
    #[inline(never)]
    fn send(&self, program: &Pubkey, accounts: Vec<AccountMeta>, data: Vec<u8>, seeds: &[&[&[u8]]]) -> Result<()> {
        let ix = Instruction {
            program_id: *program,
            accounts,
            data,
        };
        invoke_signed(&ix, self.all, seeds)?;
        Ok(())
    }
}

impl<'a, 'info> Calls<'a, 'info> {
    /// Allocate `space` bytes at an address of ours, owned by the token program, paid by `payer`.
    ///
    /// Not simply `create_account`, which refuses an address that already holds lamports -- and
    /// anyone can send lamports to an address they can compute. A launch's addresses derive from
    /// a seed that is secret until the launch lands, so nobody should be able to; this is for the
    /// case where somebody could anyway. An address that already holds lamports is topped up to
    /// rent, allocated and assigned instead, which is what `create_account` does in one step and
    /// what Anchor's `init` does for the same reason. The stranger's lamports go toward the rent.
    #[inline(never)]
    fn allocate(&self, payer: &Pubkey, account: &Pubkey, space: usize, seeds: &[&[u8]], owner: &Pubkey) -> Result<()> {
        self.allocate_holding(payer, account, space, Rent::get()?.minimum_balance(space), seeds, owner)
    }

    /// `allocate`, holding `rent` lamports rather than the rent of `space`: for an account that
    /// grows after it is made (the mint, whose metadata is written into it).
    #[inline(never)]
    fn allocate_holding(&self, payer: &Pubkey, account: &Pubkey, space: usize, rent: u64, seeds: &[&[u8]], owner: &Pubkey) -> Result<()> {
        let held = self
            .all
            .iter()
            .find(|a| a.key == account)
            .map(|a| a.lamports())
            .ok_or(SplitterError::NotThisLaunch)?;
        if held == 0 {
            let ix = system_instruction::create_account(payer, account, rent, space as u64, owner);
            invoke_signed(&ix, self.all, &[seeds])?;
            return Ok(());
        }
        if held < rent {
            invoke_signed(&system_instruction::transfer(payer, account, rent - held), self.all, &[])?;
        }
        invoke_signed(&system_instruction::allocate(account, space as u64), self.all, &[seeds])?;
        invoke_signed(&system_instruction::assign(account, owner), self.all, &[seeds])?;
        Ok(())
    }
}

/// Every account a launch's steps use, by its role, whichever instruction was sent: `launch` and
/// `launch_cosigned` (`Launch`), or `launch_v2` and `launch_self` (`crate::LaunchV2`). The steps
/// below take this and nothing else, so the four launches make the same calls from one copy of
/// the code.
pub struct LaunchAccounts<'a, 'info> {
    pub payer: &'a AccountInfo<'info>,
    pub creator: &'a AccountInfo<'info>,
    pub mint: &'a AccountInfo<'info>,
    pub token_a_account: &'a AccountInfo<'info>,
    pub oft_store: &'a AccountInfo<'info>,
    pub lz_receive_types: &'a AccountInfo<'info>,
    pub escrow: &'a AccountInfo<'info>,
    pub oapp_registry: &'a AccountInfo<'info>,
    pub endpoint_event_authority: &'a AccountInfo<'info>,
    pub authority: &'a AccountInfo<'info>,
    pub fee_owner: &'a AccountInfo<'info>,
    /// The creator's own quote account: v1's fee account for them and an asset dev buy's source.
    /// A v2 launch names it only for an asset dev buy.
    pub creator_token_b: Option<&'a AccountInfo<'info>>,
    pub position_nft_mint: &'a AccountInfo<'info>,
    pub position_nft_account: &'a AccountInfo<'info>,
    pub pool_authority: &'a AccountInfo<'info>,
    pub pool: &'a AccountInfo<'info>,
    pub position: &'a AccountInfo<'info>,
    pub quote_mint: &'a AccountInfo<'info>,
    pub token_a_vault: &'a AccountInfo<'info>,
    pub token_b_vault: &'a AccountInfo<'info>,
    pub payer_token_b: &'a AccountInfo<'info>,
    pub cp_amm_event_authority: &'a AccountInfo<'info>,
    /// The launch's fee payment, when it was handed one, and who made it.
    pub fee: Option<&'a AccountInfo<'info>>,
    pub fee_payer: Option<Pubkey>,
    pub token_program: &'a AccountInfo<'info>,
    pub token_2022_program: &'a AccountInfo<'info>,
    pub associated_token_program: &'a AccountInfo<'info>,
    pub system_program: &'a AccountInfo<'info>,
    /// Wrapped SOL's price band, from the price signer's record.
    pub native_band: crate::price::PriceBand,
}

impl<'a, 'info> LaunchAccounts<'a, 'info> {
    pub fn of(a: &'a Launch<'info>) -> Self {
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
            creator_token_b: Some(a.creator_token_b.as_ref()),
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

    /// The creator's quote account, which v1 always names.
    fn creator_quote(&self) -> Result<&'a AccountInfo<'info>> {
        self.creator_token_b.ok_or_else(|| error!(SplitterError::NotThisLaunch))
    }
}

/// How one launch's pool and its slice account are to be finished, beyond its arguments.
pub struct Finish<'a, 'info> {
    /// Where a dev buy's tokens go: the slice's account (`token_a_account`), which becomes the
    /// creator's (in either supply mode since the lockbox).
    pub buy_into: &'a AccountInfo<'info>,
    /// What may be left in the slice's account once the pool has drawn from it: `MAX_UNPOOLED` (a
    /// lockbox's locked share is in its escrow by then).
    pub may_remain: u64,
    /// Who the slice's account belongs to afterwards: None for v1's rule (closed when empty and
    /// no dev buy was made, else the creator's); Some(owner) to hand it to another (no launch
    /// does today; it was the reserve era's SUPPLY_TOTAL reserve's authority once).
    pub keep_for: Option<Pubkey>,
}

fn ro(k: &Pubkey) -> AccountMeta {
    AccountMeta::new_readonly(*k, false)
}
fn rw(k: &Pubkey) -> AccountMeta {
    AccountMeta::new(*k, false)
}
fn signer(k: &Pubkey) -> AccountMeta {
    AccountMeta::new_readonly(*k, true)
}
fn rw_signer(k: &Pubkey) -> AccountMeta {
    AccountMeta::new(*k, true)
}

pub fn launch_handler<'info>(ctx: Context<'_, '_, 'info, 'info, Launch<'info>>, args: LaunchArgs) -> Result<()> {
    launch_with(ctx, args, false)
}

/// `launch_cosigned`: the creator signs and pays. See "a co-signed launch".
pub fn launch_cosigned_handler<'info>(ctx: Context<'_, '_, 'info, 'info, Launch<'info>>, args: LaunchArgs) -> Result<()> {
    launch_with(ctx, args, true)
}

/// What the launcher must hold, wallet and quote account together, when a co-signed launch
/// ends: what it holds as the handler starts, and the rent of the launch's record, which Anchor
/// drew from it before then. Checks the two signers first.
fn cosigned_floor(a: &Launch<'_>) -> Result<u64> {
    require!(a.creator.is_signer, SplitterError::CreatorMustSign);
    require_keys_neq!(a.creator.key(), a.payer.key(), SplitterError::CreatorIsLauncher);
    let record = a.record.to_account_info();
    let record_rent = Rent::get()?.minimum_balance(record.data_len());
    a.payer
        .lamports()
        .checked_add(a.payer_token_b.lamports())
        .and_then(|held| held.checked_add(record_rent))
        .ok_or_else(|| error!(SplitterError::Overflow))
}

/// After the last call a co-signed launch makes: pay the launcher back, out of the creator's
/// wallet, whatever it is down against `floor`, and hold it to that.
///
/// No event says what was repaid: a launch's log is past the 10,000 bytes a node keeps of it, so
/// an event this late would be cut off. It is the launcher's balance before and after.
///
/// `carries_payment`: the creator's excess was just moved out of the payment's account and into
/// their wallet by hand (`refund_excess_first`), so the transfer carries that account too -- the
/// runtime refuses a call that sees the wallet's side of a move and not the payment's. The system
/// program reads only the first two accounts.
#[inline(never)]
fn repay_launcher<'info>(a: &Launch<'info>, calls: &Calls<'_, 'info>, floor: u64, carries_payment: bool) -> Result<()> {
    let held = |a: &Launch<'info>| a.payer.lamports().saturating_add(a.payer_token_b.lamports());
    let owed = floor.saturating_sub(held(a));
    // What the creator was told a launch can cost them, besides fees and a dev buy, held here: a
    // change in what another program charges cannot pass itself on to a creator unannounced.
    require!(owed <= COSIGNED_LAUNCH_RENT_BOUND, SplitterError::CosignedRentOverBound);
    if owed > 0 {
        let mut repay = system_instruction::transfer(&a.creator.key(), &a.payer.key(), owed);
        if carries_payment {
            let payment = a.fee.as_ref().ok_or(SplitterError::NotThisLaunch)?;
            repay.accounts.push(rw(&payment.key()));
        }
        invoke_signed(&repay, calls.all, &[])?;
    }
    require!(held(a) >= floor, SplitterError::LauncherNotRepaid);
    Ok(())
}

#[inline(never)]
fn launch_with<'info>(ctx: Context<'_, '_, 'info, 'info, Launch<'info>>, args: LaunchArgs, cosigned: bool) -> Result<()> {
    // A co-signed launch: both signatures, and what the launcher holds, before anything moves.
    let floor = if cosigned { Some(cosigned_floor(&ctx.accounts)?) } else { None };
    let mut args = args;
    // Everything the price does not depend on, first: a malformed launch is refused as what it is.
    check_launch_args_before_price(&args)?;
    // After the instruction's own accounts -- for a launch that pairs against an allowlisted asset
    // rather than wrapped SOL -- the asset's allowlist entry and, when Meteora requires one for
    // it, its token badge. See `quote`. (No peers: a launch records them, and each is created
    // with the route to it, by its first bridger. See `PEER_RECORD_AT`.)
    let quote = resolve_quote(&LaunchAccounts::of(&ctx.accounts), ctx.remaining_accounts)?;
    // The opening price: not an argument. Derived from the price signer's snapshot -- $3,000 over
    // the supply against the signed price of this quote asset -- or the launch is refused. See `price`.
    {
        let quote_decimals = *ctx.accounts.quote_mint.try_borrow_data()?.get(44).ok_or(error!(SplitterError::QuoteAssetUnsupported))?;
        let peers = args.peers.pairs();
        args.init_sqrt_price = crate::price::verified_opening_price(
            &args.price,
            &ctx.accounts.price_signer.address,
            &crate::launch_id_of(&args.launch_seed),
            args.fee_bps,
            &peers,
            &ctx.accounts.oft_store.key(),
            args.slice,
            quote_decimals,
            quote.usd_band,
            Clock::get()?.unix_timestamp,
        )?;
    }
    check_launch_args(&args)?;
    let liquidity = launch_liquidity(&args)?;
    // The payment, if the launch is handed one, before anything is created. It holds the fee
    // the launch was told to expect -- a floor the launcher states, and has to state -- and it
    // is not one its payer can reclaim, or will be able to within the day: the launch and the
    // reclaim would be racing for one account. With no payment handed over, the fee was paid
    // elsewhere and `launch_fee` is not read.
    let above_fee = match ctx.accounts.fee.as_ref() {
        Some(fee) => {
            require!(args.launch_fee > 0, SplitterError::LaunchFeeNotNamed);
            require!(fee.amount >= args.launch_fee, SplitterError::PaymentBelowLaunchFee);
            require!(
                Clock::get()?.unix_timestamp < crate::settleable_until(fee.at),
                SplitterError::PaymentTooOldToSettle
            );
            fee.amount - args.launch_fee
        }
        None => {
            // A fee named, and no payment to settle: a launch for nothing. See `launch_fee`.
            require!(args.launch_fee == 0, SplitterError::LaunchFeeWithoutPayment);
            0
        }
    };
    // What the payment holds above the fee: the creator's -- up to the quoted dev buy made, the
    // rest handed back -- or, in anybody else's payment, part of the fee. Decided here, before
    // anything is created, and never a reason to refuse the launch: see `dev_buy`.
    //
    // With wrapped SOL the dev buy is in the payment, as lamports. With an allowlisted asset it is
    // not: the creator bought the asset in their own payment transaction and approved this
    // program's AUTHORITY to spend it, so the payment's excess goes back and the buy, if any, comes
    // out of their own account (`check_asset_dev_buy`).
    //
    // A co-signed launch buys out of the creator's wallet, never out of a payment: the creator's
    // excess goes back to them whole, and the buy is `expected_dev_buy` from the wallet.
    let excess = match (above_fee > 0, cosigned) {
        (false, _) => Excess::Nothing,
        (true, false) => check_dev_buy(&LaunchAccounts::of(&ctx.accounts), &args, above_fee, liquidity, true)?,
        (true, true) => excess_back_to_creator(&LaunchAccounts::of(&ctx.accounts), above_fee)?,
    };
    let dev_buy = match excess {
        Excess::Creators { buy, least, .. } if buy > 0 => Some(DevBuy::FromPayment { lamports: buy, least }),
        _ if !quote.native => check_asset_dev_buy(&LaunchAccounts::of(&ctx.accounts), &args, &quote, liquidity, true)?,
        _ if cosigned => check_wallet_dev_buy(&LaunchAccounts::of(&ctx.accounts), &args, liquidity),
        _ => None,
    };

    let mut all = ctx.accounts.to_account_infos();
    all.extend_from_slice(ctx.remaining_accounts);
    let calls = Calls { all: &all };

    let a = &ctx.accounts;
    // Every address below is the seed's. The id is only what the launch is called.
    let seed = args.launch_seed;
    let id = launch_id_of(&seed);
    let mint_nonce = args.mint_nonce.to_le_bytes();
    let mint_seeds: &[&[u8]] = &[MINT_SEED, seed.as_ref(), &mint_nonce, &[ctx.bumps.mint]];
    let escrow_seeds: &[&[u8]] = &[ESCROW_SEED, seed.as_ref(), &[ctx.bumps.escrow]];
    let nft_seeds: &[&[u8]] = &[POSITION_SEED, seed.as_ref(), &[ctx.bumps.position_nft_mint]];
    let nft_key = a.position_nft_mint.key();
    let fee_owner_seeds: &[&[u8]] = &[FEES_SEED, &[ctx.bumps.fee_owner]];

    let token_a_seeds: &[&[u8]] = &[TOKEN_A_SEED, seed.as_ref(), &[ctx.bumps.token_a_account]];

    let leg = LaunchAccounts::of(a);
    create_token(&leg, &calls, &args, args.slice, mint_seeds, token_a_seeds)?;
    wire_bridge(&leg, &calls, &args, escrow_seeds, ctx.bumps.authority, Some(a.oft_store.key()), false, false)?;
    // A co-signed launch that makes a dev buy makes no quote account: those five instructions
    // go to the buy's six (as `check_dev_buy` arranges for a plain launch).
    let skip_quote_account = matches!(dev_buy, Some(DevBuy::FromWallet { .. }));
    create_quote_accounts(&leg, &quote, skip_quote_account)?;
    let pool = PoolPlan { liquidity, quote, authority_bump: ctx.bumps.authority };
    let finish = Finish { buy_into: leg.token_a_account, may_remain: MAX_UNPOOLED, keep_for: None };
    let locked = open_pool(&leg, &calls, &args, nft_seeds, fee_owner_seeds, dev_buy, &pool, &finish)?;

    // A co-signed launch's last call: the creator pays the launcher back. After every call that
    // draws on the launcher. The creator's payment excess is handed back first, so that it can
    // pay for it (`refund_excess_first`); nothing else below this moves lamports before it.
    let refunded_first = match floor {
        Some(floor) => {
            let first = refund_excess_first(a, excess)?;
            repay_launcher(a, &calls, floor, first)?;
            first
        }
        None => false,
    };

    // The launch's record, written last and by nobody but this instruction: who is paid, at what
    // fee, out of which position, in which asset. Its address derives from the position's NFT
    // mint, which only this instruction can sign for, so there is no "first" for a stranger to be.
    let record_key = ctx.accounts.record.key();
    let r = &mut ctx.accounts.record;
    r.creator = ctx.accounts.creator.key();
    r.pending_creator = Pubkey::default();
    r.position = ctx.accounts.position.key();
    r.position_nft_mint = nft_key;
    r.quote_mint = ctx.accounts.quote_mint.key();
    r.fee_bps = args.fee_bps;
    r.venue_lp_share_bps = crate::venue::VENUE_LP_SHARE_BPS;
    r.bump = ctx.bumps.record;
    r.dev_buy_made = dev_buy.is_some();
    // Every address this program holds that a creator could be named as: the launch's record, the
    // fee owner, AUTHORITY, the platform record, and the program's account for this launch's quote
    // asset (where every launch's fees in it pass through).
    let platform_record = Pubkey::find_program_address(&[crate::PLATFORM_SEED], &crate::ID).0;
    let quote_fee_account = Pubkey::find_program_address(&[crate::FEES_SEED, r.quote_mint.as_ref()], &crate::ID).0;
    crate::check_parties(
        &r.creator,
        &ADMIN,
        &[record_key, ctx.accounts.fee_owner.key(), ctx.accounts.authority.key(), platform_record, quote_fee_account, crate::native_transit()],
    )?;

    // The launch's record, after the struct: the slot it landed in -- what `open_bridge` holds a
    // route's last edit against (see `bridge`, "a route is the one in force at launch") -- and
    // the peers: each chain named and the token's address on it, which `open_bridge` creates each
    // peer from with the route to it. Written here, once, from the arguments; nothing writes it again.
    {
        let info = ctx.accounts.record.to_account_info();
        let mut data = info.try_borrow_mut_data()?;
        let at = crate::LAUNCHED_SLOT_AT;
        data[at..at + crate::LAUNCH_RECORD_LEN].copy_from_slice(&Clock::get()?.slot.to_le_bytes());
        crate::write_peer_record(&mut data, &args.peers.0);
        // No reserve record: a launch keeps no reserve (see `reserve`). Its mint supply is its
        // real local supply, and its bridge may open straight away (`bridge_may_open`).
    }

    // And the launch fee, if it was paid here. The launch is the proof, and this is the launch.
    if let Some(fee) = ctx.accounts.fee.as_mut() {
        match excess {
            // The creator's: the dev buy's lamports, if one was made, have left this account for
            // the pool. What is left of their excess goes back to their wallet, now -- after the
            // last call this instruction makes, so that no call sees one side of the move without
            // the other. (A co-signed launch made this move before its repay instead, with the
            // payment's account carried by that call: the first arm.) Then what the payment
            // records, and holds above its rent, is the fee: all the platform can withdraw.
            Excess::Creators { .. } if refunded_first => fee.amount = args.launch_fee,
            Excess::Creators { back, .. } => {
                let creator = ctx.accounts.creator.to_account_info();
                if back == 0 || can_take_back(&creator, back)? {
                    let payment = fee.to_account_info();
                    **payment.try_borrow_mut_lamports()? -= back;
                    **creator.try_borrow_mut_lamports()? += back;
                    fee.amount = args.launch_fee;
                } else {
                    // An empty wallet that cannot hold so little: it stays, and is the fee.
                    fee.amount = args.launch_fee + back;
                }
            }
            // Not the creator's payment: all of it is the fee, and `amount` says so already.
            Excess::Fee | Excess::Nothing => {}
        }
        fee.settled = true;
        emit!(crate::FeeSettled {
            launch_id: fee.launch_id,
            payer: fee.payer,
            lamports: fee.amount,
        });
    }

    emit!(LaunchedOnSolana {
        launch_id: id,
        mint: ctx.accounts.mint.key(),
        oft_store: ctx.accounts.oft_store.key(),
        pool: ctx.accounts.pool.key(),
        position: ctx.accounts.position.key(),
        splitter: record_key,
        creator: ctx.accounts.creator.key(),
        fee_bps: args.fee_bps,
        locked_liquidity: locked,
    });
    Ok(())
}

/// The mint, under Token-2022 with its metadata in it, and its whole slice.
///
/// ## The metadata is the mint's, and it never changes
///
/// Token-2022's metadata extension keeps the name, symbol and URI in the mint account itself, where
/// a metadata pointer that points at the mint says to find them -- no Metaplex account, no
/// Metaplex fee (10,000,000 lamports a token). Both are fixed here for good: the pointer is made
/// with no authority, so nothing can ever point the token's metadata elsewhere, and the metadata's
/// update authority is set to nobody in the same instruction that writes it. The creator cannot
/// rename the token afterwards and neither can the platform; what a launch says a token is, it is.
///
/// No other extension: no transfer fee, no hook, no permanent delegate, no freeze authority, no
/// default account state. Meteora opens a pool against a mint with exactly the metadata pointer and
/// the metadata without a token badge (cp-amm `is_permissionless_supported_mint`), and
/// LayerZero's OFT program mints and burns a Token-2022 mint through the program it is handed.
#[inline(never)]
pub(crate) fn create_token<'info>(
    a: &LaunchAccounts<'_, 'info>,
    calls: &Calls<'_, 'info>,
    args: &LaunchArgs,
    supply: u64,
    mint_seeds: &[&[u8]],
    token_a_seeds: &[&[u8]],
) -> Result<()> {
    let t22 = a.token_2022_program.key();
    let mint = a.mint.key();
    let payer = a.payer.key();
    // Who the mint answers to while it is made: the payer, until `wire_bridge` hands it to the
    // store -- or, SUPPLY_TOTAL, until `lock_in_escrow` revokes it.
    let mint_authority = payer;
    let uri = ipfs_uri(args.uri_form, &args.uri_digest)?;
    // Created at the size `InitializeMint2` requires, holding the rent of the size the metadata
    // grows it to.
    let lamports = Rent::get()?.minimum_balance(mint_len_with_metadata(&args.name, &args.symbol, &uri));
    calls.allocate_holding(&payer, &mint, MINT_WITH_POINTER_LEN, lamports, mint_seeds, &t22)?;
    calls.send(&t22, vec![rw(&mint)], metadata_pointer_init_data(&mint), &[])?;
    // The payer is the mint authority for the length of this instruction and no longer: it mints
    // the slice and writes the metadata below, and `wire_bridge` gives the authority to
    // the token's OFT store, the only minter from then on. No freeze authority, and nothing that can set one -- a supply locked in a pool whose
    // holders could be frozen would be locked in name only.
    token_2022::initialize_mint2(
        CpiContext::new(a.token_2022_program.clone(), token_2022::InitializeMint2 { mint: a.mint.clone() }),
        TOKEN_DECIMALS,
        &mint_authority,
        None,
    )?;

    // The metadata, in the same instruction as the mint. A token that exists for even one block
    // without it is one wallets and scanners index as unknown, and some of them cache that.
    calls.send(
        &t22,
        vec![rw(&mint), ro(&payer), ro(&mint), signer(&mint_authority)],
        token_metadata_init_data(&args.name, &args.symbol, &uri),
        &[],
    )?;
    calls.send(&t22, vec![rw(&mint), signer(&payer)], token_metadata_drop_authority_data(), &[])?;

    // The whole slice, into an account the payer owns for as long as it takes Meteora to draw it
    // into the pool. `open_pool` disposes of it afterwards.
    calls.allocate(&payer, &a.token_a_account.key(), crate::TOKEN_ACCOUNT_LEN, token_a_seeds, &t22)?;
    token_2022::initialize_account3(CpiContext::new(
        a.token_2022_program.clone(),
        token_2022::InitializeAccount3 {
            account: a.token_a_account.clone(),
            mint: a.mint.clone(),
            authority: a.payer.clone(),
        },
    ))?;
    // The slice -- or, for a SUPPLY_TOTAL launch, the whole launch total: the slice the pool takes
    // and the bridge reserve, which stays behind in this account (see `launch_v2`).
    token_2022::mint_to(
        CpiContext::new(
            a.token_2022_program.clone(),
            token_2022::MintTo {
                mint: a.mint.clone(),
                to: a.token_a_account.clone(),
                authority: a.payer.clone(),
            },
        ),
        supply,
    )
}

/// The OFT store, its fee, and the authorities that could otherwise mint. Not its peers: the launch
/// records them (`PEER_RECORD_AT`) and each route's opening creates its own.
///
/// ## The store is never the launcher's
///
/// LayerZero's `init_oft` takes the store's admin as an argument and registers that same key as
/// the endpoint delegate. `AUTHORITY` is named from the start, and this program signs for it to do
/// what an admin has to do here: set the fee (and, in `open_bridge`, make a recorded peer). The
/// launcher's key is not the store's admin for even the length of this instruction, so there is
/// nothing about a store that a launcher's key was ever able to decide.
///
/// ## `AUTHORITY` holds nothing
///
/// `AUTHORITY` is one address for every launch, so it is public, and anyone can send it lamports.
/// Nothing is lent to it here -- it pays for nothing in a launch -- and anything it holds is handed
/// on to whoever is launching at the end of this function: one transfer, the only thing lamports
/// sent there cost a launch.
///
/// `AUTHORITY` signs here for calls on ONE store: the one `init_oft` has just created, in this
/// instruction, at the address this launch's seed derives -- which is checked before the first of
/// them, and which `init_oft` would refuse to create twice.
#[inline(never)]
pub(crate) fn wire_bridge<'info>(
    a: &LaunchAccounts<'_, 'info>,
    calls: &Calls<'_, 'info>,
    args: &LaunchArgs,
    escrow_seeds: &[&[u8]],
    authority_bump: u8,
    mint_authority: Option<Pubkey>,
    adapter: bool,
    v3: bool,
) -> Result<()> {
    let payer = a.payer.key();
    let store = a.oft_store.key();
    let system = a.system_program.key();
    let registry = a.oapp_registry.key();
    let endpoint_events = a.endpoint_event_authority.key();
    let authority = a.authority.key();
    let authority_seeds: &[&[u8]] = &[AUTHORITY_SEED, &[authority_bump]];

    // The store this launch's seed derives, and no other. LayerZero's program derives it from the
    // escrow too and would refuse a different one; it is said here because everything signed as
    // `AUTHORITY` below is signed for this address.
    require_keys_eq!(store, crate::bridge::store_of_launch(&args.launch_seed), SplitterError::NotThisLaunch);

    // The store, with `AUTHORITY` as its admin and -- because `init_oft` registers the admin as
    // the delegate -- its endpoint delegate. Each of the two can mint, by adding a peer or by
    // replacing who verifies one, so neither is ever a key. The payer pays for the accounts. The
    // last seven accounts are not the OFT program's own: it hands them on to the endpoint, which
    // registers the store as an application.
    calls.send(
        &OFT_PROGRAM_ID,
        vec![
            rw_signer(&payer),
            rw(&store),
            rw(&a.lz_receive_types.key()),
            ro(&a.mint.key()),
            rw_signer(&a.escrow.key()),
            ro(&a.token_2022_program.key()),
            ro(&system),
            ro(&LZ_ENDPOINT_ID),
            rw(&payer),
            ro(&store),
            rw(&registry),
            ro(&system),
            ro(&endpoint_events),
            ro(&LZ_ENDPOINT_ID),
        ],
        // A v3 store (`v3`: a `launch_v2`/`launch_self` signed and sent as v3 -- `launch_v2::gap_v3_named`,
        // `price::terms_hash_v3` -- while the admin's `PDA(["gap_v3"])` allows it) is made by `init_oft_v3`: the same accounts and params, the
        // store 96 bytes longer (the gap tail, tail_ver 0 until `set_gap_pool`) and its
        // `LzReceiveTypes` 32 -- 890,880 lamports more rent, paid by the payer. Legacy `launch`
        // never makes one.
        oft_init_data_for(&authority, adapter, v3),
        &[escrow_seeds],
    )?;

    // No peers here. The launch records them (the record's tail, `PEER_RECORD_AT`) and each is
    // created by `open_bridge` with the route to it, from that record, signed as `AUTHORITY` --
    // so the first bridger on a route pays for its peer, and a launch pays for none: four peers
    // were 49,610,880 lamports, and about nine of the 64 instructions a transaction may run.

    // The bridge's fee: 0.2% of every transfer out, from the first one, set in the instruction
    // that creates the store. Afterwards only a v3 store's can change (`set_bridge_fee`, admin
    // only, 0 to 50 bps); never a peer's, and nobody else is the admin.
    calls.send(
        &OFT_PROGRAM_ID,
        vec![signer(&authority), rw(&store)],
        oft_set_default_fee_data(BRIDGE_FEE_BPS),
        &[authority_seeds],
    )?;

    // `AUTHORITY` holds nothing between instructions: there is never a balance sitting at an
    // address nobody has a key for. It is lent nothing here; anything it holds was sent to it by
    // somebody, and goes to whoever is launching.
    let left = a.authority.lamports();
    if left > 0 {
        invoke_signed(&system_instruction::transfer(&authority, &payer, left), calls.all, &[authority_seeds])?;
    }

    // And the mint authority, to the token's OFT store: a plain Native OFT, which mints only for
    // an arrival that the source chain burned. Nothing else can ever mint -- this program never
    // signs as the store -- so the mint's supply is the token's real supply on Solana. (A
    // SUPPLY_TOTAL launch's store is an Adapter, which never mints: `mint_authority` is None, and
    // `lock_in_escrow` revokes the payer's authority once the total is minted. See `launch_v2`.)
    let Some(mint_authority) = mint_authority else { return Ok(()) };
    token_2022::set_authority(
        CpiContext::new(
            a.token_2022_program.clone(),
            token_2022::SetAuthority {
                current_authority: a.payer.clone(),
                account_or_mint: a.mint.clone(),
            },
        ),
        anchor_spl::token_2022::spl_token_2022::instruction::AuthorityType::MintTokens,
        Some(mint_authority),
    )
}

/// Our OFT program's `init_tvl` (`solana/oft`, PANGEA-PATCH.md): sha256("global:init_tvl")[..8],
/// then the amount.
pub fn oft_init_tvl_data(tvl_ld: u64) -> Vec<u8> {
    let mut d = Vec::with_capacity(16);
    d.extend_from_slice(&[0xfa, 0x8a, 0xfb, 0x44, 0x85, 0xe5, 0xdc, 0xd6]);
    d.extend_from_slice(&tvl_ld.to_le_bytes());
    d
}

/// The seed of the store's one-shot `init_tvl` record, `PDA(["TvlMark", store])` under the OFT
/// program.
pub const TVL_MARK_SEED: &[u8] = b"TvlMark";

/// The store's `TvlMark`: the account `init_tvl` creates, once.
pub fn tvl_mark_of(store: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[TVL_MARK_SEED, store.as_ref()], &OFT_PROGRAM_ID).0
}

/// # The lockbox: a SUPPLY_TOTAL launch's other chains' share, locked in its Adapter store
///
/// A SUPPLY_TOTAL launch mints the whole total on Solana, `slice x chains`, into the slice's
/// account. Its store is an ADAPTER (`wire_bridge` with `adapter`), which locks what leaves Solana
/// in its escrow and releases from there what arrives. This moves the share that is not
/// Solana's -- `locked`, the total less the slice -- into that escrow and declares it locked
/// (`init_tvl`, the one instruction our deployment of the OFT program adds to LayerZero's), so
/// the escrow stands behind every token the EVM chains will hold. Then it revokes the mint's
/// authority, for good: an Adapter never mints, so nothing ever can, and Solana's mint supply IS
/// the total, forever, with no `rebalance`.
///
/// Signed for: the payer moves the share (it owns the slice's account for the length of the
/// launch, as `create_token` made it) and revokes its own mint authority; `AUTHORITY` signs
/// `init_tvl` as the store's admin, for the store `init_oft` created in this same instruction --
/// the store this launch's seed derives, checked in `wire_bridge`. `init_tvl` checks the rest
/// itself: an Adapter, nothing locked yet, the amount exactly the escrow's balance, once per store
/// (its `TvlMark`, made here at the payer's rent).
#[inline(never)]
pub(crate) fn lock_in_escrow<'info>(a: &LaunchAccounts<'_, 'info>, calls: &Calls<'_, 'info>, tvl_mark: &AccountInfo<'info>, locked: u64, authority_bump: u8) -> Result<()> {
    let payer = a.payer.key();
    let store = a.oft_store.key();
    let authority = a.authority.key();
    let t22 = a.token_2022_program.key();
    require!(locked > 0, SplitterError::NothingToLock);
    require_keys_eq!(tvl_mark.key(), tvl_mark_of(&store), SplitterError::LockboxMarkNotGiven);
    token_2022::transfer_checked(
        CpiContext::new(
            a.token_2022_program.clone(),
            token_2022::TransferChecked {
                from: a.token_a_account.clone(),
                mint: a.mint.clone(),
                to: a.escrow.clone(),
                authority: a.payer.clone(),
            },
        ),
        locked,
        TOKEN_DECIMALS,
    )?;
    let authority_seeds: &[&[u8]] = &[AUTHORITY_SEED, &[authority_bump]];
    calls.send(
        &OFT_PROGRAM_ID,
        vec![rw_signer(&payer), signer(&authority), rw(&store), ro(&a.escrow.key()), rw(&tvl_mark.key()), ro(&t22), ro(&a.system_program.key())],
        oft_init_tvl_data(locked),
        &[authority_seeds],
    )?;
    token_2022::set_authority(
        CpiContext::new(
            a.token_2022_program.clone(),
            token_2022::SetAuthority { current_authority: a.payer.clone(), account_or_mint: a.mint.clone() },
        ),
        anchor_spl::token_2022::spl_token_2022::instruction::AuthorityType::MintTokens,
        None,
    )
}

/// The creator's account for the quote asset, which their share of the fees is paid into.
///
/// Created here if they have none: claims create nothing, because a claimer that recreated a
/// missing account every time would be paying rent to anyone willing to close theirs. The fees
/// themselves are claimed into the program's one account for the asset and paid straight out
/// (see `fees`), so a launch makes no fee account of its own. The platform's is the platform's
/// own and is not this instruction's to make.
#[inline(never)]
fn create_quote_accounts<'info>(a: &LaunchAccounts<'_, 'info>, quote: &Quote, skip: bool) -> Result<()> {
    if skip {
        return Ok(());
    }
    let creator_token_b = a.creator_quote()?;
    // Only when NOTHING is at its address. Asking the associated-token program to create an
    // account that exists is still an instruction, and a launch has sixty-four.
    //
    // "Nothing" is lamports, not data, and the difference is deliberate. This is the one address
    // of a launch that anybody can compute beforehand -- it is the creator's own, not the seed's
    // -- so it is the one address a stranger can send lamports to. Creating an account at an
    // address that already holds some costs the associated-token program two more instructions,
    // which is one more than this launch has. So an address that holds lamports and no account
    // is left as it is: the launch goes through, the creator's fees wait in the pool (a claim names
    // both parties' accounts or waits; see `fees`), and the creator makes their own account whenever
    // they like.
    if creator_token_b.lamports() == 0 {
        associated_token::create(CpiContext::new(
            a.associated_token_program.clone(),
            associated_token::Create {
                payer: a.payer.clone(),
                associated_token: creator_token_b.clone(),
                authority: a.creator.clone(),
                mint: a.quote_mint.clone(),
                system_program: a.system_program.clone(),
                token_program: quote_program(a, quote),
            },
        ))?;
    }
    Ok(())
}

// ------------------------------------------------------------------------------ the quote asset

/// The launch's quote asset, resolved and checked (see `quote`).
#[derive(Debug, Clone, Copy)]
pub struct Quote {
    /// Wrapped SOL, which needs no allowlist entry and is the only asset a dev buy can be made in
    /// out of the payment.
    pub native: bool,
    /// The quote mint's program: the classic token program or Token-2022.
    pub program: Pubkey,
    /// The size of a token account for the quote mint.
    pub account_len: usize,
    /// Meteora's token badge for the quote mint, when it needs one to open a pool.
    pub badge: Option<Pubkey>,
    /// The band the signed price of this asset must be inside: its allowlist entry's, or for
    /// wrapped SOL the price signer record's. See `price`.
    pub usd_band: crate::price::PriceBand,
}

/// What a launch's pool is opened with besides its arguments.
pub struct PoolPlan {
    pub liquidity: u128,
    pub quote: Quote,
    pub authority_bump: u8,
}

/// The program that owns the quote mint, as the account the launch was given for it: the classic
/// token program or Token-2022, both of which every launch names already.
fn quote_program<'info>(a: &LaunchAccounts<'_, 'info>, quote: &Quote) -> AccountInfo<'info> {
    if quote.program == token::ID {
        a.token_program.clone()
    } else {
        a.token_2022_program.clone()
    }
}

/// The quote asset this launch pairs against, and whether it may: wrapped SOL, or an asset on the
/// admin's allowlist, enabled, given with its entry (and Meteora's badge, when it needs one) after
/// the peers -- and not, at this moment, paused, frozen by default or hooked. A launch against
/// anything else is refused by name before anything is created (`QuoteAssetNotAllowed`,
/// `QuoteAssetUnavailable`), and the launcher checks the same before it sends.
#[inline(never)]
pub(crate) fn resolve_quote(a: &LaunchAccounts<'_, '_>, extra: &[AccountInfo]) -> Result<Quote> {
    let mint = a.quote_mint.key();
    if mint == spl_token::native_mint::ID {
        require!(extra.is_empty(), SplitterError::QuoteAssetNotAllowed);
        return Ok(Quote {
            native: true,
            program: token::ID,
            account_len: crate::TOKEN_ACCOUNT_LEN,
            badge: None,
            usd_band: a.native_band,
        });
    }
    let entry = extra.first().ok_or(SplitterError::QuoteAssetNotAllowed)?;
    let pair = crate::read_quote_asset(entry, &mint, a.quote_mint.owner)?;
    let q = crate::inspect_mint(a.quote_mint.owner, &a.quote_mint.try_borrow_data()?).ok_or(SplitterError::QuoteAssetNotAllowed)?;
    require!(
        !q.unsupported && !q.paused && !q.default_frozen && !q.hook_program,
        SplitterError::QuoteAssetUnavailable
    );
    let badge = if pair.badge == Pubkey::default() {
        require!(extra.len() == 1, SplitterError::QuoteAssetNotAllowed);
        None
    } else {
        require!(extra.len() == 2, SplitterError::QuoteAssetNotAllowed);
        require!(
            extra[1].key() == pair.badge && crate::is_token_badge(&extra[1], &mint),
            SplitterError::QuoteAssetUnavailable
        );
        Some(pair.badge)
    };
    // The launcher's own account for the asset, which the pool's opening draws a unit from: a
    // frozen one would fail the opening, so it is refused here, by name.
    //
    // What this cannot rule out: the asset's issuer pausing it, freezing an account, or Meteora
    // revoking its badge BETWEEN the launcher's simulation and the landing. Then the launch lands
    // and fails, its transaction is public, and so is its seed -- the launch is to be started over
    // under a new one (launch-leg-solana exits 6 for exactly that). A residual risk of pairing
    // against an asset somebody else controls, accepted.
    let held = a.payer_token_b.try_borrow_data()?;
    let launcher = crate::read_token_account_view(&held).ok_or(SplitterError::MissingQuoteAccount)?;
    require!(launcher.mint == mint && launcher.state == 1, SplitterError::QuoteAssetUnavailable);
    Ok(Quote {
        native: false,
        program: q.token_program,
        account_len: q.account_len,
        badge,
        usd_band: (pair.min_usd_per_quote, pair.max_usd_per_quote),
    })
}

/// The pool, with the whole slice in it, locked for good, its position held by the program's fee owner.
#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn open_pool<'info>(
    a: &LaunchAccounts<'_, 'info>,
    calls: &Calls<'_, 'info>,
    args: &LaunchArgs,
    nft_seeds: &[&[u8]],
    fee_owner_seeds: &[&[u8]],
    dev_buy: Option<DevBuy>,
    plan: &PoolPlan,
    finish: &Finish<'_, 'info>,
) -> Result<u128> {
    let payer = a.payer.key();
    let fee_owner = a.fee_owner.key();

    // The program's fee owner holds the position from the instruction that creates it. There is
    // no handover to get wrong, and no block in which the position belonged to a hot key.
    let mut accounts = vec![
        ro(&fee_owner),
        rw_signer(&a.position_nft_mint.key()),
        rw(&a.position_nft_account.key()),
        rw_signer(&payer),
        ro(&a.pool_authority.key()),
        rw(&a.pool.key()),
        rw(&a.position.key()),
        ro(&a.mint.key()),
        ro(&a.quote_mint.key()),
        rw(&a.token_a_vault.key()),
        rw(&a.token_b_vault.key()),
        rw(&a.token_a_account.key()),
        rw(&a.payer_token_b.key()),
        ro(&a.token_2022_program.key()),
        ro(&plan.quote.program),
        ro(&a.token_2022_program.key()),
        ro(&a.system_program.key()),
        ro(&a.cp_amm_event_authority.key()),
        ro(&CP_AMM_ID),
    ];
    // Meteora reads a token badge for each side from the accounts after its own: the first for
    // the launched token, which needs none -- a Token-2022 mint with only the metadata pointer and
    // the metadata is one Meteora accepts without (so the slot is only held) -- the second for the
    // quote asset.
    if let Some(badge) = plan.quote.badge {
        accounts.push(ro(&badge));
        accounts.push(ro(&badge));
    }
    calls.send(
        &CP_AMM_ID,
        accounts,
        cp_amm_init_pool_data(args.fee_bps, args.init_sqrt_price, plan.liquidity),
        &[nft_seeds],
    )?;

    // Lock what Meteora says is there, not what was asked for: the position's own unlocked
    // liquidity, read back. Then read it again, because the lock is the whole promise.
    let unlocked = unlocked_liquidity(a.position)?;
    require!(unlocked > 0, SplitterError::NothingToLaunch);
    calls.send(
        &CP_AMM_ID,
        vec![
            rw(&a.pool.key()),
            rw(&a.position.key()),
            ro(&a.position_nft_account.key()),
            signer(&fee_owner),
            ro(&a.cp_amm_event_authority.key()),
            ro(&CP_AMM_ID),
        ],
        cp_amm_lock_data(unlocked),
        &[fee_owner_seeds],
    )?;
    require!(unlocked_liquidity(a.position)? == 0, SplitterError::NotLocked);
    let locked = {
        let data = a.position.try_borrow_data()?;
        let (pool, locked) = read_position(&data).ok_or(SplitterError::NotThisLaunch)?;
        require!(pool == a.pool.key(), SplitterError::NotThisLaunch);
        locked
    };
    require!(locked == unlocked, SplitterError::NotLocked);

    // And the slice is IN the pool: what is left outside it is rounding, not supply. (For a
    // SUPPLY_TOTAL launch, rounding and the bridge reserve, which never was the pool's.)
    let left = left_in_slice(a)?;
    require!(left <= finish.may_remain, SplitterError::SliceNotPooled);

    // The creator's dev buy, if there is one: the first trade on the pool, made here, before the
    // instruction that opened it has ended. See `dev_buy`.
    match dev_buy {
        Some(DevBuy::FromPayment { lamports, least }) => buy_for_creator(a, calls, lamports, least, plan, finish)?,
        Some(DevBuy::FromAllowance { amount, least }) => buy_with_allowance(a, calls, amount, least, plan, finish)?,
        Some(DevBuy::FromWallet { lamports, least }) => buy_from_wallet(a, calls, lamports, least, plan, finish)?,
        Some(DevBuy::FromPayerAccount { amount, least }) => swap_through_payer(a, calls, amount, least, plan, finish)?,
        None => {}
    }

    // The account the slice came out of, with whatever the pool's rounding left in it. The payer
    // ends the launch owning none of the supply, and none of it ever reaches the platform:
    //
    //   * with a dev buy it becomes the CREATOR's, holding what they bought and that rounding;
    //   * without one, and nothing left in it, it is closed, its rent back to the payer;
    //   * without one, and something left, it is the creator's too: a few base units of rounding,
    //     theirs as everything else of the launch's own supply is the pool's;
    //   * `finish.keep_for` given: it belongs to that owner. (No launch does today; a reserve-era
    //     SUPPLY_TOTAL launch's was its bridge reserve, handed that way.)
    //
    // Whether a dev buy was made is in the launch's record (`dev_buy_made`), not in who owns this.
    let owner = match finish.keep_for {
        Some(owner) => Some(owner),
        None if dev_buy.is_none() && left_in_slice(a)? == 0 => None,
        None => Some(a.creator.key()),
    };
    match owner {
        None => token_2022::close_account(CpiContext::new(
            a.token_2022_program.clone(),
            token_2022::CloseAccount {
                account: a.token_a_account.clone(),
                destination: a.payer.clone(),
                authority: a.payer.clone(),
            },
        ))?,
        Some(owner) => token_2022::set_authority(
            CpiContext::new(
                a.token_2022_program.clone(),
                token_2022::SetAuthority {
                    current_authority: a.payer.clone(),
                    account_or_mint: a.token_a_account.clone(),
                },
            ),
            anchor_spl::token_2022::spl_token_2022::instruction::AuthorityType::AccountOwner,
            Some(owner),
        )?,
    }
    Ok(locked)
}

/// What is left in the account the slice was minted to.
fn left_in_slice(a: &LaunchAccounts<'_, '_>) -> Result<u64> {
    let data = a.token_a_account.try_borrow_data()?;
    Ok(crate::read_token_account(&data).ok_or(SplitterError::NotThisLaunch)?.1)
}

/// What this launch does with the `excess` lamports its payment holds above the fee it names. Run
/// before anything is created. It refuses nothing: whatever a payer did to their payment between
/// the launcher's simulation and the landing, the launch lands (see `dev_buy`).
///
///  * a payment that is not the creator's own carries no dev buy, and all of it is the fee
///    (`Excess::Fee`). This was `DevBuyNotTheCreators`, which no longer happens;
///  * the creator's own payment (`Excess::Creators`): `min(excess, expected_dev_buy)` of it is
///    their dev buy when all of these hold, and the rest of it goes back to them -- all of it,
///    when any does not:
///     - the launch names a dev buy at all (`LaunchArgs::expected_dev_buy` above zero): nothing
///       the creator was not quoted is ever bought;
///     - the quote asset is wrapped SOL, the only asset a payment's lamports can become by being
///       counted (`sync_native`) -- this is the client's rule too, held here as well;
///     - (v1 only, `needs_quote_account`) the creator's wrapped-SOL account, their associated one,
///       is there and is a token account, so the launch has no account to make and the
///       instructions for the buy (this was `DevBuyNeedsQuoteAccount`). A v2 launch pays fees out
///       natively and makes no such account, so it does not ask;
///     - the amount can be priced at all (`DevBuyCannotBeQuoted`);
///     - the pool can sell that much (`DevBuyMoreThanThePoolSells`): Meteora would refuse the
///       swap, and with it the launch.
///
/// The least a buy must return is what it WILL return less a tenth of a percent: the first trade
/// on a pool of the liquidity and at the price and fee this launch is about to open it with, by
/// Meteora's own arithmetic (`buy_output`), with the tolerance a final program needs against a
/// venue that is not final (`dev_buy_minimum`). A pool that pays less than that fails the swap
/// -- and the launch -- on that figure: the one way a dev buy can still fail a launch, which only
/// a change to Meteora's program can bring about.
#[inline(never)]
pub(crate) fn check_dev_buy(a: &LaunchAccounts<'_, '_>, args: &LaunchArgs, excess: u64, liquidity: u128, needs_quote_account: bool) -> Result<Excess> {
    let payer = a.fee_payer.ok_or(SplitterError::NotThisLaunch)?;
    // The creator's own payment -- or, when the creator is a tokenomics account, its owner's: the
    // account cannot pay, so its owner pays for it (`tokenomics::pays_for`), and what the payment
    // holds above the fee is the account's, to forward to them (`forward_tokenomics_refund`).
    let own = payer == a.creator.key();
    if !own && !crate::tokenomics::pays_for(a.creator, &payer, &launch_id_of(&args.launch_seed)) {
        return Ok(Excess::Fee);
    }
    let all_back = Excess::Creators { buy: 0, least: 0, back: excess };
    // v1 (`needs_quote_account`) buys for a tokenomics account out of its owner's payment. A v2
    // dev buy is bound to the creator's OWN payment (`launch_v2`'s `bound`): the owner's excess
    // goes back whole, and nothing is bought (Solana audit, factory v2 round 3, L-1).
    if !own && !needs_quote_account {
        return Ok(all_back);
    }
    let buy = excess.min(args.expected_dev_buy);
    if buy == 0 || a.quote_mint.key() != spl_token::native_mint::ID {
        return Ok(all_back);
    }
    if needs_quote_account {
        let creator_token_b = a.creator_quote()?;
        let theirs = associated_token::get_associated_token_address(&a.creator.key(), &a.quote_mint.key());
        let account_is_there = creator_token_b.key() == theirs
            && *creator_token_b.owner == token::ID
            && creator_token_b.data_len() == spl_token::state::Account::LEN;
        if !account_is_there {
            return Ok(all_back);
        }
    }
    match buy_output(liquidity, args.init_sqrt_price, args.fee_bps, buy) {
        Some(expect) if (needs_quote_account || expect.tokens > 0) && expect.sqrt_price <= CP_AMM_MAX_SQRT_PRICE => Ok(Excess::Creators {
            buy,
            least: dev_buy_minimum(expect.tokens),
            back: excess - buy,
        }),
        _ => Ok(all_back),
    }
}

/// Whether `creator` can be handed `lamports` without the transaction being refused for it.
///
/// Anything may be credited to a writable account, but the runtime refuses a transaction that
/// leaves an account holding lamports and fewer than its rent-exempt minimum -- unless it was
/// already in that state and has not grown. A wallet is either empty or above its minimum, so in
/// practice this is false for one case: a creator who has emptied their wallet entirely, owed
/// back less than 890,880 lamports. That part is settled as the fee rather than failing the
/// launch. An executable account cannot be credited at all; no creator is one, but it would be
/// the launch that failed, so it is asked.
pub(crate) fn can_take_back(creator: &AccountInfo, lamports: u64) -> Result<bool> {
    let after = creator.lamports().saturating_add(lamports);
    Ok(!creator.executable && Rent::get()?.is_exempt(after, creator.data_len()))
}

/// The dev buy: `lamports` of the creator's payment, swapped through the pool just opened, into
/// the account the slice was minted to, for at least `least` tokens (`check_dev_buy`). Six
/// instructions: the system program's transfer of nothing that carries the payment's account, the
/// token program counting the lamports, and Meteora's swap with the three calls it makes.
#[inline(never)]
fn buy_for_creator<'info>(a: &LaunchAccounts<'_, 'info>, calls: &Calls<'_, 'info>, lamports: u64, least: u64, plan: &PoolPlan, finish: &Finish<'_, 'info>) -> Result<()> {
    // The lamports, out of the payment and into the launcher's wrapped-SOL account, which is
    // what Meteora draws a swap's input from. The payment's account is this program's, so no
    // system transfer can move them: they are moved directly, and the payment's account rides
    // along in the one call that follows, so that the runtime sees both sides of the move.
    // The launcher's account is a way through and nothing else: the swap below takes out of it
    // exactly what goes into it here.
    //
    // Both sides of the move reach the runtime in a call of NOTHING: a transfer of zero lamports
    // from the launcher (a signer here already) to its own account, with the payment's account
    // riding along as a third. Without it the next call would see one side and refuse the
    // instruction as unbalanced. It used to ride along on `sync_native` itself, which mainnet's
    // token program refuses (InvalidArgument: it takes exactly the one account), and every dev buy
    // failed there (2026-10-21). The system program reads only the first two.
    let fee = a.fee.ok_or(SplitterError::NotThisLaunch)?;
    **fee.try_borrow_mut_lamports()? -= lamports;
    **a.payer_token_b.try_borrow_mut_lamports()? += lamports;
    let mut both_sides = system_instruction::transfer(&a.payer.key(), &a.payer_token_b.key(), 0);
    both_sides.accounts.push(rw(fee.key));
    invoke_signed(&both_sides, calls.all, &[])?;
    let count = spl_token::instruction::sync_native(&token::ID, &a.payer_token_b.key())?;
    invoke_signed(&count, calls.all, &[])?;
    swap_through_payer(a, calls, lamports, least, plan, finish)
}

/// A co-signed launch's dev buy: `lamports` out of the CREATOR's wallet -- a system transfer
/// their signature on the transaction authorises -- into the launcher's wrapped-SOL account,
/// counted, and swapped as `buy_for_creator` swaps. Six instructions, as that one is.
#[inline(never)]
fn buy_from_wallet<'info>(a: &LaunchAccounts<'_, 'info>, calls: &Calls<'_, 'info>, lamports: u64, least: u64, plan: &PoolPlan, finish: &Finish<'_, 'info>) -> Result<()> {
    invoke_signed(&system_instruction::transfer(&a.creator.key(), &a.payer_token_b.key(), lamports), calls.all, &[])?;
    let count = spl_token::instruction::sync_native(&token::ID, &a.payer_token_b.key())?;
    invoke_signed(&count, calls.all, &[])?;
    swap_through_payer(a, calls, lamports, least, plan, finish)
}

/// A co-signed launch hands the creator's payment excess back BEFORE the creator repays the
/// launcher, so that a creator whose lamports are in their payment, and not in their wallet, can
/// pay the launch's rent out of them. The same move `launch` makes after its last call, made one
/// call earlier: the payment's account, this program's, down by `back`; the wallet up by it.
/// Returns whether it was made (not when there is no excess, or the wallet could not hold it --
/// then the settlement below treats it as `launch` does).
fn refund_excess_first(a: &Launch<'_>, excess: Excess) -> Result<bool> {
    let (Some(fee), Excess::Creators { back, .. }) = (a.fee.as_ref(), excess) else { return Ok(false) };
    let creator = a.creator.to_account_info();
    if back == 0 || !can_take_back(&creator, back)? {
        return Ok(false);
    }
    let payment = fee.to_account_info();
    **payment.try_borrow_mut_lamports()? -= back;
    **creator.try_borrow_mut_lamports()? += back;
    Ok(true)
}

/// What a co-signed launch does with a payment's excess: the creator's goes back to them whole
/// (it buys nothing), and anybody else's is the fee -- as in `check_dev_buy`.
pub(crate) fn excess_back_to_creator(a: &LaunchAccounts<'_, '_>, excess: u64) -> Result<Excess> {
    let payer = a.fee_payer.ok_or(SplitterError::NotThisLaunch)?;
    if payer != a.creator.key() {
        return Ok(Excess::Fee);
    }
    Ok(Excess::Creators { buy: 0, least: 0, back: excess })
}

/// The most a co-signed launch's rent can come to, in lamports: what a co-signed creator's wallet
/// must hold besides a dev buy for the buy to be made. 0.05 SOL; the worst launch's is about
/// 0.039 (tests/cosigned.rs measures it against this).
pub const COSIGNED_LAUNCH_RENT_BOUND: u64 = 50_000_000;

/// A co-signed launch's dev buy, against wrapped SOL: `expected_dev_buy` lamports of the
/// creator's wallet, when that is more than nothing, the wallet holds it and the launch's rent
/// (`COSIGNED_LAUNCH_RENT_BOUND`) and a wallet's rent-exempt minimum besides, and the pool can
/// sell it; otherwise none, and the launch goes on without it.
pub(crate) fn check_wallet_dev_buy(a: &LaunchAccounts<'_, '_>, args: &LaunchArgs, liquidity: u128) -> Option<DevBuy> {
    let lamports = args.expected_dev_buy;
    let needed = Rent::get()
        .ok()
        .map(|rent| rent.minimum_balance(0))
        .and_then(|least| lamports.checked_add(COSIGNED_LAUNCH_RENT_BOUND)?.checked_add(least));
    if lamports == 0 || needed.is_none_or(|needed| a.creator.lamports() < needed) {
        return None;
    }
    match buy_output(liquidity, args.init_sqrt_price, args.fee_bps, lamports) {
        // A buy too small to come to a single token's base unit is no buy: Meteora would refuse it.
        Some(expect) if expect.tokens > 0 && expect.sqrt_price <= CP_AMM_MAX_SQRT_PRICE => Some(DevBuy::FromWallet {
            lamports,
            least: dev_buy_minimum(expect.tokens),
        }),
        _ => None,
    }
}

/// The swap of a dev buy out of the payer's own quote account, which holds the buy's amount: the
/// payer signs for its own account, as it already has for the transaction; the tokens go
/// straight to `finish.buy_into`. A wrapped-SOL buy has the lamports counted into the account
/// first (`buy_for_creator`, `buy_from_wallet`); a self-launch against an asset buys with what
/// the creator's own account holds (`DevBuy::FromPayerAccount`).
#[inline(never)]
fn swap_through_payer<'info>(a: &LaunchAccounts<'_, 'info>, calls: &Calls<'_, 'info>, amount: u64, least: u64, plan: &PoolPlan, finish: &Finish<'_, 'info>) -> Result<()> {
    calls.send(
        &CP_AMM_ID,
        vec![
            ro(&a.pool_authority.key()),
            rw(&a.pool.key()),
            rw(&a.payer_token_b.key()),
            rw(&finish.buy_into.key()),
            rw(&a.token_a_vault.key()),
            rw(&a.token_b_vault.key()),
            ro(&a.mint.key()),
            ro(&a.quote_mint.key()),
            signer(&a.payer.key()),
            ro(&a.token_2022_program.key()),
            ro(&plan.quote.program),
            ro(&CP_AMM_ID), // no referral: the slot holds the program's own id
            ro(&a.cp_amm_event_authority.key()),
            ro(&CP_AMM_ID),
        ],
        cp_amm_swap_data(amount, least),
        &[],
    )
}

/// A creator's dev buy, as the launch will make it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevBuy {
    /// Wrapped SOL: `lamports` of the creator's payment, counted into the launcher's wrapped-SOL
    /// account and swapped, for at least `least` tokens.
    FromPayment { lamports: u64, least: u64 },
    /// An allowlisted asset: `amount` of it swapped straight out of the creator's own account, by
    /// this program as the delegate they approved, for at least `least` tokens.
    FromAllowance { amount: u64, least: u64 },
    /// A co-signed launch: `lamports` out of the creator's own wallet, counted into the
    /// launcher's wrapped-SOL account and swapped, for at least `least` tokens.
    FromWallet { lamports: u64, least: u64 },
    /// A self-launch against an asset: `amount` of what the creator's own account for the asset
    /// holds -- the payer's quote account, since the creator is the payer -- swapped with the
    /// creator's own signature, for at least `least` tokens.
    FromPayerAccount { amount: u64, least: u64 },
}

/// The dev buy a launch against an allowlisted asset makes: out of the creator's own account for
/// the asset -- their associated one, which is the launch's `creator_token_b` already -- spent by
/// this program's AUTHORITY, which the creator approved as that account's delegate in the same
/// transaction that paid their fee and bought the asset (with SOL, through any route they like).
///
/// It spends `min(expected_dev_buy, what they approved, what the account holds)`, and makes the
/// buy only when all of these hold; otherwise it makes none, refuses nothing, and the asset stays
/// where it is, in the creator's own account:
///
///   * the launch was handed the creator's OWN payment for this launch -- that payment is what
///     says this launch is the one the approval was for (an approval is to AUTHORITY, which every
///     launch shares; nothing else could tell one launch's from another's), and nobody's but the
///     creator's money is ever spent;
///   * a dev buy was quoted (`expected_dev_buy` above zero);
///   * the account is the creator's associated account for the asset, of its program, holding the
///     asset, not frozen, with AUTHORITY as its delegate for a non-zero amount, and a balance;
///   * the amount can be priced and the pool can sell it.
///
/// No revoke follows. What the buy spends is taken from the allowance; what is left of it (when
/// the account held less than was approved, or the quote was smaller) stays approved to AUTHORITY,
/// which signs a transfer out of a creator's account only here, only in a launch the creator has
/// paid their own fee for, and only into that launch's pool for them. A revoke would be one more
/// instruction in a transaction with two to spare, to undo something that can only ever be spent
/// on the same creator's own dev buy. The creator may revoke it at any time; the web's next
/// approval replaces it.
#[inline(never)]
///
/// `bound_by_payment`: v1's rule above. A v2 launch (`launch_v2`) does not ask for the payment:
/// the fee may be paid on another chain, and the payment cost an asset launch the bytes it does not
/// have. What the binding guarded against is a LISTED launcher -- our own key, the only one that
/// can send `launch_v2` -- spending a creator's approval in another launch naming the same
/// creator, into that creator's own account: an own-key risk, accepted.
pub(crate) fn check_asset_dev_buy(a: &LaunchAccounts<'_, '_>, args: &LaunchArgs, quote: &Quote, liquidity: u128, bound_by_payment: bool) -> Result<Option<DevBuy>> {
    let Some(creator_token_b) = a.creator_token_b else { return Ok(None) };
    let creator = a.creator.key();
    if bound_by_payment && a.fee_payer != Some(creator) {
        return Ok(None);
    }
    if args.expected_dev_buy == 0 {
        return Ok(None);
    }
    let mint = a.quote_mint.key();
    let theirs = associated_token::get_associated_token_address_with_program_id(&creator, &mint, &quote.program);
    if creator_token_b.key() != theirs || *creator_token_b.owner != quote.program {
        return Ok(None);
    }
    let Some(account) = crate::read_token_account_view(&creator_token_b.try_borrow_data()?) else {
        return Ok(None);
    };
    if account.mint != mint || account.owner != creator || account.state != 1 || account.delegate != Some(a.authority.key()) {
        return Ok(None);
    }
    let amount = args.expected_dev_buy.min(account.delegated_amount).min(account.amount);
    if amount == 0 {
        return Ok(None);
    }
    Ok(match buy_output(liquidity, args.init_sqrt_price, args.fee_bps, amount) {
        Some(expect) if expect.sqrt_price <= CP_AMM_MAX_SQRT_PRICE => Some(DevBuy::FromAllowance {
            amount,
            least: dev_buy_minimum(expect.tokens),
        }),
        _ => None,
    })
}

/// The dev buy in an allowlisted asset: `amount` of it, out of the creator's own account, swapped
/// through the pool just opened into the account the slice was minted to, for at least `least`
/// tokens. AUTHORITY signs as the account's delegate. Four instructions: Meteora's swap and the
/// three calls it makes -- one fewer than the wrapped-SOL buy, which has the lamports counted first.
#[inline(never)]
fn buy_with_allowance<'info>(a: &LaunchAccounts<'_, 'info>, calls: &Calls<'_, 'info>, amount: u64, least: u64, plan: &PoolPlan, finish: &Finish<'_, 'info>) -> Result<()> {
    let authority_seeds: &[&[u8]] = &[AUTHORITY_SEED, &[plan.authority_bump]];
    let creator_token_b = a.creator_quote()?;
    calls.send(
        &CP_AMM_ID,
        vec![
            ro(&a.pool_authority.key()),
            rw(&a.pool.key()),
            rw(&creator_token_b.key()),
            rw(&finish.buy_into.key()),
            rw(&a.token_a_vault.key()),
            rw(&a.token_b_vault.key()),
            ro(&a.mint.key()),
            ro(&a.quote_mint.key()),
            signer(&a.authority.key()),
            ro(&a.token_2022_program.key()),
            ro(&plan.quote.program),
            ro(&CP_AMM_ID), // no referral: the slot holds the program's own id
            ro(&a.cp_amm_event_authority.key()),
            ro(&CP_AMM_ID),
        ],
        cp_amm_swap_data(amount, least),
        &[authority_seeds],
    )
}

/// A Meteora position's unlocked liquidity: the part that could still be withdrawn.
fn unlocked_liquidity(position: &AccountInfo) -> Result<u128> {
    const AT: usize = 152;
    require_keys_eq!(*position.owner, CP_AMM_ID, SplitterError::NotThisLaunch);
    let data = position.try_borrow_data()?;
    let bytes: [u8; 16] = data
        .get(AT..AT + 16)
        .and_then(|b| b.try_into().ok())
        .ok_or(SplitterError::NotThisLaunch)?;
    Ok(u128::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn key(hex32: &str) -> Pubkey {
        let bytes: Vec<u8> = (0..64).step_by(2).map(|i| u8::from_str_radix(&hex32[i..i + 2], 16).unwrap()).collect();
        Pubkey::new_from_array(bytes.try_into().unwrap())
    }

    /* Each expected value below is what that program's own SDK builds for the same inputs --
       Meteora's `createCustomPool`, LayerZero's `oft.initOft` / `setPeerConfig` / `setOFTConfig`
       and Metaplex's `createCreateMetadataAccountV3Instruction` -- captured from the client's
       dependencies. They are what makes "the program builds the call itself" safe: a byte out of
       place here would not fail, it would open a pool with a different fee or hand a store to a
       different admin, and tests/launch.rs would have to notice by reading the result back.     */

    #[test]
    fn the_pool_is_opened_with_the_bytes_meteoras_sdk_sends() {
        // 1% fee, the opening price and liquidity the SDK derives for 200M tokens at 9 decimals.
        assert_eq!(
            hex(&cp_amm_init_pool_data(100, 2_259_255_519_814_896, 451_851_103_962_992_085_144_048_000_364_863)),
            [
                "14a1f118bdddb402",                             // the instruction
                "8096980000000000",                             // 10,000,000 / 1e9: the 1% fee
                "00000000000000000000000000000000000000000000", // no schedule: 22 bytes of nothing
                "00",                                           // no dynamic fee
                "f024b7eac70608000000000000000000",             // the bottom of the range
                "9b57694ea91a5c84b1c4feff00000000",             // the top of it
                "00",                                           // no alpha vault
                "3ff18c7788591f7a78f5a82947160000",             // the liquidity
                "f024b7eac70608000000000000000000",             // the opening price
                "01",                                           // activation by timestamp
                "01",                                           // fees in the quote asset only
                "00",                                           // tradeable at once
            ]
            .concat()
        );
        assert_eq!(cp_amm_init_pool_data(100, 1, 1).len(), 107);
    }

    #[test]
    fn the_fee_is_a_numerator_over_a_billion() {
        // 30 bps is 0.3%, which Meteora writes as 3,000,000 / 1e9. A factor of ten here is a
        // pool charging 3% or 0.03% from its first trade, until Meteora's operator changes it.
        for (bps, numerator) in [(30u16, 3_000_000u64), (100, 10_000_000), (500, 50_000_000)] {
            let data = cp_amm_init_pool_data(bps, 1, 1);
            assert_eq!(u64::from_le_bytes(data[8..16].try_into().unwrap()), numerator);
        }
    }

    #[test]
    fn the_position_is_locked_with_the_bytes_meteoras_sdk_sends() {
        assert_eq!(
            hex(&cp_amm_lock_data(451_851_103_962_992_085_144_048_000_364_863)),
            "a5b07d06e7abbad53ff18c7788591f7a78f5a82947160000"
        );
    }

    #[test]
    fn the_store_is_created_with_the_bytes_layerzeros_sdk_sends() {
        let admin = key("3cda8147423c834b9f31f40b0c4bd95e1f25f1dab84bafefe4404e8c281c44cb");
        assert_eq!(
            hex(&oft_init_data(&admin)),
            // discriminator, Native, the admin, 6 shared decimals, Some(endpoint)
            format!(
                "b6a99310c92d4c17003cda8147423c834b9f31f40b0c4bd95e1f25f1dab84bafefe4404e8c281c44cb0601{}",
                hex(LZ_ENDPOINT_ID.as_ref())
            )
        );
        // And the endpoint those last 32 bytes name is the one the SDK was given.
        assert_eq!(
            hex(LZ_ENDPOINT_ID.as_ref()),
            "5aad76da514b6e1dcf11037e904dac3d375f525c9fbafcb19507b78907d8c18b"
        );
    }

    #[test]
    fn a_peer_is_set_with_the_bytes_layerzeros_sdk_sends() {
        assert_eq!(
            hex(&oft_set_peer_data(30101, &[0xab; 20])),
            "4fbba8398b8c5d2f9575000000000000000000000000000000abababababababababababababababababababab"
        );
    }

    /// The store is created with `AUTHORITY` as its admin, which `init_oft` also registers as
    /// the endpoint delegate: the bytes name that address and no key.
    #[test]
    #[cfg(not(feature = "test-stack"))] // pinned to the live program id
    fn the_store_is_created_for_the_address_only_this_program_signs_for() {
        let authority = Pubkey::find_program_address(&[AUTHORITY_SEED], &crate::ID).0;
        assert_eq!(authority.to_string(), "46orND2UWkrM1tDAVwUGTGJf96GerymaP4wVJXbir9Zo");
        let data = oft_init_data(&authority);
        assert_eq!(&data[9..41], authority.as_ref(), "the admin, after the discriminator and the kind");
        assert_eq!(data[8], 0, "Native: it burns and mints, and its escrow holds fees and nothing else");
    }

    /// `oft.instructions.getSetOftConfigInstructionDataSerializer().serialize({ params:
    /// { __kind: "DefaultFee", fields: [20] } })` from `@layerzerolabs/oft-v2-solana-sdk`
    /// 3.0.168; solana/client/bridge.test.mjs asks the SDK again and pins the same bytes.
    #[test]
    fn the_bridge_fee_is_set_with_the_bytes_layerzeros_sdk_sends() {
        assert_eq!(hex(&oft_set_default_fee_data(BRIDGE_FEE_BPS)), "377e57d99f4218c2021400");
        assert_eq!(hex(&oft_set_default_fee_data(0)), "377e57d99f4218c2020000");
        assert_eq!(BRIDGE_FEE_BPS, 20, "0.2%, as on the four EVM chains");
        assert_eq!(BRIDGE_FEE_BPS as u128, crate::PLATFORM_FEE_BPS, "and as the platform's cut of trading volume");
    }

    /// The three Token-2022 calls that make the metadata, against Token-2022's own instruction
    /// builders: the pointer (no authority, at the mint), the metadata, and its authority dropped.
    #[test]
    fn the_metadata_is_written_with_the_bytes_token_2022s_own_builders_make() {
        use anchor_spl::token_2022::spl_token_2022;
        use anchor_spl::token_2022_extensions::spl_token_metadata_interface as meta;
        let mint = key("a7aabf10511a81c183fbe46aa067087d6f447fe65c8964e1722960ea600a298d");
        let theirs = spl_token_2022::extension::metadata_pointer::instruction::initialize(&spl_token_2022::ID, &mint, None, Some(mint)).unwrap();
        assert_eq!(hex(&metadata_pointer_init_data(&mint)), hex(&theirs.data));
        let theirs = meta::instruction::initialize(&spl_token_2022::ID, &mint, &mint, &mint, &mint, "NAME".into(), "SYM".into(), "ipfs://x".into());
        assert_eq!(hex(&token_metadata_init_data("NAME", "SYM", "ipfs://x")), hex(&theirs.data));
        let none: anchor_spl::token_2022_extensions::spl_pod::optional_keys::OptionalNonZeroPubkey = None.try_into().unwrap();
        let theirs = meta::instruction::update_authority(&spl_token_2022::ID, &mint, &mint, none);
        assert_eq!(hex(&token_metadata_drop_authority_data()), hex(&theirs.data));
        // The size: what Token-2022 computes for a mint with the pointer, and the metadata after it.
        let pointer = spl_token_2022::extension::ExtensionType::try_calculate_account_len::<spl_token_2022::state::Mint>(&[
            spl_token_2022::extension::ExtensionType::MetadataPointer,
        ])
        .unwrap();
        assert_eq!(pointer, MINT_WITH_POINTER_LEN);
        let metadata = meta::state::TokenMetadata {
            update_authority: none,
            mint,
            name: "a".repeat(32),
            symbol: "b".repeat(10),
            uri: "c".repeat(66),
            additional_metadata: vec![],
        };
        // `tlv_size_of` counts the generic TLV header (an 8-byte discriminator and a 4-byte length);
        // Token-2022 stores an extension behind its own 4 bytes (a 2-byte type and a 2-byte length).
        assert_eq!(mint_len_with_metadata(&metadata.name, &metadata.symbol, &metadata.uri), pointer + 4 + metadata.tlv_size_of().unwrap() - 12);
        assert_eq!(mint_len_with_metadata(&metadata.name, &metadata.symbol, &metadata.uri), 426, "the longest name, symbol and CIDv1 URI");
    }

    fn good() -> LaunchArgs {
        LaunchArgs {
            launch_seed: [1; 32],
            mint_nonce: 0,
            name: "Name".into(),
            symbol: "SYM".into(),
            uri_form: CID_V1_DAG_PB,
            uri_digest: [7; 32],
            fee_bps: 100,
            slice: 1,
            init_sqrt_price: 1,
            launch_fee: 0,
            expected_dev_buy: 0,
            peers: four_peers(),
            price: crate::price::SignedPrice { deadline: 0x2122_2324_2526_2728, usd_per_quote: vec![1, 2, 3, 4, 5], signature: [0x55; 65] },
        }
    }

    /// Four chains, each with a token of its own: 0x11..11 on 30101, 0x22..22 on 30102, and so on.
    fn four_peers() -> Peers {
        Peers(vec![(30101, [0x11; 20]), (30102, [0x22; 20]), (30184, [0x33; 20]), (30416, [0x44; 20])])
    }

    /// The peers on the wire: a one-byte mask over `PEER_CHAINS`, then twenty bytes a token, in
    /// the list's order -- 81 bytes for the four mainnet chains. solana/client/launch-leg.mjs
    /// writes the same 81 and its tests pin them.
    #[test]
    fn the_peers_are_packed_as_a_mask_then_a_token_each() {
        assert_eq!(PEER_CHAINS, &[30101, 30102, 30184, 30416], "bit 0 Ethereum, 1 BNB Chain, 2 Base, 3 Robinhood");
        let bytes = |p: &Peers| {
            let mut out = Vec::new();
            p.serialize(&mut out).unwrap();
            out
        };
        let four = four_peers();
        let want = format!("0f{}{}{}{}", "11".repeat(20), "22".repeat(20), "33".repeat(20), "44".repeat(20));
        assert_eq!(hex(&bytes(&four)), want);
        assert_eq!(bytes(&four).len(), 81);
        assert_eq!(hex(&bytes(&Peers(vec![]))), "00");
        assert_eq!(hex(&bytes(&Peers(vec![(30184, [0xab; 20])]))), format!("04{}", "ab".repeat(20)));
        assert_eq!(hex(&bytes(&Peers(vec![(30101, [1; 20]), (30416, [2; 20])]))), format!("09{}{}", "01".repeat(20), "02".repeat(20)));
        // And back, exactly; with what follows left for whoever reads next. Every mask the list
        // allows.
        for mask in 0u8..16 {
            let p = Peers(PEER_CHAINS.iter().enumerate().filter(|(i, _)| mask & (1 << i) != 0).map(|(i, e)| (*e, [i as u8 + 1; 20])).collect());
            let mut encoded = bytes(&p);
            assert_eq!(encoded[0], mask);
            encoded.extend_from_slice(&[0xaa, 0xbb]);
            let mut rest = encoded.as_slice();
            assert_eq!(Peers::deserialize(&mut rest).unwrap(), p);
            assert_eq!(rest, &[0xaa, 0xbb]);
        }
        assert_eq!(four.eids().collect::<Vec<u32>>(), vec![30101, 30102, 30184, 30416]);
        assert_eq!(four.pairs()[2], (30184, [0x33; 20]));
        // A bit past the list names no chain: refused, whatever follows.
        for mask in [0x10u8, 0x1f, 0x80, 0xff] {
            let mut encoded = vec![mask];
            encoded.extend_from_slice(&[0x11; 20 * 8]);
            assert!(Peers::deserialize(&mut encoded.as_slice()).is_err(), "{mask:#x}");
        }
        // A mask the bytes do not bear out is an error, not a shorter list.
        for short in [&[][..], &[1][..], &[3, 0x11][..], &[0x0f; 61][..]] {
            let mut rest = short;
            assert!(Peers::deserialize(&mut rest).is_err(), "{short:?}");
        }
        // What the mask cannot say cannot be written: a chain not on the list, one twice, or out
        // of order.
        for p in [Peers(vec![(30110, [1; 20])]), Peers(vec![(30101, [1; 20]), (30101, [2; 20])]), Peers(vec![(30184, [1; 20]), (30101, [2; 20])])] {
            assert!(p.serialize(&mut Vec::new()).is_err(), "{p:?}");
        }
        // The whole of a launch's arguments with it: the fee, the dev buy it was quoted, the peers,
        // then the signed price -- its deadline, a four-byte count and TWELVE bytes a leg, and the
        // 65-byte signature. The opening price is not on the wire at all.
        let mut whole = Vec::new();
        LaunchArgs { launch_fee: 0x0102_0304_0506_0708, expected_dev_buy: 0x1112_1314_1516_1718, init_sqrt_price: 99, ..good() }.serialize(&mut whole).unwrap();
        let price_len = 8 + 4 + 12 * 5 + 65;
        let end = whole.len() - price_len;
        assert_eq!(hex(&whole[end - 97..end]), format!("0807060504030201 1817161514131211 {}", want).replace(' ', ""));
        assert_eq!(hex(&whole[end..end + 12]), "2827262524232221 05000000".replace(' ', ""));
        assert_eq!(hex(&whole[end + 12..end + 24]), "010000000000000000000000");
        assert_eq!(&whole[whole.len() - 65..], &[0x55; 65][..]);
        let decoded = LaunchArgs::deserialize(&mut whole.as_slice()).unwrap();
        assert_eq!((decoded.launch_fee, decoded.expected_dev_buy, decoded.peers), (0x0102_0304_0506_0708, 0x1112_1314_1516_1718, four));
        assert_eq!(decoded.price, good().price);
        assert_eq!(decoded.init_sqrt_price, 0, "computed by the program, never sent");
    }

    #[test]
    fn a_launchs_arguments_are_checked_before_anything_is_created() {
        assert!(check_launch_args(&good()).is_ok());
        let bad = |f: fn(&mut LaunchArgs)| {
            let mut a = good();
            f(&mut a);
            check_launch_args(&a).is_err()
        };
        assert!(bad(|a| a.fee_bps = 29));
        assert!(bad(|a| a.fee_bps = 501));
        assert!(bad(|a| a.name.clear()));
        assert!(bad(|a| a.name = "N".repeat(MAX_NAME_LEN + 1)));
        assert!(bad(|a| a.symbol = "S".repeat(MAX_SYMBOL_LEN + 1)));
        // A form of identifier the program does not know how to write out.
        assert!(bad(|a| a.uri_form = 0x71));
        assert!(bad(|a| a.uri_form = 1));
        assert!(bad(|a| a.slice = 0));
        // A slice and a price whose liquidity does not fit 128 bits, as Meteora would refuse it.
        assert!(bad(|a| {
            a.slice = u64::MAX;
            a.init_sqrt_price = CP_AMM_MAX_SQRT_PRICE - 1;
        }));
        assert!(bad(|a| a.init_sqrt_price = 0));
        assert!(bad(|a| a.init_sqrt_price = CP_AMM_MAX_SQRT_PRICE));
        // Any chain's token zero.
        assert!(bad(|a| a.peers.0[0].1 = [0; 20]));
        assert!(bad(|a| a.peers.0[3].1 = [0; 20]));
        // A chain listed twice, chains out of order, a chain not on the list, and none at all.
        assert!(bad(|a| a.peers = Peers(vec![(30101, [1; 20]), (30101, [2; 20])])));
        assert!(bad(|a| a.peers = Peers(vec![(30184, [1; 20]), (30101, [2; 20])])));
        assert!(bad(|a| a.peers = Peers(vec![(30110, [1; 20])])));
        assert!(bad(|a| a.peers = Peers(vec![])));
        // One chain alone is a launch.
        let mut one = good();
        one.peers = Peers(vec![(30184, [1; 20])]);
        one.price.usd_per_quote.truncate(2);
        assert!(check_launch_args(&one).is_ok());
        // The lengths Metaplex allows are themselves allowed.
        let mut a = good();
        a.name = "N".repeat(MAX_NAME_LEN);
        a.symbol = "S".repeat(MAX_SYMBOL_LEN);
        assert!(check_launch_args(&a).is_ok());
        for form in [CID_V0, CID_V1_RAW, CID_V1_DAG_PB] {
            a.uri_form = form;
            assert!(check_launch_args(&a).is_ok());
        }
    }

    /// The URI the program writes is the URI IPFS itself would give that content -- pinned on the
    /// example from IPFS's own documentation, where one hash is shown in both its forms. The
    /// client derives the hash from the URI the EVM chains store, so if this agrees with IPFS the
    /// two sides of a launch name the same document with the same string.
    #[test]
    fn the_uri_written_out_is_the_one_ipfs_gives_that_content() {
        let digest: [u8; 32] = key("c3c4733ec8affd06cf9e9ff50ffc6bcd2ec85a6170004bb709669c31de94391a").to_bytes();
        assert_eq!(
            ipfs_uri(CID_V0, &digest).unwrap(),
            "ipfs://QmbWqxBEKC3P8tqsKc98xmWNzrzDtRLMiMPL8wBuTGsMnR"
        );
        assert_eq!(
            ipfs_uri(CID_V1_DAG_PB, &digest).unwrap(),
            "ipfs://bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
        );
        assert_eq!(
            ipfs_uri(CID_V1_RAW, &digest).unwrap(),
            "ipfs://bafkreigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
        );
        assert!(ipfs_uri(0x71, &digest).is_err());
        // Every URI this can produce is inside what Metaplex accepts, with room to spare.
        assert!(ipfs_uri(CID_V1_DAG_PB, &[0xff; 32]).unwrap().len() <= 200);
        assert_eq!(ipfs_uri(CID_V0, &[0; 32]).unwrap().len(), 7 + 46);
    }

    #[test]
    fn every_launch_address_has_its_own_seed() {
        let id = [9u8; 32];
        let at = |seed: &[u8]| Pubkey::find_program_address(&[seed, &id], &crate::ID).0;
        let mint = crate::mint_address(&id, 0).0;
        let all = [mint, at(MINT_SEED), at(ESCROW_SEED), at(POSITION_SEED), at(TOKEN_A_SEED)];
        for i in 0..all.len() {
            for j in i + 1..all.len() {
                assert_ne!(all[i], all[j]);
            }
        }
    }
}
