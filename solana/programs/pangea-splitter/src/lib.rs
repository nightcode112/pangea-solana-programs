//! # Pangea fee splitter (Solana)
//!
//! The Solana counterpart of `FeeSplitter.sol`: it holds every launch's Meteora DAMM v2 position,
//! claims the trading fees each position accrues, and divides them between that launch's creator
//! and the platform: the platform takes a fifth of the pool's fee, and never less than 0.2% of
//! volume; the creator takes the rest of what the position earns. See `platform_share` and `fees`.
//!
//! ## What this program deliberately does not do
//!
//! It does not lock the liquidity, because Meteora already does and does it better than we could.
//! `permanent_lock_position` moves liquidity out of `Position::unlocked_liquidity` into
//! `permanent_locked_liquidity`, and `remove_liquidity` refuses any withdrawal exceeding
//! `unlocked_liquidity`. Once locked, no instruction in cp-amm can return that liquidity to
//! anyone -- not the position owner, not a delegate, not Meteora. Re-implementing that here would
//! add a second thing to trust for no gain, so this program has no liquidity instructions at all.
//!
//! `launch` (see `launch_leg`) asks Meteora to open the pool and to lock the position, and this program's fee owner holds the position NFT from the
//! instant it exists. The trust-critical part is not who opened the pool -- that is public and
//! verifiable afterwards -- it is who can move the money afterwards, which is what this file
//! governs.
//!
//! ## Why the program holds the position NFT
//!
//! cp-amm's `claim_position_fee` lets the signer be either the NFT owner or an SPL delegate
//! holding the right permission bit, and it pays the claim into whichever token accounts that
//! signer names: cp-amm does not care whose they are. Whoever holds the NFT therefore controls
//! where a perpetual fee stream lands. Every launch's NFT is held by one PDA of this program, the
//! fee owner (`fees::FEES_SEED`), whose only spending instruction is `claim_fees` -- so the
//! destination is fixed by THIS program's code, not cp-amm's: a claim lands in the program's own
//! account for the quote asset and is paid out, in the same instruction, to the launch's recorded
//! creator and the platform. So the fees can go to those two in the agreed proportion, and
//! nowhere else, no matter who sends the transaction.
//!
//! `claim_fees` is permissionless for the same reason `release()` is on EVM. The only two
//! destinations are recorded, so letting anyone pay the gas to trigger a payout costs nothing and
//! means the creator never waits on the platform to press a button.
//!
//! ## The two things it does besides splitting
//!
//! Both arrived with the launch itself moving on chain, and both are here rather than in a second
//! program because they answer to the same admin and are part of the same launch.
//!
//! **It launches.** The mint, its metadata, its bridge, its pool and this fee split are made by
//! one instruction, `launch`, for a launcher the admin has listed, at addresses derived from a
//! seed that is secret until that instruction lands. See `launch_leg`, `MINT_SEED` and
//! `LAUNCHER_SEED`. The routes of the bridge are opened afterwards; see `bridge`.
//!
//! **It holds a creator's launch fee until their launch exists.** The Solana counterpart of
//! `LaunchFeeCollector.sol`, with the same promises: a payment is its payer's until the launch is
//! real, the admin can refund it and cannot take it, and after seven days the payer can take it
//! back without anyone's help. Exactly one thing releases it: `launch`, which settles the payment
//! it is handed in the same instruction that creates the token -- so the fee and the launch
//! succeed or fail together, and there is no other instruction that can mark a payment settled.
//! See `FEE_SEED`.
//!
//! ## The 0.3% floor is not arbitrary
//!
//! Meteora keeps 20% of every trading fee as protocol revenue, so only 80% ever reaches the
//! position. At a 0.2% pool fee that is 0.16% of volume arriving -- less than the 0.2% the
//! platform is owed, which would make the rule unsatisfiable on this chain alone. Hence a 0.3%
//! floor across all five chains, and hence `venue_lp_share_bps`: the share is a share of
//! *volume*, but what arrives is a share of the *fee*, and on Meteora those differ by a fifth.
//! Computing the platform's cut from the arrived amount alone would underpay it by exactly
//! Meteora's skim, silently, forever.
//!
//! ## And a third thing: the creator's first buy
//!
//! A creator who pays the launch fee here may pay more than the fee, and `launch` swaps the
//! excess for the new token through the pool it has just opened, in the same instruction. See
//! `dev_buy`.

use anchor_lang::prelude::*;
use anchor_lang::system_program::{transfer, Transfer};

pub mod bridge;
pub mod dev_buy;
pub mod fees;
pub mod launch_leg;
pub mod launch_v2;
pub mod price;
pub mod quote;
pub mod reserve;
pub mod tokenomics;
pub mod tokenomics_v2;
pub mod venue; #[cfg(any(feature = "rehearsal-admin", test))] pub mod rehearsal_admin; #[cfg(all(feature = "rehearsal-admin", feature = "test-stack"))] compile_error!("rehearsal-admin and test-stack are two different admins: build with one");
pub use bridge::*;
pub use dev_buy::*;
pub use fees::*;
pub use launch_leg::*;
pub use launch_v2::*;
pub use price::*;
pub use quote::*;
pub use reserve::*;
pub use tokenomics::*;
pub use tokenomics_v2::*;

// The build keypair in target/deploy. A mainnet deploy must replace this with a deliberately
// generated keypair held outside the repo, and re-sync this constant -- Anchor derives every PDA
// from it, so a mismatch between the declared id and the deployed keypair makes the program
// unusable rather than merely misnamed.
#[cfg(not(feature = "test-stack"))] declare_id!("Hb5uTppRbNxc3RjVRqTWqfdU3E3GiZyGYKccxYf9tUej"); #[cfg(feature = "test-stack")] include!("test_stack.rs"); // test stack: src/test_stack.rs

/// Meteora DAMM v2 (cp-amm).
pub const CP_AMM_ID: Pubkey = pubkey!("cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG");

/// Anchor discriminator for cp-amm's `claim_position_fee`, i.e. the first eight bytes of
/// sha256("global:claim_position_fee").
pub const CLAIM_POSITION_FEE_DISCRIMINATOR: [u8; 8] = [180, 38, 154, 17, 133, 33, 162, 211];

pub const BPS: u128 = 10_000;

/// The least the platform takes of volume: 0.2%, on every launch, forever.
pub const PLATFORM_FEE_BPS: u128 = 20;

/// The platform's share of the pool's whole fee, when that is more than the floor: a fifth.
///
/// Of the fee the POOL charges, before the venue takes its own cut -- not of what reaches the
/// position. At a 2% fee that is 0.4% of volume; Meteora keeps another 0.4%; the creator has 1.2%.
pub const PLATFORM_SHARE_OF_FEE_BPS: u128 = 2_000;

/// The bounds a launch fee may sit between. Identical to the EVM contracts.
pub const MIN_FEE_BPS: u16 = 30; // 0.3%
pub const MAX_FEE_BPS: u16 = 500; // 5%

/// Meteora DAMM v2 passes 80% of the trading fee to the position and keeps 20%.
pub const METEORA_LP_SHARE_BPS: u16 = 8_000;

pub const SPLITTER_SEED: &[u8] = b"splitter";

/// The mint's seed. `PDA([b"mint", launch_seed, mint_nonce], this program)` is the token on
/// Solana, where `mint_nonce` is four little-endian bytes chosen so that the address ends in
/// `6ea` (`MINT_ENDING`). See `has_pangea_ending`.
///
/// ## A launch has a seed, and its id is the seed's hash
///
/// Every address a launch creates here -- this mint, the OFT escrow and through it the store,
/// the position's NFT, the account the slice is minted into, the launch's record, and so the pool
/// and the vaults that Meteora derives from those -- is a function of 32 bytes called the launch
/// SEED. The launch ID, the public name the EVM chains sign their price snapshot over and a
/// creator pays a fee against, is `launch_id_of(seed)`: its hash.
///
/// The seed is secret until the launch transaction lands, and that is the point. These addresses
/// used to derive from the launch id, which is public from the moment a fee payment names it --
/// and anyone can send lamports to an address. An address that already holds lamports costs two
/// more instructions to create than an empty one, a launch ran 58 of the 64 a transaction may
/// (it runs 56 now), and so about 0.004 SOL sent to four of a launch's addresses made that launch impossible, for
/// good, since nothing can take lamports back out of another program's address. Nobody can send
/// anything to an address they cannot compute. The moment the launch lands the seed is in its
/// transaction for all to read, and by then every one of those accounts exists.
///
/// What is NOT derived from the seed is anything that has to be reachable beforehand: a fee
/// payment, which is keyed by the public id (`FEE_SEED`), and the creator's own quote account,
/// which `launch` therefore tolerates finding pre-funded.
///
/// ## Why the mint is derived and not a keypair
///
/// It used to be `Keypair.generate()`. Deriving it buys three things a random keypair cannot:
///
///   * **The snapshot names the token.** The EVM chains seal the OFT store as their Solana peer,
///     and the store, like this mint, is a function of the seed -- so one launch has one store and
///     one mint, and checking that a mint belongs to a launch is arithmetic.
///   * **One mint per launch, enforced by the runtime.** A second launch of the same seed fails
///     because the account exists.
///   * **The mint stops being a transaction signer**, which is 96 bytes: a 32-byte key out of the
///     static keys and a 64-byte signature. A mint's keypair signs exactly once, for the account's
///     creation, and never again -- so replacing it with a PDA's seeds removes a secret that had
///     to exist for one instruction, and is part of what lets a launch be one transaction.
pub const MINT_SEED: &[u8] = b"mint";

/// What every Pangea mint's address ends in, written in base58 (and so case-sensitive).
///
/// THE ONE DEFINITION of the ending on Solana: the modulus and the remainder `has_pangea_ending`
/// compares against are computed from this text, at compile time, and nothing else in the program
/// names the ending. (The EVM tokens end in the same three characters read as hex digits; the
/// search tool and the clients each hold the text once and are tested against this line.)
pub const MINT_ENDING: &str = "6ea";

/// Base58's digits, in order: `1` is zero and `z` is fifty-seven.
const BASE58_DIGITS: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// 58^(the ending's length): 58^3 = 195,112. An address's last characters are its number's
/// lowest base-58 digits, so the ending is a statement about the remainder by this.
pub const MINT_ENDING_MODULUS: u64 = {
    let mut modulus = 1u64;
    let mut i = 0;
    while i < MINT_ENDING.len() {
        modulus *= 58;
        i += 1;
    }
    modulus
};

/// `MINT_ENDING` read as a base-58 number: 5 * 58^2 + 37 * 58 + 33 = 18,999 for `6ea`. A base58
/// address ends in `MINT_ENDING` exactly when its 32 bytes, read as one big-endian number, leave
/// this when divided by `MINT_ENDING_MODULUS`.
///
/// (A character that is not a base58 digit does not compile: the search for it runs off the end
/// of the alphabet.)
pub const MINT_ENDING_REMAINDER: u64 = {
    let text = MINT_ENDING.as_bytes();
    let mut remainder = 0u64;
    let mut i = 0;
    while i < text.len() {
        let mut digit = 0;
        while BASE58_DIGITS[digit] != text[i] {
            digit += 1;
        }
        remainder = remainder * 58 + digit as u64;
        i += 1;
    }
    remainder
};

// Two things `has_pangea_ending` relies on. The modulus is under 2^32, so its running remainder
// shifted by 32 bits fits a u64: five characters at most. And the ending does not begin with `1`,
// base58's zero: a number too small to have that many digits is written with `1`s borrowed from
// its leading zero bytes, and only for an ending that begins with one could such a number match
// the text without matching the remainder.
const _: () = assert!(!MINT_ENDING.is_empty() && MINT_ENDING.len() <= 5 && MINT_ENDING.as_bytes()[0] != b'1');

/// Whether `address`, written in base58, ends in `MINT_ENDING` (`6ea`).
///
/// ## Every Pangea mint on Solana ends in 6ea
///
/// A mark, and a rule the chain keeps rather than a convention: `launch` refuses any other mint,
/// so a mint that does NOT end in 6ea was not launched here.
///
/// The converse is false, and nothing should be built on it. An address ending in 6ea proves
/// nothing: anyone can search for a keypair, or for a derived address of a program of their own,
/// until one ends that way, and make a mint there. What cannot be forged is this program's own
/// state. A token was launched here if and only if a `LaunchRecord` account OWNED BY THIS PROGRAM
/// records its position -- or, to say the same thing from the bridge's side, if its OFT store is
/// `PDA(["OFT", PDA(["escrow", seed], this program)], the OFT program)` for the seed its launch
/// published, which only `launch` can sign for. That is the check a wallet, an indexer or an EVM
/// chain's peer must make. The ending is for people.
///
/// The mint is a program-derived address, and a launch's seed is fixed when its quote is issued
/// -- the public launch id is the seed's hash -- so the seed cannot be what is searched. A second
/// seed is: `LaunchArgs::mint_nonce`, four bytes that mean nothing except that somebody tried
/// about 390,000 of them (`solana/tools/mint-grind`) until the address came out right. A
/// nonce changes the mint and nothing else the seed derives: the OFT store, which the EVM chains
/// seal as their Solana peer, is derived from the escrow and is the same whatever the nonce.
///
/// ## Why a remainder and not the text
///
/// Base58 writes a number in base 58, after one `1` for each leading zero byte. So the last three
/// characters are `6ea` exactly when the number's three lowest base-58 digits are 5, 37 and 33:
/// when it leaves `MINT_ENDING_REMAINDER` = 18,999 on division by 58^3 = 195,112. (A number that
/// leaves 18,999 is at least 18,999, which has all three digits, so the leading `1`s never come
/// into it.) Encoding 32 bytes to base58 on chain costs thousands of compute units and a heap
/// allocation; this is eight divisions.
pub fn has_pangea_ending(address: &Pubkey) -> bool {
    // Four bytes at a time. The remainder is under 2^32, so `r << 32 | limb` fits a u64.
    let mut r: u64 = 0;
    for limb in address.as_ref().chunks_exact(4) {
        let limb = u32::from_be_bytes([limb[0], limb[1], limb[2], limb[3]]);
        r = ((r << 32) | limb as u64) % MINT_ENDING_MODULUS;
    }
    r == MINT_ENDING_REMAINDER
}

/// A launch's mint, and its bump: what `launch` creates and what every client derives.
pub fn mint_address(launch_seed: &[u8; 32], mint_nonce: u32) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[MINT_SEED, launch_seed.as_ref(), &mint_nonce.to_le_bytes()], &crate::ID)
}

/// What the public launch id is made from: `sha256(LAUNCH_ID_DOMAIN || seed)`.
pub const LAUNCH_ID_DOMAIN: &[u8] = b"pangea launch id";

/// The public id of the launch whose secret seed is `seed`. See `MINT_SEED`.
///
/// One way: the id is published long before the launch and says nothing about the seed, so
/// knowing which launch is coming says nothing about where on Solana it will be.
pub fn launch_id_of(seed: &[u8; 32]) -> [u8; 32] {
    anchor_lang::solana_program::hash::hashv(&[LAUNCH_ID_DOMAIN, seed.as_ref()]).to_bytes()
}

/// Nine, like every other chain in a launch, and not negotiable here.
///
/// `PangeaOFT.decimals()` returns 9 on all four EVM chains, because Solana holds amounts in a u64
/// and eighteen decimals overflows it at any supply worth launching. A Solana mint created with a
/// different scale would bridge at the wrong rate forever -- LayerZero converts between a token's
/// decimals and its shared precision, so the two sides disagreeing is not a display problem, it is
/// an amount problem. Taken as a constant rather than an argument so there is no value a caller
/// can pass that produces a token which is wrong in that way.
pub const TOKEN_DECIMALS: u8 = 9;

/// The platform admin: the one key that may redirect EITHER stream of ANY launch, including a
/// creator's, and the platform until a platform payee is set (`fees::Platform`).
///
/// ## Why a constant
///
/// The EVM side reads its admin live from the factory that deployed it; there is no factory on
/// Solana, so the equivalent is a constant in the program.
///
/// IT CANNOT BE ROTATED. A constant changes only by replacing the program, and this program is
/// made final before its first launch -- `launch` exists to give guarantees that an upgradeable
/// program could take back. So whatever address is written here is the admin for the life of
/// every token launched: if that key is lost, no launcher can be listed or removed, no route set,
/// no fee refunded or withdrawn and no stream redirected, ever; if it is stolen, all of that is
/// the thief's. Nothing requires it to be one key. It may be -- and for anything that matters
/// should be -- the address of a multisig, whose own signers can be rotated without this constant
/// changing. Each platform STREAM can still be moved off it, splitter by splitter
/// (`propose_platform`), and the bridge's fees are paid to its token accounts.
///
/// ## What it can and cannot do
///
/// The same as on the EVM chains, stated plainly: it can point a creator's fee stream at any
/// address that will accept it, including its own. The two-step handover applies to it as well:
/// it proposes, and the destination accepts.
///
/// For a token that EXISTS it cannot change the pool's fee -- no instruction here writes it; the
/// split trusts Meteora's operator, who can (`update_pool_fees`), not to, and follows the pool's
/// current fee if it does (`venue::current_fee`) -- cannot unlock the position, cannot name a peer,
/// and cannot take what has already been distributed. Nor can it choose a newer route for it:
/// routes are versioned (`bridge`, "routes are versioned"), and `open_bridge` applies only the
/// version in force at the token's launch -- for anyone, the admin included; an edit made since
/// reaches only the tokens launched after it. (A token older than every version is opened by the
/// admin only, and only onto the genesis: the route as it stood at the upgrade, fixed before it.)
/// What it CAN do to a token that exists, its own key accepted: on a v3 store, set the bridge's fee
/// anywhere from 0 to `MAX_BRIDGE_FEE_BPS` (50 bps; `set_bridge_fee` -- a live v1/v2 store's stays
/// the 20 bps its launch wrote, and the fee still goes to the platform); and on an open route, set
/// the gas floor its transfers must pay for on arrival (`set_gas_floor`, at most
/// `MAX_LZ_RECEIVE_GAS`, gas only -- it can redirect nothing). Nothing else reaches an open route.
///
/// For every token launched AFTERWARDS it decides more than that, and this is where it is
/// trusted: it lists the launchers (`add_launcher`), and a launcher names a launch's peers --
/// which can mint; and it sets the routes (`set_route`), which are who verifies each later
/// token's bridge -- and a verifier can attest to a message nobody sent. It also refunds and
/// withdraws launch fees. None of that reaches back to a token already launched.
#[cfg(not(any(feature = "test-stack", feature = "rehearsal-admin")))] pub const ADMIN: Pubkey = pubkey!("7rYog4JusTy4CpwvFGPrRvWtcDrWatnA3SN3DRPuf6kM"); #[cfg(feature = "rehearsal-admin")] pub const ADMIN: Pubkey = rehearsal_admin::ADMIN; // test stack: src/test_stack.rs; // rehearsal builds only (feature rehearsal-admin): the throwaway admin PANGEA_REHEARSAL_ADMIN named at build time, src/rehearsal_admin.rs

/// A listed launcher's seed. `PDA([b"launcher", key])` existing is what "listed" means.
///
/// ## Why launching is gated here at all
///
/// `launch` takes the name, the creator, the fee, the signed price snapshot the opening is
/// derived from and the EVM token a launch's peers are, and each of those is fixed for the life
/// of the token. So, the same rule as the four
/// EVM factories: a launch is started by a launcher the admin has listed. The list is a PDA per
/// launcher rather than a field somewhere, because it is checked by existence -- there is nothing
/// to deserialise and nothing to migrate when one is added.
///
/// ## What a launcher is, and is not
///
/// A key that may call `launch`, and nothing else. It cannot list another launcher, redirect a
/// fee stream, refund anybody or withdraw a fee. A fee is released by the launch it paid for, in
/// that launch's own instruction, and by nothing else. It is the key that belongs on the machine
/// that broadcasts launches all day, so that `ADMIN` does not have to be.
pub const LAUNCHER_SEED: &[u8] = b"launcher";

/// One payer's launch fee. `PDA([b"fee", launch_id, payer])` holds the lamports themselves.
///
/// Keyed by the launch ID, the public one, because a fee is paid before the launch and the seed
/// is not known to anyone who pays. `launch` is given the seed, hashes it, and settles only a
/// payment recorded under that id.
///
/// Per payer, not per launch, for the reason the EVM collector learned: a launch id is public from
/// the moment a payment for it is visible, so "the first payer is who a refund goes to" hands the
/// creator's fee to anyone who paid a lamport ahead of them. Here nobody can be the recipient of
/// money they did not send, because every payer's money is in an account only their key derives.
pub const FEE_SEED: &[u8] = b"fee";

/// How long the platform has to launch or refund before a payer may take their fee back without
/// it. Seven days, the same as `LaunchFeeCollector.RECLAIM_AFTER` on the EVM chains, and a
/// constant for the same reason: a setting could be raised after the payment, which is the only
/// moment it protects anybody.
pub const RECLAIM_AFTER: i64 = 7 * 24 * 60 * 60;

/// How long before a payment becomes its payer's to reclaim `launch` stops settling it: a day.
///
/// `launch` settles the payment it is handed, and the launcher decides to send it on what it read
/// a moment earlier. Without this, a launch could land in the same second a payment turned
/// reclaimable -- a race between the platform's launch and the payer's reclaim over one account.
/// With it the two windows do not touch: a payment can be settled for its first six days and
/// reclaimed from its seventh, and for the day between it can only be refunded.
///
/// WHAT THIS DOES NOT DO, and what does. It is a rule about a payment's AGE, and a payment made
/// again after a reclaim is a new payment with a new clock: a launcher that sent a launch more
/// than seven days after the payment it read could be answered, in front of that launch, with a
/// reclaim and one lamport paid to the same address. The age rule cannot see that. What refuses
/// it is the AMOUNT: `launch` is told the fee it expects to settle (`LaunchArgs::launch_fee`)
/// and settles nothing that holds less. A payment taken back and made again in full is simply
/// the fee, paid.
pub const SETTLE_MARGIN: i64 = 24 * 60 * 60;

/* ----------------------------------------------------- reading Meteora's accounts

   `launch` reads back what it locked, from Meteora's accounts rather than anybody's word, which
   needs a few fields from two of cp-amm's account types and two from a token account.

   The offsets are cp-amm's zero-copy layouts, which are `repr(C)` and so fixed by field order. They
   are not taken on trust: tests/escrow.rs carries a real pool, its real locked position and its
   real vault, captured from the chain, and asserts that these offsets read back exactly what
   Meteora's own SDK decodes for them. If cp-amm ever changes a layout, the discriminator and
   length checks below fail closed -- a split simply cannot be paid until this is updated, and the
   fees wait in Meteora meanwhile -- and that test fails loudly.                                */

/// sha256("account:Pool")[..8] and sha256("account:Position")[..8], as cp-amm writes them.
pub const CP_AMM_POOL_DISCRIMINATOR: [u8; 8] = [241, 154, 109, 4, 17, 177, 109, 188];
pub const CP_AMM_POSITION_DISCRIMINATOR: [u8; 8] = [170, 188, 143, 228, 122, 64, 247, 208];

const POOL_TOKEN_A_MINT: usize = 168;
const POOL_TOKEN_B_MINT: usize = 200;
const POOL_TOKEN_A_VAULT: usize = 232;
const POOL_TOKEN_B_VAULT: usize = 264;
const POSITION_POOL: usize = 8;
const POSITION_PERMANENT_LOCKED_LIQUIDITY: usize = 184;
/// An SPL token account, classic or Token-2022: the mint, then the owner, then the amount.
const TOKEN_ACCOUNT_MINT: usize = 0;
const TOKEN_ACCOUNT_AMOUNT: usize = 64;

fn key_at(data: &[u8], at: usize) -> Option<Pubkey> {
    let bytes: [u8; 32] = data.get(at..at + 32)?.try_into().ok()?;
    Some(Pubkey::new_from_array(bytes))
}

/// The two mints and two vaults of a cp-amm pool, or None if `data` is not one.
pub fn read_pool(data: &[u8]) -> Option<[(Pubkey, Pubkey); 2]> {
    if data.get(..8)? != CP_AMM_POOL_DISCRIMINATOR {
        return None;
    }
    Some([
        (key_at(data, POOL_TOKEN_A_MINT)?, key_at(data, POOL_TOKEN_A_VAULT)?),
        (key_at(data, POOL_TOKEN_B_MINT)?, key_at(data, POOL_TOKEN_B_VAULT)?),
    ])
}

/// A cp-amm position's pool and its permanently locked liquidity, or None if `data` is not one.
pub fn read_position(data: &[u8]) -> Option<(Pubkey, u128)> {
    if data.get(..8)? != CP_AMM_POSITION_DISCRIMINATOR {
        return None;
    }
    let at = POSITION_PERMANENT_LOCKED_LIQUIDITY;
    let locked: [u8; 16] = data.get(at..at + 16)?.try_into().ok()?;
    Some((key_at(data, POSITION_POOL)?, u128::from_le_bytes(locked)))
}

/// A token account's mint and balance, or None if `data` is too short to be one.
pub fn read_token_account(data: &[u8]) -> Option<(Pubkey, u64)> {
    let at = TOKEN_ACCOUNT_AMOUNT;
    let amount: [u8; 8] = data.get(at..at + 8)?.try_into().ok()?;
    Some((key_at(data, TOKEN_ACCOUNT_MINT)?, u64::from_le_bytes(amount)))
}

/// The first moment a payment made at `at` may be reclaimed by whoever made it.
pub fn reclaimable_from(at: i64) -> i64 {
    at.saturating_add(RECLAIM_AFTER)
}

/// The first moment a payment made at `at` may NO LONGER be settled by a launch. See
/// `SETTLE_MARGIN`.
pub fn settleable_until(at: i64) -> i64 {
    reclaimable_from(at).saturating_sub(SETTLE_MARGIN)
}

/// The platform's share of a batch of fees that has already arrived.
///
/// ## The rule
///
/// Of VOLUME, the platform takes **a fifth of the pool's fee, and never less than 0.2%**:
///
/// ```text
///     platform's cut of volume = max(20% of fee_bps, 20 bps)
/// ```
///
/// | pool fee | platform, of volume | Meteora (20% of the fee) | creator |
/// |---|---|---|---|
/// | 0.3% | 0.2% (the floor)  | 0.06% | 0.04% |
/// | 0.5% | 0.2% (the floor)  | 0.1%  | 0.2%  |
/// | 1%   | 0.2% (both agree) | 0.2%  | 0.6%  |
/// | 2%   | 0.4%              | 0.4%  | 1.2%  |
/// | 5%   | 1.0%              | 1.0%  | 3.0%  |
///
/// The two halves of the rule meet at a 1% fee. Below it the floor binds and the platform's
/// share of the fee grows as the fee shrinks; from 1% up it is a flat fifth of the fee.
///
/// ## From what arrived, not from volume
///
/// This program never sees volume. It sees `amount`: what the position was paid, which is the
/// pool's fee less the venue's own cut -- `amount = volume * fee_bps * venue_lp_share_bps`. So the
/// rule is worked back through that, and the platform's share OF WHAT ARRIVED is
///
/// ```text
///     amount * max(PLATFORM_SHARE_OF_FEE_BPS * fee_bps, PLATFORM_FEE_BPS * 10_000)
///            / (fee_bps * venue_lp_share_bps)
/// ```
///
/// On Meteora, which passes 80% of the fee to the position, that is 25% of what arrives at any
/// fee of 1% or more (a fifth of the fee out of four fifths of it), and `2,000,000 / (fee_bps *
/// 8,000)` of it below: 83.33% at the 0.3% floor.
///
/// EXACT, not rounded to a basis point: one multiplication and one division of whole numbers,
/// rounded down once, with the remainder -- under one base unit -- the creator's.
///
/// Clamped to the whole batch. `check_fee` makes a shortfall impossible at any fee a launch may
/// have (at the 0.3% floor the position receives 0.24% of volume, which covers the 0.2%), but a
/// clamp is cheaper than trusting an invariant to have held for the life of a pool nobody can fix.
pub fn platform_share(amount: u64, fee_bps: u16, venue_lp_share_bps: u16) -> u64 {
    platform_share_at(amount, fee_bps as u64 * BPS_TO_FEE_NUMERATOR, venue_lp_share_bps)
}

/// One basis point as a cp-amm fee numerator (`venue::FEE_DENOMINATOR` is 10^9).
pub const BPS_TO_FEE_NUMERATOR: u64 = 100_000;

/// `platform_share` at a fee given as cp-amm states it -- a numerator over 10^9 -- which is what a
/// claim reads off the pool as it stands (`venue::current_fee`): the same rule, exactly, at any fee
/// the pool may charge, a fraction of a basis point included.
pub fn platform_share_at(amount: u64, fee_numerator: u64, venue_lp_share_bps: u16) -> u64 {
    if fee_numerator == 0 || venue_lp_share_bps == 0 {
        return 0;
    }
    let fee = fee_numerator as u128;
    // The platform's cut of volume, as a numerator times 10,000: the larger of a fifth of the fee
    // and the floor (0.2% is 2,000,000 over 10^9). Both sides carry the same factor, so nothing is
    // rounded here.
    let cut = (PLATFORM_SHARE_OF_FEE_BPS * fee).max(PLATFORM_FEE_BPS * BPS * BPS_TO_FEE_NUMERATOR as u128);
    // amount < 2^64 and cut < 2,000 * 10^9 < 2^41, so the product is inside a u128.
    let owed = (amount as u128) * cut / (fee * venue_lp_share_bps as u128);
    if owed > amount as u128 {
        amount
    } else {
        owed as u64
    }
}

/// Bounds, plus the thing the bounds exist for: after the venue takes its cut, what arrives must
/// still cover the platform's 0.2% of volume.
pub fn check_fee(fee_bps: u16, venue_lp_share_bps: u16) -> Result<()> {
    require!(
        fee_bps >= MIN_FEE_BPS && fee_bps <= MAX_FEE_BPS,
        SplitterError::FeeOutOfRange
    );
    require!(
        venue_lp_share_bps > 0 && (venue_lp_share_bps as u128) <= BPS,
        SplitterError::InvalidVenueShare
    );
    require!(
        (fee_bps as u128) * (venue_lp_share_bps as u128) >= PLATFORM_FEE_BPS * BPS,
        SplitterError::PlatformCutUnpayable
    );
    Ok(())
}

/// Who a launch may pay.
///
/// The default pubkey is refused because nobody can sign for it: a stream paid to it could never
/// be rotated away, since `propose_*` needs the current party's signature. The launch's record's
/// own address is refused for the same reason -- only this program signs for it, and it has no
/// instruction that proposes on its own behalf.
pub fn check_parties(creator: &Pubkey, platform: &Pubkey, held: &[Pubkey]) -> Result<()> {
    require!(
        *creator != Pubkey::default() && *platform != Pubkey::default(),
        SplitterError::ZeroAddress
    );
    // An address this program holds -- the launch's record, the fee owner, AUTHORITY, the platform
    // record, the program's account for the quote asset, the SOL payout's transit -- has no key anyone else signs with: a
    // fee stream paid to it could never be spent or handed on.
    require!(
        !held.contains(creator) && !held.contains(platform),
        SplitterError::PartyIsSplitter
    );
    // Nor an address the runtime will not let a transaction write (Solana audit round 2, B L-2):
    // a sysvar, a builtin program, a loader -- or a program a claim calls. Named as a party, every
    // claim that pays it would carry it read-only.
    require!(!is_reserved_account(creator) && !is_reserved_account(platform), SplitterError::PartyReserved);
    Ok(())
}

/// The runtime's reserved account keys (agave `ReservedAccountKeys`, every one active): a
/// transaction may name them writable, and the runtime demotes them to read-only. And the programs
/// this program calls, which a transaction that calls them cannot write either.
pub const RESERVED_ACCOUNTS: [Pubkey; 37] = [
    // builtin programs
    pubkey!("AddressLookupTab1e1111111111111111111111111"),
    pubkey!("BPFLoader2111111111111111111111111111111111"),
    pubkey!("BPFLoader1111111111111111111111111111111111"),
    pubkey!("BPFLoaderUpgradeab1e11111111111111111111111"),
    pubkey!("ComputeBudget111111111111111111111111111111"),
    pubkey!("Config1111111111111111111111111111111111111"),
    pubkey!("Ed25519SigVerify111111111111111111111111111"),
    pubkey!("Feature111111111111111111111111111111111111"),
    pubkey!("LoaderV411111111111111111111111111111111111"),
    pubkey!("KeccakSecp256k11111111111111111111111111111"),
    pubkey!("Secp256r1SigVerify1111111111111111111111111"),
    pubkey!("StakeConfig11111111111111111111111111111111"),
    pubkey!("Stake11111111111111111111111111111111111111"),
    pubkey!("11111111111111111111111111111111"),
    pubkey!("Vote111111111111111111111111111111111111111"),
    pubkey!("ZkE1Gama1Proof11111111111111111111111111111"),
    pubkey!("ZkTokenProof1111111111111111111111111111111"),
    // sysvars
    pubkey!("SysvarC1ock11111111111111111111111111111111"),
    pubkey!("SysvarEpochRewards1111111111111111111111111"),
    pubkey!("SysvarEpochSchedu1e111111111111111111111111"),
    pubkey!("SysvarFees111111111111111111111111111111111"),
    pubkey!("Sysvar1nstructions1111111111111111111111111"),
    pubkey!("SysvarLastRestartS1ot1111111111111111111111"),
    pubkey!("SysvarRecentB1ockHashes11111111111111111111"),
    pubkey!("SysvarRent111111111111111111111111111111111"),
    pubkey!("SysvarRewards111111111111111111111111111111"),
    pubkey!("SysvarS1otHashes111111111111111111111111111"),
    pubkey!("SysvarS1otHistory11111111111111111111111111"),
    pubkey!("SysvarStakeHistory1111111111111111111111111"),
    // other
    pubkey!("NativeLoader1111111111111111111111111111111"),
    pubkey!("Sysvar1111111111111111111111111111111111111"),
    // the programs a launch and a claim call
    crate::ID,
    anchor_spl::token::ID,
    TOKEN_2022_ID,
    anchor_spl::associated_token::ID,
    CP_AMM_ID,
    OFT_PROGRAM_ID,
];

/// Whether `key` is one a transaction cannot write (`RESERVED_ACCOUNTS`), or LayerZero's endpoint.
pub fn is_reserved_account(key: &Pubkey) -> bool {
    RESERVED_ACCOUNTS.contains(key) || *key == LZ_ENDPOINT_ID
}

#[program]
pub mod pangea_splitter {
    use super::*;

    /// The whole Solana leg of a launch -- the mint and its metadata, the bridge and its peers,
    /// the fee split, the pool with the supply locked in it, and the launch fee -- in one
    /// instruction, so that it either all happened or none of it did. See `launch_leg`.
    pub fn launch<'info>(ctx: Context<'_, '_, 'info, 'info, Launch<'info>>, args: LaunchArgs) -> Result<()> {
        launch_leg::launch_handler(ctx, args)
    }

    /// `launch`, started from the CREATOR's own wallet: the creator signs and pays, and the
    /// listed launcher signs the same transaction as its authority. Same accounts, same
    /// arguments, same launch; what differs is who pays for it and where a dev buy comes from.
    /// See `launch_leg`, "a co-signed launch".
    pub fn launch_cosigned<'info>(ctx: Context<'_, '_, 'info, 'info, Launch<'info>>, args: LaunchArgs) -> Result<()> {
        launch_leg::launch_cosigned_handler(ctx, args)
    }

    /// Set how every later launch's bridge to one chain is opened: its verifiers in each
    /// direction, its executor and its gas floor. Admin only. Changes no token that exists --
    /// a route is applied once, by `open_bridge`, and never read again. The executor and every
    /// verifier the route names are given as accounts after the instruction's own, in any order,
    /// and each has to be a config account that exists. Each edit also writes a new immutable
    /// `RouteVersion` (the first one after the upgrade snapshots the old route as version 0): a
    /// token opens onto the version in force at its launch. See `bridge`, "routes are versioned".
    pub fn set_route(ctx: Context<SetRoute>, eid: u32, route: RouteArgs) -> Result<()> {
        bridge::set_route_handler(ctx, eid, route)
    }

    /// Allowlist an asset launches may pair against besides wrapped SOL, or turn one off. Admin
    /// only. See `quote`.
    pub fn set_quote_asset(ctx: Context<SetQuoteAsset>, enabled: bool, min_usd_per_quote: u128, max_usd_per_quote: u128) -> Result<()> {
        quote::set_quote_asset_handler(ctx, enabled, min_usd_per_quote, max_usd_per_quote)
    }

    /// Set the band the signed price of wrapped SOL must be inside for a launch to pair with it:
    /// USD per SOL, 1e18-scaled. Admin only. Until it is set, no launch against wrapped SOL opens.
    /// (An allowlisted asset's band is in its entry: `set_quote_asset`.) See `price`.
    pub fn set_native_price_band(ctx: Context<SetPriceSigner>, min_usd_per_quote: u128, max_usd_per_quote: u128) -> Result<()> {
        price::set_native_price_band_handler(ctx, min_usd_per_quote, max_usd_per_quote)
    }

    /// Open a launch's bridge to the chains named: create LayerZero's accounts for each route and
    /// pin its libraries, executor, verifiers and gas floor from that chain's `Route`. Anyone may
    /// call it; it takes no settings, and each route opens exactly once. `float_per_route` is how
    /// many of the caller's own lamports the program's authority is lent, per route, to pay
    /// LayerZero's rent with; what is not spent comes straight back. See `bridge`.
    pub fn open_bridge<'info>(
        ctx: Context<'_, '_, 'info, 'info, OpenBridge<'info>>,
        launch_seed: [u8; 32],
        eids: Vec<u32>,
        float_per_route: u64,
    ) -> Result<()> {
        bridge::open_bridge_handler(ctx, launch_seed, eids, float_per_route)
    }

    /// Send everything a launch's bridge has collected in fees to the platform's own token
    /// account. Anyone may call it; where the money goes is not an argument. See `bridge`.
    pub fn withdraw_bridge_fee(ctx: Context<WithdrawBridgeFee>, launch_seed: [u8; 32]) -> Result<()> {
        bridge::withdraw_bridge_fee_handler(ctx, launch_seed)
    }

    /// Set the gas an OPEN route's transfers (Solana to `eid`) must pay for on arrival: 1 to
    /// 1,000,000, gas only. Admin only; raising it only raises what a transfer is quoted. See
    /// `bridge`, "after the route is open".
    pub fn set_gas_floor(ctx: Context<SetGasFloor>, launch_seed: [u8; 32], eid: u32, gas: u64) -> Result<()> {
        bridge::set_gas_floor_handler(ctx, launch_seed, eid, gas)
    }

    /// Set a v3 store's bridge fee: 0 to 50 bps (launches set 20). Admin only; a v1/v2 store is
    /// refused. The fee still goes to the platform. See `bridge`, "after the route is open".
    pub fn set_bridge_fee(ctx: Context<SetBridgeFee>, launch_seed: [u8; 32], bps: u16) -> Result<()> {
        bridge::set_bridge_fee_handler(ctx, launch_seed, bps)
    }

    /// LAUNCHES MADE BEFORE THE RESERVE WAS DROPPED ONLY. A launch now keeps no reserve record and
    /// its mint authority is its OFT store, so `arm` refuses it (`NoReserve`); it stays for a
    /// launch that landed with a reserve and was not armed yet.
    ///
    /// Right after a launch, once: create its reserve and the multisig that is its mint
    /// authority from now on (the OFT store or this program, one of two), mint the reserve the
    /// launch total less what is on Solana, and hand the mint to the multisig. A listed launcher
    /// sends it. Until it has, the launch's bridge cannot be opened. See `reserve`.
    pub fn arm(ctx: Context<Arm>, launch_seed: [u8; 32], mint_nonce: u32) -> Result<()> {
        reserve::arm_handler(ctx, launch_seed, mint_nonce)
    }

    /// For the launches made with a reserve (see `arm`); a launch now has none to rebalance.
    ///
    /// Bring an armed launch's mint supply back to its launch total: burn an excess out of the
    /// reserve, or mint a shortfall into it, and nothing else. Anyone may send it, as often as
    /// they like. See `reserve`.
    pub fn rebalance(ctx: Context<Rebalance>) -> Result<()> {
        reserve::rebalance_handler(ctx)
    }

    /// List a launcher: a key that may call `launch`. See `LAUNCHER_SEED`.
    ///
    /// Admin only. One step, unlike a fee stream's handover, because a mistake is cheap in both
    /// directions -- a mistyped key is one nobody holds, and a launcher removed by accident is
    /// listed again in one transaction. Nothing is stranded either way.
    pub fn add_launcher(ctx: Context<AddLauncher>, launcher: Pubkey) -> Result<()> {
        require!(launcher != Pubkey::default(), SplitterError::ZeroAddress);
        let entry = &mut ctx.accounts.entry;
        entry.launcher = launcher;
        entry.bump = ctx.bumps.entry;
        emit!(LauncherSet { launcher, allowed: true });
        Ok(())
    }

    /// Set who signs launch prices: the EVM address of the key every chain's `PriceAttestor`
    /// trusts. Admin only. A launch opens only at a price this key signed (see `price`).
    pub fn set_price_signer(ctx: Context<SetPriceSigner>, address: [u8; 20]) -> Result<()> {
        price::set_price_signer_handler(ctx, address)
    }

    /// Pangea v3 gap fee: whether `launch_v2` and `launch_self` may make v3 OFT stores
    /// (`init_oft_v3`), in `PDA(["gap_v3"])`. Admin only; turned on at the v3 cutover. A launch is
    /// v3 only when signed so (`price::terms_hash_v3`) and naming that account. See `price::GAP_V3_SEED`.
    pub fn set_gap_v3_launches(ctx: Context<SetGapV3Launches>, enabled: bool) -> Result<()> {
        price::set_gap_v3_launches_handler(ctx, enabled)
    }

    /// v3 (owner 2026-10-31): the least opening market cap PER CHAIN a v3 launch may sign, in
    /// `PDA(["gap_v3"])` beside the switch. Admin only; $600 to $3,000 a chain
    /// (`price::V3_MIN_MARKET_CAP_*_BOUND_USD`), $600 when the account is made; event
    /// `V3MinMarketCapSet` on every change put in force. A RAISE is pending for
    /// `price::V3_MIN_RAISE_DELAY` (1 h; owner Q26), event `V3MinMarketCapRaiseScheduled`; a lowering
    /// is at once. v2 launches keep `MIN_MARKET_CAP_USD`.
    pub fn set_v3_min_market_cap(ctx: Context<SetGapV3Launches>, min_market_cap_usd: u32) -> Result<()> {
        price::set_v3_min_market_cap_handler(ctx, min_market_cap_usd)
    }

    /// Delist a launcher. Its entry is closed, so it is a stranger again from the next instruction.
    pub fn remove_launcher(ctx: Context<RemoveLauncher>) -> Result<()> {
        emit!(LauncherSet {
            launcher: ctx.accounts.entry.launcher,
            allowed: false,
        });
        Ok(())
    }

    /// Pay `lamports` towards the launch fee for `launch_id`, into an account only this payer's key
    /// derives.
    ///
    /// Permissionless and accumulating, like `LaunchFeeCollector.pay`. Anyone may pay for any
    /// launch, because the only places this money can go are back to whoever sent it and to the
    /// platform; and a second payment tops the first up, because a quote underpaid by a lamport
    /// would otherwise leave a launch id that can be neither paid for nor reissued.
    ///
    /// The account's rent is the payer's and is on top of `lamports`. It comes back with a refund
    /// or a reclaim, and goes with the fee when the platform withdraws a settled one.
    ///
    /// Refused once this payment is settled. Whether the launch it names has happened is not
    /// something this instruction can see -- a launch's addresses derive from a seed nobody
    /// outside the launcher knows beforehand -- and it does not need to: a payment made for a
    /// launch that has already landed is settled by nothing, so it stays its payer's, refundable
    /// by the admin and reclaimable by the payer after seven days. The mistake costs a wait.
    pub fn pay_fee(ctx: Context<PayFee>, launch_id: [u8; 32], lamports: u64) -> Result<()> {
        require!(lamports > 0, SplitterError::NothingToPay);
        require!(!ctx.accounts.fee.settled, SplitterError::AlreadySettled);

        let fee = &mut ctx.accounts.fee;
        // A payment account nobody has paid into yet has no payer recorded.
        if fee.payer == Pubkey::default() {
            fee.launch_id = launch_id;
            fee.payer = ctx.accounts.payer.key();
            fee.at = Clock::get()?.unix_timestamp;
            fee.bump = ctx.bumps.fee;
        }
        fee.amount = fee.amount.checked_add(lamports).ok_or(SplitterError::Overflow)?;
        let total = fee.amount;

        transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.payer.to_account_info(),
                    to: ctx.accounts.fee.to_account_info(),
                },
            ),
            lamports,
        )?;

        emit!(FeePaid {
            launch_id,
            payer: ctx.accounts.payer.key(),
            lamports,
            total,
        });
        Ok(())
    }

    // THERE IS NO `settle_fee`. A payment is settled by `launch`, in the instruction that creates
    // the token it paid for, and by nothing else. There used to be a permissionless instruction
    // that settled a payment on proof read out of Meteora's accounts; it existed so that a fee
    // could be settled by a launch made of several transactions, and a launch is one instruction
    // now. Without it there is no proof for anyone to forge, and a payment that arrives after
    // its launch is simply its payer's to take back.

    /// Take a settled fee, as the admin. The payment's account is closed to the admin, so its
    /// rent goes with it.
    pub fn withdraw_fee(ctx: Context<WithdrawFee>) -> Result<()> {
        require!(ctx.accounts.fee.settled, SplitterError::NotSettled);
        emit!(FeeWithdrawn {
            launch_id: ctx.accounts.fee.launch_id,
            payer: ctx.accounts.fee.payer,
            lamports: ctx.accounts.fee.amount,
        });
        Ok(())
    }

    /// Give one payer their fee back, as the admin, for a launch that did not happen.
    pub fn refund_fee(ctx: Context<RefundFee>) -> Result<()> {
        require!(!ctx.accounts.fee.settled, SplitterError::AlreadySettled);
        emit!(FeeRefunded {
            launch_id: ctx.accounts.fee.launch_id,
            payer: ctx.accounts.fee.payer,
            lamports: ctx.accounts.fee.amount,
        });
        Ok(())
    }

    /// Take your own fee back, when the platform has neither launched nor refunded in time.
    ///
    /// No admin involvement and no admin veto. The lamports never left this payer's own account,
    /// and an unsettled one cannot be withdrawn, so there is nothing the platform could have spent
    /// in the meantime: after `RECLAIM_AFTER` the payer's signature is enough.
    pub fn reclaim_fee(ctx: Context<ReclaimFee>) -> Result<()> {
        require!(!ctx.accounts.fee.settled, SplitterError::AlreadySettled);
        let now = Clock::get()?.unix_timestamp;
        require!(
            now >= reclaimable_from(ctx.accounts.fee.at),
            SplitterError::TooEarlyToReclaim
        );

        emit!(FeeReclaimed {
            launch_id: ctx.accounts.fee.launch_id,
            payer: ctx.accounts.fee.payer,
            lamports: ctx.accounts.fee.amount,
        });
        Ok(())
    }

    // ------------------------------------------------------------ the fee split (see `fees`)

    /// Claim one launch's fees and pay them out: the creator's share to the creator, the
    /// platform's to the platform, every unit that arrived, in this instruction. Permissionless.
    /// The venue's accounts follow the instruction's own (`venue::CLAIM_ACCOUNTS`).
    pub fn claim_fees<'info>(ctx: Context<'_, '_, 'info, 'info, ClaimFees<'info>>) -> Result<()> {
        fees::claim_fees_handler(ctx)
    }

    /// `claim_fees` for a v2 launch paired against wrapped SOL, paid in native SOL: the payee's
    /// share and the platform's, the same amounts, straight to their wallets. Permissionless; the
    /// cranker fronts a temporary account's rent and gets it back in the same instruction. See
    /// `fees::claim_fees_native_handler`.
    pub fn claim_fees_native<'info>(ctx: Context<'_, '_, 'info, 'info, ClaimFeesNative<'info>>) -> Result<()> {
        fees::claim_fees_native_handler(ctx)
    }

    /// The Solana leg of a v2 launch, sent by a listed launcher: `launch`, with the snapshot v2
    /// (the creator's market cap, the supply mode and the signed terms), a payee apart from the
    /// creator, the fee enforced on its chain and SUPPLY_TOTAL's lockbox. See `launch_v2`.
    pub fn launch_v2<'info>(ctx: Context<'_, '_, 'info, 'info, LaunchV2<'info>>, args: LaunchV2Args) -> Result<()> {
        launch_v2::launch_v2_handler(ctx, args, false)
    }

    /// The same launch, sent by its CREATOR alone: the creator signs and pays everything, with a
    /// seed of their own (docs/factory-v2.md §5). No launcher. See `launch_v2`.
    pub fn launch_self<'info>(ctx: Context<'_, '_, 'info, 'info, LaunchV2<'info>>, args: LaunchV2Args) -> Result<()> {
        launch_v2::launch_v2_handler(ctx, args, true)
    }

    /// Admin only: add a chain to a v2 launch (D9) -- record its peer on `eid`, which the launch
    /// does not name yet, so `open_bridge` can open the route to it. Nothing already recorded is
    /// changed. The record grows by one peer entry, its rent paid by the admin.
    pub fn add_peer_v2(ctx: Context<AddPeerV2>, eid: u32, token: [u8; 20]) -> Result<()> {
        launch_v2::add_peer_v2_handler(ctx, eid, token)
    }

    /// Admin only, v2 launches: set the payee directly, for one that cannot sign (a program's PDA).
    /// See `launch_v2::admin_set_payee_handler`.
    pub fn admin_set_payee(ctx: Context<AdminSetPayee>, launch_seed: [u8; 32], to: Pubkey) -> Result<()> {
        launch_v2::admin_set_payee_handler(ctx, launch_seed, to)
    }

    /// Offer a launch's creator stream to `to`, as its creator. It applies when `to` accepts.
    ///
    /// Two-step, because a fee stream runs for as long as the pool does and outlives the key that
    /// was current at launch. A mistyped address here would divert that income permanently.
    pub fn propose_creator(ctx: Context<ProposeCreator>, to: Pubkey) -> Result<()> {
        // A v2 launch's stream is its PAYEE's, chosen in the signed terms; it moves only through
        // the admin (D10: `admin_propose_creator`, then `accept_creator`).
        {
            let info = ctx.accounts.record.to_account_info();
            let data = info.try_borrow_data()?;
            require!(read_v2_tail(&data).is_none(), SplitterError::PayeeMovedByAdminOnly);
        }
        fees::propose_creator_handler(&mut ctx.accounts.record, to, None)
    }

    /// The same, as the admin. Writes the same `pending_creator` slot the creator's own proposal
    /// writes, so the last proposal is the live one whoever made it; the distinct event keeps "the
    /// creator moved their own fees" and "the platform moved the creator's fees" apart in the log.
    pub fn admin_propose_creator(ctx: Context<AdminProposeCreator>, to: Pubkey) -> Result<()> {
        let admin = ctx.accounts.admin.key();
        fees::propose_creator_handler(&mut ctx.accounts.record, to, Some(admin))
    }

    /// Take the creator stream offered to the signer.
    pub fn accept_creator(ctx: Context<AcceptCreator>) -> Result<()> {
        fees::accept_creator_handler(&mut ctx.accounts.record)
    }

    /// Offer the platform's stream, for every launch at once, to `to`: as the platform, or as the
    /// admin (which may rotate the platform's payout address without a cold wallet transacting).
    pub fn propose_platform(ctx: Context<ProposePlatform>, to: Pubkey) -> Result<()> {
        fees::propose_platform_handler(ctx, to)
    }

    /// Take the platform stream offered to the signer.
    pub fn accept_platform(ctx: Context<AcceptPlatform>) -> Result<()> {
        fees::accept_platform_handler(ctx)
    }

    // ------------------------------------------------------------- tokenomics (see `tokenomics`)

    /// Make a launch's tokenomics account, from its whole config, before the launch. Anyone.
    pub fn init_tokenomics(ctx: Context<InitTokenomics>, config: TokenomicsConfig, seed: [u8; 32]) -> Result<()> {
        tokenomics::init_handler(ctx, config, seed)
    }

    /// Fix the account's launch, from the launch's seed, once it has landed. Anyone.
    pub fn bind_tokenomics(ctx: Context<BindTokenomics>, launch_seed: [u8; 32]) -> Result<()> {
        tokenomics::bind_handler(ctx, launch_seed)
    }

    /// The account's lamports above its rent, to its owner. Anyone.
    pub fn forward_tokenomics_refund(ctx: Context<ForwardRefund>) -> Result<()> {
        tokenomics::forward_refund_handler(ctx)
    }

    /// A dev buy's coins, and stray coins, to the owner. Anyone.
    pub fn forward_tokenomics_coins<'info>(ctx: Context<'_, '_, 'info, 'info, ForwardCoins<'info>>) -> Result<()> {
        tokenomics::forward_coins_handler(ctx)
    }

    /// Open the account's own liquidity position on its pool. Anyone, paying its rent; once.
    pub fn open_tokenomics_position<'info>(ctx: Context<'_, '_, 'info, 'info, OpenLpPosition<'info>>) -> Result<()> {
        tokenomics::open_lp_position_handler(ctx)
    }

    /// Claim the account's own position's fees into its wrapped-SOL account. Anyone.
    pub fn claim_tokenomics_position_fees<'info>(ctx: Context<'_, '_, 'info, 'info, ClaimLpFees<'info>>) -> Result<()> {
        tokenomics::claim_lp_fees_handler(ctx)
    }

    /// Spend every bucket that is due, by the split, and repay the caller's fee. Anyone.
    pub fn execute_tokenomics<'info>(ctx: Context<'_, '_, 'info, 'info, Execute<'info>>) -> Result<()> {
        tokenomics::execute_handler(ctx)
    }

    /// The owner or the community wallet takes its own bucket, at any size, as SOL.
    pub fn claim_tokenomics_bucket<'info>(ctx: Context<'_, '_, 'info, 'info, ClaimOwn<'info>>) -> Result<()> {
        tokenomics::claim_own_handler(ctx)
    }

    /// Move a stray wrapped-SOL account the tokenomics account owns into its own. Anyone.
    pub fn sweep_tokenomics_wsol<'info>(ctx: Context<'_, '_, 'info, 'info, SweepWsol<'info>>) -> Result<()> {
        tokenomics::sweep_wsol_handler(ctx)
    }

    /// The treasury takes the coins kept for it, into an account it names.
    pub fn claim_tokenomics_treasury_coins<'info>(ctx: Context<'_, '_, 'info, 'info, ClaimTreasuryCoins<'info>>) -> Result<()> {
        tokenomics::claim_treasury_coins_handler(ctx)
    }

    /// A recipient offers its own role to `to` (0 owner, 1 treasury, 2 community).
    pub fn propose_tokenomics_role(ctx: Context<TokenomicsRole>, role: u8, to: Pubkey) -> Result<()> {
        tokenomics::propose_role_handler(ctx, role, to)
    }

    /// Take the role offered to the signer.
    pub fn accept_tokenomics_role(ctx: Context<TokenomicsRole>, role: u8) -> Result<()> {
        tokenomics::accept_role_handler(ctx, role)
    }

    // ------------------------------------------------------- tokenomics v2 (see `tokenomics_v2`)

    /// Make a launch's v2 tokenomics account from the launch-wide config and the Solana leg. Anyone.
    pub fn init_tokenomics_v2(ctx: Context<InitTokenomicsV2>, config: TokenomicsConfigV2, leg: TokenomicsLegV2) -> Result<()> {
        tokenomics_v2::init_v2_handler(ctx, config, leg)
    }

    /// Fix the v2 account's launch; makes its vault and coin accounts. Anyone.
    pub fn bind_tokenomics_v2(ctx: Context<BindTokenomicsV2>, launch_seed: [u8; 32]) -> Result<()> {
        tokenomics_v2::bind_v2_handler(ctx, launch_seed)
    }

    /// The v2 account's lamports above its rent, to its owner. Anyone.
    pub fn forward_tokenomics_v2_refund(ctx: Context<ForwardRefundV2>) -> Result<()> {
        tokenomics_v2::forward_refund_v2_handler(ctx)
    }

    /// A dev buy's coins, and stray coins, to the owner. Anyone.
    pub fn forward_tokenomics_v2_coins<'info>(ctx: Context<'_, '_, 'info, 'info, ForwardCoinsV2<'info>>) -> Result<()> {
        tokenomics_v2::forward_coins_v2_handler(ctx)
    }

    /// Open the v2 account's liquidity position. Anyone; repaid the rent from the liquidity bucket.
    pub fn open_tokenomics_v2_position<'info>(ctx: Context<'_, '_, 'info, 'info, OpenLpPositionV2<'info>>) -> Result<()> {
        tokenomics_v2::open_lp_position_v2_handler(ctx)
    }

    /// Claim the v2 account's position fees into its vault. Anyone.
    pub fn claim_tokenomics_v2_position_fees<'info>(ctx: Context<'_, '_, 'info, 'info, ClaimLpFeesV2<'info>>) -> Result<()> {
        tokenomics_v2::claim_lp_fees_v2_handler(ctx)
    }

    /// Spend the burn, buy & hold and liquidity buckets that are due. Anyone.
    pub fn execute_tokenomics_v2<'info>(ctx: Context<'_, '_, 'info, 'info, ExecuteV2<'info>>) -> Result<()> {
        tokenomics_v2::execute_v2_handler(ctx)
    }

    /// Pay the wallets of slots `from..to` what they are owed, in SOL. Anyone.
    pub fn pay_tokenomics_wallets<'info>(ctx: Context<'_, '_, 'info, 'info, PayWallets<'info>>, from: u8, to: u8) -> Result<()> {
        tokenomics_v2::pay_wallets_handler(ctx, from, to)
    }

    /// A wallet takes what its slot is owed, at any size.
    pub fn claim_tokenomics_wallet<'info>(ctx: Context<'_, '_, 'info, 'info, ClaimWallet<'info>>, index: u8) -> Result<()> {
        tokenomics_v2::claim_wallet_handler(ctx, index)
    }

    /// A wallet offers its own slot to `to`.
    pub fn propose_tokenomics_wallet(ctx: Context<TokenomicsV2Signer>, index: u8, to: Pubkey) -> Result<()> {
        tokenomics_v2::propose_wallet_handler(ctx, index, to)
    }

    /// Take the slot offered to the signer.
    pub fn accept_tokenomics_wallet(ctx: Context<TokenomicsV2Signer>, index: u8) -> Result<()> {
        tokenomics_v2::accept_wallet_handler(ctx, index)
    }

    /// The owner (0) or the treasury (1) offers its role to `to`.
    pub fn propose_tokenomics_v2_role(ctx: Context<TokenomicsV2Signer>, role: u8, to: Pubkey) -> Result<()> {
        tokenomics_v2::propose_role_v2_handler(ctx, role, to)
    }

    /// Take the role offered to the signer.
    pub fn accept_tokenomics_v2_role(ctx: Context<TokenomicsV2Signer>, role: u8) -> Result<()> {
        tokenomics_v2::accept_role_v2_handler(ctx, role)
    }

    /// The owner or the admin sets the holder eligibility the payout service reads.
    pub fn set_tokenomics_eligibility(ctx: Context<TokenomicsV2Signer>, min_holder_bps: u16, select_mode: u8, select_count: u32) -> Result<()> {
        tokenomics_v2::set_eligibility_handler(ctx, min_holder_bps, select_mode, select_count)
    }

    /// Move a stray wrapped-SOL account of the v2 account's into its vault. Anyone.
    pub fn sweep_tokenomics_v2_wsol<'info>(ctx: Context<'_, '_, 'info, 'info, SweepWsolV2<'info>>) -> Result<()> {
        tokenomics_v2::sweep_wsol_v2_handler(ctx)
    }

    /// The treasury takes the coins kept for it.
    pub fn claim_tokenomics_v2_treasury_coins<'info>(ctx: Context<'_, '_, 'info, 'info, ClaimTreasuryCoinsV2<'info>>) -> Result<()> {
        tokenomics_v2::claim_treasury_coins_v2_handler(ctx)
    }

    /// The admin makes the program-wide v2 config, naming the operator.
    /// The admin sets a quote asset's rate for tokenomics v2.3 (`Tk2QuoteRate`): base units of the
    /// asset one SOL is worth, which converts the operator's lamport costs into the asset.
    pub fn set_tk2_quote_rate(ctx: Context<SetTk2QuoteRate>, quote_per_sol: u64) -> Result<()> {
        tokenomics_v2::set_tk2_quote_rate_handler(ctx, quote_per_sol)
    }

    pub fn init_tk2_config(ctx: Context<InitTk2Config>, operator: Pubkey) -> Result<()> {
        tokenomics_v2::init_tk2_config_handler(ctx, operator)
    }

    /// The admin names a new operator.
    pub fn set_tk2_operator(ctx: Context<SetTk2Operator>, operator: Pubkey) -> Result<()> {
        tokenomics_v2::set_tk2_operator_handler(ctx, operator)
    }

    /// Make reward entry `index`'s pot accounts. Anyone.
    pub fn open_reward_pot(ctx: Context<OpenRewardPot>, index: u8) -> Result<()> {
        tokenomics_v2::open_reward_pot_handler(ctx, index)
    }

    /// The operator swaps entry `index`'s budget into its token through a route it names.
    pub fn buy_rewards<'info>(ctx: Context<'_, '_, 'info, 'info, BuyRewards<'info>>, index: u8, amount_in: u64, min_out: u64, data: Vec<u8>) -> Result<()> {
        tokenomics_v2::buy_rewards_handler(ctx, index, amount_in, min_out, data)
    }

    /// The operator pays holders of entry `index` up to their cumulative amounts; for a SOL entry,
    /// less each one's capped fee. `amounts`: a SOL entry's (cumulative, fee) per holder, a token
    /// entry's cumulative per holder.
    pub fn pay_tokenomics_holders<'info>(ctx: Context<'_, '_, 'info, 'info, PayHolders<'info>>, index: u8, amounts: Vec<u64>) -> Result<()> {
        tokenomics_v2::pay_holders_handler(ctx, index, amounts)
    }

    /// The admin sets the v2 payout minimum (`Tk2Min`): any number of lamports, 0 included.
    pub fn set_tk2_min_execute(ctx: Context<SetTk2Min>, min_execute_lamports: u64) -> Result<()> {
        tokenomics_v2::set_tk2_min_execute_handler(ctx, min_execute_lamports)
    }

    /// The admin sets the operator's repayment margin and cap (`Tk2Min`).
    pub fn set_tk2_repay(ctx: Context<SetTk2Min>, margin_bps: u16, cap_bps: u16) -> Result<()> {
        tokenomics_v2::set_tk2_repay_handler(ctx, margin_bps, cap_bps)
    }

    /// The admin sets the swap rules v1's and v2's execute share (`Tk2Swap`, in `PDA(["tk2-min"])`):
    /// the cooldown between swaps, in seconds, and the most one swap may move the price, in bps of
    /// the pool's fee.
    pub fn set_tk2_swap(ctx: Context<SetTk2Min>, swap_cooldown_secs: u32, max_move_fee_bps: u16) -> Result<()> {
        tokenomics_v2::set_tk2_swap_handler(ctx, swap_cooldown_secs, max_move_fee_bps)
    }

    /// The admin sets the most a SOL payout may take from one holder.
    pub fn set_tk2_max_fee(ctx: Context<SetTk2Operator>, max_fee_per_recipient: u64) -> Result<()> {
        tokenomics_v2::set_tk2_max_fee_handler(ctx, max_fee_per_recipient)
    }

    /// A holder takes what it is owed of entry `index` with the operator's voucher.
    pub fn claim_holder_reward<'info>(ctx: Context<'_, '_, 'info, 'info, ClaimHolder<'info>>, index: u8, cumulative: u64) -> Result<()> {
        tokenomics_v2::claim_holder_handler(ctx, index, cumulative)
    }

    /// The admin moves stuck holders money, or unbooked money to the owner.
    pub fn admin_recover<'info>(ctx: Context<'_, '_, 'info, 'info, AdminRecover<'info>>, index: u8, kind: u8, amount: u64) -> Result<()> {
        tokenomics_v2::admin_recover_handler(ctx, index, kind, amount)
    }
}

/// The launch's slot, little-endian: the first thing its record holds after `LaunchRecord`
/// (see `LAUNCHED_SLOT_AT`). `launch` allocates the record with these bytes and the peers after
/// them, and writes them once; Anchor reads and writes the struct and leaves what follows alone.
///
/// What it is for: `open_bridge` applies a `Route` to a token only as the route stood when that
/// token launched, unless the admin signs -- see `bridge`, "a route is the one in force at launch".
pub const LAUNCH_RECORD_LEN: usize = 8;

/// Where in a launch's record (`LaunchRecord`) the slot it landed in is.
pub const LAUNCHED_SLOT_AT: usize = 8 + LaunchRecord::INIT_SPACE;

/// The slot a launch landed in, from its record's data; None if the data is too short to be a
/// launch's record (every launch writes it).
pub fn launched_slot(record_data: &[u8]) -> Option<u64> {
    record_data
        .get(LAUNCHED_SLOT_AT..LAUNCHED_SLOT_AT + LAUNCH_RECORD_LEN)
        .and_then(|b| b.try_into().ok())
        .map(u64::from_le_bytes)
}

/// Where in a launch's record its PEER RECORD starts: straight after the slot.
///
/// A launch does not create its LayerZero peers. It records what they must be -- each chain the
/// launch names, and the EVM token that is the peer on that chain -- and `open_bridge` creates a
/// chain's peer from this record, signing as `AUTHORITY`, in the same instruction that opens the
/// route to it: the first bridger on a route pays for its peer with its route, and a route nobody
/// uses costs nobody anything. Nothing about a peer is chosen at opening: the value is this
/// record's, written once by `launch`, and no instruction writes it again.
///
/// Layout, PER PEER (every launch since a token got its own address on each EVM chain): twenty
/// zero bytes, the number of chains (1), then for each chain, ascending, its endpoint id (2 bytes,
/// little-endian) and its EVM token (20) -- the `peers` the launch was given.
///
/// Layout, ONE TOKEN (the launches before that, TEST2 and TEST3 among them): the EVM token (20
/// bytes), the number of chains (1), each chain's endpoint id (2 bytes, little-endian, ascending).
/// Still read, so those launches' routes nobody has opened yet still open, to the peer they
/// recorded. The two cannot be confused: a one-token record's token was refused if it was zero,
/// so twenty zero bytes are the per-peer layout and nothing else.
pub const PEER_RECORD_AT: usize = LAUNCHED_SLOT_AT + LAUNCH_RECORD_LEN;

/// What a peer record holds before its entries: twenty bytes (zero in the per-peer layout) and the
/// number of chains.
pub const PEER_RECORD_HEAD: usize = 21;

/// One entry of the per-peer layout: the endpoint id (2) and that chain's EVM token (20).
pub const PEER_ENTRY_LEN: usize = 22;

/// The bytes a launch's record holds after `LaunchRecord`, for `peers` chains: the slot, then the
/// peers (per-peer layout). No reserve record: launches keep no reserve any more (see `reserve`);
/// a record made before keeps one after its peers, which `read_reserve_record` finds.
pub const fn launch_record_len(peers: usize) -> usize {
    LAUNCH_RECORD_LEN + PEER_RECORD_HEAD + PEER_ENTRY_LEN * peers
}

/// Write a launch's peer record (see `PEER_RECORD_AT`) into its record's data, in the per-peer
/// layout: `peers` is each chain's endpoint id and EVM token, ascending.
pub fn write_peer_record(record_data: &mut [u8], peers: &[(u16, [u8; 20])]) {
    let at = PEER_RECORD_AT;
    record_data[at..at + 20].fill(0);
    record_data[at + 20] = peers.len() as u8;
    for (i, (eid, token)) in peers.iter().enumerate() {
        let e = at + PEER_RECORD_HEAD + PEER_ENTRY_LEN * i;
        record_data[e..e + 2].copy_from_slice(&eid.to_le_bytes());
        record_data[e + 2..e + PEER_ENTRY_LEN].copy_from_slice(token);
    }
}

/// Whether a record's peers are in the per-peer layout (true) or the one-token layout of the
/// launches before it (false). None if the data is too short to hold either.
pub fn per_peer_record(record_data: &[u8]) -> Option<bool> {
    Some(record_data.get(PEER_RECORD_AT..PEER_RECORD_AT + 20)?.iter().all(|b| *b == 0))
}

/// Where a record's peer record ends -- and its reserve record, when it has one, begins -- in
/// whichever layout it was written. None if the data is too short to say.
pub fn peer_record_end(record_data: &[u8]) -> Option<usize> {
    let per_peer = per_peer_record(record_data)?;
    let count = *record_data.get(PEER_RECORD_AT + 20)? as usize;
    Some(PEER_RECORD_AT + PEER_RECORD_HEAD + count * if per_peer { PEER_ENTRY_LEN } else { 2 })
}

/// The peer a launch recorded for `eid`: its EVM token, if `eid` is one of the chains it named.
/// None for a chain it did not name. Either layout.
pub fn recorded_peer(record_data: &[u8], eid: u32) -> Option<[u8; 20]> {
    let at = PEER_RECORD_AT;
    let count = *record_data.get(at + 20)? as usize;
    let token: [u8; 20] = if per_peer_record(record_data)? {
        let entries = record_data.get(at + PEER_RECORD_HEAD..at + PEER_RECORD_HEAD + PEER_ENTRY_LEN * count)?;
        let entry = entries.chunks(PEER_ENTRY_LEN).find(|c| u16::from_le_bytes([c[0], c[1]]) as u32 == eid)?;
        entry[2..].try_into().ok()?
    } else {
        let eids = record_data.get(at + PEER_RECORD_HEAD..at + PEER_RECORD_HEAD + 2 * count)?;
        if !eids.chunks(2).any(|c| u16::from_le_bytes([c[0], c[1]]) as u32 == eid) {
            return None;
        }
        record_data.get(at..at + 20)?.try_into().ok()?
    };
    (token != [0u8; 20]).then_some(token)
}

/* --------------------------------------------------------------- the v2 tail (factory v2)

   A record made by `launch_v2` or `launch_self` carries, AFTER its peer record, what v1 records
   do not: who really launched (the record's own `creator` is the PAYEE, the fee stream), the
   supply mode and the opening market cap, and for SUPPLY_TOTAL its bridge reserve. After the
   peers, so `LAUNCHED_SLOT_AT`, `PEER_RECORD_AT`, `recorded_peer` and `open_bridge` read a v2
   record exactly as a v1 one.

       tag 0x02 | creator 32 | supply_mode u8 | market_cap_usd u32 LE
       SUPPLY_TOTAL only: total u64 LE | reserve 32 | minter 32 | reserve authority bump | minter bump

   A record is v2 when the bytes after its peers are exactly one of these two lengths and start
   with the tag: a v1 record has nothing after its peers, or the 11-byte reserve record of the
   launches made before (`reserve::read_reserve_record`), so the two cannot be mistaken.          */

/// The tag a v2 tail starts with.
pub const V2_TAIL_TAG: u8 = 0x02;
/// A SUPPLY_SLICE launch's tail: the tag, the creator, the mode and the market cap.
/// (and, last in either layout, the native claim's pending ledger: lamports owed to a payee that
/// could not yet hold them, kept in the record's own balance -- `fees::claim_fees_native`).
pub const V2_TAIL_SLICE_LEN: usize = 1 + 32 + 1 + 4 + 8;
/// A SUPPLY_TOTAL launch's: and the total, the reserve, the minter and their bumps.
pub const V2_TAIL_TOTAL_LEN: usize = 1 + 32 + 1 + 4 + 8 + 32 + 32 + 1 + 1 + 8;

/// The tail's length for a supply mode.
pub const fn v2_tail_len(supply_mode: u8) -> usize {
    if supply_mode == crate::price::SUPPLY_TOTAL {
        V2_TAIL_TOTAL_LEN
    } else {
        V2_TAIL_SLICE_LEN
    }
}

/// A SUPPLY_TOTAL launch's bridge reserve, as its record keeps it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReserveV2 {
    /// What the Solana mint's supply is held to: the launch total, fixed at launch (a chain added
    /// later brings no supply of its own).
    pub total: u64,
    /// The token account holding the reserve: the launch's `token_a` account, owned by the
    /// launch's record, which signs only `rebalance`'s burn.
    pub reserve: Pubkey,
    /// The mint authority: a 1-of-2 Token-2022 multisig {OFT store, AUTHORITY} at
    /// `PDA(["minter", record])`, made by the launch.
    pub minter: Pubkey,
    /// The record's own bump (what signs the reserve's burn).
    pub reserve_bump: u8,
    pub minter_bump: u8,
}

impl ReserveV2 {
    /// A LOCKBOX launch's (every SUPPLY_TOTAL launch since 2026-10-24): `reserve` is its OFT
    /// store's escrow, where the other chains' share is locked (`launch_leg::lock_in_escrow`), and
    /// `minter` is the zero key -- the mint has no authority, and its supply is the total for
    /// good. Launches before it keep a real reserve and minter, and `rebalance`.
    pub fn is_lockbox(&self) -> bool {
        self.minter == Pubkey::default()
    }
}

/// What a v2 record says after its peers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V2Tail {
    /// Who launched: the dev buy's and the launch's credit. The record's `creator` is the payee.
    pub creator: Pubkey,
    pub supply_mode: u8,
    pub market_cap_usd: u32,
    pub reserve: Option<ReserveV2>,
    /// Lamports a native claim owes the payee and keeps in the record until the payee can hold
    /// them (`fees::claim_fees_native`).
    pub pending_native: u64,
}

/// The v2 tail of a launch's record, or None for a v1 record (or data that is not a record).
pub fn read_v2_tail(record_data: &[u8]) -> Option<V2Tail> {
    if !per_peer_record(record_data)? {
        return None;
    }
    let at = peer_record_end(record_data)?;
    let tail = record_data.get(at..)?;
    if tail.first() != Some(&V2_TAIL_TAG) || tail.len() < V2_TAIL_SLICE_LEN {
        return None;
    }
    let supply_mode = tail[33];
    let len = match supply_mode {
        crate::price::SUPPLY_SLICE => V2_TAIL_SLICE_LEN,
        crate::price::SUPPLY_TOTAL => V2_TAIL_TOTAL_LEN,
        _ => return None,
    };
    if tail.len() != len {
        return None;
    }
    let key = |at: usize| Pubkey::new_from_array(tail[at..at + 32].try_into().unwrap());
    let reserve = (supply_mode == crate::price::SUPPLY_TOTAL).then(|| ReserveV2 {
        total: u64::from_le_bytes(tail[38..46].try_into().unwrap()),
        reserve: key(46),
        minter: key(78),
        reserve_bump: tail[110],
        minter_bump: tail[111],
    });
    Some(V2Tail {
        creator: key(1),
        supply_mode,
        market_cap_usd: u32::from_le_bytes(tail[34..38].try_into().unwrap()),
        reserve,
        pending_native: u64::from_le_bytes(tail[len - 8..len].try_into().unwrap()),
    })
}

/// Set a v2 record's pending native payout (the last eight bytes of its tail).
pub fn write_pending_native(record_data: &mut [u8], lamports: u64) -> Option<()> {
    read_v2_tail(record_data)?;
    let end = record_data.len();
    record_data[end - 8..].copy_from_slice(&lamports.to_le_bytes());
    Some(())
}

/// Write a v2 tail at `at` (the end of the peer record) of a record's data.
pub fn write_v2_tail(record_data: &mut [u8], at: usize, t: &V2Tail) {
    let d = &mut record_data[at..];
    d[0] = V2_TAIL_TAG;
    d[1..33].copy_from_slice(t.creator.as_ref());
    d[33] = t.supply_mode;
    d[34..38].copy_from_slice(&t.market_cap_usd.to_le_bytes());
    if let Some(r) = t.reserve {
        d[38..46].copy_from_slice(&r.total.to_le_bytes());
        d[46..78].copy_from_slice(r.reserve.as_ref());
        d[78..110].copy_from_slice(r.minter.as_ref());
        d[110] = r.reserve_bump;
        d[111] = r.minter_bump;
    }
    let end = v2_tail_len(t.supply_mode);
    d[end - 8..end].copy_from_slice(&t.pending_native.to_le_bytes());
}

/// A listed launcher. Its existence is the whole of its meaning; see `LAUNCHER_SEED`.
#[account]
#[derive(InitSpace)]
pub struct Launcher {
    pub launcher: Pubkey,
    pub bump: u8,
}

/// One payer's fee for one launch. The account's own lamports are the money: `amount` above the
/// rent it needs to exist.
#[account]
#[derive(InitSpace)]
pub struct FeePayment {
    pub launch_id: [u8; 32],
    pub payer: Pubkey,
    /// Until the launch: everything this payer has put towards it -- the fee, and above the fee
    /// the creator's dev buy. Once settled: the FEE, which is what is left. The launch took the
    /// creator's dev buy out of this account -- into the pool, or back to their wallet when it
    /// could not be made -- and wrote the fee it named here. A payment that was not the
    /// creator's is the fee whole, and keeps the figure it had (`dev_buy`). So a settled
    /// `amount` above the fee the launch named means its excess was settled as the fee.
    pub amount: u64,
    /// When they first paid. What `RECLAIM_AFTER` and a quote's expiry are measured against.
    pub at: i64,
    /// Whether this payment's launch exists. Final: a settled payment is the platform's, and can
    /// no longer be refunded, reclaimed or added to. What it holds by then is the fee alone.
    pub settled: bool,
    pub bump: u8,
}

// -------------------------------------------------------------------- accounts

#[derive(Accounts)]
#[instruction(launcher: Pubkey)]
pub struct AddLauncher<'info> {
    #[account(
        init,
        payer = admin,
        space = 8 + Launcher::INIT_SPACE,
        seeds = [LAUNCHER_SEED, launcher.as_ref()],
        bump
    )]
    pub entry: Account<'info, Launcher>,
    #[account(mut, address = ADMIN @ SplitterError::NotAdmin)]
    pub admin: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RemoveLauncher<'info> {
    #[account(
        mut,
        close = admin,
        seeds = [LAUNCHER_SEED, entry.launcher.as_ref()],
        bump = entry.bump
    )]
    pub entry: Account<'info, Launcher>,
    #[account(mut, address = ADMIN @ SplitterError::NotAdmin)]
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(launch_id: [u8; 32])]
pub struct PayFee<'info> {
    /// Created by the first payment and added to by the rest. `init_if_needed` is safe here
    /// because the seeds include the payer: nobody else can reach this account to initialise it
    /// first, and a second call only ever adds.
    #[account(
        init_if_needed,
        payer = payer,
        space = 8 + FeePayment::INIT_SPACE,
        seeds = [FEE_SEED, launch_id.as_ref(), payer.key().as_ref()],
        bump
    )]
    pub fee: Account<'info, FeePayment>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct WithdrawFee<'info> {
    #[account(
        mut,
        close = admin,
        seeds = [FEE_SEED, fee.launch_id.as_ref(), fee.payer.as_ref()],
        bump = fee.bump
    )]
    pub fee: Account<'info, FeePayment>,
    #[account(mut, address = ADMIN @ SplitterError::NotAdmin)]
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
pub struct RefundFee<'info> {
    #[account(
        mut,
        close = payer,
        has_one = payer,
        seeds = [FEE_SEED, fee.launch_id.as_ref(), fee.payer.as_ref()],
        bump = fee.bump
    )]
    pub fee: Account<'info, FeePayment>,
    /// CHECK: whoever paid, taken from the payment itself by `has_one`. Never a signer here.
    #[account(mut)]
    pub payer: UncheckedAccount<'info>,
    #[account(address = ADMIN @ SplitterError::NotAdmin)]
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
pub struct ReclaimFee<'info> {
    #[account(
        mut,
        close = payer,
        has_one = payer,
        seeds = [FEE_SEED, fee.launch_id.as_ref(), fee.payer.as_ref()],
        bump = fee.bump
    )]
    pub fee: Account<'info, FeePayment>,
    #[account(mut)]
    pub payer: Signer<'info>,
}

// --------------------------------------------------------------------- events

#[event]
pub struct LauncherSet {
    pub launcher: Pubkey,
    pub allowed: bool,
}

#[event]
pub struct FeePaid {
    pub launch_id: [u8; 32],
    pub payer: Pubkey,
    pub lamports: u64,
    pub total: u64,
}

#[event]
pub struct FeeSettled {
    pub launch_id: [u8; 32],
    pub payer: Pubkey,
    pub lamports: u64,
}

#[event]
pub struct FeeWithdrawn {
    pub launch_id: [u8; 32],
    pub payer: Pubkey,
    pub lamports: u64,
}

#[event]
pub struct FeeRefunded {
    pub launch_id: [u8; 32],
    pub payer: Pubkey,
    pub lamports: u64,
}

#[event]
pub struct FeeReclaimed {
    pub launch_id: [u8; 32],
    pub payer: Pubkey,
    pub lamports: u64,
}

/// The redirection events, named and shaped as `FeeSplitter.sol` emits them: who held the stream,
/// and who it was offered to or passed to. A creator's stream is one launch's (`record`); the
/// platform's is every launch's.
#[event]
pub struct CreatorProposed {
    pub record: Pubkey,
    pub from: Pubkey,
    pub to: Pubkey,
}

#[event]
pub struct CreatorChanged {
    pub record: Pubkey,
    pub from: Pubkey,
    pub to: Pubkey,
}

/// Emitted instead of `CreatorProposed` when it was the ADMIN that moved a creator's stream.
/// Separate on purpose: the two are different facts about who did what.
#[event]
pub struct AdminProposedCreator {
    pub record: Pubkey,
    pub admin: Pubkey,
    pub from: Pubkey,
    pub to: Pubkey,
}

#[event]
pub struct PlatformProposed {
    pub from: Pubkey,
    pub to: Pubkey,
}

/// Emitted instead of `PlatformProposed` when the admin, not the platform, proposed.
#[event]
pub struct AdminProposedPlatform {
    pub admin: Pubkey,
    pub from: Pubkey,
    pub to: Pubkey,
}

#[event]
pub struct PlatformChanged {
    pub from: Pubkey,
    pub to: Pubkey,
}

#[error_code]
pub enum SplitterError {
    #[msg("fee must be between 0.3% and 5%")]
    FeeOutOfRange,
    #[msg("venue lp share must be between 1 and 10000 bps")]
    InvalidVenueShare,
    #[msg("this fee and venue share cannot cover the platform's 0.2% of volume")]
    PlatformCutUnpayable,
    #[msg("nothing to release")]
    NothingToRelease,
    #[msg("address cannot be the default pubkey")]
    ZeroAddress,
    #[msg("creator and platform cannot be an address this program holds: the launch's record, the fee owner, AUTHORITY, the platform record or a fee account")]
    PartyIsSplitter,
    /// No longer raised (it was the per-launch splitter's). Kept so that every later error keeps its number.
    #[msg("fees are waiting but no side with a balance was given both of its destinations")]
    MissingDestination,
    #[msg("only the platform admin may redirect another party's stream")]
    NotAdmin,
    #[msg("a fee payment must be more than nothing")]
    NothingToPay,
    #[msg("fee total overflows")]
    Overflow,
    #[msg("these accounts are not this launch's")]
    NotThisLaunch,
    #[msg("this payment is settled: its launch exists")]
    AlreadySettled,
    #[msg("this payment is not settled, so it is still its payer's")]
    NotSettled,
    #[msg("too early to reclaim: the platform still has time to launch or refund")]
    TooEarlyToReclaim,
    #[msg("name, symbol and uri must each be present and within their limits")]
    BadMetadata,
    #[msg("a launch needs a slice, a price inside the range, and liquidity")]
    NothingToLaunch,
    #[msg("peers must be strictly ascending by endpoint id, one account per id")]
    PeersNotAscending,
    #[msg("that is not the program this launch calls")]
    WrongProgram,
    #[msg("the position's liquidity is not all permanently locked")]
    NotLocked,
    #[msg("the launcher's own quote-asset account does not exist; create it once")]
    MissingQuoteAccount,
    #[msg("a route must set every value itself: zero means LayerZero's changeable default")]
    RouteInheritsDefaults,
    #[msg("a route's verifier lists must be ascending, distinct and consistent with its threshold")]
    RouteVerifiersMalformed,
    #[msg("each direction of a route must need at least two verifiers")]
    RouteHasTooFewVerifiers,
    #[msg("the gas floor must be between 1 and 1,000,000")]
    GasFloorOutOfRange,
    #[msg("that is not this program's route for that chain")]
    NotThisRoute,
    #[msg("that is not the store's record of its peer on that chain")]
    NotThisPeer,
    #[msg("name at least one chain, with its ten accounts")]
    NothingToOpen,
    /// No longer raised (it was the per-launch splitter's). Kept so that every later error keeps its number.
    #[msg("a splitter pays out its pool's two assets and nothing else")]
    NotThePoolsAssets,
    #[msg("the liquidity given does not put the whole slice in the pool")]
    SliceNotPooled,
    /// Was `MintAddressDoesNotEndIn1111`, when the ending was `1111`: the same number, the same refusal.
    #[msg("the mint this seed and nonce derive does not end in 6ea")]
    MintAddressLacksPangeaEnding,
    #[msg("the bridge has collected no fee to withdraw")]
    NoBridgeFeeToWithdraw,
    #[msg("a bridge's fees go to the platform's associated token account and nowhere else")]
    NotThePlatformsTokenAccount,
    #[msg("this payment is within a day of being its payer's to reclaim, so a launch no longer settles it")]
    PaymentTooOldToSettle,
    #[msg("a route's executor and verifiers must each be given, and be a config account that exists: not a program, not a wallet")]
    RouteNamesNoSuchAccount,
    #[msg("the payment holds less than the fee this launch was told to settle")]
    PaymentBelowLaunchFee,
    #[msg("a launch that is handed a payment must say what fee it expects to find in it")]
    LaunchFeeNotNamed,
    #[msg("a launch that names a fee must be handed the payment it is to settle")]
    LaunchFeeWithoutPayment,
    // The four below are no longer raised: a dev buy that cannot be made is handed back to the
    // creator, and a third party's excess is settled as the fee, rather than either failing the
    // launch (`dev_buy`, "a dev buy never stops a launch"). They stay, in place, so that the
    // number of every error -- theirs included, 6037 to 6040 -- is what it was.
    /// No longer raised: a payment above the fee that is not the creator's settles as the fee.
    #[msg("a payment above the fee is a dev buy, and only the creator's own payment may carry one")]
    DevBuyNotTheCreators,
    /// No longer raised: without the account the dev buy goes back to the creator.
    #[msg("a launch with a dev buy needs the creator's wrapped-SOL account to exist already; their payment transaction makes it")]
    DevBuyNeedsQuoteAccount,
    /// No longer raised: the dev buy goes back to the creator.
    #[msg("the dev buy's amount is outside what this pool's arithmetic can price")]
    DevBuyCannotBeQuoted,
    /// No longer raised: the dev buy goes back to the creator.
    #[msg("the dev buy is more than this pool can sell: it would carry the price past the top of the range")]
    DevBuyMoreThanThePoolSells,
    // Appended, so that no number before them moves.
    /// 6041: `open_bridge` was asked to apply a route the admin has edited since this token
    /// launched. Only the admin may do that; anyone else gets the route as it stood at the launch.
    #[msg("this route was edited after the token launched; only the admin may open it with the new settings")]
    RouteEditedAfterLaunch,
    /// 6042: a route value no working route can have -- a message size below an OFT transfer's,
    /// or more confirmations than any chain will ever reach.
    #[msg("a route's message size must fit an OFT transfer and its confirmations must be reachable")]
    RouteValueOutOfRange,
    /// 6043: the launch's quote asset is neither wrapped SOL nor an enabled entry of the allowlist.
    #[msg("a launch pairs against wrapped SOL or an asset the admin has allowlisted, and this is neither")]
    QuoteAssetNotAllowed,
    /// 6044: `set_quote_asset` refused a mint a launch could not pair against (see `quote`).
    #[msg("this mint cannot be a quote asset: a transfer fee, non-transferable, a hook program, an unknown extension, or Meteora's badge missing")]
    QuoteAssetUnsupported,
    /// 6045: the quote asset is paused, creates its accounts frozen, has acquired a transfer-hook
    /// program, or has lost Meteora's badge since it was allowlisted.
    #[msg("the quote asset is paused, frozen by default, hooked, or without Meteora's badge: no launch can open a pool against it now")]
    QuoteAssetUnavailable,
    /// 6046: a route was asked to be opened to a chain whose peer does not exist, and the launch
    /// recorded no peer there to create it from.
    #[msg("the launch named no peer on this chain: there is no route to open")]
    PeerNotRecorded,
    /// 6047: the account a claim names as the platform's is not the platform's, or a platform
    /// proposal came from neither the platform nor the admin.
    #[msg("not the platform")]
    NotThePlatform,
    /// 6048: `open_bridge` named a route that is already open: its peer exists, and the route's
    /// settings were pinned when it opened.
    #[msg("this route is already open")]
    RouteAlreadyOpen,
    /// 6049: the launch's price snapshot is not the price signer's -- for this launch, its peers,
    /// its fee and slice, and a $3,000 opening -- or no price signer is set. See `price`.
    #[msg("the launch's price is not signed by the price signer for this launch at a $3,000 opening")]
    PriceNotSigned,
    /// 6050: the price snapshot's deadline has passed, or is more than an hour away.
    #[msg("the price snapshot has expired, or its deadline is more than an hour away")]
    PriceExpired,
    /// 6051: the signed price of the quote asset is outside the band the admin set for the asset
    /// the launch pairs with (or no band is set); or the prices give an opening the pool cannot
    /// hold -- zero, outside Meteora's range, or liquidity past 128 bits; or a band an admin tried
    /// to set is not one (zero, or its least not below its most).
    #[msg("the signed prices give an opening price the pool cannot take")]
    PriceOutOfRange,
    /// 6052: the launch's supply (its slice on each of its chains) is not a whole number of
    /// tokens, or is nothing, so it has no $3,000 opening. The name every implementation of the
    /// opening price gives it (test/fixtures/opening-price-vector.json).
    #[msg("the launch's supply is not a whole number of tokens, so it has no opening price")]
    SupplyNotWholeTokens,
    /// 6053: the launch's reserve is not armed yet: `arm` has to run before its bridge opens or
    /// it can be rebalanced. See `reserve`.
    #[msg("the launch's reserve is not armed yet")]
    NotArmed,
    /// 6054: `arm` has run for this launch already (its mint no longer answers to the program's
    /// authority alone, or its record says armed).
    #[msg("the launch's reserve is armed already")]
    AlreadyArmed,
    /// 6055: the launch's record keeps no reserve: a launch made before the reserve existed.
    #[msg("this launch has no reserve")]
    NoReserve,
    /// 6056: a launch's peer mask names no chain: every launch is on at least one EVM chain
    /// besides Solana. See `Peers`.
    #[msg("the launch names no peer chain")]
    NoPeers,
    /// 6057: `launch_cosigned` without the creator's signature. A co-signed launch is paid for by
    /// its creator, so the creator signs it. See `launch_leg`, "a co-signed launch".
    #[msg("a co-signed launch needs the creator's signature")]
    CreatorMustSign,
    /// 6058: `launch_cosigned` whose creator is the launcher itself. That is a plain `launch`.
    #[msg("a co-signed launch's creator cannot be the launcher")]
    CreatorIsLauncher,
    /// 6059: a co-signed launch did not leave the launcher whole: what the launcher fronted was
    /// not paid back to it by the creator in the same instruction.
    #[msg("a co-signed launch must leave the launcher whole")]
    LauncherNotRepaid,
    /// 6060: a co-signed launch would charge its creator more than `COSIGNED_LAUNCH_RENT_BOUND`
    /// in rent: more than the creator was told the launch could cost.
    #[msg("a co-signed launch's rent is over its bound")]
    CosignedRentOverBound,
    // ---- factory v2 (docs/factory-v2.md), appended so that no number before them moves.
    /// 6061: a v2 snapshot's market cap is outside [$3,000, $500,000] a chain.
    #[msg("the opening market cap must be between $3,000 and $500,000 a chain")]
    MarketCapOutOfRange,
    /// 6062: a supply mode that is neither SUPPLY_SLICE nor SUPPLY_TOTAL.
    #[msg("unknown supply mode")]
    UnknownSupplyMode,
    /// 6063: the signed terms name no fee: every launch is paid (D5).
    #[msg("a launch's terms must name a fee above nothing")]
    FeeMinZero,
    /// 6064: the terms name a fee chain that is not one of the launch's legs.
    #[msg("the fee's chain is not one of the launch's chains")]
    FeeChainNotALeg,
    /// 6065: the fee is due on Solana, and no payment for this launch holding at least it was given.
    #[msg("the launch's fee is due on Solana and has not been paid in full")]
    LaunchUnpaid,
    /// 6066: a payment was given to a launch whose fee is due on another chain, and it is not the
    /// creator's (only the creator's may carry a dev buy here).
    #[msg("the fee is due on another chain: only the creator's own payment may be given, for a dev buy")]
    PaymentNotTheCreators,
    /// 6067: the record is not a v2 launch's (no v2 tail), or is the wrong kind for this instruction.
    #[msg("this is not a launch made by launch_v2 or launch_self")]
    NotV2Record,
    /// 6068: `propose_creator` on a v2 record: only the admin moves a v2 payee (D10).
    #[msg("a v2 launch's payee is moved by the admin only")]
    PayeeMovedByAdminOnly,
    /// 6069: `launch_self` must be signed and paid by the creator alone, and names no launcher.
    #[msg("a self-launch is signed and paid by its creator, and names no launcher")]
    SelfLaunchSigner,
    /// 6070: `launch_v2` needs the payer's launcher listing.
    #[msg("launch_v2 is sent by a listed launcher")]
    NotALauncher,
    /// 6071: `add_peer_v2` for a chain the launch already names, or one the program does not know.
    #[msg("that chain is already one of the launch's, or is not a chain the program knows")]
    PeerNotAddable,
    /// 6072: `claim_fees_native` is for launches paired against wrapped SOL.
    #[msg("native fees are paid for wrapped-SOL launches only")]
    NotNativeQuote,
    /// 6073: a native payout would leave its recipient below the rent-exempt minimum.
    #[msg("the recipient cannot hold this payout yet: it would be left below the rent-exempt minimum")]
    RecipientCannotHold,
    /// 6074: a SUPPLY_TOTAL `launch_v2` or `launch_self` not given its minter, `PDA(["minter", record])`.
    #[msg("a SUPPLY_TOTAL launch needs its minter account, PDA([\"minter\", record])")]
    MinterNotGiven,
    /// 6075: a v2 launch's account given for the creator's dev-buy tokens is not the one it derives.
    #[msg("the dev-buy token account is not this launch's")]
    WrongDevBuyAccount,
    /// 6076: a v2 launch's price could not be read from the wire (a price past 128 bits).
    #[msg("a v2 launch's price is malformed")]
    BadWirePrice,
    /// 6077: `claim_fees` on a v2 launch paired against wrapped SOL: it is paid natively only.
    #[msg("a v2 wrapped-SOL launch's fees are paid natively: claim_fees_native")]
    ClaimNatively,
    /// 6078: a party (a payee, the platform) the runtime will not let a transaction write: a sysvar,
    /// a builtin or loader, or a program the launch or a claim calls.
    #[msg("the address cannot be written by a transaction: a sysvar, builtin or called program")]
    PartyReserved,
    /// 6079: `claim_fees` would pay an account of this program (a tokenomics account) in an asset
    /// that is not wrapped SOL, or an account of the token programs, cp-amm, the OFT program or
    /// LayerZero's endpoint in any asset -- into an associated account nothing can move -- or was
    /// not given the record's creator (after the venue's accounts) to show it is neither. The whole
    /// claim, the creator's share and the platform's, waits in the pool until the admin moves the
    /// stream: `admin_set_payee` on a v2 launch, `admin_propose_creator` then `accept_creator` on a
    /// v1 one.
    #[msg("the payee cannot spend this asset: a token, pool, OFT or LayerZero account, or this program's outside wrapped SOL")]
    PayeeCannotSpendAsset,
    /// 6080: `claim_fees_native` given a payee that is a plain wallet (system-owned, no data, on the
    /// curve, or the incinerator) read-only: its share would be deferred at the cranker's choice.
    #[msg("the payee is a wallet and must be sent writable")]
    PayeeNotWritable,
    /// 6081: `claim_fees_native` for a payee that is a tokenomics account bound to the launch, not
    /// given its wrapped-SOL vault, writable, after the venue's accounts.
    #[msg("the payee is a tokenomics account: give its wrapped-SOL vault, writable, after the venue's accounts")]
    TokenomicsVaultNotGiven,
    /// 6082: a SUPPLY_TOTAL `launch_v2` or `launch_self` not given its store's `TvlMark`,
    /// `PDA(["TvlMark", store])` under the OFT program, in the minter's place.
    #[msg("a SUPPLY_TOTAL launch needs its store's TvlMark, PDA([\"TvlMark\", store]) under the OFT program")]
    LockboxMarkNotGiven,
    /// 6083: `rebalance` for a SUPPLY_TOTAL launch whose other chains' share is locked in its OFT
    /// store's escrow (`launch_leg::lock_in_escrow`): its mint has no authority and its supply is
    /// the total for good, so there is nothing to rebalance.
    #[msg("a lockbox launch: its supply is locked in the OFT escrow, there is no reserve to rebalance")]
    Lockbox,
    /// 6084: a SUPPLY_TOTAL launch with no other chain: nothing beyond its slice to lock.
    #[msg("a SUPPLY_TOTAL launch on Solana alone has nothing to lock for other chains")]
    NothingToLock,
    // 6085-6087 meant BadPoolBps / TurboDevBuyAccountNotGiven / TurboNotLocked (factory v3's turbo)
    // until v3c. Turbo never shipped: no deployed program ever returned those meanings, and no client
    // maps them (audit r1 I-2, checked over web/, script/, solana/client/, worker/). Codes are stable
    // from here on.
    /// 6085: `open_bridge` on a v3 OFT store (docs/v3-gap-fee-spec.md §10.3) whose official
    /// pool has not been set yet (`set_gap_pool`, by the gap registrar): until it is, every
    /// transfer would cross with no price, so no route opens.
    #[msg("a v3 store's gap pool is not set yet: set_gap_pool first")]
    GapPoolNotSet,
    /// 6086: a creator self-launch's own terms break EVM's `checkSelfLaunch` rules (BadTerms 11-13):
    /// `selfUntil` too close to the deadline, a leg fee or EVM payer of zero, or not one per leg.
    #[msg("a self-launch's selfUntil or leg fees are not valid")]
    BadSelfTerms,
    /// 6087: a creator self-launch across chains (selfUntil != 0) is sent by our launcher through
    /// `launch_v2` (owner 2026-10-28, option b), never by `launch_self`.
    #[msg("a self-launch across chains is sent by the launcher (launch_v2), not launch_self")]
    SelfTermsNeedTheLauncher,
    /// 6088: a launch naming `PDA(["gap_v3"])` in its dev-buy place (a v3 launch, signed with the v3
    /// terms hash) while v3 launches are not enabled (`set_gap_v3_launches`). Any other account there is
    /// not the switch (`price::gap_v3_switch` is None): the launch is v2 and that account is never read.
    #[msg("v3 launches are not enabled (set_gap_v3_launches)")]
    GapV3NotEnabled,
    /// 6089: `open_bridge` was given a route version that is not the one in force at the token's
    /// launch (a newer one was made by then), or a version pair it did not use.
    #[msg("not the route version in force at the launch")]
    RouteVersionNotInForce,
    /// 6090: `set_bridge_fee` above `MAX_BRIDGE_FEE_BPS` (50).
    #[msg("a bridge fee is 0 to 50 bps")]
    BridgeFeeOutOfRange,
    /// 6091: `set_bridge_fee` on a live (v1/v2) store: only a v3 store's fee is the admin's.
    #[msg("only a v3 store's bridge fee may be set")]
    NotAV3Store,
    /// 6092: `set_gas_floor` on a route that is not open (its peer does not exist yet).
    #[msg("the route is not open")]
    RouteNotOpen,
    /// 6093: `set_gas_floor` on a v3 store below `EVM_V3_LZ_RECEIVE_GAS_MIN` (Lead #3 M-1): every v3
    /// receive on the EVM side would revert GapGasTooLow at the executor.
    #[msg("a v3 store's gas floor is at least the EVM v3 receive's")]
    GasFloorBelowV3Floor,
    /// 6094: `set_v3_min_market_cap` outside [$600, $3,000] a chain (owner 2026-10-31).
    #[msg("the v3 minimum opening market cap is outside its bounds")]
    V3MinMarketCapOutOfBounds,
    /// 6095: a v3 launch (naming `PDA(["gap_v3"])`) with SUPPLY_TOTAL: v3 is SUPPLY_SLICE only
    /// (owner 2026-10-31, as PriceAttestorV3 `SupplyModeNotV3`).
    #[msg("v3 launches are SUPPLY_SLICE only")]
    SupplyTotalNotInV3,
}

#[cfg(test)]
mod tests {
    use super::*;

    const EVM: u16 = 10_000;
    const MET: u16 = METEORA_LP_SHARE_BPS;

    /// At a 1% fee on a venue that skims nothing, the platform's 0.2% of volume is a fifth of the
    /// fee -- the same 80/20 the EVM tests assert.
    #[test]
    fn one_percent_on_evm_is_eighty_twenty() {
        assert_eq!(platform_share(1_000, 100, EVM), 200);
    }

    /// On a venue that skims nothing: a fifth of the fee from 1% up, and the 0.2% floor below.
    #[test]
    fn the_platform_takes_a_fifth_of_the_fee_and_never_less_than_the_floor() {
        assert_eq!(platform_share(1_000, 500, EVM), 200); // 5% fee -> a fifth of it (it was a twenty-fifth)
        assert_eq!(platform_share(1_000, 200, EVM), 200); // 2% fee -> a fifth
        assert_eq!(platform_share(1_000, 100, EVM), 200); // 1% fee -> a fifth, and the floor: they agree
        assert_eq!(platform_share(900, 30, EVM), 600); // 0.3% -> the floor: two thirds of the fee
        assert_eq!(platform_share(1_000, 50, EVM), 400); // 0.5% -> the floor: two fifths
    }

    /// The table the rule was agreed as, in shares of VOLUME, on Meteora: the platform's cut, the
    /// venue's and the creator's of a million units traded at each fee. Exact at every one.
    #[test]
    fn the_agreed_table_as_shares_of_volume_on_meteora() {
        const VOLUME: u64 = 1_000_000_000;
        // (fee bps, platform, Meteora, creator) in hundredths of a basis point of volume
        for (fee_bps, platform, venue, creator) in [(30u16, 2_000u64, 600u64, 400u64), (50, 2_000, 1_000, 2_000), (100, 2_000, 2_000, 6_000), (200, 4_000, 4_000, 12_000), (500, 10_000, 10_000, 30_000)] {
            let fee = VOLUME / 10_000 * fee_bps as u64;
            let venue_takes = fee / 5;
            let arrives = fee - venue_takes;
            let to_platform = platform_share(arrives, fee_bps, MET);
            let unit = VOLUME / 1_000_000; // a hundredth of a basis point of the volume
            assert_eq!(to_platform, platform * unit, "{fee_bps} bps: the platform");
            assert_eq!(venue_takes, venue * unit, "{fee_bps} bps: Meteora");
            assert_eq!(arrives - to_platform, creator * unit, "{fee_bps} bps: the creator");
            assert_eq!(to_platform + (arrives - to_platform) + venue_takes, fee);
        }
    }

    /// Either side of 1%, where the floor stops binding: the platform's share of what ARRIVES
    /// from Meteora is a quarter from 1% up and more below, with no step between them.
    #[test]
    fn the_boundary_at_one_percent() {
        let arrives: u64 = 792_000_000_000; // divisible by every denominator below
        assert_eq!(platform_share(arrives, 100, MET), arrives / 4);
        assert_eq!(platform_share(arrives, 101, MET), arrives / 4);
        assert_eq!(platform_share(arrives, 500, MET), arrives / 4);
        // 99 bps: 20 bps of volume out of the 79.2 that arrive.
        assert_eq!(platform_share(arrives, 99, MET), arrives / 792 * 200);
        assert!(platform_share(arrives, 99, MET) > arrives / 4);
        // And as volume: the same 0.2% at 99 and at 100, and a hair more at 101.
        let volume = 10_000_000_000u64;
        let cut = |fee_bps: u16| platform_share(volume / 10_000 * fee_bps as u64 / 5 * 4, fee_bps, MET);
        assert_eq!((cut(99), cut(100), cut(101)), (20_000_000, 20_000_000, 20_200_000));
        // Never more than arrives, at any fee a launch may have, and exactly the rule at each.
        for fee_bps in MIN_FEE_BPS..=MAX_FEE_BPS {
            assert!(check_fee(fee_bps, MET).is_ok());
            let p = platform_share(arrives, fee_bps, MET) as u128;
            assert!(p <= arrives as u128);
            let rule = arrives as u128 * (2_000 * fee_bps as u128).max(200_000) / (fee_bps as u128 * 8_000);
            assert_eq!(p, rule, "{fee_bps} bps");
            assert!(p * 4 >= arrives as u128, "{fee_bps} bps: never under a quarter of what arrives");
        }
    }

    /// The point of `venue_lp_share_bps`. Same fee, same volume, a fifth less money arriving from
    /// Meteora -- and the platform is owed the identical cut of volume either way (0.2% at a 1% fee).
    #[test]
    fn platform_gets_the_same_cut_despite_meteoras_skim() {
        let volume: u64 = 1_000_000;
        let fee = volume / 100; // 1%
        let owed = volume * 20 / 10_000; // 0.2% of volume

        assert_eq!(platform_share(fee, 100, EVM), owed);
        assert_eq!(platform_share(fee * 80 / 100, 100, MET), owed);
    }

    /// Who absorbs Meteora's cut: the creator. Same nominal fee earns less here than on Base.
    #[test]
    fn creator_absorbs_the_venue_cut() {
        let fee: u64 = 1_000;
        let evm_creator = fee - platform_share(fee, 100, EVM);
        let arrived = fee * 80 / 100;
        let sol_creator = arrived - platform_share(arrived, 100, MET);
        assert!(sol_creator < evm_creator);
    }

    /// 0.25% is the true minimum on Meteora; the 0.3% floor is deliberate headroom.
    #[test]
    fn floor_is_the_binding_constraint_on_meteora() {
        assert!(check_fee(30, MET).is_ok());
        assert!(check_fee(29, MET).is_err());
        for fee in 1..25u16 {
            assert!(
                (fee as u128) * (MET as u128) < PLATFORM_FEE_BPS * BPS,
                "{fee} should be unpayable"
            );
        }
        assert!((25u128) * (MET as u128) >= PLATFORM_FEE_BPS * BPS);
    }

    #[test]
    fn fee_bounds_are_enforced() {
        assert!(check_fee(30, EVM).is_ok());
        assert!(check_fee(500, EVM).is_ok());
        assert!(check_fee(29, EVM).is_err());
        assert!(check_fee(501, EVM).is_err());
    }

    /// The test stack is another program with another admin: nothing of the live one's.
    #[test]
    #[cfg(feature = "test-stack")]
    fn the_test_stack_is_its_own_program_and_admin() {
        assert_eq!(crate::ID.to_string(), "87xyMm8CCqtCBRKqFU2JCMZ4F9vZctB2LXtLb7t6dhq1");
        assert_eq!(ADMIN.to_string(), "3d75Up71ScbFCHP3zcydYkQTYP6dc9f6wZD2XYQ35f5r");
        assert_ne!(crate::ID.to_string(), "Hb5uTppRbNxc3RjVRqTWqfdU3E3GiZyGYKccxYf9tUej", "not the live splitter");
        assert_ne!(ADMIN.to_string(), "7rYog4JusTy4CpwvFGPrRvWtcDrWatnA3SN3DRPuf6kM", "not the live admin");
        assert!(ADMIN.is_on_curve() && ADMIN != Pubkey::default() && ADMIN != crate::ID);
    }

    #[test]
    #[cfg(not(any(feature = "test-stack", feature = "rehearsal-admin")))]
    fn the_admin_constant_is_the_key_we_think_it_is() {
        // Pinned, because this constant is the only thing standing between any splitter's creator
        // stream and whoever can sign for ADMIN, and the only way to change it is a program
        // upgrade -- where a mistyped base58 string would compile, deploy, and silently hand that
        // power to an address nobody holds the key for. There is no setter to correct it with.
        assert_eq!(
            ADMIN.to_string(),
            "7rYog4JusTy4CpwvFGPrRvWtcDrWatnA3SN3DRPuf6kM",
            "ADMIN changed; this is a program upgrade, so confirm the new key is one we hold"
        );
        assert_ne!(ADMIN, Pubkey::default(), "the default pubkey has no private key");
        assert_ne!(ADMIN, crate::ID, "the program cannot sign for itself");
    }

    #[test]
    fn rejects_a_venue_share_that_cannot_cover_the_cut() {
        // A 0.3% fee with a venue keeping half leaves 0.15% of volume, short of 0.2%.
        assert!(check_fee(30, 5_000).is_err());
        assert!(check_fee(0, EVM).is_err());
    }

    /// Shares always sum to the whole balance, so nothing is ever stranded in the PDA.
    #[test]
    fn shares_sum_to_the_whole_balance() {
        for amount in [0u64, 1, 2, 7, 999, 1_000_000, u64::MAX / 4] {
            for fee in [30u16, 100, 250, 500] {
                for share in [EVM, MET] {
                    let p = platform_share(amount, fee, share);
                    assert!(p <= amount, "platform never over the batch");
                    let c = amount - p;
                    assert_eq!(c + p, amount);
                }
            }
        }
    }

    /// A dust amount must not round the platform's share up past the balance.
    #[test]
    fn tiny_amounts_are_safe() {
        assert_eq!(platform_share(1, 30, MET), 0);
        assert!(platform_share(1, 30, MET) <= 1);
        assert_eq!(platform_share(0, 100, EVM), 0);
    }

    /// Large balances must not overflow the intermediate multiplication.
    #[test]
    fn large_amounts_do_not_overflow() {
        let p = platform_share(u64::MAX, 500, EVM);
        assert!(p < u64::MAX);
        assert_eq!(p, (u64::MAX as u128 / 5) as u64, "a fifth of the fee at 5%");
        assert_eq!(platform_share(u64::MAX, 30, MET), ((u64::MAX as u128) * 200_000 / 240_000) as u64);
        assert_eq!(platform_share(u64::MAX, u16::MAX, 1), u64::MAX, "and clamped where a venue passes too little");
    }

    /// The discriminator must be exactly sha256("global:claim_position_fee")[..8]; a wrong one
    /// would call some other cp-amm instruction, or none.
    #[test]
    fn claim_discriminator_is_correct() {
        use anchor_lang::solana_program::hash::hash;
        let h = hash(b"global:claim_position_fee");
        assert_eq!(&h.to_bytes()[..8], &CLAIM_POSITION_FEE_DISCRIMINATOR);
    }

    #[test]
    fn parties_must_be_addresses_someone_can_sign_for() {
        let k = |n: u8| Pubkey::new_from_array([n; 32]);
        let (creator, platform, record, fee_owner, authority) = (k(1), k(2), k(3), k(4), k(5));
        let held = [record, fee_owner, authority];
        assert!(check_parties(&creator, &platform, &held).is_ok());
        // One address may hold both roles; that is the platform launching its own token.
        assert!(check_parties(&creator, &creator, &held).is_ok());

        assert!(check_parties(&Pubkey::default(), &platform, &held).is_err());
        assert!(check_parties(&creator, &Pubkey::default(), &held).is_err());
        for h in held {
            assert!(check_parties(&h, &platform, &held).is_err(), "creator {h}");
            assert!(check_parties(&creator, &h, &held).is_err(), "platform {h}");
        }
        // Nor anything a transaction cannot write (Solana audit round 2, B L-2).
        for r in RESERVED_ACCOUNTS.iter().chain([LZ_ENDPOINT_ID].iter()) {
            assert!(check_parties(r, &platform, &held).is_err(), "creator {r}");
            assert!(check_parties(&creator, r, &held).is_err(), "platform {r}");
        }
        assert!(check_parties(&crate::INCINERATOR, &platform, &held).is_ok(), "the incinerator is writable");
    }

    /// The reserved list, against the ids solana-program declares (a mistyped one would still be
    /// a valid address): every sysvar, every builtin and loader it names.
    #[test]
    fn the_reserved_list_is_the_runtimes() {
        use anchor_lang::solana_program as sp;
        let mut known = sp::sysvar::ALL_IDS.clone();
        known.extend([
            sp::sysvar::ID,
            sp::sysvar::epoch_rewards::ID,
            sp::sysvar::last_restart_slot::ID,
            sp::address_lookup_table::program::ID,
            sp::bpf_loader::ID,
            sp::bpf_loader_deprecated::ID,
            sp::bpf_loader_upgradeable::ID,
            solana_sdk::compute_budget::ID,
            sp::config::program::ID,
            sp::ed25519_program::ID,
            sp::feature::ID,
            sp::loader_v4::ID,
            sp::secp256k1_program::ID,
            sp::stake::config::ID,
            sp::stake::program::ID,
            sp::system_program::ID,
            sp::vote::program::ID,
            solana_sdk::native_loader::ID,
        ]);
        for k in &known {
            assert!(RESERVED_ACCOUNTS.contains(k), "{k} is reserved");
        }
        // The three solana-program 1.18 does not declare, besides the programs we call.
        assert_eq!(RESERVED_ACCOUNTS.len(), known.len() + 3 + 6);
        let mut unique = RESERVED_ACCOUNTS.to_vec();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), RESERVED_ACCOUNTS.len());
    }

    /* ------------------------------------------------------------------ the mint */

    /// The mint's address, pinned. The client derives this same PDA in JavaScript, and the two
    /// disagreeing would mean the transaction creates one account and the launch records another.
    /// The nonce is the one `solana/tools/mint-grind` found for this seed, and the same pair is
    /// pinned in solana/client/mint-nonce.test.mjs.
    #[test]
    #[cfg(not(feature = "test-stack"))] // pinned to the live program id
    fn the_mint_pda_is_derived_from_the_launch_seed_and_its_nonce() {
        let (mint, bump) = mint_address(&[0x5a; 32], 36_112);
        assert_eq!(mint.to_string(), "6sXi383ceSED3wCCvUcGTRZ3ZSaGU3apxnvTfWdgq6ea");
        assert_eq!(bump, 255, "the search only accepts the first bump tried");
        assert!(has_pangea_ending(&mint));
        // The nonce is four little-endian bytes, after the seed.
        let by_hand = Pubkey::find_program_address(&[b"mint", &[0x5a; 32], &[0x10, 0x8d, 0x00, 0x00]], &crate::ID).0;
        assert_eq!(by_hand, mint);
        // And it is not the derivation there used to be, from the seed alone.
        let old = Pubkey::find_program_address(&[MINT_SEED, &[0x5a; 32]], &crate::ID).0;
        assert_ne!(old, mint);
        assert_ne!(mint_address(&[0x5a; 32], 0).0, old, "a nonce of zero is still a nonce");
        // The neighbouring nonces are other addresses, and not ones a launch may use.
        for other in [36_111, 36_113, 0, u32::MAX] {
            let (m, _) = mint_address(&[0x5a; 32], other);
            assert_ne!(m, mint);
            assert!(!has_pangea_ending(&m), "{other}");
        }
    }

    /// The rule, against the text it is a rule about: for addresses whose base58 is known, and
    /// for thousands built to sit on every edge of it, `has_pangea_ending` says exactly what
    /// `to_string().ends_with(MINT_ENDING)` says.
    #[test]
    fn has_pangea_ending_is_what_the_base58_says() {
        // The one constant, and what is computed from it: 6 is base58's digit 5, e its 37, a its 33.
        assert_eq!((MINT_ENDING, MINT_ENDING_MODULUS, MINT_ENDING_REMAINDER), ("6ea", 58 * 58 * 58, 5 * 58 * 58 + 37 * 58 + 33));
        assert_eq!((MINT_ENDING_MODULUS, MINT_ENDING_REMAINDER), (195_112, 18_999));
        for (text, ends) in [
            ("6sXi383ceSED3wCCvUcGTRZ3ZSaGU3apxnvTfWdgq6ea", true),
            ("xFbhrWCVaFSyLhonmBV55wXXiNGLTxiXh6HAz2n96ea", true),
            // What the ending used to be, and addresses that end in ones.
            ("8HVK4SeooNhEaxEQVoCZTUgwpFJNC3nFbNxuBzvZ1111", false),
            ("11111111111111111111111111111111", false),
            ("Vote111111111111111111111111111111111111111", false),
            ("ComputeBudget111111111111111111111111111111", false),
            ("So11111111111111111111111111111111111111112", false),
            // Ordinary addresses.
            ("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", false),
            ("cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG", false),
            ("7rYog4JusTy4CpwvFGPrRvWtcDrWatnA3SN3DRPuf6kM", false),
            ("A5nKd6c5sYKvHWrfBvtaYbuSHwujhmoqrPuWchucnZX", false),
        ] {
            let key: Pubkey = text.parse().unwrap();
            assert_eq!(key.to_string(), text);
            assert_eq!(text.ends_with(MINT_ENDING), ends, "{text}");
            assert_eq!(has_pangea_ending(&key), ends, "{text}");
        }

        // A 256-bit number from a multiplier and an offset: `k * 58^3 + offset`, big-endian, with
        // `high` in its top eight bytes.
        let number = |k: u128, high: u64, offset: u64| -> Pubkey {
            let low = k * MINT_ENDING_MODULUS as u128 + offset as u128;
            let mut bytes = [0u8; 32];
            bytes[16..].copy_from_slice(&low.to_be_bytes());
            bytes[..8].copy_from_slice(&high.to_be_bytes());
            Pubkey::new_from_array(bytes)
        };
        const R: u64 = MINT_ENDING_REMAINDER;
        let d = [1u64, 58, 58 * 58];
        let mut state = 0x06ea_5a5a_06ea_5a5au64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let (mut yes, mut no) = (0, 0);
        for i in 0..20_000u64 {
            let k = next() as u128 * (next() % 1_000_003) as u128 + i as u128;
            // Exactly on the rule; off by one, two and fifty-seven in each of the three places (the
            // 6's, the e's, the a's); and one unit either side.
            let mut cases = vec![number(k, 0, R)];
            for place in d {
                for digit in [1u64, 2, 57] {
                    cases.push(number(k, 0, R + place * digit));
                }
            }
            cases.push(number(k, 0, R - 1));
            cases.push(number(k, 0, R + 1));
            // And numbers that fill all 32 bytes, which are on the rule only by chance.
            cases.push(number(k, next(), next() % MINT_ENDING_MODULUS));
            for key in cases {
                let text = key.to_string();
                assert_eq!(has_pangea_ending(&key), text.ends_with(MINT_ENDING), "{text}");
                if text.ends_with(MINT_ENDING) {
                    yes += 1;
                } else {
                    no += 1;
                }
            }
        }
        assert!(yes >= 20_000 && no >= 11 * 20_000, "{yes} that end in {MINT_ENDING} and {no} that do not");

        // The three places by name, on one number: one step up in each is 7ea, 6fa, 6eb.
        let on = number(123_456_789, 0, R);
        assert!(on.to_string().ends_with("6ea") && has_pangea_ending(&on));
        for (place, ending) in [(58 * 58, "7ea"), (58, "6fa"), (1, "6eb")] {
            let off = number(123_456_789, 0, R + place);
            assert!(off.to_string().ends_with(ending), "{off}");
            assert!(!has_pangea_ending(&off), "{off}");
        }
        // The ending is case-sensitive: E is base58's digit 13 and A its 9, other numbers altogether.
        for (offset, ending) in [(5 * 58 * 58 + 13 * 58 + 33, "6Ea"), (5 * 58 * 58 + 37 * 58 + 9, "6eA"), (5 * 58 * 58 + 13 * 58 + 9, "6EA")] {
            let off = number(123_456_789, 0, offset);
            assert!(off.to_string().ends_with(ending), "{off}");
            assert!(!has_pangea_ending(&off), "{off}");
        }
        // Small numbers, written with ones borrowed from their leading zero bytes. The remainder
        // itself is the smallest address on the rule -- thirty ones and then 6ea -- and nothing
        // below it is: not zero (all ones), and not the neighbours.
        let alone = number(0, 0, R);
        assert!(alone.to_string().ends_with("1116ea") && has_pangea_ending(&alone), "{alone}");
        for small in [0u64, 1, 57, 58, 3_363, 3_364, R - 1, R + 1, 195_111] {
            let key = number(0, 0, small);
            assert!(!has_pangea_ending(&key) && !key.to_string().ends_with(MINT_ENDING), "{small}");
        }
        // One whole modulus up: the same three characters under a 2.
        assert!(has_pangea_ending(&number(1, 0, R)));
        assert!(number(1, 0, R).to_string().ends_with("126ea"));
    }

    /// The public id of a launch is the hash of its secret seed, under a fixed domain. Pinned,
    /// because the client computes the same thing in JavaScript (`launchIdOf` in
    /// solana/client/splitter.mjs, which pins these two values as well) and the two disagreeing
    /// would mean a fee paid under one id and a launch that settles under another.
    #[test]
    fn a_launchs_public_id_is_the_hash_of_its_secret_seed() {
        let hex = |b: [u8; 32]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        assert_eq!(
            hex(launch_id_of(&[0x5a; 32])),
            "0e9de6b209c05c4c29243056f987839fd9b02fec2dd7e8c090251dc64648a1c4"
        );
        assert_eq!(
            hex(launch_id_of(&[0x11; 32])),
            "6be91f517a3df65d5f923378ac657d364a37b9300281724facd85748c89153bd"
        );
        // It is the hash of the domain and the seed, and not of the seed alone: a launch id is
        // not something another protocol's sha256 of the same bytes would also produce.
        use anchor_lang::solana_program::hash::hash;
        assert_ne!(launch_id_of(&[0x5a; 32]), hash(&[0x5a; 32]).to_bytes());
        assert_ne!(launch_id_of(&[0x5a; 32]), [0x5a; 32], "and it is not the seed");
    }

    /// The addresses a launch creates are not the ones its public id derives. If they were, the
    /// id -- which a fee payment publishes -- would say where to send the lamports that stop it.
    #[test]
    fn a_launchs_addresses_cannot_be_computed_from_its_public_id() {
        let seed = [0x5a; 32];
        let id = launch_id_of(&seed);
        for nonce in [0, 24_640_793] {
            assert_ne!(mint_address(&seed, nonce).0, mint_address(&id, nonce).0);
        }
    }

    /// Two launches cannot share a mint, and one launch cannot have two.
    ///
    /// The second half is what the runtime enforces rather than this test: `init` on an account
    /// that exists fails. This pins the first half -- that the derivation separates launches at
    /// all -- which a seed that accidentally ignored its input would not.
    #[test]
    fn a_different_launch_seed_is_a_different_mint() {
        let a = mint_address(&[1u8; 32], 7).0;
        let b = mint_address(&[2u8; 32], 7).0;
        assert_ne!(a, b);
        // Nor do two nonces of one seed: the nonce is part of the address, not a comment on it.
        assert_ne!(a, mint_address(&[1u8; 32], 8).0);

        // And the seed is distinct from the splitter's, so neither can collide with the other even
        // for the same 32-byte input.
        let splitter = Pubkey::find_program_address(&[SPLITTER_SEED, &[1u8; 32]], &crate::ID).0;
        assert_ne!(a, splitter);
    }

    /* ------------------------------------------------------- launchers and fees */

    /// The client derives these three in JavaScript. Pinned so the two cannot disagree about where
    /// a launcher's listing or a creator's payment lives -- a disagreement there is a payment
    /// made to an account the launch never looks at.
    #[test]
    #[cfg(not(feature = "test-stack"))]
    fn the_launcher_and_fee_pdas_are_what_the_client_derives() {
        let key = pubkey!("7rYog4JusTy4CpwvFGPrRvWtcDrWatnA3SN3DRPuf6kM");
        let launch_id = [0x11u8; 32];

        let (launcher, _) = Pubkey::find_program_address(&[LAUNCHER_SEED, key.as_ref()], &crate::ID);
        let (fee, _) =
            Pubkey::find_program_address(&[FEE_SEED, launch_id.as_ref(), key.as_ref()], &crate::ID);

        assert_eq!(launcher.to_string(), "DFJWRGfc2TDZSxV38WNiUwDcn5SkaDJdRbyWUfYh6WDM");
        assert_eq!(fee.to_string(), "GjUNT6oHjXweK8tXUcMHJsEfp9d6SYoNEAss1MxaVy75");
    }

    /// Every payer has their own account for a launch, so nobody is ever the recipient of money
    /// they did not send. One account per launch was how a lamport paid first captured a refund.
    #[test]
    fn two_payers_for_one_launch_have_two_accounts() {
        let launch_id = [7u8; 32];
        let a = Pubkey::new_unique();
        let b = Pubkey::new_unique();
        let fee = |p: &Pubkey| {
            Pubkey::find_program_address(&[FEE_SEED, launch_id.as_ref(), p.as_ref()], &crate::ID).0
        };
        assert_ne!(fee(&a), fee(&b));

        // And one payer's accounts for two launches differ too.
        let other =
            Pubkey::find_program_address(&[FEE_SEED, [8u8; 32].as_ref(), a.as_ref()], &crate::ID).0;
        assert_ne!(fee(&a), other);
    }

    /// The seeds are distinct prefixes, so a launcher's listing can never be mistaken for a
    /// payment or a mint even for inputs chosen to collide.
    #[test]
    fn the_seeds_cannot_collide_with_each_other() {
        let x = [3u8; 32];
        let launcher = Pubkey::find_program_address(&[LAUNCHER_SEED, &x], &crate::ID).0;
        let mint = mint_address(&x, 0).0;
        let splitter = Pubkey::find_program_address(&[SPLITTER_SEED, &x], &crate::ID).0;
        assert_ne!(launcher, mint);
        assert_ne!(launcher, splitter);
    }

    /// Seven days, the same window the EVM collector gives, and not a second less.
    #[test]
    fn a_fee_is_reclaimable_after_seven_days_and_not_before() {
        assert_eq!(RECLAIM_AFTER, 604_800);
        let at = 1_750_000_000;
        assert_eq!(reclaimable_from(at), at + 604_800);
        assert!(at + 604_799 < reclaimable_from(at));
        // A timestamp at the very top of the range must not wrap round to "long ago".
        assert_eq!(reclaimable_from(i64::MAX), i64::MAX);
    }

    /// Nine decimals, matching all four EVM chains.
    ///
    /// Not a preference. LayerZero converts between a token's decimals and the shared precision it
    /// bridges at, so a Solana mint on a different scale than its EVM counterparts bridges the
    /// wrong AMOUNT -- a thousandfold error in what arrives, not a display difference. It is a
    /// constant here precisely so no caller can pass a value that produces that token.
    #[test]
    fn the_mint_is_nine_decimals_like_every_other_chain() {
        assert_eq!(TOKEN_DECIMALS, 9);
    }
}
