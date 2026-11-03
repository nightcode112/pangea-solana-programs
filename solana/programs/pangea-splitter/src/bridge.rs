//! # Opening a launch's bridge: its LayerZero routes, pinned
//!
//! `launch` creates a token's OFT store and names its peers. That is not yet a bridge. On Solana
//! every route an application uses needs accounts of its own with LayerZero's endpoint -- a nonce
//! to count messages against, and a record of which library sends and which receives -- and until
//! they exist a message has nowhere to arrive. And a route left on LayerZero's defaults is
//! verified by whoever LayerZero's defaults name on the day, which is not a property a token
//! should have: a verifier is a party able to tell the store to mint.
//!
//! `open_bridge` creates those accounts and pins everything the route depends on: the send and
//! the receive library, who the executor is, and who verifies in each direction and after how
//! many confirmations. It is what `LaunchFactoryBase._wire` does for a token on an EVM chain, and
//! the values come from the same kind of place -- a `Route` per destination, set by the admin
//! before any launch, checked against the other end of the route before every one.
//!
//! ## Nobody holds the bridge
//!
//! A store has two powers over it. Its admin can name a peer, and a peer can mint. Its endpoint
//! delegate can replace the verifiers, and a delegate that installs itself as the only verifier
//! can attest to a message nobody sent -- which also mints. On the EVM chains neither power is
//! held by a key: the peers are sealed and the delegate is the factory, which has no function
//! that takes a verifier.
//!
//! Here both are `AUTHORITY`, an address only this program can sign for, and this program signs
//! for it in exactly four places -- and, as one of the token's two minters, in `arm` and
//! `rebalance`, to mint into the reserve and nowhere else (see `reserve`). In `launch`, for the store that instruction has just created:
//! to set its fee (see `wire_bridge`) -- the launch names no peer; it records them, and each is
//! made with its route. Also in `launch`, as the token delegate of the creator's own account
//! for an allowlisted asset, to make their dev buy through the pool just opened
//! (`buy_with_allowance`; it moves only what the creator approved, at most the quoted amount).
//! Below, to make a recorded peer and apply the `Route` once to a route that has never been
//! opened. In `withdraw_bridge_fee`, to send the bridge's fees to the platform. And, admin only and
//! bounded (no-rug, 2026-10-30), in `set_gas_floor` (an open route's gas floor, gas only) and
//! `set_bridge_fee` (a v3 store's fee, 0 to 50 bps). LayerZero's own `init` refuses an account that already exists, so a second call for the
//! same route fails before it changes anything. There is no instruction that sets a peer after
//! `launch`, none that changes a library or a verifier after `open_bridge`, and none that moves
//! the admin or the delegate anywhere else.
//!
//! ## A route is the one in force at launch
//!
//! A token's route to a chain is applied once, by whoever opens it, from the `Route` the admin
//! set for that chain. Once applied, nothing changes it. But a route can be opened at any time
//! after the launch -- the bridge is a separate transaction, and one that partly failed can be
//! finished days later by anyone -- and the admin can edit a `Route` for the launches after it.
//! Were `open_bridge` to apply whatever `Route` exists when it is called, a stranger could take an
//! old token whose route was never opened and freeze the NEWER settings on it for good: a token
//! launched when the other side counted 15 confirmations, opened after the route moved to 64, has
//! verifiers attesting at one count while its peer waits for the other, and no message ever
//! delivered.
//!
//! So every `Route` records the slot it was last set in (`Route::edited_slot`), every launch
//! records the slot it landed in (`LAUNCHED_SLOT_AT`, eight bytes after the splitter it creates --
//! no account, instruction or byte added to the launch transaction), and `open_bridge` refuses a
//! route edited after the token's launch (`RouteEditedAfterLaunch`) -- unless the ADMIN signs it,
//! deliberately applying the newer route. A route edited in the very slot of the launch counts as
//! in force at it.
//!
//! What that leaves the admin able to do to a token that exists is what it could always do to one
//! whose bridge was not open yet: open it with the route it chooses. A route changed by the
//! admin afterwards changes the launches that come after it; for a token that already exists,
//! only an `open_bridge` the admin signs can apply it, and only to a route not yet opened.
//!
//! ## Routes are versioned: a token's verifiers are the ones in force at its launch (no-rug, 2026-10-30)
//!
//! That last power is gone. Every `set_route` now also writes an immutable `RouteVersion`
//! (`PDA(["route_ver", eid LE, n LE])`, n = 0, 1, ...), stamped with the slot it was made in, and
//! never touches an older one. A token's launch slot (`LAUNCHED_SLOT_AT`, already in its record)
//! therefore names exactly one version per chain -- the newest one made by that slot -- and that is
//! the snapshot `open_bridge` applies: no byte is added to a launch, and no account is reallocated.
//!
//! `open_bridge` reads the `Route` as before. If it was last edited by the token's launch, it IS
//! the version in force and is applied (unchanged, and anyone may). If it was edited since, the
//! opener appends the version in force and the one after it (`RouteVersion` n and n + 1) after the
//! routes' accounts, and that version is applied -- by anyone; the admin's signature no longer
//! picks a newer route. A token that predates every version (one launched before this upgrade,
//! whose `Route` was edited after its launch) gets, if the ADMIN opens it, the route as it stood at
//! the upgrade: version 0, the genesis, which the first `set_route` after the upgrade snapshots
//! from the `Route` before it overwrites it (or, while no version exists, the `Route` itself,
//! which nothing has written since the upgrade). Either way its content was fixed before the
//! upgrade, so no admin choice reaches a token that exists.
//!
//! After a route is open, one thing about it stays the admin's: the gas floor its transfers must
//! pay for on arrival (`set_gas_floor`, at most `MAX_LZ_RECEIVE_GAS`, gas only). A floor that is
//! too low for the other side's gas schedule would leave every transfer undeliverable; raising one
//! only raises what a transfer is quoted, so it can redirect nothing.
//!
//! ## Why it is not part of `launch`
//!
//! It does not fit, and not narrowly. A transaction may run 64 instructions counting every call a
//! program makes; a launch runs 56, and opening one route is 26 more -- ten calls into LayerZero,
//! each of which makes calls of its own. So the bridge is opened by a second kind of transaction,
//! two routes at a time: 56 instructions, where three routes would be 82.
//!
//! It is not cheap either, and none of the cost is ours to set: LayerZero's six accounts for one
//! route are 35,614,320 lamports of rent, so a token with four peers pays 0.142 SOL to be
//! bridgeable -- more than the rest of its launch.
//!
//! What makes that tolerable is that it carries no choices. Anyone may send it, for any launch
//! that has landed -- it is given the launch's seed, which the launch transaction published --
//! and its only arguments are which launch and which routes; everything it writes is read from
//! accounts this program or LayerZero's derives. A launch whose bridge is not open yet is a token
//! that trades on Solana and cannot be bridged; nothing is at risk in between, and a transfer
//! sent toward Solana in that window waits and is delivered once the route exists.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    instruction::{AccountMeta, Instruction},
    program::invoke_signed,
    system_instruction,
};

use crate::{
    launch_id_of, read_token_account, SplitterError, ADMIN, ESCROW_SEED, LZ_ENDPOINT_ID, OFT_PROGRAM_ID, POSITION_SEED, SPLITTER_SEED,
};

/// LayerZero's Ultra Light Node: the message library every route is pinned to. It is a constant
/// rather than part of a `Route` because the calls below are written for this library's accounts
/// and no other's, and because a library is the thing that decides what "verified" means -- the
/// one value here that must not be the admin's to choose.
pub const ULN_ID: Pubkey = pubkey!("7a4WjyR8VZ7yZz5XJAKm39BUGn5iT9CKcv2pmG9tdXVH");

/// seeds: ["authority"]. The admin and the endpoint delegate of every store `launch` creates.
/// It holds no data and, between instructions, no lamports.
pub const AUTHORITY_SEED: &[u8] = b"authority";

/// seeds: ["route", eid as 4 little-endian bytes]. One per destination chain.
pub const ROUTE_SEED: &[u8] = b"route";

/// LayerZero's seeds for a store's record of one peer: ["Peer", store, eid as 4 BIG-endian bytes].
pub const OFT_PEER_SEED: &[u8] = b"Peer";
/// LayerZero's seed for a store under the OFT program: ["OFT", escrow].
pub const OFT_STORE_SEED: &[u8] = b"OFT";

/// The most DVNs a `Route` holds in each of its lists: five, which a route template with our own
/// DVN among the optional verifiers needs. It keeps the account a fixed, small size (739 bytes).
pub const MAX_DVNS: usize = 5;

/// Each direction of a route must need this many independent verifiers: that many required DVNs,
/// or an optional threshold of that many. One DVN is one key that can mint, for the life of every
/// token opened on the route. The same rule, and the same number, as `RouteLib.requireExplicit`.
pub const MIN_VERIFIERS: usize = 2;

/// How LayerZero spells "none" in a DVN count. Zero does not mean none: it means "whatever the
/// default is", which is the changeable thing a pinned route exists to avoid.
pub const NIL_DVN_COUNT: u8 = 255;

/// The most gas a route may make every transfer pay for on arrival. `GasFloor.MAX_LZ_RECEIVE_GAS`.
pub const MAX_LZ_RECEIVE_GAS: u64 = 1_000_000;

/// Lead #3 M-1: a v3 receive on an EVM chain needs at least this much lzReceive gas
/// (GapFloorsV3.EVM_LZ_RECEIVE_GAS_MIN_V3; script/golive/v3-evm-receive-floor.test.mjs pins the two
/// sources together). Every route of this program goes to an EVM chain, so a v3 store's routes
/// enforce at least this for a plain transfer, and `EVM_V3_COMPOSE_EXTRA_GAS` more for one with a
/// call. ONE constant: E6's final figure is a one-line change here (and in GapFloorsV3.sol).
pub const EVM_V3_LZ_RECEIVE_GAS_MIN: u64 = 1_270_000;
/// What a composed v3 receive needs on top (E6: 1,310,000 - 1,270,000; GapFloorsV3 EVM_COMPOSE_EXTRA_GAS_V3).
pub const EVM_V3_COMPOSE_EXTRA_GAS: u64 = 40_000;
/// The most gas a v3 store's route may enforce (above the v3 floor, under any EVM block's limit).
pub const MAX_LZ_RECEIVE_GAS_V3: u64 = 3_000_000;

/// The enforced lzReceive gas of a route, (send, send_and_call): a live (v1/v2) store's one value for
/// both, exactly as before; a v3 store's at least the EVM v3 floors (plain / composed).
pub fn route_gas_floors(gas: u64, v3: bool) -> (u64, u64) {
    if !v3 {
        return (gas, gas);
    }
    let plain = gas.max(EVM_V3_LZ_RECEIVE_GAS_MIN);
    (plain, gas.max(EVM_V3_LZ_RECEIVE_GAS_MIN + EVM_V3_COMPOSE_EXTRA_GAS).max(plain))
}

/// The least `max_message_size` a route may set: one OFT transfer's message, which is the
/// recipient (32 bytes) and the amount in shared decimals (8) -- `OFTMsgCodec`'s
/// `SEND_AMOUNT_SD_OFFSET + 8`, the same on every OFT. Below it the executor refuses every transfer
/// the token will ever send, and a route is applied once: a typo here would be a dead bridge.
pub const MIN_MESSAGE_SIZE: u32 = 40;

/// The most confirmations a route may make either side wait for. A million blocks is twelve days of
/// Solana and over four months of Ethereum: nothing a route needs, and the bound is only there so
/// that a stray digit cannot set a count no chain reaches before the token is forgotten -- which,
/// a route being applied once, would be a bridge that never delivers.
pub const MAX_CONFIRMATIONS: u64 = 1_000_000;

/// Accounts `open_bridge` is given per route, after its own, in the order `Pathway` names them.
pub const PATHWAY_ACCOUNTS: usize = 10;

/// What a caller of `open_bridge` would ordinarily lend `AUTHORITY` per route to pay LayerZero's
/// rent with: the default the client sends. NOT what the program lends -- that is the caller's
/// argument, `float_per_route`.
///
/// The endpoint's `init` instructions take their rent from the delegate, and so does the OFT
/// program's record of a peer, which `open_bridge` creates with the route (a launch records its
/// peers and creates none: see `PEER_RECORD_AT`). So the delegate has to be holding it. The
/// endpoint's four accounts cost 18,938,160 lamports at today's sizes and rent -- most of it the
/// pending-nonce account, at 15,235,440 -- and the peer 12,402,720: 31,340,880, and this is that
/// with about a quarter again in case any of them grows. Whatever is not spent returns to the
/// payer before the instruction ends. A figure, not a fee: nothing is kept.
///
/// It was a constant the program itself used, and that was a way for every later bridge to
/// become unopenable for good. LayerZero's endpoint can be upgraded and this program cannot: had
/// those accounts ever grown past the constant, `AUTHORITY` would have been lent too little to
/// create them, for every token launched from then on, with no instruction able to say
/// otherwise. So the amount is the caller's to state. It is the caller's own money, lent for the
/// length of one instruction and returned to the lamport less what LayerZero took, so there is
/// nothing in it to abuse: too little and the route does not open (and nothing is spent), enough
/// and it does.
pub const PATHWAY_FLOAT: u64 = 40_000_000;

// LayerZero's config types, as `set_config` numbers them.
const CONFIG_TYPE_EXECUTOR: u32 = 1;
const CONFIG_TYPE_SEND_ULN: u32 = 2;
const CONFIG_TYPE_RECEIVE_ULN: u32 = 3;

// ---------------------------------------------------------------------------------- the route

/// Who verifies one direction of a route, and after how many confirmations.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq, InitSpace)]
pub struct Verifiers {
    /// Blocks on the SOURCE chain before the DVNs attest. Both ends of a route must hold the same
    /// number for the same direction, or the DVNs attest at one count while the receiver waits
    /// for another and nothing is ever delivered.
    pub confirmations: u64,
    /// Every one of these must attest. Strictly ascending.
    #[max_len(MAX_DVNS)]
    pub required: Vec<Pubkey>,
    /// `optional_threshold` of these must attest as well. Strictly ascending.
    #[max_len(MAX_DVNS)]
    pub optional: Vec<Pubkey>,
    pub optional_threshold: u8,
}

/// What `set_route` is given: a `Route` without the fields the program fills in.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct RouteArgs {
    /// Solana to the destination.
    pub send: Verifiers,
    /// The destination to Solana.
    pub receive: Verifiers,
    pub executor: Pubkey,
    pub max_message_size: u32,
    /// Gas every transfer to the destination must pay for on arrival, at least.
    pub receive_gas: u64,
}

/// One destination chain, as every launch's bridge to it is opened.
#[account]
#[derive(InitSpace)]
pub struct Route {
    pub eid: u32,
    pub send: Verifiers,
    pub receive: Verifiers,
    pub executor: Pubkey,
    pub max_message_size: u32,
    pub receive_gas: u64,
    pub bump: u8,
    /// The slot `set_route` last wrote this route in. `open_bridge` refuses, unless the admin
    /// signs, to apply a route edited after the token it opens launched: see "a route is the one
    /// in force at launch". Last, so that a route account made before it existed -- whose lists
    /// were not full, leaving zeros at the end of its allocation -- reads it as 0.
    pub edited_slot: u64,
}

/// seeds: ["route_ver", eid as 4 little-endian bytes, n as 4 little-endian bytes]. Version n of the
/// route to `eid`: written once by `set_route`, never changed or closed.
pub const ROUTE_VERSION_SEED: &[u8] = b"route_ver";
/// seeds: ["route_head", eid as 4 little-endian bytes]. Which version of the route to `eid` is the newest.
pub const ROUTE_HEAD_SEED: &[u8] = b"route_head";

/// The newest version of one chain's route.
#[account]
#[derive(InitSpace)]
pub struct RouteHead {
    pub eid: u32,
    /// The newest version's number.
    pub latest: u32,
    pub bump: u8,
}

/// One version of one chain's route, as `set_route` wrote it: immutable.
#[account]
#[derive(InitSpace)]
pub struct RouteVersion {
    pub eid: u32,
    pub version: u32,
    /// The slot it came into force: `set_route`'s, or for the genesis the `Route`'s own
    /// `edited_slot` (when the content it snapshots was written).
    pub created_slot: u64,
    /// Version 0 snapshotted from a `Route` that existed before routes were versioned: the route as
    /// it stood at the upgrade.
    pub genesis: bool,
    pub send: Verifiers,
    pub receive: Verifiers,
    pub executor: Pubkey,
    pub max_message_size: u32,
    pub receive_gas: u64,
    pub bump: u8,
}

/// The address of version `n` of the route to `eid`.
pub fn route_version_address(eid: u32, n: u32) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[ROUTE_VERSION_SEED, eid.to_le_bytes().as_ref(), n.to_le_bytes().as_ref()], &crate::ID)
}

fn args_of_route(r: Route) -> RouteArgs {
    RouteArgs { send: r.send, receive: r.receive, executor: r.executor, max_message_size: r.max_message_size, receive_gas: r.receive_gas }
}

fn args_of_version(v: RouteVersion) -> RouteArgs {
    RouteArgs { send: v.send, receive: v.receive, executor: v.executor, max_message_size: v.max_message_size, receive_gas: v.receive_gas }
}

fn check_verifiers(v: &Verifiers) -> Result<()> {
    // Zero is LayerZero's "use the default". The largest value is its "none at all": the library
    // reads u64::MAX as no confirmations, so a route that set it would have its verifiers attest
    // to a block the moment it appeared, with no protection against that block being replaced.
    require!(
        v.confirmations != 0 && v.confirmations != u64::MAX,
        SplitterError::RouteInheritsDefaults
    );
    require!(v.confirmations <= MAX_CONFIRMATIONS, SplitterError::RouteValueOutOfRange);
    require!(
        v.required.len() <= MAX_DVNS && v.optional.len() <= MAX_DVNS,
        SplitterError::RouteVerifiersMalformed
    );
    for list in [&v.required, &v.optional] {
        let mut last = Pubkey::default();
        for dvn in list {
            // Strictly ascending from the zero address: no duplicates, and no zero. A list that
            // named one DVN twice would claim two verifiers while holding one.
            require!(dvn.to_bytes() > last.to_bytes(), SplitterError::RouteVerifiersMalformed);
            last = *dvn;
        }
    }
    // A threshold with nothing to count, or one that can never be met, or optional DVNs none of
    // which has to attest.
    let threshold = v.optional_threshold as usize;
    require!(
        threshold <= v.optional.len() && (threshold == 0) == v.optional.is_empty(),
        SplitterError::RouteVerifiersMalformed
    );
    require!(
        v.required.len() >= MIN_VERIFIERS || threshold >= MIN_VERIFIERS,
        SplitterError::RouteHasTooFewVerifiers
    );
    Ok(())
}

/// What the executor or a verifier named by a route has to be: an account that exists, holds
/// data, belongs to a program, and is not itself a program.
///
/// A route names CONFIG accounts -- the executor's and each verifier's own account, which is what
/// LayerZero's library reads and pays -- and a config account's address is easily confused with
/// the address of the program that owns it. A route naming the PROGRAM is accepted by LayerZero
/// when the route is applied, and then no transfer over it can ever be sent: `send` is handed
/// the config account, which is not the one the route pinned. A route is applied once per token
/// and never again, so that token's route to that chain would be dead for good, and so would
/// every token's opened before anyone noticed. A program is executable; a wallet or a mistyped
/// address is owned by the system program or is nothing at all. None of those is a config
/// account, and each is refused here, when the route is SET.
///
/// It is not proof of the right account: nothing here knows LayerZero's layouts, and an account
/// of some unrelated program would pass. It turns away the mistakes that are easy to make.
pub fn is_a_config_account(account: &AccountInfo) -> bool {
    account.lamports() > 0
        && !account.data_is_empty()
        && !account.executable
        && *account.owner != anchor_lang::solana_program::system_program::ID
}

/// Every account a route names -- its executor, and each verifier in either direction -- must be
/// among `given` and be a config account. In any order; one that is named twice is given once.
pub fn check_route_accounts(r: &RouteArgs, given: &[AccountInfo]) -> Result<()> {
    let named = core::iter::once(&r.executor)
        .chain(&r.send.required)
        .chain(&r.send.optional)
        .chain(&r.receive.required)
        .chain(&r.receive.optional);
    for key in named {
        let account = given.iter().find(|a| a.key == key).ok_or(SplitterError::RouteNamesNoSuchAccount)?;
        require!(is_a_config_account(account), SplitterError::RouteNamesNoSuchAccount);
    }
    Ok(())
}

/// Refuse a route that would leave anything to LayerZero's defaults, or to one verifier.
pub fn check_route(eid: u32, r: &RouteArgs) -> Result<()> {
    require!(eid != 0, SplitterError::RouteInheritsDefaults);
    check_verifiers(&r.send)?;
    check_verifiers(&r.receive)?;
    require!(
        r.executor != Pubkey::default() && r.max_message_size != 0,
        SplitterError::RouteInheritsDefaults
    );
    require!(r.max_message_size >= MIN_MESSAGE_SIZE, SplitterError::RouteValueOutOfRange);
    require!(
        r.receive_gas != 0 && r.receive_gas <= MAX_LZ_RECEIVE_GAS,
        SplitterError::GasFloorOutOfRange
    );
    Ok(())
}

#[derive(Accounts)]
#[instruction(eid: u32)]
pub struct SetRoute<'info> {
    #[account(
        init_if_needed,
        payer = admin,
        space = 8 + Route::INIT_SPACE,
        seeds = [ROUTE_SEED, eid.to_le_bytes().as_ref()],
        bump
    )]
    pub route: Account<'info, Route>,
    #[account(mut, address = ADMIN @ SplitterError::NotAdmin)]
    pub admin: Signer<'info>,
    pub system_program: Program<'info, System>,
    #[account(
        init_if_needed,
        payer = admin,
        space = 8 + RouteHead::INIT_SPACE,
        seeds = [ROUTE_HEAD_SEED, eid.to_le_bytes().as_ref()],
        bump
    )]
    pub head: Account<'info, RouteHead>,
    /// CHECK: `route_version_address(eid, n)`, n the next version (0 when `head` is new): created here.
    #[account(mut)]
    pub version: UncheckedAccount<'info>,
    /// CHECK: `route_version_address(eid, n + 1)`: created here only by the first versioned edit of a
    /// `Route` that already existed (version n = 0 is then its genesis and this the new route).
    #[account(mut)]
    pub next_version: UncheckedAccount<'info>,
}

#[event]
pub struct RouteVersionCreated {
    pub eid: u32,
    pub version: u32,
    pub created_slot: u64,
    pub genesis: bool,
}

#[event]
pub struct RouteSet {
    pub eid: u32,
    pub send_confirmations: u64,
    pub receive_confirmations: u64,
    pub receive_gas: u64,
}

/// Create version `n` of the route to `eid` at `target` (its derived address), paid by `payer`.
#[inline(never)]
fn create_version<'info>(
    payer: &AccountInfo<'info>,
    target: &AccountInfo<'info>,
    system: &AccountInfo<'info>,
    mut v: RouteVersion,
) -> Result<()> {
    let (key, bump) = route_version_address(v.eid, v.version);
    require_keys_eq!(target.key(), key, SplitterError::NotThisRoute);
    // Never over a version that exists: versions are written once.
    require!(target.data_is_empty() && *target.owner == anchor_lang::solana_program::system_program::ID, SplitterError::NotThisRoute);
    let (e, n) = (v.eid.to_le_bytes(), v.version.to_le_bytes());
    let seeds: &[&[u8]] = &[ROUTE_VERSION_SEED, &e, &n, &[bump]];
    let space = 8 + RouteVersion::INIT_SPACE;
    let rent = Rent::get()?.minimum_balance(space);
    let infos = [payer.clone(), target.clone(), system.clone()];
    if target.lamports() == 0 {
        invoke_signed(&system_instruction::create_account(payer.key, &key, rent, space as u64, &crate::ID), &infos, &[seeds])?;
    } else {
        // Someone sent lamports to the address first: top up, allocate and assign it instead.
        let short = rent.saturating_sub(target.lamports());
        if short > 0 {
            invoke_signed(&system_instruction::transfer(payer.key, &key, short), &infos, &[])?;
        }
        invoke_signed(&system_instruction::allocate(&key, space as u64), &infos, &[seeds])?;
        invoke_signed(&system_instruction::assign(&key, &crate::ID), &infos, &[seeds])?;
    }
    v.bump = bump;
    let mut data = target.try_borrow_mut_data()?;
    v.try_serialize(&mut &mut data[..])?;
    emit!(RouteVersionCreated { eid: v.eid, version: v.version, created_slot: v.created_slot, genesis: v.genesis });
    Ok(())
}

pub fn set_route_handler(ctx: Context<SetRoute>, eid: u32, args: RouteArgs) -> Result<()> {
    check_route(eid, &args)?;
    check_route_accounts(&args, ctx.remaining_accounts)?;
    let slot = Clock::get()?.slot;

    // The versions. A head made now means no version exists yet: version 0 is then the genesis --
    // the `Route` as it stood before this edit, if one existed -- and the new route the next.
    {
        let a = &ctx.accounts;
        let fresh_head = a.head.eid == 0;
        let n = if fresh_head { 0 } else { a.head.latest.checked_add(1).ok_or(SplitterError::Overflow)? };
        let legacy = &a.route;
        let had_legacy = legacy.eid == eid;
        let (payer, system) = (a.admin.to_account_info(), a.system_program.to_account_info());
        let mut latest = n;
        if fresh_head && had_legacy {
            create_version(
                &payer,
                &a.version.to_account_info(),
                &system,
                RouteVersion {
                    eid,
                    version: 0,
                    created_slot: legacy.edited_slot,
                    genesis: true,
                    send: legacy.send.clone(),
                    receive: legacy.receive.clone(),
                    executor: legacy.executor,
                    max_message_size: legacy.max_message_size,
                    receive_gas: legacy.receive_gas,
                    bump: 0,
                },
            )?;
            latest = 1;
        } else {
            // The next version's neighbour must still be the one derived: the client names both.
            require_keys_eq!(a.next_version.key(), route_version_address(eid, n + 1).0, SplitterError::NotThisRoute);
        }
        let target = if latest == n { a.version.to_account_info() } else { a.next_version.to_account_info() };
        create_version(
            &payer,
            &target,
            &system,
            RouteVersion {
                eid,
                version: latest,
                created_slot: slot,
                genesis: false,
                send: args.send.clone(),
                receive: args.receive.clone(),
                executor: args.executor,
                max_message_size: args.max_message_size,
                receive_gas: args.receive_gas,
                bump: 0,
            },
        )?;
        let h = &mut ctx.accounts.head;
        h.eid = eid;
        h.latest = latest;
        h.bump = ctx.bumps.head;
    }

    let r = &mut ctx.accounts.route;
    r.eid = eid;
    r.executor = args.executor;
    r.max_message_size = args.max_message_size;
    r.receive_gas = args.receive_gas;
    r.bump = ctx.bumps.route;
    // Every write, including one that sets the same values again: a launch after it is held to
    // the route as it stands now, and one before it can no longer be opened onto it by a stranger.
    r.edited_slot = slot;
    emit!(RouteSet {
        eid,
        send_confirmations: args.send.confirmations,
        receive_confirmations: args.receive.confirmations,
        receive_gas: args.receive_gas,
    });
    r.send = args.send;
    r.receive = args.receive;
    Ok(())
}

// ------------------------------------------------------------ what the other programs are sent

fn endpoint_call(discriminator: [u8; 8], oapp: &Pubkey, eid: u32, extra: usize) -> Vec<u8> {
    let mut d = Vec::with_capacity(44 + extra);
    d.extend_from_slice(&discriminator);
    d.extend_from_slice(oapp.as_ref());
    d.extend_from_slice(&eid.to_le_bytes());
    d
}

/// Endpoint `init_send_library`: the store's own record of which library sends to `eid`.
pub fn endpoint_init_send_library_data(oapp: &Pubkey, eid: u32) -> Vec<u8> {
    endpoint_call([0x9c, 0x18, 0xeb, 0x78, 0x49, 0xc1, 0x90, 0x13], oapp, eid, 0)
}

/// Endpoint `init_receive_library`: and which receives from it.
pub fn endpoint_init_receive_library_data(oapp: &Pubkey, eid: u32) -> Vec<u8> {
    endpoint_call([0xc5, 0x72, 0x51, 0x64, 0x2d, 0xe9, 0x24, 0xe6], oapp, eid, 0)
}

/// Endpoint `init_nonce`: the counters for messages between the store and `remote` on `eid`.
pub fn endpoint_init_nonce_data(oapp: &Pubkey, eid: u32, remote: &[u8; 32]) -> Vec<u8> {
    let mut d = endpoint_call([0xcc, 0xab, 0x10, 0xd6, 0xb6, 0xbf, 0x1b, 0xc4], oapp, eid, 32);
    d.extend_from_slice(remote);
    d
}

/// Endpoint `set_send_library`: name the library, instead of leaving it on the default.
pub fn endpoint_set_send_library_data(oapp: &Pubkey, eid: u32, library: &Pubkey) -> Vec<u8> {
    let mut d = endpoint_call([0xfb, 0x76, 0x4e, 0x9e, 0x86, 0x95, 0x81, 0x05], oapp, eid, 32);
    d.extend_from_slice(library.as_ref());
    d
}

/// Endpoint `set_receive_library`, with no grace period: there is no earlier library to honour.
pub fn endpoint_set_receive_library_data(oapp: &Pubkey, eid: u32, library: &Pubkey) -> Vec<u8> {
    let mut d = endpoint_call([0xdf, 0xac, 0xb4, 0x69, 0xa5, 0xa1, 0x93, 0xe4], oapp, eid, 40);
    d.extend_from_slice(library.as_ref());
    d.extend_from_slice(&0u64.to_le_bytes());
    d
}

/// Endpoint `init_config`: the library's own accounts for the store's config on this route.
pub fn endpoint_init_config_data(oapp: &Pubkey, eid: u32) -> Vec<u8> {
    endpoint_call([0x17, 0xeb, 0x73, 0xe8, 0xa8, 0x60, 0x01, 0xe7], oapp, eid, 0)
}

/// Endpoint `set_config`: hand the library one config, which it decodes by `config_type`.
pub fn endpoint_set_config_data(oapp: &Pubkey, eid: u32, config_type: u32, config: &[u8]) -> Vec<u8> {
    let mut d = endpoint_call([0x6c, 0x9e, 0x9a, 0xaf, 0xd4, 0x62, 0x34, 0x42], oapp, eid, 8 + config.len());
    d.extend_from_slice(&config_type.to_le_bytes());
    d.extend_from_slice(&(config.len() as u32).to_le_bytes());
    d.extend_from_slice(config);
    d
}

/// A DVN count as LayerZero wants it: the number, or NIL for none. Never zero.
fn dvn_count(list: &[Pubkey]) -> u8 {
    if list.is_empty() {
        NIL_DVN_COUNT
    } else {
        list.len() as u8
    }
}

/// The library's `UlnConfig` for one direction, with every field explicit.
pub fn uln_config_bytes(v: &Verifiers) -> Vec<u8> {
    let mut d = Vec::with_capacity(19 + 32 * (v.required.len() + v.optional.len()));
    d.extend_from_slice(&v.confirmations.to_le_bytes());
    d.push(dvn_count(&v.required));
    d.push(dvn_count(&v.optional));
    d.push(v.optional_threshold);
    for list in [&v.required, &v.optional] {
        d.extend_from_slice(&(list.len() as u32).to_le_bytes());
        for dvn in list {
            d.extend_from_slice(dvn.as_ref());
        }
    }
    d
}

/// The library's `ExecutorConfig`.
pub fn executor_config_bytes(max_message_size: u32, executor: &Pubkey) -> Vec<u8> {
    let mut d = Vec::with_capacity(36);
    d.extend_from_slice(&max_message_size.to_le_bytes());
    d.extend_from_slice(executor.as_ref());
    d
}

/// The options that make every transfer pay for at least `gas` on arrival. Byte for byte what
/// `GasFloor.encode(gas, 0)` produces on the EVM chains: type-3 options holding one executor
/// `lzReceive` entry. The length inside it (17) counts the entry's type and its gas, and a wrong
/// one does not fail -- the executor skips the entry and the delivery runs with no gas at all.
pub fn gas_floor(gas: u64) -> [u8; 22] {
    let mut d = [0u8; 22];
    d[..6].copy_from_slice(&[0x00, 0x03, 0x01, 0x00, 0x11, 0x01]);
    d[6..].copy_from_slice(&(gas as u128).to_be_bytes());
    d
}

/// OFT `set_peer_config(EnforcedOptions)`: the same floor for a transfer and for a transfer with
/// a call, which is what the factory sets on the EVM chains.
pub fn oft_set_enforced_options_data(eid: u32, floor: &[u8; 22]) -> Vec<u8> {
    oft_set_enforced_options_split(eid, floor, floor)
}

/// OFT `set_peer_config(EnforcedOptions { send, send_and_call })`: a v3 store's split floors.
pub fn oft_set_enforced_options_split(eid: u32, send: &[u8; 22], send_and_call: &[u8; 22]) -> Vec<u8> {
    let mut d = Vec::with_capacity(65);
    d.extend_from_slice(&[0x4f, 0xbb, 0xa8, 0x39, 0x8b, 0x8c, 0x5d, 0x2f]);
    d.extend_from_slice(&eid.to_le_bytes());
    d.push(2); // PeerConfigParam::EnforcedOptions
    for floor in [send, send_and_call] {
        d.extend_from_slice(&(floor.len() as u32).to_le_bytes());
        d.extend_from_slice(floor);
    }
    d
}

// ------------------------------------------------------------------------------- the accounts

#[derive(Accounts)]
pub struct OpenBridge<'info> {
    /// Anyone. Pays LayerZero's rent for the routes opened, and nothing else.
    #[account(mut)]
    pub payer: Signer<'info>,

    /// CHECK: the admin and delegate of every store, which only this program signs for. It is
    /// lent the rent on the way in and holds nothing on the way out.
    #[account(mut, seeds = [AUTHORITY_SEED], bump)]
    pub authority: UncheckedAccount<'info>,

    /// CHECK: the launch's OFT store; the handler derives it from the launch's seed and compares.
    pub oft_store: UncheckedAccount<'info>,
    /// CHECK: the launch's splitter, for the slot the launch landed in (`LAUNCHED_SLOT_AT`); the
    /// handler derives it from the launch's seed and compares. Read, never written.
    pub splitter: UncheckedAccount<'info>,
    /// CHECK: the endpoint's record of the store and its delegate; the endpoint derives it.
    pub oapp_registry: UncheckedAccount<'info>,
    /// CHECK: the endpoint's record of the library; the endpoint derives it.
    pub message_lib_info: UncheckedAccount<'info>,
    /// CHECK: the library's own address and settings. This is the value written as each route's
    /// send and receive library, so it is derived here and not left to LayerZero's checks alone.
    #[account(seeds = [b"MessageLib"], bump, seeds::program = ULN_ID)]
    pub message_lib: UncheckedAccount<'info>,
    /// CHECK: the endpoint's event authority.
    pub endpoint_event_authority: UncheckedAccount<'info>,
    /// CHECK: the library's event authority.
    pub uln_event_authority: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
    /// CHECK: pinned.
    #[account(address = LZ_ENDPOINT_ID @ SplitterError::WrongProgram)]
    pub endpoint_program: UncheckedAccount<'info>,
    /// CHECK: pinned.
    #[account(address = ULN_ID @ SplitterError::WrongProgram)]
    pub uln_program: UncheckedAccount<'info>,
    /// CHECK: pinned.
    #[account(address = OFT_PROGRAM_ID @ SplitterError::WrongProgram)]
    pub oft_program: UncheckedAccount<'info>,
}

#[event]
pub struct BridgeOpened {
    pub launch_id: [u8; 32],
    pub oft_store: Pubkey,
    pub eid: u32,
    pub remote: [u8; 32],
}

/// The addresses every route's calls share.
struct Shared {
    payer: Pubkey,
    authority: Pubkey,
    store: Pubkey,
    registry: Pubkey,
    lib_info: Pubkey,
    lib: Pubkey,
    endpoint_events: Pubkey,
    uln_events: Pubkey,
    system: Pubkey,
    /// A v3 store (319 bytes): its routes enforce the EVM v3 floors (`route_gas_floors`).
    v3: bool,
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

#[inline(never)]
fn send(
    all: &[AccountInfo],
    program: &Pubkey,
    accounts: Vec<AccountMeta>,
    data: Vec<u8>,
    authority_seeds: &[&[u8]],
) -> Result<()> {
    let ix = Instruction {
        program_id: *program,
        accounts,
        data,
    };
    invoke_signed(&ix, all, &[authority_seeds])?;
    Ok(())
}

/// The store a launch's seed derives: the same two derivations `launch` created it under.
pub fn store_of_launch(launch_seed: &[u8; 32]) -> Pubkey {
    let escrow = Pubkey::find_program_address(&[ESCROW_SEED, launch_seed.as_ref()], &crate::ID).0;
    Pubkey::find_program_address(&[OFT_STORE_SEED, escrow.as_ref()], &OFT_PROGRAM_ID).0
}

/// The splitter a launch's seed derives: `PDA(["splitter", PDA(["position", seed])])`, as `launch`
/// created it.
pub fn splitter_of_launch(launch_seed: &[u8; 32]) -> Pubkey {
    let nft = Pubkey::find_program_address(&[POSITION_SEED, launch_seed.as_ref()], &crate::ID).0;
    Pubkey::find_program_address(&[SPLITTER_SEED, nft.as_ref()], &crate::ID).0
}

pub fn open_bridge_handler<'info>(
    ctx: Context<'_, '_, 'info, 'info, OpenBridge<'info>>,
    launch_seed: [u8; 32],
    eids: Vec<u32>,
    float_per_route: u64,
) -> Result<()> {
    // Each route's accounts, then -- for each route edited since the launch, in the order named --
    // the version in force at the launch and the one after it (see "routes are versioned").
    let base = eids.len().checked_mul(PATHWAY_ACCOUNTS).ok_or(SplitterError::Overflow)?;
    require!(
        !eids.is_empty()
            && ctx.remaining_accounts.len() >= base
            && (ctx.remaining_accounts.len() - base) % 2 == 0
            && (ctx.remaining_accounts.len() - base) / 2 <= eids.len(),
        SplitterError::NothingToOpen
    );

    // The store is this launch's, and it exists: it is LayerZero's account at the address the
    // launch's seed derives. Nothing else about which store this is comes from the caller. The
    // seed is no secret by now -- a store exists only once its launch has landed, and the launch
    // carried the seed -- and the launch is named, in the event below, by its public id.
    let a = &ctx.accounts;
    let store = store_of_launch(&launch_seed);
    let launch_id = launch_id_of(&launch_seed);
    require_keys_eq!(a.oft_store.key(), store, SplitterError::NotThisLaunch);
    require_keys_eq!(*a.oft_store.owner, OFT_PROGRAM_ID, SplitterError::NotThisLaunch);
    // Pangea v3 gap fee: a v3 store opens no route until its official pool is set (`set_gap_pool`,
    // the registrar's, sent ahead of this instruction in the first opening): before it, every
    // transfer would cross with no price, so no gap fee. A live store has no tail.
    require!(gap_pool_ready(&a.oft_store.try_borrow_data()?), SplitterError::GapPoolNotSet);
    let v3 = a.oft_store.data_len() >= OFT_V3_STORE_LEN;

    // When the launch landed, from its splitter -- the seed's, and this program's. A route edited
    // after then is applied only if the admin is the one opening it: see "a route is the one in
    // force at launch".
    require_keys_eq!(a.splitter.key(), splitter_of_launch(&launch_seed), SplitterError::NotThisLaunch);
    require_keys_eq!(*a.splitter.owner, crate::ID, SplitterError::NotThisLaunch);
    // And the peers the launch recorded, for the routes being opened: a route's peer that does not
    // exist yet is created from this, and from nothing else (see `PEER_RECORD_AT`).
    let (launched, recorded): (u64, Vec<Option<[u8; 20]>>) = {
        let data = a.splitter.try_borrow_data()?;
        // And not before the launch's reserve is armed: until then Solana's supply is its slice
        // alone and the store cannot mint (see `reserve`), so nothing may cross. A launch made
        // before launches kept a reserve opens as it always did.
        require!(crate::bridge_may_open(&data), SplitterError::NotArmed);
        (crate::launched_slot(&data).ok_or(SplitterError::NotThisLaunch)?, eids.iter().map(|eid| crate::recorded_peer(&data, *eid)).collect())
    };
    let by_admin = a.payer.key() == ADMIN;

    let mut all = a.to_account_infos();
    all.extend_from_slice(ctx.remaining_accounts);

    let shared = Shared {
        payer: a.payer.key(),
        authority: a.authority.key(),
        store,
        registry: a.oapp_registry.key(),
        lib_info: a.message_lib_info.key(),
        lib: a.message_lib.key(),
        endpoint_events: a.endpoint_event_authority.key(),
        uln_events: a.uln_event_authority.key(),
        system: a.system_program.key(),
        v3,
    };
    let authority_seeds: &[&[u8]] = &[AUTHORITY_SEED, &[ctx.bumps.authority]];

    // Lend the authority the rent: as much per route as the caller says. See `PATHWAY_FLOAT`.
    let float = float_per_route.checked_mul(eids.len() as u64).ok_or(SplitterError::Overflow)?;
    if float > 0 {
        invoke_signed(&system_instruction::transfer(&shared.payer, &shared.authority, float), &all, &[])?;
    }

    let mut versions = &ctx.remaining_accounts[base..];
    for (i, (eid, accounts)) in eids.iter().zip(ctx.remaining_accounts[..base].chunks(PATHWAY_ACCOUNTS)).enumerate() {
        let route = route_in_force(&accounts[0], *eid, launched, by_admin, &mut versions)?;
        let remote = open_pathway(&all, &shared, *eid, accounts, authority_seeds, &route, recorded[i])?;
        emit!(BridgeOpened {
            launch_id,
            oft_store: store,
            eid: *eid,
            remote,
        });
    }

    // Every version pair given was used.
    require!(versions.is_empty(), SplitterError::RouteVersionNotInForce);

    // And take back everything it did not spend, so the authority is empty between instructions
    // and there is never a balance sitting at an address nobody holds a key for.
    let left = a.authority.lamports();
    if left > 0 {
        invoke_signed(
            &system_instruction::transfer(&shared.authority, &shared.payer, left),
            &all,
            &[authority_seeds],
        )?;
    }
    Ok(())
}

/// Read a route's pinned settings out of the account given for it, having checked it is ours.
#[inline(never)]
fn read_route(account: &AccountInfo, eid: u32) -> Result<Route> {
    require_keys_eq!(*account.owner, crate::ID, SplitterError::NotThisRoute);
    let route = Route::try_deserialize(&mut &account.try_borrow_data()?[..])?;
    let expected = Pubkey::create_program_address(&[ROUTE_SEED, eid.to_le_bytes().as_ref(), &[route.bump]], &crate::ID)
        .map_err(|_| error!(SplitterError::NotThisRoute))?;
    require!(account.key() == expected && route.eid == eid, SplitterError::NotThisRoute);
    Ok(route)
}

/// Read version account `account` of the route to `eid`, having checked it is ours and at its address.
#[inline(never)]
fn read_version(account: &AccountInfo, eid: u32) -> Result<RouteVersion> {
    require_keys_eq!(*account.owner, crate::ID, SplitterError::NotThisRoute);
    let v = RouteVersion::try_deserialize(&mut &account.try_borrow_data()?[..])?;
    let expected = Pubkey::create_program_address(
        &[ROUTE_VERSION_SEED, eid.to_le_bytes().as_ref(), v.version.to_le_bytes().as_ref(), &[v.bump]],
        &crate::ID,
    )
    .map_err(|_| error!(SplitterError::NotThisRoute))?;
    require!(account.key() == expected && v.eid == eid, SplitterError::NotThisRoute);
    Ok(v)
}

/// The route to `eid` in force when the token launched (`launched`): the `Route` itself when it
/// was last edited by then; otherwise the version pair the caller appended (taken off `versions`):
/// version n made by the launch and n + 1 absent or made after it. A token older than every version
/// is opened only by the admin, and only onto the genesis (or, with no version yet, the `Route`,
/// which nothing has written since the upgrade). See "routes are versioned".
#[inline(never)]
fn route_in_force(legacy: &AccountInfo, eid: u32, launched: u64, by_admin: bool, versions: &mut &[AccountInfo]) -> Result<RouteArgs> {
    let route = read_route(legacy, eid)?;
    if route.edited_slot <= launched {
        return Ok(args_of_route(route));
    }
    let given: &[AccountInfo] = *versions;
    require!(given.len() >= 2, SplitterError::RouteEditedAfterLaunch);
    let (v, next) = (&given[0], &given[1]);
    *versions = &given[2..];
    if v.data_is_empty() {
        // No version at all yet: the `Route` is the route as it stood at the upgrade.
        require_keys_eq!(v.key(), route_version_address(eid, 0).0, SplitterError::NotThisRoute);
        require!(by_admin, SplitterError::RouteEditedAfterLaunch);
        return Ok(args_of_route(route));
    }
    let ver = read_version(v, eid)?;
    if ver.created_slot <= launched {
        let n1 = ver.version.checked_add(1).ok_or(SplitterError::Overflow)?;
        require_keys_eq!(next.key(), route_version_address(eid, n1).0, SplitterError::NotThisRoute);
        if !next.data_is_empty() {
            require!(read_version(next, eid)?.created_slot > launched, SplitterError::RouteVersionNotInForce);
        }
        return Ok(args_of_version(ver));
    }
    // Older than every version: the genesis, by the admin, or nothing.
    require!(by_admin && ver.version == 0 && ver.genesis, SplitterError::RouteEditedAfterLaunch);
    Ok(args_of_version(ver))
}

/// The store's peer on `eid` has to be the one LayerZero derives, and not made yet: a launch records
/// its peers and `open_pathway` creates each, with the route, from that record (see
/// `PEER_RECORD_AT`). An address somebody has sent lamports to is still not made. A peer that
/// exists means the route was opened, and a route opens once.
///
/// The nonce accounts are derived from the peer's address, so it has to be the one the store will
/// actually accept messages from: the launch's record says what it is, and nothing else does -- a
/// wrong one would open a route to nobody and, since a route opens once, leave the real one closed
/// for good.
#[inline(never)]
fn check_peer_unmade(account: &AccountInfo, store: &Pubkey, eid: u32) -> Result<()> {
    let expected = Pubkey::find_program_address(
        &[OFT_PEER_SEED, store.as_ref(), eid.to_be_bytes().as_ref()],
        &OFT_PROGRAM_ID,
    )
    .0;
    require_keys_eq!(account.key(), expected, SplitterError::NotThisPeer);
    // The peer is made with its route, and only then: if it is there, so is the route. Lamports
    // alone (someone pre-funding the address) leave it the system program's and empty, so they
    // cannot block an opening.
    require_keys_eq!(*account.owner, anchor_lang::solana_program::system_program::ID, SplitterError::RouteAlreadyOpen);
    require!(account.data_is_empty(), SplitterError::RouteAlreadyOpen);
    Ok(())
}

/// One route: its accounts with the endpoint, its libraries, its executor, its verifiers in both
/// directions and its gas floor. Ten calls, each of which LayerZero checks the accounts of.
#[inline(never)]
fn open_pathway(
    all: &[AccountInfo],
    s: &Shared,
    eid: u32,
    accounts: &[AccountInfo],
    authority_seeds: &[&[u8]],
    route: &RouteArgs,
    recorded: Option<[u8; 20]>,
) -> Result<[u8; 32]> {
    // In the order `PATHWAY_ACCOUNTS` promises; `route` is the one in force at the launch
    // (`route_in_force`, from accounts[0] and the versions given).
    let peer = accounts[1].key();
    // The peer, created now from the launch's record -- the EVM token it named for this chain,
    // signed as `AUTHORITY`, its rent out of what the payer lent. Nobody opening a route chooses a
    // peer: there is no argument for one.
    check_peer_unmade(&accounts[1], &s.store, eid)?;
    let token = recorded.ok_or(SplitterError::PeerNotRecorded)?;
    send(
        all,
        &OFT_PROGRAM_ID,
        vec![rw_signer(&s.authority), rw(&peer), ro(&s.store), ro(&s.system)],
        crate::launch_leg::oft_set_peer_data(eid, &token),
        authority_seeds,
    )?;
    let mut remote = [0u8; 32];
    remote[12..].copy_from_slice(&token);
    let send_library = accounts[2].key();
    let receive_library = accounts[3].key();
    let nonce = accounts[4].key();
    let pending_nonce = accounts[5].key();
    let send_config = accounts[6].key();
    let receive_config = accounts[7].key();
    let default_send_config = accounts[8].key();
    let default_receive_config = accounts[9].key();

    // The endpoint's own accounts for the route. Each is an `init`, which is what makes a route
    // openable exactly once: the second attempt fails here, before anything is written.
    send(
        all,
        &LZ_ENDPOINT_ID,
        vec![rw_signer(&s.authority), ro(&s.registry), rw(&send_library), ro(&s.system)],
        endpoint_init_send_library_data(&s.store, eid),
        authority_seeds,
    )?;
    send(
        all,
        &LZ_ENDPOINT_ID,
        vec![rw_signer(&s.authority), ro(&s.registry), rw(&receive_library), ro(&s.system)],
        endpoint_init_receive_library_data(&s.store, eid),
        authority_seeds,
    )?;
    send(
        all,
        &LZ_ENDPOINT_ID,
        vec![
            rw_signer(&s.authority),
            ro(&s.registry),
            rw(&nonce),
            rw(&pending_nonce),
            ro(&s.system),
        ],
        endpoint_init_nonce_data(&s.store, eid, &remote),
        authority_seeds,
    )?;

    // The libraries, by name. Left on the default they are whichever the endpoint's owner points
    // the default at, and the configs below would be settings on a library no longer in use.
    for (config, data) in [
        (send_library, endpoint_set_send_library_data(&s.store, eid, &s.lib)),
        (receive_library, endpoint_set_receive_library_data(&s.store, eid, &s.lib)),
    ] {
        send(
            all,
            &LZ_ENDPOINT_ID,
            vec![
                signer(&s.authority),
                ro(&s.registry),
                rw(&config),
                ro(&s.lib_info),
                ro(&s.endpoint_events),
                ro(&LZ_ENDPOINT_ID),
            ],
            data,
            authority_seeds,
        )?;
    }

    // The library's accounts for this store on this route. The payer pays for these itself.
    send(
        all,
        &LZ_ENDPOINT_ID,
        vec![
            signer(&s.authority),
            ro(&s.registry),
            ro(&s.lib_info),
            ro(&s.lib),
            ro(&ULN_ID),
            rw_signer(&s.payer),
            ro(&s.lib),
            rw(&send_config),
            rw(&receive_config),
            ro(&s.system),
        ],
        endpoint_init_config_data(&s.store, eid),
        authority_seeds,
    )?;

    // And what goes in them: who executes, who verifies outbound, who verifies inbound.
    for (config_type, config) in [
        (
            CONFIG_TYPE_EXECUTOR,
            executor_config_bytes(route.max_message_size, &route.executor),
        ),
        (CONFIG_TYPE_SEND_ULN, uln_config_bytes(&route.send)),
        (CONFIG_TYPE_RECEIVE_ULN, uln_config_bytes(&route.receive)),
    ] {
        send(
            all,
            &LZ_ENDPOINT_ID,
            vec![
                signer(&s.authority),
                ro(&s.registry),
                ro(&s.lib_info),
                ro(&s.lib),
                ro(&ULN_ID),
                ro(&s.lib),
                rw(&send_config),
                rw(&receive_config),
                ro(&default_send_config),
                ro(&default_receive_config),
                ro(&s.uln_events),
                ro(&ULN_ID),
            ],
            endpoint_set_config_data(&s.store, eid, config_type, &config),
            authority_seeds,
        )?;
    }

    // Last, the gas floor, on the store's own record of the peer. Without one a transfer may be
    // sent with too little gas to be delivered, and an undelivered message blocks every later
    // one on the route.
    send(
        all,
        &OFT_PROGRAM_ID,
        vec![rw_signer(&s.authority), rw(&peer), ro(&s.store), ro(&s.system)],
        {
            // Lead #3 M-1: a v3 store's floors, at least the EVM v3 receive's (plain / composed);
            // a live store's one value for both, as before.
            let (plain, composed) = route_gas_floors(route.receive_gas, s.v3);
            oft_set_enforced_options_split(eid, &gas_floor(plain), &gas_floor(composed))
        },
        authority_seeds,
    )?;

    Ok(remote)
}

/* ------------------------------------------------------------------- the bridge's fee

   Bridging out of Solana costs 0.2% (`BRIDGE_FEE_BPS`), taken by LayerZero's OFT program itself:
   `send` burns what crosses and moves the fee into the store's token escrow. The store's admin
   may take it out with the OFT program's `withdraw_fee`, to any token account of the mint it
   names -- and the admin of every store is `AUTHORITY`, an address with no key.

   So this program has to be the one that asks, or the fees stay in the escrow for good. And since
   the only choice in a withdrawal is where the money goes, the instruction below makes that
   choice itself: the platform's associated token account for the mint, the platform being the
   one the program's platform record names (`platform_of`) -- the same payee as the trading
   fees' platform share. With the destination fixed and
   the amount "all of it", there is nothing left for a caller to decide, which is what makes it
   safe for anyone to send -- the same reasoning as `claim_fees`.

   What it can take is what LayerZero's program lets an admin take: the escrow's balance above the
   store's `tvl_ld`. A store made by `launch` is of the Native kind, which burns and mints rather
   than locking, so its `tvl_ld` is always zero and its escrow holds fees and nothing else (and
   whatever anybody chose to send there, which goes the same way). The fee is real supply, never
   burned, and withdrawing it moves it without changing the supply: `rebalance` (see `reserve`)
   and this never touch each other's tokens.

   One instruction of this program sets a fee, once: `launch` sets the store's default in the
   instruction that creates the store, signing as `AUTHORITY` -- which is the store's admin from
   its creation; the store is never anyone else's and is never handed over. Only `set_bridge_fee`
   sets a fee on a store that already exists -- a v3 store's, admin only, 0 to 50 bps -- and none
   sets one on a peer or on a live (v1/v2) store. `open_bridge` signs as
   `AUTHORITY` for the calls it lists and no others; and this signs for `withdraw_fee` alone. */

/// sha256("account:OFTStore")[..8], as LayerZero's OFT program writes it.
pub const OFT_STORE_DISCRIMINATOR: [u8; 8] = [195, 215, 104, 134, 185, 195, 240, 114];

// LayerZero's `OFTStore`, as Borsh lays it out after the discriminator: oft_type (1), ld2sd_rate
// (8), token_mint (32), token_escrow (32), endpoint_program (32), bump (1), tvl_ld (8), admin
// (32), default_fee_bps (2), paused (1), then two optional keys. Read here rather than taken on
// trust, and pinned in tests/launch.rs against a store the real program created.
const OFT_STORE_TOKEN_MINT: usize = 17;
const OFT_STORE_TOKEN_ESCROW: usize = 49;
const OFT_STORE_TVL: usize = 114;
const OFT_STORE_ADMIN: usize = 122;
const OFT_STORE_DEFAULT_FEE_BPS: usize = 154;

/// What this program reads out of a store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OftStoreView {
    pub token_mint: Pubkey,
    pub token_escrow: Pubkey,
    /// What the escrow holds that is NOT fee: always zero for a Native store; for a lockbox
    /// (SUPPLY_TOTAL's Adapter store) what it has locked for the other chains.
    pub tvl_ld: u64,
    pub admin: Pubkey,
    pub default_fee_bps: u16,
}

/// A v3 OFT store (`init_oft_v3`) is at least this long: LayerZero's 223 bytes and the gap tail.
pub const OFT_V3_STORE_LEN: usize = 319;
/// The tail's version byte: 0 until `set_gap_pool`, then 1 (docs/v3-gap-fee-spec.md §10.3).
pub const OFT_TAIL_VER_AT: usize = 223;

/// Whether a store may have routes opened: any live (223-byte) store, and a v3 store once its
/// official pool is set.
pub fn gap_pool_ready(store_data: &[u8]) -> bool {
    store_data.len() < OFT_V3_STORE_LEN || store_data[OFT_TAIL_VER_AT] == 1
}

/// The fields of an OFT store this program reads, or None if `data` is not one.
pub fn read_oft_store(data: &[u8]) -> Option<OftStoreView> {
    if data.get(..8)? != OFT_STORE_DISCRIMINATOR {
        return None;
    }
    let key = |at: usize| -> Option<Pubkey> {
        let bytes: [u8; 32] = data.get(at..at + 32)?.try_into().ok()?;
        Some(Pubkey::new_from_array(bytes))
    };
    let tvl: [u8; 8] = data.get(OFT_STORE_TVL..OFT_STORE_TVL + 8)?.try_into().ok()?;
    let fee: [u8; 2] = data.get(OFT_STORE_DEFAULT_FEE_BPS..OFT_STORE_DEFAULT_FEE_BPS + 2)?.try_into().ok()?;
    Some(OftStoreView {
        token_mint: key(OFT_STORE_TOKEN_MINT)?,
        token_escrow: key(OFT_STORE_TOKEN_ESCROW)?,
        tvl_ld: u64::from_le_bytes(tvl),
        admin: key(OFT_STORE_ADMIN)?,
        default_fee_bps: u16::from_le_bytes(fee),
    })
}

/// A v3 store's reserved writer-reward total (`Tail::reward_owed`, u64 LE at 300..308 of the
/// 319-byte store); 0 for a live store, which has no tail.
pub const OFT_TAIL_REWARD_OWED_AT: usize = 300;
pub fn store_reward_owed(store_data: &[u8]) -> u64 {
    if store_data.len() < OFT_V3_STORE_LEN {
        return 0;
    }
    u64::from_le_bytes(store_data[OFT_TAIL_REWARD_OWED_AT..OFT_TAIL_REWARD_OWED_AT + 8].try_into().unwrap())
}

/// What `withdraw_bridge_fee` takes: the escrow's balance less the TVL less the reserved rewards,
/// never below 0 (the OFT's withdraw_fee check, so the withdrawal never reverts on the reserve).
pub fn withdrawable_fee(held: u64, tvl_ld: u64, reward_owed: u64) -> u64 {
    held.saturating_sub(tvl_ld).saturating_sub(reward_owed)
}

/// OFT `withdraw_fee(fee_ld)`.
pub fn oft_withdraw_fee_data(fee_ld: u64) -> Vec<u8> {
    let mut d = Vec::with_capacity(16);
    d.extend_from_slice(&[0x0e, 0x7a, 0xe7, 0xda, 0x1f, 0xee, 0xdf, 0x96]);
    d.extend_from_slice(&fee_ld.to_le_bytes());
    d
}

/// Where a launch's bridge fees go: the platform's associated token account for its mint -- the
/// platform the program records (`fees::Platform`, the admin until a payee is set), the same payee
/// its trading fees go to, so rotating the platform rotates both.
pub fn platform_fee_account(mint: &Pubkey, platform: &Pubkey) -> Pubkey {
    anchor_spl::associated_token::get_associated_token_address_with_program_id(platform, mint, &crate::TOKEN_2022_ID)
}

#[derive(Accounts)]
pub struct WithdrawBridgeFee<'info> {
    /// CHECK: the admin of every store, which only this program signs for.
    #[account(seeds = [AUTHORITY_SEED], bump)]
    pub authority: UncheckedAccount<'info>,
    /// CHECK: the launch's OFT store; the handler derives it from the launch's seed and compares.
    pub oft_store: UncheckedAccount<'info>,
    /// CHECK: the launch's mint; the handler compares it with the one the store records.
    pub token_mint: UncheckedAccount<'info>,
    /// CHECK: the store's token escrow, where the fees are; compared with the store's record.
    #[account(mut)]
    pub token_escrow: UncheckedAccount<'info>,
    /// CHECK: the platform's associated token account for the mint. The handler derives it and
    /// compares: it is the one thing a caller might want to choose, and cannot.
    #[account(mut)]
    pub platform_token: UncheckedAccount<'info>,
    /// CHECK: the program-wide platform record, which may not exist yet (the platform is then
    /// `ADMIN`); read by `fees::platform_of`.
    #[account(seeds = [crate::PLATFORM_SEED], bump)]
    pub platform_config: UncheckedAccount<'info>,
    /// The launched token's program: every launch's mint is a Token-2022 mint.
    pub token_program: Program<'info, anchor_spl::token_2022::Token2022>,
    /// CHECK: pinned.
    #[account(address = OFT_PROGRAM_ID @ SplitterError::WrongProgram)]
    pub oft_program: UncheckedAccount<'info>,
}

#[event]
pub struct BridgeFeeWithdrawn {
    pub launch_id: [u8; 32],
    pub oft_store: Pubkey,
    pub mint: Pubkey,
    pub to: Pubkey,
    pub amount: u64,
}

pub fn withdraw_bridge_fee_handler(ctx: Context<WithdrawBridgeFee>, launch_seed: [u8; 32]) -> Result<()> {
    let a = &ctx.accounts;

    // The store is this launch's: LayerZero's account at the address the seed derives.
    let store = store_of_launch(&launch_seed);
    require_keys_eq!(a.oft_store.key(), store, SplitterError::NotThisLaunch);
    require_keys_eq!(*a.oft_store.owner, OFT_PROGRAM_ID, SplitterError::NotThisLaunch);
    let view = read_oft_store(&a.oft_store.try_borrow_data()?).ok_or(SplitterError::NotThisLaunch)?;

    // The mint and the escrow are the store's own. LayerZero's program checks both again; they
    // are checked here first because the amount below is read out of this escrow.
    require_keys_eq!(a.token_mint.key(), view.token_mint, SplitterError::NotThisLaunch);
    require_keys_eq!(a.token_escrow.key(), view.token_escrow, SplitterError::NotThisLaunch);
    require_keys_eq!(*a.token_escrow.owner, crate::TOKEN_2022_ID, SplitterError::NotThisLaunch);

    // And the destination is the platform's, for this mint. Not an argument, not a setting.
    let platform = crate::platform_of(&a.platform_config)?;
    require_keys_eq!(
        a.platform_token.key(),
        platform_fee_account(&view.token_mint, &platform),
        SplitterError::NotThePlatformsTokenAccount
    );

    // Everything the store's admin may take: the escrow's balance above what it holds for others --
    // its TVL and, on a v3 store, the writer rewards reserved out of the fees (the OFT's withdraw_fee
    // refuses a fee that would dip into them: escrow - tvl - fee >= reward_owed). A live (223-byte)
    // store has no tail: 0 reserved, the amount as before.
    let held = read_token_account(&a.token_escrow.try_borrow_data()?).ok_or(SplitterError::NotThisLaunch)?.1;
    let reserved = store_reward_owed(&a.oft_store.try_borrow_data()?);
    let amount = withdrawable_fee(held, view.tvl_ld, reserved);
    require!(amount > 0, SplitterError::NoBridgeFeeToWithdraw);

    let ix = Instruction {
        program_id: OFT_PROGRAM_ID,
        accounts: vec![
            signer(&a.authority.key()),
            ro(&store),
            ro(&view.token_mint),
            rw(&view.token_escrow),
            rw(&a.platform_token.key()),
            ro(&a.token_program.key()),
        ],
        data: oft_withdraw_fee_data(amount),
    };
    let authority_seeds: &[&[u8]] = &[AUTHORITY_SEED, &[ctx.bumps.authority]];
    invoke_signed(&ix, &a.to_account_infos(), &[authority_seeds])?;

    emit!(BridgeFeeWithdrawn {
        launch_id: launch_id_of(&launch_seed),
        oft_store: store,
        mint: view.token_mint,
        to: a.platform_token.key(),
        amount,
    });
    Ok(())
}

/* ------------------------------------------------------------- after the route is open (no-rug, 2026-10-30)

   Two settings of an open route stay the admin's, each bounded, each with an event, neither able
   to move anybody's tokens: the gas floor a transfer to the chain must pay for on arrival
   (`set_gas_floor`), and -- for a v3 store only -- the bridge's fee (`set_bridge_fee`). The fee's
   recipient is not a setting: `withdraw_bridge_fee` still sends it to the platform. */

/// The most a bridge fee may be set to: 0.5%.
pub const MAX_BRIDGE_FEE_BPS: u16 = 50;

#[derive(Accounts)]
pub struct SetGasFloor<'info> {
    #[account(address = ADMIN @ SplitterError::NotAdmin)]
    pub admin: Signer<'info>,
    /// CHECK: the admin of every store, which only this program signs for.
    #[account(mut, seeds = [AUTHORITY_SEED], bump)]
    pub authority: UncheckedAccount<'info>,
    /// CHECK: the launch's OFT store; the handler derives it from the launch's seed and compares.
    pub oft_store: UncheckedAccount<'info>,
    /// CHECK: the store's record of its peer on `eid`, which `open_bridge` made: derived and checked
    /// in the handler.
    #[account(mut)]
    pub peer: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
    /// CHECK: pinned.
    #[account(address = OFT_PROGRAM_ID @ SplitterError::WrongProgram)]
    pub oft_program: UncheckedAccount<'info>,
}

#[event]
pub struct GasFloorSet {
    pub launch_id: [u8; 32],
    pub oft_store: Pubkey,
    pub eid: u32,
    pub gas: u64,
}

/// Set the gas an OPEN route's every transfer (Solana to `eid`) must pay for on arrival: the
/// store's enforced options toward `eid`, `gas_floor(gas)` -- gas only, no value -- for a plain
/// transfer and for a transfer with a call, as `open_bridge` set them. Admin only; 1 to
/// `MAX_LZ_RECEIVE_GAS`.
pub fn set_gas_floor_handler(ctx: Context<SetGasFloor>, launch_seed: [u8; 32], eid: u32, gas: u64) -> Result<()> {
    let a = &ctx.accounts;
    // Lead #3 M-1: a v3 store's floor is at least the EVM v3 receive's (refused below it, up to
    // MAX_LZ_RECEIVE_GAS_V3) and written split, the composed one EVM_V3_COMPOSE_EXTRA_GAS above; a
    // live store's 1 to MAX_LZ_RECEIVE_GAS for both, as before.
    let v3 = a.oft_store.data_len() >= OFT_V3_STORE_LEN;
    if v3 {
        require!(gas <= MAX_LZ_RECEIVE_GAS_V3, SplitterError::GasFloorOutOfRange);
        require!(gas >= EVM_V3_LZ_RECEIVE_GAS_MIN, SplitterError::GasFloorBelowV3Floor);
    } else {
        require!(gas != 0 && gas <= MAX_LZ_RECEIVE_GAS, SplitterError::GasFloorOutOfRange);
    }
    let store = store_of_launch(&launch_seed);
    require_keys_eq!(a.oft_store.key(), store, SplitterError::NotThisLaunch);
    require_keys_eq!(*a.oft_store.owner, OFT_PROGRAM_ID, SplitterError::NotThisLaunch);
    // The peer exists only once its route was opened: this changes an open route, never opens one.
    let peer = Pubkey::find_program_address(&[OFT_PEER_SEED, store.as_ref(), eid.to_be_bytes().as_ref()], &OFT_PROGRAM_ID).0;
    require_keys_eq!(a.peer.key(), peer, SplitterError::NotThisPeer);
    require!(*a.peer.owner == OFT_PROGRAM_ID && !a.peer.data_is_empty(), SplitterError::RouteNotOpen);
    let authority_seeds: &[&[u8]] = &[AUTHORITY_SEED, &[ctx.bumps.authority]];
    send(
        &a.to_account_infos(),
        &OFT_PROGRAM_ID,
        vec![rw_signer(&a.authority.key()), rw(&peer), ro(&store), ro(&a.system_program.key())],
        {
            let (plain, composed) = if v3 { (gas, gas + EVM_V3_COMPOSE_EXTRA_GAS) } else { (gas, gas) };
            oft_set_enforced_options_split(eid, &gas_floor(plain), &gas_floor(composed))
        },
        authority_seeds,
    )?;
    emit!(GasFloorSet { launch_id: launch_id_of(&launch_seed), oft_store: store, eid, gas });
    Ok(())
}

#[derive(Accounts)]
pub struct SetBridgeFee<'info> {
    #[account(address = ADMIN @ SplitterError::NotAdmin)]
    pub admin: Signer<'info>,
    /// CHECK: the admin of every store, which only this program signs for.
    #[account(seeds = [AUTHORITY_SEED], bump)]
    pub authority: UncheckedAccount<'info>,
    /// CHECK: the launch's OFT store; the handler derives it from the launch's seed and compares.
    #[account(mut)]
    pub oft_store: UncheckedAccount<'info>,
    /// CHECK: pinned.
    #[account(address = OFT_PROGRAM_ID @ SplitterError::WrongProgram)]
    pub oft_program: UncheckedAccount<'info>,
}

#[event]
pub struct BridgeFeeSet {
    pub launch_id: [u8; 32],
    pub oft_store: Pubkey,
    pub from_bps: u16,
    pub to_bps: u16,
}

/// Set a v3 store's bridge fee (its `default_fee_bps`, through the OFT's `set_oft_config` signed as
/// `AUTHORITY`): 0 to `MAX_BRIDGE_FEE_BPS`. Admin only. A live (v1/v2) store is refused
/// (`NotAV3Store`): its fee stays the one its launch set. Where the fee goes is unchanged.
pub fn set_bridge_fee_handler(ctx: Context<SetBridgeFee>, launch_seed: [u8; 32], bps: u16) -> Result<()> {
    require!(bps <= MAX_BRIDGE_FEE_BPS, SplitterError::BridgeFeeOutOfRange);
    let a = &ctx.accounts;
    let store = store_of_launch(&launch_seed);
    require_keys_eq!(a.oft_store.key(), store, SplitterError::NotThisLaunch);
    require_keys_eq!(*a.oft_store.owner, OFT_PROGRAM_ID, SplitterError::NotThisLaunch);
    let from_bps = {
        let d = a.oft_store.try_borrow_data()?;
        require!(d.len() >= OFT_V3_STORE_LEN, SplitterError::NotAV3Store);
        read_oft_store(&d).ok_or(SplitterError::NotThisLaunch)?.default_fee_bps
    };
    let authority_seeds: &[&[u8]] = &[AUTHORITY_SEED, &[ctx.bumps.authority]];
    send(
        &a.to_account_infos(),
        &OFT_PROGRAM_ID,
        vec![signer(&a.authority.key()), rw(&store)],
        crate::oft_set_default_fee_data(bps),
        authority_seeds,
    )?;
    emit!(BridgeFeeSet { launch_id: launch_id_of(&launch_seed), oft_store: store, from_bps, to_bps: bps });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anchor_lang::solana_program::program_error::ProgramError;

    /// `oft.instructions.getWithdrawFeeInstructionDataSerializer().serialize({ feeLd:
    /// 1234567890123n })` from `@layerzerolabs/oft-v2-solana-sdk` 3.0.168; pinned again, against
    /// the SDK itself, in solana/client/bridge.test.mjs.
    #[test]
    fn the_fee_is_withdrawn_with_the_bytes_layerzeros_sdk_sends() {
        let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(hex(&oft_withdraw_fee_data(1_234_567_890_123)), "0e7ae7da1feedf96cb04fb711f010000");
        assert_eq!(hex(&oft_withdraw_fee_data(0)), "0e7ae7da1feedf960000000000000000");
    }

    /// The store's layout, on bytes laid out the way LayerZero's program lays them out; the
    /// same offsets are read back from a store the real program made in tests/launch.rs.
    #[test]
    fn a_store_is_read_field_by_field_and_nothing_else_is_a_store() {
        let (mint, escrow, endpoint, admin) = (Pubkey::new_unique(), Pubkey::new_unique(), Pubkey::new_unique(), Pubkey::new_unique());
        let mut d = OFT_STORE_DISCRIMINATOR.to_vec();
        d.push(0); // Native
        d.extend_from_slice(&1_000u64.to_le_bytes());
        d.extend_from_slice(mint.as_ref());
        d.extend_from_slice(escrow.as_ref());
        d.extend_from_slice(endpoint.as_ref());
        d.push(254);
        d.extend_from_slice(&77u64.to_le_bytes());
        d.extend_from_slice(admin.as_ref());
        d.extend_from_slice(&20u16.to_le_bytes());
        d.extend_from_slice(&[0, 0, 0]); // not paused, no pauser, no unpauser
        assert_eq!(
            read_oft_store(&d),
            Some(OftStoreView { token_mint: mint, token_escrow: escrow, tvl_ld: 77, admin, default_fee_bps: 20 })
        );
        let mut wrong = d.clone();
        wrong[0] ^= 1;
        assert_eq!(read_oft_store(&wrong), None, "another account's discriminator");
        assert_eq!(read_oft_store(&d[..155]), None, "too short to hold the fee");
        assert_eq!(read_oft_store(&[]), None);
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn key(hex32: &str) -> Pubkey {
        let bytes: Vec<u8> = (0..64).step_by(2).map(|i| u8::from_str_radix(&hex32[i..i + 2], 16).unwrap()).collect();
        Pubkey::new_from_array(bytes.try_into().unwrap())
    }

    // The store of launch seed 0x5a..5a, Ethereum's endpoint id, and two DVNs in ascending order.
    const STORE: &str = "c41326871016c299fd3748b4c3b72a307b30b4f6f386c5edfdbd9a247caf47e1";
    const EID: u32 = 30101;
    const DVN_A: &str = "33cdb9fb56d28a2f028cbb36c254a7d54c92f0419b53e44ddcc0a5c373f854f2";
    const DVN_B: &str = "e4b2ac493a2dd060e66df3200996f7050bced9c0a465bedc1261272a1bb24330";

    fn verifiers(confirmations: u64) -> Verifiers {
        Verifiers {
            confirmations,
            required: vec![key(DVN_A), key(DVN_B)],
            optional: vec![],
            optional_threshold: 0,
        }
    }

    fn route() -> RouteArgs {
        RouteArgs {
            send: verifiers(32),
            receive: verifiers(15),
            executor: key("53b82142f29732a56fb6c88fa402fd18a1ddca13741d6ba73d3fcf9ae81021c1"),
            max_message_size: 10_000,
            receive_gas: 100_000,
        }
    }

    /* Each expected value is what LayerZero's own SDK builds for the same inputs --
       `EndpointProgram.Endpoint` and `oft.setPeerConfig` from the client's dependencies. A byte
       out of place in most of these would fail loudly inside LayerZero. In a config it would not:
       it would pin a different confirmation count or a different verifier, for good.           */

    #[test]
    fn the_endpoint_is_called_with_the_bytes_layerzeros_sdk_sends() {
        let store = key(STORE);
        let lib = key("16b7830c3f8a44c810ca87de56e032889c358ec75d4732bf7361862658acb2af");
        let eid = "95750000";
        assert_eq!(
            hex(&endpoint_init_send_library_data(&store, EID)),
            ["9c18eb7849c19013", STORE, eid].concat()
        );
        assert_eq!(
            hex(&endpoint_init_receive_library_data(&store, EID)),
            ["c57251642de924e6", STORE, eid].concat()
        );
        assert_eq!(
            hex(&endpoint_init_nonce_data(&store, EID, &{
                let mut remote = [0u8; 32];
                remote[12..].copy_from_slice(&[0xab; 20]);
                remote
            })),
            [
                "ccab10d6b6bf1bc4",
                STORE,
                eid,
                "000000000000000000000000abababababababababababababababababababab"
            ]
            .concat()
        );
        assert_eq!(
            hex(&endpoint_set_send_library_data(&store, EID, &lib)),
            [
                "fb764e9e86958105",
                STORE,
                eid,
                "16b7830c3f8a44c810ca87de56e032889c358ec75d4732bf7361862658acb2af"
            ]
            .concat()
        );
        assert_eq!(
            hex(&endpoint_set_receive_library_data(&store, EID, &lib)),
            [
                "dfacb469a5a193e4",
                STORE,
                eid,
                "16b7830c3f8a44c810ca87de56e032889c358ec75d4732bf7361862658acb2af",
                "0000000000000000"
            ]
            .concat()
        );
        assert_eq!(
            hex(&endpoint_init_config_data(&store, EID)),
            ["17eb73e8a86001e7", STORE, eid].concat()
        );
    }

    #[test]
    fn a_verifier_config_is_the_bytes_layerzeros_sdk_sends_with_nothing_left_to_a_default() {
        let store = key(STORE);
        assert_eq!(
            hex(&endpoint_set_config_data(
                &store,
                EID,
                CONFIG_TYPE_SEND_ULN,
                &uln_config_bytes(&verifiers(32))
            )),
            [
                "6c9e9aafd4623442",
                STORE,
                "95750000",
                "02000000",         // SEND_ULN
                "53000000",         // 83 bytes of config follow
                "2000000000000000", // 32 confirmations
                "02",               // two required
                "ff",               // NIL optional: none, NOT "the default"
                "00",               // so no threshold
                "02000000",
                DVN_A,
                DVN_B,
                "00000000",
            ]
            .concat()
        );
        assert_eq!(
            hex(&endpoint_set_config_data(
                &store,
                EID,
                CONFIG_TYPE_EXECUTOR,
                &executor_config_bytes(10_000, &route().executor)
            )),
            [
                "6c9e9aafd4623442",
                STORE,
                "95750000",
                "01000000",
                "24000000",
                "10270000",
                "53b82142f29732a56fb6c88fa402fd18a1ddca13741d6ba73d3fcf9ae81021c1",
            ]
            .concat()
        );

        // Optional DVNs: counted, and NIL moves to the required side when there are none of those.
        let optional = Verifiers {
            confirmations: 1,
            required: vec![],
            optional: vec![key(DVN_A), key(DVN_B)],
            optional_threshold: 2,
        };
        assert_eq!(
            hex(&uln_config_bytes(&optional)),
            ["0100000000000000", "ff", "02", "02", "00000000", "02000000", DVN_A, DVN_B].concat()
        );
    }

    #[test]
    fn the_gas_floor_is_the_one_the_evm_chains_set() {
        // `GasFloor.encode(60_000, 0)`, and the OFT SDK's `setPeerConfig` carrying it twice.
        assert_eq!(hex(&gas_floor(60_000)), "0003010011010000000000000000000000000000ea60");
        assert_eq!(
            hex(&oft_set_enforced_options_data(EID, &gas_floor(60_000))),
            [
                "4fbba8398b8c5d2f",
                "95750000",
                "02",
                "16000000",
                "0003010011010000000000000000000000000000ea60",
                "16000000",
                "0003010011010000000000000000000000000000ea60",
            ]
            .concat()
        );
    }

    fn refused(r: &RouteArgs) -> bool {
        check_route(EID, r).is_err()
    }

    #[test]
    fn a_route_must_say_everything_and_need_two_verifiers() {
        assert!(check_route(EID, &route()).is_ok());
        assert!(check_route(0, &route()).is_err());

        // Anything left at zero is LayerZero's default, which somebody else can change.
        let mut r = route();
        r.send.confirmations = 0;
        assert!(refused(&r));
        // And the largest value is LayerZero's "none": no confirmations at all.
        let mut r = route();
        r.receive.confirmations = u64::MAX;
        assert!(refused(&r));
        // And a count no chain reaches before the token is forgotten is a dead route: a million
        // blocks is the most (MAX_CONFIRMATIONS), refused by name above it.
        r.receive.confirmations = u64::MAX - 1;
        assert!(refused(&r));
        r.receive.confirmations = MAX_CONFIRMATIONS + 1;
        assert!(refused(&r));
        r.receive.confirmations = MAX_CONFIRMATIONS;
        assert!(!refused(&r));
        r.send.confirmations = MAX_CONFIRMATIONS + 1;
        assert_eq!(ProgramError::from(check_route(EID, &r).unwrap_err()), ProgramError::Custom(6042), "RouteValueOutOfRange");
        let mut r = route();
        r.executor = Pubkey::default();
        assert!(refused(&r));
        let mut r = route();
        r.max_message_size = 0;
        assert!(refused(&r));
        // A message size below one OFT transfer's 40 bytes is a route that can send nothing.
        for (size, ok) in [(1u32, false), (MIN_MESSAGE_SIZE - 1, false), (MIN_MESSAGE_SIZE, true), (10_000, true), (u32::MAX, true)] {
            r.max_message_size = size;
            assert_eq!(!refused(&r), ok, "max_message_size {size}");
        }
        r.max_message_size = MIN_MESSAGE_SIZE - 1;
        assert_eq!(ProgramError::from(check_route(EID, &r).unwrap_err()), ProgramError::Custom(6042), "RouteValueOutOfRange");

        // One required DVN is one key.
        let mut r = route();
        r.receive.required.pop();
        assert!(refused(&r));
        // ...unless two optional ones must agree as well.
        r.receive.optional = vec![key(DVN_A), key(DVN_B)];
        r.receive.optional_threshold = 2;
        assert!(!refused(&r));
        // A threshold of one over two optional DVNs is still one key.
        r.receive.optional_threshold = 1;
        assert!(refused(&r));
        // And one that can never be met is not a threshold.
        r.receive.optional_threshold = 3;
        assert!(refused(&r));

        // The same DVN twice is one verifier claiming to be two; so is a list out of order,
        // which is how LayerZero would have caught the duplicate.
        let mut r = route();
        r.send.required = vec![key(DVN_A), key(DVN_A)];
        assert!(refused(&r));
        r.send.required = vec![key(DVN_B), key(DVN_A)];
        assert!(refused(&r));
        r.send.required = vec![Pubkey::default(), key(DVN_A)];
        assert!(refused(&r));

        // Optional DVNs with no threshold verify nothing; a threshold with none counts nothing.
        let mut r = route();
        r.send.optional = vec![key(DVN_A)];
        assert!(refused(&r));
        let mut r = route();
        r.send.optional_threshold = 1;
        assert!(refused(&r));

        // The gas floor is bounded both ways.
        let mut r = route();
        r.receive_gas = 0;
        assert!(refused(&r));
        r.receive_gas = MAX_LZ_RECEIVE_GAS + 1;
        assert!(refused(&r));
        r.receive_gas = MAX_LZ_RECEIVE_GAS;
        assert!(!refused(&r));

        // More DVNs than the account has room for: five fit, six do not.
        let mut r = route();
        r.send.required = (1..=5u8).map(|i| Pubkey::new_from_array([i; 32])).collect();
        assert!(!refused(&r));
        r.send.required = (1..=6u8).map(|i| Pubkey::new_from_array([i; 32])).collect();
        assert!(refused(&r));
    }

    #[test]
    fn a_route_account_holds_the_largest_route() {
        // Five DVNs in every list is the most `check_route` lets through, and it has to fit in
        // what `set_route` allocates.
        let full = Verifiers {
            confirmations: u64::MAX,
            required: vec![Pubkey::new_unique(); MAX_DVNS],
            optional: vec![Pubkey::new_unique(); MAX_DVNS],
            optional_threshold: 5,
        };
        let route = Route {
            eid: u32::MAX,
            send: full.clone(),
            receive: full,
            executor: Pubkey::new_unique(),
            max_message_size: u32::MAX,
            receive_gas: u64::MAX,
            bump: 255,
            edited_slot: u64::MAX,
        };
        let mut bytes = Vec::new();
        route.try_serialize(&mut bytes).unwrap();
        assert_eq!(bytes.len(), 8 + Route::INIT_SPACE);
        assert_eq!(bytes.len(), 739, "603, the slot it was last set in, and a fifth DVN in each of four lists");
    }
}
