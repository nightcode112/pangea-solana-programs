//! # The reserve: Solana's mint supply held at the token's global total
//!
//! **Launches no longer get one.** Since the 1B-per-chain release a launch's mint authority is
//! its OFT store, as for any Native OFT, its record has no reserve record, and its mint supply is
//! its real supply on Solana -- matching the EVM tokens, whose `totalSupply()` is now their local
//! supply. `arm` refuses such a launch (`NoReserve`) and `open_bridge` opens it at once. What
//! follows describes the launches made before, which keep their reserve and `rebalance`. (The v2
//! SUPPLY_TOTAL launches of the reserve era keep theirs too, in their tail -- `rebalance_v2`; those
//! since the lockbox have none: their share is locked in their OFT store's escrow and `rebalance`
//! refuses them, `Lockbox`.)
//!
//! A launch's token lives on five chains at once, and every chain but Solana reports the global
//! supply. On Solana the store is LayerZero's Native kind -- a transfer out burns here and a
//! transfer in mints here -- so the mint's own `supply`, which is what explorers and trackers
//! read, would be Solana's share alone: a fifth of the token at launch, and moving with every
//! transfer. The reserve makes it the global total, always, with LayerZero's OFT program left
//! exactly as LayerZero ships it.
//!
//! ## Two minters, one of them capped
//!
//! The mint's authority is a Token-2022 MULTISIG, one of two: the token's OFT store and this
//! program's `AUTHORITY`. LayerZero's program supports exactly this (`lz_receive.rs`: "a spl-token
//! multisig account with oft_store as one of the signers, and the quorum MUST be 1-of-n"): an
//! arrival mints through the multisig, the store signing, as it would mint as the authority
//! itself. The second signer is ours, and this program uses it for one thing: to mint into the
//! RESERVE, never anywhere else, and never more than brings the supply back to the launch total.
//!
//! The reserve is a token account of the launched token whose owner is the account itself, an
//! address of this program's (`RESERVE_SEED`). Nothing can move tokens out of it but a signature
//! for that address, and this program makes that signature in one place: `rebalance`, to BURN.
//! There is no transfer out of it, no delegate and no close authority, in any instruction.
//!
//! ## `rebalance`
//!
//! The launch's total is recorded at launch (a slice for Solana and one for each peer). Then:
//!
//!   * supply above the total -- an arrival minted on Solana what the EVM chain burned -- the
//!     excess is burned out of the reserve;
//!   * supply below the total -- a transfer out burned here what the EVM chain will mint -- the
//!     shortfall is minted into the reserve;
//!   * supply at the total: nothing, successfully. Anyone may send it, as often as they like.
//!
//! So the reserve always holds the total less what is on Solana outside it: what the EVM chains
//! hold, plus what is in flight towards them. The bridge's fees are not in that sum's way: `send`
//! moves the fee into the store's escrow -- real supply, never burned -- and `withdraw_fee` moves
//! it on to the platform, which changes no supply. Rebalancing and withdrawing never touch each
//! other's tokens.
//!
//! The reserve cannot run out under the invariant: an excess on Solana is a mint for an EVM-side
//! burn, and the EVM chains can only burn what they hold, which the reserve counts. If it ever
//! did -- more than the total existing at once, which only a fault in LayerZero or an EVM chain
//! could produce -- `rebalance` burns all the reserve has, and says what it could not
//! (`ReserveShort`) rather than failing: the transaction it rides in is often an arrival's.
//!
//! ## `arm`: after the launch, never before
//!
//! The launch transaction has no room for two more accounts and the five instructions this takes,
//! so a launch sets the mint's authority to `AUTHORITY` and `arm` follows it: a listed launcher
//! sends it, and it creates the multisig and the reserve, mints the reserve its share, and moves
//! the mint's authority to the multisig. Once: the record says it is armed, and the mint's
//! authority is no longer `AUTHORITY`. Until then `open_bridge` refuses the launch, so nothing can
//! cross before Solana's supply is the total (see `bridge`).
//!
//! ## `AUTHORITY` never signs a mint anywhere else
//!
//! `AUTHORITY` is one of every armed token's two minters. This program signs as it in other
//! places -- LayerZero admin calls, a dev buy's swap -- and a signature reaches the programs those
//! call. None of them is handed a launched mint writable, nor the multisig, so none can mint; any
//! new call made as `AUTHORITY` has to keep it that way.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::{program::invoke_signed, system_instruction};
use anchor_spl::token_2022::spl_token_2022;

use crate::{
    launch_id_of, splitter_of_launch, store_of_launch, LaunchRecord, Launcher, SplitterError, AUTHORITY_SEED, LAUNCHER_SEED, MINT_SEED,
    OFT_PROGRAM_ID, PEER_RECORD_AT, TOKEN_2022_ID, TOKEN_ACCOUNT_LEN, TOKEN_DECIMALS,
};

/// The multisig that is an armed token's mint authority: `PDA([b"minter", launch record])`.
pub const MINTER_SEED: &[u8] = b"minter";
/// The reserve: `PDA([b"reserve", launch record])`, a token account of the launched token owned
/// by itself.
pub const RESERVE_SEED: &[u8] = b"reserve";

/// A Token-2022 multisig: `Multisig::LEN`.
pub const MULTISIG_LEN: usize = 355;

/// What a launch's record holds after its peers: the launch total (8 bytes), whether it is armed
/// (1), and the bumps of the multisig and the reserve (1 each), which `arm` writes.
pub const RESERVE_RECORD_LEN: usize = 11;

/// Where the reserve record starts in a record of `peers` peers, as `launch` writes it (the
/// per-peer layout; see `PEER_RECORD_AT`). A record already written is read with
/// `crate::peer_record_end`, which knows both layouts.
pub const fn reserve_record_at(peers: usize) -> usize {
    PEER_RECORD_AT + crate::PEER_RECORD_HEAD + crate::PEER_ENTRY_LEN * peers
}

/// What the reserve record says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReserveRecord {
    pub total: u64,
    pub armed: bool,
    pub minter_bump: u8,
    pub reserve_bump: u8,
}

/// The reserve record of a launch's record data, or None if the record has none (or is not a
/// launch's record at all). A record made before launches kept one is exactly that much shorter.
pub fn read_reserve_record(record_data: &[u8]) -> Option<ReserveRecord> {
    // A v2 record's tail is not a reserve record (a SUPPLY_TOTAL launch's reserve is in its tail:
    // `crate::read_v2_tail`).
    if crate::read_v2_tail(record_data).is_some() {
        return None;
    }
    // After the peers, in whichever layout the launch wrote them.
    let at = crate::peer_record_end(record_data)?;
    let b = record_data.get(at..at + RESERVE_RECORD_LEN)?;
    Some(ReserveRecord {
        total: u64::from_le_bytes(b[..8].try_into().ok()?),
        armed: b[8] == 1,
        minter_bump: b[9],
        reserve_bump: b[10],
    })
}

/// Write the launch total, unarmed: `launch` does, once.
pub fn write_reserve_record(record_data: &mut [u8], peers: usize, total: u64) {
    let at = reserve_record_at(peers);
    record_data[at..at + 8].copy_from_slice(&total.to_le_bytes());
    record_data[at + 8..at + RESERVE_RECORD_LEN].fill(0);
}

/// Whether a launch's record says its bridge may open: armed -- or a record from before launches
/// kept a reserve, whose token mints and burns as it always did (the TEST token).
pub fn bridge_may_open(record_data: &[u8]) -> bool {
    match read_reserve_record(record_data) {
        Some(r) => r.armed,
        None => true,
    }
}

/// The multisig and reserve of a launch's record.
pub fn minter_of(record: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[MINTER_SEED, record.as_ref()], &crate::ID)
}
pub fn reserve_of(record: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[RESERVE_SEED, record.as_ref()], &crate::ID)
}

// A Token-2022 mint's base fields, at their offsets.
const MINT_AUTHORITY_TAG: usize = 0;
const MINT_AUTHORITY: usize = 4;
const MINT_SUPPLY: usize = 36;

/// A mint's authority and supply, from its data.
pub fn read_mint(data: &[u8]) -> Option<(Option<Pubkey>, u64)> {
    let tag = u32::from_le_bytes(data.get(MINT_AUTHORITY_TAG..MINT_AUTHORITY_TAG + 4)?.try_into().ok()?);
    let key = Pubkey::new_from_array(data.get(MINT_AUTHORITY..MINT_AUTHORITY + 32)?.try_into().ok()?);
    let supply = u64::from_le_bytes(data.get(MINT_SUPPLY..MINT_SUPPLY + 8)?.try_into().ok()?);
    Some(((tag == 1).then_some(key), supply))
}

// A token account's owner, delegate and close authority, at their offsets.
const ACCOUNT_OWNER: usize = 32;
const ACCOUNT_DELEGATE_TAG: usize = 72;
const ACCOUNT_CLOSE_TAG: usize = 129;

/// What `rebalance` has to do: mint this much into the reserve, burn this much out of it, or
/// nothing -- and how much of an excess the reserve could not cover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Move {
    Nothing,
    Mint(u64),
    Burn { amount: u64, short: u64 },
}

/// The move that brings `supply` to `total`, out of a reserve holding `reserve`.
pub fn rebalance_move(supply: u64, total: u64, reserve: u64) -> Move {
    if supply < total {
        Move::Mint(total - supply)
    } else if supply > total {
        let excess = supply - total;
        let amount = excess.min(reserve);
        Move::Burn { amount, short: excess - amount }
    } else {
        Move::Nothing
    }
}

// ------------------------------------------------------------------------------------- arm

#[derive(Accounts)]
#[instruction(launch_seed: [u8; 32], mint_nonce: u32)]
pub struct Arm<'info> {
    /// A listed launcher, who pays the multisig's and the reserve's rent.
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(seeds = [LAUNCHER_SEED, payer.key().as_ref()], bump = launcher.bump)]
    pub launcher: Box<Account<'info, Launcher>>,
    /// CHECK: the launch's record, which the seed derives: compared in the handler.
    #[account(mut)]
    pub record: UncheckedAccount<'info>,
    /// CHECK: the launch's mint, at the address the seed and nonce derive.
    #[account(mut, seeds = [MINT_SEED, launch_seed.as_ref(), &mint_nonce.to_le_bytes()], bump)]
    pub mint: UncheckedAccount<'info>,
    /// CHECK: the launch's OFT store, which the seed derives: compared in the handler. One of the
    /// multisig's two signers.
    pub oft_store: UncheckedAccount<'info>,
    /// CHECK: the mint's authority until now, and the multisig's other signer.
    #[account(seeds = [AUTHORITY_SEED], bump)]
    pub authority: UncheckedAccount<'info>,
    /// CHECK: created here.
    #[account(mut, seeds = [MINTER_SEED, record.key().as_ref()], bump)]
    pub minter: UncheckedAccount<'info>,
    /// CHECK: created here.
    #[account(mut, seeds = [RESERVE_SEED, record.key().as_ref()], bump)]
    pub reserve: UncheckedAccount<'info>,
    /// CHECK: pinned.
    #[account(address = TOKEN_2022_ID @ SplitterError::WrongProgram)]
    pub token_2022_program: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[event]
pub struct ReserveArmed {
    pub launch_id: [u8; 32],
    pub mint: Pubkey,
    pub minter: Pubkey,
    pub reserve: Pubkey,
    pub total: u64,
    pub reserved: u64,
}

/// Allocate `space` at a PDA of ours for `owner`, paid by `payer`, whether or not somebody has
/// sent lamports there first (anyone can, once the launch's seed is public).
pub(crate) fn allocate<'info>(all: &[AccountInfo<'info>], payer: &Pubkey, account: &AccountInfo<'info>, space: usize, owner: &Pubkey, seeds: &[&[u8]]) -> Result<()> {
    let rent = Rent::get()?.minimum_balance(space);
    let held = account.lamports();
    if held == 0 {
        invoke_signed(&system_instruction::create_account(payer, account.key, rent, space as u64, owner), all, &[seeds])?;
        return Ok(());
    }
    require!(account.data_is_empty() && *account.owner == anchor_lang::system_program::ID, SplitterError::AlreadyArmed);
    if held < rent {
        invoke_signed(&system_instruction::transfer(payer, account.key, rent - held), all, &[])?;
    }
    invoke_signed(&system_instruction::allocate(account.key, space as u64), all, &[seeds])?;
    invoke_signed(&system_instruction::assign(account.key, owner), all, &[seeds])?;
    Ok(())
}

pub fn arm_handler(ctx: Context<Arm>, launch_seed: [u8; 32], _mint_nonce: u32) -> Result<()> {
    let a = &ctx.accounts;
    // The launch's record and store, by its seed.
    require_keys_eq!(a.record.key(), splitter_of_launch(&launch_seed), SplitterError::NotThisLaunch);
    require_keys_eq!(*a.record.owner, crate::ID, SplitterError::NotThisLaunch);
    require_keys_eq!(a.oft_store.key(), store_of_launch(&launch_seed), SplitterError::NotThisLaunch);
    require_keys_eq!(*a.oft_store.owner, OFT_PROGRAM_ID, SplitterError::NotThisLaunch);
    let record = read_reserve_record(&a.record.try_borrow_data()?).ok_or(SplitterError::NoReserve)?;
    require!(!record.armed, SplitterError::AlreadyArmed);
    // The mint is the launch's, and still answers to AUTHORITY alone: what `launch` left it.
    require_keys_eq!(*a.mint.owner, TOKEN_2022_ID, SplitterError::NotThisLaunch);
    let (mint_authority, supply) = read_mint(&a.mint.try_borrow_data()?).ok_or(SplitterError::NotThisLaunch)?;
    require!(mint_authority == Some(a.authority.key()), SplitterError::AlreadyArmed);
    require!(supply <= record.total, SplitterError::Overflow);

    let all = a.to_account_infos();
    let t22 = TOKEN_2022_ID;
    let (payer, record_key, authority) = (a.payer.key(), a.record.key(), a.authority.key());
    let authority_seeds: &[&[u8]] = &[AUTHORITY_SEED, &[ctx.bumps.authority]];
    let minter_seeds: &[&[u8]] = &[MINTER_SEED, record_key.as_ref(), &[ctx.bumps.minter]];
    let reserve_seeds: &[&[u8]] = &[RESERVE_SEED, record_key.as_ref(), &[ctx.bumps.reserve]];

    // ---- the multisig: one of two, the store and AUTHORITY
    allocate(&all, &payer, &a.minter.to_account_info(), MULTISIG_LEN, &t22, minter_seeds)?;
    let store = a.oft_store.key();
    let ix = spl_token_2022::instruction::initialize_multisig2(&t22, &a.minter.key(), &[&store, &authority], 1)?;
    invoke_signed(&ix, &all, &[])?;

    // ---- the reserve: the launched token, owned by its own address
    let reserve = a.reserve.key();
    allocate(&all, &payer, &a.reserve.to_account_info(), TOKEN_ACCOUNT_LEN, &t22, reserve_seeds)?;
    let ix = spl_token_2022::instruction::initialize_account3(&t22, &reserve, &a.mint.key(), &reserve)?;
    invoke_signed(&ix, &all, &[])?;

    // ---- its share, minted while AUTHORITY is still the mint's authority, then the authority moved
    let reserved = record.total - supply;
    if reserved > 0 {
        let ix = spl_token_2022::instruction::mint_to_checked(&t22, &a.mint.key(), &reserve, &authority, &[], reserved, TOKEN_DECIMALS)?;
        invoke_signed(&ix, &all, &[authority_seeds])?;
    }
    let ix = spl_token_2022::instruction::set_authority(
        &t22,
        &a.mint.key(),
        Some(&a.minter.key()),
        spl_token_2022::instruction::AuthorityType::MintTokens,
        &authority,
        &[],
    )?;
    invoke_signed(&ix, &all, &[authority_seeds])?;

    // ---- and the record says so, with the bumps `rebalance` derives the two addresses from
    {
        let mut data = a.record.try_borrow_mut_data()?;
        let at = crate::peer_record_end(&data).ok_or(SplitterError::NoReserve)?;
        data[at + 8] = 1;
        data[at + 9] = ctx.bumps.minter;
        data[at + 10] = ctx.bumps.reserve;
    }
    emit!(ReserveArmed { launch_id: launch_id_of(&launch_seed), mint: a.mint.key(), minter: a.minter.key(), reserve, total: record.total, reserved });
    Ok(())
}

// ------------------------------------------------------------------------------- rebalance

#[derive(Accounts)]
pub struct Rebalance<'info> {
    /// CHECK: a launch's record, for its total and its two bumps: this program's, armed.
    pub record: UncheckedAccount<'info>,
    /// CHECK: the launched token: the one whose mint authority is this record's multisig.
    #[account(mut)]
    pub mint: UncheckedAccount<'info>,
    /// CHECK: the record's multisig, derived from it in the handler.
    pub minter: UncheckedAccount<'info>,
    /// CHECK: the record's reserve, derived from it in the handler.
    #[account(mut)]
    pub reserve: UncheckedAccount<'info>,
    /// CHECK: the multisig's signer that is ours.
    #[account(seeds = [AUTHORITY_SEED], bump)]
    pub authority: UncheckedAccount<'info>,
    /// CHECK: pinned.
    #[account(address = TOKEN_2022_ID @ SplitterError::WrongProgram)]
    pub token_2022_program: UncheckedAccount<'info>,
}

#[event]
pub struct Rebalanced {
    pub mint: Pubkey,
    pub total: u64,
    /// What the supply was before.
    pub supply: u64,
    pub minted: u64,
    pub burned: u64,
}

/// More was on Solana than the launch's total and the reserve could take back: the rest of the
/// excess, which no instruction of this program can burn. See "the reserve cannot run out".
#[event]
pub struct ReserveShort {
    pub mint: Pubkey,
    pub short: u64,
}

pub fn rebalance_handler(ctx: Context<Rebalance>) -> Result<()> {
    let a = &ctx.accounts;
    require_keys_eq!(*a.record.owner, crate::ID, SplitterError::NotThisLaunch);
    let (record, v2) = {
        let data = a.record.try_borrow_data()?;
        require!(data.get(..8) == Some(&<LaunchRecord as anchor_lang::Discriminator>::discriminator()[..]), SplitterError::NotThisLaunch);
        match crate::read_v2_tail(&data) {
            Some(tail) => (None, Some(tail.reserve.ok_or(SplitterError::NoReserve)?)),
            None => (Some(read_reserve_record(&data).ok_or(SplitterError::NoReserve)?), None),
        }
    };
    if let Some(r) = v2 {
        return rebalance_v2(&ctx, r);
    }
    let record = record.ok_or(SplitterError::NoReserve)?;
    require!(record.armed, SplitterError::NotArmed);
    let record_key = a.record.key();
    let minter = Pubkey::create_program_address(&[MINTER_SEED, record_key.as_ref(), &[record.minter_bump]], &crate::ID)
        .map_err(|_| error!(SplitterError::NotThisLaunch))?;
    let reserve = Pubkey::create_program_address(&[RESERVE_SEED, record_key.as_ref(), &[record.reserve_bump]], &crate::ID)
        .map_err(|_| error!(SplitterError::NotThisLaunch))?;
    require_keys_eq!(a.minter.key(), minter, SplitterError::NotThisLaunch);
    require_keys_eq!(a.reserve.key(), reserve, SplitterError::NotThisLaunch);
    // The mint is the one this record's multisig mints: only `arm` made it so.
    require_keys_eq!(*a.mint.owner, TOKEN_2022_ID, SplitterError::NotThisLaunch);
    let (mint_authority, supply) = read_mint(&a.mint.try_borrow_data()?).ok_or(SplitterError::NotThisLaunch)?;
    require!(mint_authority == Some(minter), SplitterError::NotThisLaunch);
    // And the reserve is its, owned by itself, as `arm` made it.
    require_keys_eq!(*a.reserve.owner, TOKEN_2022_ID, SplitterError::NotThisLaunch);
    let held = {
        let data = a.reserve.try_borrow_data()?;
        let (mint, amount) = crate::read_token_account(&data).ok_or(SplitterError::NotThisLaunch)?;
        require_keys_eq!(mint, a.mint.key(), SplitterError::NotThisLaunch);
        let owner = Pubkey::new_from_array(data[ACCOUNT_OWNER..ACCOUNT_OWNER + 32].try_into().unwrap());
        require_keys_eq!(owner, reserve, SplitterError::NotThisLaunch);
        // Nobody can have been made a delegate or a closer of it: no instruction does.
        require!(data[ACCOUNT_DELEGATE_TAG] == 0 && data[ACCOUNT_CLOSE_TAG] == 0, SplitterError::NotThisLaunch);
        amount
    };

    let all = a.to_account_infos();
    let t22 = TOKEN_2022_ID;
    let mint = a.mint.key();
    let (minted, burned) = match rebalance_move(supply, record.total, held) {
        Move::Nothing => (0, 0),
        Move::Mint(amount) => {
            let ix = spl_token_2022::instruction::mint_to_checked(&t22, &mint, &reserve, &minter, &[&a.authority.key()], amount, TOKEN_DECIMALS)?;
            invoke_signed(&ix, &all, &[&[AUTHORITY_SEED, &[ctx.bumps.authority]]])?;
            (amount, 0)
        }
        Move::Burn { amount, short } => {
            if amount > 0 {
                let ix = spl_token_2022::instruction::burn_checked(&t22, &reserve, &mint, &reserve, &[], amount, TOKEN_DECIMALS)?;
                invoke_signed(&ix, &all, &[&[RESERVE_SEED, record_key.as_ref(), &[record.reserve_bump]]])?;
            }
            if short > 0 {
                msg!("the reserve is {} short of the excess", short);
                emit!(ReserveShort { mint, short });
            }
            (0, amount)
        }
    };
    if minted > 0 || burned > 0 {
        emit!(Rebalanced { mint, total: record.total, supply, minted, burned });
    }
    Ok(())
}

/// The owner of a v2 SUPPLY_TOTAL launch's reserve (its `token_a` account): the launch's RECORD,
/// an address of this program's that it signs for in one place only -- `rebalance`, to burn. (The
/// record is already every `rebalance`'s account, so the burn needs no account more.)
pub fn reserve_authority_of(record: &Pubkey) -> Pubkey {
    *record
}

/// `rebalance` for a SUPPLY_TOTAL launch made by `launch_v2` or `launch_self`: the same moves as
/// for the launches of the reserve era, with the reserve in the launch's `token_a` account
/// (owned by the launch's record, which signs only the burn below) and the minter made in
/// the launch itself.
fn rebalance_v2(ctx: &Context<Rebalance>, r: crate::ReserveV2) -> Result<()> {
    // A lockbox launch has no reserve and no minter: nothing to move, refused by name.
    require!(!r.is_lockbox(), SplitterError::Lockbox);
    let a = &ctx.accounts;
    let record_key = a.record.key();
    require_keys_eq!(a.minter.key(), r.minter, SplitterError::NotThisLaunch);
    require_keys_eq!(a.reserve.key(), r.reserve, SplitterError::NotThisLaunch);
    // The record signs the burn: its own seeds, from its own data.
    let (nft, record_bump) = {
        let data = a.record.try_borrow_data()?;
        let rec = LaunchRecord::try_deserialize(&mut &data[..])?;
        (rec.position_nft_mint, rec.bump)
    };
    require_keys_eq!(Pubkey::create_program_address(&[crate::SPLITTER_SEED, nft.as_ref(), &[record_bump]], &crate::ID).map_err(|_| error!(SplitterError::NotThisLaunch))?, record_key, SplitterError::NotThisLaunch);
    let reserve_authority = record_key;
    // The mint is the one this record's minter mints: the launch named it its authority.
    require_keys_eq!(*a.mint.owner, TOKEN_2022_ID, SplitterError::NotThisLaunch);
    let (mint_authority, supply) = read_mint(&a.mint.try_borrow_data()?).ok_or(SplitterError::NotThisLaunch)?;
    require!(mint_authority == Some(r.minter), SplitterError::NotThisLaunch);
    require_keys_eq!(*a.reserve.owner, TOKEN_2022_ID, SplitterError::NotThisLaunch);
    let held = {
        let data = a.reserve.try_borrow_data()?;
        let (mint, amount) = crate::read_token_account(&data).ok_or(SplitterError::NotThisLaunch)?;
        require_keys_eq!(mint, a.mint.key(), SplitterError::NotThisLaunch);
        let owner = Pubkey::new_from_array(data[ACCOUNT_OWNER..ACCOUNT_OWNER + 32].try_into().unwrap());
        require_keys_eq!(owner, reserve_authority, SplitterError::NotThisLaunch);
        require!(data[ACCOUNT_DELEGATE_TAG] == 0 && data[ACCOUNT_CLOSE_TAG] == 0, SplitterError::NotThisLaunch);
        amount
    };
    let all = a.to_account_infos();
    let t22 = TOKEN_2022_ID;
    let mint = a.mint.key();
    let (minted, burned) = match rebalance_move(supply, r.total, held) {
        Move::Nothing => (0, 0),
        Move::Mint(amount) => {
            // The minter the launch made.
            require!(*a.minter.owner == t22 && a.minter.data_len() == MULTISIG_LEN, SplitterError::NotArmed);
            let ix = spl_token_2022::instruction::mint_to_checked(&t22, &mint, &r.reserve, &r.minter, &[&a.authority.key()], amount, TOKEN_DECIMALS)?;
            invoke_signed(&ix, &all, &[&[AUTHORITY_SEED, &[ctx.bumps.authority]]])?;
            (amount, 0)
        }
        Move::Burn { amount, short } => {
            if amount > 0 {
                let ix = spl_token_2022::instruction::burn_checked(&t22, &r.reserve, &mint, &reserve_authority, &[], amount, TOKEN_DECIMALS)?;
                invoke_signed(&ix, &all, &[&[crate::SPLITTER_SEED, nft.as_ref(), &[record_bump]]])?;
            }
            if short > 0 {
                msg!("the reserve is {} short of the excess", short);
                emit!(ReserveShort { mint, short });
            }
            (0, amount)
        }
    };
    if minted > 0 || burned > 0 {
        emit!(Rebalanced { mint, total: r.total, supply, minted, burned });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rebalance_moves_the_supply_to_the_total_and_nowhere_else() {
        let t = 1_000_000_000_000_000_000u64;
        assert_eq!(rebalance_move(t, t, 800), Move::Nothing);
        assert_eq!(rebalance_move(t - 5, t, 800), Move::Mint(5));
        assert_eq!(rebalance_move(t + 5, t, 800), Move::Burn { amount: 5, short: 0 });
        assert_eq!(rebalance_move(t + 900, t, 800), Move::Burn { amount: 800, short: 100 });
        assert_eq!(rebalance_move(t + 1, t, 0), Move::Burn { amount: 0, short: 1 });
        assert_eq!(rebalance_move(0, t, 0), Move::Mint(t));
    }

    #[test]
    fn the_reserve_record_is_after_the_peers() {
        let peers = 4;
        let mut data = vec![0u8; reserve_record_at(peers) + RESERVE_RECORD_LEN];
        crate::write_peer_record(&mut data, &[(30101, [7; 20]), (30102, [8; 20]), (30184, [9; 20]), (30416, [10; 20])]);
        write_reserve_record(&mut data, peers, 1_000);
        assert_eq!(read_reserve_record(&data), Some(ReserveRecord { total: 1_000, armed: false, minter_bump: 0, reserve_bump: 0 }));
        assert!(!bridge_may_open(&data));
        // A record of the length launches had before the reserve: no reserve record, opens as it did.
        assert_eq!(read_reserve_record(&data[..data.len() - RESERVE_RECORD_LEN]), None);
        assert!(bridge_may_open(&data[..data.len() - RESERVE_RECORD_LEN]));
        let at = reserve_record_at(peers);
        data[at + 8] = 1;
        assert!(bridge_may_open(&data));
        // A launch now writes no reserve record (`launch_record_len`); one made before kept these 11.
        assert_eq!(crate::launch_record_len(peers) + RESERVE_RECORD_LEN, 8 + 20 + 1 + 22 * peers + RESERVE_RECORD_LEN);
    }

    /// A launch from before each EVM chain had its own token address (TEST2, TEST3): one token,
    /// then the ids. Its reserve record is found after the ids, armed or not, and one older still
    /// (no reserve record at all) opens as it always did.
    #[test]
    fn a_one_token_records_reserve_is_found_where_it_was_written() {
        let eids: [u16; 4] = [30101, 30102, 30184, 30416];
        let at = PEER_RECORD_AT + 20 + 1 + 2 * eids.len();
        let mut data = vec![0u8; at + RESERVE_RECORD_LEN];
        data[PEER_RECORD_AT..PEER_RECORD_AT + 20].copy_from_slice(&[7; 20]);
        data[PEER_RECORD_AT + 20] = eids.len() as u8;
        for (i, eid) in eids.iter().enumerate() {
            data[PEER_RECORD_AT + 21 + 2 * i..PEER_RECORD_AT + 23 + 2 * i].copy_from_slice(&eid.to_le_bytes());
        }
        data[at..at + 8].copy_from_slice(&5_000u64.to_le_bytes());
        assert_eq!(crate::peer_record_end(&data), Some(at));
        assert_eq!(read_reserve_record(&data), Some(ReserveRecord { total: 5_000, armed: false, minter_bump: 0, reserve_bump: 0 }));
        assert!(!bridge_may_open(&data));
        data[at + 8] = 1;
        assert!(bridge_may_open(&data));
        assert_eq!(read_reserve_record(&data[..at]), None);
        assert!(bridge_may_open(&data[..at]));
    }
}
