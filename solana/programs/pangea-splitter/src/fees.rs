//! The fee split, shared by every launch.
//!
//! ## One owner, one account per asset, and a record per launch
//!
//! A launch's pool fees are split between its creator and the platform: a fifth of the pool's fee,
//! never less than 0.2% of volume, to the platform, and the rest to the creator (`platform_share`).
//! That used to need, for every launch, a `Splitter` account that owned the locked position and two
//! token accounts of its own the fees were claimed into -- 2,039,280 lamports of rent each, made by
//! every launch, holding nothing between claims.
//!
//! Now the program has ONE fee owner, `PDA(["fees"])`, which holds every launch's position NFT, and
//! ONE account per quote asset, `PDA(["fees", quote mint])`, that fees are claimed into. A launch
//! keeps only its record (`LaunchRecord`, at the address its splitter had): who is paid, at what
//! fee, out of which position, in which asset.
//!
//! ## A shared account never holds one launch's fees for another
//!
//! `claim_fees` claims one launch's fees into the shared account and pays every unit of what
//! ARRIVED -- the account's balance after the claim less its balance before -- out to that launch's
//! creator and the platform, in the same instruction. Nothing a claim brings in is left behind,
//! so between instructions the shared account holds only what somebody sent it directly, which no
//! claim ever pays out (it is not any launch's fees).
//!
//! A claim names both destinations or it does not happen: there is no splitting one side now and
//! the other later, because there is nowhere to keep the other side meanwhile. A creator without an
//! account for the asset has their fees wait in the pool, where they accrue, until one exists --
//! anyone may make the creator's associated account, and the claimer does so in the same
//! transaction.
//!
//! ## Wrapped SOL is paid to the creator as SOL
//!
//! Where the quote is wrapped SOL and the claim names the creator's wallet, the creator's share
//! reaches that wallet as lamports, not as wrapped SOL (`SolPayout`), and the creator needs no
//! token account at all. The amount is the same to the lamport; only its form differs. The
//! platform's share stays wrapped SOL. Every other quote asset is paid in that asset, as before.
//!
//! ## Who is paid
//!
//! The creator, from the launch's record, handed over in two steps (`propose_creator`, then
//! `accept_creator` by the new key; the admin may propose too). The platform, from the one
//! program-wide `Platform` record -- the admin (`ADMIN`) until a platform payee is set, the same two
//! steps -- so rotating the platform's payout address is one change for every launch, not one per
//! launch.
//!
//! Permissionless: the caller chooses only when a claim happens, never where the money goes.

use anchor_lang::prelude::*;
use anchor_lang::system_program::{allocate, assign, create_account, transfer, Allocate, Assign, CreateAccount, Transfer};
use anchor_lang::solana_program::{incinerator, program_pack::Pack};
use anchor_spl::token::spl_token;
use anchor_spl::token_interface::{
    close_account, initialize_account3, transfer_checked, CloseAccount, InitializeAccount3, Mint, TokenAccount, TokenInterface,
    TransferChecked,
};

use crate::{inspect_mint, platform_share_at, read_token_account, venue, SplitterError, ADMIN, SPLITTER_SEED};

/// The program's fee owner: `PDA(["fees"])` holds every launch's locked position, and is the owner
/// of each shared fee account, `PDA(["fees", quote mint])`.
pub const FEES_SEED: &[u8] = b"fees";
/// The program-wide platform payee record: `PDA(["platform"])`.
pub const PLATFORM_SEED: &[u8] = b"platform";
/// The account a wrapped-SOL claim passes the creator's share through to pay it as SOL:
/// `PDA(["native"])`. It exists only inside `claim_fees`: made, filled and closed in one
/// instruction (`pay_creator_in_sol`), so between instructions it is never a token account.
pub const NATIVE_SEED: &[u8] = b"native";
/// `PDA(["native"])`'s bump, so that a claim derives it with one hash rather than a search
/// (`tests::the_native_transit_bump_is_the_canonical_one` pins it).
#[cfg(not(feature = "test-stack"))] pub const NATIVE_BUMP: u8 = 254; #[cfg(feature = "test-stack")] pub const NATIVE_BUMP: u8 = crate::TEST_STACK_NATIVE_BUMP;

/// `PDA(["native"])`, the transit a wrapped-SOL claim pays the creator's share as SOL through.
pub fn native_transit() -> Pubkey {
    Pubkey::create_program_address(&[NATIVE_SEED, &[NATIVE_BUMP]], &crate::ID).expect("the bump is off the curve")
}

/// One launch's record: who its fees are paid to, at what fee, out of which position. At
/// `PDA(["splitter", position NFT mint])`, the address the launch's splitter had, followed by the
/// launch's slot and peers (`LAUNCHED_SLOT_AT`, `PEER_RECORD_AT`).
#[account]
#[derive(InitSpace)]
pub struct LaunchRecord {
    pub creator: Pubkey,
    pub pending_creator: Pubkey,
    /// The venue's position the launch's liquidity is locked in.
    pub position: Pubkey,
    pub position_nft_mint: Pubkey,
    /// What the pool is paired against, and so what its fees are paid in.
    pub quote_mint: Pubkey,
    /// The pool's fee at launch. A claim splits by the fee the pool charges NOW (`venue::current_fee`):
    /// Meteora's operator can change it, and the split follows.
    pub fee_bps: u16,
    /// The share of the pool's fee that reached the position at launch (`venue::VENUE_LP_SHARE_BPS`);
    /// a claim reads the pool's current share too.
    pub venue_lp_share_bps: u16,
    pub bump: u8,
    /// Whether the launch made the creator's dev buy: then the account the slice came out of is the
    /// creator's, holding what they bought.
    pub dev_buy_made: bool,
}

/// The program-wide platform payee. Until one is set, the platform is `ADMIN`.
#[account]
#[derive(InitSpace)]
pub struct Platform {
    pub platform: Pubkey,
    pub pending_platform: Pubkey,
    pub bump: u8,
}

/// Who the platform is: the record's, or `ADMIN` while there is none.
pub fn platform_of(config: &AccountInfo) -> Result<Pubkey> {
    if config.data_is_empty() {
        return Ok(ADMIN);
    }
    require_keys_eq!(*config.owner, crate::ID, SplitterError::NotThisLaunch);
    let p = Platform::try_deserialize(&mut &config.try_borrow_data()?[..])?;
    Ok(if p.platform == Pubkey::default() { ADMIN } else { p.platform })
}

// ------------------------------------------------------------------------------ claiming

#[derive(Accounts)]
pub struct ClaimFees<'info> {
    /// Anyone. Pays, the first time an asset's fees are claimed, the rent of the program's account
    /// for that asset; nothing else.
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(seeds = [SPLITTER_SEED, record.position_nft_mint.as_ref()], bump = record.bump)]
    pub record: Box<Account<'info, LaunchRecord>>,
    /// CHECK: the program's fee owner, which holds the position and signs the claim.
    #[account(seeds = [FEES_SEED], bump)]
    pub fee_owner: UncheckedAccount<'info>,
    /// CHECK: where the claim lands, for the length of this instruction: the program's account for
    /// the asset, at its address (`seeds`), made by the first claim in it (`make_fee_account`).
    /// Only this program can allocate an address of its own, so an account there owned by the
    /// quote's token program is the one it made.
    #[account(mut, seeds = [FEES_SEED, quote_mint.key().as_ref()], bump)]
    pub fee_account: UncheckedAccount<'info>,
    #[account(address = record.quote_mint @ SplitterError::NotThisLaunch)]
    pub quote_mint: Box<InterfaceAccount<'info, Mint>>,
    /// CHECK: the creator's account for the asset, when their share is paid in it. Any account of
    /// theirs: its token program, owner and mint are checked by `creator_token_account` -- whenever
    /// it is paid into, and only then. A wrapped-SOL claim that pays the creator in SOL
    /// (`sol_payout`) does not touch it, so it need not exist.
    #[account(mut)]
    pub creator_quote: UncheckedAccount<'info>,
    /// CHECK: the program-wide platform record, which may not exist yet (the platform is then
    /// `ADMIN`); read by `platform_of`.
    #[account(seeds = [PLATFORM_SEED], bump)]
    pub platform_config: UncheckedAccount<'info>,
    /// The platform's account for the asset; its owner is checked against `platform_of`.
    #[account(mut, token::mint = quote_mint, token::token_program = quote_program)]
    pub platform_quote: Box<InterfaceAccount<'info, TokenAccount>>,
    pub quote_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
    // Then the venue's accounts for the claim, in `venue::CLAIM_ACCOUNTS` order. Then, optionally,
    // for a wrapped-SOL launch whose creator is to be paid in SOL: the creator's wallet (the
    // record's `creator`, writable) and `PDA(["native"])` (writable). See `sol_payout`.
}

/// A wrapped-SOL creator payout made as SOL, not wrapped SOL (2026-10-22: many wallets hide a
/// wrapped-SOL account, and creators thought their fees never arrived).
///
/// The claim names the creator's wallet and `PDA(["native"])` after the venue's accounts. The
/// creator's share goes from the program's fee account into a wrapped-SOL account made at that
/// address for the moment, owned by the fee owner; the fee owner closes it to the claim's payer,
/// who in the same instruction sends the creator's share on to the creator's wallet. The payer
/// ends where it started (the rent it put up comes back); the creator receives exactly the share
/// they would have received as wrapped SOL, as lamports.
///
/// The two accounts are optional so that a claim built before this existed still works, and still
/// pays wrapped SOL. Given, they must be exactly the creator's wallet and that address. They are
/// used only when the quote is wrapped SOL under the SPL Token program, the creator has something
/// to be paid, and the wallet can take it: a plain wallet -- owned by the system program, no data,
/// on the curve (lamports on a program's account, or on a program's derived address, may be
/// lamports nobody can move), writable -- and either the incinerator
/// (whose lamports the runtime burns and does not hold to rent) or left at least rent-exempt -- the
/// runtime refuses to leave an account between nothing and rent-exempt -- and the claim's payer can
/// put up the transit's rent for the moment (a plain account holding it). Otherwise the creator is
/// paid in wrapped SOL, as before.
pub struct SolPayout<'a, 'info> {
    pub wallet: &'a AccountInfo<'info>,
    pub transit: &'a AccountInfo<'info>,
    pub transit_bump: u8,
}

/// Whether, and through what, this claim pays the creator's `to_creator` in SOL. `extra` is what
/// follows the venue's accounts.
pub fn sol_payout<'a, 'info>(a: &ClaimFees<'info>, extra: &'a [AccountInfo<'info>], to_creator: u64) -> Result<Option<SolPayout<'a, 'info>>> {
    if extra.is_empty() {
        return Ok(None);
    }
    require!(extra.len() == 2, SplitterError::NotThisLaunch);
    let (wallet, transit) = (&extra[0], &extra[1]);
    require_keys_eq!(wallet.key(), a.record.creator, SplitterError::NotThisLaunch);
    let transit_bump = NATIVE_BUMP;
    require_keys_eq!(transit.key(), native_transit(), SplitterError::NotThisLaunch);
    require!(transit.is_writable, SplitterError::NotThisLaunch);
    if a.quote_mint.key() != spl_token::native_mint::ID || a.quote_program.key() != spl_token::ID {
        return Ok(None);
    }
    if to_creator == 0 || wallet.key() == transit.key() {
        return Ok(None);
    }
    // A plain wallet only: owned by the system program and holding no data, which its key spends.
    // Lamports on an account some program owns -- a DAO's governance account, a smart wallet's
    // state -- are that program's to move, and many have no instruction that moves them: there
    // the share would be stranded, so such a creator is paid in the quote asset as before.
    if *wallet.owner != System::id() || !wallet.data_is_empty() || wallet.executable {
        return Ok(None);
    }
    // And a key somebody holds: an address on the curve. A program's derived address that only the
    // system program owns -- an escrow's or a distributor's authority, say -- is off it, and its
    // program may sign token transfers and never a lamport one: SOL there could be stranded. The
    // incinerator is off the curve too, and is paid in SOL because SOL there is burned, as intended.
    if wallet.key() != incinerator::ID && !on_curve(&wallet.key()) {
        return Ok(None);
    }
    // A wallet the runtime made read-only in this transaction (a key it reserves) cannot be paid.
    if !wallet.is_writable {
        return Ok(None);
    }
    // The payer puts up the transit's rent for the length of the instruction and passes the share
    // on with a system transfer: it must be a plain account that can. One that cannot -- short of
    // the rent, or holding data -- gets the claim it would have had before, in wrapped SOL.
    let payer = a.payer.to_account_info();
    let rent = Rent::get()?.minimum_balance(spl_token::state::Account::LEN);
    if *payer.owner != System::id() || !payer.data_is_empty() || payer.lamports().saturating_add(transit.lamports()) < rent {
        return Ok(None);
    }
    if wallet.key() != incinerator::ID {
        let after = wallet.lamports().checked_add(to_creator).ok_or(SplitterError::Overflow)?;
        if after < Rent::get()?.minimum_balance(0) {
            return Ok(None);
        }
    }
    Ok(Some(SolPayout { wallet, transit, transit_bump }))
}

/// Whether `key` is a point on ed25519: an address a keypair can sign for, not a derived one.
/// On chain, the curve25519 syscall (`Pubkey::is_on_curve` is not available there).
pub fn on_curve(key: &Pubkey) -> bool {
    #[cfg(target_os = "solana")]
    {
        // CURVE25519_EDWARDS = 0; the syscall returns 0 for a valid point.
        let mut unused = 0u8;
        unsafe { anchor_lang::solana_program::syscalls::sol_curve_validate_point(0, key.as_ref().as_ptr(), &mut unused) == 0 }
    }
    #[cfg(not(target_os = "solana"))]
    {
        key.is_on_curve()
    }
}

/// Pay `amount` of the fee account's wrapped SOL to the creator's wallet as SOL. See `SolPayout`.
fn pay_creator_in_sol<'info>(a: &ClaimFees<'info>, p: &SolPayout<'_, 'info>, fee_owner_seeds: &[&[u8]], amount: u64) -> Result<()> {
    let transit = p.transit;
    // Only this program can allocate its own address, and it always closes this one in the
    // instruction it made it: anything else here is not ours to reason about.
    require!(transit.data_is_empty() && *transit.owner == System::id(), SplitterError::NotThisLaunch);
    let space = spl_token::state::Account::LEN;
    let rent = Rent::get()?.minimum_balance(space);
    let seeds: &[&[u8]] = &[NATIVE_SEED, &[p.transit_bump]];
    let system = a.system_program.to_account_info();
    let payer = a.payer.to_account_info();
    let held = transit.lamports();
    // Its address is public, so it may hold lamports somebody sent; they go toward the rent (and
    // what is more than the rent comes back to the payer with it).
    if held == 0 {
        create_account(
            CpiContext::new_with_signer(system.clone(), CreateAccount { from: payer.clone(), to: transit.clone() }, &[seeds]),
            rent,
            space as u64,
            &spl_token::ID,
        )?;
    } else {
        if held < rent {
            transfer(CpiContext::new(system.clone(), Transfer { from: payer.clone(), to: transit.clone() }), rent - held)?;
        }
        allocate(CpiContext::new_with_signer(system.clone(), Allocate { account_to_allocate: transit.clone() }, &[seeds]), space as u64)?;
        assign(CpiContext::new_with_signer(system.clone(), Assign { account_to_assign: transit.clone() }, &[seeds]), &spl_token::ID)?;
    }
    let quote_program = a.quote_program.to_account_info();
    let quote_mint = a.quote_mint.to_account_info();
    let fee_owner = a.fee_owner.to_account_info();
    initialize_account3(CpiContext::new(
        quote_program.clone(),
        InitializeAccount3 { account: transit.clone(), mint: quote_mint.clone(), authority: fee_owner.clone() },
    ))?;
    transfer_checked(
        CpiContext::new_with_signer(
            quote_program.clone(),
            TransferChecked { from: a.fee_account.to_account_info(), mint: quote_mint, to: transit.clone(), authority: fee_owner.clone() },
            &[fee_owner_seeds],
        ),
        amount,
        a.quote_mint.decimals,
    )?;
    // Every lamport it holds -- the rent, the share, anything sent to the address -- to the payer...
    let before = payer.lamports();
    close_account(CpiContext::new_with_signer(
        quote_program,
        CloseAccount { account: transit.clone(), destination: payer.clone(), authority: fee_owner },
        &[fee_owner_seeds],
    ))?;
    require!(payer.lamports().checked_sub(before).ok_or(SplitterError::Overflow)? >= amount, SplitterError::Overflow);
    // ...who passes the share on, in the same instruction: the payer signed this transaction.
    if p.wallet.key() != payer.key() {
        transfer(CpiContext::new(system, Transfer { from: payer, to: p.wallet.clone() }), amount)?;
    }
    Ok(())
}

/// The creator's token account for the asset, checked as `ClaimFees` used to check it -- Anchor's
/// `InterfaceAccount<TokenAccount>` with `token::mint`, `token::authority` and
/// `token::token_program` -- in the same order and with the same errors: the quote's token program
/// owns it, it is of the quote mint, and the record's creator owns it.
fn creator_token_account<'info>(a: &ClaimFees<'info>) -> Result<()> {
    use anchor_lang::error::ErrorCode;
    let info = a.creator_quote.to_account_info();
    if *info.owner == System::id() && info.lamports() == 0 {
        return err!(ErrorCode::AccountNotInitialized);
    }
    require!(
        *info.owner == anchor_spl::token::ID || *info.owner == anchor_spl::token_2022::ID,
        ErrorCode::AccountOwnedByWrongProgram
    );
    let account = TokenAccount::try_deserialize(&mut &info.try_borrow_data()?[..])?;
    require_keys_eq!(account.mint, a.quote_mint.key(), ErrorCode::ConstraintTokenMint);
    require_keys_eq!(account.owner, a.record.creator, ErrorCode::ConstraintTokenOwner);
    require_keys_eq!(*info.owner, a.quote_program.key(), ErrorCode::ConstraintTokenTokenProgram);
    Ok(())
}

/// Whether the record's creator can move what `claim_fees` pays into its account for the asset
/// (audit round 6, L). A tokenomics account is this program's, takes its fees as wrapped SOL into
/// its vault (`claim_fees_native`), and has no instruction that moves any other asset: paid in one,
/// the share would sit in its associated account for good. So outside wrapped SOL an account of
/// this program is never paid -- the claim reverts, and the whole claim (the creator's share and
/// the platform's) stays in the pool until the admin moves the stream: `admin_set_payee` on a v2
/// launch, `admin_propose_creator` then `accept_creator` on a v1 one.
///
/// Nor, in any asset, an account of a program `owner_refused` lists (audit round 7, L): a token
/// account, a mint, a pool or position, an OFT store, a LayerZero account. The tokens would sit in
/// an associated account whose owner is an account that can never sign: refused, as above, rather
/// than stranded. (Wrapped SOL is checked so when the claim shows the creator, as every claim that
/// asks for SOL does; one that does not show it is paid as before.)
///
/// A key on the curve is somebody's wallet, which signs for its own token accounts whoever owns the
/// account at that address: it may always be paid, and so may the incinerator. Only an address off the curve -- a derived one,
/// which a tokenomics account is -- has to be shown: the claim gives the record's creator after the
/// venue's accounts (the pair `sol_payout` reads, with `PDA(["native"])`), and it must not be this
/// program's. One that does not exist yet is owned by the system program and is paid.
fn creator_spends_asset(a: &ClaimFees, extra: &[AccountInfo]) -> bool {
    if a.record.creator == incinerator::ID || on_curve(&a.record.creator) {
        return true;
    }
    // `sol_payout` has checked that a given `extra[0]` is the record's creator.
    let shown = extra.first().filter(|c| c.key() == a.record.creator);
    if a.quote_mint.key() == spl_token::native_mint::ID {
        return shown.map_or(true, |c| !owner_refused(c.owner));
    }
    shown.is_some_and(|c| (*c.owner != crate::ID && !owner_refused(c.owner)) || tokenomics_takes_asset(a, c))
}

/// Tokenomics v2.3: a v2 account bound to this launch whose quote is this launch's asset spends it
/// (`tokenomics_v2::quote_asset`), and is paid into its vault -- its associated account for the
/// asset, and only there.
fn tokenomics_takes_asset(a: &ClaimFees, c: &AccountInfo) -> bool {
    if *c.owner != crate::ID {
        return false;
    }
    let bound = c
        .try_borrow_data()
        .is_ok_and(|d| crate::TokenomicsV2::try_deserialize(&mut &d[..]).is_ok_and(|t| t.bound && t.record == a.record.key()));
    let q = crate::quote_of(c);
    bound && q.mint == a.quote_mint.key() && q.program == a.quote_program.key() && a.creator_quote.key() == q.vault(c.key)
}

#[event]
pub struct CreatorPaidInSol {
    pub record: Pubkey,
    pub creator: Pubkey,
    pub lamports: u64,
}

#[event]
pub struct FeesClaimed {
    pub record: Pubkey,
    pub quote_mint: Pubkey,
    pub amount: u64,
    pub to_creator: u64,
    pub to_platform: u64,
    /// The fee the split was made at: the pool's, as it stood at the claim.
    pub fee_numerator: u64,
    pub lp_share_bps: u16,
}

/// Make the program's account for the quote asset, the first time one of its fees is claimed, at
/// the size the asset's extensions require (`inspect_mint`: a transfer-hook account, a pausable
/// account). Not Anchor's `init`: it sizes a Token-2022 account by parsing the mint's extensions
/// with the token library it was built with, which refuses extensions newer than itself -- and an
/// allowlisted asset such as AAPLx carries some. Its address is public, so it may already hold
/// lamports somebody sent; they go toward the rent, as with every address `launch` makes.
fn make_fee_account<'info>(a: &ClaimFees<'info>, bump: u8) -> Result<()> {
    let account = a.fee_account.to_account_info();
    if !account.data_is_empty() {
        require_keys_eq!(*account.owner, a.quote_program.key(), SplitterError::NotThisLaunch);
        return Ok(());
    }
    let mint = a.quote_mint.to_account_info();
    let space = inspect_mint(mint.owner, &mint.try_borrow_data()?).ok_or(SplitterError::NotThisLaunch)?.account_len;
    let rent = Rent::get()?.minimum_balance(space);
    let mint_key = mint.key();
    let seeds: &[&[u8]] = &[FEES_SEED, mint_key.as_ref(), &[bump]];
    let system = a.system_program.to_account_info();
    let payer = a.payer.to_account_info();
    let owner = a.quote_program.key();
    let held = account.lamports();
    if held == 0 {
        create_account(
            CpiContext::new_with_signer(system, CreateAccount { from: payer, to: account.clone() }, &[seeds]),
            rent,
            space as u64,
            &owner,
        )?;
    } else {
        if held < rent {
            transfer(CpiContext::new(system.clone(), Transfer { from: payer, to: account.clone() }), rent - held)?;
        }
        allocate(CpiContext::new_with_signer(system.clone(), Allocate { account_to_allocate: account.clone() }, &[seeds]), space as u64)?;
        assign(CpiContext::new_with_signer(system, Assign { account_to_assign: account.clone() }, &[seeds]), &owner)?;
    }
    initialize_account3(CpiContext::new(
        a.quote_program.to_account_info(),
        InitializeAccount3 { account, mint, authority: a.fee_owner.to_account_info() },
    ))
}

/// The balance of the program's account for the asset.
fn held(account: &AccountInfo) -> Result<u64> {
    Ok(read_token_account(&account.try_borrow_data()?).ok_or(SplitterError::NotThisLaunch)?.1)
}

pub fn claim_fees_handler<'info>(ctx: Context<'_, '_, 'info, 'info, ClaimFees<'info>>) -> Result<()> {
    // A v2 launch paired against wrapped SOL is paid natively, and only so (Solana audit B1 M-1):
    // a stranger who made the payee's wrapped-SOL account could otherwise claim first and leave a
    // payee -- a tokenomics PDA, say -- holding wrapped SOL it cannot use.
    {
        let info = ctx.accounts.record.to_account_info();
        let data = info.try_borrow_data()?;
        let native = ctx.accounts.record.quote_mint == anchor_spl::token::spl_token::native_mint::ID;
        require!(!(native && crate::read_v2_tail(&data).is_some()), SplitterError::ClaimNatively);
    }
    let platform = platform_of(&ctx.accounts.platform_config)?;
    require_keys_eq!(ctx.accounts.platform_quote.owner, platform, SplitterError::NotThePlatform);
    make_fee_account(&ctx.accounts, ctx.bumps.fee_account)?;
    let r = &ctx.accounts.record;
    let bump = ctx.bumps.fee_owner;
    let seeds: &[&[u8]] = &[FEES_SEED, &[bump]];

    let before = held(&ctx.accounts.fee_account)?;
    let fee_owner = ctx.accounts.fee_owner.to_account_info();
    let into = ctx.accounts.fee_account.to_account_info();
    let quote_mint = ctx.accounts.quote_mint.to_account_info();
    let quote_program = ctx.accounts.quote_program.to_account_info();
    let unused = ctx.accounts.platform_quote.to_account_info();
    venue::claim_quote_fees(
        ctx.remaining_accounts,
        &venue::ClaimInto {
            position: r.position,
            fee_owner: &fee_owner,
            fee_owner_seeds: seeds,
            into: &into,
            quote_mint: &quote_mint,
            quote_program: &quote_program,
            unused_token_a: &unused,
        },
    )?;
    // What this claim brought in, and nothing else the account holds.
    let amount = held(&into)?.checked_sub(before).ok_or(SplitterError::Overflow)?;
    require!(amount > 0, SplitterError::NothingToRelease);
    // Split by what the pool charges now, not by what it charged at launch: Meteora's operator can
    // change a pool's fee (venue::current_fee). The pool is the one Meteora's claim just took the
    // fees out of -- the position's -- and is checked to be once more here.
    let pool = &ctx.remaining_accounts[1];
    let (position_pool, _) = crate::read_position(&ctx.remaining_accounts[2].try_borrow_data()?).ok_or(SplitterError::NotThisLaunch)?;
    require_keys_eq!(position_pool, pool.key(), SplitterError::NotThisLaunch);
    let fee = venue::current_fee(pool)?;
    let to_platform = platform_share_at(amount, fee.fee_numerator, fee.lp_share_bps);
    // The remainder, not a second division: the two always sum to what arrived, and the rounding
    // crumb is the creator's.
    let to_creator = amount - to_platform;
    let decimals = ctx.accounts.quote_mint.decimals;
    // The creator's share in SOL where the claim asks for it and the wallet can take it; else in
    // the quote asset, as always. The same amount either way.
    let extra = &ctx.remaining_accounts[venue::CLAIM_ACCOUNTS..];
    let creator_paid = match sol_payout(&ctx.accounts, extra, to_creator)? {
        Some(p) => {
            pay_creator_in_sol(&ctx.accounts, &p, seeds, to_creator)?;
            emit!(CreatorPaidInSol { record: r.key(), creator: r.creator, lamports: to_creator });
            0
        }
        None => to_creator,
    };
    if creator_paid > 0 {
        creator_token_account(&ctx.accounts)?;
        require!(creator_spends_asset(&ctx.accounts, extra), SplitterError::PayeeCannotSpendAsset);
    }
    let creator_quote = ctx.accounts.creator_quote.to_account_info();
    let platform_quote = ctx.accounts.platform_quote.to_account_info();
    for (to, value) in [(&creator_quote, creator_paid), (&platform_quote, to_platform)] {
        if value == 0 {
            continue;
        }
        transfer_checked(
            CpiContext::new_with_signer(
                quote_program.clone(),
                TransferChecked {
                    from: into.clone(),
                    mint: quote_mint.clone(),
                    to: (*to).clone(),
                    authority: fee_owner.clone(),
                },
                &[seeds],
            ),
            value,
            decimals,
        )?;
    }
    emit!(FeesClaimed {
        record: r.key(),
        quote_mint: r.quote_mint,
        amount,
        to_creator,
        to_platform,
        fee_numerator: fee.fee_numerator,
        lp_share_bps: fee.lp_share_bps,
    });
    Ok(())
}

// ------------------------------------------------------------- native SOL fees (factory v2)

/// The temporary wrapped-SOL account `claim_fees_native` claims into and unwraps:
/// `PDA(["unwrap", record])`. It exists only inside that instruction.
pub const UNWRAP_SEED: &[u8] = b"unwrap";

/// The incinerator: a payee who chose to burn their fees. The runtime burns what it holds, and
/// exempts it from the rent check, so any share may be paid to it.
pub const INCINERATOR: Pubkey = anchor_lang::solana_program::incinerator::ID;

#[derive(Accounts)]
pub struct ClaimFeesNative<'info> {
    /// Anyone. Fronts the temporary account's rent and passes each share on, in this instruction:
    /// it ends exactly where it began.
    #[account(mut)]
    pub payer: Signer<'info>,
    /// Writable: it keeps the payee's share while the payee cannot yet hold it (the pending ledger).
    #[account(mut, seeds = [SPLITTER_SEED, record.position_nft_mint.as_ref()], bump = record.bump)]
    pub record: Box<Account<'info, LaunchRecord>>,
    /// CHECK: the program's fee owner, which holds the position, signs the claim and owns the
    /// temporary account.
    #[account(seeds = [FEES_SEED], bump)]
    pub fee_owner: UncheckedAccount<'info>,
    /// CHECK: the program's one wrapped-SOL account (`claim_fees`'s), handed to Meteora as the
    /// launched token's side of the claim, which it never writes (fees are taken in the quote only).
    /// Made by the first claim of either kind when missing, at the claimer's cost, once for all.
    #[account(mut, seeds = [FEES_SEED, anchor_spl::token::spl_token::native_mint::ID.as_ref()], bump)]
    pub fee_account: UncheckedAccount<'info>,
    /// CHECK: the temporary wrapped-SOL account, at its address: made, claimed into and closed here.
    #[account(mut, seeds = [UNWRAP_SEED, record.key().as_ref()], bump)]
    pub unwrap: UncheckedAccount<'info>,
    /// CHECK: wrapped SOL's mint, which the record must be paired against.
    #[account(address = anchor_spl::token::spl_token::native_mint::ID @ SplitterError::NotNativeQuote)]
    pub quote_mint: UncheckedAccount<'info>,
    /// CHECK: the payee: the record's `creator`, any address (the incinerator included). SENT
    /// WRITABLE, but not `mut` to Anchor, on purpose (Solana audit round 2, B L-2): a payee the
    /// runtime will not let a transaction write -- a sysvar, a program -- arrives read-only however
    /// it is sent, and must not fail the platform's share with it. Its share then waits in the
    /// pending ledger (`can_hold`) for the admin to move the stream (`admin_set_payee`). A plain
    /// wallet (system-owned, no data, on the curve, or the incinerator) sent read-only is refused
    /// (`payee_writable_or_reserved`, round 8): an account list built from the IDL, which marks it
    /// read-only, must set it writable.
    #[account(address = record.creator @ SplitterError::NotThisLaunch)]
    pub payee: UncheckedAccount<'info>,
    /// CHECK: the program-wide platform record, which may not exist yet; read by `platform_of`.
    #[account(seeds = [PLATFORM_SEED], bump)]
    pub platform_config: UncheckedAccount<'info>,
    /// CHECK: the platform's own address, as `platform_of` names it.
    #[account(mut)]
    pub platform: UncheckedAccount<'info>,
    pub token_program: Program<'info, anchor_spl::token::Token>,
    pub system_program: Program<'info, System>,
    // Then the venue's accounts for the claim, in `venue::CLAIM_ACCOUNTS` order. Then, when the
    // payee is a tokenomics account, its wrapped-SOL vault, writable (`tokenomics_vault`; required
    // when the account is bound to this launch).
}

/// Paid natively: the same split as `FeesClaimed`, in lamports straight to the two wallets.
#[event]
pub struct FeesClaimedNative {
    pub record: Pubkey,
    pub amount: u64,
    pub to_creator: u64,
    pub to_platform: u64,
    /// What reached the payee: this claim's share and everything that was pending for it.
    pub paid_to_payee: u64,
    /// What the record keeps for the payee after this claim.
    pub pending: u64,
    pub fee_numerator: u64,
    pub lp_share_bps: u16,
}

/// The programs whose accounts can never be a payee: the token programs (mints, token accounts),
/// Meteora (pools, positions), the OFT program and LayerZero's endpoint (stores, LayerZero
/// accounts). Lamports on one are that program's to move, and none of them moves a payee's.
/// `can_hold` and `launch_v2::payee_owner_allowed` refuse the same list (audit round 6, I).
pub fn owner_refused(owner: &Pubkey) -> bool {
    [anchor_spl::token::ID, crate::TOKEN_2022_ID, crate::CP_AMM_ID, crate::OFT_PROGRAM_ID, crate::LZ_ENDPOINT_ID].contains(owner)
}

/// Whether `to` can be paid `lamports`: it is writable in this transaction, no program's code, not
/// this program's own account nor one of the programs `owner_refused` lists, and is not left below
/// its rent-exempt minimum (the incinerator, which the runtime exempts, always is not).
///
/// Not this program's (Solana audit round 2, A L-1): an account it owns -- a fee payment, which
/// `withdraw_fee` sweeps to the admin, the price signer, a listing, a record -- is spent only by
/// what this program does with it, never by a payee. A share for one waits in the pending ledger,
/// for the admin to move the stream (`admin_set_payee`).
fn can_hold(to: &AccountInfo, lamports: u64) -> Result<bool> {
    if !to.is_writable || to.executable || *to.owner == crate::ID || owner_refused(to.owner) {
        return Ok(false);
    }
    if *to.key == INCINERATOR {
        return Ok(true);
    }
    let after = to.lamports().saturating_add(lamports);
    Ok(Rent::get()?.is_exempt(after, to.data_len()))
}

/// The wrapped-SOL vault a native claim pays `payee` into, when `payee` is a tokenomics account
/// bound to the launch at `record`: its associated wrapped-SOL account, where `claim_fees` would
/// credit it (`tokenomics::InitTokenomics::vault_wsol`), given after the venue's accounts. None for
/// any other payee: an unbound tokenomics account is owed (its share joins the pending ledger, as
/// for any payee this program owns).
///
/// A BOUND one's vault must be given, writable (factory v2 audit round 8, L): left out or sent
/// read-only, the payee's share would wait in the ledger at the cranker's choice. The vault is made
/// with the account (`init_tokenomics`) and never closed, so a claim can always give it.
fn tokenomics_vault<'a, 'info>(payee: &AccountInfo<'info>, record: &Pubkey, given: Option<&'a AccountInfo<'info>>) -> Result<Option<&'a AccountInfo<'info>>> {
    if *payee.owner != crate::ID {
        return Ok(None);
    }
    let bound = {
        let data = payee.try_borrow_data()?;
        match crate::Tokenomics::try_deserialize(&mut &data[..]) {
            Ok(t) => t.bound && t.record == *record,
            // A v2 account (`tokenomics_v2`): the same vault, made at its bind.
            Err(_) => crate::TokenomicsV2::try_deserialize(&mut &data[..]).is_ok_and(|t| t.bound && t.record == *record),
        }
    };
    if !bound {
        return Ok(None);
    }
    let vault = given.ok_or(SplitterError::TokenomicsVaultNotGiven)?;
    let expected = anchor_spl::associated_token::get_associated_token_address(payee.key, &spl_token::native_mint::ID);
    let ok = vault.is_writable
        && *vault.key == expected
        && *vault.owner == spl_token::ID
        && crate::read_token_account_view(&vault.try_borrow_data()?).is_some_and(|v| v.mint == spl_token::native_mint::ID && v.owner == *payee.key);
    require!(ok, SplitterError::TokenomicsVaultNotGiven);
    Ok(Some(vault))
}

/// Whether a native claim may leave `payee` owed rather than paid because it arrived read-only: only
/// when it is not a wallet `can_hold` would pay -- a program, a sysvar, a data account, an address
/// off the curve (the incinerator aside, which is paid) -- since the runtime never lets a
/// transaction write a reserved key or a program, however it is sent. A plain wallet sent read-only
/// is refused (factory v2 audit round 8, L): otherwise a cranker defers its share at will. The rule
/// is `tokenomics::writable_or_reserved`'s, with the incinerator counted as payable.
fn payee_writable_or_reserved(payee: &AccountInfo) -> bool {
    let payable = *payee.owner == System::id() && payee.data_is_empty() && !payee.executable && (*payee.key == INCINERATOR || on_curve(payee.key));
    payee.is_writable || !payable
}

/// `claim_fees`, paid in native SOL, for a v2 launch paired against wrapped SOL: one launch's
/// quote fees claimed into a temporary wrapped-SOL account, split by the same `platform_share`,
/// the account closed to the cranker, and each share sent on from the cranker to its wallet. The
/// same amounts as `claim_fees` would pay in wrapped SOL; the cranker nets nothing.
pub fn claim_fees_native_handler<'info>(ctx: Context<'_, '_, 'info, 'info, ClaimFeesNative<'info>>) -> Result<()> {
    let a = &ctx.accounts;
    require_keys_eq!(a.record.quote_mint, anchor_spl::token::spl_token::native_mint::ID, SplitterError::NotNativeQuote);
    let pending = {
        let info = a.record.to_account_info();
        let data = info.try_borrow_data()?;
        crate::read_v2_tail(&data).ok_or(SplitterError::NotV2Record)?.pending_native
    };
    let platform = platform_of(&a.platform_config)?;
    require_keys_eq!(a.platform.key(), platform, SplitterError::NotThePlatform);

    // The temporary account, owned by the fee owner, rent fronted by the cranker. Its address is
    // public, so it may hold lamports somebody sent: they go toward the rent, and to the cranker.
    let record_key = a.record.key();
    let unwrap_seeds: &[&[u8]] = &[UNWRAP_SEED, record_key.as_ref(), &[ctx.bumps.unwrap]];
    let unwrap = a.unwrap.to_account_info();
    let system = a.system_program.to_account_info();
    let payer = a.payer.to_account_info();
    let token_program = a.token_program.to_account_info();
    let space = crate::TOKEN_ACCOUNT_LEN;
    let rent = Rent::get()?.minimum_balance(space);
    let held_before = unwrap.lamports();
    require!(unwrap.data_is_empty(), SplitterError::NotThisLaunch);
    if held_before == 0 {
        create_account(
            CpiContext::new_with_signer(system.clone(), CreateAccount { from: payer.clone(), to: unwrap.clone() }, &[unwrap_seeds]),
            rent,
            space as u64,
            &token_program.key(),
        )?;
    } else {
        if held_before < rent {
            transfer(CpiContext::new(system.clone(), Transfer { from: payer.clone(), to: unwrap.clone() }), rent - held_before)?;
        }
        allocate(CpiContext::new_with_signer(system.clone(), Allocate { account_to_allocate: unwrap.clone() }, &[unwrap_seeds]), space as u64)?;
        assign(CpiContext::new_with_signer(system.clone(), Assign { account_to_assign: unwrap.clone() }, &[unwrap_seeds]), &token_program.key())?;
    }
    let fee_owner = a.fee_owner.to_account_info();
    let quote_mint = a.quote_mint.to_account_info();
    anchor_spl::token::initialize_account3(CpiContext::new(
        token_program.clone(),
        anchor_spl::token::InitializeAccount3 { account: unwrap.clone(), mint: quote_mint.clone(), authority: fee_owner.clone() },
    ))?;
    // The shared account Meteora is handed for the side it never pays: made once, if missing.
    let shared = a.fee_account.to_account_info();
    if shared.data_is_empty() {
        let mint_key = quote_mint.key();
        let shared_seeds: &[&[u8]] = &[FEES_SEED, mint_key.as_ref(), &[ctx.bumps.fee_account]];
        let held = shared.lamports();
        if held == 0 {
            create_account(
                CpiContext::new_with_signer(system.clone(), CreateAccount { from: payer.clone(), to: shared.clone() }, &[shared_seeds]),
                rent,
                space as u64,
                &token_program.key(),
            )?;
        } else {
            if held < rent {
                transfer(CpiContext::new(system.clone(), Transfer { from: payer.clone(), to: shared.clone() }), rent - held)?;
            }
            allocate(CpiContext::new_with_signer(system.clone(), Allocate { account_to_allocate: shared.clone() }, &[shared_seeds]), space as u64)?;
            assign(CpiContext::new_with_signer(system.clone(), Assign { account_to_assign: shared.clone() }, &[shared_seeds]), &token_program.key())?;
        }
        anchor_spl::token::initialize_account3(CpiContext::new(
            token_program.clone(),
            anchor_spl::token::InitializeAccount3 { account: shared.clone(), mint: quote_mint.clone(), authority: fee_owner.clone() },
        ))?;
    } else {
        require_keys_eq!(*shared.owner, token_program.key(), SplitterError::NotThisLaunch);
    }

    // The claim, into it: what it brought in is what the account holds after less what it held
    // before -- a wrapped-SOL account made at an address somebody had sent lamports to counts them
    // as its balance, and they are not fees (they go to the cranker with the rent).
    let before = held(&unwrap)?;
    let seeds: &[&[u8]] = &[FEES_SEED, &[ctx.bumps.fee_owner]];
    venue::claim_quote_fees(
        ctx.remaining_accounts,
        &venue::ClaimInto {
            position: a.record.position,
            fee_owner: &fee_owner,
            fee_owner_seeds: seeds,
            into: &unwrap,
            quote_mint: &quote_mint,
            quote_program: &token_program,
            unused_token_a: &shared,
        },
    )?;
    let amount = held(&unwrap)?.checked_sub(before).ok_or(SplitterError::Overflow)?;
    require!(amount > 0 || pending > 0, SplitterError::NothingToRelease);
    let pool = &ctx.remaining_accounts[1];
    let (position_pool, _) = crate::read_position(&ctx.remaining_accounts[2].try_borrow_data()?).ok_or(SplitterError::NotThisLaunch)?;
    require_keys_eq!(position_pool, pool.key(), SplitterError::NotThisLaunch);
    let fee = venue::current_fee(pool)?;
    let to_platform = platform_share_at(amount, fee.fee_numerator, fee.lp_share_bps);
    let to_creator = amount - to_platform;

    // Unwrapped: every lamport of it -- the rent and the claim, and anything a stranger sent the
    // address -- to the cranker, which passes the two shares on.
    anchor_spl::token::close_account(CpiContext::new_with_signer(
        token_program,
        anchor_spl::token::CloseAccount { account: unwrap, destination: payer.clone(), authority: fee_owner },
        &[seeds],
    ))?;
    // The platform's share, always (Solana audit B1 L-2).
    if to_platform > 0 {
        let to = a.platform.to_account_info();
        require!(can_hold(&to, to_platform)?, SplitterError::RecipientCannotHold);
        transfer(CpiContext::new(system.clone(), Transfer { from: payer.clone(), to }), to_platform)?;
    }
    // The payee's, with what is pending for it, when it can hold all of that; otherwise its share
    // joins the pending ledger, kept in the record's own balance, and waits for a later claim.
    let payee = a.payee.to_account_info();
    let record_info = a.record.to_account_info();
    let owed = pending.checked_add(to_creator).ok_or(SplitterError::Overflow)?;
    // A tokenomics account bound to this launch is paid where `claim_fees` pays it in v1: wrapped
    // SOL in its vault, which its buckets spend (Solana audit, factory v2 round 3, M-1). Never as
    // lamports, which `can_hold` refuses an account of this program's anyway -- they would reach
    // its owner past the buckets (`forward_tokenomics_refund`).
    require!(payee_writable_or_reserved(&payee), SplitterError::PayeeNotWritable);
    if let Some(vault) = tokenomics_vault(&payee, &record_key, ctx.remaining_accounts.get(venue::CLAIM_ACCOUNTS))? {
        if owed > 0 {
            // The ledger's lamports, the record's own, moved directly; then the claim's share from
            // the cranker -- a call that carries the record too, so that the runtime sees both sides
            // of the move -- and the vault counts them as its balance.
            **record_info.try_borrow_mut_lamports()? -= pending;
            **vault.try_borrow_mut_lamports()? += pending;
            let mut share = anchor_lang::solana_program::system_instruction::transfer(&payer.key(), vault.key, to_creator);
            share.accounts.push(AccountMeta::new(record_key, false));
            anchor_lang::solana_program::program::invoke(&share, &[payer.clone(), vault.clone(), record_info.clone(), system.clone()])?;
            anchor_lang::solana_program::program::invoke(&spl_token::instruction::sync_native(&spl_token::ID, vault.key)?, &[vault.clone(), a.token_program.to_account_info()])?;
            if pending > 0 {
                let mut data = record_info.try_borrow_mut_data()?;
                crate::write_pending_native(&mut data, 0).ok_or(SplitterError::NotV2Record)?;
            }
        }
        emit!(FeesClaimedNative {
            record: record_key,
            amount,
            to_creator,
            to_platform,
            paid_to_payee: owed,
            pending: 0,
            fee_numerator: fee.fee_numerator,
            lp_share_bps: fee.lp_share_bps,
        });
        return Ok(());
    }
    let pays = owed > 0 && can_hold(&payee, owed)?;
    if to_creator > 0 {
        let into = if pays { payee.clone() } else { record_info.clone() };
        transfer(CpiContext::new(system.clone(), Transfer { from: payer.clone(), to: into }), to_creator)?;
    }
    let now_pending = if pays { 0 } else { owed };
    if pays && pending > 0 {
        // The ledger's lamports are the record's own: moved directly, after the last call.
        **record_info.try_borrow_mut_lamports()? -= pending;
        **payee.try_borrow_mut_lamports()? += pending;
    }
    if now_pending != pending {
        let mut data = record_info.try_borrow_mut_data()?;
        crate::write_pending_native(&mut data, now_pending).ok_or(SplitterError::NotV2Record)?;
    }
    emit!(FeesClaimedNative {
        record: record_key,
        amount,
        to_creator,
        to_platform,
        paid_to_payee: if pays { owed } else { 0 },
        pending: now_pending,
        fee_numerator: fee.fee_numerator,
        lp_share_bps: fee.lp_share_bps,
    });
    Ok(())
}

// ------------------------------------------------------------------- the creator's stream

#[derive(Accounts)]
pub struct ProposeCreator<'info> {
    #[account(mut, has_one = creator)]
    pub record: Account<'info, LaunchRecord>,
    pub creator: Signer<'info>,
}

#[derive(Accounts)]
pub struct AdminProposeCreator<'info> {
    #[account(mut)]
    pub record: Account<'info, LaunchRecord>,
    #[account(address = ADMIN @ SplitterError::NotAdmin)]
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
pub struct AcceptCreator<'info> {
    #[account(mut, has_one = pending_creator)]
    pub record: Account<'info, LaunchRecord>,
    pub pending_creator: Signer<'info>,
}

pub fn propose_creator_handler(record: &mut Account<LaunchRecord>, to: Pubkey, admin: Option<Pubkey>) -> Result<()> {
    require!(to != Pubkey::default(), SplitterError::ZeroAddress);
    record.pending_creator = to;
    match admin {
        None => emit!(crate::CreatorProposed { record: record.key(), from: record.creator, to }),
        Some(admin) => emit!(crate::AdminProposedCreator { record: record.key(), admin, from: record.creator, to }),
    }
    Ok(())
}

pub fn accept_creator_handler(record: &mut Account<LaunchRecord>) -> Result<()> {
    let from = record.creator;
    record.creator = record.pending_creator;
    record.pending_creator = Pubkey::default();
    emit!(crate::CreatorChanged { record: record.key(), from, to: record.creator });
    Ok(())
}

// ------------------------------------------------------------------ the platform's stream

#[derive(Accounts)]
pub struct ProposePlatform<'info> {
    /// The platform, or the admin. Pays for the record the first time.
    #[account(mut)]
    pub proposer: Signer<'info>,
    #[account(init_if_needed, payer = proposer, space = 8 + Platform::INIT_SPACE, seeds = [PLATFORM_SEED], bump)]
    pub platform_config: Account<'info, Platform>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AcceptPlatform<'info> {
    #[account(mut, seeds = [PLATFORM_SEED], bump = platform_config.bump, has_one = pending_platform)]
    pub platform_config: Account<'info, Platform>,
    pub pending_platform: Signer<'info>,
}

pub fn propose_platform_handler(ctx: Context<ProposePlatform>, to: Pubkey) -> Result<()> {
    require!(to != Pubkey::default(), SplitterError::ZeroAddress);
    let c = &mut ctx.accounts.platform_config;
    let current = if c.platform == Pubkey::default() { ADMIN } else { c.platform };
    let who = ctx.accounts.proposer.key();
    require!(who == current || who == ADMIN, SplitterError::NotThePlatform);
    c.bump = ctx.bumps.platform_config;
    c.pending_platform = to;
    if who == current {
        emit!(crate::PlatformProposed { from: current, to });
    } else {
        emit!(crate::AdminProposedPlatform { admin: who, from: current, to });
    }
    Ok(())
}

pub fn accept_platform_handler(ctx: Context<AcceptPlatform>) -> Result<()> {
    let c = &mut ctx.accounts.platform_config;
    let from = if c.platform == Pubkey::default() { ADMIN } else { c.platform };
    c.platform = c.pending_platform;
    c.pending_platform = Pubkey::default();
    emit!(crate::PlatformChanged { from, to: c.platform });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_keypairs_address_is_on_the_curve_and_a_derived_one_is_not() {
        assert!(on_curve(&pubkey!("7rYog4JusTy4CpwvFGPrRvWtcDrWatnA3SN3DRPuf6kM")), "ADMIN, a wallet");
        assert!(!on_curve(&native_transit()));
        assert!(!on_curve(&incinerator::ID), "the incinerator is off the curve: it is let through by name");
    }

    #[test]
    fn the_native_transit_bump_is_the_canonical_one() {
        assert_eq!(Pubkey::find_program_address(&[NATIVE_SEED], &crate::ID), (native_transit(), NATIVE_BUMP));
    }

    /// A tokenomics account's bytes, v1 or v2: its discriminator, zeros, `bound` (byte 10) and
    /// `record` where each layout keeps it -- the offsets solana/client/claim-fees-native.mjs
    /// TOKENOMICS_LAYOUTS reads (v1 380, v2 1514), held to the program's own decoding here.
    fn tokenomics_bytes(v2: bool, bound: bool, record: &Pubkey) -> Vec<u8> {
        use anchor_lang::Discriminator;
        let (disc, len, record_at): (&[u8], usize, usize) = if v2 {
            (&crate::TokenomicsV2::DISCRIMINATOR[..], 8 + crate::TokenomicsV2::INIT_SPACE, 1514)
        } else {
            (&crate::Tokenomics::DISCRIMINATOR[..], 8 + crate::Tokenomics::INIT_SPACE, 380)
        };
        let mut d = vec![0u8; len];
        d[..8].copy_from_slice(disc);
        d[10] = bound as u8;
        d[record_at..record_at + 32].copy_from_slice(record.as_ref());
        d
    }

    /// The rule the sweep leans on when it passes a vault for any payee of the program that has one
    /// (claim-fees-native.mjs namesVault): `tokenomics_vault` reads a given vault ONLY for an account
    /// it takes as bound to this record, and ignores it -- whatever it is -- otherwise. A bound one
    /// with no vault is refused (6081, live 2026-10-27, XANGEA, a v2 payee the sweep did not know).
    #[test]
    fn tokenomics_vault_ignores_a_vault_given_for_an_unbound_payee_and_needs_it_for_a_bound_one() {
        let record = Pubkey::new_unique();
        let payee_key = Pubkey::new_unique();
        let owner = crate::ID;
        // Not a vault at all: a system account, read-only. Taken for an unbound payee, it is never read.
        let junk_key = Pubkey::new_unique();
        let sys = anchor_lang::system_program::ID;
        for v2 in [false, true] {
            for (bound, rec, given, want) in [
                (false, record, true, "none"),
                (true, Pubkey::new_unique(), true, "none"), // bound to another launch
                (false, record, false, "none"),
                (true, record, false, "refused"),
                (true, record, true, "refused"), // the junk is not its vault
            ] {
                let mut data = tokenomics_bytes(v2, bound, &rec);
                let mut lamports = 1_000_000u64;
                let (mut junk_lamports, mut junk_data) = (1u64, vec![]);
                let payee = AccountInfo::new(&payee_key, false, true, &mut lamports, &mut data, &owner, false, 0);
                let junk = AccountInfo::new(&junk_key, false, false, &mut junk_lamports, &mut junk_data, &sys, false, 0);
                let got = tokenomics_vault(&payee, &record, if given { Some(&junk) } else { None });
                match want {
                    "none" => assert!(matches!(got, Ok(None)), "v2 {v2} bound {bound} given {given}: ignored"),
                    _ => assert_eq!(got.err(), Some(SplitterError::TokenomicsVaultNotGiven.into()), "v2 {v2} bound {bound} given {given}: refused"),
                }
            }
        }
    }
}
