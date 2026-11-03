//! # What a launch pairs against
//!
//! Every launch pairs its token with one quote asset: wrapped SOL, which is always allowed, or an
//! asset the admin has allowlisted for that purpose (`QuoteAsset`, at `["pair", mint]`). The
//! allowlist starts empty. A launch against anything else is refused (`QuoteAssetNotAllowed`).
//!
//! An allowlisted asset may be a Token-2022 mint -- the tokenized stocks on Solana are: xStocks
//! carry a permanent delegate, a freeze authority, a pause switch, a default account state, a
//! scaled UI amount, confidential transfers, and a transfer hook whose program is unset. None of
//! that is something this program designs around. The issuer of such an asset can move, burn or
//! freeze any account holding it, pause every transfer of it, or attach a hook to it, at any time,
//! and every pool, fee account and dev buy in that asset is subject to it. That is the user's
//! accepted risk, and it is stated here so that nobody reads these launches as more than that.
//!
//! What IS checked is what would make a launch fail or a dev buy misbehave:
//!
//!   * when an asset is allowlisted (`set_quote_asset`): that it is a mint of the classic or the
//!     Token-2022 program; that it has no transfer fee (the dev buy's arithmetic would be off by
//!     it, and the swap's minimum would refuse the launch), is not non-transferable, has no
//!     transfer-hook PROGRAM (a hook's accounts are not something a launch can name), and carries
//!     no extension this program does not know; and that Meteora's token badge for it exists when
//!     Meteora requires one (any Token-2022 extension beyond metadata and a transfer fee, or a
//!     transfer-hook authority) -- `QuoteAssetUnsupported`;
//!   * at every launch: that it is still allowlisted and enabled, and is not paused, not set to
//!     create its accounts frozen, and has not acquired a hook program since
//!     (`QuoteAssetUnavailable`). These refuse the launch by name, before anything is created;
//!     the launcher checks the same before it sends, so that one never lands.

use anchor_lang::prelude::*;

use crate::{SplitterError, CP_AMM_ID};

/// seeds: ["pair", mint]. One per allowlisted quote asset.
pub const PAIR_SEED: &[u8] = b"pair";

/// Meteora's seed for a mint's token badge, under the cp-amm program.
pub const TOKEN_BADGE_SEED: &[u8] = b"token_badge";

/// The Token-2022 program.
pub const TOKEN_2022_ID: Pubkey = anchor_spl::token_2022::ID;

/// An asset a launch may pair against, besides wrapped SOL. Written by the admin only
/// (`set_quote_asset`), read by `launch`.
#[account]
#[derive(InitSpace)]
pub struct QuoteAsset {
    pub mint: Pubkey,
    /// The mint's program: the classic token program or Token-2022.
    pub token_program: Pubkey,
    /// Meteora's token badge for the mint, which cp-amm requires to open a pool against a
    /// Token-2022 mint with extensions it does not accept on its own; the default address when
    /// none is needed.
    pub badge: Pubkey,
    pub decimals: u8,
    /// Whether launches may pair against it. Turning it off stops new launches and changes
    /// nothing about launches made.
    pub enabled: bool,
    pub bump: u8,
    /// The band the signed price of this asset must be inside for a launch to pair with it: USD
    /// per 10^decimals base units, 1e18-scaled -- the unit of the snapshot's `usdPerQuote`. See
    /// `price`.
    pub min_usd_per_quote: u128,
    pub max_usd_per_quote: u128,
}

// Token-2022's extension types, by number, as its program numbers them.
const TRANSFER_FEE_CONFIG: u16 = 1;
const MINT_CLOSE_AUTHORITY: u16 = 3;
const CONFIDENTIAL_TRANSFER_MINT: u16 = 4;
const DEFAULT_ACCOUNT_STATE: u16 = 6;
const NON_TRANSFERABLE: u16 = 9;
const INTEREST_BEARING_CONFIG: u16 = 10;
const PERMANENT_DELEGATE: u16 = 12;
const TRANSFER_HOOK: u16 = 14;
const CONFIDENTIAL_TRANSFER_FEE_CONFIG: u16 = 16;
const METADATA_POINTER: u16 = 18;
const TOKEN_METADATA: u16 = 19;
const GROUP_POINTER: u16 = 20;
const TOKEN_GROUP: u16 = 21;
const GROUP_MEMBER_POINTER: u16 = 22;
const TOKEN_GROUP_MEMBER: u16 = 23;
const SCALED_UI_AMOUNT: u16 = 25;
const PAUSABLE: u16 = 26;

/// A token account's size with no extensions: the classic program's, and Token-2022's base.
pub const TOKEN_ACCOUNT_LEN: usize = 165;
/// Where Token-2022 writes the account type byte, and after it the extensions, in a mint or an
/// account that has any.
const ACCOUNT_TYPE_AT: usize = 165;
const MINT_ACCOUNT_TYPE: u8 = 1;

/// What a launch needs to know about its quote mint, read from the mint account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuoteMint {
    pub token_program: Pubkey,
    pub decimals: u8,
    /// The size a token account for this mint must be allocated at: the base, and the account
    /// extensions Token-2022 requires for this mint's extensions (a transfer-hook account, a
    /// pausable account), which `initialize_account3` refuses an account too small to hold.
    pub account_len: usize,
    /// Whether Meteora requires a token badge to open a pool against it.
    pub needs_badge: bool,
    /// An extension a launch cannot live with: a transfer fee, non-transferable, a confidential
    /// transfer fee, or one this program does not know.
    pub unsupported: bool,
    pub paused: bool,
    pub default_frozen: bool,
    /// A transfer-hook PROGRAM is set: every transfer would need the hook's accounts.
    pub hook_program: bool,
}

/// Read a quote mint. None if it is not an initialised mint of either token program.
pub fn inspect_mint(owner: &Pubkey, data: &[u8]) -> Option<QuoteMint> {
    if data.len() < 82 || data[45] != 1 {
        return None;
    }
    let decimals = data[44];
    if *owner == anchor_spl::token::ID {
        return Some(QuoteMint {
            token_program: *owner,
            decimals,
            account_len: TOKEN_ACCOUNT_LEN,
            needs_badge: false,
            unsupported: false,
            paused: false,
            default_frozen: false,
            hook_program: false,
        });
    }
    if *owner != TOKEN_2022_ID {
        return None;
    }
    let mut q = QuoteMint {
        token_program: *owner,
        decimals,
        account_len: TOKEN_ACCOUNT_LEN,
        needs_badge: false,
        unsupported: false,
        paused: false,
        default_frozen: false,
        hook_program: false,
    };
    if data.len() <= ACCOUNT_TYPE_AT {
        return Some(q);
    }
    if data[ACCOUNT_TYPE_AT] != MINT_ACCOUNT_TYPE {
        return None;
    }
    // The account extensions an account for this mint must be created with, in bytes: two of
    // type, two of length, and the data.
    let mut account_extensions = 0usize;
    let mut at = ACCOUNT_TYPE_AT + 1;
    while at + 4 <= data.len() {
        let kind = u16::from_le_bytes([data[at], data[at + 1]]);
        let len = u16::from_le_bytes([data[at + 2], data[at + 3]]) as usize;
        if kind == 0 {
            break;
        }
        let value = data.get(at + 4..at + 4 + len)?;
        match kind {
            // What Meteora takes from anyone: metadata, its pointer.
            METADATA_POINTER | TOKEN_METADATA => {}
            DEFAULT_ACCOUNT_STATE => {
                q.needs_badge = true;
                q.default_frozen = value.first() == Some(&2);
            }
            PAUSABLE => {
                q.needs_badge = true;
                q.paused = value.get(32).is_some_and(|p| *p != 0);
                account_extensions += 4; // a pausable account: no data
            }
            TRANSFER_HOOK => {
                q.needs_badge = true;
                // authority (32), then the program (32): set means every transfer calls it.
                q.hook_program = value.get(32..64).is_none_or(|p| p.iter().any(|b| *b != 0));
                account_extensions += 4 + 1; // a transfer-hook account: one flag
            }
            MINT_CLOSE_AUTHORITY | CONFIDENTIAL_TRANSFER_MINT | INTEREST_BEARING_CONFIG | PERMANENT_DELEGATE
            | GROUP_POINTER | TOKEN_GROUP | GROUP_MEMBER_POINTER | TOKEN_GROUP_MEMBER | SCALED_UI_AMOUNT => {
                q.needs_badge = true;
            }
            TRANSFER_FEE_CONFIG | NON_TRANSFERABLE | CONFIDENTIAL_TRANSFER_FEE_CONFIG => q.unsupported = true,
            _ => q.unsupported = true,
        }
        at += 4 + len;
    }
    if account_extensions > 0 {
        // The account type byte, then the extensions.
        q.account_len = TOKEN_ACCOUNT_LEN + 1 + account_extensions;
    }
    Some(q)
}

/// Meteora's token badge for `mint`.
pub fn token_badge_address(mint: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[TOKEN_BADGE_SEED, mint.as_ref()], &CP_AMM_ID).0
}

/// Whether `badge` is Meteora's badge for `mint`, and exists.
pub fn is_token_badge(badge: &AccountInfo, mint: &Pubkey) -> bool {
    *badge.owner == CP_AMM_ID
        && badge.key() == token_badge_address(mint)
        && badge.try_borrow_data().is_ok_and(|d| d.get(8..40) == Some(mint.as_ref()))
}

/// The fields of a token account a delegated dev buy reads (the same in both programs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenAccountView {
    pub mint: Pubkey,
    pub owner: Pubkey,
    pub amount: u64,
    pub delegate: Option<Pubkey>,
    /// 1 initialised, 2 frozen.
    pub state: u8,
    pub delegated_amount: u64,
}

pub fn read_token_account_view(data: &[u8]) -> Option<TokenAccountView> {
    if data.len() < TOKEN_ACCOUNT_LEN {
        return None;
    }
    let key = |at: usize| Pubkey::new_from_array(data[at..at + 32].try_into().unwrap());
    let u64_at = |at: usize| u64::from_le_bytes(data[at..at + 8].try_into().unwrap());
    let delegate = match u32::from_le_bytes(data[72..76].try_into().unwrap()) {
        1 => Some(key(76)),
        _ => None,
    };
    Some(TokenAccountView {
        mint: key(0),
        owner: key(32),
        amount: u64_at(64),
        delegate,
        state: data[108],
        delegated_amount: u64_at(121),
    })
}

// ------------------------------------------------------------------------- set_quote_asset

#[derive(Accounts)]
pub struct SetQuoteAsset<'info> {
    #[account(
        init_if_needed,
        payer = admin,
        space = 8 + QuoteAsset::INIT_SPACE,
        seeds = [PAIR_SEED, mint.key().as_ref()],
        bump
    )]
    pub pair: Account<'info, QuoteAsset>,
    /// CHECK: the asset's mint, read and checked by the handler.
    pub mint: UncheckedAccount<'info>,
    /// CHECK: Meteora's token badge for the mint when it needs one (checked); any account
    /// otherwise -- the program's own id, by convention.
    pub badge: UncheckedAccount<'info>,
    #[account(mut, address = crate::ADMIN @ SplitterError::NotAdmin)]
    pub admin: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[event]
pub struct QuoteAssetSet {
    pub mint: Pubkey,
    pub token_program: Pubkey,
    pub badge: Pubkey,
    pub enabled: bool,
    pub min_usd_per_quote: u128,
    pub max_usd_per_quote: u128,
}

/// Allowlist an asset to pair launches against -- with the band its signed price must be inside
/// (USD per 10^decimals base units, 1e18-scaled; `price`) -- or turn it off. Admin only. Wrapped
/// SOL needs no entry and cannot have one; its band is `set_native_price_band`'s.
pub fn set_quote_asset_handler(ctx: Context<SetQuoteAsset>, enabled: bool, min_usd_per_quote: u128, max_usd_per_quote: u128) -> Result<()> {
    let mint = ctx.accounts.mint.key();
    require_keys_neq!(mint, anchor_spl::token::spl_token::native_mint::ID, SplitterError::QuoteAssetUnsupported);
    // Turning an asset OFF reads nothing about it: the admin must be able to stop launches against
    // an asset whose mint has been closed or whose badge Meteora has withdrawn -- exactly when
    // reading them would fail. What the entry already says is kept, with `enabled` false.
    if !enabled {
        let p = &mut ctx.accounts.pair;
        p.mint = mint;
        p.enabled = false;
        p.bump = ctx.bumps.pair;
        emit!(QuoteAssetSet {
            mint,
            token_program: p.token_program,
            badge: p.badge,
            enabled: false,
            min_usd_per_quote: p.min_usd_per_quote,
            max_usd_per_quote: p.max_usd_per_quote,
        });
        return Ok(());
    }
    crate::price::check_band(min_usd_per_quote, max_usd_per_quote)?;
    let q = inspect_mint(ctx.accounts.mint.owner, &ctx.accounts.mint.try_borrow_data()?).ok_or(SplitterError::QuoteAssetUnsupported)?;
    require!(!q.unsupported && !q.hook_program, SplitterError::QuoteAssetUnsupported);
    let badge = if q.needs_badge {
        require!(is_token_badge(&ctx.accounts.badge, &mint), SplitterError::QuoteAssetUnsupported);
        ctx.accounts.badge.key()
    } else {
        Pubkey::default()
    };
    let p = &mut ctx.accounts.pair;
    p.mint = mint;
    p.token_program = q.token_program;
    p.badge = badge;
    p.decimals = q.decimals;
    p.enabled = true;
    p.bump = ctx.bumps.pair;
    p.min_usd_per_quote = min_usd_per_quote;
    p.max_usd_per_quote = max_usd_per_quote;
    emit!(QuoteAssetSet { mint, token_program: q.token_program, badge, enabled: true, min_usd_per_quote, max_usd_per_quote });
    Ok(())
}

/// The allowlist entry `account` is, for `mint`, read and checked: this program's, at the address
/// the mint derives, enabled, and for the program that owns the mint.
pub fn read_quote_asset(account: &AccountInfo, mint: &Pubkey, mint_owner: &Pubkey) -> Result<QuoteAsset> {
    require_keys_eq!(*account.owner, crate::ID, SplitterError::QuoteAssetNotAllowed);
    let pair = QuoteAsset::try_deserialize(&mut &account.try_borrow_data()?[..]).map_err(|_| error!(SplitterError::QuoteAssetNotAllowed))?;
    let expected = Pubkey::create_program_address(&[PAIR_SEED, mint.as_ref(), &[pair.bump]], &crate::ID)
        .map_err(|_| error!(SplitterError::QuoteAssetNotAllowed))?;
    require!(account.key() == expected && pair.mint == *mint && pair.enabled, SplitterError::QuoteAssetNotAllowed);
    require_keys_eq!(pair.token_program, *mint_owner, SplitterError::QuoteAssetNotAllowed);
    Ok(pair)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/xstocks/XsbEhLAtcf6HdfpFZ5xEMdqW8nfAvcsP5bdudRLJzJp.bin")).unwrap()
    }

    /// AAPLx as it is on mainnet: Token-2022, 8 decimals, a badge needed, its accounts 175 bytes
    /// (a transfer-hook account and a pausable account), not paused, not default-frozen, and its
    /// transfer hook has an authority and no program.
    #[test]
    fn an_xstock_reads_as_what_it_is() {
        let q = inspect_mint(&TOKEN_2022_ID, &fixture()).unwrap();
        assert_eq!(
            q,
            QuoteMint {
                token_program: TOKEN_2022_ID,
                decimals: 8,
                account_len: 175,
                needs_badge: true,
                unsupported: false,
                paused: false,
                default_frozen: false,
                hook_program: false,
            }
        );
        // Paused, default-frozen, a hook program: each read.
        let mut d = fixture();
        d[335 + 4 + 32] = 1;
        assert!(inspect_mint(&TOKEN_2022_ID, &d).unwrap().paused);
        let mut d = fixture();
        d[270 + 4] = 2;
        assert!(inspect_mint(&TOKEN_2022_ID, &d).unwrap().default_frozen);
        let mut d = fixture();
        d[441 + 4 + 32] = 7;
        assert!(inspect_mint(&TOKEN_2022_ID, &d).unwrap().hook_program);
        // A transfer fee, or an extension nobody here knows: unsupported.
        let mut d = fixture();
        d[166] = TRANSFER_FEE_CONFIG as u8;
        assert!(inspect_mint(&TOKEN_2022_ID, &d).unwrap().unsupported);
        let mut d = fixture();
        d[166] = 99;
        assert!(inspect_mint(&TOKEN_2022_ID, &d).unwrap().unsupported);
        // Owned by anything but a token program, or not a mint: nothing.
        assert!(inspect_mint(&Pubkey::default(), &fixture()).is_none());
        assert!(inspect_mint(&TOKEN_2022_ID, &[0u8; 10]).is_none());
    }

    #[test]
    fn a_classic_mint_needs_nothing() {
        let mut d = vec![0u8; 82];
        d[44] = 9;
        d[45] = 1;
        let q = inspect_mint(&anchor_spl::token::ID, &d).unwrap();
        assert_eq!((q.decimals, q.account_len, q.needs_badge, q.unsupported), (9, 165, false, false));
    }
}
