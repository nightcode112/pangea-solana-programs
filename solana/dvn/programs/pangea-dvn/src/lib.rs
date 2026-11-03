//! Pangea's LayerZero V2 verifier (DVN) on Solana.
//!
//! A DVN on Solana is an ACCOUNT -- this program's config PDA, `["DvnConfig"]` -- that LayerZero's
//! Ultra Light Node (ULN) treats as a worker:
//!
//! * SOURCE side. When an OApp whose send config names the config PDA sends, the ULN CPIs
//!   `quote_dvn` on the account's owner (this program) with the account, and pays the fee it
//!   returns into the account (`uln/src/instructions/endpoint/quote.rs`, `send.rs`). LayerZero's
//!   SDK finds the accounts that call needs by decoding the config with ITS DVN's layout and
//!   reading `price_feed`, so the config keeps LayerZero's field order exactly (see `DvnConfig`)
//!   and names ITSELF as its price feed: a send through this verifier depends on no other account.
//! * DESTINATION side. `verify` checks a quorum of secp256k1 signatures over one packet, then
//!   calls the ULN's `init_verify` (if needed) and `verify` signed as the config PDA, which is what
//!   writes this verifier's `Confirmations` for the packet. The ULN's `commit_verification` counts
//!   it like any other DVN's.
//!
//! WHY NOT LAYERZERO'S OWN DVN PROGRAM. Their `programs/dvn` is published under BUSL-1.1 (per its
//! package.json; the EVM twin is under the LayerZero Business License 1.2, which grants
//! non-production use only). This program is written for production instead, against the
//! interfaces alone: the ULN's instruction and account layouts, and the account layout LayerZero's
//! SDK decodes. Its signature scheme matches `PangeaDVN.sol`'s (EIP-191 personal-sign of a
//! keccak digest, secp256k1), so one signer key attests on all five chains.
//!
//! IT MUST NEVER BREAK A SEND. A route that names this verifier is pinned into every token opened
//! on it, and the ULN quotes EVERY DVN in a send config, optional ones too. So `quote_dvn` cannot
//! be paused, checks no allow-list and fails on nothing a sender controls; its answer is capped
//! by `fee_cap`. (LayerZero's layout has `paused`, `acl` and `msglibs`; they are kept for the
//! layout, always empty/false, and never read.)
//!
//! THE FEE CAP IS THE ADMIN'S, UNDER A HARD MAXIMUM (owner 2026-10-30). It was fixed at
//! initialisation (90,000 lamports, about $0.009), which could not pay for one verification on
//! Ethereum (about $0.046 of gas). Since this upgrade the config admin sets it with
//! `set_config(ConfigChange::FeeCap)`, which emits `FeeCapChanged` and refuses anything above
//! `FEE_CAP_MAX` (5,000,000 lamports, about $0.49 at $98/SOL) -- so whatever the admin sets, a sender
//! is never charged more than `FEE_CAP_MAX` per packet by this verifier. The account layout is
//! unchanged (`fee_cap` was always stored), so the live config needs no migration and no realloc.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    instruction::{AccountMeta, Instruction},
    keccak,
    program::{invoke, invoke_signed},
    secp256k1_recover::secp256k1_recover,
};

declare_id!("HwNU4xXd7GVuTcjWTtWdT83d27ACJtwSGiFFWDxaELkn");

/// LayerZero's seed for a DVN's config; their SDK derives the config as `PDA(["DvnConfig"], program)`.
pub const DVN_CONFIG_SEED: &[u8] = b"DvnConfig";
/// LayerZero's Ultra Light Node on Solana mainnet.
pub const ULN_ID: Pubkey = pubkey!("7a4WjyR8VZ7yZz5XJAKm39BUGn5iT9CKcv2pmG9tdXVH");
pub const CONFIRMATIONS_SEED: &[u8] = b"Confirmations";
pub const EVENT_AUTHORITY_SEED: &[u8] = b"__event_authority";

/// version(1) nonce(8) src_eid(4) sender(32) dst_eid(4) receiver(32).
pub const PACKET_HEADER_SIZE: usize = 81;
pub const SIGNATURE_LEN: usize = 65;

pub const SIGNERS_MAX_LEN: usize = 7;
pub const ADMINS_MAX_LEN: usize = 5;
pub const MSGLIBS_MAX_LEN: usize = 10;
pub const ACL_MAX_LEN: usize = 8;
pub const FEES_MAX_LEN: usize = 16;

/// The most `fee_cap` can ever be set to, in lamports: 5,000,000 (about $0.49 at $98/SOL, 2026-10-30).
pub const FEE_CAP_MAX: u64 = 5_000_000;

/// Domain tags of the two things signers sign.
pub const VERIFY_TAG: &[u8] = b"PangeaDVN.solana.verify.v1";
pub const CLOSE_TAG: &[u8] = b"PangeaDVN.solana.close.v1";

#[program]
pub mod pangea_dvn {
    use super::*;

    /// Create the config, once. Only the program's upgrade authority may: the config is a
    /// singleton, and whoever made it first would own the verifier.
    pub fn init_dvn(ctx: Context<InitDvn>, params: InitDvnParams) -> Result<()> {
        require!(params.fee_cap <= FEE_CAP_MAX, DvnError::FeeCapTooHigh);
        let c = &mut ctx.accounts.config;
        c.vid = params.vid;
        c.bump = ctx.bumps.config;
        c.set_multisig(params.signers, params.quorum)?;
        c.set_admins(params.admins)?;
        c.acl = Acl::default();
        c.paused = false;
        c.msglibs = vec![];
        c.price_feed = c.key(); // see the module docs: the config is its own "price feed"
        c.dst_configs = vec![];
        c.default_multiplier_bps = 0;
        c.uln_program = params.uln_program;
        c.fee_cap = params.fee_cap;
        c.default_fee = params.default_fee;
        c.fees = vec![];
        emit!(ConfigChanged { what: "init".to_string() });
        Ok(())
    }

    // ------------------------------------------------------------------------- the send side

    /// The ULN's quote of this verifier, inside every `quote` and `send` that names it. Same name
    /// (so same discriminator), accounts and arguments as `worker_interface::quote_dvn`.
    pub fn quote_dvn(ctx: Context<Quote>, params: QuoteDvnParams) -> Result<u64> {
        let fee = ctx.accounts.dvn_config.fee_for(params.dst_eid);
        emit!(JobQuoted {
            dst_eid: params.dst_eid,
            sender: params.sender,
            confirmations: params.confirmations,
            payload_hash: params.payload_hash,
            packet_header: params.packet_header,
            fee,
        });
        Ok(fee)
    }

    // ------------------------------------------------------------------ the destination side

    /// Attest to one packet in the ULN, on the strength of `quorum` signatures. Anyone may send
    /// it; the payer only pays (the `Confirmations` rent, when this is the first attestation).
    pub fn verify(ctx: Context<Verify>, params: VerifyParams) -> Result<()> {
        let config = &ctx.accounts.config;
        require!(params.expiration > Clock::get()?.unix_timestamp, DvnError::Expired);
        let digest = verify_digest(
            &config.key(),
            &params.packet_header,
            &params.payload_hash,
            params.confirmations,
            params.expiration,
        );
        config.multisig.check(&digest, &params.signatures)?;

        let uln = ctx.accounts.uln_program.to_account_info();
        let dvn = config.to_account_info();
        // The ULN's `init_verify`, unless the ULN already owns the account (an earlier attestation,
        // ours retried, made it). NOT "unless it has lamports": the address is predictable, and
        // anyone can send lamports to it first -- it is then a system account with a balance,
        // which the ULN's `init` still initialises and a lamports check would wrongly skip,
        // leaving `verify` to refuse an account it does not own, for good.
        if *ctx.accounts.confirmations.owner != uln.key() {
            let mut data = anchor_sighash("init_verify").to_vec();
            data.extend_from_slice(&params.packet_header);
            data.extend_from_slice(&params.payload_hash);
            data.extend_from_slice(config.key().as_ref());
            invoke(
                &Instruction {
                    program_id: uln.key(),
                    accounts: vec![
                        AccountMeta::new(ctx.accounts.payer.key(), true),
                        AccountMeta::new(ctx.accounts.confirmations.key(), false),
                        AccountMeta::new_readonly(ctx.accounts.system_program.key(), false),
                    ],
                    data,
                },
                &[
                    ctx.accounts.payer.to_account_info(),
                    ctx.accounts.confirmations.to_account_info(),
                    ctx.accounts.system_program.to_account_info(),
                    uln.clone(),
                ],
            )?;
        }
        // The ULN's `verify`, signed as the config PDA: the DVN.
        let mut data = anchor_sighash("verify").to_vec();
        data.extend_from_slice(&params.packet_header);
        data.extend_from_slice(&params.payload_hash);
        data.extend_from_slice(&params.confirmations.to_le_bytes());
        invoke_signed(
            &Instruction {
                program_id: uln.key(),
                accounts: vec![
                    AccountMeta::new_readonly(dvn.key(), true),
                    AccountMeta::new(ctx.accounts.confirmations.key(), false),
                    AccountMeta::new_readonly(ctx.accounts.uln_event_authority.key(), false),
                    AccountMeta::new_readonly(uln.key(), false),
                ],
                data,
            },
            &[
                dvn,
                ctx.accounts.confirmations.to_account_info(),
                ctx.accounts.uln_event_authority.to_account_info(),
                uln,
            ],
            &[&[DVN_CONFIG_SEED, &[config.bump]]],
        )?;
        emit!(PacketVerified {
            header_hash: keccak::hash(&params.packet_header).to_bytes(),
            payload_hash: params.payload_hash,
            confirmations: params.confirmations,
        });
        Ok(())
    }

    /// Close this verifier's `Confirmations` for a packet that has been committed, returning its
    /// rent to `receiver`. Signed like `verify` (the signers name the receiver), because closing
    /// it BEFORE the commit would withdraw the attestation.
    pub fn close_verify(ctx: Context<CloseVerify>, params: CloseVerifyParams) -> Result<()> {
        let config = &ctx.accounts.config;
        require!(params.expiration > Clock::get()?.unix_timestamp, DvnError::Expired);
        let digest = close_digest(
            &config.key(),
            &params.packet_header_hash,
            &params.payload_hash,
            &ctx.accounts.receiver.key(),
            params.expiration,
        );
        config.multisig.check(&digest, &params.signatures)?;
        let mut data = anchor_sighash("close_verify").to_vec();
        data.extend_from_slice(&params.packet_header_hash);
        data.extend_from_slice(&params.payload_hash);
        let uln = ctx.accounts.uln_program.to_account_info();
        invoke_signed(
            &Instruction {
                program_id: uln.key(),
                accounts: vec![
                    AccountMeta::new_readonly(config.key(), true),
                    AccountMeta::new(ctx.accounts.receiver.key(), false),
                    AccountMeta::new(ctx.accounts.confirmations.key(), false),
                ],
                data,
            },
            &[
                config.to_account_info(),
                ctx.accounts.receiver.to_account_info(),
                ctx.accounts.confirmations.to_account_info(),
                uln,
            ],
            &[&[DVN_CONFIG_SEED, &[config.bump]]],
        )?;
        Ok(())
    }

    // ------------------------------------------------------------------------------- admin

    pub fn set_config(ctx: Context<AdminOnly>, change: ConfigChange) -> Result<()> {
        let c = &mut ctx.accounts.config;
        let what = match change {
            ConfigChange::Admins(admins) => {
                c.set_admins(admins)?;
                "admins"
            }
            ConfigChange::Signers { signers, quorum } => {
                c.set_multisig(signers, quorum)?;
                "signers"
            }
            ConfigChange::Fees { default_fee, fees } => {
                require!(fees.len() <= FEES_MAX_LEN, DvnError::TooMany);
                for (i, f) in fees.iter().enumerate() {
                    require!(!fees[..i].iter().any(|g| g.eid == f.eid), DvnError::Duplicate);
                }
                c.default_fee = default_fee;
                c.fees = fees;
                "fees"
            }
            ConfigChange::FeeCap(fee_cap) => {
                require!(fee_cap <= FEE_CAP_MAX, DvnError::FeeCapTooHigh);
                let old_fee_cap = c.fee_cap;
                c.fee_cap = fee_cap;
                emit!(FeeCapChanged { old_fee_cap, new_fee_cap: fee_cap });
                "fee_cap"
            }
        };
        emit!(ConfigChanged { what: what.to_string() });
        Ok(())
    }

    /// Take accrued fees out of the config, never below its rent-exempt minimum.
    pub fn withdraw_fee(ctx: Context<WithdrawFee>, amount: u64) -> Result<()> {
        let config = ctx.accounts.config.to_account_info();
        let floor = Rent::get()?.minimum_balance(config.data_len());
        require!(config.lamports().saturating_sub(floor) >= amount, DvnError::InvalidAmount);
        config.sub_lamports(amount)?;
        ctx.accounts.receiver.add_lamports(amount)?;
        emit!(FeeWithdrawn { receiver: ctx.accounts.receiver.key(), amount });
        Ok(())
    }
}

// ----------------------------------------------------------------------------------- state

/// Field for field LayerZero's `DvnConfig` (programs/dvn/src/state/dvn_config.rs), whose layout
/// their SDK uses to decode every DVN a route names -- then Pangea's own fields after it, which a
/// decoder of their layout simply does not read.
#[account]
#[derive(InitSpace)]
pub struct DvnConfig {
    // ---- LayerZero's layout
    pub vid: u32,
    pub bump: u8,
    pub multisig: Multisig,
    pub acl: Acl,
    pub paused: bool,
    #[max_len(MSGLIBS_MAX_LEN)]
    pub msglibs: Vec<Pubkey>,
    #[max_len(ADMINS_MAX_LEN)]
    pub admins: Vec<Pubkey>,
    pub price_feed: Pubkey,
    #[max_len(0)]
    pub dst_configs: Vec<LzDstConfig>,
    pub default_multiplier_bps: u16,
    // ---- Pangea's
    /// The program `verify` calls: LayerZero's ULN. Fixed at initialisation.
    pub uln_program: Pubkey,
    /// The most a sender is ever charged per packet, in lamports. Set at initialisation and by the
    /// admin (`ConfigChange::FeeCap`), never above `FEE_CAP_MAX`.
    pub fee_cap: u64,
    pub default_fee: u64,
    #[max_len(FEES_MAX_LEN)]
    pub fees: Vec<DstFee>,
}

impl DvnConfig {
    pub fn fee_for(&self, dst_eid: u32) -> u64 {
        let fee = self.fees.iter().find(|f| f.eid == dst_eid).map(|f| f.lamports).unwrap_or(self.default_fee);
        fee.min(self.fee_cap)
    }

    fn set_multisig(&mut self, signers: Vec<[u8; 64]>, quorum: u8) -> Result<()> {
        require!(!signers.is_empty() && signers.len() <= SIGNERS_MAX_LEN, DvnError::InvalidSigners);
        require!(quorum > 0 && quorum as usize <= signers.len(), DvnError::InvalidQuorum);
        for (i, s) in signers.iter().enumerate() {
            require!(!signers[..i].contains(s), DvnError::Duplicate);
        }
        self.multisig = Multisig { signers, quorum };
        Ok(())
    }

    fn set_admins(&mut self, admins: Vec<Pubkey>) -> Result<()> {
        require!(!admins.is_empty() && admins.len() <= ADMINS_MAX_LEN, DvnError::TooMany);
        self.admins = admins;
        Ok(())
    }
}

#[derive(InitSpace, Clone, Default, AnchorSerialize, AnchorDeserialize)]
pub struct Multisig {
    /// Uncompressed secp256k1 public keys (x || y), as `secp256k1_recover` returns them.
    #[max_len(SIGNERS_MAX_LEN)]
    pub signers: Vec<[u8; 64]>,
    pub quorum: u8,
}

impl Multisig {
    /// `quorum` distinct signers signed `digest` (EIP-191 personal-sign, so the same key and the
    /// same signing call serve the EVM chains). Exactly `quorum` signatures, any order.
    pub fn check(&self, digest: &[u8; 32], signatures: &[[u8; SIGNATURE_LEN]]) -> Result<()> {
        require!(signatures.len() == self.quorum as usize, DvnError::InvalidSignatureLen);
        let signed = eth_signed(digest);
        let mut seen: Vec<[u8; 64]> = Vec::with_capacity(signatures.len());
        for sig in signatures {
            let v = sig[64];
            let recovery_id = if v >= 27 { v - 27 } else { v };
            let key = secp256k1_recover(&signed, recovery_id, &sig[..64])
                .map_err(|_| error!(DvnError::SignatureError))?
                .to_bytes();
            require!(self.signers.contains(&key), DvnError::SignerNotInCommittee);
            require!(!seen.contains(&key), DvnError::Duplicate);
            seen.push(key);
        }
        Ok(())
    }
}

#[derive(InitSpace, Clone, Default, AnchorSerialize, AnchorDeserialize)]
pub struct Acl {
    #[max_len(ACL_MAX_LEN)]
    pub allow_list: Vec<Pubkey>,
    #[max_len(ACL_MAX_LEN)]
    pub deny_list: Vec<Pubkey>,
}

/// LayerZero's `DstConfig`, for the layout only. Always an empty list here.
#[derive(InitSpace, Clone, AnchorSerialize, AnchorDeserialize)]
pub struct LzDstConfig {
    pub eid: u32,
    pub dst_gas: u32,
    pub multiplier_bps: Option<u16>,
    pub floor_margin_usd: Option<u128>,
}

#[derive(InitSpace, Clone, Debug, PartialEq, AnchorSerialize, AnchorDeserialize)]
pub struct DstFee {
    pub eid: u32,
    pub lamports: u64,
}

// ---------------------------------------------------------------------------------- digests

/// keccak256(EIP-191 prefix || digest): what `personal_sign` signs.
pub fn eth_signed(digest: &[u8; 32]) -> [u8; 32] {
    keccak::hashv(&[b"\x19Ethereum Signed Message:\n32", digest]).to_bytes()
}

/// What the signers sign for one `verify` through the config at `dvn`.
pub fn verify_digest(
    dvn: &Pubkey,
    header: &[u8; PACKET_HEADER_SIZE],
    payload_hash: &[u8; 32],
    confirmations: u64,
    expiration: i64,
) -> [u8; 32] {
    keccak::hashv(&[
        VERIFY_TAG,
        dvn.as_ref(),
        &keccak::hash(header).to_bytes(),
        payload_hash,
        &confirmations.to_be_bytes(),
        &expiration.to_be_bytes(),
    ])
    .to_bytes()
}

pub fn close_digest(
    dvn: &Pubkey,
    header_hash: &[u8; 32],
    payload_hash: &[u8; 32],
    receiver: &Pubkey,
    expiration: i64,
) -> [u8; 32] {
    keccak::hashv(&[CLOSE_TAG, dvn.as_ref(), header_hash, payload_hash, receiver.as_ref(), &expiration.to_be_bytes()])
        .to_bytes()
}

pub fn anchor_sighash(name: &str) -> [u8; 8] {
    let h = anchor_lang::solana_program::hash::hash(format!("global:{name}").as_bytes()).to_bytes();
    h[..8].try_into().unwrap()
}

// --------------------------------------------------------------------------------- accounts

#[derive(Accounts)]
pub struct InitDvn<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    /// This program's upgrade authority.
    pub authority: Signer<'info>,
    #[account(constraint = program.programdata_address()? == Some(program_data.key()) @ DvnError::NotUpgradeAuthority)]
    pub program: Program<'info, crate::program::PangeaDvn>,
    #[account(constraint = program_data.upgrade_authority_address == Some(authority.key()) @ DvnError::NotUpgradeAuthority)]
    pub program_data: Account<'info, ProgramData>,
    #[account(init, payer = payer, space = 8 + DvnConfig::INIT_SPACE, seeds = [DVN_CONFIG_SEED], bump)]
    pub config: Account<'info, DvnConfig>,
    pub system_program: Program<'info, System>,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct InitDvnParams {
    pub vid: u32,
    pub admins: Vec<Pubkey>,
    pub signers: Vec<[u8; 64]>,
    pub quorum: u8,
    pub uln_program: Pubkey,
    pub fee_cap: u64,
    pub default_fee: u64,
}

/// `worker_interface::Quote`, account for account.
#[derive(Accounts)]
pub struct Quote<'info> {
    #[account(seeds = [DVN_CONFIG_SEED], bump = dvn_config.bump)]
    pub dvn_config: Account<'info, DvnConfig>,
    /// CHECK: whatever the SDK derived from `price_feed`; not read.
    pub price_feed_program: UncheckedAccount<'info>,
    /// CHECK: as above.
    pub price_feed_config: UncheckedAccount<'info>,
}

/// `worker_interface::QuoteDvnParams`, field for field.
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct QuoteDvnParams {
    pub msglib: Pubkey,
    pub dst_eid: u32,
    pub sender: Pubkey,
    pub packet_header: Vec<u8>,
    pub payload_hash: [u8; 32],
    pub confirmations: u64,
    pub options: Vec<LzOption>,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct LzOption {
    pub option_type: u8,
    pub params: Vec<u8>,
}

#[derive(Accounts)]
pub struct Verify<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(seeds = [DVN_CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, DvnConfig>,
    /// CHECK: `PDA(["Confirmations", keccak(header), payload_hash, config], ULN)`; the ULN checks
    /// the seeds itself.
    #[account(mut)]
    pub confirmations: UncheckedAccount<'info>,
    /// CHECK: the ULN this verifier was initialised for.
    #[account(address = config.uln_program @ DvnError::WrongUln)]
    pub uln_program: UncheckedAccount<'info>,
    /// CHECK: the ULN's event authority; the ULN checks it.
    pub uln_event_authority: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct VerifyParams {
    pub packet_header: [u8; PACKET_HEADER_SIZE],
    pub payload_hash: [u8; 32],
    pub confirmations: u64,
    pub expiration: i64,
    pub signatures: Vec<[u8; SIGNATURE_LEN]>,
}

#[derive(Accounts)]
pub struct CloseVerify<'info> {
    #[account(seeds = [DVN_CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, DvnConfig>,
    /// CHECK: named in what the signers signed.
    #[account(mut)]
    pub receiver: UncheckedAccount<'info>,
    /// CHECK: the ULN checks the seeds.
    #[account(mut)]
    pub confirmations: UncheckedAccount<'info>,
    /// CHECK: as in `Verify`.
    #[account(address = config.uln_program @ DvnError::WrongUln)]
    pub uln_program: UncheckedAccount<'info>,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct CloseVerifyParams {
    pub packet_header_hash: [u8; 32],
    pub payload_hash: [u8; 32],
    pub expiration: i64,
    pub signatures: Vec<[u8; SIGNATURE_LEN]>,
}

#[derive(Accounts)]
pub struct AdminOnly<'info> {
    pub admin: Signer<'info>,
    #[account(mut, seeds = [DVN_CONFIG_SEED], bump = config.bump,
        constraint = config.admins.contains(admin.key) @ DvnError::NotAdmin)]
    pub config: Account<'info, DvnConfig>,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub enum ConfigChange {
    Admins(Vec<Pubkey>),
    Signers { signers: Vec<[u8; 64]>, quorum: u8 },
    Fees { default_fee: u64, fees: Vec<DstFee> },
    /// The cap on every quote, in lamports; at most `FEE_CAP_MAX`. LAST: the variants before it keep
    /// their Borsh tags (0, 1, 2), so every existing client's encoding means what it meant.
    FeeCap(u64),
}

#[derive(Accounts)]
pub struct WithdrawFee<'info> {
    pub admin: Signer<'info>,
    #[account(mut, seeds = [DVN_CONFIG_SEED], bump = config.bump,
        constraint = config.admins.contains(admin.key) @ DvnError::NotAdmin)]
    pub config: Account<'info, DvnConfig>,
    /// CHECK: any account the admin names.
    #[account(mut)]
    pub receiver: UncheckedAccount<'info>,
}

// ----------------------------------------------------------------------------------- events

#[event]
pub struct JobQuoted {
    pub dst_eid: u32,
    pub sender: Pubkey,
    pub confirmations: u64,
    pub payload_hash: [u8; 32],
    pub packet_header: Vec<u8>,
    pub fee: u64,
}

#[event]
pub struct PacketVerified {
    pub header_hash: [u8; 32],
    pub payload_hash: [u8; 32],
    pub confirmations: u64,
}

#[event]
pub struct ConfigChanged {
    pub what: String,
}

/// `fee_cap` was changed by the admin (`ConfigChange::FeeCap`).
#[event]
pub struct FeeCapChanged {
    pub old_fee_cap: u64,
    pub new_fee_cap: u64,
}

#[event]
pub struct FeeWithdrawn {
    pub receiver: Pubkey,
    pub amount: u64,
}

#[error_code]
pub enum DvnError {
    NotAdmin,
    NotUpgradeAuthority,
    InvalidSigners,
    InvalidQuorum,
    InvalidSignatureLen,
    SignatureError,
    SignerNotInCommittee,
    Duplicate,
    TooMany,
    Expired,
    WrongUln,
    InvalidAmount,
    /// A fee cap above `FEE_CAP_MAX`. Appended: every earlier code keeps its number.
    FeeCapTooHigh,
}
