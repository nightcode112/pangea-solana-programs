//! The tokenomics v2 config and its hash: the one definition `src/tokenomics/v2/TokenomicsV2Config.sol`
//! and `web/lib/tokenomics/v2-config.mjs` share (vector: `test/fixtures/tokenomics-v2-vector.json`).
//!
//! ```text
//! legHash    = keccak256(abi.encode(uint32 eid, uint16 burn, uint16 buyHold, uint16 liquidity,
//!                uint16 holders, bytes32 treasury, bytes32[] wallets, uint16[] walletBps,
//!                bytes32[] rewardTokens, uint16[] rewardBps))
//! configHash = keccak256(abi.encode(bytes32 V2_TAG, bytes32 launchId, bytes32 ownerEvm,
//!                bytes32 ownerSol, uint16 minHolderBps, uint8 selectMode, uint32 selectCount,
//!                uint32[] legEids, bytes32[] legHashes))
//! V2_TAG     = keccak256("pangea tokenomics v2")
//! ```
//!
//! `abi.encode` of a parameter list: one head word per parameter (a static value, or for a dynamic
//! array the byte offset of its tail from the start), then each array's tail -- its length and one
//! word per element -- in parameter order. Every value here is one word, so the offsets are plain
//! word counts.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::keccak;

pub const V2_BPS: u32 = 10_000;
pub const V2_MAX_LEGS: usize = 8;
pub const MAX_WALLETS: usize = 10;
pub const MAX_REWARD_TOKENS: usize = 5;
/// 0.1% of supply: the default holder minimum and the lowest one may be set.
pub const MIN_HOLDER_BPS_FLOOR: u16 = 10;
pub const SELECT_ALL: u8 = 0;
pub const SELECT_TOP: u8 = 1;
pub const SELECT_RANDOM: u8 = 2;
/// `PDA(["tokenomics-v2", configHash])`.
pub const TOKENOMICS_V2_SEED: &[u8] = b"tokenomics-v2";

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct TokenomicsLegV2 {
    pub eid: u32,
    pub burn_bps: u16,
    pub buy_hold_bps: u16,
    pub liquidity_bps: u16,
    pub holders_bps: u16,
    pub treasury: [u8; 32],
    pub wallets: Vec<[u8; 32]>,
    pub wallet_bps: Vec<u16>,
    pub reward_tokens: Vec<[u8; 32]>,
    pub reward_bps: Vec<u16>,
}

/// The launch-wide fields and every leg's eid and hash, ascending by eid.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct TokenomicsConfigV2 {
    pub launch_id: [u8; 32],
    pub owner_evm: [u8; 32],
    pub owner_sol: [u8; 32],
    pub min_holder_bps: u16,
    pub select_mode: u8,
    pub select_count: u32,
    pub leg_eids: Vec<u32>,
    pub leg_hashes: Vec<[u8; 32]>,
}

fn word(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&[0u8; 24]);
    out.extend_from_slice(&v.to_be_bytes());
}

fn tail_words<T: Copy>(out: &mut Vec<u8>, xs: &[T], f: impl Fn(&mut Vec<u8>, T)) {
    word(out, xs.len() as u64);
    for x in xs {
        f(out, *x);
    }
}

pub fn v2_tag() -> [u8; 32] {
    keccak::hash(b"pangea tokenomics v2").to_bytes()
}

impl TokenomicsLegV2 {
    pub fn encoding(&self) -> Vec<u8> {
        // 10 head words; tails in order: wallets, walletBps, rewardTokens, rewardBps.
        let n_w = self.wallets.len() as u64;
        let n_wb = self.wallet_bps.len() as u64;
        let n_r = self.reward_tokens.len() as u64;
        let o1 = 10 * 32;
        let o2 = o1 + 32 * (1 + n_w);
        let o3 = o2 + 32 * (1 + n_wb);
        let o4 = o3 + 32 * (1 + n_r);
        let mut out = Vec::with_capacity((o4 as usize) + 32 * (1 + self.reward_bps.len()));
        word(&mut out, self.eid as u64);
        word(&mut out, self.burn_bps as u64);
        word(&mut out, self.buy_hold_bps as u64);
        word(&mut out, self.liquidity_bps as u64);
        word(&mut out, self.holders_bps as u64);
        out.extend_from_slice(&self.treasury);
        word(&mut out, o1);
        word(&mut out, o2);
        word(&mut out, o3);
        word(&mut out, o4);
        tail_words(&mut out, &self.wallets, |o, a: [u8; 32]| o.extend_from_slice(&a));
        tail_words(&mut out, &self.wallet_bps, |o, b: u16| word(o, b as u64));
        tail_words(&mut out, &self.reward_tokens, |o, a: [u8; 32]| o.extend_from_slice(&a));
        tail_words(&mut out, &self.reward_bps, |o, b: u16| word(o, b as u64));
        out
    }

    pub fn hash(&self) -> [u8; 32] {
        keccak::hash(&self.encoding()).to_bytes()
    }
}

impl TokenomicsConfigV2 {
    pub fn encoding(&self) -> Vec<u8> {
        // 9 head words; tails: legEids, legHashes.
        let n = self.leg_eids.len() as u64;
        let o1 = 9 * 32;
        let o2 = o1 + 32 * (1 + n);
        let mut out = Vec::with_capacity((o2 as usize) + 32 * (1 + self.leg_hashes.len()));
        out.extend_from_slice(&v2_tag());
        out.extend_from_slice(&self.launch_id);
        out.extend_from_slice(&self.owner_evm);
        out.extend_from_slice(&self.owner_sol);
        word(&mut out, self.min_holder_bps as u64);
        word(&mut out, self.select_mode as u64);
        word(&mut out, self.select_count as u64);
        word(&mut out, o1);
        word(&mut out, o2);
        tail_words(&mut out, &self.leg_eids, |o, e: u32| word(o, e as u64));
        tail_words(&mut out, &self.leg_hashes, |o, h: [u8; 32]| o.extend_from_slice(&h));
        out
    }

    /// The EVM vault's CREATE2 salt and the Solana account's seed.
    pub fn hash(&self) -> [u8; 32] {
        keccak::hash(&self.encoding()).to_bytes()
    }
}
