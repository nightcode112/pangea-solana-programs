//! L4 (owner 2026-10-30): the SENDER prepays an expired compose's way home. A composed v3 arrival
//! for a listed composer may come with a LayerZero native drop to the guid-independent
//! PDA(["GapPrepay", store, src_eid BE, compose_from, sha256(composeMsg)]) (state::prepay_address):
//! P = receipt rent + 1.1 x LayerZero's fee home + GapGlobal.return_gas_lamports. The receive sweeps
//! it into the receipt (so the receipt's rent comes from the sender), `sweep_gap_prepay` sweeps a
//! drop that lands later, the receipt's `prepaid` counts the sender's lamports, and:
//!   * the compose runs: `close_gap_receipt` sends all of `prepaid` to the composer's refund account;
//!   * it expires: `return_expired_compose` reimburses the caller LayerZero's fee as actually spent
//!     plus the return gas, out of `prepaid`; the rest goes to receipt.refund_to (else the caller).
//! The rent a delivery payer fronted (an unfunded compose) always goes back to receipt.payer.
//! Pangea never pays a return and never keeps any of it.
use crate::*;
use anchor_lang::solana_program::{program::invoke_signed, system_instruction};

/// Every lamport of the prepay PDA `prepay` to `to` (a system transfer signed by the PDA), when it is
/// the PDA of (store, src_eid, compose_from, compose_msg) and a funded 0-data system account; 0
/// otherwise (nothing dropped, or not a system account: nothing can be moved, nothing is).
#[allow(clippy::too_many_arguments)]
pub fn sweep<'info>(prepay: &AccountInfo<'info>, to: &AccountInfo<'info>, system: &AccountInfo<'info>, program_id: &Pubkey, store: &Pubkey, src_eid: u32, compose_from: &[u8; 32], compose_msg: &[u8]) -> Result<u64> {
    let (key, bump) = crate::gap::state::prepay_address(program_id, store, src_eid, compose_from, compose_msg);
    require_keys_eq!(*prepay.key, key, OFTError::GapAccountMismatch);
    require_keys_eq!(*system.key, anchor_lang::system_program::ID, OFTError::GapAccountMismatch);
    let n = prepay.lamports();
    if n == 0 || *prepay.owner != anchor_lang::system_program::ID || !prepay.data_is_empty() {
        return Ok(0);
    }
    let h = anchor_lang::solana_program::hash::hash(compose_msg).to_bytes();
    let eid = src_eid.to_be_bytes();
    let seeds: &[&[u8]] = &[crate::gap::state::GAP_PREPAY_SEED, store.as_ref(), &eid, compose_from, &h, &[bump]];
    invoke_signed(&system_instruction::transfer(prepay.key, to.key, n), &[prepay.clone(), to.clone(), system.clone()], &[seeds])?;
    Ok(n)
}

/// Move `n` lamports out of `from` (an account this program owns) into `to`.
pub fn move_lamports(from: &AccountInfo, to: &AccountInfo, n: u64) -> Result<()> {
    if n == 0 {
        return Ok(());
    }
    require!(to.is_writable, OFTError::GapAccountMismatch);
    let have = from.lamports();
    require!(have >= n, OFTError::GapAccountMismatch);
    **from.try_borrow_mut_lamports()? = have - n;
    let t = to.lamports();
    **to.try_borrow_mut_lamports()? = t.checked_add(n).ok_or(OFTError::GapAccountMismatch)?;
    Ok(())
}

/// oft-lows6 (oft-lows5-r1 L-1): the runtime's RESERVED account keys -- agave-reserved-account-keys 4.3.2
/// `RESERVED_ACCOUNTS`, all 31 (builtin programs, sysvars, the native loader, the sysvar owner), which every
/// transaction gets READ-ONLY whatever it asks for (some do not exist on chain: they are demoted all the
/// same). Kept in step with script/fastbridge/solana-recipient.mjs, web/lib/chain/solana-route-open.mjs and
/// pangea-fastbridge's copy (script/fastbridge/solana-recipient.test.mjs compares them).
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

/// oft-lows6: an account the runtime itself keeps read-only or uncreditable: a program (executable), a sysvar
/// (owned by the sysvar id) or a reserved key. A legacy message also demotes a key it calls as a program: an
/// executable one.
pub fn runtime_read_only(acc: &AccountInfo) -> bool {
    acc.executable || *acc.owner == SYSVAR_OWNER || RESERVED_ACCOUNT_KEYS.contains(acc.key)
}

/// oft-lows6 (oft-lows5-r1 L-1; oft-lows5 option (a) widened): whether a refund account CANNOT be credited, so
/// what it would get stays with the receipt's payer (a close) or the caller (a return), named by
/// GapPrepaidRefundToExecutable for a manual return: an executable account (ExecutableLamportChange) or one
/// this transaction has read-only (ReadonlyLamportChange) -- a sysvar, a builtin, any reserved key, the
/// called program's own id. Neither can ever be credited, so before this every close / return naming one
/// failed for good. A READ-ONLY account the runtime would let be written (a wallet, a box, a PDA) is refused
/// (RefundNotWritable): passing a holder read-only never moves its refund to anyone else.
pub fn cannot_hold(acc: &AccountInfo) -> Result<bool> {
    if acc.executable {
        return Ok(true);
    }
    if acc.is_writable {
        return Ok(false);
    }
    require!(runtime_read_only(acc), OFTError::RefundNotWritable);
    Ok(true)
}

/// The return's split of the sender's `prepaid` lamports: (to the caller, to the refund) for
/// LayerZero's fee as actually spent `spent` and the return gas `gas`: the caller is reimbursed
/// min(prepaid, spent + gas), the rest is the sender's.
pub fn return_split(prepaid: u64, spent: u64, gas: u64) -> (u64, u64) {
    let pay = prepaid.min(spent.saturating_add(gas));
    (pay, prepaid - pay)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_split_never_pays_more_than_prepaid_and_reimburses_spend_plus_gas() {
        // the worked example: P = 3,949,188, X = 486,062, Y = 25,000
        assert_eq!(return_split(3_949_188, 486_062, 25_000), (511_062, 3_438_126));
        // short: everything to the caller, nothing back (the caller pays the difference itself)
        assert_eq!(return_split(300_000, 486_062, 25_000), (300_000, 0));
        assert_eq!(return_split(0, 486_062, 25_000), (0, 0));
        assert_eq!(return_split(u64::MAX, u64::MAX, u64::MAX), (u64::MAX, 0));
        for p in [0u64, 1, 511_061, 511_062, 511_063, 10_000_000] {
            let (a, b) = return_split(p, 486_062, 25_000);
            assert_eq!(a + b, p);
            assert!(a <= 511_062);
        }
    }
}
