//! Byte layouts this program reads and never writes: LayerZero's OFT store and `send` instruction,
//! the OFT program's compose message, a sale's payload, Token-2022 / SPL token accounts. Pure
//! functions over byte slices, so every one is unit-tested without a VM.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::instruction::Instruction;

/// sha256("account:OFTStore")[..8], as LayerZero's OFT program writes it.
pub const OFT_STORE_DISCRIMINATOR: [u8; 8] = [195, 215, 104, 134, 185, 195, 240, 114];
// `OFTStore` after the discriminator: oft_type (1), ld2sd_rate (8), token_mint (32), token_escrow
// (32), endpoint_program (32), bump (1), tvl_ld (8), admin (32), default_fee_bps (2), paused (1) ...
// The same offsets the splitter reads (`bridge::read_oft_store`), pinned there against the program.
const OFT_STORE_TOKEN_MINT: usize = 17;
const OFT_STORE_ADMIN: usize = 122;

/// sha256("global:send")[..8]: the OFT program's `send`.
pub const OFT_SEND_DISCRIMINATOR: [u8; 8] = [102, 251, 20, 187, 65, 75, 12, 69];
/// sha256("global:clear_compose")[..8]: the endpoint's `clear_compose`.
pub const CLEAR_COMPOSE_DISCRIMINATOR: [u8; 8] = [118, 1, 18, 142, 95, 175, 21, 125];
/// sha256("global:swap")[..8]: Meteora DAMM v2's `swap(amount_in, minimum_amount_out)`.
pub const CP_AMM_SWAP_DISCRIMINATOR: [u8; 8] = [248, 198, 158, 145, 225, 117, 135, 200];

/// Pangea v3 gap fee (docs/v3-gap-fee-spec.md §10.3): a store made by `init_oft_v3` is at least
/// this long (LayerZero's 223 bytes and the gap tail). The marker this program goes by: such a
/// store refuses its `send` under CPI or after an earlier instruction touched its pool, and its
/// composed arrivals make no LayerZero compose record (a `GapReceipt` instead).
pub const V3_STORE_LEN: usize = 319;

/// Whether an OFT store's data is a v3 store's.
pub fn is_v3_store(store_data: &[u8]) -> bool {
    store_data.len() >= V3_STORE_LEN
}

/// The seed of a composed v3 arrival's record, `PDA(["GapReceipt", guid])` under the OFT program.
pub const GAP_RECEIPT_SEED: &[u8] = b"GapReceipt";
/// sha256("account:GapReceipt")[..8].
pub const GAP_RECEIPT_DISCRIMINATOR: [u8; 8] = [0x58, 0x38, 0x01, 0xa7, 0x0e, 0xa2, 0x1f, 0x1e];
/// sha256("global:close_gap_receipt")[..8]: the OFT program's `close_gap_receipt`.
pub const CLOSE_GAP_RECEIPT_DISCRIMINATOR: [u8; 8] = [0x2a, 0xf6, 0x72, 0x5a, 0x73, 0x18, 0xa0, 0x01];
/// sha256("global:set_gap_receipt_refund")[..8]: the OFT program's `set_gap_receipt_refund` (L4).
pub const SET_GAP_RECEIPT_REFUND_DISCRIMINATOR: [u8; 8] = [0x05, 0xa5, 0x05, 0xb0, 0xbc, 0xcb, 0x2d, 0x49];
/// The receipt's fixed part: the discriminator and every field up to compose_msg's length.
pub const GAP_RECEIPT_FIXED_LEN: usize = 219;
/// The longest compose_msg a receipt holds (the OFT program's `MAX_COMPOSE_MSG_LEN`).
pub const GAP_RECEIPT_MAX_MSG: usize = 512;

/// A v3 store's record of one composed arrival (spec §10.5), as the OFT program writes it:
/// discriminator 8 | version @8 | bump @9 | oft_store @10 | guid @42 | src_eid u32 LE @74 | nonce u64
/// LE @78 | to @86 | payer @118 | amount_ld @150 | withheld_ld @158 | credited_ld @166 | reason @174
/// | created_at i64 @175 | compose_from @183 | compose_msg (u32 LE length @215, bytes @219) | L4
/// (owner 2026-10-30), appended: prepaid u64 LE @219+len | refund_to @227+len (219 + len + 40 B). A
/// receipt without the 40 bytes (written before L4) reads as prepaid 0, refund_to unset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GapReceiptView<'a> {
    pub version: u8,
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
    /// L4: the sender's prepaid return lamports in the receipt (0 without the L4 tail).
    pub prepaid: u64,
    /// L4: where the sender's lamports go on a return (default: unset).
    pub refund_to: Pubkey,
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
        version: d[8],
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
        prepaid: u64_at(219 + len).unwrap_or(0),
        refund_to: key(227 + len).unwrap_or_default(),
    })
}

/// The seed of the OFT program's one `GapGlobal`, `PDA(["GapGlobal"])` under the OFT program.
pub const GAP_GLOBAL_SEED: &[u8] = b"GapGlobal";
/// sha256("account:GapGlobal")[..8].
pub const GAP_GLOBAL_DISCRIMINATOR: [u8; 8] = [0x16, 0xf0, 0xc9, 0x49, 0x02, 0x6b, 0xa9, 0xda];
/// oft-q7 (Q7-e): `GapGlobal.dst_delivery`, 4 slots of {eid u32 LE, lamports u64 LE} at 764 (eid 0 =
/// an empty slot); the account is at least 844 bytes from that layout on (912 since oft-fix). The
/// same offsets as solana/client/gap-a6-layout.mjs GAP_GLOBAL_DST_DELIVERY_AT.
pub const GAP_GLOBAL_DST_DELIVERY_AT: usize = 764;
pub const GAP_GLOBAL_DST_DELIVERY_SLOTS: usize = 4;
pub const GAP_GLOBAL_DST_DELIVERY_SLOT_LEN: usize = 12;
pub const GAP_GLOBAL_MIN_LEN: usize = 844;

/// The OFT program's `GapGlobal.dst_delivery_of(eid)` (state.rs): what OUR keys charge to deliver a
/// send toward `eid` -- a KEYS-ONLY destination, LayerZero's executor not executing there -- or 0
/// when LayerZero's executor delivers. None if `d` is not a GapGlobal with that field.
pub fn gap_global_dst_delivery(d: &[u8], eid: u32) -> Option<u64> {
    if d.len() < GAP_GLOBAL_MIN_LEN || d[..8] != GAP_GLOBAL_DISCRIMINATOR {
        return None;
    }
    if eid == 0 {
        return Some(0);
    }
    for i in 0..GAP_GLOBAL_DST_DELIVERY_SLOTS {
        let at = GAP_GLOBAL_DST_DELIVERY_AT + GAP_GLOBAL_DST_DELIVERY_SLOT_LEN * i;
        if u32::from_le_bytes(d[at..at + 4].try_into().ok()?) == eid {
            return Some(u64::from_le_bytes(d[at + 4..at + 12].try_into().ok()?));
        }
    }
    Some(0)
}

/// Q59 (owner 2026-10-31): the least margin a keys-only destination's cap on the fee home keeps above
/// its delivery cost -- today's cap, LayerZero's own part of the way home.
pub const KEYS_ONLY_HOME_FEE_MARGIN_MIN: u64 = 50_000_000;

/// Q59: the cap on LayerZero's fee home toward a source chain, from the cap every route has
/// (`base`, today 50,000,000) and the OFT program's `dst_delivery` toward it (0: LayerZero's
/// executor delivers there).
///
///   * dst_delivery 0: `base`, unchanged.
///   * a KEYS-ONLY chain (dst_delivery > 0, Ethereum: 84,516,130 = 2 gwei x 1.31M gas): the way home
///     carries LayerZero's fee with its executor gas on that chain (the same gas the delivery cost
///     is figured on) or, through send_v3, LayerZero's part plus that cost. So the cap is
///     `dst_delivery + max(dst_delivery, KEYS_ONLY_HOME_FEE_MARGIN_MIN)` (never below `base`):
///     169,032,260 at today's 84,516,130, which takes a quoted fee home of up to 112.7M with the
///     plan's 1.5x headroom; at the OFT's DST_DELIVERY_LAMPORTS_MAX (206,451,612) 412,903,224.
///
/// A cap is a ceiling the seller names and agrees to, not a charge: a failed sale pays LayerZero's
/// actual fee home, and what it does not charge goes to the seller's box (`finish_send`).
pub fn home_fee_cap_for(base: u64, dst_delivery: u64) -> u64 {
    if dst_delivery == 0 {
        return base;
    }
    base.max(dst_delivery.saturating_add(dst_delivery.max(KEYS_ONLY_HOME_FEE_MARGIN_MIN)))
}

/// What an OFT store says about itself that this program relies on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreView {
    /// LayerZero's `OFTType`: 0 Native (mints and burns), 1 Adapter (locks and releases).
    pub oft_type: u8,
    pub token_mint: Pubkey,
    pub admin: Pubkey,
}

/// `OFTType::Adapter`: a SUPPLY_TOTAL launch's lockbox store since 2026-10-24.
pub const OFT_TYPE_ADAPTER: u8 = 1;

/// sha256("account:TvlMark")[..8]: our OFT program's one-shot `init_tvl` record (solana/oft).
pub const TVL_MARK_DISCRIMINATOR: [u8; 8] = [178, 12, 132, 142, 124, 240, 74, 80];

/// The admin that signed a store's `init_tvl`, from its `TvlMark` (the discriminator, then the
/// key), or None if `data` is not one.
pub fn read_tvl_mark(data: &[u8]) -> Option<Pubkey> {
    if data.get(..8)? != TVL_MARK_DISCRIMINATOR {
        return None;
    }
    Some(Pubkey::new_from_array(data.get(8..40)?.try_into().ok()?))
}

pub fn read_store(data: &[u8]) -> Option<StoreView> {
    if data.get(..8)? != OFT_STORE_DISCRIMINATOR {
        return None;
    }
    let key = |at: usize| -> Option<Pubkey> { Some(Pubkey::new_from_array(data.get(at..at + 32)?.try_into().ok()?)) };
    Some(StoreView { oft_type: *data.get(8)?, token_mint: key(OFT_STORE_TOKEN_MINT)?, admin: key(OFT_STORE_ADMIN)? })
}

/// A token account's mint, owner and balance (the first 72 bytes are the same in SPL Token and
/// Token-2022). None for anything shorter than a token account, or one not initialized (its state,
/// byte 108, is 1): a multisig or anything else of that size is not read as one.
pub fn read_token_account(data: &[u8]) -> Option<(Pubkey, Pubkey, u64)> {
    if data.len() < 165 || data[108] != 1 {
        return None;
    }
    let mint = Pubkey::new_from_array(data[0..32].try_into().ok()?);
    let owner = Pubkey::new_from_array(data[32..64].try_into().ok()?);
    let amount = u64::from_le_bytes(data[64..72].try_into().ok()?);
    Some((mint, owner, amount))
}

/// A mint's authority: `COption<Pubkey>` at the start of the mint (SPL Token and Token-2022 alike), or
/// None when it has none.
pub fn read_mint_authority(data: &[u8]) -> Option<Pubkey> {
    if data.len() < 82 || data[0..4] != [1, 0, 0, 0] {
        return None;
    }
    Some(Pubkey::new_from_array(data[4..36].try_into().ok()?))
}

/// A Token-2022 (or SPL Token) multisig's signers: `m`, `n`, initialized, then eleven keys, of
/// which the first `n` are its own. 355 bytes exactly. None for anything else.
pub fn read_multisig(data: &[u8]) -> Option<Vec<Pubkey>> {
    if data.len() != 355 || data[2] != 1 {
        return None;
    }
    let n = data[1] as usize;
    if n == 0 || n > 11 || data[0] == 0 || data[0] as usize > n {
        return None;
    }
    Some((0..n).map(|i| Pubkey::new_from_array(data[3 + 32 * i..35 + 32 * i].try_into().unwrap())).collect())
}

/// The parameters of an OFT `send`, when it carries nothing but a transfer: no options of the
/// sender's own and no compose message. Anything else is None.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OftSend {
    pub dst_eid: u32,
    pub to: [u8; 32],
    pub amount_ld: u64,
    pub min_amount_ld: u64,
    pub native_fee: u64,
    pub lz_token_fee: u64,
}

/// Exactly 81 bytes: the discriminator, then `SendParams` as Borsh lays it out with an empty
/// options vector (four zero bytes) and no compose message (one zero byte).
pub fn read_oft_send(data: &[u8]) -> Option<OftSend> {
    if data.len() != 81 || data[..8] != OFT_SEND_DISCRIMINATOR {
        return None;
    }
    let u64_at = |at: usize| u64::from_le_bytes(data[at..at + 8].try_into().unwrap());
    let dst_eid = u32::from_le_bytes(data[8..12].try_into().unwrap());
    let to: [u8; 32] = data[12..44].try_into().unwrap();
    let amount_ld = u64_at(44);
    let min_amount_ld = u64_at(52);
    if data[60..64] != [0, 0, 0, 0] || data[64] != 0 {
        return None;
    }
    Some(OftSend { dst_eid, to, amount_ld, min_amount_ld, native_fee: u64_at(65), lz_token_fee: u64_at(73) })
}

/// The OFT `send` an instruction is, with the accounts this program checks: the signer (0), the
/// store (2), the token account the amount leaves (3) and the mint (5). None if it is not one.
pub struct SendIx {
    pub params: OftSend,
    pub signer: Pubkey,
    pub signer_signs: bool,
    pub store: Pubkey,
    pub source: Pubkey,
    pub mint: Pubkey,
}

pub fn read_send_ix(ix: &Instruction, oft_program: &Pubkey) -> Option<SendIx> {
    if ix.program_id != *oft_program || ix.accounts.len() < 6 {
        return None;
    }
    let params = read_oft_send(&ix.data)?;
    Some(SendIx {
        params,
        signer: ix.accounts[0].pubkey,
        signer_signs: ix.accounts[0].is_signer,
        store: ix.accounts[2].pubkey,
        source: ix.accounts[3].pubkey,
        mint: ix.accounts[5].pubkey,
    })
}

/// What the OFT program hands a composer: the packet's nonce, its source chain, the amount that
/// arrived in base units, who composed it (32 bytes) and the call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Composed<'a> {
    pub nonce: u64,
    pub src_eid: u32,
    pub amount_ld: u64,
    pub from: [u8; 32],
    pub payload: &'a [u8],
}

pub fn read_composed(m: &[u8]) -> Option<Composed<'_>> {
    if m.len() < 52 {
        return None;
    }
    Some(Composed {
        nonce: u64::from_be_bytes(m[0..8].try_into().ok()?),
        src_eid: u32::from_be_bytes(m[8..12].try_into().ok()?),
        amount_ld: u64::from_be_bytes(m[12..20].try_into().ok()?),
        from: m[20..52].try_into().ok()?,
        payload: &m[52..],
    })
}

/// A sale's call, as the EVM web writes it with `abi.encodePacked(uint8 1, uint64 minSolOut,
/// uint64 deadline, uint64 runnerFee, uint64 homeFeeCap)`: 33 bytes, big-endian.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SellPayload {
    /// The least the sale must fetch, in lamports, before anything is taken from it.
    pub min_sol_out: u64,
    /// Unix seconds. After it the sale is not made; the tokens go home.
    pub deadline: i64,
    /// What whoever runs the compose is paid out of the proceeds (or, on the way home, out of the
    /// slice sold to pay for it), in lamports.
    pub runner_fee: u64,
    /// The most LayerZero's fee home may be, if the tokens go home.
    pub home_fee_cap: u64,
}

pub const SELL_PAYLOAD_VERSION: u8 = 1;
pub const SELL_PAYLOAD_LEN: usize = 33;
/// L4 (lead decision, 2026-10-30): the JS compose builder appends a 16-byte random salt to the
/// composeMsg, so two identical sales from one sender never share a GapPrepay PDA
/// (sha256(composeMsg) is one of its seeds). The salt is not read.
pub const SELL_PAYLOAD_SALT_LEN: usize = 16;

/// A sale's payload: exactly 33 bytes, or 33 + the 16-byte salt; anything else is not a sale.
pub fn read_sell_payload(p: &[u8]) -> Option<SellPayload> {
    if (p.len() != SELL_PAYLOAD_LEN && p.len() != SELL_PAYLOAD_LEN + SELL_PAYLOAD_SALT_LEN) || p[0] != SELL_PAYLOAD_VERSION {
        return None;
    }
    let u = |at: usize| u64::from_be_bytes(p[at..at + 8].try_into().unwrap());
    let deadline = i64::try_from(u(9)).ok()?;
    Some(SellPayload { min_sol_out: u(1), deadline, runner_fee: u(17), home_fee_cap: u(25) })
}

/// An EVM address as LayerZero writes it in 32 bytes: twelve zero bytes, then twenty that are not
/// all zero.
pub fn evm_address(b: &[u8; 32]) -> Option<[u8; 20]> {
    if b[..12] != [0u8; 12] || b[12..] == [0u8; 20] {
        return None;
    }
    Some(b[12..].try_into().unwrap())
}

pub fn left_pad(user: &[u8; 20]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(user);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use anchor_lang::solana_program::hash::hash;

    #[test]
    fn the_discriminators_are_anchors() {
        for (name, d) in [
            ("global:send", OFT_SEND_DISCRIMINATOR),
            ("global:clear_compose", CLEAR_COMPOSE_DISCRIMINATOR),
            ("global:swap", CP_AMM_SWAP_DISCRIMINATOR),
            ("account:OFTStore", OFT_STORE_DISCRIMINATOR),
            ("account:GapReceipt", GAP_RECEIPT_DISCRIMINATOR),
            ("global:close_gap_receipt", CLOSE_GAP_RECEIPT_DISCRIMINATOR),
            ("global:set_gap_receipt_refund", SET_GAP_RECEIPT_REFUND_DISCRIMINATOR),
            ("account:GapGlobal", GAP_GLOBAL_DISCRIMINATOR),
        ] {
            assert_eq!(&hash(name.as_bytes()).to_bytes()[..8], &d, "{name}");
        }
    }

    /// Q59: the per-chain cap on the fee home, and GapGlobal's dst_delivery as the OFT program lays
    /// it out (the litesvm tests read it from the real program's account: cheapest.rs, gap_v3.rs).
    #[test]
    fn the_home_fee_cap_is_read_per_chain_from_dst_delivery() {
        assert_eq!(home_fee_cap_for(50_000_000, 0), 50_000_000, "LayerZero's executor delivers: today's cap");
        assert_eq!(home_fee_cap_for(50_000_000, 84_516_130), 169_032_260, "Ethereum at go-live: 2 x dst_delivery");
        assert!(home_fee_cap_for(50_000_000, 84_516_130) >= 84_516_130 + KEYS_ONLY_HOME_FEE_MARGIN_MIN);
        assert_eq!(home_fee_cap_for(50_000_000, 1), 50_000_001, "a small delivery cost keeps the 50M margin");
        assert_eq!(home_fee_cap_for(50_000_000, 20_000_000), 70_000_000);
        assert_eq!(home_fee_cap_for(50_000_000, 206_451_612), 412_903_224, "the OFT's DST_DELIVERY_LAMPORTS_MAX");
        assert_eq!(home_fee_cap_for(500_000_000, 84_516_130), 500_000_000, "never below the base");
        assert_eq!(home_fee_cap_for(50_000_000, u64::MAX), u64::MAX, "saturates");

        let mut d = vec![0u8; 912];
        d[..8].copy_from_slice(&GAP_GLOBAL_DISCRIMINATOR);
        for (i, (eid, lamports)) in [(30102u32, 7u64), (0, 0), (30101, 84_516_130)].iter().enumerate() {
            let at = GAP_GLOBAL_DST_DELIVERY_AT + 12 * i;
            d[at..at + 4].copy_from_slice(&eid.to_le_bytes());
            d[at + 4..at + 12].copy_from_slice(&lamports.to_le_bytes());
        }
        assert_eq!(gap_global_dst_delivery(&d, 30101), Some(84_516_130));
        assert_eq!(gap_global_dst_delivery(&d, 30102), Some(7));
        assert_eq!(gap_global_dst_delivery(&d, 30184), Some(0), "not keys-only");
        assert_eq!(gap_global_dst_delivery(&d, 0), Some(0), "an empty slot is no chain");
        assert_eq!(gap_global_dst_delivery(&d[..844], 30101), Some(84_516_130), "the 844-byte (oft-q7) layout");
        assert_eq!(gap_global_dst_delivery(&d[..843], 30101), None, "too short: before oft-q7");
        d[0] ^= 1;
        assert_eq!(gap_global_dst_delivery(&d, 30101), None, "not a GapGlobal");
    }

    /// solana/oft/tests-litesvm/fixtures/gap/receipt-vector.json (item 4, f364d1da): the receipt
    /// `lz_receive` writes for a composed v1 message on a v3 Native store, byte for byte.
    #[test]
    fn the_gap_receipt_vector_reads() {
        let hex = "583801a70ea21f1e01ff605ab3929759ebbec7367c88cda26596fefe7be96d8b1cb2841d58a20da5bb223131313131313131313131313131313131313131313131313131313131313131e87500000700000000000000332ebe8d27cb7323b3a401c1c13b5dd64bccc0e10ecda1c2b5d11a03779a85e56e7a1cdd29b0b78fd13af4c5598feff4ef2a97166e3ca6f2e4fbfccd80505bf150c3000000000000ca24000000000000869e000000000000000000000000000000abababababababababababababababababababababababababababababababab6400000009090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909";
        let d: Vec<u8> = (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect();
        assert_eq!(d.len(), 319);
        let r = read_gap_receipt(&d).expect("a receipt");
        assert_eq!(r.oft_store.to_string(), "7V8MdxE2S8qRfzPpoqsydTGKjK3sKPfchjZmwQC4WPHK");
        assert_eq!(r.to.to_string(), "4So8kA2BCfQD4zhvfYVqhWiyrXBgRPNRuoicJdh9G36c");
        assert_eq!(r.payer.to_string(), "8SFqwqnq4whPhs8icwHA2hQg3hUoN1qrCLK1SBx3WKwe");
        assert_eq!(r.guid, [0x31; 32]);
        assert_eq!((r.src_eid, r.nonce), (30184, 7));
        assert_eq!((r.amount_ld, r.withheld_ld, r.credited_ld), (50_000, 9_418, 40_582));
        assert_eq!(r.compose_from, [0xab; 32]);
        assert_eq!(r.compose_msg, &[9u8; 100][..]);
        // not a receipt: another discriminator, version, a length past the cap or the data
        let mut x = d.clone();
        x[0] ^= 1;
        assert!(read_gap_receipt(&x).is_none());
        let mut x = d.clone();
        x[8] = 2;
        assert!(read_gap_receipt(&x).is_none());
        let mut x = d.clone();
        x[215..219].copy_from_slice(&513u32.to_le_bytes());
        assert!(read_gap_receipt(&x).is_none());
        assert!(read_gap_receipt(&d[..318]).is_none());
        assert!(is_v3_store(&[0u8; 319]) && !is_v3_store(&[0u8; 223]));
        // the pre-L4 receipt: no tail, prepaid 0 and no refund_to
        assert_eq!((r.prepaid, r.refund_to), (0, Pubkey::default()));
        // L4 (owner 2026-10-30): prepaid u64 @219+len and refund_to @227+len appended (+40 B); every
        // earlier field reads the same
        let mut l4 = d.clone();
        l4.extend_from_slice(&3_949_188u64.to_le_bytes());
        l4.extend_from_slice(&[0x5a; 32]);
        assert_eq!(l4.len(), 219 + 100 + 40);
        let r4 = read_gap_receipt(&l4).expect("an L4 receipt");
        assert_eq!((r4.prepaid, r4.refund_to), (3_949_188, Pubkey::new_from_array([0x5a; 32])));
        assert_eq!((r4.credited_ld, r4.compose_from, r4.compose_msg), (40_582, [0xab; 32], &[9u8; 100][..]));
    }

    fn send_data(options: &[u8], compose: Option<&[u8]>) -> Vec<u8> {
        let mut d = OFT_SEND_DISCRIMINATOR.to_vec();
        d.extend_from_slice(&30184u32.to_le_bytes());
        d.extend_from_slice(&[7u8; 32]);
        d.extend_from_slice(&1_000_000u64.to_le_bytes());
        d.extend_from_slice(&900_000u64.to_le_bytes());
        d.extend_from_slice(&(options.len() as u32).to_le_bytes());
        d.extend_from_slice(options);
        match compose {
            None => d.push(0),
            Some(c) => {
                d.push(1);
                d.extend_from_slice(&(c.len() as u32).to_le_bytes());
                d.extend_from_slice(c);
            }
        }
        d.extend_from_slice(&580_000u64.to_le_bytes());
        d.extend_from_slice(&0u64.to_le_bytes());
        d
    }

    #[test]
    fn a_plain_send_is_read_and_anything_more_is_not() {
        let s = read_oft_send(&send_data(&[], None)).unwrap();
        assert_eq!(s, OftSend { dst_eid: 30184, to: [7; 32], amount_ld: 1_000_000, min_amount_ld: 900_000, native_fee: 580_000, lz_token_fee: 0 });
        assert!(read_oft_send(&send_data(&[0, 3], None)).is_none(), "options of the sender's own");
        assert!(read_oft_send(&send_data(&[], Some(b"x"))).is_none(), "a compose message");
        assert!(read_oft_send(&send_data(&[], Some(b""))).is_none(), "an empty compose message");
        let mut d = send_data(&[], None);
        d.push(0);
        assert!(read_oft_send(&d).is_none(), "trailing bytes");
        let mut d = send_data(&[], None);
        d[0] ^= 1;
        assert!(read_oft_send(&d).is_none(), "another instruction");
    }

    #[test]
    fn a_compose_message_and_its_payload() {
        let mut m = 9u64.to_be_bytes().to_vec();
        m.extend_from_slice(&30184u32.to_be_bytes());
        m.extend_from_slice(&123_000u64.to_be_bytes());
        m.extend_from_slice(&left_pad(&[0xab; 20]));
        let mut p = vec![1u8];
        for v in [5_000_000u64, 1_800_000_000, 2_000_000, 900_000] {
            p.extend_from_slice(&v.to_be_bytes());
        }
        m.extend_from_slice(&p);
        let c = read_composed(&m).unwrap();
        assert_eq!((c.nonce, c.src_eid, c.amount_ld), (9, 30184, 123_000));
        assert_eq!(evm_address(&c.from), Some([0xab; 20]));
        let s = read_sell_payload(c.payload).unwrap();
        assert_eq!(s, SellPayload { min_sol_out: 5_000_000, deadline: 1_800_000_000, runner_fee: 2_000_000, home_fee_cap: 900_000 });
        assert!(read_sell_payload(&p[..32]).is_none());
        // L4: + a 16-byte salt reads the same; any other tail is refused
        for (extra, ok) in [(16usize, true), (1, false), (15, false), (17, false), (32, false)] {
            let mut salted = p.clone();
            salted.extend((0..extra).map(|i| 0xC0 ^ i as u8));
            assert_eq!(read_sell_payload(&salted), if ok { Some(s) } else { None }, "+{extra}");
        }
        let mut v2 = p.clone();
        v2[0] = 2;
        assert!(read_sell_payload(&v2).is_none());
        let mut huge = p.clone();
        huge[9..17].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(read_sell_payload(&huge).is_none(), "a deadline past i64");
        assert!(read_composed(&m[..51]).is_none());
        assert!(evm_address(&[0u8; 32]).is_none());
        let mut sol = [1u8; 32];
        assert!(evm_address(&sol).is_none());
        sol[..12].copy_from_slice(&[0; 12]);
        assert!(evm_address(&sol).is_some());
    }

    #[test]
    fn a_mint_authority_and_a_multisig_are_read_as_token_2022_lays_them_out() {
        let mut mint = vec![0u8; 82];
        assert_eq!(read_mint_authority(&mint), None, "no authority");
        mint[0] = 1;
        mint[4..36].copy_from_slice(&[9; 32]);
        assert_eq!(read_mint_authority(&mint), Some(Pubkey::new_from_array([9; 32])));
        assert_eq!(read_mint_authority(&mint[..81]), None);
        let mut ms = vec![0u8; 355];
        ms[0] = 1;
        ms[1] = 2;
        ms[2] = 1;
        ms[3..35].copy_from_slice(&[1; 32]);
        ms[35..67].copy_from_slice(&[2; 32]);
        ms[67..99].copy_from_slice(&[3; 32]); // beyond n: not a signer
        let signers = read_multisig(&ms).unwrap();
        assert_eq!(signers, vec![Pubkey::new_from_array([1; 32]), Pubkey::new_from_array([2; 32])]);
        let mut bad = ms.clone();
        bad[2] = 0;
        assert!(read_multisig(&bad).is_none(), "uninitialized");
        let mut bad = ms.clone();
        bad[1] = 12;
        assert!(read_multisig(&bad).is_none(), "more than eleven");
        assert!(read_multisig(&ms[..354]).is_none());
    }
}
