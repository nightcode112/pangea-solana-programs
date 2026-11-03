//! The shared Solana PriceLog (BRIEF Amendment 4, lead decision 2026-10-30; owner decisions (A)
//! and (B) 2026-10-30): one PDA per v3 store, ["GapPriceLog", store], a ring of 69 written slots
//! plus a 9-slot table of evicted writer rewards and (Amendment 6, step 2) an 8-slot table of the
//! sends' cover windows per destination. Isolated on purpose: everything the send, the receive,
//! `record_price` and the reward claims know of it is in this file.
//!
//! Each entry is one slot: the minimum and maximum, over every write in that slot, of the token's
//! USD price (psUsd) and its pool price in the quote (psClass units), the minimum SOL/USD, the
//! capacity already consumed from it, the writer reward it owes, the pool fee read at the write and
//! the writer. A write records the USER-favoured rounding on each side: the minimum fields take the
//! price rounded UP (they become a send's Ps), the maximum fields the price rounded DOWN (they
//! become a receive's Pd). 0 is "not read" and never enters a min or max.
//!
//! Window: entries with slot in [now - W, now - 1]. The current slot never counts: a write and a
//! read in the same slot cannot be told apart from a same-slot bundle (pump, write, unpump).
//!
//! THE MERGE RULE (audit r1 M-1, lead 2026-10-30): W may be longer than the ring (up to 1500
//! slots), so a full ring never simply drops an entry that is still in the window. A write for a
//! NEW slot `now` into a FULL ring (count = ENTRIES) looks at the oldest entry O:
//!   * O.slot <  now - W (outside the current window): O is dropped.
//!   * O.slot >= now - W (still inside it): O and the next-oldest entry N become ONE entry, at N's
//!     place: slot = N.slot (the newer), each min field = the lower non-zero of O's and N's, each
//!     max field = the higher of both, fee = the lower of both, capacity_used, writer = N's (O's
//!     capacity is dropped). The write then takes O's freed place.
//! Rewards on eviction (owner (A)): an evicted entry's unclaimed owed (merged or dropped) goes to
//! N when N has the same writer (merge only), else to the reward table (`orphan_add`). What a full
//! table forfeits is parked in `forfeit_ld` until the next send, receive or claim (each has the
//! store writable) folds it out of the store's reserved total (`take_forfeit`).
//!
//! CONSUMED-ENTRY PRICING (owner (B), only with GapGlobal.capacity_on; `plan` / `apply`):
//! see docs/v3c-gap-spec.md §8.2, the text the JS mirrors copy.
//!
//! THE COVER WINDOW (Amendment 6 lead decision 1, Solana variant per (store, dst_eid); coordinator
//! 2026-10-30): a send carries a gas cover at most once per destination per window w = floor(slot /
//! W). The log, already writable in every send, keeps one slot per destination: {dst_eid u32,
//! last_cover_window_p1 u64} (p1 = the covered window's index + 1; eid 0 = an empty slot). A send to
//! a destination not in the table takes an empty slot, else the slot whose window is oldest among
//! those whose window has passed (p1 != w + 1); a table whose 8 slots are all covered in THIS
//! window (only reachable with more than 8 destinations) grants nothing -- never a second cover.
//! Only a send that really carries a cover writes its slot (`cover_write`).
//!
//! Layout (raw, little-endian; the program owns the account):
//!   tag [u8; 8] = "GapPLog3" @0 | version u8 = 3 @8 | bump u8 @9 | store @10 | head u8 @42 (the
//!   latest entry) | count u8 @43 (entries in use, <= 69) | pad @44..48 | 69 x entry @48 |
//!   9 x reward slot @9,708 | forfeit_ld u64 @10,068 | 8 x cover slot @10,076 (10,172 B)
//!   entry (140 B): slot u64 @0 | usd_min u128 @8 | usd_max @24 | cls_min @40 | cls_max @56 |
//!   sol_min @72 | capacity_used u64 @88 (pico of the locked depth, 1e-12) | owed_ld u64 @96 |
//!   fee_ppm u32 @104 | writer [u8; 32] @108
//!   reward slot (40 B): writer [u8; 32] @0 | owed_ld u64 @32 (0 = empty)
//!   cover slot (12 B): dst_eid u32 @0 (0 = empty) | last_cover_window_p1 u64 @4
//! (sol_max of the 112-byte v1 entry is gone: nothing ever read it.)
use super::introspect;
use super::math;
use crate::*;

pub const PRICE_LOG_SEED: &[u8] = b"GapPriceLog";
pub const TAG: [u8; 8] = *b"GapPLog3";
pub const VERSION: u8 = 3;
/// 69 (owner 2026-10-30: 70; one entry gave its 140 B to the cover table, step 2). The log is a
/// PDA, so it can only be created by a CPI to the system
/// program, and an account made or grown inside an instruction may grow by at most
/// MAX_PERMITTED_DATA_INCREASE (10,240 bytes). Safety does not depend on the ring size: the merge
/// rule (module doc) keeps every in-window extreme for any W up to 1500.
pub const ENTRIES: usize = 69;
pub const ENTRY_LEN: usize = 140;
pub const HEADER: usize = 48;
/// The evicted-reward table (owner (A)): one slot per writer, coalesced.
pub const ORPHANS: usize = 9;
pub const ORPHAN_LEN: usize = 40;
pub const ORPHAN_AT: usize = HEADER + ENTRIES * ENTRY_LEN;
/// Forfeited rewards not yet taken out of the store's reserved total.
pub const FORFEIT_AT: usize = ORPHAN_AT + ORPHANS * ORPHAN_LEN;
/// The cover window table (Amendment 6 step 2): one slot per destination eid.
pub const COVERS: usize = 8;
pub const COVER_LEN: usize = 12;
pub const COVER_AT: usize = FORFEIT_AT + 8;
pub const LEN: usize = COVER_AT + COVERS * COVER_LEN;
// head and count are u8
const _: () = assert!(ENTRIES >= 3 && ENTRIES <= 255);
// one-instruction creation (init_gap_price_log): MAX_PERMITTED_DATA_INCREASE
const _: () = assert!(LEN <= 10_240);
const _: () = assert!(LEN == 10_172);
const _: () = assert!(HEADER + ENTRIES * ENTRY_LEN == 9_708);
// four EVM peers and a spare, at least (coordinator 2026-10-30)
const _: () = assert!(COVERS >= 5);

const O_SLOT: usize = 0;
const O_USD_MIN: usize = 8;
const O_USD_MAX: usize = 24;
const O_CLS_MIN: usize = 40;
const O_CLS_MAX: usize = 56;
const O_SOL_MIN: usize = 72;
const O_CAP: usize = 88;
const O_OWED: usize = 96;
const O_FEE: usize = 104;
const O_WRITER: usize = 108;
const _: () = assert!(O_WRITER + 32 == ENTRY_LEN);

/// One ppm of the locked depth in capacity units (pico: 1e-12 of the depth).
pub const PICO_PER_PPM: u64 = 1_000_000;

pub fn address(program_id: &Pubkey, store: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[PRICE_LOG_SEED, store.as_ref()], program_id)
}

fn u32_at(d: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(d[at..at + 4].try_into().unwrap())
}
fn u64_at(d: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(d[at..at + 8].try_into().unwrap())
}
fn u128_at(d: &[u8], at: usize) -> u128 {
    u128::from_le_bytes(d[at..at + 16].try_into().unwrap())
}
fn put_u32(d: &mut [u8], at: usize, v: u32) {
    d[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn put_u64(d: &mut [u8], at: usize, v: u64) {
    d[at..at + 8].copy_from_slice(&v.to_le_bytes());
}
fn put_u128(d: &mut [u8], at: usize, v: u128) {
    d[at..at + 16].copy_from_slice(&v.to_le_bytes());
}
fn key_at(d: &[u8], at: usize) -> [u8; 32] {
    d[at..at + 32].try_into().unwrap()
}
fn entry(i: usize) -> usize {
    HEADER + i * ENTRY_LEN
}
fn orphan(j: usize) -> usize {
    ORPHAN_AT + j * ORPHAN_LEN
}

/// What one write records, read live in the writing instruction. 0 = not read.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Live {
    pub usd_up: u128,
    pub usd_down: u128,
    pub cls_up: u128,
    pub cls_down: u128,
    /// SOL/USD rounded down (only `record_price` reads the wSOL route).
    pub sol: u128,
}

/// The writer of an entry that earns no reward (round 2 B I-3): a receive's own write. All-zero
/// is never a signer, so nobody could ever claim what such an entry were owed; `apply` owes it
/// nothing instead, and a later write in the same slot by a real signer takes the entry over.
pub const NO_WRITER: [u8; 32] = [0u8; 32];

/// Who wrote, and the pool's flat fee read in the writing instruction (0 = unreadable).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Writer {
    pub key: [u8; 32],
    pub fee_ppm: u32,
}

/// The window's extremes (or, with capacity on, the consumed entries'), 0 where no entry has the
/// field.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Window {
    pub entries: u32,
    pub usd_min: u128,
    pub usd_max: u128,
    pub cls_min: u128,
    pub cls_max: u128,
    pub sol_min: u128,
}

/// The store's PriceLog as passed: Ok(true) when it is the PDA and initialised, Ok(false) when the
/// PDA exists only as an address (not created yet), Err(PriceLogMismatch) for anything else.
pub fn open(info: &AccountInfo, store: &Pubkey, program_id: &Pubkey) -> Result<bool> {
    if info.owner != program_id {
        // not created yet: only the PDA itself is "the store's PriceLog, missing"
        require_keys_eq!(*info.key, address(program_id, store).0, OFTError::PriceLogMismatch);
        return Ok(false);
    }
    let d = info.try_borrow_data()?;
    require!(d.len() == LEN && d[..8] == TAG && d[8] == VERSION && d[10..42] == store.to_bytes(), OFTError::PriceLogMismatch);
    // the bump written at creation (the canonical one): one hash, not a search
    let key = Pubkey::create_program_address(&[PRICE_LOG_SEED, store.as_ref(), &[d[9]]], program_id).map_err(|_| error!(OFTError::PriceLogMismatch))?;
    require_keys_eq!(*info.key, key, OFTError::PriceLogMismatch);
    Ok(true)
}

/// At most ONE PriceLog write per transaction: refuse when another top-level instruction lists the
/// log (the caller's own instruction, or the executor's `execute` around it, is the one allowed).
pub fn refuse_second_write(ixs: &AccountInfo, log: &Pubkey) -> Result<()> {
    let d = ixs.try_borrow_data()?;
    let other = introspect::listed_by_another(&d, &log.to_bytes()).ok_or(OFTError::GapAccountMismatch)?;
    require!(!other, OFTError::OneLogWritePerTx);
    Ok(())
}

fn in_window(slot: u64, now: u64, w: u64) -> bool {
    slot < now && slot >= now.saturating_sub(w)
}

/// The in-use entries, oldest first.
fn order(d: &[u8]) -> impl Iterator<Item = usize> + Clone {
    let count = (d[43] as usize).min(ENTRIES);
    let head = d[42] as usize % ENTRIES;
    let first = (head + ENTRIES + 1 - count) % ENTRIES;
    (0..count).map(move |k| (first + k) % ENTRIES)
}

/// The in-use entries, newest first (from `head` backward): the consumption order.
fn newest_first(d: &[u8]) -> impl Iterator<Item = usize> {
    let count = (d[43] as usize).min(ENTRIES);
    let head = d[42] as usize % ENTRIES;
    (0..count).map(move |k| (head + ENTRIES - k) % ENTRIES)
}

pub fn lower(a: u128, b: u128) -> u128 {
    if a == 0 { b } else if b == 0 { a } else { a.min(b) }
}

/// The window over [now - w, now - 1].
pub fn window(d: &[u8], now: u64, w: u64) -> Window {
    let mut out = Window::default();
    for i in order(d) {
        let e = entry(i);
        if !in_window(u64_at(d, e + O_SLOT), now, w) {
            continue;
        }
        out.entries += 1;
        out.usd_min = lower(out.usd_min, u128_at(d, e + O_USD_MIN));
        out.usd_max = out.usd_max.max(u128_at(d, e + O_USD_MAX));
        out.cls_min = lower(out.cls_min, u128_at(d, e + O_CLS_MIN));
        out.cls_max = out.cls_max.max(u128_at(d, e + O_CLS_MAX));
        out.sol_min = lower(out.sol_min, u128_at(d, e + O_SOL_MIN));
    }
    out
}

// ------------------------------------------------------------------ writer rewards (owner (A))

/// Credit `owed` to `writer` in the reward table: its own slot (coalesced), else an empty one,
/// else the slot owing the least is forfeited if it owes less than `owed` (and takes this one),
/// else `owed` itself is forfeited. Returns what is forfeited (back to the bridge-fee accrual: the
/// caller lowers the store's reserved total by it).
pub fn orphan_add(d: &mut [u8], writer: &[u8; 32], owed: u64) -> u64 {
    if owed == 0 {
        return 0;
    }
    let mut empty = None;
    let mut least: Option<(usize, u64)> = None;
    for j in 0..ORPHANS {
        let o = orphan(j);
        let v = u64_at(d, o + 32);
        if v == 0 {
            empty = empty.or(Some(j));
            continue;
        }
        if key_at(d, o) == *writer {
            put_u64(d, o + 32, v.saturating_add(owed));
            return 0;
        }
        if least.map_or(true, |(_, m)| v < m) {
            least = Some((j, v));
        }
    }
    let (j, lost) = match (empty, least) {
        (Some(j), _) => (j, 0),
        (None, Some((j, m))) if m < owed => (j, m),
        _ => return owed,
    };
    let o = orphan(j);
    d[o..o + 32].copy_from_slice(writer);
    put_u64(d, o + 32, owed);
    lost
}

/// The owed of entry `i` if `writer` wrote it, zeroed (claim). Any index; others give 0.
pub fn take_entry_owed(d: &mut [u8], i: usize, writer: &[u8; 32]) -> u64 {
    if i >= ENTRIES {
        return 0;
    }
    let e = entry(i);
    let v = u64_at(d, e + O_OWED);
    if v == 0 || key_at(d, e + O_WRITER) != *writer {
        return 0;
    }
    put_u64(d, e + O_OWED, 0);
    v
}

/// `writer`'s reward-table slot, zeroed (claim / settle).
pub fn take_orphan(d: &mut [u8], writer: &[u8; 32]) -> u64 {
    for j in 0..ORPHANS {
        let o = orphan(j);
        let v = u64_at(d, o + 32);
        if v != 0 && key_at(d, o) == *writer {
            d[o..o + ORPHAN_LEN].fill(0);
            return v;
        }
    }
    0
}

/// The forfeits parked since the last fold, zeroed: the caller lowers the store's reserved total by
/// it (a send, a receive, a claim).
pub fn take_forfeit(d: &mut [u8]) -> u64 {
    let v = u64_at(d, FORFEIT_AT);
    put_u64(d, FORFEIT_AT, 0);
    v
}

/// Everything the log owes (entries + reward table): with the parked forfeits and the ledgers'
/// owed, the store's reserved total (tests check the identity).
pub fn total_owed(d: &[u8]) -> u128 {
    let e: u128 = (0..ENTRIES).map(|i| u64_at(d, entry(i) + O_OWED) as u128).sum();
    let o: u128 = (0..ORPHANS).map(|j| u64_at(d, orphan(j) + 32) as u128).sum();
    e + o
}

// ------------------------------------------------------------------ the cover window (Amendment 6)

fn cover(j: usize) -> usize {
    COVER_AT + j * COVER_LEN
}

/// `dst_eid`'s last covered window + 1 (0 = never covered, or not in the table).
pub fn cover_last(d: &[u8], dst_eid: u32) -> u64 {
    if dst_eid == 0 {
        return 0;
    }
    (0..COVERS).map(cover).find(|o| u32_at(d, *o) == dst_eid).map_or(0, |o| u64_at(d, o + 4))
}

/// The slot a cover for `dst_eid` in window `w` would be recorded in, or None when the send may
/// not carry one: its own slot already holds this window (the window's cover is spent), or no
/// slot is free (every other slot's window is this one). eid 0 is never a destination (it marks an
/// empty slot), so it is never granted.
pub fn cover_grant(d: &[u8], dst_eid: u32, w: u64) -> Option<usize> {
    if dst_eid == 0 {
        return None;
    }
    let now_p1 = w.saturating_add(1);
    let mut empty = None;
    let mut stale: Option<(usize, u64)> = None;
    for j in 0..COVERS {
        let o = cover(j);
        let eid = u32_at(d, o);
        let p1 = u64_at(d, o + 4);
        if eid == dst_eid {
            return super::math::cover_granted(p1, w).then_some(j);
        }
        if eid == 0 {
            empty = empty.or(Some(j));
        } else if p1 != now_p1 && stale.map_or(true, |(_, m)| p1 < m) {
            stale = Some((j, p1));
        }
    }
    empty.or(stale.map(|(j, _)| j))
}

/// Record that a send to `dst_eid` carried its window `w`'s cover, in slot `j` (`cover_grant`).
pub fn cover_write(d: &mut [u8], j: usize, dst_eid: u32, w: u64) {
    let o = cover(j);
    put_u32(d, o, dst_eid);
    put_u64(d, o + 4, w.saturating_add(1));
}

// ------------------------------------------------------------------ writes

/// The merge rule (module doc): entry `older` folds into entry `newer`, which keeps its slot,
/// writer and capacity_used; mins take the lower non-zero, maxes the higher, fee the lower. O's
/// owed goes to N (same writer) or the reward table; returns what the table forfeited.
fn merge_into(d: &mut [u8], older: usize, newer: usize) -> u64 {
    let (o, n) = (entry(older), entry(newer));
    for f in [O_USD_MIN, O_CLS_MIN, O_SOL_MIN] {
        let v = lower(u128_at(d, n + f), u128_at(d, o + f));
        put_u128(d, n + f, v);
    }
    for f in [O_USD_MAX, O_CLS_MAX] {
        let v = u128_at(d, n + f).max(u128_at(d, o + f));
        put_u128(d, n + f, v);
    }
    let fee = u32_at(d, n + O_FEE).min(u32_at(d, o + O_FEE));
    put_u32(d, n + O_FEE, fee);
    let owed = u64_at(d, o + O_OWED);
    if owed == 0 {
        return 0;
    }
    put_u64(d, o + O_OWED, 0);
    if key_at(d, o + O_WRITER) == key_at(d, n + O_WRITER) {
        let v = u64_at(d, n + O_OWED).saturating_add(owed);
        put_u64(d, n + O_OWED, v);
        0
    } else {
        let w = key_at(d, o + O_WRITER);
        orphan_add(d, &w, owed)
    }
}

/// Record `live` in the entry of slot `now`, `w` the window W in use: a new entry (its writer and
/// fee `by`) or, for a second write in the same slot, its min and max widened and its fee lowered
/// (the first writer stays, unless it is NO_WRITER: then this writer takes the entry). A full
/// ring drops its oldest entry only when that entry is outside
/// [now - w, now - 1]; otherwise the two oldest merge first (module doc). Returns the reward the
/// table forfeited, which is also added to the parked `forfeit_ld` (`take_forfeit`).
pub fn write(d: &mut [u8], now: u64, w: u64, live: &Live, by: &Writer) -> u64 {
    let count = d[43] as usize;
    let head = d[42] as usize % ENTRIES;
    let same = count > 0 && u64_at(d, entry(head) + O_SLOT) == now;
    let i = if same { head } else if count == 0 { 0 } else { (head + 1) % ENTRIES };
    let e = entry(i);
    let mut lost = 0u64;
    if same {
        let fee = u32_at(d, e + O_FEE).min(by.fee_ppm);
        put_u32(d, e + O_FEE, fee);
        // round 2 B I-3: an entry a receive opened (no writer) goes to the first real writer of its
        // slot; it owes nothing yet (apply never rewards NO_WRITER), so nothing moves with it
        if key_at(d, e + O_WRITER) == NO_WRITER && by.key != NO_WRITER {
            d[e + O_WRITER..e + O_WRITER + 32].copy_from_slice(&by.key);
        }
    } else {
        if count >= ENTRIES {
            // i is the oldest entry of a full ring: never drop it while it is in the window
            if in_window(u64_at(d, e + O_SLOT), now, w) {
                lost = merge_into(d, i, (i + 1) % ENTRIES);
            } else {
                let owed = u64_at(d, e + O_OWED);
                let wr = key_at(d, e + O_WRITER);
                lost = orphan_add(d, &wr, owed);
            }
        }
        d[e..e + ENTRY_LEN].fill(0);
        put_u64(d, e + O_SLOT, now);
        put_u32(d, e + O_FEE, by.fee_ppm);
        d[e + O_WRITER..e + O_WRITER + 32].copy_from_slice(&by.key);
        d[42] = i as u8;
        d[43] = (count + 1).min(ENTRIES) as u8;
    }
    let mins = [(O_USD_MIN, live.usd_up), (O_CLS_MIN, live.cls_up), (O_SOL_MIN, live.sol)];
    for (o, v) in mins {
        let cur = u128_at(d, e + o);
        put_u128(d, e + o, lower(cur, v));
    }
    let maxes = [(O_USD_MAX, live.usd_down), (O_CLS_MAX, live.cls_down)];
    for (o, v) in maxes {
        let cur = u128_at(d, e + o);
        put_u128(d, e + o, cur.max(v));
    }
    if lost > 0 {
        let v = u64_at(d, FORFEIT_AT).saturating_add(lost);
        put_u64(d, FORFEIT_AT, v);
    }
    lost
}

// ------------------------------------------------------------------ consumed-entry pricing (B)

/// What one send or receive asks of the log (capacity on).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Need {
    /// false: a send (Ps from the consumed minimums), true: a receive (Pd from the maximums).
    pub receive: bool,
    pub amount_ld: u64,
    /// The live prices of this instruction: the send's rounded up, the receive's rounded down.
    pub live_usd: u128,
    pub live_cls: u128,
    pub locked_l: u128,
    pub quote_decimals: u8,
    pub token_decimals: u8,
    /// 0: every entry gives k_flat_ppm; 1: min(entry fee, fee_now) * k_factor_ppm / 1e6, floored.
    pub k_mode: u8,
    pub k_flat_ppm: u32,
    pub k_factor_ppm: u32,
    pub fee_now_ppm: u32,
    /// Step 3: k_mode 1's fee is min(entry fee, fee now, this) (GapGlobal.platform_floor_ppm).
    pub platform_floor_ppm: u32,
}

/// The consumption: the consumed entries' extremes (as a Window), the capacity f taken (pico) and
/// how many entries it consumed. No per-entry list (no heap): `apply` / `takes` walk the same
/// entries again, newest first, filling f; the log must not change in between.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Plan {
    pub window: Window,
    pub need_pico: u64,
    pub consumed: u32,
    pub now: u64,
    pub w: u64,
    pub need: Need,
}

/// Each consumed entry (ring index) and its take, newest first: f filled entry by entry with each
/// one's unused capacity (the last may be partial, later ones 0).
pub fn walk(d: &[u8], p: &Plan, mut f: impl FnMut(usize, u64)) {
    let mut left = p.need_pico;
    let mut k = 0u32;
    for i in newest_first(d) {
        if k == p.consumed {
            break;
        }
        let e = entry(i);
        if !in_window(u64_at(d, e + O_SLOT), p.now, p.w) {
            continue;
        }
        let cap = entry_k_ppm(&p.need, u32_at(d, e + O_FEE)) as u64 * PICO_PER_PPM;
        let free = cap.saturating_sub(u64_at(d, e + O_CAP));
        if free == 0 {
            continue;
        }
        let take = free.min(left);
        left -= take;
        k += 1;
        f(i, take);
    }
}

/// `walk` as a list (tests, and anyone reading a plan).
pub fn takes(d: &[u8], p: &Plan) -> Vec<(u8, u64)> {
    let mut v = vec![];
    walk(d, p, |i, t| v.push((i as u8, t)));
    v
}

/// An entry's capacity in pico of the locked depth: k_ppm * 1e6. Both modes are capped at
/// CAPACITY_K_MAX_PPM (10% of the locked depth per entry; audit I-1: k_mode 1's fee x factor can
/// reach 99.9%, far above the bound set_gap_capacity_k enforces on the flat k).
pub fn entry_k_ppm(n: &Need, fee_at_record: u32) -> u32 {
    let k = if n.k_mode == 1 {
        // step 3: never above the platform floor (a creator's pool-fee rebate, GapGlobal docs)
        let fee = fee_at_record.min(n.fee_now_ppm).min(n.platform_floor_ppm);
        if fee == 0 {
            // an unreadable fee (at the entry's write or now) gives no capacity
            return 0;
        }
        // audit s3 I-1: never below the flat k's minimum, so a small factor x floor cannot floor
        // every entry to 0 (which would hold every capacity-on arrival)
        ((fee as u64 * n.k_factor_ppm as u64 / 1_000_000) as u32).max(crate::gap::state::CAPACITY_K_MIN_PPM)
    } else {
        n.k_flat_ppm
    };
    k.min(crate::gap::state::CAPACITY_K_MAX_PPM)
}

/// min(a, b), 0 when either is 0 (the send's side).
fn min_known(a: u128, b: u128) -> u128 {
    if a == 0 || b == 0 { 0 } else { a.min(b) }
}
/// max(live, window), 0 when live is 0 (the receive's side).
fn higher_known(live: u128, window: u128) -> u128 {
    if live == 0 { 0 } else { live.max(window) }
}

/// Owner (B), docs/v3c-gap-spec.md §8.2: walk the in-window entries newest first, skipping those
/// with no unused capacity; after each, the running price P (send: min(live, the consumed
/// minimums); receive: max(live, the consumed maximums)) gives the need f(P) =
/// math::capacity_need_pico; stop at the first entry where the consumed entries' unused capacity
/// reaches f. None (the send refuses GapNeedRecords, the receive holds) when no prefix does.
#[inline(never)]
pub fn plan(d: &[u8], now: u64, w: u64, n: &Need) -> Option<Plan> {
    let mut win = Window::default();
    let mut free_sum: u64 = 0;
    // the price-free part of the need, once; per entry only a root (when the price moved) and two
    // wide multiplications (math::need_met), the exact f once at the end
    let ratio = math::need_ratio(n.amount_ld, n.locked_l, n.quote_decimals, n.token_decimals)?;
    let mut last_q: Option<u128> = None;
    let mut root: Option<u128> = None;
    for i in newest_first(d) {
        let e = entry(i);
        if !in_window(u64_at(d, e + O_SLOT), now, w) {
            continue;
        }
        let cap = entry_k_ppm(n, u32_at(d, e + O_FEE)) as u64 * PICO_PER_PPM;
        let free = cap.saturating_sub(u64_at(d, e + O_CAP));
        if free == 0 {
            continue;
        }
        win.entries += 1;
        win.usd_min = lower(win.usd_min, u128_at(d, e + O_USD_MIN));
        win.usd_max = win.usd_max.max(u128_at(d, e + O_USD_MAX));
        win.cls_min = lower(win.cls_min, u128_at(d, e + O_CLS_MIN));
        win.cls_max = win.cls_max.max(u128_at(d, e + O_CLS_MAX));
        free_sum = free_sum.saturating_add(free);
        let q = if n.receive { higher_known(n.live_cls, win.cls_max) } else { min_known(n.live_cls, win.cls_min) };
        // f only changes with the running quote price
        if last_q != Some(q) {
            root = math::need_root(&ratio, q);
            last_q = Some(q);
        }
        let met = root.map_or(false, |r| math::need_met(&ratio, r, free_sum));
        let f = if met { math::capacity_need_pico(n.amount_ld, q, n.locked_l, n.quote_decimals, n.token_decimals) } else { u64::MAX };
        if met && f != u64::MAX && free_sum >= f {
            return Some(Plan { window: win, need_pico: f, consumed: win.entries, now, w, need: *n });
        }
    }
    None
}

/// Apply `p`: each consumed entry's capacity_used grows by its take, and (send only, bps > 0) its
/// writer is owed floor(covered * bps / 10,000) with covered = floor(amount * take / f), each
/// capped so the total never passes `fee_cap` (the bridge fee this send collected). Returns the
/// total owed added.
#[inline(never)]
pub fn apply(d: &mut [u8], p: &Plan, amount_ld: u64, reward_bps: u16, fee_cap: u64) -> u64 {
    // (index, take) newest first; at most ENTRIES, on the stack
    let mut list = [(0u8, 0u64); ENTRIES];
    let mut n = 0usize;
    walk(d, p, |i, t| {
        list[n] = (i as u8, t);
        n += 1;
    });
    let mut left = fee_cap;
    let mut total = 0u64;
    for (i, take) in list[..n].iter() {
        let e = entry(*i as usize);
        let used = u64_at(d, e + O_CAP).saturating_add(*take);
        put_u64(d, e + O_CAP, used);
        // round 2 B I-3: a receive's entry (NO_WRITER) earns no reward: nobody could claim it
        if reward_bps == 0 || p.need_pico == 0 || left == 0 || key_at(d, e + O_WRITER) == NO_WRITER {
            continue;
        }
        let covered = (amount_ld as u128 * *take as u128 / p.need_pico as u128) as u64;
        let r = ((covered as u128 * reward_bps as u128 / 10_000) as u64).min(left);
        if r == 0 {
            continue;
        }
        left -= r;
        total += r;
        let owed = u64_at(d, e + O_OWED).saturating_add(r);
        put_u64(d, e + O_OWED, owed);
    }
    total
}

/// A fresh log's header.
pub fn init(d: &mut [u8], bump: u8, store: &Pubkey) {
    d.fill(0);
    d[..8].copy_from_slice(&TAG);
    d[8] = VERSION;
    d[9] = bump;
    d[10..42].copy_from_slice(store.as_ref());
}

#[cfg(test)]
#[path = "pricelog_tests.rs"]
mod tests;
