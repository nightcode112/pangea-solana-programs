// The PriceLog's unit tests (pricelog.rs `mod tests`): the ring, the merge rule, consumed-entry
// pricing (owner (B)), k per entry and the writer rewards (owner (A)).
use super::*;

fn fresh() -> Vec<u8> {
    let mut d = vec![0u8; LEN];
    init(&mut d, 255, &Pubkey::new_from_array([7; 32]));
    d
}
fn live(p: u128) -> Live {
    Live { usd_up: p + 1, usd_down: p, cls_up: 2 * p + 1, cls_down: 2 * p, sol: 0 }
}
/// usd and cls the same (a stable quote), no rounding gap
fn flat(p: u128) -> Live {
    Live { usd_up: p, usd_down: p, cls_up: p, cls_down: p, sol: 0 }
}
fn by(w: u8, fee: u32) -> Writer {
    Writer { key: [w; 32], fee_ppm: fee }
}
const BY: Writer = Writer { key: [1; 32], fee_ppm: 3_000 };

fn slots(d: &[u8]) -> Vec<u64> {
    order(d).map(|i| u64_at(d, entry(i) + O_SLOT)).collect()
}
fn caps(d: &[u8]) -> Vec<u64> {
    order(d).map(|i| u64_at(d, entry(i) + O_CAP)).collect()
}
fn owed(d: &[u8]) -> Vec<u64> {
    order(d).map(|i| u64_at(d, entry(i) + O_OWED)).collect()
}

const E18: u128 = 1_000_000_000_000_000_000;
/// A pool whose locked depth is exactly $1,000,000 at $1 (6/6 decimals, a stable quote): L = 2^64 * 1e12.
const L_1M: u128 = (1u128 << 64) * 1_000_000_000_000;

/// A send (receive = false) or receive of `amount` LD at live price `p` (E18), flat k `k_ppm`.
fn need(receive: bool, amount: u64, p: u128, k_ppm: u32) -> Need {
    Need {
        receive,
        amount_ld: amount,
        live_usd: p,
        live_cls: p,
        locked_l: L_1M,
        quote_decimals: 6,
        token_decimals: 6,
        k_mode: 0,
        k_flat_ppm: k_ppm,
        k_factor_ppm: 333_333,
        fee_now_ppm: 3_000,
        // no floor in these older cases (1e6 never binds); the floor's own test sets it
        platform_floor_ppm: 1_000_000,
    }
}

// ------------------------------------------------------------------ the ring (as before)

#[test]
fn layout_is_69_entries_of_140_bytes_a_9_slot_reward_table_and_an_8_slot_cover_table() {
    assert_eq!((ENTRIES, ENTRY_LEN, HEADER, ORPHANS, ORPHAN_LEN), (69, 140, 48, 9, 40));
    assert_eq!((ORPHAN_AT, FORFEIT_AT, LEN), (9_708, 10_068, 10_172));
    assert_eq!((COVERS, COVER_LEN, COVER_AT), (8, 12, 10_076));
    assert!(LEN <= 10_240);
    let mut d = fresh();
    write(&mut d, 100, 150, &Live { usd_up: 11, usd_down: 12, cls_up: 13, cls_down: 14, sol: 15 }, &by(9, 2_500));
    let e = entry(0);
    assert_eq!(u64_at(&d, e), 100);
    assert_eq!([u128_at(&d, e + 8), u128_at(&d, e + 24), u128_at(&d, e + 40), u128_at(&d, e + 56), u128_at(&d, e + 72)], [11, 12, 13, 14, 15]);
    assert_eq!((u64_at(&d, e + 88), u64_at(&d, e + 96), u32_at(&d, e + 104)), (0, 0, 2_500));
    assert_eq!(&d[e + 108..e + 140], &[9u8; 32][..]);
    assert_eq!(&d[..8], b"GapPLog3");
    assert_eq!(d[8], 3);
    // a fresh cover table is empty: every destination is granted, into slot 0
    assert!((0..COVERS).all(|j| d[COVER_AT + j * COVER_LEN..COVER_AT + (j + 1) * COVER_LEN] == [0u8; 12]));
    assert_eq!(cover_grant(&d, 30101, 7), Some(0));
    cover_write(&mut d, 0, 30101, 7);
    assert_eq!(&d[COVER_AT..COVER_AT + 4], &30101u32.to_le_bytes());
    assert_eq!(&d[COVER_AT + 4..COVER_AT + 12], &8u64.to_le_bytes());
    // the cover table is outside the entries and the reward table: a full ring of writes leaves it
    for s in 0..2 * ENTRIES as u64 {
        write(&mut d, 1_000 + s, 3, &flat(E18), &BY);
    }
    assert_eq!(cover_last(&d, 30101), 8);
}

// ------------------------------------------------------------------ the cover window (Amendment 6 step 2)

#[test]
fn cover_window_once_per_destination_per_window() {
    let mut d = fresh();
    let w = 2_000_000u64; // slot 300,000,100 at W 150 (gap-vectors coverWindow)
    // two destinations in one window: both get their cover
    let a = cover_grant(&d, 30101, w).expect("ETH, first in the window");
    cover_write(&mut d, a, 30101, w);
    let b = cover_grant(&d, 30184, w).expect("Base, first in the window: its own cover");
    assert_ne!(a, b);
    cover_write(&mut d, b, 30184, w);
    // a second send to the same destination in the same window: no cover
    assert_eq!(cover_grant(&d, 30101, w), None);
    assert_eq!(cover_grant(&d, 30184, w), None);
    assert_eq!((cover_last(&d, 30101), cover_last(&d, 30184)), (w + 1, w + 1));
    // the next window: covered again, in the same slot
    assert_eq!(cover_grant(&d, 30101, w + 1), Some(a));
    // a destination never seen is granted; eid 0 never is
    assert_eq!(cover_last(&d, 30102), 0);
    assert!(cover_grant(&d, 30102, w).is_some());
    assert_eq!(cover_grant(&d, 0, w), None);
    // not written unless the send carries: a grant alone changes nothing
    let before = d.clone();
    let _ = cover_grant(&d, 30110, w);
    assert_eq!(d, before);
}

#[test]
fn a_full_cover_table_reuses_the_oldest_passed_window_and_never_a_current_one() {
    let mut d = fresh();
    // eight destinations, covered in windows 10..17 (eid 40000 + k in window 10 + k)
    for k in 0..COVERS as u32 {
        let j = cover_grant(&d, 40_000 + k, 10 + k as u64).unwrap();
        assert_eq!(j, k as usize, "empty slots first, in order");
        cover_write(&mut d, j, 40_000 + k, 10 + k as u64);
    }
    // a ninth destination in window 17: the oldest passed window (eid 40000, window 10) gives way
    let j = cover_grant(&d, 40_100, 17).unwrap();
    assert_eq!(j, 0);
    cover_write(&mut d, j, 40_100, 17);
    assert_eq!(cover_last(&d, 40_000), 0, "evicted: its window had passed");
    // the evicted destination in a later window is granted as new (the next oldest, 40001 @11)
    assert_eq!(cover_grant(&d, 40_000, 18), Some(1));
    // every slot covered in THIS window: a new destination gets no cover (never a second cover
    // for a destination whose window is current)
    let mut e = fresh();
    for k in 0..COVERS as u32 {
        let j = cover_grant(&e, 50_000 + k, 99).unwrap();
        cover_write(&mut e, j, 50_000 + k, 99);
    }
    assert_eq!(cover_grant(&e, 50_100, 99), None);
    for k in 0..COVERS as u32 {
        assert_eq!(cover_grant(&e, 50_000 + k, 99), None, "spent this window");
        assert_eq!(cover_grant(&e, 50_000 + k, 100), Some(k as usize), "the next window");
    }
    assert!(cover_grant(&e, 50_100, 100).is_some());
}

#[test]
fn current_slot_never_counts_and_same_slot_widens() {
    let mut d = fresh();
    write(&mut d, 100, 150, &live(10), &by(1, 3_000));
    assert_eq!(window(&d, 100, 150).entries, 0);
    write(&mut d, 100, 150, &live(30), &by(2, 2_000));
    write(&mut d, 100, 150, &live(20), &by(3, 4_000));
    let w = window(&d, 101, 150);
    assert_eq!((w.entries, w.usd_min, w.usd_max, w.cls_min, w.cls_max), (1, 11, 30, 21, 60));
    // the first writer stays, the fee is the lowest seen in the slot
    assert_eq!((key_at(&d, entry(0) + O_WRITER), u32_at(&d, entry(0) + O_FEE)), ([1; 32], 2_000));
    assert_eq!(window(&d, 251, 150).entries, 0);
    assert_eq!(window(&d, 250, 150).entries, 1);
}

#[test]
fn zero_never_enters_a_min_and_sol_is_kept() {
    let mut d = fresh();
    write(&mut d, 5, 150, &Live { usd_up: 0, usd_down: 0, cls_up: 9, cls_down: 8, sol: 0 }, &BY);
    write(&mut d, 5, 150, &Live { sol: 200, ..Default::default() }, &BY);
    write(&mut d, 6, 150, &live(4), &BY);
    let w = window(&d, 7, 150);
    assert_eq!((w.entries, w.usd_min, w.usd_max, w.cls_min, w.cls_max, w.sol_min), (2, 5, 4, 9, 8, 200));
}

#[test]
fn a_full_ring_drops_its_oldest_only_outside_the_window() {
    let mut d = fresh();
    for s in 0..200u64 {
        write(&mut d, 1_000 + 2 * s, 10, &live(100 + s as u128), &BY);
    }
    let k = 200 - ENTRIES as u64;
    assert_eq!(slots(&d), (k..200u64).map(|s| 1_000 + 2 * s).collect::<Vec<_>>(), "the last ENTRIES, unmerged");
    let w = window(&d, 1_400, 1_500);
    assert_eq!((w.entries as usize, w.usd_min, w.usd_max), (ENTRIES, 100 + k as u128 + 1, 299));
}

#[test]
fn a_full_ring_merges_its_two_oldest_while_the_oldest_is_in_the_window() {
    let mut d = fresh();
    for s in 0..200u64 {
        write(&mut d, 1_000 + 2 * s, 1_500, &live(100 + s as u128), &by(1, 3_000 - s as u32));
    }
    let sl = slots(&d);
    assert_eq!(sl.len(), ENTRIES);
    let k = 200 - ENTRIES as u64;
    assert_eq!(sl, (k..200u64).map(|s| 1_000 + 2 * s).collect::<Vec<_>>(), "the merged entry takes the newer slot");
    let e = entry(order(&d).next().unwrap());
    assert_eq!((u128_at(&d, e + O_USD_MIN), u128_at(&d, e + O_USD_MAX)), (101, 100 + k as u128));
    assert_eq!((u128_at(&d, e + O_CLS_MIN), u128_at(&d, e + O_CLS_MAX)), (201, 2 * (100 + k as u128)));
    // the merged fee is the lower (the newer writes had lower fees here)
    assert_eq!(u32_at(&d, e + O_FEE), 3_000 - k as u32);
    let w = window(&d, 1_400, 1_500);
    assert_eq!((w.entries as usize, w.usd_min, w.usd_max), (ENTRIES, 101, 299), "the first write still counts");
}

#[test]
fn an_attacker_filling_the_ring_cannot_evict_an_honest_entry_in_the_window() {
    for w in [150u64, 375, 750, 1_500] {
        let mut d = fresh();
        write(&mut d, 1_000, w, &live(10), &by(1, 3_000));
        for now in 1_001..=2_200u64 {
            if now - 1_000 <= w {
                let win = window(&d, now, w);
                assert_eq!(win.usd_min, 11, "W {w}, now {now}: the honest minimum");
                assert_eq!(win.cls_min, 21);
            }
            write(&mut d, now, w, &live(1_000_000), &by(66, 3_000));
        }
        assert_eq!(d[43] as usize, ENTRIES);
    }
}

// ------------------------------------------------------------------ capacity_need_pico

#[test]
fn the_need_is_the_usd_value_over_the_locked_depth() {
    // $1 a token, a $1,000,000 locked depth: 1,000 tokens are 0.1% = 1e9 pico
    assert_eq!(math::locked_depth_dollars_up(L_1M, E18, E18, 6, 6), 1_000_000);
    assert_eq!(math::capacity_need_pico(1_000_000_000, E18, L_1M, 6, 6), 1_000_000_000);
    // against need_usd / D computed apart, over prices, decimals and amounts (D large: the whole-dollar
    // rounding of D is below 1e-6)
    for (qd, td) in [(6u8, 6u8), (9, 6), (6, 9), (9, 9), (6, 18), (18, 6), (8, 9)] {
        for q in [E18 / 1_000, E18 / 3, E18, 7 * E18, 1_000 * E18] {
            let l = L_1M * 1_000_000;
            let usd = q; // a stable quote
            let dep = math::locked_depth_dollars_up(l, usd, q, qd, td) as u128;
            if dep < 1_000_000 || dep == u32::MAX as u128 {
                continue;
            }
            let amount = 10u64.pow(td as u32).saturating_mul(1_000);
            let micro = math::usd_micro_up(amount, usd, td) as u128;
            let want = micro * 1_000_000 / dep;
            let got = math::capacity_need_pico(amount, q, l, qd, td) as u128;
            let tol = want / 100_000 + 2;
            assert!(got + tol >= want && got <= want + tol, "qd {qd} td {td} q {q}: got {got} want {want}");
        }
    }
    // rounding: up; saturating; zeros
    assert_eq!(math::capacity_need_pico(0, E18, L_1M, 6, 6), 0);
    assert_eq!(math::capacity_need_pico(1, E18, 0, 6, 6), u64::MAX);
    assert_eq!(math::capacity_need_pico(1, 0, L_1M, 6, 6), u64::MAX);
    assert_eq!(math::capacity_need_pico(1, E18, L_1M, 6, 6), 1, "1e-6 pico rounds up to 1");
    assert_eq!(math::capacity_need_pico(u64::MAX, u128::MAX / 20, 1, 18, 0), u64::MAX);
    // the cheap test equals the exact need: free >= f exactly when need_met
    for (amount, q, l, qd, td) in [(1_000_000_000u64, E18, L_1M, 6u8, 6u8), (7, E18 / 3, L_1M, 9, 6), (123_456_789, 7 * E18, L_1M / 3, 6, 9), (u64::MAX / 3, 1_000 * E18, L_1M, 18, 6), (5, E18, 3, 0, 18), (999, E18 / 7, L_1M * 9, 8, 9)] {
        let f = math::capacity_need_pico(amount, q, l, qd, td);
        let r = math::need_ratio(amount, l, qd, td).unwrap();
        let root = math::need_root(&r, q).unwrap();
        for free in [0u64, 1, f.saturating_sub(1), f, f.saturating_add(1), u64::MAX - 1] {
            assert_eq!(math::need_met(&r, root, free), f != u64::MAX && free >= f, "{amount} {q} {l} {qd} {td} free {free} f {f}");
        }
    }
    // isqrt's 64-bit path equals the 128-bit one
    for n in [2u128, 3, 4, 15, 16, 17, 1 << 40, (1 << 63) - 1, 1 << 63, u64::MAX as u128, u64::MAX as u128 + 1, 10u128.pow(30)] {
        let s = math::isqrt(n);
        assert!(s * s <= n && (s + 1) * (s + 1) > n, "{n}");
    }
    // a higher price needs more (sqrt): 4x the price, 2x the need
    let a = math::capacity_need_pico(1_000_000_000, E18, L_1M, 6, 6);
    let b = math::capacity_need_pico(1_000_000_000, 4 * E18, L_1M, 6, 6);
    assert_eq!(b, 2 * a);
}

// ------------------------------------------------------------------ consumed-entry pricing (B)

/// k 1,000 ppm and D $1M at $1: every entry covers k * D(P) = $1,000 * sqrt(P), i.e. the need of
/// `amount` LD at price P is amount * sqrt(P) pico (L_1M, 6/6 decimals).
#[test]
fn a_send_consumes_newest_first_and_prices_at_the_consumed_minimum() {
    let mut d = fresh();
    for (s, p) in [(10u64, 100u128), (11, 200), (12, 300)] {
        write(&mut d, s, 150, &flat(p * E18 / 100), &BY);
    }
    let live = 4 * E18;
    // 300 tokens at $3: $900 < k * D($3) = $1,732: one entry
    let p = plan(&d, 13, 150, &need(false, 300_000_000, live, 1_000)).unwrap();
    assert_eq!((p.window.entries, p.window.usd_min, p.window.cls_min), (1, 3 * E18, 3 * E18));
    assert_eq!(takes(&d, &p).len(), 1);
    assert_eq!(takes(&d, &p)[0].0 as usize, 2, "the newest entry first");
    // 700 tokens: at $3, $2,100 > $1,732; two entries, Ps the lower of both ($2): $1,400 <= 2 x $1,414
    let p = plan(&d, 13, 150, &need(false, 700_000_000, live, 1_000)).unwrap();
    assert_eq!((p.window.entries, p.window.usd_min), (2, 2 * E18));
    assert_eq!(takes(&d, &p).iter().map(|t| t.0).collect::<Vec<_>>(), vec![2, 1]);
    // the newest is used first, fully, then the next takes the rest
    let full = 1_000 * PICO_PER_PPM;
    assert_eq!(takes(&d, &p)[0].1, full.min(p.need_pico));
    assert_eq!(takes(&d, &p).iter().map(|t| t.1).sum::<u64>(), p.need_pico);
    // the live price below every entry: Ps is live
    let p = plan(&d, 13, 150, &need(false, 1_000_000, E18 / 2, 1_000)).unwrap();
    assert_eq!(p.window.usd_min, 3 * E18, "the consumed min");
    assert_eq!(super::super::record::min_known(E18 / 2, p.window.usd_min), E18 / 2);
    // more than all three can give: none, nothing written (plan is read-only)
    let before = d.clone();
    assert!(plan(&d, 13, 150, &need(false, 10_000_000_000, live, 1_000)).is_none());
    assert_eq!(d, before);
}

#[test]
fn a_partly_used_entry_keeps_its_remainder_and_used_entries_are_skipped() {
    let mut d = fresh();
    for (s, p) in [(10u64, 1u128), (11, 2), (12, 3)] {
        write(&mut d, s, 150, &flat(p * E18), &BY);
    }
    let full = 1_000 * PICO_PER_PPM;
    // a send of half the newest entry's capacity
    let p = plan(&d, 13, 150, &need(false, 166_666_666, 3 * E18, 1_000)).unwrap();
    apply(&mut d, &p, 166_666_666, 0, 0);
    let used = caps(&d)[2];
    assert!(used > 0 && used < full, "{used}");
    // the next send fills the rest of the newest, then the one before
    let p = plan(&d, 13, 150, &need(false, 600_000_000, 3 * E18, 1_000)).unwrap();
    assert_eq!(takes(&d, &p)[0], (2, full - used), "the newest's remainder first");
    assert_eq!(takes(&d, &p).len(), 2);
    assert!(takes(&d, &p)[1].1 > 0);
    apply(&mut d, &p, 600_000_000, 0, 0);
    assert_eq!(caps(&d)[2], full);
    // the newest is now full: the next send starts at the middle entry and prices there
    let p = plan(&d, 13, 150, &need(false, 1_000, 3 * E18, 1_000)).unwrap();
    assert_eq!(takes(&d, &p)[0].0, 1);
    assert_eq!(p.window.usd_min, 2 * E18);
}

#[test]
fn a_receive_consumes_newest_first_and_prices_at_the_consumed_maximum() {
    let mut d = fresh();
    for (s, p) in [(10u64, 5u128), (11, 4), (12, 3)] {
        write(&mut d, s, 150, &flat(p * E18), &BY);
    }
    // live $2, a small arrival: the newest only, Pd = max(2, 3) = 3
    let p = plan(&d, 13, 150, &need(true, 1_000_000, 2 * E18, 1_000)).unwrap();
    assert_eq!((p.window.entries, p.window.usd_max, p.window.cls_max), (1, 3 * E18, 3 * E18));
    // a larger one: 700 tokens need 700e6 * sqrt(3) > 1e9 at $3, so the next entry too, and Pd
    // rises with it ($4: 700e6 * 2 <= 2e9)
    let p = plan(&d, 13, 150, &need(true, 700_000_000, 2 * E18, 1_000)).unwrap();
    assert_eq!((p.window.entries, p.window.usd_max), (2, 4 * E18));
    assert_eq!(p.need_pico, 1_400_000_000);
    // live 0 (unreadable): never satisfiable, the receive holds
    assert!(plan(&d, 13, 150, &need(true, 1, 0, 1_000)).is_none());
    // more than every entry: none
    assert!(plan(&d, 13, 150, &need(true, 5_000_000_000, 2 * E18, 1_000)).is_none());
}

/// The owner's honest-move scenarios: the price rose 5x (10x) steadily over the window. Newest
/// first prices a send near live; the whole-window minimum would have charged ~80% (~90%).
#[test]
fn honest_5x_and_10x_moves_price_near_live_where_the_window_minimum_charges_80_and_90_percent() {
    for x in [5u128, 10] {
        let mut d = fresh();
        let start = 1_000u64;
        for i in 0..ENTRIES as u64 {
            // E18 .. x * E18 linearly over 70 slots
            let p = E18 + (x - 1) * E18 * i as u128 / (ENTRIES as u128 - 1);
            write(&mut d, start + i, 150, &flat(p), &BY);
        }
        let now = start + ENTRIES as u64;
        let live = x * E18;
        let win = window(&d, now, 150);
        let old_gap_ppm = (live - win.usd_min) * 1_000_000 / live;
        assert!(old_gap_ppm >= (x - 1) * 1_000_000 / x - 1, "the whole window: {old_gap_ppm} ppm");
        // a $1,000 send (one entry at k 0.1% of $1M)
        let amount = (1_000 * 1_000_000 * E18 / live) as u64;
        let p = plan(&d, now, 150, &need(false, amount, live, 1_000)).unwrap();
        let ps = super::super::record::min_known(live, p.window.usd_min);
        let new_gap_ppm = (live - ps) * 1_000_000 / live;
        assert!(new_gap_ppm < 20_000, "{x}x: newest first {new_gap_ppm} ppm vs whole window {old_gap_ppm} ppm");
        assert!(old_gap_ppm > 790_000);
        println!("{x}x honest move: whole-window gap {old_gap_ppm} ppm, newest-first {new_gap_ppm} ppm");
    }
}

/// The cost bound: an attacker pumps the pool for ONE slot and records it; the next send consumes
/// that entry first. Every LD priced at the pumped minimum is covered by the pumped entry, whose
/// capacity is k * D: the attacker's gain is at most k * D * gap per pumped entry. The next send
/// (the entry used up) prices at the honest entries.
#[test]
fn a_single_slot_pumped_entry_gains_at_most_k_times_d_times_the_gap() {
    let k_ppm = 1_000u32;
    let mut d = fresh();
    for i in 0..10u64 {
        write(&mut d, 100 + i, 150, &flat(E18), &by(1, 3_000));
    }
    write(&mut d, 110, 150, &flat(10 * E18), &by(66, 3_000)); // the pump, one slot
    let now = 111;
    let live = 10 * E18; // still pumped at the send
    // the largest send that consumes only the pumped entry: its capacity at the pumped price
    let cap = k_ppm as u64 * PICO_PER_PPM;
    let mut lo = 0u64;
    let mut hi = 10_000_000_000u64;
    while lo < hi {
        let mid = (lo + hi + 1) / 2;
        let p = plan(&d, now, 150, &need(false, mid, live, k_ppm)).unwrap();
        if p.window.entries == 1 { lo = mid } else { hi = mid - 1 }
    }
    let p = plan(&d, now, 150, &need(false, lo, live, k_ppm)).unwrap();
    assert_eq!((p.window.entries, p.window.usd_min), (1, 10 * E18));
    assert!(p.need_pico <= cap);
    // its USD value at the pumped price is at most k * D(pumped) (+ rounding)
    let usd_micro = math::usd_micro_up(lo, 10 * E18, 6) as u128;
    let dep = math::locked_depth_dollars_up(L_1M, 10 * E18, 10 * E18, 6, 6) as u128;
    assert!(usd_micro <= k_ppm as u128 * dep + 1, "{usd_micro} vs {}", k_ppm as u128 * dep);
    // one more LD reaches the honest entries: Ps drops to the honest $1
    let p2 = plan(&d, now, 150, &need(false, lo + 1, live, k_ppm)).unwrap();
    assert_eq!(p2.window.usd_min, E18);
    // after the pumped entry is used up, even a tiny send prices at the honest entries
    apply(&mut d, &p, lo, 0, 0);
    let p3 = plan(&d, now, 150, &need(false, 1, live, k_ppm)).unwrap();
    assert_eq!(p3.window.usd_min, E18);
    // the gain bound in dollars: k * D * gap with gap = 90%
    let gain_bound = k_ppm as u128 * dep * 9 / 10; // micro-dollars
    let gain = usd_micro * 9 / 10;
    assert!(gain <= gain_bound + 1);
}

// ------------------------------------------------------------------ k per entry

#[test]
fn k_mode_0_is_flat_and_k_mode_1_is_the_lower_fee_times_the_factor_floored() {
    let n0 = need(false, 1, E18, 1_000);
    assert_eq!(entry_k_ppm(&n0, 0), 1_000);
    assert_eq!(entry_k_ppm(&n0, 9_999), 1_000);
    let n1 = Need { k_mode: 1, k_factor_ppm: 333_333, fee_now_ppm: 3_000, ..n0 };
    assert_eq!(entry_k_ppm(&n1, 2_500), 833, "floor(2,500 * 333,333 / 1e6)");
    assert_eq!(entry_k_ppm(&n1, 5_000), 999, "the fee now is lower");
    assert_eq!(entry_k_ppm(&n1, 0), 0, "an unreadable fee at record gives no capacity");
    assert_eq!(entry_k_ppm(&Need { fee_now_ppm: 0, ..n1 }, 3_000), 0);
    assert_eq!(entry_k_ppm(&Need { k_factor_ppm: 1_000_000, ..n1 }, 3_000), 3_000);
    // through a plan: entries with k 0 are skipped; the fee-based k is smaller than the flat one
    let mut d = fresh();
    write(&mut d, 10, 150, &flat(E18), &by(1, 0)); // fee unreadable at its write
    write(&mut d, 11, 150, &flat(2 * E18), &by(1, 2_500));
    let p = plan(&d, 12, 150, &Need { amount_ld: 1, live_usd: 3 * E18, live_cls: 3 * E18, ..n1 }).unwrap();
    assert_eq!(takes(&d, &p)[0].0, 1);
    let big = 900_000_000; // $900 at $1: above 0.0833% of $1M
    assert!(plan(&d, 12, 150, &Need { amount_ld: big, live_usd: E18, live_cls: E18, ..n1 }).is_none(), "the fee-0 entry gives nothing");
    assert!(plan(&d, 12, 150, &need(false, big, E18, 1_000)).is_some(), "flat k 0.1% covers it");
}

#[test]
fn k_mode_1_is_capped_at_the_flat_k_maximum_with_a_high_fee_and_factor() {
    // audit I-1: a 50% pool fee x a 100% factor would give k 500,000 ppm (half the locked depth
    // per entry); it is capped at CAPACITY_K_MAX_PPM (100,000 = 10%)
    let n0 = need(false, 1, E18, 1_000);
    let hi = Need { k_mode: 1, k_factor_ppm: 1_000_000, fee_now_ppm: 999_999, ..n0 };
    assert_eq!(entry_k_ppm(&hi, 500_000), crate::gap::state::CAPACITY_K_MAX_PPM);
    assert_eq!(entry_k_ppm(&hi, 999_999), 100_000);
    assert_eq!(entry_k_ppm(&Need { k_factor_ppm: 333_333, ..hi }, 500_000), 100_000, "floor(500,000 * 333,333 / 1e6) = 166,666 -> 100,000");
    assert_eq!(entry_k_ppm(&Need { k_factor_ppm: 200_000, ..hi }, 500_000), 100_000, "exactly the cap");
    assert_eq!(entry_k_ppm(&Need { k_factor_ppm: 199_998, ..hi }, 500_000), 99_999, "below the cap: unchanged");
    // the flat k is capped too (the setter already bounds it; a hand-built Need cannot pass it)
    assert_eq!(entry_k_ppm(&Need { k_flat_ppm: 900_000, ..n0 }, 0), 100_000);
    // through a plan: one entry's capacity is 10% of the locked depth (1e11 pico), not 50%
    let mut d = fresh();
    write(&mut d, 10, 150, &flat(E18), &by(1, 500_000));
    let free_now = free(&d, 11, 150, &hi);
    assert_eq!(free_now, 100_000 * PICO_PER_PPM, "capacity = CAPACITY_K_MAX_PPM * 1e6 pico");
    let p = plan(&d, 11, 150, &Need { amount_ld: 1, live_usd: E18, live_cls: E18, ..hi }).unwrap();
    assert_eq!(takes(&d, &p).len(), 1);
}

#[test]
fn k_mode_1_takes_the_lowest_of_the_entry_fee_the_fee_now_and_the_platform_floor() {
    // step 3 (lead, EVM audit): a creator's own trades get part of the pool fee back, so k_mode 1's
    // fee is capped at the platform floor (default 2,000 ppm)
    let n0 = need(false, 1, E18, 1_000);
    let n = Need { k_mode: 1, k_factor_ppm: 333_333, fee_now_ppm: 10_000, platform_floor_ppm: crate::gap::state::PLATFORM_FLOOR_DEFAULT_PPM, ..n0 };
    assert_eq!(entry_k_ppm(&n, 10_000), 666, "floor(2,000 * 333,333 / 1e6): the floor binds");
    assert_eq!(entry_k_ppm(&n, 1_500), 499, "the entry's fee is lower");
    assert_eq!(entry_k_ppm(&Need { fee_now_ppm: 1_200, ..n }, 10_000), 399, "the fee now is lower");
    // audit s3 I-1 (spec change: these gave 0 before): a read fee never floors k below 100 ppm
    assert_eq!(entry_k_ppm(&Need { platform_floor_ppm: 1, ..n }, 10_000), 100, "floor(1 * 333,333 / 1e6) = 0 -> the 100 ppm minimum");
    assert_eq!(entry_k_ppm(&Need { k_factor_ppm: 1, ..n }, 10_000), 100, "factor 1: floor(2,000 * 1 / 1e6) = 0 -> 100");
    assert_eq!(entry_k_ppm(&Need { platform_floor_ppm: 300, ..n }, 10_000), 100, "floor(300 * 333,333 / 1e6) = 99 -> 100");
    assert_eq!(entry_k_ppm(&Need { platform_floor_ppm: 301, ..n }, 10_000), 100);
    assert_eq!(entry_k_ppm(&Need { platform_floor_ppm: 2_600, ..n }, 10_000), 866, "the highest floor");
    // an unreadable fee still gives none
    assert_eq!(entry_k_ppm(&Need { fee_now_ppm: 0, ..n }, 10_000), 0);
    assert_eq!(entry_k_ppm(&n, 0), 0);
    assert_eq!(entry_k_ppm(&Need { platform_floor_ppm: 1_000_000, ..n }, 10_000), 3_333, "a floor of 1e6 never binds");
    // the 10% cap still applies above it
    assert_eq!(entry_k_ppm(&Need { platform_floor_ppm: 1_000_000, fee_now_ppm: 999_999, k_factor_ppm: 1_000_000, ..n }, 900_000), 100_000);
    // k_mode 0 ignores it
    assert_eq!(entry_k_ppm(&Need { k_mode: 0, platform_floor_ppm: 1, ..n }, 0), 1_000);
    // through a plan: the floor shrinks each entry's capacity (2,000 vs 10,000 ppm fee: 5x fewer)
    let mut d = fresh();
    write(&mut d, 10, 150, &flat(E18), &by(1, 10_000));
    assert_eq!(free(&d, 11, 150, &n), 666 * PICO_PER_PPM);
    assert_eq!(free(&d, 11, 150, &Need { platform_floor_ppm: 1_000_000, ..n }), 3_333 * PICO_PER_PPM);
}

// ------------------------------------------------------------------ rewards (A)

#[test]
fn a_send_owes_each_consumed_writer_its_share_out_of_the_bridge_fee_only() {
    let mut d = fresh();
    for (s, w) in [(10u64, 1u8), (11, 2), (12, 3)] {
        write(&mut d, s, 150, &flat(E18), &by(w, 3_000));
    }
    let amount = 1_500_000_000u64; // $1,500: the newest whole, half of the middle
    let p = plan(&d, 13, 150, &need(false, amount, E18, 1_000)).unwrap();
    assert_eq!(takes(&d, &p).len(), 2);
    let fee = amount / 500; // a 0.2% bridge fee
    let total = apply(&mut d, &p, amount, 1, fee);
    // 1 bp of what each covered: 1,000 tokens -> 100_000 LD, 500 -> 50_000 LD (floors)
    assert_eq!(owed(&d), vec![0, 50_000, 100_000]);
    assert_eq!(total, 150_000);
    assert!(total <= fee);
    assert_eq!(total_owed(&d), 150_000);
    // never more than the bridge fee: a cap of 120,000 pays the newest in full, the next the rest
    let mut d2 = fresh();
    for (s, w) in [(10u64, 1u8), (11, 2), (12, 3)] {
        write(&mut d2, s, 150, &flat(E18), &by(w, 3_000));
    }
    let t2 = apply(&mut d2, &p, amount, 20, 120_000);
    assert_eq!(t2, 120_000);
    assert_eq!(owed(&d2), vec![0, 0, 120_000]);
    // bps 0 (a receive): capacity used, nothing owed
    let mut d3 = fresh();
    for s in [10u64, 11, 12] {
        write(&mut d3, s, 150, &flat(E18), &BY);
    }
    assert_eq!(apply(&mut d3, &p, amount, 0, 0), 0);
    assert_eq!(total_owed(&d3), 0);
    assert_eq!(caps(&d3)[2], 1_000 * PICO_PER_PPM);
}

/// Round 2 B I-3: a receive's own entry has NO writer (NO_WRITER, all zero): a send consuming it owes
/// nobody (the consumed capacity is used, the reward stays in the bridge fee); a real writer in the
/// same slot takes the entry over (and earns from then on); a NO_WRITER write never takes a real
/// writer's entry; nothing NO_WRITER ever reaches the reward table.
#[test]
fn a_receive_entry_earns_no_reward_and_a_same_slot_writer_takes_it_over() {
    let nobody = Writer { key: NO_WRITER, fee_ppm: 3_000 };
    let mut d = fresh();
    write(&mut d, 10, 150, &flat(E18), &by(1, 3_000));
    write(&mut d, 11, 150, &flat(E18), &nobody);
    write(&mut d, 12, 150, &flat(E18), &nobody);
    let amount = 1_500_000_000u64;
    let p = plan(&d, 13, 150, &need(false, amount, E18, 1_000)).unwrap();
    let total = apply(&mut d, &p, amount, 20, u64::MAX);
    assert_eq!(owed(&d), vec![0, 0, 0], "the two NO_WRITER entries covered it: owed to nobody");
    assert_eq!(total, 0);
    assert!(caps(&d)[2] > 0 && caps(&d)[1] > 0, "their capacity is used all the same");
    assert_eq!(total_owed(&d), 0);
    // a real writer in a NO_WRITER entry's slot takes it over ...
    let mut d2 = fresh();
    write(&mut d2, 20, 150, &flat(E18), &nobody);
    write(&mut d2, 20, 150, &flat(E18), &by(9, 3_000));
    let i = order(&d2).last().unwrap();
    assert_eq!(key_at(&d2, entry(i) + O_WRITER), [9u8; 32]);
    // ... and earns on it from then on
    let p2 = plan(&d2, 21, 150, &need(false, 100_000_000, E18, 1_000)).unwrap();
    assert!(apply(&mut d2, &p2, 100_000_000, 1, u64::MAX) > 0);
    // a NO_WRITER write never takes a real writer's entry
    let mut d3 = fresh();
    write(&mut d3, 30, 150, &flat(E18), &by(4, 3_000));
    write(&mut d3, 30, 150, &flat(E18), &nobody);
    let j = order(&d3).last().unwrap();
    assert_eq!(key_at(&d3, entry(j) + O_WRITER), [4u8; 32]);
    // merges of NO_WRITER entries (owed 0) put nothing in the reward table
    let mut d4 = fresh();
    for s in 0..(ENTRIES as u64 + 5) {
        write(&mut d4, 100 + s, 1_500, &flat(E18), &nobody);
    }
    assert!((0..ORPHANS).all(|j| u64_at(&d4, orphan(j) + 32) == 0));
}

#[test]
fn a_claim_takes_only_the_writers_own_owed_once() {
    let mut d = fresh();
    write(&mut d, 10, 150, &flat(E18), &by(1, 3_000));
    write(&mut d, 11, 150, &flat(E18), &by(2, 3_000));
    let p = plan(&d, 12, 150, &need(false, 2_000_000_000, E18, 1_000)).unwrap();
    apply(&mut d, &p, 2_000_000_000, 1, u64::MAX);
    assert_eq!(owed(&d), vec![100_000, 100_000]);
    // writer 2 names both entries: gets entry 1 only
    assert_eq!(take_entry_owed(&mut d, 0, &[2; 32]), 0);
    assert_eq!(take_entry_owed(&mut d, 1, &[2; 32]), 100_000);
    assert_eq!(take_entry_owed(&mut d, 1, &[2; 32]), 0, "no double pay");
    assert_eq!(take_entry_owed(&mut d, 999, &[2; 32]), 0);
    assert_eq!(owed(&d), vec![100_000, 0]);
    assert_eq!(take_entry_owed(&mut d, 0, &[1; 32]), 100_000);
    assert_eq!(total_owed(&d), 0);
}

/// Owed survives a merge (same writer: on the merged entry; another: the reward table) and a drop
/// (the table); the table coalesces per writer; a full table forfeits the smallest; claims take
/// the table slot once. total_owed + forfeited is conserved throughout.
#[test]
fn merge_and_drop_move_owed_to_the_reward_table_and_nothing_is_lost_or_paid_twice() {
    let set_owed = |d: &mut Vec<u8>, i: usize, v: u64| put_u64(d, entry(i) + O_OWED, v);
    // merge, same writer: carried onto the newer entry
    let mut d = fresh();
    for s in 0..ENTRIES as u64 {
        write(&mut d, 10 + s, 1_500, &flat(E18), &by(1, 3_000));
    }
    set_owed(&mut d, 0, 70);
    set_owed(&mut d, 1, 5);
    assert_eq!(write(&mut d, 10 + ENTRIES as u64, 1_500, &flat(E18), &by(1, 3_000)), 0);
    assert_eq!(owed(&d)[0], 75, "merged onto N, same writer");
    assert_eq!(total_owed(&d), 75);
    // merge, another writer: the table
    let mut d = fresh();
    write(&mut d, 10, 1_500, &flat(E18), &by(9, 3_000));
    for s in 1..ENTRIES as u64 {
        write(&mut d, 10 + s, 1_500, &flat(E18), &by(1, 3_000));
    }
    set_owed(&mut d, 0, 70);
    assert_eq!(write(&mut d, 10 + ENTRIES as u64, 1_500, &flat(E18), &by(1, 3_000)), 0);
    assert_eq!(total_owed(&d), 70);
    assert_eq!(take_orphan(&mut d, &[1; 32]), 0, "nobody else's");
    assert_eq!(take_orphan(&mut d, &[9; 32]), 70);
    assert_eq!(take_orphan(&mut d, &[9; 32]), 0, "once");
    // drop (out of the window): the table
    let mut d = fresh();
    write(&mut d, 10, 10, &flat(E18), &by(9, 3_000));
    for s in 1..ENTRIES as u64 {
        write(&mut d, 1_000 + s, 10, &flat(E18), &by(1, 3_000));
    }
    set_owed(&mut d, 0, 33);
    write(&mut d, 2_000, 10, &flat(E18), &by(1, 3_000));
    assert_eq!(slots(&d)[0], 1_001, "dropped");
    assert_eq!(total_owed(&d), 33);
    // the table: coalesced per writer, 9 writers, then the smallest forfeits
    let mut d = fresh();
    for w in 1..=9u8 {
        assert_eq!(orphan_add(&mut d, &[w; 32], 100 * w as u64), 0);
    }
    assert_eq!(orphan_add(&mut d, &[3; 32], 1), 0);
    assert_eq!(total_owed(&d), (1..=9u128).map(|w| 100 * w).sum::<u128>() + 1);
    // a 10th writer owing 150 forfeits the 100 of writer 1
    assert_eq!(orphan_add(&mut d, &[10; 32], 150), 100);
    // through a write: the forfeit is parked until a send, receive or claim folds it
    let mut r = fresh();
    for w in 1..=9u8 {
        orphan_add(&mut r, &[w; 32], 1_000);
    }
    write(&mut r, 10, 10, &flat(E18), &by(20, 3_000));
    for s in 1..ENTRIES as u64 {
        write(&mut r, 1_000 + s, 10, &flat(E18), &by(1, 3_000));
    }
    put_u64(&mut r, entry(0) + O_OWED, 5);
    assert_eq!(write(&mut r, 5_000, 10, &flat(E18), &by(1, 3_000)), 5, "writer 20's 5 forfeits (every slot owes more)");
    assert_eq!(take_forfeit(&mut r), 5);
    assert_eq!(take_forfeit(&mut r), 0, "once");
    assert_eq!(take_orphan(&mut d, &[1; 32]), 0);
    // one owing 50 (less than every slot) forfeits itself
    assert_eq!(orphan_add(&mut d, &[11; 32], 50), 50);
    assert_eq!(take_orphan(&mut d, &[10; 32]), 150);
    assert_eq!(take_orphan(&mut d, &[3; 32]), 301);
    // a freed slot is used again
    assert_eq!(orphan_add(&mut d, &[12; 32], 7), 0);
    assert_eq!(take_orphan(&mut d, &[12; 32]), 7);
}

// ---- the invariants over random write / consume sequences (a seeded LCG; no crate)

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn free(d: &[u8], now: u64, w: u64, n: &Need) -> u64 {
    order(d)
        .map(entry)
        .filter(|e| in_window(u64_at(d, e + O_SLOT), now, w))
        .map(|e| (entry_k_ppm(n, u32_at(d, e + O_FEE)) as u64 * PICO_PER_PPM).saturating_sub(u64_at(d, e + O_CAP)))
        .sum()
}

fn extremes(x: &Window) -> (u128, u128, u128, u128, u128) {
    (x.usd_min, x.usd_max, x.cls_min, x.cls_max, x.sol_min)
}

/// (i) for every slot s in [now - W, now - 1] the window min is <= and the max >= every price
/// written at s; (ii) the current slot never counts; (iii) a write (and its merge) never changes
/// the window's extremes; (iv) a write never adds capacity; (v) owed is conserved: the log's total
/// plus everything forfeited equals everything credited; (vi) a plan's prices lie inside the
/// window's and its takes sum to its need.
#[test]
fn the_merge_and_reward_invariants_hold_over_random_sequences() {
    let mut rng = Lcg(0x5eed_6ea);
    for run in 0..24 {
        let w = [3u64, 10, 69, 70, 71, 375, 750, 1_500][run % 8];
        let mut d = fresh();
        let mut history: Vec<(u64, Live)> = vec![];
        let mut now = 10_000u64;
        let (mut credited, mut forfeited) = (0u128, 0u128);
        for _ in 0..1_100 {
            now += [0, 1, 1, 1, 2, 3, 7, 40][rng.below(8) as usize];
            let p = 1 + rng.below(1_000_000) as u128;
            let mut l = live(p);
            match rng.below(10) {
                0 => l.usd_up = 0,
                1 => l.cls_down = 0,
                2 => l.sol = 1 + rng.below(500) as u128,
                _ => {}
            }
            let n = Need {
                receive: rng.below(2) == 0,
                amount_ld: 1 + rng.below(3_000),
                live_usd: 1 + rng.below(1_000_000) as u128,
                live_cls: 1 + rng.below(1_000_000) as u128,
                locked_l: (1u128 << 64) * 1_000,
                quote_decimals: 6,
                token_decimals: 6,
                k_mode: (run % 2) as u8,
                k_flat_ppm: 50,
                k_factor_ppm: 333_333,
                fee_now_ppm: 2_000 + rng.below(3_000) as u32,
                platform_floor_ppm: 1 + rng.below(6_000) as u32,
            };
            if rng.below(3) == 0 {
                if let Some(pl) = plan(&d, now, w, &n) {
                    let win = window(&d, now, w);
                    assert!(pl.window.entries >= 1 && pl.window.entries <= win.entries);
                    assert!(pl.window.usd_max <= win.usd_max && pl.window.cls_max <= win.cls_max);
                    assert!(pl.window.usd_min == 0 || pl.window.usd_min >= win.usd_min);
                    assert_eq!(takes(&d, &pl).iter().map(|t| t.1).sum::<u64>(), pl.need_pico, "(vi) run {run}");
                    let f0 = free(&d, now, w, &n);
                    let c = apply(&mut d, &pl, n.amount_ld, (rng.below(21)) as u16, rng.below(10));
                    credited += c as u128;
                    assert_eq!(free(&d, now, w, &n), f0 - pl.need_pico);
                }
            }
            let before = window(&d, now, w);
            let cap_before = free(&d, now, w, &n);
            let wr = by(1 + rng.below(12) as u8, 1_000 + rng.below(5_000) as u32);
            forfeited += write(&mut d, now, w, &l, &wr) as u128;
            let after = window(&d, now, w);
            assert_eq!(extremes(&after), extremes(&before), "(ii)/(iii) run {run} W {w} now {now}");
            assert!(free(&d, now, w, &n) <= cap_before, "(iv) run {run}");
            assert_eq!(total_owed(&d) + forfeited, credited, "(v) run {run}");
            if rng.below(50) == 0 {
                // a claim: some writer's entries and table slot
                let who = [1 + rng.below(12) as u8; 32];
                let mut got = take_orphan(&mut d, &who) as u128;
                for i in 0..ENTRIES {
                    got += take_entry_owed(&mut d, i, &who) as u128;
                }
                credited -= got;
                assert_eq!(total_owed(&d) + forfeited, credited, "(v) claim run {run}");
            }
            history.push((now, l));
            for probe in [now, now + 1, now + w / 2, now + w] {
                let win = window(&d, probe, w);
                for (s, h) in history.iter().filter(|(s, _)| in_window(*s, probe, w)) {
                    let (s, h) = (*s, h);
                    for (got, put) in [(win.usd_min, h.usd_up), (win.cls_min, h.cls_up), (win.sol_min, h.sol)] {
                        assert!(put == 0 || (got != 0 && got <= put), "(i) min run {run} W {w} probe {probe} slot {s}");
                    }
                    for (got, put) in [(win.usd_max, h.usd_down), (win.cls_max, h.cls_down)] {
                        assert!(got >= put, "(i) max run {run} W {w} probe {probe} slot {s}");
                    }
                }
            }
            let keep = now.saturating_sub(2 * w + 100);
            history.retain(|(s, _)| *s >= keep);
        }
    }
}

#[test]
fn the_current_slot_and_out_of_window_entries_give_no_capacity() {
    let mut d = fresh();
    write(&mut d, 10, 150, &flat(E18), &BY);
    write(&mut d, 200, 150, &flat(E18), &BY);
    // at 200 the entry of 200 is the current slot and the one of 10 is past W
    assert!(plan(&d, 200, 150, &need(false, 1, E18, 1_000)).is_none());
    assert!(plan(&d, 201, 150, &need(false, 1, E18, 1_000)).is_some());
}
