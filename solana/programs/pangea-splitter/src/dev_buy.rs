//! # The creator's first buy, inside the launch
//!
//! A creator who pays the launch fee on Solana may pay more than the fee. Whatever their payment
//! holds above the fee the launch names (`LaunchArgs::launch_fee`) is their "dev buy": in the
//! same instruction that opens the pool, that SOL is swapped for the new token through the pool
//! -- a real Meteora swap, the first trade the pool ever sees, paying the pool's fee like any
//! other -- and the tokens are the creator's when the transaction lands. Nobody can trade in
//! between, because there is no between.
//!
//! ## A dev buy never stops a launch
//!
//! The launcher simulates a launch and then sends it, and in between a payer can change their
//! payment: top it up, close their wrapped-SOL account. A launch transaction that lands and FAILS
//! is the worst outcome there is -- it publishes the launch's seed, after which a few lamports
//! sent to the addresses the seed derives block that launch for good (`MINT_SEED`). So nothing
//! about a dev buy is a reason for `launch` to fail. What it holds is decided before anything is
//! created (`check_dev_buy`), as one of four outcomes (`Excess`):
//!
//!   * **No excess.** The payment holds the fee, or there is no payment. Nothing to decide.
//!   * **The payment is not the creator's.** A third party may pay somebody's launch fee, and
//!     cannot buy tokens with their money for anybody: so there is no dev buy, and the WHOLE
//!     payment settles as the fee, as it did before dev buys existed. The excess stays in the
//!     payment's account and `withdraw_fee` takes it with the rest. (A fee of 10,000,000
//!     lamports paid as 10,000,001 by a friend settles 10,000,001.) This used to be refused
//!     (`DevBuyNotTheCreators`), which let that friend fail the launch by topping their payment
//!     up by a lamport after the launcher had simulated it.
//!   * **The creator's own payment, and the buy can be made.** It is -- for at most what the
//!     creator was QUOTED, which the launch names (`LaunchArgs::expected_dev_buy`): the buy is
//!     `min(excess, expected_dev_buy)`, and whatever the creator paid above that goes back to
//!     their wallet in the same instruction, as below. A creator who tops their payment up after
//!     the launcher has looked is not bought tokens nobody quoted -- and the platform does not
//!     pay, for a buy it never quoted, the rent of the token account that buy would need. A launch that names no dev buy (zero) hands back the creator's whole excess.
//!   * **The creator's own payment, and the buy cannot be made** -- their wrapped-SOL account is
//!     missing or is not a token account, or the pool cannot sell that much, or the amount cannot
//!     be priced, or the quote asset is not wrapped SOL (the only asset a payment's lamports turn
//!     into by being counted; the launcher refuses any other, and this holds it as well). Then
//!     ALL of the creator's excess goes straight back to the creator's wallet, in the same
//!     instruction, moved directly out of the payment's account (this program's) into `creator`:
//!     no instruction, no account the transaction did not already name. The payment settles
//!     holding exactly the fee, and the launch is exactly a launch without a dev buy -- the
//!     slice's account is closed (or, if the pool's rounding left a few base units in it, is the
//!     creator's), the creator's wrapped-SOL account is made if nothing is at its address. (A fee of 10,000,000 paid as 510,000,000 by a creator with no
//!     wrapped-SOL account: 500,000,000 back to their wallet, 10,000,000 settled.) These used to
//!     be refused by name (`DevBuyNeedsQuoteAccount`, `DevBuyMoreThanThePoolSells`,
//!     `DevBuyCannotBeQuoted`).
//!
//!     One case of that does not return: a wallet with NOTHING in it, handed less than its
//!     rent-exempt minimum (890,880 lamports for a plain wallet), would be left rent-paying, which
//!     the runtime refuses -- and that would fail the launch. A creator who has emptied their
//!     wallet entirely and paid a dev buy smaller than that has it settled as the fee, as a
//!     third party's excess is. Any wallet holding anything at all can take any amount back.
//!
//! The error variants named above stay in `SplitterError`, where they are, so that no number
//! after them moves; `launch` no longer raises any of them.
//!
//! What is STILL fatal, by design: the swap itself returning less than `dev_buy_minimum`. That is
//! Meteora's arithmetic having changed under this program, it is found by the swap call failing,
//! and a call that fails cannot be undone part of the way through an instruction -- the launch
//! fails with it, and the payment is whole. See "the amount out is asserted".
//!
//! ## A dev buy in an allowlisted asset
//!
//! A launch paired against an asset the admin has allowlisted (`quote`) -- a tokenized stock, say
//! -- cannot buy with the payment's lamports: it would have to swap SOL for the asset first, and
//! a route inside the launch is room the launch does not have. So the creator does that in their
//! own payment transaction, the way stonks.fun and embercurve do: they pay the SOL fee as with any
//! pair, swap SOL for the asset into their own associated account through whatever route Jupiter
//! finds, and approve this program's AUTHORITY as that account's delegate for the dev buy. The
//! launch then swaps `min(expected_dev_buy, the approval, the balance)` out of that account --
//! which is the launch's `creator_token_b` already, so the buy names no new account, and is one
//! instruction shorter than the wrapped-SOL buy (no lamports to count). The same 0.1% floor.
//!
//! Every reason it cannot be made -- no approval, a short one, nothing held, the account frozen,
//! nothing quoted, a payment that is not the creator's own, more than the pool sells -- means no
//! dev buy and nothing refused: the asset simply stays in the creator's account. The payment's
//! SOL above the fee goes back to the creator, as above. A PAUSED asset is different: no pool can
//! be opened against it at all, so the launch is refused by name before anything is created
//! (`QuoteAssetUnavailable`), and the launcher refuses to send it in the first place.
//!
//! ## Which it was, read off the chain
//!
//! Nothing is logged for it (a launch's log is cut off long before it ends). What the launch did
//! with a payment's excess is in what it leaves behind:
//!
//!   * the launch's record says whether a dev buy was made (`LaunchRecord::dev_buy_made`). The
//!     slice's account (`TOKEN_A_SEED`) does not: it is the creator's when a buy was made, and
//!     also when none was but the pool's rounding left a few base units in it, and closed
//!     otherwise -- never the splitter's;
//!   * the settled payment's `amount` is the fee the launch named when the excess was bought
//!     with or returned, and the whole payment when it was settled as the fee.
//!
//! So, for a payment that held more than the fee: `dev_buy_made` -- MADE, for
//! `min(excess, expected_dev_buy)` lamports, and the rest of the creator's excess returned;
//! not made and `amount` equal to the fee named -- RETURNED to the creator's wallet, all of it;
//! `amount` above the fee named -- that much KEPT as the fee (a third party's excess, or what an
//! empty wallet could not hold). In lamports, for the creator's payment:
//! `bought + returned + (amount - fee) = excess`, with `bought` the first figure when
//! `dev_buy_made` and 0 otherwise.
//!
//! ## Whose money, and whose tokens
//!
//! The SOL is the creator's own and nobody else's. `pay_fee` keeps each payer's lamports in an
//! account only that payer's key derives and only that payer can add to, so a payment's excess
//! is its payer's by construction -- and `launch` makes a dev buy only when that payer IS the
//! creator. The platform funds no part of it: the lamports leave the payment's account, pass
//! through the launcher's wrapped-SOL account (which Meteora draws a swap's input from, and which
//! ends the instruction holding what it held before), and are in the pool's vault. What stays in
//! the payment's account is the fee, and that is all `withdraw_fee` can then take.
//!
//! There is no cap. A swap takes the whole amount it is given, at whatever price the curve
//! reaches: nothing is left over, so nothing can be stranded or kept. At the price and supply
//! the platform launches at, no amount a u64 of lamports can express runs the range out. For a
//! launch priced so low that one could, the buy is not made and its lamports go back to the
//! creator, as above.
//!
//! ## Where the tokens land
//!
//! In the account the slice itself was minted into (`TOKEN_A_SEED`), which then becomes the
//! CREATOR's. It is the one account for the launched token that
//! exists in the transaction: the mint did not exist a moment earlier and its address was a
//! secret, so nobody could have made the creator an account for it beforehand, and making one
//! here costs instructions the transaction does not have (two for a plain account, five for an
//! associated one, with two to spare). The creator's wallet owns that account outright -- any
//! wallet lists it under the mint -- and one ordinary transfer moves the tokens to their
//! associated account.
//!
//! ## Why the creator's wrapped-SOL account must already exist
//!
//! A transaction runs at most 64 instructions, counting every call a program makes. A launch
//! runs 56; the dev buy is five more (one to have the token program count the lamports, four
//! for the swap); a priority fee is one. That is 62. Creating the creator's wrapped-SOL account
//! -- which a launch does when it is missing -- is five, and 67 does not land. So a launch makes
//! the dev buy only when the account is already there, and when it is not, returns the dev
//! buy's lamports to the creator and makes the account instead: the five instructions of the
//! buy for the five of the account, the same 62 as any launch that makes it. The creator's own
//! payment transaction makes it, so that the buy is made: they are signing that anyway.
//!
//! ## The amount out is asserted, not hoped for -- to within a tenth of a percent
//!
//! It is the first trade on a pool this instruction has just opened, at a price and with a
//! liquidity this instruction chose, so what it returns is arithmetic: `buy_output` below, which
//! is Meteora's own calculation step for step, and which today it returns to the base unit.
//!
//! The swap's minimum is that figure less a tenth of a percent (`dev_buy_minimum`), not the
//! figure itself. This program is final and Meteora is not: were Meteora ever to round its swap
//! one unit differently, an exact minimum would make every dev-buy launch fail from that day on.
//! With the tolerance the creator's worst case is 0.1% of what their buy should have returned;
//! a pool that returns less than that -- the wrong pool, the wrong price, a changed curve --
//! fails the swap and with it the launch, and the payment is whole. This is the one way a dev
//! buy can still fail a launch, and it is deliberate: it is not something a payer can bring
//! about between a simulation and a landing, only a change in Meteora's program, and a buy that
//! has started cannot be backed out of half-way through an instruction.

/// What a launch does with what a payment holds above the fee it names. Decided before anything
/// is created (`check_dev_buy`); see "a dev buy never stops a launch".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Excess {
    /// The payment holds exactly the fee, or there is no payment.
    Nothing,
    /// The creator's own excess: `buy` lamports of it swapped for at least `least` tokens (no buy
    /// when `buy` is 0), and `back` lamports -- the rest of it -- handed back to their wallet.
    Creators { buy: u64, least: u64, back: u64 },
    /// A payment that is not the creator's: no dev buy, and all of it is the fee.
    Fee,
}

/// The tolerance on a dev buy's output: `1 / DEV_BUY_TOLERANCE` of it, a tenth of a percent.
pub const DEV_BUY_TOLERANCE: u64 = 1_000;

/// The least a dev buy quoted at `expected` tokens may return: `expected - expected / 1000`.
///
/// The tolerance is rounded DOWN, so it is never more than a tenth of a percent of `expected`:
/// under a thousand base units it is nothing, and the minimum is the quote itself.
pub fn dev_buy_minimum(expected: u64) -> u64 {
    expected - expected / DEV_BUY_TOLERANCE
}

/// Meteora's fee denominator: a pool's fee is `fee_bps * 100_000` over this.
pub const CP_AMM_FEE_DENOMINATOR: u128 = 1_000_000_000;

/// Meteora `swap`: sha256("global:swap")[..8].
pub const CP_AMM_SWAP_DISCRIMINATOR: [u8; 8] = [248, 198, 158, 145, 225, 117, 135, 200];

/// Meteora `swap(amount_in, minimum_amount_out)`.
pub fn cp_amm_swap_data(amount_in: u64, minimum_amount_out: u64) -> Vec<u8> {
    let mut d = Vec::with_capacity(24);
    d.extend_from_slice(&CP_AMM_SWAP_DISCRIMINATOR);
    d.extend_from_slice(&amount_in.to_le_bytes());
    d.extend_from_slice(&minimum_amount_out.to_le_bytes());
    d
}

/// What a buy returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuyOutput {
    /// Base units of the launched token the buyer receives.
    pub tokens: u64,
    /// The pool's fee, in the quote asset, taken out of what the buyer paid.
    pub fee: u64,
    /// Where the pool's square-root price is afterwards.
    pub sqrt_price: u128,
}

/// What `lamports` of the quote asset buys from a Meteora DAMM v2 pool of `liquidity` standing
/// at `sqrt_price`, charging a flat `fee_bps` taken in the quote asset. None if the arithmetic
/// leaves the range these types hold, which no real launch's does.
///
/// Step for step what cp-amm does for an exact-input swap of token B for token A with its fee
/// on the input:
///
///   fee        = ceil(lamports * numerator / 1e9)                 the fee, rounded UP
///   in         = lamports - fee
///   next price = sqrt_price + floor(in * 2^128 / liquidity)       rounded DOWN
///   tokens     = floor(liquidity * (next - sqrt_price) / (sqrt_price * next))   rounded DOWN
///
/// It is not taken on trust. `tests/stress_support` checks it against the real program on every
/// buy in every suite -- thousands of them, at every price a pool reaches -- and `tests/dev_buy.rs`
/// against the first trade of a launch.
pub fn buy_output(liquidity: u128, sqrt_price: u128, fee_bps: u16, lamports: u64) -> Option<BuyOutput> {
    if liquidity == 0 || sqrt_price == 0 {
        return None;
    }
    let numerator = fee_bps as u128 * 100_000;
    let fee = (lamports as u128 * numerator).checked_add(CP_AMM_FEE_DENOMINATOR - 1)? / CP_AMM_FEE_DENOMINATOR;
    let fee = u64::try_from(fee).ok()?;
    let amount_in = lamports.checked_sub(fee)?;
    let next = sqrt_price.checked_add(shl128_div(amount_in, liquidity)?)?;
    let tokens = mul_div_floor(liquidity, next - sqrt_price, sqrt_price, next)?;
    Some(BuyOutput { tokens, fee, sqrt_price: next })
}

/// floor(amount * 2^128 / divisor), when it fits 128 bits.
pub fn shl128_div(amount: u64, divisor: u128) -> Option<u128> {
    if divisor == 0 {
        return None;
    }
    // amount * 2^64 fits a u128. Divide that, then bring down the other 64 zero bits one at a
    // time, keeping the remainder in 256 bits' worth of care: it is below the divisor, so
    // doubling it overflows a u128 only when the divisor is above 2^127 -- handled with the carry.
    let high = (amount as u128) << 64;
    let mut quotient = high / divisor;
    let mut remainder = high % divisor;
    for _ in 0..64 {
        let carry = remainder >> 127;
        remainder <<= 1;
        quotient = quotient.checked_mul(2)?;
        if carry == 1 || remainder >= divisor {
            remainder = remainder.wrapping_sub(divisor);
            quotient |= 1;
        }
    }
    Some(quotient)
}

/// A 256-bit number as two halves, most significant first.
type U256 = (u128, u128);

fn mul_128(a: u128, b: u128) -> U256 {
    const M: u128 = u64::MAX as u128;
    let (a0, a1, b0, b1) = (a & M, a >> 64, b & M, b >> 64);
    let (p00, p01, p10, p11) = (a0 * b0, a0 * b1, a1 * b0, a1 * b1);
    let mid = (p00 >> 64) + (p01 & M) + (p10 & M);
    let low = (p00 & M) | (mid << 64);
    let high = p11 + (p01 >> 64) + (p10 >> 64) + (mid >> 64);
    (high, low)
}

fn ge(a: U256, b: U256) -> bool {
    a.0 > b.0 || (a.0 == b.0 && a.1 >= b.1)
}

fn sub(a: U256, b: U256) -> U256 {
    let (low, borrow) = a.1.overflowing_sub(b.1);
    (a.0.wrapping_sub(b.0).wrapping_sub(borrow as u128), low)
}

/// floor(a * b / (c * d)), when the quotient fits 64 bits and the divisor 255.
///
/// The product and the divisor are each up to 256 bits, which is why this is written out: a
/// position's liquidity is over a hundred bits and a price difference can be nearly as many.
pub fn mul_div_floor(a: u128, b: u128, c: u128, d: u128) -> Option<u64> {
    let n = mul_128(a, b);
    let divisor = mul_128(c, d);
    if divisor == (0, 0) || divisor.0 >> 127 != 0 {
        return None;
    }
    // The quotient fits 64 bits exactly when the product's top 192 bits are below the divisor.
    let mut r: U256 = (n.0 >> 64, (n.0 << 64) | (n.1 >> 64));
    if ge(r, divisor) {
        return None;
    }
    let low = n.1 as u64;
    let mut q: u64 = 0;
    for bit in (0..64).rev() {
        // r < divisor < 2^255, so doubling it and adding a bit stays within 256.
        r = ((r.0 << 1) | (r.1 >> 127), (r.1 << 1) | ((low >> bit) & 1) as u128);
        if ge(r, divisor) {
            r = sub(r, divisor);
            q |= 1 << bit;
        }
    }
    Some(q)
}

/// The liquidity a single-sided position of `amount` of the launched token holds, from
/// `sqrt_price` to the top of the range `sqrt_max`: Meteora's own
/// `getLiquidityDeltaFromAmountAForConcentratedLiquidity`, which is what its SDK hands a launcher
///
///   liquidity = floor(amount * sqrt_price * sqrt_max / (sqrt_max - sqrt_price))
///
/// It used to be an argument of `launch`, the client's computation of this. It is computed here
/// now, which is sixteen bytes a launch transaction no longer carries -- and one value fewer a
/// launcher states and the program merely checks the consequences of. None when the result does
/// not fit 128 bits, or the prices are not in order; no real launch's does either.
pub fn single_sided_liquidity(amount: u64, sqrt_price: u128, sqrt_max: u128) -> Option<u128> {
    if sqrt_price == 0 || sqrt_price >= sqrt_max {
        return None;
    }
    let d = sqrt_max - sqrt_price;
    // amount * sqrt_price < 2^192: (hi, lo) with hi < 2^64.
    let (hi, lo) = mul_128(amount as u128, sqrt_price);
    // ... * sqrt_max: three 128-bit limbs, most significant first.
    let (h1, l1) = mul_128(lo, sqrt_max);
    let (h2, l2) = mul_128(hi, sqrt_max);
    let (mid, carry) = l2.overflowing_add(h1);
    let top = h2.checked_add(carry as u128)?;
    // A quotient that fits 128 bits needs the top limb empty and the middle below the divisor.
    if top != 0 || mid >= d {
        return None;
    }
    // Long division of (mid, l1) by d, a bit at a time; the remainder stays below d.
    let (mut r, mut q) = (mid, 0u128);
    for bit in (0..128).rev() {
        let carry = r >> 127;
        r = (r << 1) | ((l1 >> bit) & 1);
        if carry == 1 || r >= d {
            r = r.wrapping_sub(d);
            q |= 1u128 << bit;
        }
    }
    Some(q)
}

// There is no event. A launch's log is cut off at the runtime's 10 kB long before the launch
// ends, so one would never be read; what the buy did is in the transaction itself -- the swap is
// one of its inner instructions, with both amounts -- and in the balances it left.

#[cfg(test)]
mod tests {
    use super::*;

    /// A launch as the client computes it: 200M tokens at 9 decimals, opening where tests/launch.rs does.
    const L: u128 = 451_851_103_962_992_085_144_048_000_364_863;
    const P0: u128 = 2_259_255_519_814_896;

    #[test]
    fn the_swap_is_called_with_its_discriminator_and_two_amounts() {
        let d = cp_amm_swap_data(10_000_000_000, 153_488_372_093_026_618);
        assert_eq!(d.len(), 24);
        assert_eq!(&d[..8], &anchor_lang::solana_program::hash::hash(b"global:swap").to_bytes()[..8]);
        assert_eq!(&d[8..16], &[0x00, 0xe4, 0x0b, 0x54, 0x02, 0x00, 0x00, 0x00], "ten SOL, little-endian");
        assert_eq!(u64::from_le_bytes(d[16..24].try_into().unwrap()), 153_488_372_093_026_618);
    }

    /// Figures the real program returned for the first trade on this launch's pool at a 1% fee
    /// (tests/dev_buy.rs measures them again, against Meteora itself, every run).
    #[test]
    fn a_first_buy_returns_what_meteora_returns() {
        for (lamports, tokens) in [
            (0u64, 0u64),
            (1, 0),
            (1_000, 65_999_978_172),
            (100_000_000, 6_389_157_792_836_367),
            (1_000_000_000, 49_624_060_150_376_269),
            (10_000_000_000, 153_488_372_093_026_618),
            (100_000_000_000, 194_117_647_058_828_903),
            (1_000_000_000_000, 199_395_770_392_754_913),
        ] {
            let out = buy_output(L, P0, 100, lamports).unwrap();
            assert_eq!(out.tokens, tokens, "a buy of {lamports} lamports");
            // The fee is a hundredth, rounded up; and a buy that is all fee moves nothing.
            assert_eq!(out.fee as u128, (lamports as u128 + 99) / 100);
            assert_eq!(out.sqrt_price == P0, lamports <= 1);
        }
        assert_eq!(buy_output(L, P0, 100, 10_000_000_000).unwrap().sqrt_price, 9_714_798_735_203_841);
    }

    /// A tenth of a percent, never more: `expected - minimum` is at most `expected / 1000`, and
    /// the minimum is at least 99.9% of the quote at every size.
    #[test]
    fn the_minimum_is_the_quote_less_a_tenth_of_a_percent_and_never_more() {
        for (expected, least) in [
            (0u64, 0u64),
            (1, 1),
            (999, 999),
            (1_000, 999),
            (1_999, 1_998),
            (2_000, 1_998),
            (153_488_372_093_026_618, 153_334_883_720_933_592),
            (u64::MAX, u64::MAX - u64::MAX / 1_000),
        ] {
            assert_eq!(dev_buy_minimum(expected), least, "{expected}");
        }
        let mut x: u64 = 0x2545_F491_4F6C_DD1D;
        for _ in 0..100_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let least = dev_buy_minimum(x) as u128;
            assert!(least <= x as u128 && (x as u128 - least) * 1_000 <= x as u128, "{x}");
            assert!(least * 1_000 >= x as u128 * 999, "{x}: under 99.9%");
        }
    }

    /// The program's liquidity is the SDK's: the launch every test makes (200M tokens at 9
    /// decimals at the opening price the client computes) gives the figure the client used to send.
    #[test]
    fn the_liquidity_is_meteoras_figure() {
        const SLICE: u64 = 200_000_000_000_000_000;
        const MAX: u128 = 79_226_673_521_066_979_257_578_248_091;
        assert_eq!(single_sided_liquidity(SLICE, P0, MAX), Some(L));
        // Against plain arithmetic wherever u128 can hold the product.
        let mut x: u64 = 0x5DEE_CE66_D1CE_4E5B;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..20_000 {
            let (a, p) = ((next() >> 40) as u64, (next() >> 30) as u128 + 1);
            let m = p + (next() >> 20) as u128 + 1;
            let expect = (a as u128).checked_mul(p).and_then(|v| v.checked_mul(m)).map(|n| n / (m - p));
            if let Some(e) = expect {
                assert_eq!(single_sided_liquidity(a, p, m), Some(e), "{a} {p} {m}");
            }
        }
        // And at real magnitudes, checked by multiplying back: q*d <= n < (q+1)*d.
        for _ in 0..20_000 {
            let a = next();
            let p = ((next() as u128) << 40 | next() as u128) % (MAX / 2) + 1;
            let Some(q) = single_sided_liquidity(a, p, MAX) else { continue };
            let d = MAX - p;
            let n = {
                let (hi, lo) = mul_128(a as u128, p);
                let (h1, l1) = mul_128(lo, MAX);
                let (_h2, l2) = mul_128(hi, MAX);
                (l2.wrapping_add(h1), l1)
            };
            let qd = mul_128(q, d);
            assert!(ge(n, qd), "q*d <= n");
            let rest = sub(n, qd);
            assert!(rest.0 == 0 && rest.1 < d, "n - q*d < d");
        }
        // Out of order, or a result over 128 bits: None, never a wrong number.
        assert_eq!(single_sided_liquidity(1, MAX, MAX), None);
        assert_eq!(single_sided_liquidity(1, 0, MAX), None);
        assert_eq!(single_sided_liquidity(u64::MAX, MAX - 1, MAX), None);
    }

    #[test]
    fn the_long_division_is_division() {
        // Against plain u128 arithmetic wherever that can do it.
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..20_000 {
            let (a, b, c, d) = (next() as u128 >> 8, next() as u128 >> 20, (next() as u128 >> 34) + 1, (next() as u128 >> 40) + 1);
            let expect = a * b / (c * d);
            assert_eq!(mul_div_floor(a, b, c, d), u64::try_from(expect).ok(), "{a} * {b} / ({c} * {d})");
            let (amount, divisor) = (next() >> 30, (next() as u128) << 40 | 1);
            // amount * 2^128 / divisor == ((amount * 2^64 / g) * 2^64) ... checked by multiplying back.
            let q = shl128_div(amount, divisor).unwrap();
            let (hi, lo) = mul_128(q, divisor);
            let target: U256 = (amount as u128, 0);
            assert!(ge(target, (hi, lo)), "the quotient is not too large");
            let rest = sub(target, (hi, lo));
            assert!(rest.0 == 0 && rest.1 < divisor, "and the remainder is below the divisor");
        }
        // A divisor above 2^127, where the remainder's doubling carries.
        let big = u128::MAX - 12_345;
        let q = shl128_div(u64::MAX, big).unwrap();
        let (hi, lo) = mul_128(q, big);
        let rest = sub((u64::MAX as u128, 0), (hi, lo));
        assert!(rest.0 == 0 && rest.1 < big);
        // What does not fit is None, not a wrong number.
        assert_eq!(shl128_div(1, 0), None);
        assert_eq!(shl128_div(u64::MAX, 1), None);
        assert_eq!(mul_div_floor(u128::MAX, u128::MAX, 1, 1), None);
        assert_eq!(mul_div_floor(1, 1, 0, 5), None);
        assert_eq!(mul_div_floor(u128::MAX, 2, u128::MAX, 2), Some(1));
        assert_eq!(mul_div_floor(1 << 127, 1 << 60, 1 << 64, 1 << 60), Some(1 << 63));
        assert_eq!(buy_output(0, P0, 100, 5), None);
        assert_eq!(buy_output(L, 0, 100, 5), None);
    }
}
