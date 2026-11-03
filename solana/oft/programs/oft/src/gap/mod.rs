//! The v3 gap fee (docs/v3-gap-fee-spec.md). `math` is frozen; the accounts, the DAMM v2 reader and
//! the receive/send logic are work item 4 (`state`, `pool`, `introspect`, `engine`).
pub mod math;
pub mod engine;
pub mod introspect;
pub mod pool;
pub mod pricelog;
pub mod record;
pub mod state;
pub mod prepay;
// stocks-d (v3.1, owner D3): Raydium CLMM / Orca Whirlpool route hops, off by default.
#[cfg(feature = "stock-hops")]
pub mod hops;
// stocks-d (v3.1, MAIN Q93): the stock-route re-anchor keeper, off by default.
#[cfg(feature = "stock-hops")]
pub mod keeper;
