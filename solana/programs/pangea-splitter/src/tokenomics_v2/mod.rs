//! Tokenomics v2 on Solana: holder rewards and up to 10 payout wallets per chain.
//!
//! The account `TokenomicsV2` at `PDA(["tokenomics-v2", configHash])`, configHash the one hash
//! every chain computes (`config`). The Solana leg's five shares:
//!
//! | share     | where it goes                                                                       |
//! |-----------|-------------------------------------------------------------------------------------|
//! | burn      | `execute_tokenomics_v2`: bought, sent to the incinerator (v1's run)                 |
//! | buy&hold  | `execute_tokenomics_v2`: bought, sent to the treasury's coin account (v1's buyback) |
//! | liquidity | `execute_tokenomics_v2`: v1's capped add on the account's own locked position       |
//! | wallets   | credited to each wallet at allocation; `pay_tokenomics_wallets` (crank) pays them in |
//! |           | SOL, a wallet may `claim_tokenomics_wallet` at any time; slots hand on two-step      |
//! | holders   | split by reward entry into pots (`holders`): paid to holders by the operator         |
//!
//! Fees arrive as wrapped SOL in the account's vault (`claim_fees_native` -> `fees::tokenomics_vault`),
//! or -- for a launch paired against an allow-listed asset (v2.3, `quote_asset`) -- in that asset,
//! into the account's associated account for it (`claim_fees`).

pub mod config;
pub mod holders;
pub mod quote_asset;
pub mod state;
pub mod vault;

pub use config::*;
pub use holders::*;
pub use quote_asset::*;
pub use state::*;
pub use vault::*;
