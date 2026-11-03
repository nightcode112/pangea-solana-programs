// The TEST STACK's identity (feature `test-stack`, never in a default build): the isolated
// splitter the owner's test launches run on, beside the live one and sharing nothing with it.
//
// Public keys only. The keypairs are in `.pangea-keys/test-stack/` (splitter-program-keypair.json,
// admin-keypair.json); this file is written from them by `solana/tools/test-stack-ids.sh`, which a
// fresh pair of keys needs re-run, and nothing else in the program differs between the two builds.
// Everything the program derives -- AUTHORITY, the fee owner, every launch's PDAs -- follows from
// the program id, so a test-stack launch can never touch a live launch's accounts, and the live
// ADMIN has no power over the test stack (nor its ADMIN over the live one).

declare_id!("87xyMm8CCqtCBRKqFU2JCMZ4F9vZctB2LXtLb7t6dhq1");

/// The test stack's admin: lists its launchers, sets its routes and price signer. See `ADMIN`.
pub const ADMIN: Pubkey = pubkey!("3d75Up71ScbFCHP3zcydYkQTYP6dc9f6wZD2XYQ35f5r");

/// `PDA(["native"])`'s canonical bump under this program id (`fees::NATIVE_BUMP`, which a claim
/// uses instead of a search; `fees::tests::the_native_transit_bump_is_the_canonical_one` pins it).
pub const TEST_STACK_NATIVE_BUMP: u8 = 252;
