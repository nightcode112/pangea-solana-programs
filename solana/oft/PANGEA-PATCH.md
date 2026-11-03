# Pangea's patches to LayerZero's OFT program

Three patches, each as small as it can be. Every LayerZero instruction, account, account layout and
error code is as shipped; new error codes are appended after LayerZero's.

1. `init_tvl` (2026-10-24): one new instruction, for SUPPLY_TOTAL lockbox stores.
2. Small peers (2026-10-27, factory v3 wave 2): a `PeerConfig` is created at its smallest layout
   and grows only when `set_peer_config` writes something longer.
3. The v3c bridge gap fee (2026-10-30, round 2 2026-10-31): v3 stores (`init_oft_v3`, 319 bytes)
   speak codec v3 with the shared PriceLog; live stores are untouched. Spec: `docs/v3c-gap-spec.md`.

# Patch 1: `init_tvl`

Owner decision, 2026-10-24: SUPPLY_TOTAL ("degen mode") launches keep the other chains' share
in an Adapter store's escrow (a lockbox) instead of the shared-minter reserve. LayerZero's program
cannot pre-fund an Adapter. `tvl_ld` starts at 0, so:

- an arrival's `tvl_ld -= amount` overflows (overflow-checks are on, so it reverts), and
- `withdraw_fee` takes anything above `tvl_ld`, so it would sweep the pre-funded escrow as fees.

This patch adds one instruction and changes nothing else. Every LayerZero instruction, account,
layout and error code is as shipped. The new error codes are appended after LayerZero's.

## `init_tvl(tvl_ld)`

Accounts: `payer` (signer, writable; pays the mark's rent), `admin` (signer), `oft_store`
(writable), `token_escrow`, `tvl_mark` (writable, created), `token_program`, `system_program`.

| check | error |
|---|---|
| `admin == oft_store.admin` | `Unauthorized` |
| `oft_store.oft_type == Adapter` | `NotAdapter` |
| `oft_store.tvl_ld == 0` (nothing locked by a `send` yet) | `TvlAlreadySet` |
| `tvl_ld > 0` and `tvl_ld == token_escrow.amount` exactly | `InvalidTvl` |
| `token_escrow` is the store's own escrow, owned by the store | Anchor constraint |
| once per store: `TvlMark` at `PDA(["TvlMark", oft_store])` is created with `init` | Anchor (account in use) |

The `TvlMark` records the admin that signed (`TvlMark { admin }`, 40 bytes). A store's admin can
be handed on afterwards (`set_oft_config` `Admin`), so only the mark's `admin` says who declared
the lock: pangea-cheapest accepts a lockbox store only when it is the splitter's AUTHORITY (audit
round 1, 2026-10-24).

Effect: `oft_store.tvl_ld = tvl_ld`. After that the store behaves exactly like an Adapter that had
locked `tvl_ld` through `send`:

- an arrival releases from the escrow and lowers `tvl_ld`;
- a transfer out locks into it and raises `tvl_ld`;
- `withdraw_fee` can take only `escrow - tvl_ld`, which is the bridge fees.

The store's admin for every Pangea launch is the splitter's `AUTHORITY` PDA. The splitter signs
`init_tvl` in exactly one place, `launch_leg::lock_in_escrow`, inside the launch instruction that
has just created the store.

# Patch 2: small peers

LayerZero's `set_peer_config` creates a peer's record (`PeerConfig`) with `init_if_needed` at
`8 + PeerConfig::INIT_SPACE` = 1,654 bytes: room for 512 + 1,024 bytes of enforced options and
both rate limiters. A Pangea route uses 96 of them (the peer's address and the 22-byte gas floor
for send and for send-and-call), so each route's first bridger paid rent on 1,558 bytes nobody uses.

## The change (two files, nothing else)

- `state/peer_config.rs`: `PEER_CONFIG_MIN_LEN` (52: discriminator, address, two empty option
  blobs, two `None` limiters, `None` fee, bump), `PEER_CONFIG_MAX_LEN` (`8 + INIT_SPACE`, LayerZero's
  1,654), `PeerConfig::space_for(info)` (= `max(data_len, 52)`) and `PeerConfig::serialized_len()`.
- `instructions/set_peer_config.rs`:
  - `space = PeerConfig::space_for(peer)` instead of `8 + PeerConfig::INIT_SPACE`. A new peer is
    created at 52 bytes. An existing peer of any size passes Anchor's `init_if_needed` size check
    as it is (Anchor requires `space == data_len` for an existing account; without this every
    1,654-byte peer made before the upgrade would be refused with `ConstraintSpace`).
  - After the write, `grow`: if the record now serialises to more than the account holds, the
    store's admin pays the rent up to exemption at the new size (`system_program::transfer`) and
    the account is resized. Only ever grows.

Accounts, instruction data, `PeerConfigParam`, the account layout and every error are unchanged,
so LayerZero's SDK, our clients and the splitter's CPIs build exactly the same instructions.

## Why it is safe

| question | answer |
|---|---|
| Which paths write a variable-length field? | Only `set_peer_config`: `EnforcedOptions` (two `Vec<u8>`), `OutboundRateLimit` / `InboundRateLimit` (`None` to `Some` is +32 each), `FeeBps` (`None` to `Some` is +2). `PeerAddress` is fixed. `send` and `lz_receive` only change a limiter's numbers, never whether it is set, so the record never grows there. `init_oft`, `set_oft_config`, `set_pause`, `withdraw_fee`, `init_tvl`, the quotes and `lz_receive_types` never write a peer. |
| Can a write leave the peer below rent exemption? | No: `grow` tops it up to `minimum_balance(new size)` before resizing, and the runtime refuses any instruction that leaves a resized account below it. A peer that had lamports sent to its address before it existed counts them (tested). |
| Who pays? | The store's admin, the signer `set_peer_config` already requires (`has_one = admin`), exactly as it pays the creation today. Nobody else can write a peer, so nobody else can make one grow or be charged for it. For every Pangea store the admin is the splitter's `AUTHORITY`, paid out of what `open_bridge`'s caller lends it. |
| Does it ever accept a write LayerZero's program refuses, or refuse one it accepts? | No. LayerZero's limit is the total serialised size against 1,654 bytes (Anchor fails to write a longer record, `AccountDidNotSerialize`), not a per-blob limit. `grow` refuses past `PEER_CONFIG_MAX_LEN` with the same error. `it_accepts_and_refuses_exactly_what_layerzeros_program_does` runs one sequence of writes against both builds and compares every result and every record. |
| Shrinking? | Not done. Clearing a field leaves the account its size and its rent, and setting it again costs nothing. The bytes after the record are never read. |
| Peers that exist today (1,654 bytes)? | Unchanged: never resized, written and read as before, nothing charged (tested across the upgrade, from both earlier builds). |
| Does a short account deserialise everywhere? | Yes. Anchor's `Account<PeerConfig>` (in `send`, `quote_send`, `quote_oft`, `lz_receive`) reads Borsh from the front and ignores anything after the record. LayerZero's SDK (`@layerzerolabs/oft-v2-solana-sdk`, `fetchPeerConfig` / `deserializePeerConfig`) is a umi struct serializer read from the front; its GPA builder filters by discriminator only, not by data size. Our readers (`solana/client/oft-store.mjs` `decodePeerConfig` / `decodePeerFeeBps`, `bridge.mjs` `decodeEnforcedOptions`, `web/lib/chain/solana-fast-order.mjs` `peerFeeBps`) walk the layout from the front too. The executor and the endpoint never read a peer's data (`lz_receive_types` derives its address only). |
| Compute and transaction size? | Instruction data and accounts are unchanged, so no transaction is a byte longer. A write that grows the peer costs one more inner instruction (the system transfer) and about 2,700 compute units; one that does not grow costs a few hundred (the size check). See the measurements below. |

## Measured

`solana/oft/tests-litesvm` (litesvm 0.1.0), against this build and the two earlier ones:

| | LayerZero / patch 1 | patch 2 |
|---|---|---|
| a new peer (`PeerAddress`) | 1,654 B, 12,402,720 lamports | 52 B, 1,252,800 |
| after `open_bridge`'s gas floor (`EnforcedOptions`, 22 + 22) | 1,654 B, 12,402,720 | 96 B, 1,559,040 (+306,240 paid at the grow) |
| saved per route at 6,960 a byte (the tests' rate) | | 10,843,680 |
| saved per launch, 4 routes | | 43,374,720 (0.0434 SOL) |
| at mainnet's live 5,080 a byte | 9,052,560 a peer | 1,137,920: 7,914,640 a route, 31,658,560 (0.0317 SOL) a launch |
| compute, `PeerAddress` creating the peer | 10,555 | 10,791 |
| compute, `EnforcedOptions` (grows 52 to 96) | 8,341 | 11,014 |

`open_bridge` (the splitter's own tests, run in a scratch copy with this build as its OFT fixture):

| | patch 1 fixture | patch 2 |
|---|---|---|
| instructions, one route (limit 64) | 32 | 33 |
| instructions, two routes in one transaction | 60 | 62 |
| three routes in one transaction | do not fit | still do not fit |
| compute, the two transactions of a 4-route opening | 720,660 / 727,604 | 726,466 / 733,410 (the test's bound: 750,000) |
| transaction bytes | unchanged (`opening_two_routes_fits_in_a_packet_with_the_launchers_table_and_one_without` passes) | |
| rent spent by a 4-route opening (`spent`) | 4 x (35,614,320 + 12,402,720) | 4 x (35,614,320 + 1,559,040) |

With that fixture, `bridge_fee`, `bridge_inbound` and `bridge_adversarial` pass unchanged:
transfers out (`send`, burning, the fee into the escrow), arrivals (`lz_receive`, verified,
minting), round trips, and every refused admin action all run on 96-byte peers. Of `launch.rs`, the
four tests that fail are exactly the pins listed for piece D below; with them updated, all 30 pass.
(`delivery_bot.rs` fails in this checkout with either fixture: it shells out to the node planner,
which needs `solana/client/node_modules`.)

## For the splitter (piece D) and the clients

- The splitter needs no change to work: it calls `set_peer_config` with the same four accounts
  (`AUTHORITY` as admin, writable signer; the peer; the store; the system program) and the same
  data, and `AUTHORITY` already holds the float the grow is paid from (it pays 1,252,800 at the
  creation and 306,240 at the gas floor, 1,559,040 of the 40,000,000 lent; the rest comes back).
- The pins to update in its tests once this build becomes its OFT fixture
  (`tests/fixtures/programs/SNyKy...so`, with fixtures/README.md's sha256 and size line), all
  measured above:
  - `tests/launch.rs`: `PEER_RENT` 12,402,720 to 1,559,040 (this fixes
    `the_bridge_is_opened_two_routes_at_a_time_and_each_is_pinned`,
    `the_rent_the_authority_is_lent_..._comes_back` and
    `a_route_names_five_optional_verifiers_...`); `two_routes_fit_in_a_transaction_and_three_do_not`
    32 to 33 and 60 to 62.
  - `tests/stress_edges.rs:1256` / `:1279`: 60 to 62 and 32 to 33.
  - `tests/delivery_bot.rs:302`: `5_000 + 35_614_320 + 12_402_720` to `... + 1_559_040`.
  - fixtures/README.md: "one route runs 26 instructions, two fit in a transaction at 56 of 64" is
    already stale (32 / 60 with the patch-1 fixture); it becomes 33 / 62.
  - Docs only: `OFT_PEER_SPACE` (src/launch_leg.rs, 1,654) and the `PATHWAY_FLOAT` comment
    (src/bridge.rs: "the peer 12,402,720: 31,340,880"). Neither changes behaviour: the float is the
    caller's argument. The fixture swap is wave 2. It goes with the upgrade, since the fixture is
    meant to be what mainnet runs.
- **After the upgrade, every peer write may need the admin to hold lamports** (the grow's rent).
  `open_bridge` lends `AUTHORITY` a float, so its writes are paid. Any future path that writes a
  peer as `AUTHORITY` (an emergency rate limit, a fee per peer, new options) must lend a float the
  same way, or it fails with insufficient lamports the first time the record grows: a rate limiter
  on a 96-byte peer is +32 bytes (222,720 lamports at 6,960 a byte), both +64, a fee +2.

## Which figure is charged (no switch to flip)

The quote does not trust a constant for this: it asks the chain.
`web/lib/launch/oft-peer-rent.mjs` reads the OFT program's ProgramData account
(`281hiRxx...`, one RPC call, cached 10 minutes; a failed read is retried after 30 s). It charges the
small-peer figure only when the program bytes are exactly the pinned patch-2 build: sha256 and
length in `solana/client/bridge-figures.mjs` `OFT_PATCH2_SHA256` / `OFT_PATCH2_LEN`, with only zeros
after them. Any other build, no account, a failed read, or an unpinned build (`"FILL_IN"`, as now)
gets LayerZero's larger figure. So nothing is ever under-charged, before the upgrade or after a
redeploy.

- Where it is used, which is where the route rent is charged to a launch: `gas.mjs`
  `quoteLaunchFee` (the prepare route and the worker both price through it) passes it to
  `fee-quote.mjs` `priceLaunch` / `openRoutesLamports`. `app/api/launch/open-routes` passes it
  to `openRoutesPrice`. `fee-quote.mjs` stays pure: it takes the figure as an argument, accepts
  only the two known values, and uses the larger when none is given.
- Everything else keeps the larger fixed figure (`PEER_RENT_LAMPORTS` / `OPENING_RENT_LAMPORTS`).
  It over-charges after the upgrade and never under-charges. That covers lazy openings
  (`ROUTE_RENT_LAMPORTS` in the bridge and trade quotes, the delivery bot), the worker's own
  funding check (`script/open-routes.mjs` `RENT_PER_ROUTE_LAMPORTS`) and the arb
  (`script/arb/chains.mjs`). Moving them onto the reader is a follow-up for their owners.

## Upgrade runbook (the owner's; not run by any agent)

Prerequisite: the lockbox release's step 1 (`solana/tools/lockbox-upgrade-oft.sh`, patch 1) is
live. Patch 2 is built on it and its script checks that mainnet runs exactly that build.

1. **Two reproducible builds of the audited commit** (not while a PX run holds
   `px-running.lock`). Check out the commit the audit signed off, then:

       SOLANA_VERSION=4.1.0 bash script/solana-docker-build.sh solana/oft oft OFT_ID=SNyKyiZYU4R54SF9sYLmjCaCUsa1sC6QouNAj3x3Zzf
       mkdir -p solana/target/verified && cp solana/oft/target/deploy/oft.so solana/target/verified/oft-small-peer.so
       sha256sum solana/target/verified/oft-small-peer.so; stat -c %s solana/target/verified/oft-small-peer.so

   Then make a second build that shares nothing with the first (another machine, a fresh clone,
   or `solana-verify build` where it compiles) and check that its sha256 is the same. If the two
   differ, stop. Nothing is pinned from a single build.
2. **Pin it**, in one commit:
   - `EXPECT_COMMIT` (the audited sha), `EXPECT_SHA256` and `EXPECT_SIZE` in
     `solana/oft/tools/small-peer-upgrade-oft.sh`. The script refuses to run until all three are
     written, and when `solana/oft` in the tree differs from that commit's.
   - The same sha256 and size as `OFT_PATCH2_SHA256` / `OFT_PATCH2_LEN` in
     `solana/client/bridge-figures.mjs`, so the quote recognises the build once it is deployed.
     Releasing this before the upgrade is safe: the quote keeps the larger figure until the chain
     runs exactly that build.
3. **Test the pinned binary**: copy it over `target/deploy/oft.so` and run
   `cargo test --manifest-path solana/oft/tests-litesvm/Cargo.toml`. Copy it over the splitter's
   fixture `tests/fixtures/programs/SNyKyiZYU4R54SF9sYLmjCaCUsa1sC6QouNAj3x3Zzf.so` and run the
   splitter's `launch`, `bridge_fee`, `bridge_inbound` and `bridge_adversarial` tests with the
   updated pins (piece D). Then run the mainnet-replay crate on those transactions (fixtures/README.md).
4. **Dry run** on the keys machine: `U=<mainnet RPC> bash solana/oft/tools/small-peer-upgrade-oft.sh`.
   It checks:
   - that mainnet runs the patch-1 build (sha256 a6188594..., 547,136 bytes);
   - the build and the authority (848j...).

   It also says what the upgrade will cost. The build is larger than 547,136 bytes, so the data
   account is extended first, by at least 10,240 bytes (that rent stays with the program). The
   buffer's rent is held until the upgrade and then returned.
5. **Upgrade**: the same with `RUN=1`. It asks before the extension, the buffer and the upgrade,
   and checks the dump after. Never `--final`.
6. **Nothing to flip.** Within 10 minutes the open-routes price and the launch quote read the new
   build and charge the smaller figure. The other readers listed above keep the larger one.
7. **Check**: `/api/launch/open-routes` reports `lamports` = 4 x 27,132,280 + 2,810,000. The
   next opened route's peer is 96 bytes and holds 1,137,920 lamports (`solana account <peer>`).

**No rollback: fix forward.** Redeploying the patch-1 (or LayerZero) build after peers have been
made small would break them. Its `set_peer_config` has `space = 8 + INIT_SPACE`, and Anchor's
`init_if_needed` refuses an existing account of any other size with `ConstraintSpace`. Every peer
made at 52 or 96 bytes would then be unwritable: no new options, no rate limit, no fee. `send`
and `lz_receive` would keep working. If patch 2 has a bug, the fix is a corrected patch-2 build,
deployed the same way.

## Building

    cd solana/oft
    OFT_ID=SNyKyiZYU4R54SF9sYLmjCaCUsa1sC6QouNAj3x3Zzf cargo build-sbf
    cargo test --manifest-path tests-litesvm/Cargo.toml

Check the id in the binary before deploying (DEPLOYMENTS.md, "THE TRAP IN BUILDING IT"). Patch 1's
upgrade script is `solana/tools/lockbox-upgrade-oft.sh` (step 1 of 3, `lockbox-upgrade-lib.sh`);
patch 2's is `solana/oft/tools/small-peer-upgrade-oft.sh` on the same library. Both are dry-run by
default.

# Patch 3: the v3c gap fee

The reference is `docs/v3c-gap-spec.md` (codec §1, formula §2, receive §3, source §4, Solana §8.1-§8.9)
and the program's own docs and tests; this section is the map. The 2026-10-28 patch 3 (codec v1/v2,
GapSendRecord, no capacity) is gone from the program; its text is in git history only.

## What changes, and what does not

- **Live stores (223 bytes) run LayerZero's code unchanged.** `send`, `lz_receive`,
  `lz_receive_types` and `quote_send` branch on the store's size (`gap::state::is_v3_store`, at least
  319 bytes) before anything else; below the branch the live path is byte for byte patch 2's
  (`live_stores_behave_exactly_as_before`, `peer_size`). Patch 2 (small peers) is inside this build.
- **v3 stores** (`init_oft_v3`): the send carries a 96-byte codec v3 header (Ps from the PriceLog's
  consumed entries, the bridge fee, the gas cover; `send_v3.rs`); the receive (`lz_receive_v3.rs`,
  `gap/engine.rs`) withholds the gap fee (§2) and burns it, writes the live price into the PriceLog, and
  HOLDS (a retriable revert, nothing consumed) whenever a price cannot be read, the window has no
  entry, or the window's free capacity does not cover the arrival.
- **The shared PriceLog** (`gap/pricelog.rs`, PDA ["GapPriceLog", store], 10,172 B): 69 slot entries,
  capacity per entry (MANDATORY: `set_gap_capacity(false)` is CapacityMandatory), writer rewards (1 bp of
  what an entry covered on a send, out of the bridge fee; `claim_writer_rewards` /
  `settle_writer_rewards`), the per-destination cover table. `record_price` is permissionless.
- **Who runs a receive's price path (R1', round 2)**: directly under LayerZero's executor `execute`
  (CPI, gated to its executor keys), a GapGlobal delivery key at the top level with its mandatory Pd
  floor (priced at max(Pd, floor)), or `land_held_receive` (admin; a delivery key for an oversized
  arrival). LayerZero's top-level pre_execute / lz_receive / post_execute sandwich is REFUSED: on
  mainnet any key can build it (verified on a mainnet fork, §8.9). The escape, the refund marker and
  SEED_NO_POOL stay permissionless.
- New instructions: `init_oft_v3`, `init_gap_global` (signer: the upgrade authority),
  `init_gap_price_log`, `record_price`, `propose_gap_admin` / `accept_gap_admin`, `set_gap_*` (the
  registrar, margin, gas cover, cost max, stables, classes, composers, seeders, delivery keys, window,
  capacity / capacity k / k_mode / k_factor, platform floor, reward bps, escape), `set_gap_route` / `clear_gap_route`,
  `set_gap_pool`, `close_gap_receipt`, `return_expired_compose`, `land_held_receive`,
  `claim_writer_rewards`, `settle_writer_rewards`; L4: `set_gap_receipt_refund`, `sweep_gap_prepay`, `set_gap_return_gas`.
- New accounts: GapGlobal (912 B since oft-fix: 760 B at L4, 844 B at oft-q7 with the delivery block, then
  ata_lamports @844 and the cosigners @848; `migrate_gap_global` brings an older one to 912), GapRoute, GapReceipt (259 B + call since L4: + prepaid, refund_to),
  the GapPrepay PDA (L4, the sender's native drop; system-owned), the PriceLog, GapReward ledgers (90 B), the store tail (223..319) and the v3 LzReceiveTypes PDA (104 B).
- Error codes 6012..6068 appended after LayerZero's (6068 BadReturnGas, L4) (errors.rs; the JS table is
  solana/client/price-log.mjs `OFT_GAP_ERRORS`). Events emit_cpi plus one `sol_log_data` line per
  send ("gap-send"), receive ("gap"), hold ("gap-hold") and record ("gap-price"); a co-signed send
  adds "gap-cosign".
- Owner M-1 (oft-m1): the v3 send's trailing tail may be 57 bytes (flags bit 1 COSIGNED + the
  co-signer's Ps ceilings) with ONE extra remaining account, the co-signer, after the PriceLog; signed by
  one of the dedicated GapGlobal.cosigners (oft-fix L-2: never the admin, pending admin, registrar or a
  delivery key; `set_gap_cosigners` refuses them) with the escape off, it is priced at the whole window's
  minimum and consumes no capacity (docs/v3c-gap-spec.md §8.10). LayerZero's own send layout is unchanged.

## Measured (tests-litesvm, litesvm 0.1.0; pinned in tests-litesvm/fixtures/gap/cu, compare mode)

The current figures are the pinned files (regenerated with the build, never hand-edited):
receive-stub-endpoint.json, receive-real-clear.json (LayerZero's real endpoint clear + a new ATA),
receive-executor-execute-cpi.json, receive-delivery-key-top-level.json, send-real-route.json; the
receive transaction sizes are gap.rs `PINNED_RECEIVE_SIZES`. Every receive asks for its own compute
limit (the lzReceive option toward Solana is 550,000 CU); every pin is asserted below its limit.

## Build and upgrade

    cd solana/oft
    OFT_ID=SNyKyiZYU4R54SF9sYLmjCaCUsa1sC6QouNAj3x3Zzf cargo build-sbf
    cargo build-sbf --manifest-path tests-litesvm/stub-endpoint/Cargo.toml --sbf-out-dir tests-litesvm/stub-endpoint/deploy
    (cd tests-litesvm && cargo test)            # its own toolchain and workspace
    OFT_ID=SNyKyiZYU4R54SF9sYLmjCaCUsa1sC6QouNAj3x3Zzf cargo test -p oft

The splitter's and FastBridge's tests load this build as `oft-v3-gap.so` (copy it in with the build;
programs/pangea-splitter/tests/gap_v3.rs header). Reproducible builds, pins and the upgrade itself are
the owner's runbook (docs/factory-v3-cutover.md step 3; the pre-upgrade check
script/v3-mainnet/check-no-gap-accounts.mjs). Nothing here is pinned or deployed.
