# LayerZero's Solana OFT program, as Pangea deploys it

Vendored from `LayerZero-Labs/devtools` at `4973ba8bef7b0fdf7268469abea3ea50dbd4bbd8`,
`examples/oft-solana/` (workspace `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml` and
`programs/oft`), unmodified in the commit that adds it. Deployed at
`SNyKyiZYU4R54SF9sYLmjCaCUsa1sC6QouNAj3x3Zzf`.

Build with the program id set, or the binary carries LayerZero's default id:

    cd solana/oft && OFT_ID=SNyKyiZYU4R54SF9sYLmjCaCUsa1sC6QouNAj3x3Zzf cargo build-sbf

See `PANGEA-PATCH.md` for the two changes Pangea makes (`init_tvl`; small peers). Tests of the
SBF build: `tests-litesvm/`.
