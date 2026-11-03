# Pangea Solana programs

Source of the five Pangea programs live on Solana mainnet, published so anyone can rebuild them and
check that the on-chain code is this code (`solana-verify`, OtterSec verified builds).

| Program | Program ID | Library | Workspace (mount path) | Tag |
|---|---|---|---|---|
| Pangea OFT (LayerZero OFT with the Pangea patches) | `SNyKyiZYU4R54SF9sYLmjCaCUsa1sC6QouNAj3x3Zzf` | `oft` | `solana/oft` | `oft-cd23010b` |
| Pangea splitter | `Hb5uTppRbNxc3RjVRqTWqfdU3E3GiZyGYKccxYf9tUej` | `pangea_splitter` | `solana` | `splitter-c4c4cc20` |
| Pangea fast bridge | `7YNA5pg5sxmKxma7XiKDJnpWgyF5VPc7SaqyuzNhqZtw` | `pangea_fastbridge` | `solana` | `fastbridge-34447f3f` |
| Pangea cheapest route | `HQ6RgB3GGJvrkpj4dRiVMEQJAcEq4bAwtmaH6swnvDQC` | `pangea_cheapest` | `solana` | `cheapest-34447f3f` |
| Pangea DVN (LayerZero verifier) | `HwNU4xXd7GVuTcjWTtWdT83d27ACJtwSGiFFWDxaELkn` | `pangea_dvn` | `solana/dvn` | `dvn-34447f3f` |

Each tag is one commit holding `solana/` as it was at the source commit named in the tag (the part
of the Pangea repository the programs build from). Client scripts, tools and test harnesses are not
part of this mirror. The one file added is `solana/oft/.cargo/config.toml` (below).

## Rebuild

The workspaces use Solana 4.1.0 (`[workspace.metadata.cli]`), so the build runs on the 4.1.0
verifiable-build image:

```
git checkout <tag>
solana-verify build --library-name <library> --base-image solanafoundation/solana-verifiable-build@sha256:6468b89ae21d87b8eb002f894ac3f3442dbd8bcf5ea93414051e96e00d03b5ab <mount path>
solana-verify get-executable-hash <mount path>/target/deploy/<library>.so
solana-verify get-program-hash <program id>
```

The OFT takes its program id from `OFT_ID` at build time (`solana/oft/.cargo/config.toml` sets it
to `SNyKyiZYU4R54SF9sYLmjCaCUsa1sC6QouNAj3x3Zzf`) and is built with `--features stock-hops`.
