use crate::*;
use oapp::endpoint::{instructions::QuoteParams, MessagingFee};

use anchor_spl::{
    token_2022::spl_token_2022::{
        extension::{
            transfer_fee::{TransferFee, TransferFeeConfig},
            BaseStateWithExtensions, StateWithExtensions,
        },
        state::Mint as MintState,
    },
    token_interface::Mint,
};

#[derive(Accounts)]
#[instruction(params: QuoteSendParams)]
pub struct QuoteSend<'info> {
    #[account(
        seeds = [OFT_SEED, oft_store.token_escrow.as_ref()],
        bump = oft_store.bump
    )]
    pub oft_store: Account<'info, OFTStore>,
    #[account(
        seeds = [
            PEER_SEED,
            oft_store.key().as_ref(),
            &params.dst_eid.to_be_bytes()
        ],
        bump = peer.bump
    )]
    pub peer: Account<'info, PeerConfig>,
    #[account(address = oft_store.token_mint)]
    pub token_mint: InterfaceAccount<'info, Mint>,
}

impl QuoteSend<'_> {
    pub fn apply(ctx: &Context<QuoteSend>, params: &QuoteSendParams) -> Result<MessagingFee> {
        require!(!ctx.accounts.oft_store.paused, OFTError::Paused);

        let (_, amount_received_ld, _) = compute_fee_and_adjust_amount(
            params.amount_ld,
            &ctx.accounts.oft_store,
            &ctx.accounts.token_mint,
            ctx.accounts.peer.fee_bps,
        )?;
        require!(amount_received_ld >= params.min_amount_ld, OFTError::SlippageExceeded);

        // oft-q7 (Q7-e): a v3 store's quote may name the ["GapGlobal"] PDA as its FIRST remaining
        // account (before the endpoint's): toward a keys-only destination the fee then includes our
        // delivery cost and the options are the keys-only ones, exactly as the v3 send pays them.
        // Without it the quote is LayerZero's alone, as before.
        let v3 = crate::gap::state::is_v3_store(&ctx.accounts.oft_store.to_account_info());
        let global_key = crate::gap::state::GapGlobal::address(ctx.program_id);
        let (dst_delivery, eps) = match ctx.remaining_accounts.first() {
            Some(g) if v3 && *g.key == global_key => {
                let global = crate::gap::engine::read_global(g, ctx.program_id)?;
                (global.map_or(0, |g| g.dst_delivery_of(params.dst_eid)), &ctx.remaining_accounts[1..])
            }
            _ => (0, ctx.remaining_accounts),
        };
        // calling endpoint cpi
        let fee = oapp::endpoint_cpi::quote(
            ctx.accounts.oft_store.endpoint_program,
            eps,
            QuoteParams {
                sender: ctx.accounts.oft_store.key(),
                dst_eid: params.dst_eid,
                receiver: ctx.accounts.peer.peer_address,
                // Pangea v3: a v3 store's message is the gap codec (only its length is priced)
                message: if crate::gap::state::is_v3_store(&ctx.accounts.oft_store.to_account_info()) {
                    let compose = params.compose_msg.as_ref().filter(|m| !m.is_empty());
                    crate::gap::math::encode(params.to, 0, 0, 0, 0, 0, 0, 0, 0, 0, compose.map(|m| ([0u8; 32], m.as_slice())))
                } else {
                    msg_codec::encode(
                        params.to,
                        amount_received_ld,
                        Pubkey::default(),
                        &params.compose_msg,
                    )
                },
                pay_in_lz_token: params.pay_in_lz_token,
                // round-1 OFT I-4 (lead #3): a v3 store picks the options with the same rule as its
                // send (send_v3.rs: an empty compose is no compose, SEND); a live store's quote is
                // as its live send's (the unfiltered compose_msg), unchanged
                options: if v3 {
                    let compose = params.compose_msg.as_ref().filter(|m| !m.is_empty()).cloned();
                    oapp::options::combine_options(crate::instructions::send_v3::enforced_for(&ctx.accounts.peer, &compose, dst_delivery != 0), &params.options)?
                } else {
                    ctx.accounts.peer.enforced_options.combine_options(&params.compose_msg, &params.options)?
                },
            },
        )?;
        Ok(MessagingFee { native_fee: fee.native_fee.saturating_add(dst_delivery), lz_token_fee: fee.lz_token_fee })
    }
}

pub fn compute_fee_and_adjust_amount(
    amount_ld: u64,
    oft_store: &OFTStore,
    token_mint: &InterfaceAccount<Mint>,
    fee_bps: Option<u16>,
) -> Result<(u64, u64, u64)> {
    let (amount_sent_ld, amount_received_ld, oft_fee_ld) = if OFTType::Adapter == oft_store.oft_type
    {
        let mut amount_received_ld =
            oft_store.remove_dust(get_post_fee_amount_ld(token_mint, amount_ld)?);
        let amount_sent_ld = get_pre_fee_amount_ld(token_mint, amount_received_ld)?;

        // remove the oft fee from the amount_received_ld
        let oft_fee_ld = oft_store.remove_dust(calculate_fee(
            amount_received_ld,
            oft_store.default_fee_bps,
            fee_bps,
        ));
        amount_received_ld -= oft_fee_ld;
        (amount_sent_ld, amount_received_ld, oft_fee_ld)
    } else {
        // if it is Native OFT, there is no transfer fee
        let amount_sent_ld = oft_store.remove_dust(amount_ld);
        let oft_fee_ld = oft_store.remove_dust(calculate_fee(
            amount_sent_ld,
            oft_store.default_fee_bps,
            fee_bps,
        ));
        let amount_received_ld = amount_sent_ld - oft_fee_ld;
        (amount_sent_ld, amount_received_ld, oft_fee_ld)
    };
    Ok((amount_sent_ld, amount_received_ld, oft_fee_ld))
}

fn calculate_fee(pre_fee_amount: u64, default_fee_bps: u16, fee_bps: Option<u16>) -> u64 {
    let final_fee_bps = if let Some(bps) = fee_bps { bps as u128 } else { default_fee_bps as u128 };
    if final_fee_bps == 0 || pre_fee_amount == 0 {
        0
    } else {
        // pre_fee_amount * final_fee_bps / ONE_IN_BASIS_POINTS
        let fee = (pre_fee_amount as u128) * final_fee_bps;
        (fee / ONE_IN_BASIS_POINTS) as u64
    }
}

pub fn get_post_fee_amount_ld(token_mint: &InterfaceAccount<Mint>, amount_ld: u64) -> Result<u64> {
    let token_mint_info = token_mint.to_account_info();
    let token_mint_data = token_mint_info.try_borrow_data()?;
    let token_mint_ext = StateWithExtensions::<MintState>::unpack(&token_mint_data)?;
    let post_amount_ld =
        if let Ok(transfer_fee_config) = token_mint_ext.get_extension::<TransferFeeConfig>() {
            transfer_fee_config
                .get_epoch_fee(Clock::get()?.epoch)
                .calculate_post_fee_amount(amount_ld)
                .ok_or(ProgramError::InvalidArgument)?
        } else {
            amount_ld
        };
    Ok(post_amount_ld)
}

// Calculate the amount_sent_ld necessary to receive amount_received_ld
// Does *not* de-dust any inputs or outputs.
fn get_pre_fee_amount_ld(token_mint: &InterfaceAccount<Mint>, amount_ld: u64) -> Result<u64> {
    let token_mint_info = token_mint.to_account_info();
    let token_mint_data = token_mint_info.try_borrow_data()?;
    let token_mint_ext = StateWithExtensions::<MintState>::unpack(&token_mint_data)?;
    let pre_amount_ld =
        if let Ok(transfer_fee) = token_mint_ext.get_extension::<TransferFeeConfig>() {
            calculate_pre_fee_amount(transfer_fee.get_epoch_fee(Clock::get()?.epoch), amount_ld)
                .ok_or(ProgramError::InvalidArgument)?
        } else {
            amount_ld
        };
    Ok(pre_amount_ld)
}

// DO NOT CHANGE THIS CODE!!!
// bug reported on token2022: https://github.com/solana-labs/solana-program-library/pull/6704/files
// copy code over as fix has not been published
pub const MAX_FEE_BASIS_POINTS: u16 = 10_000;
const ONE_IN_BASIS_POINTS: u128 = MAX_FEE_BASIS_POINTS as u128;
fn calculate_pre_fee_amount(fee: &TransferFee, post_fee_amount: u64) -> Option<u64> {
    let maximum_fee = u64::from(fee.maximum_fee);
    let transfer_fee_basis_points = u16::from(fee.transfer_fee_basis_points) as u128;
    match (transfer_fee_basis_points, post_fee_amount) {
        // no fee, same amount
        (0, _) => Some(post_fee_amount),
        // 0 zero out, 0 in
        (_, 0) => Some(0),
        // 100%, cap at max fee
        (ONE_IN_BASIS_POINTS, _) => maximum_fee.checked_add(post_fee_amount),
        _ => {
            let numerator = (post_fee_amount as u128).checked_mul(ONE_IN_BASIS_POINTS)?;
            let denominator = ONE_IN_BASIS_POINTS.checked_sub(transfer_fee_basis_points)?;
            let raw_pre_fee_amount = ceil_div(numerator, denominator)?;

            if raw_pre_fee_amount.checked_sub(post_fee_amount as u128)? >= maximum_fee as u128 {
                post_fee_amount.checked_add(maximum_fee)
            } else {
                // should return `None` if `pre_fee_amount` overflows
                u64::try_from(raw_pre_fee_amount).ok()
            }
        },
    }
}

fn ceil_div(numerator: u128, denominator: u128) -> Option<u128> {
    numerator.checked_add(denominator)?.checked_sub(1)?.checked_div(denominator)
}

#[derive(Clone, AnchorSerialize, AnchorDeserialize)]
pub struct QuoteSendParams {
    pub dst_eid: u32,
    pub to: [u8; 32],
    pub amount_ld: u64,
    pub min_amount_ld: u64,
    pub options: Vec<u8>,
    pub compose_msg: Option<Vec<u8>>,
    pub pay_in_lz_token: bool,
}

/// Round 2 C I6 (proof + test): the v3 header's bridgeFeePpm b = fee_bps * 100 is the NOMINAL rate,
/// while the fee actually taken is fee = remove_dust(floor(G * fee_bps / 10,000)) on the gross G
/// (Native: G = remove_dust(amount); Adapter: G = what the escrow receives, net of a Token-2022
/// transfer fee, dust removed; either way G is dust-free and net = G - fee). The destination treats
/// the arrival as if net = G' * (1 - b) with the implied fee net * b / (1e6 - b). With F = G * b / 1e6
/// (exact): fee <= F and fee > F - rate (the floor loses < 1, the dust removal <= rate - 1), so
///     fee <= net * b / (1e6 - b)  <  fee + rate * 1e6 / (1e6 - b)
/// (the lower bound from net >= G - F, the upper from net < G - F + rate). The header never
/// understates the fee, and overstates it by less than one shared-decimals unit (rate LD) times
/// 1e6 / (1e6 - b) -- 1.002 units at the 0.2% fee: an allowance of at most ONE DUST UNIT per message,
/// below anything an arbitrage could use. The wire value stays the nominal one on every chain.
#[cfg(test)]
mod bridge_fee_ppm_tests {
    use super::*;

    fn store(rate: u64, bps: u16) -> OFTStore {
        OFTStore {
            oft_type: OFTType::Native,
            ld2sd_rate: rate,
            token_mint: Pubkey::default(),
            token_escrow: Pubkey::default(),
            endpoint_program: Pubkey::default(),
            bump: 0,
            tvl_ld: 0,
            admin: Pubkey::default(),
            default_fee_bps: bps,
            paused: false,
            pauser: None,
            unpauser: None,
        }
    }

    /// compute_fee_and_adjust_amount's Native arithmetic on the gross `g` (already dust-free), with the
    /// program's own calculate_fee and remove_dust: (net, fee).
    fn native(s: &OFTStore, amount: u64) -> (u64, u64, u64) {
        let gross = s.remove_dust(amount);
        let fee = s.remove_dust(calculate_fee(gross, s.default_fee_bps, None));
        (gross, gross - fee, fee)
    }

    #[test]
    fn the_nominal_bridge_fee_ppm_overstates_the_fee_taken_by_less_than_one_dust_unit() {
        let mut n = 0u64;
        let mut worst: u128 = 0;
        let mut seed: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for rate in [1u64, 10, 1_000, 1_000_000, 1_000_000_000] {
            for bps in [0u16, 1, 5, 20, 100, 500] {
                let s = store(rate, bps);
                let b = bps as u128 * 100;
                let mut amounts: Vec<u64> = vec![0, 1, rate - 1, rate, rate + 1, 9_999, 10_000, 10_001, 49_999 * rate, u64::MAX / 4];
                for _ in 0..2_000 {
                    amounts.push(next() % (u64::MAX / 4));
                    amounts.push(next() % 100_000_000);
                }
                for a in amounts {
                    let (gross, net, fee) = native(&s, a);
                    assert_eq!(net + fee, gross);
                    // the header never understates: fee * (1e6 - b) <= net * b
                    assert!(fee as u128 * (1_000_000 - b) <= net as u128 * b, "rate {rate} bps {bps} amount {a}: fee {fee} net {net}");
                    // and overstates by less than one dust unit x 1e6 / (1e6 - b)
                    assert!((net as u128 * b) < fee as u128 * (1_000_000 - b) + rate as u128 * 1_000_000, "rate {rate} bps {bps} amount {a}");
                    // the implied fee above the real one, rounded up: < rate x 1e6 / (1e6 - b) + 1
                    let over = (net as u128 * b).div_ceil(1_000_000 - b).saturating_sub(fee as u128);
                    assert!(over * (1_000_000 - b) < rate as u128 * 1_000_000 + (1_000_000 - b), "rate {rate} bps {bps} amount {a}: over {over}");
                    if bps <= 20 {
                        // our fee (0.2% at most): one dust unit, 0.2% of a unit and one LD
                        assert!(over <= rate as u128 + rate as u128 / 498 + 1, "rate {rate} bps {bps} amount {a}: over {over}");
                    }
                    worst = worst.max(over * 1_000 / rate as u128);
                    n += 1;
                }
            }
        }
        assert!(n > 100_000);
        // the bound is tight to the unit: some amount reaches a full dust unit's worth
        assert!(worst >= 900, "worst {worst} milli-units");
    }
}
