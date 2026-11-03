//! Pangea v3 `lz_receive_types`: the accounts of a v3 store's `lz_receive` (spec §10.4).
//!
//! The 13 named accounts and the endpoint's clear accounts as LayerZero's; then the six gap
//! accounts, the hop pools read from the `GapRoute` the executor passes as the `LzReceiveTypes`
//! PDA's third key; then the store's PriceLog (writable); then, for a composed v1 message only, the guid's `GapReceipt` (which carries
//! the compose: no endpoint compose accounts on a v3 store) and the sender's GapPrepay PDA (L4).
//! oft-fix L-1: for a composed v1 message (tail >= 32 bytes) `to_address` (4) is writable.
use crate::gap::{
    engine,
    math,
    state::{GapReceipt, Tail},
};
use crate::*;
use anchor_lang::solana_program;
use anchor_spl::{
    associated_token::{get_associated_token_address_with_program_id, ID as ASSOCIATED_TOKEN_ID},
    token_2022::spl_token_2022::solana_program::program_option::COption,
};
use oapp::endpoint_cpi::LzAccount;

impl LzReceiveTypes<'_> {
    pub fn apply_v3(ctx: &Context<LzReceiveTypes>, params: &LzReceiveParams) -> Result<Vec<LzAccount>> {
        let h = math::decode(&params.message).ok_or(OFTError::GapMsgTooShort)?;
        let composed = h.v1 && h.composed;
        let tail = {
            let info = ctx.accounts.oft_store.to_account_info();
            let d = info.try_borrow_data()?;
            Tail::read(&d).ok_or(OFTError::NotV3Store)?
        };
        let (peer, _) = Pubkey::find_program_address(
            &[PEER_SEED, ctx.accounts.oft_store.key().as_ref(), &params.src_eid.to_be_bytes()],
            ctx.program_id,
        );
        let ro = |pubkey| LzAccount { pubkey, is_signer: false, is_writable: false };
        let rw = |pubkey| LzAccount { pubkey, is_signer: false, is_writable: true };

        let to_address = Pubkey::from(h.send_to);
        // oft-fix L-1: a composed message's `to` is writable -- an arrival that writes no receipt
        // (plain land, escape + unlisted composer, zero credit) sends the sender's prepay to it
        let tail_len = crate::gap::math::compose_tail(&params.message).len();
        let to_writable = composed && tail_len >= 32;
        let token_program = ctx.accounts.token_mint.to_account_info().owner;
        let token_dest = get_associated_token_address_with_program_id(&to_address, &ctx.accounts.oft_store.token_mint, token_program);
        let mint_authority = if let COption::Some(a) = ctx.accounts.token_mint.mint_authority { a } else { ctx.program_id.key() };
        let (event_authority, _) = Pubkey::find_program_address(&[oapp::endpoint_cpi::EVENT_SEED], ctx.program_id);

        let mut accounts = vec![
            LzAccount { pubkey: Pubkey::default(), is_signer: true, is_writable: true }, // 0 payer
            rw(peer),                                                                    // 1
            rw(ctx.accounts.oft_store.key()),                                            // 2
            rw(ctx.accounts.oft_store.token_escrow),                                     // 3
            LzAccount { pubkey: to_address, is_signer: false, is_writable: to_writable }, // 4
            rw(token_dest),                                                              // 5
            rw(ctx.accounts.token_mint.key()),                                           // 6
            ro(mint_authority),                                                          // 7
            ro(*token_program),                                                          // 8
            ro(ASSOCIATED_TOKEN_ID),                                                     // 9
            ro(solana_program::system_program::ID),                                      // 10
            ro(event_authority),                                                         // 11
            ro(ctx.program_id.key()),                                                    // 12
        ];

        let endpoint_program = ctx.accounts.oft_store.endpoint_program;
        accounts.extend(oapp::endpoint_cpi::get_accounts_for_clear(
            endpoint_program,
            &ctx.accounts.oft_store.key(),
            params.src_eid,
            &params.sender,
            params.nonce,
        ));

        let gap = engine::receive_type_accounts(&tail, ctx.remaining_accounts.first(), ctx.program_id);
        accounts.extend(gap.iter().map(|k| ro(*k)));
        // the store's PriceLog (Amendment 4): the price path writes the live price into it
        accounts.push(rw(crate::gap::pricelog::address(ctx.program_id, &ctx.accounts.oft_store.key()).0));
        if composed {
            accounts.push(rw(GapReceipt::address(ctx.program_id, &params.guid).0));
            // L4: the sender's prepay PDA (its native drop), swept into the receipt by the receive
            let tail_bytes = crate::gap::math::compose_tail(&params.message);
            if tail_bytes.len() >= 32 {
                let from: [u8; 32] = tail_bytes[..32].try_into().unwrap();
                accounts.push(rw(crate::gap::state::prepay_address(ctx.program_id, &ctx.accounts.oft_store.key(), params.src_eid, &from, &tail_bytes[32..]).0));
            }
        }
        Ok(accounts)
    }
}
