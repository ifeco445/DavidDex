## H1 - Program fails to validate program Id passed in by user when Depositing would allow attackers pass in malicious instructions
## Description
Solana allows programs to call one another through cross-program invocation (CPI). This can be done via invoke, which is responsible for routing the passed in instruction to the program. Whenever an external contract is invoked via CPI, the program must check and verify the program ID. If the program ID isn't verified, then the contract can call an attacker-controlled program instead of the intended one. A reference to this https://github.com/crytic/building-secure-contracts/tree/master/not-so-smart-contracts/solana/arbitrary_cpi

However the `handler_deposit` fails to enforce check on the program id passed in by the user this would make the vault invoke maliious instructions instead of deposit the user can invoke a withdrawal or deposit of fake tokens and mint free kamnino shares.
```solidity
    // Deposit from user token
    token_ops::tokens::transfer_to_vault(
        &UserTransferAccounts {
   @>         token_program: ctx.accounts.token_program.to_account_info(),
            user_authority: ctx.accounts.user.to_account_info(),
            token_ata: ctx.accounts.user_token_ata.to_account_info(),
            token_vault: ctx.accounts.token_vault.to_account_info(),
            token_mint: ctx.accounts.token_mint.to_account_info(),
        },
        token_to_deposit + crank_funds_to_deposit,
        ctx.accounts.token_mint.decimals,
    )?;
```
https://github.com/Kamino-Finance/kvault/blob/0321f6287d236b8286495ff7b7a410fcb93f0599/programs/kvault/src/handlers/handler_deposit.rs#L74
As we can see no validation of token program being passed, this is a user controlled parameter so validatoin musr be checked this can allow him deposit fake tokens and mint shares at the expense of the kamino vault
## Mitigation
Validate the token program

## H-2 Missing authorization of signer in `update_vault_config`
## Description
In Solana, since all accounts are provided as inputs when invoking a Solana program, users can supply arbitrary accounts and there’s no built-in stopping a malicious user from doing so with fake data. Therefore, Solana programs must check the validity of the input accounts. a refernce to this: https://www.sec3.dev/blog/from-ethereum-smart-contracts-to-solana-programs-two-common-security-pitfalls-and-beyond

However kamino fails to validate if the signer or caller of the `updaate_vault_cofig` is authorized or is the owner this would allow atackers control vaults update.
```solidity
pub fn process<'info>(
    ctx: Context<'_, '_, '_, 'info, UpdateVaultConfig<'info>>,
    entry: VaultConfigField,
    data: &[u8],
) -> Result<()> {
    // CPI memory allocation
    let mut cpi_mem = CpiMemoryLender::build_cpi_memory_lender(
        ctx.accounts.to_account_infos(),
        ctx.remaining_accounts,
    );
    let vault = &mut ctx.accounts.vault_state.load_mut()?;
    let reserves_count = vault.get_reserves_count();
    {
        // Refresh all reserves
        klend_operations::cpi_refresh_reserves(
            &mut cpi_mem,
            ctx.remaining_accounts.iter().take(reserves_count),
            reserves_count,
        )?;
    }
    let reserves_iter = ctx
        .remaining_accounts
        .iter()
        .take(reserves_count)
        .map(|account_info| FatAccountLoader::<Reserve>::try_from(account_info).unwrap());

    let holdings = holdings(vault, reserves_iter, Clock::get()?.slot)?;
    msg!("holdings {:?}", holdings);
```
https://github.com/Kamino-Finance/kvault/blob/0321f6287d236b8286495ff7b7a410fcb93f0599/programs/kvault/src/handlers/handler_update_vault_config.rs#L43
## Recommneded Mitigation
Enforce chaeck that the signer is authorized
```solidity
  	if !EXPECTED_ACCOUNT.is_signer {
    	return Err(ProgramError::MissingRequiredSignature);
	}
```

## H3 - Missing Admin signer check when updating Admin
## Description
Similair to the previous issue protocol fails to validate if the caller changing the admin is the admin signer, This vulnerable to unauthorized changing of admin os the vault.
```solidity
pub fn process(ctx: Context<UpdateAdmin>) -> Result<()> {
    let vault = &mut ctx.accounts.vault_state.load_mut()?;

    msg!(
        "Update admin from {} to {}",
        vault.vault_admin_authority,
        vault.pending_admin
    );
    vault.vault_admin_authority = vault.pending_admin;

    Ok(())
}

#[derive(Accounts)]
pub struct UpdateAdmin<'info> {
    #[account(mut)]
    pub pending_admin: Signer<'info>,

    #[account(mut,
        has_one = pending_admin,
    )]
    pub vault_state: AccountLoader<'info, VaultState>,
}
```
https://github.com/Kamino-Finance/kvault/blob/0321f6287d236b8286495ff7b7a410fcb93f0599/programs/kvault/src/handlers/handler_update_admin.rs#L5
As we can see in the change admin crate no check on the signer caller if he is authorized to cahnge uthority of the admin this can allow attackers make himself as admin and make free withdrawals from vault.

## Recommneded Mitigation
Check the key of the caller matches previous admin.

## H4- Anyone can claim vault pending fees due to lack of Signer check of caller
In solana programs users has access to control the input of their account data , So a malicous user can set his address as `vault_admin_authority` this would bypass the check and allw him claim vault fees. This issue occurs in Kamino vault `handler_withdraw_pending_fess` where program fails to validate the signer or caller address matches the `vault_admin_address` , An attacker can set his account as the vault_admin_address and start claiming fees of the protocol
```solidity
pub fn process<'info>(ctx: Context<'_, '_, '_, 'info, WithdrawPendingFees<'info>>) -> Result<()> {
    let mut cpi_mem = CpiMemoryLender::build_cpi_memory_lender(
        ctx.accounts.to_account_infos(),
        ctx.remaining_accounts,
    );

    let vault_state = &mut ctx.accounts.vault_state.load_mut()?;
    let reserves_count = vault_state.get_reserves_count();

    {
        // Refresh all reserves
        klend_operations::cpi_refresh_reserves(
            &mut cpi_mem,
            ctx.remaining_accounts.iter().take(reserves_count),
            reserves_count,
        )?;
    }

    let reserve = ctx.accounts.reserve.load()?;
    let bump = vault_state.base_vault_authority_bump;
    let reserve_address = ctx.accounts.reserve.to_account_info().key;

    // Cache some values
    let token_vault_before = ctx.accounts.token_vault.amount;
    let ctoken_vault_before = ctx.accounts.ctoken_vault.amount;
    let admin_ata_before = ctx.accounts.token_ata.amount;
    let reserve_supply_liquidity_before = ctx.accounts.reserve_liquidity_supply.amount;

    let reserves_iter = ctx
        .remaining_accounts
        .iter()
        .take(reserves_count)
        .map(|account_info| FatAccountLoader::<Reserve>::try_from(account_info).unwrap());

    let reserve_allocation = vault_state.allocation_for_reserve(reserve_address)?;
    require_keys_eq!(
        reserve_allocation.ctoken_vault,
        ctx.accounts.ctoken_vault.key()
    );
```
https://github.com/Kamino-Finance/kvault/blob/0321f6287d236b8286495ff7b7a410fcb93f0599/programs/kvault/src/handlers/handler_withdraw_pending_fees.rs#L21
As we can see no check or validation on the caller of the function opens up for this attack.
## Recommended Mitigation
Enforce signer checks

## H-5 Deposit reserve fails to validate the Klend program key being passed
## Description
```solidity
pub fn cpi_deposit_reserve_liquidity(
    ctx: &Context<Invest>,
    cpi: &mut CpiMemoryLender,
    base_vault_authority_bump: u8,
    liquidity_amount: u64,
) -> Result<()> {
    let accs = kamino_lending::accounts::DepositReserveLiquidity {
        owner: ctx.accounts.base_vault_authority.key(),
        reserve: ctx.accounts.reserve.key(),
        lending_market: ctx.accounts.lending_market.key(),
        lending_market_authority: ctx.accounts.lending_market_authority.key(),
        reserve_liquidity_mint: ctx.accounts.token_mint.key(),
        reserve_liquidity_supply: ctx.accounts.reserve_liquidity_supply.key(),
        reserve_collateral_mint: ctx.accounts.reserve_collateral_mint.key(),
        user_source_liquidity: ctx.accounts.token_vault.key(),
        user_destination_collateral: ctx.accounts.ctoken_vault.key(),
        collateral_token_program: ctx.accounts.reserve_collateral_token_program.key(),
        liquidity_token_program: ctx.accounts.token_program.key(),
        instruction_sysvar_account: ctx.accounts.instruction_sysvar_account.key(),
    }
    .to_account_metas(None);

    let mut data = [0_u8; 40];
    data[0..8]
        .copy_from_slice(&kamino_lending::instruction::DepositReserveLiquidity::DISCRIMINATOR);
    let mut writer = &mut data[8..40];
    borsh::to_writer(&mut writer, &liquidity_amount).unwrap();

    let base_vault_authority_bump = vec![base_vault_authority_bump];
    let vault_state_key = ctx.accounts.vault_state.key();
    let inner_seeds = [
        BASE_VAULT_AUTHORITY_SEED,
        vault_state_key.as_ref(),
        base_vault_authority_bump.as_ref(),
    ];
    let signer_seeds = &[&inner_seeds[..]];

    cpi.program_invoke_signed(
@>        &ctx.accounts.klend_program.key(),
        &accs,
        &data,
        signer_seeds,
    )
    .map_err(Into::into)
}
```
As we can see in the pointer the program fails to validate the program key being passed this are user controlled values allowing them to invoke malicious instructions on the program, Kamnino valuls should validate a program id parameters to prevent unwanted intructions from being executed.
