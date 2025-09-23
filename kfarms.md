## H-1 Protocol fails to prevent 1 owner from initializaing mmultiple accounts to farm rewards
## Description
The kfarm protoclo allows users to initialize the state of the user account , so for every user addes an id is attached for distribution of rewards, However protocol fails to prevent one malicious user from initializing multiple accounts to inflate his rewards, This he would give more rewards when protocol tries to distribute rewards to user.
```solidity
pub fn initialize_user(
    farm_state: &mut FarmState,
    user_state: &mut UserState,
    owner_key: &Pubkey,
    farm_state_key: &Pubkey,
    ts: u64,
) -> Result<()> {
    user_state.owner = *owner_key;
    user_state.farm_state = *farm_state_key;

    let user_id = farm_state.num_users;
    user_state.user_id = user_id;
    user_state.rewards_tally_scaled = [0; MAX_REWARDS_TOKENS];
    user_state.rewards_issued_unclaimed = [0; MAX_REWARDS_TOKENS];
    user_state.active_stake_scaled = 0;
    user_state.last_claim_ts = [ts; MAX_REWARDS_TOKENS];


    farm_state.num_users = farm_state
        .num_users
        .checked_add(1)
        .ok_or_else(|| dbg_msg!(FarmError::IntegerOverflow))?;

```
https://github.com/Kamino-Finance/kfarms/blob/204d6d073f1537d13f04be0dd661361db97b6c67/programs/kfarms/src/farm_operations.rs#L354
As we can see no check to prevent one user from initialize duplicate accounts for more farming of rewards , Lets say for exampple protocol wants to distibute 100 tokens rewards among 10 users , If Bob opens up multiple user accounts he would be able to claim lion share of the token rewards at the expense of other users.
## Recommended Mitigation
Enforce checks for duplicate accounts

## H2- Multiple missing Overflow checks in stakeOperations
## Description
The protocol fails to prevent overflow on multiple instances of stake operation:
When adding stake:
```solidity
pub fn add_active_stake(
    user_stake: &mut impl UserStakeAccessor,
    farm: &mut impl FarmStakeAccessor,
    staked_amount: u64,
) -> Result<Decimal, FarmError> {
    let mut user_stake = user_stake.get_accessor();
    let mut farm = farm.get_accessor();

    let user_gained_active_stake = convert_amount_to_stake(
        staked_amount,
        farm.total_active_stake,
        farm.total_active_amount,
    );

    user_stake.active_stake = user_stake.active_stake + user_gained_active_stake;

@>    farm.total_active_amount += staked_amount;
 @>   farm.total_active_stake = farm.total_active_stake + user_gained_active_stake;

    Ok(user_gained_active_stake)
}
```
https://github.com/Kamino-Finance/kfarms/blob/204d6d073f1537d13f04be0dd661361db97b6c67/programs/kfarms/src/stake_operations.rs#L247

When adding pending withdrawal stakes:
```solidity
pub fn add_pending_withdrawal_stake(
    user_stake: &mut impl UserStakeAccessor,
    farm: &mut impl FarmStakeAccessor,
    unstaked_amount: u64,
) -> Result<Decimal, FarmError> {
    let mut user_stake = user_stake.get_accessor();
    let mut farm = farm.get_accessor();

    let user_gained_pending_stake = convert_amount_to_stake(
        unstaked_amount,
        farm.total_pending_stake,
        farm.total_pending_amount,
    );

    user_stake.pending_withdrawal_unstake =
        user_stake.pending_withdrawal_unstake + user_gained_pending_stake;

    farm.total_pending_amount += unstaked_amount;
    farm.total_pending_stake = farm.total_pending_stake + user_gained_pending_stake;

    Ok(user_gained_pending_stake)
}
```
https://github.com/Kamino-Finance/kfarms/blob/204d6d073f1537d13f04be0dd661361db97b6c67/programs/kfarms/src/stake_operations.rs#L309

When adding pending deposit stake:
```solidity
pub fn add_pending_deposit_stake(
    user_stake: &mut impl UserStakeAccessor,
    farm: &mut impl FarmStakeAccessor,
    deposited_amount: u64,
) -> Result<Decimal, FarmError> {
    let mut user_stake = user_stake.get_accessor();
    let mut farm = farm.get_accessor();

    let user_gained_pending_stake = convert_amount_to_stake(
        deposited_amount,
        farm.total_pending_stake,
        farm.total_pending_amount,
    );

    user_stake.pending_deposit_stake = user_stake.pending_deposit_stake + user_gained_pending_stake;

@>    farm.total_pending_amount += deposited_amount;
    farm.total_pending_stake = farm.total_pending_stake + user_gained_pending_stake;

    Ok(user_gained_pending_stake)
}
```
https://github.com/Kamino-Finance/kfarms/blob/204d6d073f1537d13f04be0dd661361db97b6c67/programs/kfarms/src/stake_operations.rs#L186

As we can see in all this sceanrious overflow is not tracked to when the u64 max amount is reached it would downcast leading to wrong accounting of values

## Recommended MITIGATION
Safecast the addition of stake operations
