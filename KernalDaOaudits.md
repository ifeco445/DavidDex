Good day team, me and my team were observing your contract and found two issues that can be exploited by Attackers
## C-1 Attackers can exploit updateRSETHPrice  by frontrunning updates or calling during Flashloan to drain vault
## Description
In the LRTOracle.sol contract(https://github.com/Kelp-DAO/LRT-rsETH/blob/c289b815eb8f3300ed9feab13ef6b8b05515a15c/contracts/LRTOracle.sol#L50) ,It contains a function updateRSETHPrice it responsible for updates RSETH/ETH exchange rate, It does this by calculating based on stakedAsset value received from eigen layer. However this stale price update can be exploited by attackers. For example Attacker observes there is an increase in price of RSETH/ETH and update has not been called. Attacker quickly Flashloan a large deposits of staked token , Attacker then calls in updateRSETHPrice in the call back to update price to make profit from the increased price , after that then calls withdrawal to convert his assets back, Attacker leaves protocol with large profit potentially affecting pool.
```solidity
/// @notice updates RSETH/ETH exchange rate
    /// @dev calculates based on stakedAsset value received from eigen layer
@>    function updateRSETHPrice() external {
        uint256 oldRsETHPrice = rsETHPrice;
        address rsETHTokenAddress = lrtConfig.rsETH();

        uint256 rsethSupply = IRSETH(rsETHTokenAddress).totalSupply(); // 1e18
        if (rsethSupply == 0) {
            rsETHPrice = 1 ether;
            return;
        }

        uint256 totalETHInProtocol = _getTotalEthInProtocol(); // 1e36
        uint256 protocolFeeInETH;
        {
            uint256 tempRsETHPrice = totalETHInProtocol / rsethSupply; // 1e18
            if (tempRsETHPrice > oldRsETHPrice) {
                uint256 increaseInRsEthPrice = tempRsETHPrice - oldRsETHPrice; // new_price - old_price // 1e18
                uint256 rewardInETH = (increaseInRsEthPrice * rsethSupply) / 1e18; // 1e18
                protocolFeeInETH = (rewardInETH * lrtConfig.protocolFeeInBPS()) / 10_000; // 1e18
            }
        }
```
Another Scenrio of attack
Attacker can front-run any update of price by staking large assets to make instant profits.

Recommend Mitigation
The call should be made for every deposts and withdrawal to prevent stale price update and price manipulation or the call should be only made by admin

## C-2 Protocol fails to check if value == msg.value , Allowing Attackers to inflate value transfers by specifying small msg.value

## Description
In the L2/folder under ScrollMessenger.sol(https://github.com/Kelp-DAO/LRT-rsETH/blob/c289b815eb8f3300ed9feab13ef6b8b05515a15c/contracts/L2/ScrollMessenger.sol#L15) The function sendETHToL1ViaBridge fails to check if the msg.value is equal to the value being sent to the message. In Scroll implementation of transfering native tokens it validates if the msg.value is == to amount, But Kelp protocol fails to do so. This missing validation would allow an attacker Bridge more tokens than sent ETH amount. Opening vulenrability for attackers to drain bridge by sending small small msg.value amounts and bridging more tokens through this function.
```solidity
     */
    function sendETHToL1ViaBridge(address l2bridge, address target, uint256 value) external payable {
        IScrollMessenger(l2bridge).sendMessage{ value: value }(target, value, "", 0, msg.sender);
    }
}
```
## Recommended MITIGATION
Validate that value is equal to msg.value
