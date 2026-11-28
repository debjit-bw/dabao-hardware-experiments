// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.28;

/// DEMO ONLY: an ETH vault with ERC-4626-style share math and the classic flaw that made the
/// "inflation attack" famous: no virtual shares, so the share price is just
/// `totalAssets / totalSupply`, and anyone can raise it by sending ETH straight to the vault.
///
/// The attack: on a new vault, the attacker deposits 1 wei (1 share), then donates D wei. The
/// next deposit of P wei mints `P * 1 / (1 + D)` shares, rounded down, and the rounding goes to
/// the attacker. With D = 0.6 P, a 0.0001 ETH deposit gets 1 share worth 0.00008 ETH.
///
/// There is no owner: nothing here can be switched. The flaw is in the arithmetic, and the
/// attacker is a stranger.
contract DemoVault {
    string public constant name = "Demo ETH vault share";
    string public constant symbol = "dvETH";
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Deposit(address indexed sender, address indexed owner, uint256 assets, uint256 shares);
    event Withdraw(address indexed sender, address indexed receiver, address indexed owner, uint256 assets, uint256 shares);

    /// ERC-4626 `asset()`; zero means ETH.
    function asset() external pure returns (address) {
        return address(0);
    }

    function totalAssets() public view returns (uint256) {
        return address(this).balance;
    }

    function convertToShares(uint256 assets) public view returns (uint256) {
        return totalSupply == 0 ? assets : assets * totalSupply / totalAssets();
    }

    function convertToAssets(uint256 shares) public view returns (uint256) {
        return totalSupply == 0 ? shares : shares * totalAssets() / totalSupply;
    }

    function previewRedeem(uint256 shares) external view returns (uint256) {
        return convertToAssets(shares);
    }

    /// Deposit `msg.value` for `receiver`.
    function deposit(address receiver) external payable returns (uint256 shares) {
        uint256 before = totalAssets() - msg.value;
        shares = totalSupply == 0 ? msg.value : msg.value * totalSupply / before;
        totalSupply += shares;
        balanceOf[receiver] += shares;
        emit Transfer(address(0), receiver, shares);
        emit Deposit(msg.sender, receiver, msg.value, shares);
    }

    /// Burn the caller's `shares`, send what they are worth to `receiver`.
    function redeem(uint256 shares, address receiver, address owner) external returns (uint256 assets) {
        require(owner == msg.sender, "owner");
        assets = convertToAssets(shares);
        balanceOf[owner] -= shares;
        totalSupply -= shares;
        emit Transfer(owner, address(0), shares);
        emit Withdraw(msg.sender, receiver, owner, assets, shares);
        (bool ok,) = receiver.call{value: assets}("");
        require(ok, "send");
    }

    /// Donations: anyone can send ETH, which is what the attack uses.
    receive() external payable {}
}
