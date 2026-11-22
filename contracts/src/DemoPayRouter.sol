// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.28;

/// DEMO ONLY: a payment router whose behaviour its owner can change at any time, standing in
/// for the real cases (an upgradeable proxy, a token whose fee changes, a pool that moves).
/// `pay` forwards `amount` to `to` and refunds the change to the sender, unless the owner has
/// switched on `keepChange`. A simulation before the switch sees a refund that the inclusion
/// after it doesn't get. That's the gap the Dabao's on-chain postcondition closes.
contract DemoPayRouter {
    address public immutable owner;
    bool public keepChange;

    event Paid(address indexed from, address indexed to, uint256 amount, uint256 change);

    constructor(address owner_) {
        owner = owner_;
    }

    function setKeepChange(bool k) external {
        require(msg.sender == owner, "owner");
        keepChange = k;
    }

    function pay(address to, uint256 amount) external payable {
        require(msg.value >= amount, "value");
        (bool ok,) = to.call{value: amount}("");
        require(ok, "pay");
        uint256 change = keepChange ? 0 : msg.value - amount;
        if (change > 0) {
            (ok,) = msg.sender.call{value: change}("");
            require(ok, "change");
        }
        emit Paid(msg.sender, to, amount, change);
    }
}
