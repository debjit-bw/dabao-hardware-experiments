// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.28;

interface ISafeView {
    function isOwner(address owner) external view returns (bool);
    function getThreshold() external view returns (uint256);
    function getModulesPaginated(address start, uint256 pageSize) external view returns (address[] memory, address);
    function getStorageAt(uint256 offset, uint256 length) external view returns (bytes memory);
}

interface IBalance {
    function balanceOf(address who) external view returns (uint256);
}

/// The on-chain half of the Dabao's Safe co-signing.
///
/// The device co-signs a Safe transaction only as a MultiSendCallOnly batch of
///   1. the call it simulated, then
///   2. `check(...)` on this contract,
/// so the call executes only if, at inclusion time, the state still matches the simulated
/// state. A Safe transaction with safeTxGas = 0 and gasPrice = 0 reverts entirely (GS013) if
/// any call in the batch fails.
///
/// `msg.sender` is the Safe: MultiSendCallOnly runs in the Safe's context through
/// DELEGATECALL and CALLs this contract from there. Stateless, no owner, no upgrades. Deployed
/// with the deterministic CREATE2 deployer, so its address commits to this code.
contract DabaoPostcondition {
    /// keccak256("guard_manager.guard.address")
    uint256 internal constant GUARD_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
    address internal constant SENTINEL = address(1);

    /// `who`'s balance of each asset (address(0) = ETH).
    function balances(address who, address[] calldata assets) public view returns (uint256[] memory b) {
        b = new uint256[](assets.length);
        for (uint256 i = 0; i < assets.length; i++) {
            b[i] = assets[i] == address(0) ? who.balance : IBalance(assets[i]).balanceOf(who);
        }
    }

    /// Reverts unless the calling Safe still has `device` as an owner, the same `threshold`, no
    /// modules and no guard, and at least `floors[i]` of each `assets[i]`.
    function check(address device, uint256 threshold, address[] calldata assets, uint256[] calldata floors) external view {
        ISafeView s = ISafeView(msg.sender);
        require(s.isOwner(device), "Dabao: device is no longer an owner");
        require(s.getThreshold() == threshold, "Dabao: threshold changed");
        (address[] memory modules,) = s.getModulesPaginated(SENTINEL, 1);
        require(modules.length == 0, "Dabao: a module is enabled");
        require(abi.decode(s.getStorageAt(GUARD_SLOT, 1), (uint256)) == 0, "Dabao: a guard is set");
        require(assets.length == floors.length, "Dabao: length");
        uint256[] memory b = balances(msg.sender, assets);
        for (uint256 i = 0; i < b.length; i++) {
            require(b[i] >= floors[i], "Dabao: balance below the simulated outcome");
        }
    }
}
