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
///   1. `begin(assets)`: records the Safe's balances (transient storage),
///   2. the call it simulated,
///   3. `check(...)`: reverts unless each balance CHANGED by at least the signed minimum, the
///      deadline hasn't passed and the checked Safe settings hold.
/// Changes, not absolute balances: funds that arrive before execution can't absorb a loss.
/// The deadline: signatures published by a reverted transaction stop working.
/// Approvals and unlisted assets are not checked. A Safe transaction with safeTxGas = 0 and
/// gasPrice = 0 reverts entirely (GS013) if any call in the batch fails.
///
/// `msg.sender` is the Safe: MultiSendCallOnly runs in the Safe's context through
/// DELEGATECALL and CALLs this contract from there. No owner, no upgrades, no permanent
/// storage. Deployed with the deterministic CREATE2 deployer, so its address commits to this code.
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

    /// Opens the caller's snapshot. One at a time: a nested co-signed batch would otherwise
    /// replace the outer batch's baseline with a balance from the middle of its call.
    function begin(address[] calldata assets) external {
        bytes32 session = keccak256(abi.encode(msg.sender));
        require(_load(session) == 0, "Dabao: already begun");
        _store(session, uint256(keccak256(abi.encode(assets))));
        uint256[] memory b = balances(msg.sender, assets);
        for (uint256 i = 0; i < b.length; i++) {
            _store(keccak256(abi.encode(msg.sender, i)), b[i]);
        }
    }

    /// Closes the snapshot and runs `verify` against it.
    function check(address device, uint256 threshold, uint256 deadline, address[] calldata assets, int256[] calldata minDeltas)
        external
    {
        bytes32 session = keccak256(abi.encode(msg.sender));
        require(_load(session) == uint256(keccak256(abi.encode(assets))), "Dabao: not begun with these assets");
        uint256[] memory pre = new uint256[](assets.length);
        for (uint256 i = 0; i < pre.length; i++) {
            pre[i] = _load(keccak256(abi.encode(msg.sender, i)));
        }
        _store(session, 0);
        _verify(msg.sender, device, threshold, deadline, assets, pre, minDeltas);
    }

    /// `check` with the earlier balances given: the device runs this on its simulated state,
    /// where the batch's transient snapshot doesn't exist.
    function verify(
        address device,
        uint256 threshold,
        uint256 deadline,
        address[] calldata assets,
        uint256[] calldata pre,
        int256[] calldata minDeltas
    ) external view {
        _verify(msg.sender, device, threshold, deadline, assets, pre, minDeltas);
    }

    function _verify(
        address safe,
        address device,
        uint256 threshold,
        uint256 deadline,
        address[] calldata assets,
        uint256[] memory pre,
        int256[] calldata minDeltas
    ) private view {
        require(block.timestamp <= deadline, "Dabao: expired");
        ISafeView s = ISafeView(safe);
        require(s.isOwner(device), "Dabao: device is no longer an owner");
        require(s.getThreshold() == threshold, "Dabao: threshold changed");
        (address[] memory modules,) = s.getModulesPaginated(SENTINEL, 1);
        require(modules.length == 0, "Dabao: a module is enabled");
        require(abi.decode(s.getStorageAt(GUARD_SLOT, 1), (uint256)) == 0, "Dabao: a guard is set");
        require(assets.length == pre.length && assets.length == minDeltas.length, "Dabao: length");
        uint256[] memory b = balances(safe, assets);
        for (uint256 i = 0; i < b.length; i++) {
            require(b[i] <= uint256(type(int256).max) && pre[i] <= uint256(type(int256).max), "Dabao: balance range");
            require(int256(b[i]) - int256(pre[i]) >= minDeltas[i], "Dabao: change worse than the simulated outcome");
        }
    }

    function _store(bytes32 k, uint256 v) private {
        assembly {
            tstore(k, v)
        }
    }

    function _load(bytes32 k) private view returns (uint256 v) {
        assembly {
            v := tload(k)
        }
    }
}
