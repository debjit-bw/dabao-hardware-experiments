// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.28;

import {DabaoPostcondition} from "../src/DabaoPostcondition.sol";
import {DemoPayRouter} from "../src/DemoPayRouter.sol";

interface Vm {
    function prank(address) external;
    function expectRevert(bytes calldata) external;
    function deal(address, uint256) external;
    function warp(uint256) external;
}

interface ISafeSim {
    function simulateAndRevert(address target, bytes calldata data) external;
}

/// Run against Sepolia: forge test --fork-url $SEPOLIA_RPC
contract PostconditionTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address constant SAFE = 0x265871a72567419AE2f799a1288271C09B589fd9;
    address constant DEVICE = 0x7813e1C142086D37060Be2335ff9Dd4EA4a2F986;
    address constant MULTISEND = 0x9641d764fc13c8B624c04430C7356C1C7C8102e2;
    address constant WETH = 0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14;
    DabaoPostcondition pc = new DabaoPostcondition();
    DemoPayRouter router = new DemoPayRouter(address(this));

    function assets() internal pure returns (address[] memory a) {
        a = new address[](2);
        a[1] = WETH;
    }

    function deltas(int256 eth) internal pure returns (int256[] memory d) {
        d = new int256[](2);
        d[0] = eth;
    }

    function one(address to, uint256 value, bytes memory data) internal pure returns (bytes memory) {
        return abi.encodePacked(uint8(0), to, value, data.length, data);
    }

    /// The real batch, through the real MultiSendCallOnly, in the real Safe's context.
    function runBatch(uint256 deadline) internal returns (bool ok) {
        bytes memory txs = abi.encodePacked(
            one(address(pc), 0, abi.encodeCall(pc.begin, (assets()))),
            one(address(router), 500, abi.encodeCall(router.pay, (address(0xdEaD), 100))),
            one(address(pc), 0, abi.encodeCall(pc.check, (DEVICE, 2, deadline, assets(), deltas(-100))))
        );
        try ISafeSim(SAFE).simulateAndRevert(MULTISEND, abi.encodeWithSignature("multiSend(bytes)", txs)) {
            revert("didn't revert");
        } catch (bytes memory out) {
            assembly {
                ok := mload(add(out, 0x20))
            }
        }
    }

    function test_batch_passes() public {
        require(runBatch(block.timestamp), "refused");
    }

    function test_deposit_cannot_absorb_a_loss() public {
        vm.deal(SAFE, SAFE.balance + 1 ether);
        router.setKeepChange(true);
        require(!runBatch(block.timestamp), "loss passed");
    }

    function test_deposit_alone_is_harmless() public {
        vm.deal(SAFE, SAFE.balance + 1 ether);
        require(runBatch(block.timestamp), "refused");
    }

    function test_expired_batch_reverts() public {
        uint256 deadline = block.timestamp;
        vm.warp(deadline + 1);
        require(!runBatch(deadline), "expired batch passed");
    }

    function test_check_needs_begin() public {
        vm.prank(SAFE);
        vm.expectRevert("Dabao: not begun with these assets");
        pc.check(DEVICE, 2, block.timestamp, assets(), deltas(0));
    }

    function test_no_nested_begin() public {
        vm.prank(SAFE);
        pc.begin(assets());
        vm.prank(SAFE);
        vm.expectRevert("Dabao: already begun");
        pc.begin(assets());
    }

    function test_verify() public {
        uint256[] memory pre = pc.balances(SAFE, assets());
        vm.prank(SAFE);
        pc.verify(DEVICE, 2, block.timestamp, assets(), pre, deltas(0));
        vm.prank(SAFE);
        vm.expectRevert("Dabao: change worse than the simulated outcome");
        pc.verify(DEVICE, 2, block.timestamp, assets(), pre, deltas(1));
    }

    function test_threshold_and_owner() public {
        uint256[] memory pre = pc.balances(SAFE, assets());
        vm.prank(SAFE);
        vm.expectRevert("Dabao: threshold changed");
        pc.verify(DEVICE, 1, block.timestamp, assets(), pre, deltas(0));
        vm.prank(SAFE);
        vm.expectRevert("Dabao: device is no longer an owner");
        pc.verify(address(0xBEEF), 2, block.timestamp, assets(), pre, deltas(0));
    }

    receive() external payable {}
}
