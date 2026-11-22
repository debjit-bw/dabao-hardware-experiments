// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.28;

import {DabaoPostcondition} from "../src/DabaoPostcondition.sol";
import {DemoPayRouter} from "../src/DemoPayRouter.sol";

interface Vm {
    function prank(address) external;
    function expectRevert(bytes calldata) external;
    function deal(address, uint256) external;
}

/// Run against Sepolia: forge test --fork-url $SEPOLIA_RPC
contract PostconditionTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address constant SAFE = 0x265871a72567419AE2f799a1288271C09B589fd9;
    address constant DEVICE = 0x7813e1C142086D37060Be2335ff9Dd4EA4a2F986;
    address constant WETH = 0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14;
    DabaoPostcondition pc = new DabaoPostcondition();

    function assets() internal pure returns (address[] memory a) {
        a = new address[](2);
        a[0] = address(0);
        a[1] = WETH;
    }

    function test_passes_on_current_state() public {
        uint256[] memory f = pc.balances(SAFE, assets());
        vm.prank(SAFE);
        pc.check(DEVICE, 2, assets(), f);
    }

    function test_balance_below_floor() public {
        uint256[] memory f = pc.balances(SAFE, assets());
        f[0] += 1;
        vm.prank(SAFE);
        vm.expectRevert("Dabao: balance below the simulated outcome");
        pc.check(DEVICE, 2, assets(), f);
    }

    function test_threshold_and_owner() public {
        uint256[] memory f = new uint256[](2);
        vm.prank(SAFE);
        vm.expectRevert("Dabao: threshold changed");
        pc.check(DEVICE, 1, assets(), f);
        vm.prank(SAFE);
        vm.expectRevert("Dabao: device is no longer an owner");
        pc.check(address(0xBEEF), 2, assets(), f);
    }

    function test_router_switch() public {
        DemoPayRouter r = new DemoPayRouter(address(this));
        vm.deal(address(this), 1 ether);
        uint256 b0 = address(this).balance;
        r.pay{value: 5}(address(0xdEaD), 1);
        require(address(this).balance == b0 - 1, "refund");
        r.setKeepChange(true);
        r.pay{value: 5}(address(0xdEaD), 1);
        require(address(this).balance == b0 - 6, "kept");
    }

    receive() external payable {}
}
