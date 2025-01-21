// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Create2Factory} from "../src/Create2Factory.sol";
import {CommitProtocol} from "../src/CommitProtocol.sol";

contract Create2FactoryTest is Test {
    Create2Factory internal factory;
    
    function setUp() public {
        factory = new Create2Factory();
    }

    function testDeterministicDeploy() public {
        bytes32 salt = "COMMIT_PROTOCOL";
        bytes memory creationCode = type(CommitProtocol).creationCode;

        address computedAddress = factory.computeAddress(salt, creationCode);
        address deployedAddress = factory.deploy(salt, creationCode);

        assertEq(computedAddress, deployedAddress);
    }
}