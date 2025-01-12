// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import "forge-std/console2.sol";
import {CommitProtocolV04} from "../src/CommitProtocolV04.sol";
import {SignatureVerifier} from "../src/verifiers/SignatureVerifier.sol";
import {TokenUtils} from "../src/libraries/TokenUtils.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IVerifier} from "../src/interfaces/IVerifier.sol";
import {ICommit} from "../src/interfaces/ICommit.sol";
import {ERC20Mock} from "../src/mocks/ERC20Mock.sol";

contract CommitProtocolV04Test is Test {
    CommitProtocolV04 internal protocol;

    function setUp() public {
        // TODO: Add tests
    }
}
