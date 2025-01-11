// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {CommitProtocolV04} from "../src/CommitProtocolV04.sol";

contract CommitProtocolV04Test is Test {
    CommitProtocolV04 public protocol;

    function setUp() public {
        protocol = new CommitProtocolV04();
    }
}
