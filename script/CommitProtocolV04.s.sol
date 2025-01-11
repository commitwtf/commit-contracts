// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {CommitProtocolV04} from "../src/CommitProtocolV04.sol";

contract CounterScript is Script {
    CommitProtocolV04 public protocol;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        protocol = new CommitProtocolV04();

        vm.stopBroadcast();
    }
}
