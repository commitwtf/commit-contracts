// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script} from "../lib/forge-std/src/Script.sol";
import {console} from "../lib/forge-std/src/console.sol";
import {Upgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";
import {CommitProtocolV04} from "../src/CommitProtocolV04.sol";


contract DeployCommitProtocol is Script {

    function run() public {
        address owner = vm.envAddress("PROTOCOL_OWNER_ADDRESS");
        address protocolFeeRecipient = vm.envAddress("PROTOCOL_FEE_ADDRESS");
        vm.startBroadcast();

        address proxy =
            Upgrades.deployUUPSProxy(
                "CommitProtocolV04.sol",
                abi.encodeCall(CommitProtocolV04.initialize, (owner)));

        vm.stopBroadcast();

        console.log("CommitProtocol proxy deployed to:", proxy);
        console.log("Protocol owner address set to:", owner);
        console.log("Protocol fee address set to:", protocolFeeRecipient);
    }
}