// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script} from "forge-std/src/Script.sol";
import {console} from "../lib/forge-std/src/console.sol";
import {Upgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";
import {CommitProtocolV04} from "../src/CommitProtocolV04.sol";

contract DeployCommitProtocol is Script {
    CommitProtocolV04 public protocol;

    function setUp() public {}

    function run() public {
        address owner = vm.envAddress("PROTOCOL_OWNER_ADDRESS");
        address protocolFeeRecipient = vm.envAddress("PROTOCOL_FEE_ADDRESS");
        vm.startBroadcast();

        address proxy =
            Upgrades.deployUUPSProxy(
                "CommitProtocolV04.sol",
                abi.encodeCall(CommitProtocolV04.initialize, (owner)));

        CommitProtocolV04.ProtocolConfig memory config = CommitProtocolV04.ProtocolConfig({
            maxCommitDuration: 30 days,
            baseURI: "https://example.com/",
            fee: CommitProtocolV04.ProtocolFee({
                recipient: protocolFeeRecipient,
                fee: 0.01 ether, // protocol creation/join fee in ETH
                shareBps: 500 // 5%
            })
        });

        CommitProtocolV04(proxy).setProtocolConfig(config);

        console.log("CommitProtocol proxy deployed to:", proxy);
        console.log("Protocol owner address set to:", owner);
        console.log("Protocol fee address set to:", protocolFeeRecipient);
        vm.stopBroadcast();
    }
}
