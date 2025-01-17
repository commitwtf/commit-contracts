// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script} from "../lib/forge-std/src/Script.sol";
import {console} from "../lib/forge-std/src/console.sol";
import {CommitProtocolV04} from "../src/CommitProtocolV04.sol";

contract SetProtocolConfig is Script {
    function run() public {
        address protocolAddress = vm.envAddress("PROTOCOL_ADDRESS");

        CommitProtocolV04.ProtocolConfig memory config = CommitProtocolV04.ProtocolConfig({
            maxCommitDuration: 31536000, // 365 days in seconds
            baseURI: "https://commit.wtf",
            fee: CommitProtocolV04.ProtocolFee({
                recipient: 0x7c145a1B6527DeD57D741331e15f01f5818E7F8c,
                fee: 200000000000000, // 0.0002 ETH in wei
                shareBps: 100 // 1%
            })
        });

        vm.startBroadcast();

        // Get protocol contract instance
        CommitProtocolV04 protocol = CommitProtocolV04(protocolAddress);

        // Call setProtocolConfig
        protocol.setProtocolConfig(config);

        vm.stopBroadcast();

        console.log("Protocol config updated:");
        console.log("- Max duration:", config.maxCommitDuration / 1 days, "days");
        console.log("- Base URI:", config.baseURI);
        console.log("- Fee recipient:", config.fee.recipient);
        console.log("- Fee amount:", config.fee.fee, "wei");
        console.log("- Share BPS:", config.fee.shareBps / 100, "%");
    }
}
