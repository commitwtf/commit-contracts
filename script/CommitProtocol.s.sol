// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script} from "../lib/forge-std/src/Script.sol";
import {console} from "../lib/forge-std/src/console.sol";

import {Create2Factory as Create2} from "../src/Create2Factory.sol";
import {CommitProtocol} from "../src/CommitProtocol.sol";
import {ERC1967Proxy} from "openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract DeployCommitProtocol is Script {
    function run() public {
        address owner = vm.envAddress("PROTOCOL_OWNER_ADDRESS");
        vm.startBroadcast();

        bytes32 salt = "commitProtocol";
        Create2 create2 = new Create2();

        console.log("Create2 deployed at:", address(create2));

        bytes memory creationCode = abi.encodePacked(
            type(CommitProtocol).creationCode
        );

        address resolver = create2.deploy(salt, creationCode);
        console.log("CommitProtocol deployed at:", address(resolver));

        creationCode = abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(
                address(resolver),
                abi.encodeCall(CommitProtocol.initialize, (owner))
            )
        );

        address computedAddress = create2.computeAddress(
            salt,
            keccak256(creationCode)
        );
        address deployedAddress = create2.deploy(salt, creationCode);

        vm.stopBroadcast();

        console.log(
            "Computed/Deployed Addresses:",
            computedAddress,
            deployedAddress
        );
        console.log("CommitProtocol proxy deployed to:", deployedAddress);
        console.log("Protocol owner address set to:", owner);
    }
}
