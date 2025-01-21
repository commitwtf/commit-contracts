pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {CommitProtocol} from "../src/CommitProtocol.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract UpgradeProtocolScript is Script {
    //Proxy address 
    address constant PROXY_ADDRESS = 0x0000000000000000000000000000000000000000; 

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);

        // 1. Deploy new implementation
        CommitProtocol newImplementation = new CommitProtocol();

        // 2. Upgrade proxy to new implementation
        UUPSUpgradeable(PROXY_ADDRESS).upgradeToAndCall(
            address(newImplementation),
            ""
        );

        vm.stopBroadcast();
    }
}
