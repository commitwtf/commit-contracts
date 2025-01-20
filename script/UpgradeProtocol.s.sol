pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {CommitProtocolV04} from "../src/CommitProtocolV04.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract UpgradeProtocolScript is Script {
    //Proxy address 
    address constant PROXY_ADDRESS = 0x...; 

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);

        // 1. Deploy new implementation
        CommitProtocolV04 newImplementation = new CommitProtocolV04();

        // 2. Upgrade proxy to new implementation
        UUPSUpgradeable(PROXY_ADDRESS).upgradeToAndCall(
            address(newImplementation),
            ""
        );

        vm.stopBroadcast();
    }
}
