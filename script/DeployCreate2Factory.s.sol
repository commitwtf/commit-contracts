// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {Create2Factory} from "../src/Create2Factory.sol";

contract DeployCreate2FactoryScript is Script {
    function run() external returns (Create2Factory) {
        vm.startBroadcast();
        Create2Factory factory = new Create2Factory();
        vm.stopBroadcast();
        
        return factory;
    }
}