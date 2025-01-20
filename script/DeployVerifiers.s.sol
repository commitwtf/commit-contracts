// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {SignatureVerifier} from "../src/verifiers/SignatureVerifier.sol";
import {TokenVerifier} from "../src/verifiers/TokenVerifier.sol";
import {EASVerifier} from "../src/verifiers/EASVerifier.sol";
import {ERC20Mock} from "../src/mocks/ERC20Mock.sol";

contract DeployVerifiers is Script {
    function run() public {
        vm.startBroadcast();

        // Deploy SignatureVerifier (no constructor params)
        SignatureVerifier sigVerifier = new SignatureVerifier();
        console.log("SignatureVerifier deployed to:", address(sigVerifier));

        // Deploy TokenVerifier (no constructor params)
        TokenVerifier tokenVerifier = new TokenVerifier();
        console.log("TokenVerifier deployed to:", address(tokenVerifier));

				// Deploy EASVerifier (no constructor params)
				// EASVerifier easVerifier = new EASVerifier();
				//console.log("EASVerifier deployed to:", address(easVerifier));	

        // Deploy ERC20Mock (constructor sets name and symbol)
        // ERC20Mock mockToken = new ERC20Mock();
        //console.log("ERC20Mock deployed to:", address(mockToken));


        vm.stopBroadcast();

        // Log all addresses for easy reference
        console.log("\nDeployed Contracts Summary:");
        console.log("----------------------------");
        // console.log("SignatureVerifier:  ", address(sigVerifier));
        console.log("TokenVerifier:      ", address(tokenVerifier));
        // console.log("ERC20Mock:          ", address(mockToken));
    }
} 
