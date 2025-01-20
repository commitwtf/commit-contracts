// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IVerifier} from "../interfaces/IVerifier.sol";

contract MockVerifier is IVerifier {
    function verify(address, bytes calldata, bytes calldata) external pure returns (bool) {
        return true;
    }
}
