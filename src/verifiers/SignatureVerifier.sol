// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IVerifier} from "../interfaces/IVerifier.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

// A signature can be created off-chain by a trusted service
contract SignatureVerifier is IVerifier {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    uint256 public constant SIGNATURE_EXPIRY = 15 minutes;

    function verify(address participant, bytes calldata data, bytes calldata userdata)
        external
        view
        override
        returns (bool)
    {
        address signer = abi.decode(data, (address));
        (uint256 timestamp, uint256 commitId, bytes memory signature) =
            abi.decode(userdata, (uint256, uint256, bytes));

        // Ensure the signature hasn't expired
        require(block.timestamp <= timestamp + SIGNATURE_EXPIRY, "Signature expired");

        // Compute the hash locally using the input parameters
        bytes32 hash = keccak256(abi.encodePacked(participant, timestamp, commitId));

        // Verify the signature matches the computed hash
        return hash.toEthSignedMessageHash().recover(signature) == signer;
    }
}
