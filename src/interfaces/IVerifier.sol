// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IVerifier {
    function verify(
        address participant,
        bytes calldata data, // Initialized Commit.Config.verifierData
        bytes calldata userdata // User-provided data from frontend (i.e. signature)
    ) external view returns (bool);
}
