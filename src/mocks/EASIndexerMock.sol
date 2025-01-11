// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract EASIndexerMock {
    function getSchemaAttesterRecipientAttestationUIDCount(
        bytes32,
        address,
        address
    ) external pure returns (uint256) {
        return 1;
    }
}
