// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract EASIndexerMock {
    function getSchemaAttesterRecipientAttestationUIDCount(
        bytes32 schemaUID,
        address attester,
        address recipient
    ) external view returns (uint256) {
        return 1;
    }
}
