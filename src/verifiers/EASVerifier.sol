// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IVerifier} from "../interfaces/IVerifier.sol";

interface IEASIndexer {
    function getSchemaAttesterRecipientAttestationUIDCount(
        bytes32 schemaUID,
        address attester,
        address recipient
    ) external view returns (uint256);
}

// A trusted service can create attestations to users that are verified here
contract EASVerifier is IVerifier {
    IEASIndexer private immutable easIndexer;

    constructor(address _easIndexer) {
        easIndexer = IEASIndexer(_easIndexer);
    }

    function verify(
        address participant,
        bytes calldata data,
        bytes calldata
    ) external view override returns (bool) {
        (bytes32 schemaUID, address attester) = abi.decode(
            data,
            (bytes32, address)
        );
        // Return true if the account has a valid attestation
        return
            easIndexer.getSchemaAttesterRecipientAttestationUIDCount(
                schemaUID,
                attester,
                participant
            ) > 0;
    }
}
