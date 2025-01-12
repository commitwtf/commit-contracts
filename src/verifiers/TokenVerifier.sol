// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IVerifier} from "../interfaces/IVerifier.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {IERC1155} from "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";

interface ITokenBalance {
    function balanceOf(address account) external view returns (uint256);
}

// Verifies token holdings
contract TokenVerifier is IVerifier {
    function verify(
        address participant,
        bytes calldata data,
        bytes calldata
    ) external view returns (bool) {
        (address token, uint256 minBalance) = abi.decode(
            data,
            (address, uint256)
        );
        // ERC20 and ERC721 share the same interface for balanceOf
        return ITokenBalance(token).balanceOf(participant) >= minBalance;
    }
}

contract ERC1155Verifier is IVerifier {
    function verify(
        address account,
        bytes calldata data,
        bytes calldata
    ) external view returns (bool) {
        (address token, uint256 minBalance, uint256 id) = abi.decode(
            data,
            (address, uint256, uint256)
        );
        return IERC1155(token).balanceOf(account, id) >= minBalance;
    }
}
