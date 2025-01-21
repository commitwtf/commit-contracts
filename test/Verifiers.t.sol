// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {CommitProtocol} from "../src/CommitProtocol.sol";
import {SignatureVerifier} from "../src/verifiers/SignatureVerifier.sol";
import {TokenUtils} from "../src/libraries/TokenUtils.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IVerifier} from "../src/interfaces/IVerifier.sol";
import {ERC20Mock} from "../src/mocks/ERC20Mock.sol";
import {ERC721Mock} from "../src/mocks/ERC721Mock.sol";
import {ERC1155Mock} from "../src/mocks/ERC1155Mock.sol";
import {MockVerifier} from "../src/mocks/VerifierMock.sol";
import {TokenVerifier, ERC1155Verifier} from "../src/verifiers/TokenVerifier.sol";
import {SignatureVerifier} from "../src/verifiers/SignatureVerifier.sol";

contract CommitProtocolTest is Test {
    CommitProtocol internal commitProtocol;
    TokenVerifier internal tokenVerifier;
    ERC1155Verifier internal erc1155Verifier;
    SignatureVerifier internal signatureVerifier;

    ERC20Mock internal erc20;
    ERC721Mock internal erc721;
    ERC1155Mock internal erc1155;

    address internal alice = address(0x1111);
    address internal bob = address(0x2222);

    function setUp() public {
        tokenVerifier = new TokenVerifier();
        erc1155Verifier = new ERC1155Verifier();
        signatureVerifier = new SignatureVerifier();
        erc20 = new ERC20Mock();
        erc721 = new ERC721Mock();
        erc1155 = new ERC1155Mock();

        erc20.mint(alice, 1 ether);
        erc721.mint(alice, 1);
        erc1155.mint(alice, 1);
    }

    function testTokenVerifier() public {
        // Test ERC20
        assertFalse(tokenVerifier.verify(alice, abi.encode(address(erc20), 2 ether), ""), "verify mismatch");
        assertTrue(tokenVerifier.verify(alice, abi.encode(address(erc20), 1 ether), ""), "verify mismatch");

        // Test ERC721
        assertFalse(tokenVerifier.verify(alice, abi.encode(address(erc721), 2), ""), "verify mismatch");
        assertTrue(tokenVerifier.verify(alice, abi.encode(address(erc721), 1), ""), "verify mismatch");

        // Test ERC1155
        assertFalse(erc1155Verifier.verify(alice, abi.encode(address(erc1155), 2, 1), ""), "verify mismatch");
        assertFalse(erc1155Verifier.verify(alice, abi.encode(address(erc1155), 1, 2), ""), "verify mismatch");
        assertTrue(erc1155Verifier.verify(alice, abi.encode(address(erc1155), 1, 1), ""), "verify mismatch");
    }

    // TODO: Not working yet
    function testSignatureVerifier() public {
        uint256 privateKey = 123;

        address signer = vm.addr(privateKey);

        uint256 commitId = uint256(1);
        uint256 timestamp = block.timestamp;
        bytes32 hash = MessageHashUtils.toEthSignedMessageHash(keccak256(abi.encodePacked(alice, timestamp, commitId)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, hash);

        // assertTrue(
        //     signatureVerifier.verify(
        //         alice, abi.encode(address(signer)), abi.encode(timestamp, commitId, abi.encodePacked(v, r, s))
        //     ),
        //     "verify mismatch"
        // );
    }
}
