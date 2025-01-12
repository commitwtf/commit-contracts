// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import "forge-std/console2.sol";
import {CommitProtocolV04} from "../src/CommitProtocolV04.sol";
import {SignatureVerifier} from "../src/verifiers/SignatureVerifier.sol";
import {TokenUtils} from "../src/libraries/TokenUtils.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IVerifier} from "../src/interfaces/IVerifier.sol";
import {ICommit} from "../src/interfaces/ICommit.sol";
import {ERC20Mock} from "../src/mocks/ERC20Mock.sol";
import {MockVerifier} from "../src/mocks/VerifierMock.sol";

// Example Foundry test
contract CommitProtocolV04Test is Test {
    CommitProtocolV04 internal commitProtocol;
    MockVerifier internal verifier;
    ERC20Mock internal stakeToken;
    ERC20Mock internal altToken;

    address internal owner = address(0xABCD);
    address internal alice = address(0x1111);
    address internal bob = address(0x2222);

    // Example: protocol config
    CommitProtocolV04.ProtocolConfig internal protoCfg;

    // We'll store a created commitId for tests
    uint256 internal createdCommitId;

    function setUp() public {
        // 1. Deploy the protocol contract as an upgradeable base (UUPS).
        //    We call initialize(...) from the inherited ERC1155 contract constructor.
        vm.startPrank(owner);
        commitProtocol = new CommitProtocolV04();
        commitProtocol.initialize(owner); // from CommitProtocolERC1155 base

        verifier = new MockVerifier();
        // 2. Configure protocol fees
        protoCfg = CommitProtocolV04.ProtocolConfig({
            maxCommitDuration: 30 days,
            baseURI: "https://example.com/",
            fee: CommitProtocolV04.ProtocolFee({
                recipient: address(0xFEE),
                fee: 0.01 ether, // protocol creation/join fee in ETH
                shareBps: 500 // 5%
            })
        });

        // Store the config in the contract
        commitProtocol.setProtocolConfig(protoCfg);

        // 3. Deploy and mint mock tokens
        stakeToken = new ERC20Mock();
        altToken = new ERC20Mock();

        stakeToken.mint(alice, 1000 ether);
        stakeToken.mint(bob, 1000 ether);

        altToken.mint(alice, 500 ether);
        altToken.mint(bob, 500 ether);

        // 4. Approve tokens in the protocol
        commitProtocol.approveToken(address(stakeToken), true);
        commitProtocol.approveToken(address(altToken), true);

        vm.stopPrank();
    }

    function testCreateCommit() public {
        // Alice creates a commit
        vm.startPrank(alice);

        // Must pay protocol fee of 0.01 ETH
        vm.deal(alice, 1 ether); // give Alice some ETH to pay for creation

        // Build Commit details
        CommitProtocolV04.Commit memory newCommit = CommitProtocolV04.Commit({
            owner: alice,
            metadataURI: "ipfs://commitMetadata",
            joinBefore: block.timestamp + 1 days,
            verifyBefore: block.timestamp + 2 days,
            maxParticipants: 2,
            joinVerifier: CommitProtocolV04.Verifier({
                target: address(verifier),
                data: ""
            }),
            fulfillVerifier: CommitProtocolV04.Verifier({
                target: address(verifier),
                data: ""
            }),
            token: address(stakeToken),
            stake: 10 ether,
            fee: 2 ether,
            client: CommitProtocolV04.ClientConfig({
                recipient: address(0xBEEF),
                shareBps: 900 // 9%
            })
        });

        // Create commit
        uint256 commitId = commitProtocol.create{value: 0.01 ether}(newCommit);
        createdCommitId = commitId; // store for other tests
        // Check that commitId increments
        assertEq(commitId, 0, "First commit should have ID 0");
        assertEq(
            commitProtocol.commitIds(),
            1,
            "commitIds should be 1 after creation"
        );

        // Verify the commit data is stored properly
        CommitProtocolV04.Commit memory stored = commitProtocol.getCommit(
            commitId
        );
        assertEq(stored.owner, alice, "Owner mismatch");
        assertEq(stored.maxParticipants, 2, "Max participants mismatch");
        assertEq(stored.token, address(stakeToken), "Token mismatch");

        vm.stopPrank();
    }

    function testJoinCommit() public {
        // First create the commit as Alice
        vm.startPrank(alice);
        vm.deal(alice, 1 ether);
        uint256 commitId = commitProtocol.create{value: 0.01 ether}(
            CommitProtocolV04.Commit({
                owner: alice,
                metadataURI: "ipfs://commitMetadata",
                joinBefore: block.timestamp + 1 days,
                verifyBefore: block.timestamp + 2 days,
                maxParticipants: 2,
                joinVerifier: CommitProtocolV04.Verifier({
                    target: address(verifier),
                    data: ""
                }),
                fulfillVerifier: CommitProtocolV04.Verifier({
                    target: address(verifier),
                    data: ""
                }),
                token: address(stakeToken),
                stake: 10 ether,
                fee: 2 ether,
                client: CommitProtocolV04.ClientConfig({
                    recipient: address(0xBEEF),
                    shareBps: 900
                })
            })
        );
        vm.stopPrank();

        // Bob joins the commit
        vm.startPrank(bob);
        stakeToken.approve(address(commitProtocol), type(uint256).max);

        // Must pay protocol fee of 0.01 ETH to join
        vm.deal(bob, 1 ether);
        commitProtocol.join{value: 0.01 ether}(commitId, "");

        // Check Bob's participant status
        CommitProtocolV04.ParticipantStatus status = commitProtocol
            .participants(commitId, bob);
        assertEq(
            uint256(status),
            uint256(CommitProtocolV04.ParticipantStatus.joined)
        );

        // Also check that stake got pulled in
        // commit.stake + commit.fee = 12 ether
        // -> funds for stake is +10, claims for Alice is +2
        uint256 staked = commitProtocol.funds(address(stakeToken), commitId);
        assertEq(staked, 10 ether, "Stake not recorded properly");

        uint256 creatorClaim = commitProtocol.claims(
            address(stakeToken),
            alice
        );
        assertEq(creatorClaim, 2 ether, "Creator fee not recorded properly");
        vm.stopPrank();
    }

    function testVerifyAndClaim() public {
        // 1. Create and join in a single flow
        uint256 commitId;
        {
            vm.startPrank(alice);
            vm.deal(alice, 1 ether);
            commitId = commitProtocol.create{value: 0.01 ether}(
                CommitProtocolV04.Commit({
                    owner: alice,
                    metadataURI: "ipfs://commitMetadata",
                    joinBefore: block.timestamp + 1 days,
                    verifyBefore: block.timestamp + 2 days,
                    maxParticipants: 0, // no limit
                    joinVerifier: CommitProtocolV04.Verifier({
                        target: address(verifier),
                        data: ""
                    }),
                    fulfillVerifier: CommitProtocolV04.Verifier({
                        target: address(verifier),
                        data: ""
                    }),
                    token: address(stakeToken),
                    stake: 20 ether,
                    fee: 5 ether,
                    client: CommitProtocolV04.ClientConfig({
                        recipient: address(0xBEEF),
                        shareBps: 500 // 5%
                    })
                })
            );
            vm.stopPrank();

            vm.startPrank(bob);
            stakeToken.approve(address(commitProtocol), type(uint256).max);
            vm.deal(bob, 1 ether);
            commitProtocol.join{value: 0.01 ether}(commitId, "");
            vm.stopPrank();
        }

        // 2. Warp time so we can verify
        vm.warp(block.timestamp + 1 days + 1);
        // 3. Anyone can call verify; let's have Alice verify bob
        vm.startPrank(alice);
        bool verified = commitProtocol.verify(commitId, bob, "");
        assertTrue(verified, "Verification unexpectedly failed");
        vm.stopPrank();

        // 4. Warp past verifyBefore so claim is allowed
        vm.warp(block.timestamp + 1 days + 1);

        // 5. Bob calls claim
        vm.startPrank(bob);
        uint256 bobBalanceBefore = stakeToken.balanceOf(bob);
        commitProtocol.claim(commitId, bob);
        uint256 bobBalanceAfter = stakeToken.balanceOf(bob);
        vm.stopPrank();

        // Bob staked 20, plus 0 additional funding, total pot = 20 + any leftover
        // minus fees for protocol & client
        // Protocol shareBps = 5%
        // Client shareBps   = 5%
        // total 10% fee => Bob should get ~90% of 20 = 18
        // plus we must not forget Bob also paid the creator fee (5 ether)
        // but that was assigned to Alice's claims immediately.

        // We'll do a simple assertion that Bob's new balance is at least 18 more
        // than before, ignoring small edge cases.
        assertApproxEqRel(
            bobBalanceAfter - bobBalanceBefore,
            18 ether,
            1e16,
            "Bob's staked return not as expected"
        );
    }

    function testFundAndClaimMultipleTokens() public {
        // 1. Create commit
        vm.startPrank(alice);
        vm.deal(alice, 1 ether);
        uint256 commitId = commitProtocol.create{value: 0.01 ether}(
            CommitProtocolV04.Commit({
                owner: alice,
                metadataURI: "ipfs://commitMetadata",
                joinBefore: block.timestamp + 1 days,
                verifyBefore: block.timestamp + 2 days,
                maxParticipants: 0,
                joinVerifier: CommitProtocolV04.Verifier({
                    target: address(verifier),
                    data: ""
                }),
                fulfillVerifier: CommitProtocolV04.Verifier({
                    target: address(verifier),
                    data: ""
                }),
                token: address(stakeToken),
                stake: 10 ether,
                fee: 2 ether,
                client: CommitProtocolV04.ClientConfig({
                    recipient: address(0xBEEF),
                    shareBps: 500
                })
            })
        );
        vm.stopPrank();

        // 2. Bob joins
        vm.startPrank(bob);
        stakeToken.approve(address(commitProtocol), type(uint256).max);
        vm.deal(bob, 1 ether);
        commitProtocol.join{value: 0.01 ether}(commitId, "");
        vm.stopPrank();

        // 3. Alice funds the commit with altToken
        vm.startPrank(alice);
        altToken.approve(address(commitProtocol), type(uint256).max);
        commitProtocol.fund(commitId, address(altToken), 50 ether);
        vm.stopPrank();

        // 4. Warp past joinBefore, verify Bob
        vm.warp(block.timestamp + 1 days);
        vm.startPrank(alice);
        commitProtocol.verify(commitId, bob, "");
        vm.stopPrank();

        // 5. Warp beyond verifyBefore => Bob can claim
        vm.warp(block.timestamp + 2 days);

        // Check that funds are recorded for both stakeToken & altToken
        // stakeToken: 10 staked
        // altToken:   50 funded
        uint256 stakeFunds = commitProtocol.funds(
            address(stakeToken),
            commitId
        );
        uint256 altFunds = commitProtocol.funds(address(altToken), commitId);
        assertEq(stakeFunds, 10 ether, "stakeFunds mismatch");
        assertEq(altFunds, 50 ether, "altFunds mismatch");

        // Bob claims
        uint256 bobStakeBalBefore = stakeToken.balanceOf(bob);
        uint256 bobAltBalBefore = altToken.balanceOf(bob);

        vm.startPrank(bob);
        commitProtocol.claim(commitId, bob);
        vm.stopPrank();
        uint256 bobStakeBalAfter = stakeToken.balanceOf(bob);
        uint256 bobAltBalAfter = altToken.balanceOf(bob);

        // He should have gained some STK and ALT
        // Fees go to protocolFee.recipient & client. Bob gets the rest.
        // We won't do precise math here. Just check that Bob's balances have increased.
        assertTrue(
            bobStakeBalAfter > bobStakeBalBefore + 1,
            "Bob STK claim failed"
        );
        assertTrue(bobAltBalAfter > bobAltBalBefore, "Bob ALT claim failed");
    }

    function testWithdrawFees() public {
        // 1. Create & join quickly
        vm.startPrank(alice);
        vm.deal(alice, 1 ether);
        commitProtocol.create{value: 0.01 ether}(
            CommitProtocolV04.Commit({
                owner: alice,
                metadataURI: "ipfs://commitMetadata",
                joinBefore: block.timestamp + 1 days,
                verifyBefore: block.timestamp + 2 days,
                maxParticipants: 0,
                joinVerifier: CommitProtocolV04.Verifier({
                    target: address(verifier),
                    data: ""
                }),
                fulfillVerifier: CommitProtocolV04.Verifier({
                    target: address(verifier),
                    data: ""
                }),
                token: address(stakeToken),
                stake: 10 ether,
                fee: 2 ether,
                client: CommitProtocolV04.ClientConfig({
                    recipient: address(0xBEEF),
                    shareBps: 500
                })
            })
        );
        vm.stopPrank();

        vm.startPrank(bob);
        stakeToken.approve(address(commitProtocol), type(uint256).max);
        vm.deal(bob, 1 ether);
        commitProtocol.join{value: 0.01 ether}(0, "");
        vm.stopPrank();

        // 2. Check that Alice (creator) has 2 ether claim in the contract
        uint256 aliceClaim = commitProtocol.claims(address(stakeToken), alice);
        assertEq(aliceClaim, 2 ether, "Creator fee not stored");

        // 3. Alice withdraws her 2 ether
        uint256 aliceBalBefore = stakeToken.balanceOf(alice);
        vm.startPrank(alice);
        commitProtocol.withdraw(address(stakeToken), alice);
        vm.stopPrank();
        uint256 aliceBalAfter = stakeToken.balanceOf(alice);

        assertEq(
            commitProtocol.claims(address(stakeToken), alice),
            0,
            "Claim not cleared"
        );
        assertEq(
            aliceBalAfter - aliceBalBefore,
            2 ether,
            "Incorrect withdrawal amount"
        );
    }
}
