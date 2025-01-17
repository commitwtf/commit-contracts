// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {CommitProtocolV04} from "../src/CommitProtocolV04.sol";
import {SignatureVerifier} from "../src/verifiers/SignatureVerifier.sol";
import {TokenUtils} from "../src/libraries/TokenUtils.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IVerifier} from "../src/interfaces/IVerifier.sol";
import {ERC20Mock} from "../src/mocks/ERC20Mock.sol";
import {MockVerifier} from "../src/mocks/VerifierMock.sol";

contract CommitProtocolV04Test is Test {
    CommitProtocolV04 internal commitProtocol;
    MockVerifier internal verifier;
    ERC20Mock internal stakeToken;
    ERC20Mock internal altToken;

    address internal protocolOwner = address(0xABCD);
    address internal alice = address(0x1111);
    address internal bob = address(0x2222);
    address internal protocolFeeRecipient = address(0x3333);
    address internal client = address(0xBEEF);

    // Example: protocol config
    CommitProtocolV04.ProtocolConfig internal config;

    // We'll store a created commitId for tests
    uint256 internal createdCommitId;

    function setUp() public {
        // 1. Deploy the protocol contract as an upgradeable base (UUPS).
        vm.startPrank(protocolOwner);
        commitProtocol = new CommitProtocolV04();
        commitProtocol.initialize(protocolOwner);

        verifier = new MockVerifier();
        // 2. Configure protocol fees
        config = CommitProtocolV04.ProtocolConfig({
            maxCommitDuration: 30 days,
            baseURI: "https://example.com/",
            fee: CommitProtocolV04.ProtocolFee({
                recipient: protocolFeeRecipient,
                fee: 0.01 ether, // protocol creation/join fee in ETH
                shareBps: 500 // 5%
            })
        });

        // Store the config in the contract
        commitProtocol.setProtocolConfig(config);

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
        CommitProtocolV04.Commit memory newCommit = createCommit();

        // Create commit
        uint256 commitId = commitProtocol.create{value: 0.01 ether}(newCommit);
        createdCommitId = commitId; // store for other tests
        // Check that commitId increments
        assertEq(commitId, 1, "First commit should have ID 1");
        assertEq(commitProtocol.commitIds(), 1, "commitIds should be 1 after creation");

        // Verify the commit data is stored properly
        CommitProtocolV04.Commit memory stored = commitProtocol.getCommit(commitId);
        assertEq(stored.creator, alice, "Creator mismatch");
        assertEq(stored.maxParticipants, 2, "Max participants mismatch");
        assertEq(stored.token, address(stakeToken), "Token mismatch");

        // Create fee should be transferred to protocol fee recipient
        assertEq(address(protocolFeeRecipient).balance, 0.01 ether, "Create fee transfer mismatch");

        vm.stopPrank();
    }

    function testJoinCommit() public {
        // First create the commit as Alice
        vm.startPrank(alice);
        vm.deal(alice, 1 ether);
        uint256 commitId = commitProtocol.create{value: 0.01 ether}(createCommit());
        vm.stopPrank();

        // Bob joins the commit
        vm.startPrank(bob);
        stakeToken.approve(address(commitProtocol), type(uint256).max);

        // Must pay protocol fee of 0.01 ETH to join
        vm.deal(bob, 1 ether);
        commitProtocol.join{value: 0.01 ether}(commitId, "");

        // Join fee should be transferred to protocol fee recipient
        assertEq(address(protocolFeeRecipient).balance, 0.02 ether, "Join fee transfer mismatch");

        // Check Bob's participant status
        CommitProtocolV04.ParticipantStatus status = commitProtocol.participants(commitId, bob);
        assertEq(uint256(status), uint256(CommitProtocolV04.ParticipantStatus.joined));

        // Also check that stake got pulled in
        // commit.stake + commit.fee = 12 ether
        // -> funds for stake is +10, claims for Alice is +2
        uint256 staked = commitProtocol.funds(address(stakeToken), commitId);
        assertEq(staked, 10 ether, "Stake not recorded properly");

        uint256 creatorClaim = commitProtocol.claims(address(stakeToken), alice);
        assertEq(creatorClaim, 2 ether, "Creator fee not recorded properly");

        // NFT should be minted
        assertEq(commitProtocol.balanceOf(bob, 1), 1, "Token count mismatch");
        vm.stopPrank();
    }

    function testVerifyAndClaim() public {
        // 1. Create and join in a single flow
        uint256 commitId;
        {
            vm.startPrank(alice);
            vm.deal(alice, 1 ether);
            commitId = commitProtocol.create{value: 0.01 ether}(createCommit());
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

        // Bob staked 10, plus 0 additional funding, total pot = 10 + any leftover
        // minus fees for protocol & client
        // Protocol shareBps = 5%
        // Client shareBps   = 5%
        // total 10% fee => Bob should get ~90% of 10 = 9
        // plus we must not forget Bob also paid the creator fee (5 ether)
        // but that was assigned to Alice's claims immediately.

        // We'll do a simple assertion that Bob's new balance is at least 9 more
        // than before, ignoring small edge cases.
        assertApproxEqRel(bobBalanceAfter - bobBalanceBefore, 9 ether, 1e16, "Bob's staked return not as expected");
    }

    function testFundAndClaimMultipleTokens() public {
        // 1. Create commit
        vm.startPrank(alice);
        vm.deal(alice, 1 ether);
        uint256 commitId = commitProtocol.create{value: 0.01 ether}(createCommit());
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
        uint256 stakeFunds = commitProtocol.funds(address(stakeToken), commitId);
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
        assertTrue(bobStakeBalAfter > bobStakeBalBefore + 1, "Bob STK claim failed");
        assertTrue(bobAltBalAfter > bobAltBalBefore, "Bob ALT claim failed");
    }

    function testWithdrawFees() public {
        // 1. Create & join quickly
        vm.startPrank(alice);
        vm.deal(alice, 1 ether);
        uint256 commitId = commitProtocol.create{value: 0.01 ether}(createCommit());
        vm.stopPrank();
        vm.startPrank(bob);
        stakeToken.approve(address(commitProtocol), type(uint256).max);
        vm.deal(bob, 1 ether);
        commitProtocol.join{value: 0.01 ether}(commitId, "");
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

        assertEq(commitProtocol.claims(address(stakeToken), alice), 0, "Claim not cleared");
        assertEq(aliceBalAfter - aliceBalBefore, 2 ether, "Incorrect withdrawal amount");
    }

    function createCommit() public view returns (CommitProtocolV04.Commit memory) {
        return CommitProtocolV04.Commit({
            creator: alice,
            metadataURI: "ipfs://commitMetadata",
            joinBefore: block.timestamp + 1 days,
            verifyBefore: block.timestamp + 2 days,
            maxParticipants: 2,
            joinVerifier: CommitProtocolV04.Verifier({target: address(verifier), data: ""}),
            fulfillVerifier: CommitProtocolV04.Verifier({target: address(verifier), data: ""}),
            token: address(stakeToken),
            stake: 10 ether,
            fee: 2 ether,
            client: CommitProtocolV04.ClientConfig({
                recipient: address(0xBEEF),
                shareBps: 500 // 5%
            })
        });
    }

    function testCancelAndRefund() public {
        // 1. Setup: Create and join commit
        vm.startPrank(alice);
        vm.deal(alice, 1 ether);
        uint256 commitId = commitProtocol.create{value: 0.01 ether}(createCommit());
        vm.stopPrank();

        vm.startPrank(bob);
        stakeToken.approve(address(commitProtocol), type(uint256).max);
        vm.deal(bob, 1 ether);
        commitProtocol.join{value: 0.01 ether}(commitId, "");
        vm.stopPrank();

        // Record balances before cancel
        uint256 bobBalanceBefore = stakeToken.balanceOf(bob);

        // 2. Creator (alice) triggers cancel
        vm.startPrank(alice);
        commitProtocol.cancel(commitId);

        // Check status changed
        CommitProtocolV04.CommitStatus commitStatus = commitProtocol.status(commitId);
        assertEq(uint256(commitStatus), uint256(CommitProtocolV04.CommitStatus.cancelled));
        vm.stopPrank();

        // 3. Bob requests refund
        vm.startPrank(bob);
        commitProtocol.refund(commitId);

        // Can only refund once
        vm.expectRevert(
            abi.encodeWithSignature("InvalidParticipantStatus(uint256,address,string)", commitId, bob, "not-joined")
        );
        commitProtocol.refund(commitId);
        vm.stopPrank();

        // 4. Verify refund amounts
        uint256 bobBalanceAfter = stakeToken.balanceOf(bob);
        assertEq(bobBalanceAfter - bobBalanceBefore, 10 ether, "Incorrect refund amount");
    }

    function testAccessControl() public {
        // Test unauthorized cancel
        vm.startPrank(alice);
        vm.deal(alice, 1 ether);
        uint256 commitId = commitProtocol.create{value: 0.01 ether}(createCommit());
        vm.stopPrank();

        vm.startPrank(bob);
        vm.expectRevert(abi.encodeWithSignature("InvalidCommitCreator(uint256)", commitId));
        commitProtocol.cancel(commitId);
        vm.stopPrank();

        // Test unauthorized protocol config update
        vm.startPrank(bob);
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", bob));
        commitProtocol.setProtocolConfig(config);
        vm.stopPrank();
    }

    function testFailedVerification() public {
        // 1. Setup commit and participant
        vm.startPrank(alice);
        vm.deal(alice, 1 ether);
        uint256 commitId = commitProtocol.create{value: 0.01 ether}(createCommit());
        vm.stopPrank();

        vm.startPrank(bob);
        stakeToken.approve(address(commitProtocol), type(uint256).max);
        vm.deal(bob, 1 ether);
        commitProtocol.join{value: 0.01 ether}(commitId, "");
        vm.stopPrank();

        // 2. Deploy a failing verifier
        vm.startPrank(protocolOwner);
        FailingMockVerifier failingVerifier = new FailingMockVerifier();

        // Update commit to use failing verifier
        CommitProtocolV04.Commit memory commit = commitProtocol.getCommit(commitId);
        commit.fulfillVerifier.target = address(failingVerifier);
        vm.stopPrank();

        // 3. Attempt verification
        vm.warp(block.timestamp + 1 days + 1);
        vm.startPrank(alice);
        bool verified = commitProtocol.verify(commitId, bob, "");
        assertFalse(verified, "Verification should have failed");

        // 4. Check participant status remains unchanged
        CommitProtocolV04.ParticipantStatus status = commitProtocol.participants(commitId, bob);
        assertEq(uint256(status), uint256(CommitProtocolV04.ParticipantStatus.joined));
        vm.stopPrank();
    }

    function testClientFeeDistribution() public {
        uint256 clientBalanceBefore = stakeToken.balanceOf(client);

        // 1. Create and join commit
        vm.startPrank(alice);
        vm.deal(alice, 1 ether);
        uint256 commitId = commitProtocol.create{value: 0.01 ether}(createCommit());
        vm.stopPrank();

        vm.startPrank(bob);
        stakeToken.approve(address(commitProtocol), type(uint256).max);
        vm.deal(bob, 1 ether);
        commitProtocol.join{value: 0.01 ether}(commitId, "");
        vm.stopPrank();

        // 2. Complete the commitment flow
        vm.warp(block.timestamp + 1 days + 1);
        vm.startPrank(alice);
        commitProtocol.verify(commitId, bob, "");
        vm.stopPrank();

        vm.warp(block.timestamp + 1 days + 1);
        vm.startPrank(bob);
        commitProtocol.claim(commitId, bob);
        vm.stopPrank();

        // 3. Client withdraws their fee share
        vm.startPrank(client);
        commitProtocol.withdraw(address(stakeToken), client);
        vm.stopPrank();

        // 4. Check client received their fee share
        uint256 clientBalanceAfter = stakeToken.balanceOf(client);
        assertTrue(clientBalanceAfter > clientBalanceBefore, "Client did not receive fee share");

        // Client gets 5% of the stake amount (10 ether)
        uint256 expectedClientFee = (10 ether * 500) / 10000; // 500 bps = 5%
        assertEq(clientBalanceAfter - clientBalanceBefore, expectedClientFee, "Incorrect client fee amount");
    }

    function testTokenApprovalAndRemoval() public {
        address newToken = address(new ERC20Mock());

        // Test token approval
        vm.startPrank(protocolOwner);
        commitProtocol.approveToken(newToken, true);
        address[] memory approvedTokens = commitProtocol.getApprovedTokens();
        bool isApproved = false;
        for (uint256 i = 0; i < approvedTokens.length; i++) {
            if (approvedTokens[i] == newToken) {
                isApproved = true;
                break;
            }
        }
        assertTrue(isApproved, "Token not approved");

        // Test token removal
        commitProtocol.approveToken(newToken, false);
        approvedTokens = commitProtocol.getApprovedTokens();
        isApproved = false;
        for (uint256 i = 0; i < approvedTokens.length; i++) {
            if (approvedTokens[i] == newToken) {
                isApproved = true;
                break;
            }
        }
        assertFalse(isApproved, "Token not removed");

        // Test creating commit with unapproved token
        vm.stopPrank();
        vm.startPrank(alice);
        vm.deal(alice, 1 ether);
        CommitProtocolV04.Commit memory invalidCommit = createCommit();
        invalidCommit.token = newToken;

        vm.expectRevert(abi.encodeWithSignature("TokenNotApproved(address)", newToken));
        commitProtocol.create{value: 0.01 ether}(invalidCommit);
        vm.stopPrank();
    }

    function testStatusTransitions() public {
        // 1. Create commit
        vm.startPrank(alice);
        vm.deal(alice, 1 ether);
        uint256 commitId = commitProtocol.create{value: 0.01 ether}(createCommit());

        CommitProtocolV04.CommitStatus commitStatus = commitProtocol.status(commitId);
        assertEq(uint256(commitStatus), uint256(CommitProtocolV04.CommitStatus.created));

        // 2. Test cannot verify before join
        vm.expectRevert(
            abi.encodeWithSignature("InvalidParticipantStatus(uint256,address,string)", commitId, bob, "not-joined")
        );
        commitProtocol.verify(commitId, bob, "");
        vm.stopPrank();

        // 3. Join and verify (Active -> Verified)
        vm.startPrank(bob);
        stakeToken.approve(address(commitProtocol), type(uint256).max);
        vm.deal(bob, 1 ether);
        commitProtocol.join{value: 0.01 ether}(commitId, "");
        vm.stopPrank();

        vm.warp(block.timestamp + 1 days + 1);
        vm.startPrank(alice);
        commitProtocol.verify(commitId, bob, "");
        vm.stopPrank();

        // 4. Test cannot join after join period
        address charlie = address(0x4444);
        vm.startPrank(charlie);
        stakeToken.mint(charlie, 1000 ether);
        stakeToken.approve(address(commitProtocol), type(uint256).max);
        vm.deal(charlie, 1 ether);

        vm.expectRevert(abi.encodeWithSignature("CommitClosed(uint256,string)", commitId, "join"));
        commitProtocol.join{value: 0.01 ether}(commitId, "");
        vm.stopPrank();
    }

    function testVerifyOverride() public {
        // Setup commit and participant
        vm.startPrank(alice);
        vm.deal(alice, 1 ether);
        uint256 commitId = commitProtocol.create{value: 0.01 ether}(createCommit());
        vm.stopPrank();

        vm.startPrank(bob);
        stakeToken.approve(address(commitProtocol), type(uint256).max);
        vm.deal(bob, 1 ether);
        commitProtocol.join{value: 0.01 ether}(commitId, "");
        vm.stopPrank();

        // Test non-owner cannot override
        vm.startPrank(alice);
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", alice));
        commitProtocol.verifyOverride(commitId, bob);
        vm.stopPrank();

        // Test owner can override
        vm.startPrank(protocolOwner);
        commitProtocol.verifyOverride(commitId, bob);
        assertEq(
            uint256(commitProtocol.participants(commitId, bob)), uint256(CommitProtocolV04.ParticipantStatus.verified)
        );
        vm.stopPrank();

        // Test cannot override already verified
        vm.startPrank(protocolOwner);
        vm.expectRevert(
            abi.encodeWithSignature(
                "InvalidParticipantStatus(uint256,address,string)", commitId, bob, "already-verified"
            )
        );
        commitProtocol.verifyOverride(commitId, bob);
        vm.stopPrank();
    }

    function testPauseUnpause() public {
        vm.startPrank(protocolOwner);
        commitProtocol.pause();

        vm.deal(protocolOwner, 1 ether);
        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        commitProtocol.create{value: 0.01 ether}(createCommit());

        commitProtocol.unpause();
        uint256 commitId = commitProtocol.create{value: 0.01 ether}(createCommit());
        assertGt(commitId, 0, "Create failed");
        vm.stopPrank();
    }

    function testE2ESuccessfulCommitmentLifecycle() public {
        // 1. Setup: Alice creates a commit
        vm.startPrank(alice);
        vm.deal(alice, 1 ether);
        uint256 commitId = commitProtocol.create{value: 0.01 ether}(createCommit());
        vm.stopPrank();

        // 2. Bob joins the commit
        vm.startPrank(bob);
        stakeToken.approve(address(commitProtocol), type(uint256).max);
        vm.deal(bob, 1 ether);
        commitProtocol.join{value: 0.01 ether}(commitId, "");
        vm.stopPrank();

        // 3. Time passes, verification period starts
        vm.warp(block.timestamp + 1 days + 1);

        // 4. Alice verifies Bob's completion
        vm.startPrank(alice);
        bool verified = commitProtocol.verify(commitId, bob, "");
        assertTrue(verified, "Verification failed");
        vm.stopPrank();

        // 5. Creator claims their fees
        uint256 aliceBalanceBefore = stakeToken.balanceOf(alice);
        vm.startPrank(alice);
        commitProtocol.withdraw(address(stakeToken), alice);
        uint256 aliceBalanceAfter = stakeToken.balanceOf(alice);
        assertGt(aliceBalanceAfter, aliceBalanceBefore, "Creator fee claim failed");
        vm.stopPrank();

        // 6. Time passes, claim period starts
        vm.warp(block.timestamp + 1 days + 1);

        // 7. Bob claims their rewards
        uint256 bobBalanceBefore = stakeToken.balanceOf(bob);
        vm.startPrank(bob);
        commitProtocol.claim(commitId, bob);
        uint256 bobBalanceAfter = stakeToken.balanceOf(bob);
        assertGt(bobBalanceAfter, bobBalanceBefore, "Participant reward claim failed");
        vm.stopPrank();

        // 8. Verify final state
        assertEq(
            uint256(commitProtocol.participants(commitId, bob)),
            uint256(CommitProtocolV04.ParticipantStatus.claimed),
            "Final participant status incorrect"
        );
        assertEq(commitProtocol.claims(address(stakeToken), alice), 0, "Creator claims not cleared");
        assertEq(commitProtocol.funds(address(stakeToken), commitId), 0, "Commit funds not cleared");
    }

    function testE2EEmergencyScenario() public {
        // 1. Create and setup commit
        vm.startPrank(alice);
        vm.deal(alice, 1 ether);
        uint256 commitId = commitProtocol.create{value: 0.01 ether}(createCommit());
        vm.stopPrank();

        // Bob joins
        vm.startPrank(bob);
        stakeToken.approve(address(commitProtocol), type(uint256).max);
        vm.deal(bob, 1 ether);
        commitProtocol.join{value: 0.01 ether}(commitId, "");
        vm.stopPrank();

        // 2. Owner pauses contract
        vm.startPrank(protocolOwner);
        commitProtocol.pause();

        // 3. Verify operations are blocked for new participants
        address charlie = address(0x4444);
        vm.startPrank(charlie);
        stakeToken.mint(charlie, 100 ether);
        stakeToken.approve(address(commitProtocol), type(uint256).max);
        vm.deal(charlie, 1 ether);
        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        commitProtocol.join{value: 0.01 ether}(commitId, "");
        vm.stopPrank();

        // 4. Owner performs emergency withdrawal
        vm.startPrank(protocolOwner);
        uint256 balanceBefore = stakeToken.balanceOf(address(commitProtocol));
        commitProtocol.emergencyWithdraw(address(stakeToken), balanceBefore);
        uint256 balanceAfter = stakeToken.balanceOf(address(commitProtocol));
        assertEq(balanceAfter, 0, "Emergency withdrawal failed");

        // 5. Owner unpauses contract
        commitProtocol.unpause();
        vm.stopPrank();

        // 6. Verify operations resume
        vm.startPrank(charlie);
        commitProtocol.join{value: 0.01 ether}(commitId, "");
        vm.stopPrank();
    }
}
// Helper contract for testing verification failures

contract FailingMockVerifier is IVerifier {
    function verify(address, bytes calldata, bytes calldata) external pure returns (bool) {
        return false;
    }
}
