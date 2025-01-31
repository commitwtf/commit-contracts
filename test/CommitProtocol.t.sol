// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {CommitProtocol} from "../src/CommitProtocol.sol";
import {SignatureVerifier} from "../src/verifiers/SignatureVerifier.sol";
import {TokenUtils} from "../src/libraries/TokenUtils.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IVerifier} from "../src/interfaces/IVerifier.sol";
import {ERC20Mock} from "../src/mocks/ERC20Mock.sol";
import {MockVerifier} from "../src/mocks/VerifierMock.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract CommitProtocolTest is Test {
    CommitProtocol internal commitProtocol;
    MockVerifier internal verifier;
    ERC20Mock internal stakeToken;
    ERC20Mock internal altToken;

    address internal protocolOwner = address(0xABCD);
    address internal alice = address(0x1111);
    address internal bob = address(0x2222);
    address internal protocolFeeRecipient = address(0x3333);
    address internal client = address(0xBEEF);

    // Example: protocol config
    CommitProtocol.ProtocolConfig internal config;

    // We'll store a created commitId for tests
    uint256 internal createdCommitId;

    // Add upgrade-specific variables
    CommitProtocol public implementationV2;

    function setUp() public {
        // 1. Deploy implementation and proxy
        vm.startPrank(protocolOwner);
        CommitProtocol implementation = new CommitProtocol();
        
        bytes memory initData = abi.encodeWithSelector(
            CommitProtocol.initialize.selector,
            protocolOwner
        );
        
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(implementation),
            initData
        );
        commitProtocol = CommitProtocol(address(proxy));

        verifier = new MockVerifier();
        // 2. Configure protocol fees
        config = CommitProtocol.ProtocolConfig({
            maxCommitDuration: 30 days,
            baseURI: "https://example.com/",
            fee: CommitProtocol.ProtocolFee({
                recipient: protocolFeeRecipient,
                fee: 0.01 ether, // protocol creation/join fee in ETH
                shareBps: 500 // 5%
            })
        });

        // Store the config in the contract
        commitProtocol.setProtocolConfig(config);
        commitProtocol.setURI("https://new.example.com/{id}.json");

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
        commitProtocol.approveToken(address(0), true);
        vm.stopPrank();
    }

    function testCreateCommit() public {
        // Alice creates a commit
        vm.startPrank(alice);

        // Must pay protocol fee of 0.01 ETH
        vm.deal(alice, 1 ether); // give Alice some ETH to pay for creation

        // Build Commit details
        CommitProtocol.Commit memory newCommit = createCommit(address(stakeToken));

        // Create commit
        // Check correct fee amount
        vm.expectRevert("Incorrect ETH amount sent");
        commitProtocol.create{value: 0.02 ether}(newCommit);

        uint256 commitId = commitProtocol.create{value: 0.01 ether}(newCommit);
        createdCommitId = commitId; // store for other tests
        // Check that commitId increments
        assertEq(commitId, 1, "First commit should have ID 1");
        assertEq(commitProtocol.commitIds(), 1, "commitIds should be 1 after creation");

        // Verify the commit data is stored properly
        CommitProtocol.Commit memory stored = commitProtocol.getCommit(commitId);
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
        uint256 commitId = commitProtocol.create{value: 0.01 ether}(createCommit(address(stakeToken)));
        vm.stopPrank();

        // Bob joins the commit
        vm.startPrank(bob);
        stakeToken.approve(address(commitProtocol), type(uint256).max);

        // Must pay protocol fee of 0.01 ETH to join
        vm.deal(bob, 1 ether);
        // Test check join fee matches
        vm.expectRevert("Incorrect ETH amount sent");
        commitProtocol.join{value: 0.02 ether}(commitId, "");

        commitProtocol.join{value: 0.01 ether}(commitId, "");

        // Join fee should be transferred to protocol fee recipient
        assertEq(address(protocolFeeRecipient).balance, 0.02 ether, "Join fee transfer mismatch");

        // Check Bob's participant status
        CommitProtocol.ParticipantStatus status = commitProtocol.participants(commitId, bob);
        assertEq(uint256(status), uint256(CommitProtocol.ParticipantStatus.joined));

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
            commitId = commitProtocol.create{value: 0.01 ether}(createCommit(address(stakeToken)));
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

    function testFundAndWithdraw() public {
        // 1. Alice creates a commit
        vm.startPrank(alice);
        vm.deal(alice, 1 ether);
        uint256 commitId = commitProtocol.create{value: 0.01 ether}(createCommit(address(stakeToken)));
        vm.stopPrank();

        // 2. Bob funds the commit
        vm.startPrank(bob);
        stakeToken.approve(address(commitProtocol), type(uint256).max);
        commitProtocol.fund(commitId, address(stakeToken), 50 ether);

        // Verify funding
        uint256 bobFundedAmount = commitProtocol.fundsByAddress(address(stakeToken), commitId, bob);
        uint256 totalFunds = commitProtocol.funds(address(stakeToken), commitId);
        assertEq(bobFundedAmount, 50 ether, "Bob's funded amount mismatch");
        assertEq(totalFunds, 50 ether, "Total funds mismatch");

        vm.stopPrank();

        // 3. Bob withdraws the funds before the join period ends
        vm.startPrank(bob);

        // Withdraw the funded amount
        commitProtocol.withdraw(commitId, address(stakeToken));

        // Attempt to withdraw more than funded, expect revert
        vm.expectRevert(abi.encodeWithSignature("InsufficientAmount()"));
        commitProtocol.withdraw(commitId, address(stakeToken));

        // Verify withdrawal
        uint256 bobBalanceAfterWithdraw = stakeToken.balanceOf(bob);
        assertEq(bobBalanceAfterWithdraw, 1000 ether, "Bob's balance after withdrawal mismatch");

        uint256 remainingFunds = commitProtocol.funds(address(stakeToken), commitId);
        assertEq(remainingFunds, 0, "Remaining funds mismatch");

        vm.stopPrank();
    }

    function testFundAndClaimMultipleTokens() public {
        // 1. Create commit
        vm.startPrank(alice);
        vm.deal(alice, 1 ether);
        uint256 commitId = commitProtocol.create{value: 0.01 ether}(createCommit(address(stakeToken)));
        vm.stopPrank();

        // 2. Bob joins
        vm.startPrank(bob);
        stakeToken.approve(address(commitProtocol), type(uint256).max);
        vm.deal(bob, 1 ether);
        commitProtocol.join{value: 0.01 ether}(commitId, "");

        // Test trying to withdraw stake
        vm.expectRevert(abi.encodeWithSignature("InsufficientAmount()"));
        commitProtocol.withdraw(commitId, address(stakeToken));

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

    function testClaimFees() public {
        // 1. Create & join quickly
        vm.startPrank(alice);
        vm.deal(alice, 1 ether);
        uint256 commitId = commitProtocol.create{value: 0.01 ether}(createCommit(address(stakeToken)));
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
        commitProtocol.claimFees(address(stakeToken));
        vm.stopPrank();
        uint256 aliceBalAfter = stakeToken.balanceOf(alice);

        assertEq(commitProtocol.claims(address(stakeToken), alice), 0, "Claim not cleared");
        assertEq(aliceBalAfter - aliceBalBefore, 2 ether, "Incorrect withdrawal amount");
    }

    function createCommit(address token) public view returns (CommitProtocol.Commit memory) {
        return CommitProtocol.Commit({
            creator: alice,
            metadataURI: "ipfs://commitMetadata",
            joinBefore: block.timestamp + 1 days,
            verifyBefore: block.timestamp + 2 days,
            maxParticipants: 2,
            joinVerifier: CommitProtocol.Verifier({target: address(verifier), data: ""}),
            fulfillVerifier: CommitProtocol.Verifier({target: address(verifier), data: ""}),
            token: token,
            stake: 10 ether,
            fee: 2 ether,
            client: CommitProtocol.ClientConfig({
                recipient: address(0xBEEF),
                shareBps: 500 // 5%
            })
        });
    }

    function testCancel() public {
        // 1. Setup: Create and join commit
        vm.startPrank(alice);
        vm.deal(alice, 1 ether);
        uint256 commitId = commitProtocol.create{value: 0.01 ether}(createCommit(address(stakeToken)));
        vm.stopPrank();

        // 2. Creator (alice) triggers cancel
        vm.startPrank(alice);
        vm.warp(commitProtocol.getCommit(commitId).verifyBefore);
        vm.expectRevert(abi.encodeWithSignature("CommitClosed(uint256,string)", commitId, "verify"));
        commitProtocol.cancel(commitId);
        vm.warp(commitProtocol.getCommit(commitId).verifyBefore - 1);
        commitProtocol.cancel(commitId);

        // // Check status changed
        CommitProtocol.CommitStatus commitStatus = commitProtocol.status(commitId);
        assertEq(uint256(commitStatus), uint256(CommitProtocol.CommitStatus.cancelled));
        vm.stopPrank();
    }

    function testCancelAndRefund() public {
        // 1. Setup: Create and join commit
        vm.startPrank(alice);
        vm.deal(alice, 1 ether);
        uint256 commitId = commitProtocol.create{value: 0.01 ether}(createCommit(address(stakeToken)));
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
        CommitProtocol.CommitStatus commitStatus = commitProtocol.status(commitId);
        assertEq(uint256(commitStatus), uint256(CommitProtocol.CommitStatus.cancelled));
        vm.stopPrank();

        // 3. Bob requests refund
        vm.startPrank(bob);
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
        uint256 commitId = commitProtocol.create{value: 0.01 ether}(createCommit(address(stakeToken)));
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
        uint256 commitId = commitProtocol.create{value: 0.01 ether}(createCommit(address(stakeToken)));
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
        CommitProtocol.Commit memory commit = commitProtocol.getCommit(commitId);
        commit.fulfillVerifier.target = address(failingVerifier);
        vm.stopPrank();

        // 3. Attempt verification
        vm.warp(block.timestamp + 1 days + 1);
        vm.startPrank(alice);
        bool verified = commitProtocol.verify(commitId, bob, "");
        assertFalse(verified, "Verification should have failed");

        // 4. Check participant status remains unchanged
        CommitProtocol.ParticipantStatus status = commitProtocol.participants(commitId, bob);
        assertEq(uint256(status), uint256(CommitProtocol.ParticipantStatus.joined));
        vm.stopPrank();
    }

    function testClientFeeDistribution() public {
        uint256 clientBalanceBefore = stakeToken.balanceOf(client);

        // 1. Create and join commit
        vm.startPrank(alice);
        vm.deal(alice, 1 ether);
        uint256 commitId = commitProtocol.create{value: 0.01 ether}(createCommit(address(stakeToken)));
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
        commitProtocol.claimFees(address(stakeToken));
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
        CommitProtocol.Commit memory invalidCommit = createCommit(address(stakeToken));
        invalidCommit.token = newToken;

        vm.expectRevert(abi.encodeWithSignature("TokenNotApproved(address)", newToken));
        commitProtocol.create{value: 0.01 ether}(invalidCommit);
        vm.stopPrank();
    }

    function testStatusTransitions() public {
        // 1. Create commit
        vm.startPrank(alice);
        vm.deal(alice, 1 ether);
        uint256 commitId = commitProtocol.create{value: 0.01 ether}(createCommit(address(stakeToken)));

        CommitProtocol.CommitStatus commitStatus = commitProtocol.status(commitId);
        assertEq(uint256(commitStatus), uint256(CommitProtocol.CommitStatus.created));

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
        uint256 commitId = commitProtocol.create{value: 0.01 ether}(createCommit(address(stakeToken)));
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
            uint256(commitProtocol.participants(commitId, bob)), uint256(CommitProtocol.ParticipantStatus.verified)
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
        commitProtocol.create{value: 0.01 ether}(createCommit(address(stakeToken)));

        commitProtocol.unpause();
        uint256 commitId = commitProtocol.create{value: 0.01 ether}(createCommit(address(stakeToken)));
        assertGt(commitId, 0, "Create failed");
        vm.stopPrank();
    }

    function testE2ESuccessfulCommitmentLifecycle() public {
        // 1. Setup: Alice creates a commit
        vm.startPrank(alice);
        vm.deal(alice, 1 ether);
        uint256 commitId = commitProtocol.create{value: 0.01 ether}(createCommit(address(stakeToken)));
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
        commitProtocol.claimFees(address(stakeToken));
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
            uint256(CommitProtocol.ParticipantStatus.claimed),
            "Final participant status incorrect"
        );
        assertEq(commitProtocol.claims(address(stakeToken), alice), 0, "Creator claims not cleared");
        assertEq(commitProtocol.funds(address(stakeToken), commitId), 0, "Commit funds not cleared");
    }

    function testE2ESuccessfulCommitmentLifecycleETH() public {
        // 1. Setup: Alice creates a commit

        vm.startPrank(alice);
        vm.deal(alice, 100 ether);

        uint256 commitId = commitProtocol.create{value: 0.01 ether}(createCommit(address(0)));
        vm.stopPrank();

        // 2. Bob joins the commit
        vm.startPrank(bob);
        stakeToken.approve(address(commitProtocol), type(uint256).max);
        vm.deal(bob, 100 ether);
        commitProtocol.join{value: 12.01 ether}(commitId, "");
        vm.stopPrank();

        // 3. Time passes, verification period starts
        vm.warp(block.timestamp + 1 days + 1);

        // 4. Alice verifies Bob's completion
        vm.startPrank(alice);
        bool verified = commitProtocol.verify(commitId, bob, "");
        assertTrue(verified, "Verification failed");
        vm.stopPrank();

        // 5. Creator claims their fees
        uint256 aliceBalanceBefore = alice.balance;
        vm.startPrank(alice);
        commitProtocol.claimFees(address(0));
        uint256 aliceBalanceAfter = alice.balance;
        assertGt(aliceBalanceAfter, aliceBalanceBefore, "Creator fee claim failed");
        vm.stopPrank();

        // 6. Time passes, claim period starts
        vm.warp(block.timestamp + 1 days + 1);

        // 7. Bob claims their rewards
        uint256 bobBalanceBefore = bob.balance;
        vm.startPrank(bob);
        commitProtocol.claim(commitId, bob);
        uint256 bobBalanceAfter = bob.balance;
        assertGt(bobBalanceAfter, bobBalanceBefore, "Participant reward claim failed");
        vm.stopPrank();

        // 8. Verify final state
        assertEq(
            uint256(commitProtocol.participants(commitId, bob)),
            uint256(CommitProtocol.ParticipantStatus.claimed),
            "Final participant status incorrect"
        );
        assertEq(commitProtocol.claims(address(stakeToken), alice), 0, "Creator claims not cleared");
        assertEq(commitProtocol.funds(address(stakeToken), commitId), 0, "Commit funds not cleared");
    }

    function testE2EEmergencyScenario() public {
        // 1. Create and setup commit
        vm.startPrank(alice);
        vm.deal(alice, 1 ether);
        uint256 commitId = commitProtocol.create{value: 0.01 ether}(createCommit(address(stakeToken)));
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

    function testGetCommitTokensAndSetURI() public {
        // 1. Setup: Alice creates a commit with stakeToken.
        vm.startPrank(alice);
        vm.deal(alice, 1 ether);

        CommitProtocol.Commit memory newCommit = createCommit(address(stakeToken));
        uint256 commitId = commitProtocol.create{value: 0.01 ether}(newCommit);

        // 2. Alice also funds this commit with altToken to ensure multiple tokens are tracked.
        altToken.approve(address(commitProtocol), type(uint256).max);
        commitProtocol.fund(commitId, address(altToken), 50 ether);

        // 3. Check getCommitTokens to cover the uncovered lines.
        address[] memory tokensUsed = commitProtocol.getCommitTokens(commitId);
        // Expect two tokens: stakeToken and altToken.
        assertEq(tokensUsed.length, 2, "Should have exactly two tokens in commitTokens");
        // Order depends on the set insertion, so just confirm presence:
        bool hasStakeToken;
        bool hasAltToken;
        for (uint256 i = 0; i < tokensUsed.length; i++) {
            if (tokensUsed[i] == address(stakeToken)) hasStakeToken = true;
            if (tokensUsed[i] == address(altToken)) hasAltToken = true;
        }
        assertTrue(hasStakeToken, "stakeToken not found in commitTokens");
        assertTrue(hasAltToken, "altToken not found in commitTokens");

        vm.stopPrank();
    }

    function testUpgradePreservesState() public {
        // Store pre-upgrade state
        vm.startPrank(alice);
        vm.deal(alice, 1 ether);
        uint256 commitId = commitProtocol.create{value: 0.01 ether}(createCommit(address(stakeToken)));
        vm.stopPrank();

        // Join with bob
        vm.startPrank(bob);
        stakeToken.approve(address(commitProtocol), type(uint256).max);
        vm.deal(bob, 1 ether);
        commitProtocol.join{value: 0.01 ether}(commitId, "");
        vm.stopPrank();
        
        // Store pre-upgrade state
        CommitProtocol.Commit memory preUpgradeCommit = commitProtocol.getCommit(commitId);
        uint256 preUpgradeBalance = commitProtocol.funds(address(stakeToken), commitId);
        
        // Store protocol config and approved tokens
        (uint256 preMaxDuration, string memory preBaseURI, CommitProtocol.ProtocolFee memory preFee) = commitProtocol.config();
        CommitProtocol.ProtocolConfig memory preUpgradeConfig = CommitProtocol.ProtocolConfig({
            maxCommitDuration: preMaxDuration,
            baseURI: preBaseURI,
            fee: preFee
        });
        address[] memory preUpgradeApprovedTokens = commitProtocol.getApprovedTokens();

        // Perform upgrade
        vm.startPrank(protocolOwner);
        implementationV2 = new CommitProtocol();
        UUPSUpgradeable(address(commitProtocol)).upgradeToAndCall(address(implementationV2), "");
        vm.stopPrank();
        
        // Verify state preserved
        CommitProtocol.Commit memory postUpgradeCommit = commitProtocol.getCommit(commitId);
        assertEq(preUpgradeCommit.token, postUpgradeCommit.token);
        assertEq(preUpgradeBalance, commitProtocol.funds(address(stakeToken), commitId));
    }

    function testUpgradeAccessControl() public {
        implementationV2 = new CommitProtocol();
        
        vm.startPrank(alice);
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", alice));
        UUPSUpgradeable(address(commitProtocol)).upgradeToAndCall(address(implementationV2), "");
        vm.stopPrank();
        
        vm.startPrank(protocolOwner);
        UUPSUpgradeable(address(commitProtocol)).upgradeToAndCall(address(implementationV2), "");
        vm.stopPrank();
    }

    function testUpgradeWithMultipleCommitsAndStates() public {
        (uint256 commitId1, uint256 commitId2) = _setupCommitsForUpgradeTest();
        _verifyPreUpgradeState(commitId1, commitId2);
        _performUpgrade();
        _verifyPostUpgradeState(commitId1, commitId2);
    }

    function _setupCommitsForUpgradeTest() internal returns (uint256 commitId1, uint256 commitId2) {
        // 1. Create multiple commits with different states
        vm.startPrank(alice);
        vm.deal(alice, 10 ether);
        
        // First commit: Created and joined
        commitId1 = commitProtocol.create{value: 0.01 ether}(createCommit(address(stakeToken)));
        
        // Second commit: Created, joined, and verified
        commitId2 = commitProtocol.create{value: 0.01 ether}(createCommit(address(stakeToken)));
        vm.stopPrank();

        // Bob joins both commits
        vm.startPrank(bob);
        stakeToken.approve(address(commitProtocol), type(uint256).max);
        vm.deal(bob, 10 ether);
        commitProtocol.join{value: 0.01 ether}(commitId1, "");
        commitProtocol.join{value: 0.01 ether}(commitId2, "");
        vm.stopPrank();

        // Verify bob in commit2
        vm.warp(block.timestamp + 1 days + 1);
        vm.startPrank(alice);
        commitProtocol.verify(commitId2, bob, "");
        vm.stopPrank();
    }

    function _verifyPreUpgradeState(uint256 commitId1, uint256 commitId2) internal {
        // Store pre-upgrade state
        CommitProtocol.Commit memory preUpgradeCommit1 = commitProtocol.getCommit(commitId1);
        CommitProtocol.Commit memory preUpgradeCommit2 = commitProtocol.getCommit(commitId2);
        CommitProtocol.ParticipantStatus preUpgradeStatus1 = commitProtocol.participants(commitId1, bob);
        CommitProtocol.ParticipantStatus preUpgradeStatus2 = commitProtocol.participants(commitId2, bob);
        uint256 preUpgradeBalance1 = commitProtocol.funds(address(stakeToken), commitId1);
        uint256 preUpgradeBalance2 = commitProtocol.funds(address(stakeToken), commitId2);
        
        // Store protocol config and approved tokens
        (uint256 preMaxDuration, string memory preBaseURI, CommitProtocol.ProtocolFee memory preFee) = commitProtocol.config();
        address[] memory preUpgradeApprovedTokens = commitProtocol.getApprovedTokens();

        // Store values in storage for later comparison
        s_preUpgradeCommit1 = preUpgradeCommit1;
        s_preUpgradeCommit2 = preUpgradeCommit2;
        s_preUpgradeStatus1 = preUpgradeStatus1;
        s_preUpgradeStatus2 = preUpgradeStatus2;
        s_preUpgradeBalance1 = preUpgradeBalance1;
        s_preUpgradeBalance2 = preUpgradeBalance2;
        s_preMaxDuration = preMaxDuration;
        s_preBaseURI = preBaseURI;
        s_preFee = preFee;
        s_preUpgradeApprovedTokens = preUpgradeApprovedTokens;
    }

    function _performUpgrade() internal {
        vm.startPrank(protocolOwner);
        implementationV2 = new CommitProtocol();
        UUPSUpgradeable(address(commitProtocol)).upgradeToAndCall(address(implementationV2), "");
        vm.stopPrank();
    }

    function _verifyPostUpgradeState(uint256 commitId1, uint256 commitId2) internal {
        // Verify all state is preserved
        CommitProtocol.Commit memory postUpgradeCommit1 = commitProtocol.getCommit(commitId1);
        CommitProtocol.Commit memory postUpgradeCommit2 = commitProtocol.getCommit(commitId2);
        
        // Check commit details preserved
        assertEq(s_preUpgradeCommit1.token, postUpgradeCommit1.token, "Commit1 token mismatch");
        assertEq(s_preUpgradeCommit2.token, postUpgradeCommit2.token, "Commit2 token mismatch");
        
        // Check participant statuses preserved
        CommitProtocol.ParticipantStatus postStatus1 = commitProtocol.participants(commitId1, bob);
        CommitProtocol.ParticipantStatus postStatus2 = commitProtocol.participants(commitId2, bob);
        
        assertEq(
            uint256(s_preUpgradeStatus1),
            uint256(postStatus1),
            "Participant status 1 mismatch"
        );
        assertEq(
            uint256(s_preUpgradeStatus2),
            uint256(postStatus2),
            "Participant status 2 mismatch"
        );
        
        // Check balances preserved
        assertEq(s_preUpgradeBalance1, commitProtocol.funds(address(stakeToken), commitId1), "Balance 1 mismatch");
        assertEq(s_preUpgradeBalance2, commitProtocol.funds(address(stakeToken), commitId2), "Balance 2 mismatch");
        
        // Check protocol config preserved
        (uint256 postMaxDuration, string memory postBaseURI, CommitProtocol.ProtocolFee memory postFee) = commitProtocol.config();
        assertEq(s_preMaxDuration, postMaxDuration, "Max duration mismatch");
        assertEq(s_preBaseURI, postBaseURI, "Base URI mismatch");
        assertEq(s_preFee.fee, postFee.fee, "Fee mismatch");
        assertEq(s_preFee.recipient, postFee.recipient, "Fee recipient mismatch");
        assertEq(s_preFee.shareBps, postFee.shareBps, "Fee share mismatch");
        
        // Check approved tokens preserved
        address[] memory postUpgradeApprovedTokens = commitProtocol.getApprovedTokens();
        assertEq(s_preUpgradeApprovedTokens.length, postUpgradeApprovedTokens.length, "Approved tokens length mismatch");
        for (uint256 i = 0; i < s_preUpgradeApprovedTokens.length; i++) {
            assertEq(s_preUpgradeApprovedTokens[i], postUpgradeApprovedTokens[i], "Approved token mismatch");
        }
    }

    // Storage variables for upgrade test state
    CommitProtocol.Commit internal s_preUpgradeCommit1;
    CommitProtocol.Commit internal s_preUpgradeCommit2;
    CommitProtocol.ParticipantStatus internal s_preUpgradeStatus1;
    CommitProtocol.ParticipantStatus internal s_preUpgradeStatus2;
    uint256 internal s_preUpgradeBalance1;
    uint256 internal s_preUpgradeBalance2;
    uint256 internal s_preMaxDuration;
    string internal s_preBaseURI;
    CommitProtocol.ProtocolFee internal s_preFee;
    address[] internal s_preUpgradeApprovedTokens;

    function testUpgradeInitialization() public {
        // Setup initial state
        vm.startPrank(protocolOwner);
        commitProtocol.setURI("test-uri");
        commitProtocol.pause();
        vm.stopPrank();

        // Store pre-upgrade state that depends on initializers
        bool preUpgradePaused = commitProtocol.paused();
        string memory preUpgradeURI = commitProtocol.uri(1);
        address preUpgradeOwner = commitProtocol.owner();

        // Perform upgrade
        vm.startPrank(protocolOwner);
        implementationV2 = new CommitProtocol();
        UUPSUpgradeable(address(commitProtocol)).upgradeToAndCall(address(implementationV2), "");
        vm.stopPrank();

        // Verify all initialized state is preserved
        assertEq(commitProtocol.paused(), preUpgradePaused, "Pause state not preserved");
        assertEq(commitProtocol.uri(1), preUpgradeURI, "URI not preserved");
        assertEq(commitProtocol.owner(), preUpgradeOwner, "Owner not preserved");
        
        // Verify initialized functions still work
        vm.startPrank(protocolOwner);
        commitProtocol.unpause();
        assertFalse(commitProtocol.paused(), "Pause functionality broken after upgrade");
        vm.stopPrank();
    }

    function testUpgradeStorageLayout() public {
        // Setup complex state with multiple storage slots
        vm.startPrank(protocolOwner);
        
        // Update protocol config (first storage slot)
        CommitProtocol.ProtocolConfig memory newConfig = CommitProtocol.ProtocolConfig({
            maxCommitDuration: 60 days,
            baseURI: "new-uri",
            fee: CommitProtocol.ProtocolFee({
                recipient: address(0x9999),
                fee: 0.02 ether,
                shareBps: 1000
            })
        });
        commitProtocol.setProtocolConfig(newConfig);
        
        // Add approved tokens (different storage slot)
        address newToken = address(0x8888);
        commitProtocol.approveToken(newToken, true);
        vm.stopPrank();
        
        // Create commit to test mappings
        vm.startPrank(alice);
        vm.deal(alice, 1 ether);
        uint256 commitId = commitProtocol.create{value: 0.02 ether}(createCommit(address(stakeToken)));
        vm.stopPrank();

        // Store pre-upgrade state from different storage slots
        (uint256 preMaxDuration, string memory preBaseURI, CommitProtocol.ProtocolFee memory preFee) = commitProtocol.config();
        address[] memory preApprovedTokens = commitProtocol.getApprovedTokens();
        CommitProtocol.Commit memory preCommit = commitProtocol.getCommit(commitId);
        uint256 preCommitIds = commitProtocol.commitIds();

        // Perform upgrade
        vm.startPrank(protocolOwner);
        implementationV2 = new CommitProtocol();
        UUPSUpgradeable(address(commitProtocol)).upgradeToAndCall(address(implementationV2), "");
        vm.stopPrank();

        // Verify all storage slots maintained their values
        (uint256 postMaxDuration, string memory postBaseURI, CommitProtocol.ProtocolFee memory postFee) = commitProtocol.config();
        address[] memory postApprovedTokens = commitProtocol.getApprovedTokens();
        CommitProtocol.Commit memory postCommit = commitProtocol.getCommit(commitId);
        uint256 postCommitIds = commitProtocol.commitIds();

        // Assert storage layout is preserved
        assertEq(postMaxDuration, preMaxDuration, "Config maxDuration not preserved");
        assertEq(postBaseURI, preBaseURI, "Config baseURI not preserved");
        assertEq(postFee.fee, preFee.fee, "Config fee not preserved");
        assertEq(postFee.recipient, preFee.recipient, "Config recipient not preserved");
        assertEq(postFee.shareBps, preFee.shareBps, "Config shareBps not preserved");
        assertEq(postApprovedTokens.length, preApprovedTokens.length, "Approved tokens length not preserved");
        assertEq(postCommit.creator, preCommit.creator, "Commit creator not preserved");
        assertEq(postCommitIds, preCommitIds, "CommitIds not preserved");
    }

    function testUpgradeWithPendingDistributions() public {
        // Setup: Create commit and get participants
        vm.startPrank(alice);
        vm.deal(alice, 1 ether);
        uint256 commitId = commitProtocol.create{value: 0.01 ether}(createCommit(address(stakeToken)));
        vm.stopPrank();

        // Bob and Charlie join
        address charlie = address(0x4444);
        vm.startPrank(bob);
        stakeToken.approve(address(commitProtocol), type(uint256).max);
        vm.deal(bob, 1 ether);
        commitProtocol.join{value: 0.01 ether}(commitId, "");
        vm.stopPrank();

        vm.startPrank(charlie);
        stakeToken.mint(charlie, 1000 ether);
        stakeToken.approve(address(commitProtocol), type(uint256).max);
        vm.deal(charlie, 1 ether);
        commitProtocol.join{value: 0.01 ether}(commitId, "");
        vm.stopPrank();

        // Add some additional funding
        vm.startPrank(alice);
        stakeToken.approve(address(commitProtocol), type(uint256).max);
        commitProtocol.fund(commitId, address(stakeToken), 50 ether);
        vm.stopPrank();

        // Verify participants but don't distribute yet
        vm.warp(block.timestamp + 1 days + 1);
        vm.startPrank(alice);
        commitProtocol.verify(commitId, bob, "");
        commitProtocol.verify(commitId, charlie, "");
        vm.stopPrank();

        // Store pre-upgrade state
        uint256 preUpgradeFunds = commitProtocol.funds(address(stakeToken), commitId);
        uint256 preUpgradeVerifiedCount = commitProtocol.verifiedCount(commitId);
        uint256 preUpgradeCreatorClaims = commitProtocol.claims(address(stakeToken), alice);
        uint256 preUpgradeProtocolClaims = commitProtocol.claims(address(stakeToken), protocolFeeRecipient);
        uint256 preUpgradeClientClaims = commitProtocol.claims(address(stakeToken), client);

        // Perform upgrade
        vm.startPrank(protocolOwner);
        implementationV2 = new CommitProtocol();
        UUPSUpgradeable(address(commitProtocol)).upgradeToAndCall(address(implementationV2), "");
        vm.stopPrank();

        // Verify post-upgrade state
        assertEq(commitProtocol.funds(address(stakeToken), commitId), preUpgradeFunds, "Funds not preserved");
        assertEq(commitProtocol.verifiedCount(commitId), preUpgradeVerifiedCount, "Verified count not preserved");
        assertEq(commitProtocol.claims(address(stakeToken), alice), preUpgradeCreatorClaims, "Creator claims not preserved");
        assertEq(commitProtocol.claims(address(stakeToken), protocolFeeRecipient), preUpgradeProtocolClaims, "Protocol claims not preserved");
        assertEq(commitProtocol.claims(address(stakeToken), client), preUpgradeClientClaims, "Client claims not preserved");

        // Verify distribution still works after upgrade
        vm.warp(block.timestamp + 1 days);
        commitProtocol.distribute(commitId, address(stakeToken));

        // Verify participants can still claim
        uint256 bobBalanceBefore = stakeToken.balanceOf(bob);
        vm.startPrank(bob);
        commitProtocol.claim(commitId, bob);
        vm.stopPrank();
        uint256 bobBalanceAfter = stakeToken.balanceOf(bob);
        assertTrue(bobBalanceAfter > bobBalanceBefore, "Claim after upgrade failed");

        // Verify fee recipients can claim
        uint256 aliceBalanceBefore = stakeToken.balanceOf(alice);
        vm.startPrank(alice);
        commitProtocol.claimFees(address(stakeToken));
        vm.stopPrank();
        uint256 aliceBalanceAfter = stakeToken.balanceOf(alice);
        assertTrue(aliceBalanceAfter > aliceBalanceBefore, "Fee claim after upgrade failed");
    }

    function testEmergencyWithdraw() public {
        // Setup: Deploy and fund the contract
        vm.startPrank(alice);
        vm.deal(alice, 1 ether);
        uint256 commitId = commitProtocol.create{value: 0.01 ether}(createCommit(address(stakeToken)));
        vm.stopPrank();

        // Bob joins and stakes tokens
        vm.startPrank(bob);
        stakeToken.approve(address(commitProtocol), type(uint256).max);
        vm.deal(bob, 1 ether);
        commitProtocol.join{value: 0.01 ether}(commitId, "");
        vm.stopPrank();

        // Record initial balances
        uint256 initialContractBalance = stakeToken.balanceOf(address(commitProtocol));
        uint256 initialOwnerBalance = stakeToken.balanceOf(protocolOwner);

        // Test non-owner cannot withdraw
        vm.startPrank(alice);
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", alice));
        commitProtocol.emergencyWithdraw(address(stakeToken), initialContractBalance);
        vm.stopPrank();

        // Test owner can withdraw without pausing
        vm.startPrank(protocolOwner);
        commitProtocol.emergencyWithdraw(address(stakeToken), initialContractBalance);

        // Verify balances
        assertEq(
            stakeToken.balanceOf(address(commitProtocol)), 
            0, 
            "Contract should have 0 balance after emergency withdraw"
        );
        assertEq(
            stakeToken.balanceOf(protocolOwner), 
            initialOwnerBalance + initialContractBalance,
            "Owner should receive withdrawn tokens"
        );
        vm.stopPrank();
    }
}

// Helper contract for testing verification failures

contract FailingMockVerifier is IVerifier {
    function verify(address, bytes calldata, bytes calldata) external pure returns (bool) {
        return false;
    }
}
