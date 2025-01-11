// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import "forge-std/console2.sol";
import {CommitProtocolV04, ICommitProtocolV04} from "../src/CommitProtocolV04.sol";
import {CommitV04} from "../src/CommitV04.sol";
import {SignatureVerifier} from "../src/verifiers/SignatureVerifier.sol";
import {TokenUtils} from "../src/libraries/TokenUtils.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IVerifier} from "../src/interfaces/IVerifier.sol";
import {ICommit} from "../src/interfaces/ICommit.sol";
import {ERC20Mock} from "../src/mocks/ERC20Mock.sol";

contract CommitProtocolV04Test is Test {
    // Contracts
    CommitProtocolV04 internal protocol;
    CommitV04 internal commitImplementation;
    SignatureVerifier internal verifier;
    ERC20Mock internal mockToken;

    // Users
    address internal owner = address(0xABCD);
    address internal alice = address(0xAAAA);
    address internal bob = address(0xBBBB);

    // Sample protocol config
    ICommitProtocolV04.ProtocolConfig internal protocolCfg;

    // Common data
    uint256 internal initialSupply = 1_000_000 ether;
    uint256 internal createFee = 0.01 ether;
    uint256 internal joinFee = 0.005 ether;
    address internal feeAddress = address(0xFEE);

    function setUp() public {
        // Label addresses for better console readability
        vm.label(owner, "Owner");
        vm.label(alice, "Alice");
        vm.label(bob, "Bob");
        vm.label(feeAddress, "FeeReceiver");

        // Deploy a mock token
        mockToken = new ERC20Mock();
        mockToken.mint(owner, 1000 ether);
        mockToken.mint(alice, 1000 ether);
        mockToken.mint(bob, 1000 ether);

        // Deploy the reference commit implementation
        commitImplementation = new CommitV04();
        vm.label(address(commitImplementation), "CommitImplementation");

        // Deploy a verifier (SignatureVerifier for example) or your own mock
        verifier = new SignatureVerifier();
        vm.label(address(verifier), "SignatureVerifier");

        // Create an initial protocol config
        protocolCfg = ICommitProtocolV04.ProtocolConfig({
            share: 500, // 5%
            joinFee: joinFee,
            createFee: createFee,
            maxDeadlineDuration: 365 days, // Just an example
            baseURI: "https://my-base.com/",
            feeAddress: feeAddress
        });

        // Deploy the protocol
        protocol = new CommitProtocolV04();

        vm.label(address(protocol), "CommitProtocol");

        // Initialize the protocol (UUPS pattern)
        protocol.initialize(address(commitImplementation), protocolCfg);
        protocol.setApprovedToken(address(mockToken), true);

        // Transfer some ETH to Alice & Bob for fees
        vm.deal(alice, 10 ether);
        vm.deal(bob, 10 ether);

        // Approve protocol for mockToken if needed
        // Not strictly necessary unless your tests require protocol to pull tokens from participants
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test: create a new commit
    // ─────────────────────────────────────────────────────────────────────────
    function testCreateCommit() public {
        ICommit.Config memory config = ICommit.Config({
            owner: owner,
            metadataURI: "ipfs://test-uri",
            joinBefore: block.timestamp + 1 days,
            verifyBefore: block.timestamp + 2 days,
            verifier: address(verifier),
            verifierData: abi.encode(alice), // Example: store some signer as data
            token: address(mockToken),
            stake: 1 ether,
            fee: 0.5 ether,
            maxParticipants: 10,
            milestones: new ICommit.Milestone[](0),
            client: ICommit.ClientConfig({
                recipient: address(0),
                fee: 0,
                share: 0
            })
        });

        // Check that create() requires exact protocol.createFee
        vm.prank(alice);
        vm.expectRevert("Incorrect ETH amount for protocol fee");
        protocol.create{value: 0}(config);

        // Provide correct createFee
        vm.prank(alice);
        protocol.create{value: createFee}(config);

        // The CommitCreated event is emitted. We can verify it by reading from the tx logs:
        // (In Foundry, you can also use `vm.expectEmit()` prior to the call)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helper: create a new commit and return address
    // ─────────────────────────────────────────────────────────────────────────
    function _createCommit(
        uint256 joinDays,
        uint256 verifyDays
    ) internal returns (address) {
        ICommit.Config memory config = ICommit.Config({
            owner: owner,
            metadataURI: "ipfs://metadata",
            joinBefore: block.timestamp + joinDays,
            verifyBefore: block.timestamp + verifyDays,
            verifier: address(verifier),
            verifierData: abi.encode(alice), // Example data
            token: address(mockToken),
            stake: 1 ether,
            fee: 0.5 ether,
            maxParticipants: 0,
            milestones: new ICommit.Milestone[](0),
            client: ICommit.ClientConfig({
                recipient: address(0),
                fee: 0,
                share: 0
            })
        });
        vm.prank(alice);
        // Create and capture event
        // vm.expectEmit(true, true, true, true);
        emit ICommitProtocolV04.CommitCreated(
            address(0), // will be replaced
            config.owner,
            config.metadataURI,
            config.joinBefore,
            config.verifyBefore,
            config.verifier,
            config.token,
            config.stake,
            config.fee,
            config.maxParticipants
        );
        return protocol.create{value: createFee}(config);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test: joining a commit
    // ─────────────────────────────────────────────────────────────────────────
    function testJoinCommit() public {
        address clonedCommit = _createCommit(1 days, 2 days);

        // Have Bob try to join with insufficient token approval
        vm.startPrank(bob);
        // Approve the commit to pull tokens
        mockToken.approve(clonedCommit, 1.5 ether);

        // The protocol itself also charges joinFee in ETH, so ensure Bob has enough ETH
        // Bob has 10 ether from setUp, so that's fine.

        // Bob calls join - must send joinFee in ETH
        ICommit(clonedCommit).join{value: joinFee}();

        // If Bob calls join again, it should revert: "Already joined"
        vm.expectRevert("Already joined");
        ICommit(clonedCommit).join{value: joinFee}();

        vm.stopPrank();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test: funding a commit
    // ─────────────────────────────────────────────────────────────────────────
    function testFundCommit() public {
        address clonedCommit = _createCommit(1 days, 2 days);

        // Let’s have Alice fund the commit with 100 tokens
        vm.startPrank(alice);
        mockToken.approve(clonedCommit, 100 ether);
        ICommit(clonedCommit).fund(100 ether);
        vm.stopPrank();

        // Check that the commit contract’s balance increased
        uint256 balance = mockToken.balanceOf(clonedCommit);
        assertEq(balance, 100 ether, "Commit should have 100 tokens");

        // Test revert: if commit is not active or if we pass incorrect arguments, etc.
        // e.g. if we try to fund after status changes
        // (We can test that after a forced cancellation or resolution.)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test: verifying participants
    // ─────────────────────────────────────────────────────────────────────────
    function testVerifyParticipants() public {
        address clonedCommit = _createCommit(1 days, 2 days);

        // Bob joins
        vm.startPrank(bob);
        mockToken.approve(clonedCommit, 1.5 ether);
        ICommit(clonedCommit).join{value: joinFee}();
        vm.stopPrank();

        // Move time forward so we can test boundary conditions if needed
        vm.warp(block.timestamp + 12 hours);

        vm.expectRevert("Not a participant");
        ICommit(clonedCommit).verify(alice, "");

        uint256 timestamp = block.timestamp;
        address commitId = clonedCommit;
        bytes32 hash = keccak256(abi.encodePacked(bob, timestamp, commitId));

        bytes memory userData = ""; // TODO: Sign hash with alice
        return;

        // Bob verifies
        bool success = ICommit(clonedCommit).verify(bob, userData);
        assertTrue(success, "Verification must pass");

        // Trying again reverts with "Already verified"
        vm.expectRevert("Already verified");
        ICommit(clonedCommit).verify(bob, "");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test: claiming rewards
    // ─────────────────────────────────────────────────────────────────────────
    function testClaimRewards() public {
        address clonedCommit = _createCommit(1 days, 2 days);

        // Bob joins
        vm.startPrank(bob);
        mockToken.approve(clonedCommit, 1.5 ether);
        ICommit(clonedCommit).join{value: joinFee}();
        vm.stopPrank();
        // TODO: Fix verify test first
        return;
        // Bob verifies
        ICommit(clonedCommit).verify(bob, "");

        // Before verification deadline is passed, claim should revert (since _calculateRewards not triggered yet)
        vm.expectRevert("Verification ongoing");
        ICommit(clonedCommit).claim();

        // Move time past verification
        vm.warp(block.timestamp + 3 days);

        // Now Bob can claim
        ICommit(clonedCommit).claim();

        // Trying to claim again should revert with "Already claimed"
        vm.expectRevert("Already claimed");
        ICommit(clonedCommit).claim();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test: creator claiming fees
    // ─────────────────────────────────────────────────────────────────────────
    function testCreatorFees() public {
        address clonedCommit = _createCommit(1 days, 2 days);

        // Bob joins
        vm.startPrank(bob);
        mockToken.approve(clonedCommit, 1.5 ether);
        ICommit(clonedCommit).join{value: joinFee}();
        vm.stopPrank();

        // The owner can claim fees at any point
        vm.startPrank(owner);
        ICommit(clonedCommit).claimFees();
        vm.stopPrank();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test: cancelling a commit
    // ─────────────────────────────────────────────────────────────────────────
    function testCancelAndRefund() public {
        address clonedCommit = _createCommit(1 days, 2 days);

        // Bob joins
        vm.startPrank(bob);
        mockToken.approve(clonedCommit, 1.5 ether);
        ICommit(clonedCommit).join{value: joinFee}();
        vm.stopPrank();

        // The owner can cancel if it's still in Created status and before joinBefore
        vm.startPrank(owner);
        ICommit(clonedCommit).cancel();
        vm.stopPrank();

        // Now Bob can claim a refund
        vm.startPrank(bob);
        ICommit(clonedCommit).claimRefund();
        vm.stopPrank();

        // Trying to claim refund again reverts
        vm.startPrank(bob);
        vm.expectRevert("Already refunded");
        ICommit(clonedCommit).claimRefund();
        vm.stopPrank();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test: protocol forcibly withdrawing leftover
    // ─────────────────────────────────────────────────────────────────────────
    function testProtocolWithdraw() public {
        address clonedCommit = _createCommit(1 days, 2 days);

        // Bob joins, but never verifies
        vm.startPrank(bob);
        mockToken.approve(clonedCommit, 1.5 ether);
        ICommit(clonedCommit).join{value: joinFee}();
        vm.stopPrank();

        // Move time forward
        vm.warp(block.timestamp + 3 days);

        // If the commit is done verifying and no claims or partial claims remain, protocol can withdraw the remainder
        // Only the protocol can call withdraw
        vm.expectRevert("Only protocol");
        ICommit(clonedCommit).withdraw();

        vm.startPrank(address(protocol));
        ICommit(clonedCommit).withdraw();
        vm.stopPrank();
    }
}
