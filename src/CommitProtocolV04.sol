// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {TokenUtils} from "./libraries/TokenUtils.sol";
import {IVerifier} from "./interfaces/IVerifier.sol";
import {CommitProtocolERC1155} from "./CommitProtocolERC1155.sol";

/**
 * @title CommitProtocolV04
 * @notice Handles the creation and management of “Commits,”
 *         where users can stake tokens, complete verifications,
 *         and claim rewards. Supports multiple tokens and flexible fees.
 */
contract CommitProtocolV04 is CommitProtocolERC1155 {
    using EnumerableSet for EnumerableSet.AddressSet;

    // ----------------- Events -----------------
    event ApproveToken(address token, bool isApproved);
    event Created(uint256 commitId, Commit config);
    event Funded(uint256 commitId, address funder, address token, uint256 amount);
    event Joined(uint256 commitId, address participant);
    event Verified(uint256 commitId, address participant, bool isVerified);
    event Claimed(uint256 commitId, address participant, address token, uint256 amount);
    event Withdraw(address recipient, address token, uint256 amount);

    // ----------------- Structs -----------------

    struct ProtocolConfig {
        uint256 maxCommitDuration; // Maximum allowable duration from join to verify
        string baseURI; // Base URI for token metadata
        ProtocolFee fee; // Protocol fee settings
    }

    struct ProtocolFee {
        address recipient; // Collects protocol fees
        uint256 fee; // Flat fee in ETH required to create or join
        uint256 shareBps; // Percentage share taken from staked/funded pools
    }

    struct Commit {
        address owner; // Owner/creator of the commit
        string metadataURI; // Metadata describing the commit
        uint256 joinBefore; // Deadline for participants to join
        uint256 verifyBefore; // Deadline for verifications
        uint256 maxParticipants; // Limit on how many can join (0 = unlimited)
        Verifier joinVerifier; // Logic to verify eligibility to join
        Verifier fulfillVerifier; // Logic to verify commit completion
        address token; // Primary token for stake
        uint256 stake; // Amount each participant must stake
        uint256 fee; // Creator fee (taken from each participant’s stake)
        ClientConfig client; // Optional client fees, e.g. partners or DApps
    }

    struct Verifier {
        address target; // Contract to call for verification logic
        bytes data; // Arguments or config for the verifier
    }

    struct ClientConfig {
        address recipient; // Client’s fee recipient
        uint256 shareBps; // Percentage share the client receives
    }

    enum ParticipantStatus {
        init, // Participant has not joined
        joined, // Participant has staked and joined
        verified, // Participant successfully verified
        claimed // Participant has claimed rewards

    }

    // ----------------- State Variables -----------------

    // Protocol-wide configuration
    ProtocolConfig public config;

    // Tracks how many commits have been created so far
    uint256 public commitIds;

    // commitId => Commit data
    mapping(uint256 => Commit) public commits;

    // commitId => (participant => status)
    mapping(uint256 => mapping(address => ParticipantStatus)) public participants;

    // token => (commitId => total staked + funded)
    mapping(address => mapping(uint256 => uint256)) public funds;

    // token => (recipient => amount) for fees or distributions
    mapping(address => mapping(address => uint256)) public claims;

    // token => (commitId => per-participant reward)
    mapping(address => mapping(uint256 => uint256)) public rewards;

    // commitId => number of verified participants
    mapping(uint256 => uint256) public verifiedCount;

    // Whitelist of tokens allowed for staking/funding
    EnumerableSet.AddressSet private approvedTokens;

    // Max share for protocol + client combined (15%)
    uint256 public immutable MAX_SHARE_BPS = 1500;

    // Storage gap for future upgrades
    uint256[50] private __gap;

    // ----------------- Modifiers -----------------

    modifier onlyApprovedToken(address token) {
        require(approvedTokens.contains(token), "Token not approved");
        _;
    }

    // ----------------- Functions -----------------

    /**
     * @notice Creates a new Commit, requiring a protocol fee in ETH.
     * @param commit The Commit configuration struct.
     * @return commitId The newly created commit’s ID.
     */
    function create(Commit calldata commit)
        public
        payable
        whenNotPaused
        onlyApprovedToken(commit.token)
        returns (uint256)
    {
        require(config.fee.shareBps + commit.client.shareBps <= MAX_SHARE_BPS, "Shares cannot exceed 15%");
        require(
            block.timestamp < commit.joinBefore && commit.joinBefore < commit.verifyBefore, "Validate timestamp error"
        );
        require(commit.verifyBefore - block.timestamp < config.maxCommitDuration, "Max commit duration exceeded");

        uint256 commitId = commitIds++;
        commits[commitId] = commit;

        // Charge a flat protocol creation fee (ETH)
        TokenUtils.transferFrom(address(0), _msgSender(), config.fee.recipient, config.fee.fee);

        emit Created(commitId, commit);
        return commitId;
    }

    /**
     * @notice Participant joins a commit, staking tokens and paying the protocol join fee in ETH.
     * @dev The joinVerifier can be used to apply custom eligibility checks.
     */
    function join(uint256 commitId, bytes calldata data) public payable nonReentrant {
        Commit memory commit = getCommit(commitId);
        require(block.timestamp < commit.joinBefore, "Join period ended");
        require(participants[commitId][_msgSender()] == ParticipantStatus.init, "Already joined");
        participants[commitId][_msgSender()] = ParticipantStatus.joined;

        // Enforce max participant limit if set
        require(
            commit.maxParticipants == 0 || totalSupply(commitId) < commit.maxParticipants,
            "Max participants have already joined"
        );

        // Optionally verify participant’s eligibility
        if (commit.joinVerifier.target != address(0)) {
            bool verified = IVerifier(commit.joinVerifier.target).verify(_msgSender(), commit.joinVerifier.data, data);
            require(verified, "Not verified to join");
        }

        // Pay protocol join fee in ETH
        TokenUtils.transferFrom(address(0), _msgSender(), config.fee.recipient, config.fee.fee);

        // Add participant stake
        funds[commit.token][commitId] += commit.stake;

        // Set aside creator fee to claims
        claims[commit.token][commit.owner] += commit.fee;

        // Transfer stake + creator fee to this contract
        TokenUtils.transferFrom(commit.token, _msgSender(), address(this), commit.stake + commit.fee);

        // Mint an ERC1155 token representing this commit for the participant
        _mint(_msgSender(), commitId, 1, "");

        emit Joined(commitId, _msgSender());
    }

    /**
     * @notice Allows anyone to fund an existing commit with approved tokens (before verify ends).
     */
    function fund(uint256 commitId, address token, uint256 amount)
        public
        payable
        whenNotPaused
        onlyApprovedToken(token)
    {
        Commit memory commit = getCommit(commitId);
        require(block.timestamp < commit.verifyBefore, "Verification period ended");

        // Transfer tokens into the commit’s pool
        funds[token][commitId] += amount;
        TokenUtils.transferFrom(token, _msgSender(), address(this), amount);
        emit Funded(commitId, _msgSender(), token, amount);
    }

    /**
     * @notice Anyone can call verify to confirm a participant has completed their commit.
     */
    function verify(uint256 commitId, address participant, bytes calldata data) public payable returns (bool) {
        Commit memory commit = getCommit(commitId);
        require(block.timestamp < commit.verifyBefore, "Verification period ended");
        require(participants[commitId][participant] == ParticipantStatus.joined, "Already verified");

        // Use fulfillVerifier to check if participant truly completed the commit
        bool verified = IVerifier(commit.fulfillVerifier.target).verify(participant, commit.fulfillVerifier.data, data);

        // If successful, mark them as verified
        if (verified) {
            participants[commitId][participant] = ParticipantStatus.verified;
        }

        verifiedCount[commitId]++;
        emit Verified(commitId, participant, verified);
        return verified;
    }

    /**
     * @notice Verified participants can claim their reward. The reward is distributed
     *         proportionally among verified users (minus protocol/client fees).
     */
    function claim(uint256 commitId, address participant) public payable nonReentrant {
        require(participants[commitId][participant] == ParticipantStatus.verified, "Must be verified");
        participants[commitId][participant] = ParticipantStatus.claimed;

        // Distribute for each approved token
        uint256 length = approvedTokens.length();
        for (uint256 i = 0; i < length; i++) {
            address token = approvedTokens.at(i);

            // Calculate distribution if not done already
            if (rewards[token][commitId] == 0) {
                distribute(commitId, token);
            }

            uint256 amount = rewards[token][commitId];
            // Transfer reward to participant
            if (amount > 0) {
                TokenUtils.transfer(token, participant, amount);
                emit Claimed(commitId, participant, token, amount);
            }
        }
    }

    /**
     * @notice Splits the total pool of tokens among verified participants, allocating fee shares
     *         to the protocol and client.
     */
    function distribute(uint256 commitId, address token) public {
        Commit memory commit = getCommit(commitId);
        require(block.timestamp > commit.verifyBefore, "Still verifying");
        require(verifiedCount[commitId] > 0, "No verified participants");

        uint256 amount = funds[token][commitId];

        // Allocate shares to client and protocol
        uint256 clientShare = (amount * commit.client.shareBps) / 10000;
        uint256 protocolShare = (amount * config.fee.shareBps) / 10000;

        claims[token][commit.client.recipient] += clientShare;
        claims[token][config.fee.recipient] += protocolShare;

        // The remainder is split equally among verified participants
        uint256 rewardsPool = amount - clientShare - protocolShare;
        funds[token][commitId] = 0;
        rewards[token][commitId] = rewardsPool / verifiedCount[commitId];
    }

    /**
     * @notice Allows creators, clients, and the protocol to withdraw their accumulated fee claims.
     */
    function withdraw(address token, address account) public payable nonReentrant {
        uint256 amount = claims[token][account];
        claims[token][account] = 0;
        TokenUtils.transfer(token, account, amount);
        emit Withdraw(account, token, amount);
    }

    /**
     * @notice Returns the details of a specific commit by ID.
     */
    function getCommit(uint256 commitId) public view returns (Commit memory commit) {
        require(commitId < commitIds, "Commit not found");
        return commits[commitId];
    }

    /**
     * @notice Allows the owner to approve or revoke approval for a token to be used in commits.
     */
    function approveToken(address token, bool isApproved) public onlyOwner {
        isApproved ? approvedTokens.add(token) : approvedTokens.remove(token);
        emit ApproveToken(token, isApproved);
    }

    /**
     * @dev Sets the base URI for the ERC1155 tokens.
     * for example: https://commit.wtf/api/commit/{id}.json
     * this endpoint will dynamically generate the metadata based on token status (verified, claimed, rewards etc)
     */
    function setURI(string memory uri) public onlyOwner {
        _setURI(uri);
    }

    /**
     * @notice Allows the owner to update the protocol-wide config.
     */
    function setProtocolConfig(ProtocolConfig calldata _c) public onlyOwner {
        config = _c;
    }

    /**
     * @notice Owner-only function to withdraw tokens in emergencies (if needed).
     */
    function emergencyWithdraw(address token, uint256 amount) public onlyOwner {
        TokenUtils.transfer(token, _msgSender(), amount);
    }
}
