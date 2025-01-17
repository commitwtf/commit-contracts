// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ERC1155Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC1155/ERC1155Upgradeable.sol";
import {ERC1155SupplyUpgradeable} from
    "@openzeppelin/contracts-upgradeable/token/ERC1155/extensions/ERC1155SupplyUpgradeable.sol";
import {ERC1155PausableUpgradeable} from
    "@openzeppelin/contracts-upgradeable/token/ERC1155/extensions/ERC1155PausableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {TokenUtils} from "./libraries/TokenUtils.sol";
import {IVerifier} from "./interfaces/IVerifier.sol";

/// @title CommitProtocolV04
/// @notice Enables users to create and participate in commitment-based challenges

contract CommitProtocolV04 is
    UUPSUpgradeable,
    ReentrancyGuardUpgradeable,
    OwnableUpgradeable,
    ERC1155Upgradeable,
    ERC1155PausableUpgradeable,
    ERC1155SupplyUpgradeable
{
    using EnumerableSet for EnumerableSet.AddressSet;

    function initialize(address initialOwner) public initializer {
        __Ownable_init(initialOwner);
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
        __ERC1155Pausable_init();
        __ERC1155_init("");
    }

    event TokenApproved(address indexed token, bool isApproved);
    event Created(uint256 indexed commitId, Commit config);
    event Funded(uint256 indexed commitId, address indexed funder, address indexed token, uint256 amount);
    event Joined(uint256 indexed commitId, address indexed participant);
    event Verified(uint256 indexed commitId, address indexed participant, bool isVerified);
    event Claimed(uint256 indexed commitId, address indexed participant, address indexed token, uint256 amount);
    event Withdraw(address indexed recipient, address indexed token, uint256 amount);
    event Cancelled(uint256 indexed commitId);
    event Refunded(uint256 indexed commitId, address indexed participant, address indexed token, uint256 amount);

    error TokenNotApproved(address token);
    error MaxShareReached();
    error InvalidCommitConfig(string reason);
    error CommitClosed(uint256 commitId, string phase);
    error InvalidCommitStatus(uint256 commitId, string reason);
    error InvalidParticipantStatus(uint256 commitId, address participant, string reason);
    error MaxParticipantsReached(uint256 commitId);
    error NoVerified(uint256 commitId);
    error InvalidCommitCreator(uint256 commitId);

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
        address creator; // Creator of the commit
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

    enum CommitStatus {
        created,
        resolved,
        cancelled
    }

    enum ParticipantStatus {
        init, // Participant has not joined
        joined, // Participant has staked and joined
        verified, // Participant successfully verified
        claimed // Participant has claimed rewards

    }

    // Protocol-wide configuration
    ProtocolConfig public config;

    // Tracks how many commits have been created so far
    uint256 public commitIds;

    // commitId => Commit data
    mapping(uint256 => Commit) public commits;

    // commitId => Commit status
    mapping(uint256 => CommitStatus) public status;

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

    // commitId => TokenSet for each commit
    mapping(uint256 => EnumerableSet.AddressSet) private commitTokens;

    // Max share for protocol + client combined (15%)
    uint256 public constant MAX_SHARE_BPS = 1500;

    // Storage gap for future upgrades
    uint256[50] private __gap;

    modifier onlyApprovedToken(address token) {
        if (!approvedTokens.contains(token)) {
            revert TokenNotApproved(token);
        }
        _;
    }

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
        if (config.fee.shareBps + commit.client.shareBps > MAX_SHARE_BPS) {
            revert MaxShareReached();
        }
        if (block.timestamp >= commit.joinBefore || commit.joinBefore >= commit.verifyBefore) {
            revert InvalidCommitConfig("now < joinBefore < verifyBefore required");
        }
        if (commit.verifyBefore - block.timestamp >= config.maxCommitDuration) {
            revert InvalidCommitConfig("exceeds maxCommitDuration");
        }

        uint256 commitId = ++commitIds;
        commits[commitId] = commit;

        commitTokens[commitId].add(commit.token);

        // Collect the protocol creation fee in ETH
        TokenUtils.transferFrom(address(0), msg.sender, config.fee.recipient, config.fee.fee);

        emit Created(commitId, commit);
        return commitId;
    }

    /**
     * @notice Participant joins a commit, staking tokens and paying the protocol join fee in ETH.
     * @dev The joinVerifier can be used to apply custom eligibility checks.
     */
    function join(uint256 commitId, bytes calldata data) public payable nonReentrant {
        Commit memory commit = getCommit(commitId);
        if (block.timestamp >= commit.joinBefore) {
            revert CommitClosed(commitId, "join");
        }
        if (participants[commitId][msg.sender] != ParticipantStatus.init) {
            revert InvalidParticipantStatus(commitId, msg.sender, "already-joined");
        }

        participants[commitId][msg.sender] = ParticipantStatus.joined;

        // Enforce max participant limit if set
        if (commit.maxParticipants != 0 && totalSupply(commitId) >= commit.maxParticipants) {
            revert MaxParticipantsReached(commitId);
        }

        // Optionally verify participant’s eligibility
        if (commit.joinVerifier.target != address(0)) {
            bool ok = IVerifier(commit.joinVerifier.target).verify(msg.sender, commit.joinVerifier.data, data);
            if (!ok) {
                revert InvalidParticipantStatus(commitId, msg.sender, "not-eligible-join");
            }
        }

        // Pay protocol join fee in ETH
        TokenUtils.transferFrom(address(0), msg.sender, config.fee.recipient, config.fee.fee);

        // Add participant stake
        funds[commit.token][commitId] += commit.stake;

        // Set aside creator fee to claims
        claims[commit.token][commit.creator] += commit.fee;

        // Transfer stake + creator fee to this contract
        TokenUtils.transferFrom(commit.token, msg.sender, address(this), commit.stake + commit.fee);

        // Mint an ERC1155 token representing this commit for the participant
        _mint(msg.sender, commitId, 1, "");

        emit Joined(commitId, msg.sender);
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
        if (block.timestamp >= commit.verifyBefore) {
            revert CommitClosed(commitId, "verify");
        }

        commitTokens[commitId].add(token);

        // Transfer tokens into the commit’s pool
        funds[token][commitId] += amount;
        TokenUtils.transferFrom(token, msg.sender, address(this), amount);
        emit Funded(commitId, msg.sender, token, amount);
    }

    /**
     * @notice Anyone can call verify to confirm a participant has completed their commit.
     */
    function verify(uint256 commitId, address participant, bytes calldata data) public payable returns (bool) {
        Commit memory c = getCommit(commitId);
        if (block.timestamp >= c.verifyBefore) {
            revert CommitClosed(commitId, "verify");
        }
        if (participants[commitId][participant] != ParticipantStatus.joined) {
            revert InvalidParticipantStatus(commitId, participant, "not-joined");
        }
        // Use fulfillVerifier to check if participant truly completed the commit
        bool ok = IVerifier(c.fulfillVerifier.target).verify(participant, c.fulfillVerifier.data, data);

        // If successful, mark them as verified
        if (ok) {
            participants[commitId][participant] = ParticipantStatus.verified;
            verifiedCount[commitId]++;
        }

        emit Verified(commitId, participant, ok);
        return ok;
    }

    /**
     * @notice Verified participants can claim their reward. The reward is distributed
     *         proportionally among verified users (minus protocol/client fees).
     */
    function claim(uint256 commitId, address participant) public payable nonReentrant {
        if (participants[commitId][participant] != ParticipantStatus.verified) {
            revert InvalidParticipantStatus(commitId, participant, "not-verified");
        }
        participants[commitId][participant] = ParticipantStatus.claimed;

        // Distribute for each approved token used by the commit
        uint256 length = commitTokens[commitId].length();
        for (uint256 i = 0; i < length; i++) {
            address token = commitTokens[commitId].at(i);

            // Calculate distribution if not done already
            if (rewards[token][commitId] == 0) {
                distribute(commitId, token);
            }

            uint256 reward = rewards[token][commitId];
            // Transfer reward to participant
            if (reward > 0) {
                TokenUtils.transfer(token, participant, reward);
                emit Claimed(commitId, participant, token, reward);
            }
        }
        status[commitId] = CommitStatus.resolved;
    }

    /**
     * @notice Splits the total pool of tokens among verified participants, allocating fee shares
     *         to the protocol and client.
     */
    function distribute(uint256 commitId, address token) public {
        Commit memory commit = getCommit(commitId);
        if (block.timestamp <= commit.verifyBefore) {
            revert CommitClosed(commitId, "verify still open");
        }
        if (verifiedCount[commitId] == 0) {
            revert NoVerified(commitId);
        }

        // Stake + funding
        uint256 amount = funds[token][commitId];
        funds[token][commitId] = 0;

        // Allocate shares to client and protocol
        uint256 clientShare = (amount * commit.client.shareBps) / 10000;
        uint256 protocolShare = (amount * config.fee.shareBps) / 10000;

        // The remainder is split equally among verified participants
        uint256 rewardsPool = amount - clientShare - protocolShare;

        // Update rewards to claim for each verified participant
        rewards[token][commitId] = rewardsPool / verifiedCount[commitId];

        // Add any rounding remainder to protocol
        protocolShare += rewardsPool % verifiedCount[commitId];

        // Update claims
        claims[token][commit.client.recipient] += clientShare;
        claims[token][config.fee.recipient] += protocolShare;
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

    // Commit creator can cancel the commit
    function cancel(uint256 commitId) public {
        Commit memory commit = getCommit(commitId);
        if (msg.sender != commit.creator) {
            revert InvalidCommitCreator(commitId);
        }
        if (block.timestamp >= commit.verifyBefore) {
            revert CommitClosed(commitId, "join");
        }

        status[commitId] = CommitStatus.cancelled;

        emit Cancelled(commitId);
    }

    // Participants can claim refund of cancelled commits
    function refund(uint256 commitId) public nonReentrant {
        Commit memory commit = getCommit(commitId);
        if (status[commitId] != CommitStatus.cancelled) {
            revert InvalidCommitStatus(commitId, "not-cancelled");
        }

        ParticipantStatus currentStatus = participants[commitId][msg.sender];
        if (!(currentStatus == ParticipantStatus.joined || currentStatus == ParticipantStatus.verified)) {
            revert InvalidParticipantStatus(commitId, msg.sender, "not-joined");
        }

        // Update participant status to prevent multiple refunds
        participants[commitId][msg.sender] = ParticipantStatus.claimed;

        // Transfer stake amount to msg.sender
        funds[commit.token][commitId] -= commit.stake;
        TokenUtils.transfer(commit.token, msg.sender, commit.stake);

        emit Refunded(commitId, msg.sender, commit.token, commit.stake);
    }

    function verifyOverride(uint256 commitId, address participant) public onlyOwner {
        if (participants[commitId][participant] == ParticipantStatus.verified) {
            revert InvalidParticipantStatus(commitId, participant, "already-verified");
        }
        participants[commitId][participant] = ParticipantStatus.verified;
        verifiedCount[commitId]++;
    }

    /**
     * @notice Returns the details of a specific commit by ID.
     */
    function getCommit(uint256 commitId) public view returns (Commit memory commit) {
        require(commitId <= commitIds, "Commit not found");
        return commits[commitId];
    }

    /**
     * @notice Allows the owner to approve or revoke approval for a token to be used in commits.
     */
    function approveToken(address token, bool isApproved) public onlyOwner {
        isApproved ? approvedTokens.add(token) : approvedTokens.remove(token);
        emit TokenApproved(token, isApproved);
    }

    /**
     * @notice Returns the approved tokens
     */
    function getApprovedTokens() public view returns (address[] memory) {
        return approvedTokens.values();
    }

    /**
     * @notice Returns the tokens used for a commit
     */
    function getCommitTokens(uint256 commitId) public view returns (address[] memory) {
        return commitTokens[commitId].values();
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

    function pause() public onlyOwner {
        _pause();
    }

    function unpause() public onlyOwner {
        _unpause();
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    // The following functions are overrides required by Solidity.

    function _update(address from, address to, uint256[] memory ids, uint256[] memory values)
        internal
        override(ERC1155Upgradeable, ERC1155PausableUpgradeable, ERC1155SupplyUpgradeable)
    {
        super._update(from, to, ids, values);
    }

    /**
     * @notice Owner-only function to withdraw tokens in emergencies (if needed).
     */
    function emergencyWithdraw(address token, uint256 amount) public onlyOwner {
        TokenUtils.transfer(token, msg.sender, amount);
    }
}
