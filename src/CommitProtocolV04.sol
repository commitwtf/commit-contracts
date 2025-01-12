// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {TokenUtils} from "./libraries/TokenUtils.sol";
import {IVerifier} from "./interfaces/IVerifier.sol";
import {CommitProtocolERC1155} from "./CommitProtocolERC1155.sol";

contract CommitProtocolV04 is CommitProtocolERC1155 {
    using EnumerableSet for EnumerableSet.AddressSet;

    event ApproveToken(address token, bool isApproved);
    event Created(uint256 commitId, Commit config);
    event Funded(
        uint256 commitId,
        address funder,
        address token,
        uint256 amount
    );
    event Joined(uint256 commitId, address participant);
    event Verified(uint256 commitId, address participant, bool isVerified);
    event Claimed(
        uint256 commitId,
        address participant,
        address token,
        uint256 amount
    );
    event Withdraw(address recipient, address token, uint256 amount);

    struct ProtocolConfig {
        uint256 maxCommitDuration;
        string baseURI;
        ProtocolFee fee;
    }
    struct ProtocolFee {
        address recipient;
        uint256 fee;
        uint256 shareBps;
    }

    struct Commit {
        address owner;
        // Commit details
        string metadataURI; // { title, image, description, tags } - Use a standard NFT format
        // Commit period
        uint256 joinBefore;
        uint256 verifyBefore;
        uint256 maxParticipants; // (Optional) Limit how many participants can join (this just sets the ERC721 supply)
        // Verifiers
        Verifier joinVerifier;
        Verifier fulfillVerifier;
        // Stake
        address token;
        uint256 stake; // Cost to join Commit
        // Fees
        uint256 fee; // Creator fee
        ClientConfig client; // Partners building Apps can earn shares of stakes + fundings
    }
    struct Verifier {
        address target;
        bytes data;
    }
    struct ClientConfig {
        address recipient;
        uint256 shareBps;
    }
    enum ParticipantStatus {
        init,
        joined,
        verified,
        claimed
    }

    ProtocolConfig public config;

    uint256 public commitIds;
    mapping(uint256 => Commit) public commits;

    // participants[commitId][participant] = status
    mapping(uint256 => mapping(address => ParticipantStatus))
        public participants;

    // Mappings for funds[token][recipient] = amount
    mapping(address => mapping(uint256 => uint256)) public funds;
    mapping(address => mapping(address => uint256)) public claims;
    mapping(address => mapping(uint256 => uint256)) public rewards;

    mapping(uint256 => uint256) public verifiedCount;

    EnumerableSet.AddressSet private approvedTokens;

    uint256[50] private __gap;

    modifier onlyApprovedToken(address token) {
        require(approvedTokens.contains(token), "Token not approved");
        _;
    }

    function create(
        Commit calldata commitConfig
    ) public payable whenNotPaused onlyApprovedToken(commitConfig.token) {
        uint256 commitId = commitIds++;
        commits[commitId] = commitConfig;

        // Transfer protocol create fee (ETH)
        TokenUtils.transferFrom(
            address(0),
            _msgSender(),
            config.fee.recipient,
            config.fee.fee
        );

        emit Created(commitId, commitConfig);
    }

    // Participants can join Commits - cost is stake + fees
    function join(
        uint256 commitId,
        bytes calldata data
    ) public payable nonReentrant {
        require(
            participants[commitId][_msgSender()] == ParticipantStatus.init,
            "Already joined"
        );
        participants[commitId][_msgSender()] = ParticipantStatus.joined;

        Commit memory commit = getCommit(commitId);

        require(
            commit.maxParticipants == 0 ||
                totalSupply(commitId) < commit.maxParticipants,
            "Max participants have already joined"
        );
        require(block.timestamp < commit.joinBefore, "Join period ended");

        // Check the conditions to join the Commit (ie token holdings, attestation, signature, etc)
        if (commit.joinVerifier.target != address(0)) {
            bool verified = IVerifier(commit.joinVerifier.target).verify(
                _msgSender(),
                commit.joinVerifier.data,
                data
            );
            require(verified, "Not verified to join");
        }

        // Transfer protocol join fee (ETH)
        TokenUtils.transferFrom(
            address(0),
            _msgSender(),
            config.fee.recipient,
            config.fee.fee
        );

        // Add stake to Commit funds
        funds[commit.token][commitId] += commit.stake;

        // Set aside creator fee to be claimed
        claims[commit.token][commit.owner] += commit.fee;

        // Transfer stake + creator fee
        TokenUtils.transferFrom(
            commit.token,
            _msgSender(),
            address(this),
            commit.stake + commit.fee
        );

        // Mint ERC1155 NFT
        _mint(_msgSender(), commitId, 1, "");

        emit Joined(commitId, _msgSender());
    }

    // Anyone can verify a participant - the verifier contract checks validity
    function verify(
        uint256 commitId,
        address participant,
        bytes calldata data
    ) public payable returns (bool) {
        require(
            participants[commitId][participant] == ParticipantStatus.joined,
            "Already verified"
        );

        Commit memory commit = getCommit(commitId);
        require(
            block.timestamp < commit.verifyBefore,
            "Verification period ended"
        );

        // Check the conditions to claim the Commit rewards (ie token holdings, attestation, signature, etc)
        bool verified = IVerifier(commit.fulfillVerifier.target).verify(
            participant,
            commit.fulfillVerifier.data,
            data
        );

        // Mark as verified
        if (verified) {
            participants[commitId][participant] = ParticipantStatus.verified;
        }

        emit Verified(commitId, participant, verified);

        verifiedCount[commitId]++;
        return verified;
    }

    // Anyone can fund Commits with approved tokens
    function fund(
        uint256 commitId,
        address token,
        uint256 amount
    ) public payable whenNotPaused onlyApprovedToken(token) {
        Commit memory commit = getCommit(commitId);
        require(
            block.timestamp < commit.verifyBefore,
            "Verification period ended"
        );

        // Add tokens to Commit funds
        funds[token][commitId] += amount;
        TokenUtils.transferFrom(token, _msgSender(), address(this), amount);
        emit Funded(commitId, _msgSender(), token, amount);
    }

    // Verified participants can claim rewards - (funded + stake) / verifiedCount - fees
    function claim(
        uint256 commitId,
        address token
    ) public payable nonReentrant {
        require(
            participants[commitId][_msgSender()] == ParticipantStatus.verified,
            "Must be verified"
        );
        participants[commitId][_msgSender()] = ParticipantStatus.claimed;

        Commit memory commit = getCommit(commitId);
        require(block.timestamp > commit.verifyBefore, "Still verifying");

        uint256 amount = rewards[token][commitId];

        // First claim attempt calculates the rewards
        if (amount == 0) {
            calculate(commitId, token);
        }

        TokenUtils.transfer(token, _msgSender(), amount);
        emit Claimed(commitId, _msgSender(), commit.token, amount);
    }

    // Calculates the reward for a token and Commit
    function calculate(uint256 commitId, address token) public {
        require(verifiedCount[commitId] > 0, "No verified participants");
        Commit memory commit = getCommit(commitId);

        uint256 amount = funds[token][commitId];

        // Set aside Protocol + Creator + Client fees
        uint256 clientShare = (amount * commit.client.shareBps) / 10000;
        uint256 protocolShare = (amount * config.fee.shareBps) / 10000;
        claims[token][commit.client.recipient] += clientShare;
        claims[token][config.fee.recipient] += protocolShare;

        uint256 rewardsPool = amount - clientShare - protocolShare;

        funds[token][commitId] = 0;
        rewards[token][commitId] = rewardsPool / verifiedCount[commitId];
    }

    // Creators, clients, and protocol can withdraw fees
    function withdraw(address token) public payable nonReentrant {
        uint256 amount = claims[token][_msgSender()];
        claims[token][_msgSender()] = 0;
        TokenUtils.transfer(token, _msgSender(), amount);
        emit Withdraw(_msgSender(), token, amount);
    }

    function getCommit(
        uint256 commitId
    ) public view returns (Commit memory commit) {
        require(commitId < commitIds, "Commit not found");
        return commits[commitId];
    }

    function approveToken(address token, bool isApproved) public onlyOwner {
        isApproved ? approvedTokens.add(token) : approvedTokens.remove(token);
        emit ApproveToken(token, isApproved);
    }

    // Set tokenURI for token metadata
    // eg. https://commit.wtf/api/commit/{id}.json - this will dynamically generate the metadata based on token status (verified, claimed, rewards etc)
    function setURI(string memory newuri) public onlyOwner {
        _setURI(newuri);
    }

    function emergencyWithdraw(address token, uint256 amount) public onlyOwner {
        TokenUtils.transfer(token, _msgSender(), amount);
    }
}
