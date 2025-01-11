// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {TokenUtils} from "./libraries/TokenUtils.sol";
import {ICommit} from "./interfaces/ICommit.sol";
import {IVerifier} from "./interfaces/IVerifier.sol";
import {ICommitProtocolV04} from "./CommitProtocolV04.sol";

contract CommitV04 is ICommit, ERC721, Ownable, ReentrancyGuard {
    Config public config;
    Status public status;
    ICommitProtocolV04 public protocol;

    uint256 private _nextTokenId;
    uint256 public creatorFees;
    uint256 public verifiedCount;
    uint256 public finalDistributionAmount;
    uint256 public rewardsAmount;

    address[] public participants;
    mapping(address => bool) public isParticipant;
    mapping(address => bool) public isVerified;
    mapping(address => bool) public isClaimed;

    constructor() ERC721("Commit", "Commit") Ownable(_msgSender()) {}

    function initialize(Config calldata _config, address _protocol) external {
        require(status == Status.Init, "Already initialized");
        require(msg.sender == _protocol, "Only protocol can initialize");
        require(_config.joinBefore < _config.verifyBefore, "Invalid deadlines");
        require(_config.verifier != address(0), "Invalid verifier");
        require(
            config.client.share <= 10000, // TODO: What's the max value?
            "Client share must not exceed the max value"
        );
        config = _config;
        protocol = ICommitProtocolV04(payable(_protocol));
        _transferOwnership(config.owner);
        status = Status.Created;
    }

    function fund(
        uint256 _amount
    ) external payable nonReentrant onlyActiveCommit {
        TokenUtils.transferFrom(
            config.token,
            _msgSender(),
            address(this),
            _amount
        );
        emit Fund(config.token, _msgSender(), address(this), _amount);
    }

    function join() external payable nonReentrant onlyActiveCommit {
        require(block.timestamp < config.joinBefore, "Join deadline passed");
        require(!isParticipant[_msgSender()], "Already joined");
        require(
            config.maxParticipants == 0 ||
                _nextTokenId < config.maxParticipants,
            "Max participants reached"
        );

        ICommitProtocolV04.ProtocolConfig memory pc = protocol
            .getProtocolConfig();

        // Protocol fee in ETH
        (bool success, ) = payable(pc.feeAddress).call{value: pc.joinFee}("");
        require(success, "Protocol fee transfer failed");

        // Handle stake and fees
        creatorFees += config.fee;
        uint256 totalCost = config.stake + config.fee + config.client.fee;
        TokenUtils.transferFrom(
            config.token,
            _msgSender(),
            address(this),
            totalCost
        );

        // Transfer client fee if configured
        if (config.client.fee > 0 && config.client.recipient != address(0)) {
            TokenUtils.transfer(
                config.token,
                config.client.recipient,
                config.client.fee
            );
        }

        _mint(_msgSender());
    }

    // TODO: Verify can be called by anyone for any participant (supports subject commits)
    function verify(
        address _participant,
        bytes calldata data
    ) external nonReentrant onlyActiveCommit returns (bool) {
        require(isParticipant[_participant], "Not a participant");
        require(!isVerified[_participant], "Already verified");
        require(block.timestamp <= config.verifyBefore, "Verification ended");

        bool verified = IVerifier(config.verifier).verify(
            _participant,
            config.verifierData,
            data
        );
        require(verified, "Not verified");

        verifiedCount++;
        isVerified[_participant] = true;
        emit Verify(_participant, verified);

        return verified;
    }

    function claim() external nonReentrant {
        if (rewardsAmount == 0) {
            require(
                block.timestamp > config.verifyBefore,
                "Verification ongoing"
            );
            _calculateRewards();
            status = Status.Resolved;
        }

        require(rewardsAmount > 0, "No distribution set");
        require(isVerified[_msgSender()], "Not verified");
        require(!isClaimed[_msgSender()], "Already claimed");

        isClaimed[_msgSender()] = true;
        TokenUtils.transfer(config.token, _msgSender(), rewardsAmount);
        emit Claim(_msgSender(), config.token, rewardsAmount);
    }

    function _calculateRewards() private {
        uint256 currentBalance = TokenUtils.balanceOf(
            config.token,
            address(this)
        );
        uint256 stakePool = currentBalance - creatorFees;

        ICommitProtocolV04.ProtocolConfig memory pc = protocol
            .getProtocolConfig();

        // Calculate shares
        uint256 protocolShare = (stakePool * pc.share) / 10000;
        uint256 clientShare = (stakePool * config.client.share) / 10000;

        // Transfer protocol share
        if (protocolShare > 0) {
            TokenUtils.transfer(config.token, pc.feeAddress, protocolShare);
        }

        // Transfer client share
        if (clientShare > 0 && config.client.recipient != address(0)) {
            TokenUtils.transfer(
                config.token,
                config.client.recipient,
                clientShare
            );
        }

        // Calculate participant rewards
        uint256 participantPool = stakePool - protocolShare - clientShare;
        if (verifiedCount > 0) {
            rewardsAmount = participantPool / verifiedCount;
            uint256 remainder = participantPool % verifiedCount;
            if (remainder > 0) {
                creatorFees += remainder;
            }
            TokenUtils.transfer(config.token, config.owner, creatorFees);
        }

        finalDistributionAmount = participantPool;
    }

    function claimFees() external nonReentrant onlyOwner {
        require(creatorFees > 0, "No fees to claim");
        uint256 amount = creatorFees;
        creatorFees = 0;

        TokenUtils.transfer(config.token, owner(), amount);
        emit ClaimFees(owner(), config.token, amount);
    }

    function cancel() external onlyOwner nonReentrant {
        require(status == Status.Created, "Not in created state");
        require(
            block.timestamp < config.joinBefore,
            "Cannot cancel after joinBefore"
        );

        status = Status.Cancelled;
        emit Cancel();
    }

    function claimRefund() external nonReentrant {
        require(status == Status.Cancelled, "Commit not cancelled");
        require(isParticipant[_msgSender()], "Not a participant");
        require(!isClaimed[_msgSender()], "Already refunded");

        isClaimed[_msgSender()] = true;
        TokenUtils.transfer(config.token, _msgSender(), config.stake);
        emit Refund(_msgSender(), config.token, config.stake);
    }

    function withdraw() external nonReentrant {
        require(msg.sender == address(protocol), "Only protocol");
        require(
            block.timestamp > config.verifyBefore,
            "Must be after verification"
        );

        uint256 balance = TokenUtils.balanceOf(config.token, address(this));
        TokenUtils.transfer(
            config.token,
            protocol.getProtocolConfig().feeAddress,
            balance
        );
    }

    function _mint(address to) internal {
        uint256 tokenId = _nextTokenId++;
        _safeMint(to, tokenId);
        isParticipant[to] = true;
        participants.push(to);
        emit Join(to, tokenId);
    }

    function getConfig() external view returns (Config memory) {
        return config;
    }

    function tokenURI(
        uint256 tokenId
    ) public view override returns (string memory) {
        return protocol.tokenURI(address(this), tokenId);
    }

    modifier onlyActiveCommit() {
        require(status == Status.Created, "Not active");
        _;
    }
}
