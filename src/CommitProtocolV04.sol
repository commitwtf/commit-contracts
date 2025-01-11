// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {ERC721Pausable} from "@openzeppelin/contracts/token/ERC721/extensions/ERC721Pausable.sol";
import {ERC721URIStorage} from "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {ICommit} from "./interfaces/ICommit.sol";
import {TokenUtils} from "./libraries/TokenUtils.sol";

interface ICommitProtocolV04 {
    struct ProtocolConfig {
        uint256 share;
        uint256 joinFee;
        uint256 createFee;
        uint256 maxDeadlineDuration;
        string baseURI;
        address feeAddress;
    }

    event ApproveToken(address token, bool isApproved);
    event ConfigUpdated();

    event CommitCreated(
        address indexed commitAddress,
        address indexed owner,
        string metadataURI,
        uint256 joinBefore,
        uint256 verifyBefore,
        address verifier,
        address token,
        uint256 stake,
        uint256 fee,
        uint256 maxParticipants
    );

    function getProtocolConfig() external returns (ProtocolConfig memory);

    function tokenURI(
        address commit,
        uint256 tokenId
    ) external view returns (string memory);
}

contract CommitProtocolV04 is
    ICommitProtocolV04,
    UUPSUpgradeable,
    OwnableUpgradeable,
    PausableUpgradeable
{
    using EnumerableSet for EnumerableSet.AddressSet;

    address public commitImplementation;
    ProtocolConfig public protocolConfig;
    EnumerableSet.AddressSet private approvedTokens;

    uint256[50] private __gap;

    function initialize(
        address _commitImplementation,
        ProtocolConfig calldata _protocolConfig
    ) public initializer {
        __Ownable_init(_msgSender());
        __UUPSUpgradeable_init();
        __Pausable_init();
        commitImplementation = _commitImplementation;
        protocolConfig = _protocolConfig;
    }

    receive() external payable {}

    fallback() external payable {}

    function create(
        ICommit.Config calldata _config
    ) external payable whenNotPaused returns (address) {
        require(
            _config.token == address(0) ||
                approvedTokens.contains(_config.token),
            "Token not approved"
        );
        require(
            _config.verifyBefore - block.timestamp <=
                protocolConfig.maxDeadlineDuration,
            "Max deadline duration exceeded"
        );
        require(
            msg.value == protocolConfig.createFee,
            "Incorrect ETH amount for protocol fee"
        );

        TokenUtils.transfer(
            address(0),
            protocolConfig.feeAddress,
            protocolConfig.createFee
        );

        address commitAddress = Clones.clone(commitImplementation);
        emit CommitCreated(
            commitAddress,
            _config.owner,
            _config.metadataURI,
            _config.joinBefore,
            _config.verifyBefore,
            _config.verifier,
            _config.token,
            _config.stake,
            _config.fee,
            _config.maxParticipants
        );
        ICommit(commitAddress).initialize(_config, address(this));

        return commitAddress;
    }

    function tokenURI(
        address commit,
        uint256 tokenId
    ) public view returns (string memory) {
        return
            string(
                abi.encodePacked(
                    protocolConfig.baseURI,
                    Strings.toHexString(uint160(commit), 20),
                    "/",
                    Strings.toString(tokenId)
                )
            );
    }

    function getApprovedTokens() public view returns (address[] memory) {
        return approvedTokens.values();
    }

    function setApprovedToken(address token, bool approved) external onlyOwner {
        approved ? approvedTokens.add(token) : approvedTokens.remove(token);
        emit ApproveToken(token, approved);
    }

    function setImplementation(address _implementation) external onlyOwner {
        require(_implementation != address(0), "Zero address");
        commitImplementation = _implementation;
    }

    function withdraw(
        address token,
        uint256 amount,
        address _recipient
    ) external onlyOwner {
        TokenUtils.transfer(token, _recipient, amount);
    }

    function setProtocolConfig(
        ProtocolConfig calldata _config
    ) external onlyOwner {
        protocolConfig = _config;
        emit ConfigUpdated();
    }

    function getProtocolConfig() external view returns (ProtocolConfig memory) {
        return protocolConfig;
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyOwner {}
}
