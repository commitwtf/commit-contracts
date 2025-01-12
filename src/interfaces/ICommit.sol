// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface ICommit {
    event Join(address participant, uint256 tokenId);
    event Fund(address token, address from, address to, uint256 amount);
    event Verify(address participant, bool isVerified);
    event Claim(address participant, address token, uint256 amount);
    event ClaimFees(address creator, address token, uint256 amount);
    event Cancel();
    event Refund(address participant, address token, uint256 amount);

    enum Status {
        Init,
        Created,
        Resolved,
        Cancelled
    }

    // Structs
    struct Config {
        address owner;
        // Commit details
        string metadataURI; // { title, image, description, tags } - Use a standard NFT format
        // Commit period
        uint256 joinBefore; // or startsAt ?
        uint256 verifyBefore; // or endsAt ? (is this superseded by milestones?)
        // Verifier
        address verifier; // Verifier strategy contract (EAS, Signature, Token)
        bytes verifierData; // Passed to Verifier contract (schemaUID, attester, tokenAddress etc)
        // Stake and fees
        address token;
        uint256 stake; // Cost to join Commit
        uint256 fee; // Creator fee
        // Referals
        uint256 maxParticipants; // (Optional) Limit how many participants can join (this just sets the ERC721 supply)
        ClientConfig client;
        // Note: Milestones not implemented yet
        Milestone[] milestones; // (Optional) Define milestones
    }

    struct ClientConfig {
        address recipient;
        uint256 fee;
        uint256 share;
    }

    struct Milestone {
        uint256 deadline; // Timestamp when participant must verify before
        string metadataURI; // (Optional) Details about milestone
    }

    function initialize(Config calldata _config, address _protocol) external;

    // Commits can be funded with additional tokens to be rewarded to verified participants
    function fund(uint256 amount) external payable;

    // Participants can join a Commit by staking funds (mints NFT)
    function join() external payable;

    // Participants can verify they've completed a commit (use simulate to check status without paying gas)
    // Sets verified[address] = true (or verified[address][milestoneIndex] = true)
    function verify(address participant, bytes calldata data) external returns (bool);

    // Verified participants can claim their share of the rewards (stake + rewards)
    // Verifies each milestone?
    function claim() external;

    // Creator can claim fees at any point during the Commit cycle
    function claimFees() external;

    // Participants can claim refund on cancelled commits
    function claimRefund() external;

    // Creator can cancel a commitment and return stakeAmounts to participants
    function cancel() external;

    // Protocol can withdraw funds if needed
    function withdraw() external;
}
