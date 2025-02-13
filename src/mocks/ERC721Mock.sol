// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";

contract ERC721Mock is ERC721 {
    constructor() ERC721("tNFT", "tNFT") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
