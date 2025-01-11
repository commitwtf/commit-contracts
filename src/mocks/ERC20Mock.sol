// SPDX-License-Identifier: MIT
pragma solidity ^0.8.2;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract ERC20Mock is ERC20 {
    constructor() ERC20("tUSD", "tUSD") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
