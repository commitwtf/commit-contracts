// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title TokenUtils
 * @notice A library to unify the handling of native ETH and ERC20 transfers,
 *         using OpenZeppelin's SafeERC20 for robust token operations.
 */
library TokenUtils {
    using SafeERC20 for IERC20;

    /**
     * @dev Transfers tokens or ETH to a recipient.
     * @param token The address of the token to transfer. Use address(0) for native ETH.
     * @param to The recipient address.
     * @param amount The amount to transfer.
     */
    function transfer(address token, address to, uint256 amount) internal {
        if (token == address(0)) {
            // Transfer native ETH
            (bool success, ) = payable(to).call{value: amount}("");
            require(success, "ETH transfer failed");
        } else {
            // Transfer ERC20 token safely
            IERC20(token).safeTransfer(to, amount);
        }
    }

    /**
     * @dev Transfers tokens or ETH from a sender to a recipient.
     * @param token The address of the token to transfer. Use address(0) for native ETH.
     * @param from The sender address.
     * @param to The recipient address.
     * @param amount The amount to transfer.
     *
     * NOTE: For native ETH (`token == address(0)`), this library expects that
     *       the caller has already sent ETH along with the transaction (`msg.value == amount`).
     */
    function transferFrom(
        address token,
        address from,
        address to,
        uint256 amount
    ) internal {
        if (token == address(0)) {
            // For ETH, the 'from' address must match msg.sender
            require(from == msg.sender, "Sender mismatch for ETH transfer");
            require(msg.value == amount, "Incorrect ETH amount sent");

            // ETH already received with the call, so we just forward it to 'to'
            (bool success, ) = payable(to).call{value: amount}("");
            require(success, "ETH transfer failed");
        } else {
            // Safe transferFrom for ERC20 token
            IERC20(token).safeTransferFrom(from, to, amount);
        }
    }

    function balanceOf(
        address token,
        address account
    ) internal view returns (uint256) {
        if (token == address(0)) {
            return address(account).balance;
        } else {
            return IERC20(token).balanceOf(account);
        }
    }
}
