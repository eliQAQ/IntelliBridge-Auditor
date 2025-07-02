// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title CustomToken
 * @dev A custom ERC20 token contract with mint functionality,
 *      only accessible by the owner.
 */
contract CustomToken is ERC20, Ownable {
    constructor() ERC20("CustomToken", "CTK") {}

    /**
     * @dev Mints new tokens and assigns them to the specified account.
     * @param account The address to receive the newly minted tokens.
     * @param amount The amount of tokens to mint.
     */
    function mint(address account, uint256 amount) external onlyOwner {
        _mint(account, amount);
    }
}
