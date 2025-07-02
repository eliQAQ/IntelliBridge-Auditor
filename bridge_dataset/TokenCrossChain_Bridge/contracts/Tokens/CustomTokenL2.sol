// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";

/**
 * @title CustomTokenL2
 * @dev A custom ERC20 token contract with burn and mint functionalities,
 *      only accessible by a designated bridge address.
 */
contract CustomTokenL2 is ERC20, ERC20Burnable {
    address public bridgeL2;

    /**
     * @dev Modifier that only allows access from the designated bridge address.
     */
    modifier onlyBridge() {
        require(msg.sender == bridgeL2, "Only Bridge access allowed");
        _;
    }

    /**
     * @dev Constructor function.
     * @param _bridgeL2 The address of the designated bridge contract.
     */
    constructor(address _bridgeL2) ERC20("CustomTokenL2", "CTK") {
        bridgeL2 = _bridgeL2;
    }

    /**
     * @dev Mints new tokens and assigns them to the specified recipient.
     * @param recipient The address to receive the newly minted tokens.
     * @param amount The amount of tokens to mint.
     */
    function mint(address recipient, uint256 amount) public virtual onlyBridge {
        _mint(recipient, amount);
    }

    /**
     * @dev Burns a specific amount of tokens.
     * @param amount The amount of tokens to burn.
     */
    function burn(
        uint256 amount
    ) public virtual override(ERC20Burnable) onlyBridge {
        super.burn(amount);
    }

    /**
     * @dev Burns a specific amount of tokens from the specified account.
     * @param account The address of the account that will have tokens burned.
     * @param amount The amount of tokens to burn.
     */
    function burnFrom(
        address account,
        uint256 amount
    ) public virtual override(ERC20Burnable) onlyBridge {
        super.burnFrom(account, amount);
    }
}
