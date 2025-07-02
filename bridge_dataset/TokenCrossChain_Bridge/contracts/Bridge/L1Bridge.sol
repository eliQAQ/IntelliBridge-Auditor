// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title L1Bridge
 * @dev A smart contract for bridging tokens from Layer 1 to Layer 2.
 */
contract L1Bridge {
    IERC20 private tokenL1;

    address public crossChainValidators;

    event TokensLocked(
        address indexed requester,
        bytes32 indexed layer1DepositHash,
        uint amount,
        uint timestamp
    );

    event TokensUnlocked(
        address indexed requester,
        bytes32 indexed sideDepositHash,
        uint amount,
        uint timestamp
    );

    /**
     * @dev Modifier to restrict access to cross-chain validators only.
     */
    modifier onlyCrossChainValidators() {
        require(
            msg.sender == crossChainValidators,
            "only crossChainValidators can execute this function"
        );
        _;
    }

    /**
     * @dev Constructor function for Layer1Bridge.
     * @param _tokenL1 The address of the ERC20 token contract on Layer 1.
     * @param _crossChainValidators The address of the cross-chain crossChainValidators contract.
     */
    constructor(address _tokenL1, address _crossChainValidators) {
        tokenL1 = IERC20(_tokenL1);
        crossChainValidators = _crossChainValidators;
    }

    /**
     * @dev Locks tokens on Layer 1 and emits an event.
     * @param _receiver The address of the receiver of the bridged tokens.
     * @param _bridgedAmount The amount of tokens to be bridged.
     * @param _layer1DepositHash The deposit hash generated on Layer 1.
     */
    function lockTokens(
        address _receiver,
        uint _bridgedAmount,
        bytes32 _layer1DepositHash
    ) external onlyCrossChainValidators {
        tokenL1.transferFrom(_receiver, address(this), _bridgedAmount);
        emit TokensLocked(
            _receiver,
            _layer1DepositHash,
            _bridgedAmount,
            block.timestamp
        );
    }

    /**
     * @dev Unlocks tokens on Layer 1 and emits an event.
     * @param _receiver The address of the receiver of the unlocked tokens.
     * @param _bridgedAmount The amount of tokens to be unlocked.
     * @param _layer2DepositHash The deposit hash generated on Layer 2.
     */
    function unlockTokens(
        address _receiver,
        uint _bridgedAmount,
        bytes32 _layer2DepositHash
    ) external onlyCrossChainValidators {
        tokenL1.transfer(_receiver, _bridgedAmount);
        emit TokensUnlocked(
            _receiver,
            _layer2DepositHash,
            _bridgedAmount,
            block.timestamp
        );
    }
}
