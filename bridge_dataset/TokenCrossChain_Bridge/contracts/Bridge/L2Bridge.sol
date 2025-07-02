// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface ICustomTokenL2 {
    /**
     * @dev Mints new tokens and assigns them to the specified recipient.
     * @param recipient The address to receive the newly minted tokens.
     * @param amount The amount of tokens to mint.
     */
    function mint(address recipient, uint256 amount) external;

    /**
     * @dev Burns a specific amount of tokens.
     * @param amount The amount of tokens to burn.
     */
    function burn(uint256 amount) external;

    /**
     * @dev Burns a specific amount of tokens from the specified account.
     * @param account The address of the account that will have tokens burned.
     * @param amount The amount of tokens to burn.
     */
    function burnFrom(address account, uint256 amount) external;
}

import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title L2Bridge
 * @dev A smart contract for bridging tokens from Layer 1 to Layer 2.
 */
contract L2Bridge is Ownable {
    event BridgeInitialized(uint indexed timestamp);
    event TokensBridged(
        address indexed receiver,
        bytes32 indexed layer1DepositHash,
        uint amount,
        uint timestamp
    );
    event TokensReturned(
        address indexed receiver,
        bytes32 indexed layer2DepositHash,
        uint amount,
        uint timestamp
    );

    ICustomTokenL2 private tokenL2;
    bool public bridgeInitialized;
    address public crossChainValidator;

    /**
     * @dev Modifier to check if the bridge has been initialized.
     */
    modifier isBridgeInitialized() {
        require(bridgeInitialized, "Bridge has not been initialized");
        _;
    }

    /**
     * @dev Modifier to restrict access to cross-chain validators only.
     */
    modifier onlyCrossChainValidators() {
        require(
            msg.sender == crossChainValidator,
            "Only crossChainValidator can execute this function"
        );
        _;
    }

    /**
     * @dev Constructor function for L2Bridge.
     * @param _crossChainValidator The address of the cross-chain validator contract.
     */
    constructor(address _crossChainValidator) {
        crossChainValidator = _crossChainValidator;
    }

    /**
     * @dev Initializes the bridge with the address of the ERC20 token contract on Layer 2.
     * @param _l2Token The address of the ERC20 token contract on Layer 2.
     */
    function initializeBridge(address _l2Token) external onlyOwner {
        tokenL2 = ICustomTokenL2(_l2Token);
        bridgeInitialized = true;
    }

    /**
     * @dev Bridges tokens from Layer 1 to Layer 2 and emits an event.
     * @param _receiver The address of the receiver of the bridged tokens.
     * @param _bridgedAmount The amount of tokens to be bridged.
     * @param _layer1DepositHash The deposit hash generated on Layer 1.
     */
    function bridgeTokens(
        address _receiver,
        uint _bridgedAmount,
        bytes32 _layer1DepositHash
    ) external isBridgeInitialized onlyCrossChainValidators {
        tokenL2.mint(_receiver, _bridgedAmount);
        emit TokensBridged(
            _receiver,
            _layer1DepositHash,
            _bridgedAmount,
            block.timestamp
        );
    }

    /**
     * @dev Returns tokens from Layer 2 to Layer 1 and emits an event.
     * @param _receiver The address of the receiver of the returned tokens.
     * @param _bridgedAmount The amount of tokens to be returned.
     * @param _layer2DepositHash The deposit hash generated on Layer 2.
     */
    function returnTokens(
        address _receiver,
        uint _bridgedAmount,
        bytes32 _layer2DepositHash
    ) external isBridgeInitialized onlyCrossChainValidators {
        tokenL2.burn(_bridgedAmount);
        emit TokensReturned(
            _receiver,
            _layer2DepositHash,
            _bridgedAmount,
            block.timestamp
        );
    }
}
