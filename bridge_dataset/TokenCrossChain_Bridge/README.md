# SimpleCrossChainBridge

This repository contains smart contracts for a cross-chain bridge between Layer 1 and Layer 2 of a blockchain network. The bridge allows users to transfer tokens from Layer 1 to Layer 2.

### L1Bridge

`L1Bridge` is a smart contract that operates on Layer 1 of the blockchain network. Its purpose is to lock tokens on Layer 1 and emit an event. The locked tokens are then bridged to Layer 2 using the `L2Bridge` contract.

### L2Bridge

`L2Bridge` is a smart contract that operates on Layer 2 of the blockchain network. Its purpose is to bridge tokens from Layer 1 to Layer 2. The contract need to be initialized the bridge by owner with the address of the ERC20 token contract on Layer 2. Once the bridge is initialized, users can bridge tokens from Layer 1 to Layer 2 by calling the `bridgeTokens` function. Similarly, users can return tokens from Layer 2 to Layer 1 by calling the `returnTokens` function.

## Usage

To use the contracts, developers can deploy them on the blockchain network. The `L1Bridge` contract should be deployed on Layer 1, and the `L2Bridge` contract should be deployed on Layer 2.

It is important to note that the contracts are designed to be used with cross-chain validators. The `onlyCrossChainValidators` modifier restricts access to certain functions to only the cross-chain validators. Developers will need to customize the contracts to suit their specific use case.

## Deployment of Contracts

```
npx hardhat run scripts/deploy.js
```
