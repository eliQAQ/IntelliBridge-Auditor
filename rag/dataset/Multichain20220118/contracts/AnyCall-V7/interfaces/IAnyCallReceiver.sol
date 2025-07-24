pragma solidity ^0.8.1;

interface IAnyCallReceiver {
    function anyExecute(
        uint256 fromChainId,
        address sender,
        bytes calldata data,
        uint256 callNonce
    ) external returns (bool success, bytes memory result);
}