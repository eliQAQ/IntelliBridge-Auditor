// SPDX-License-Identifier: Unlicense

pragma solidity ^0.8.1;

interface IUniswapV2Factory {
    
    function getPair(address tokenA, address tokenB) external view returns (address pair);
    
}