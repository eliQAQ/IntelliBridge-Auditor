// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import {IPausable} from "../../contracts/router/interfaces/IPausable.sol";
import {IndexedToken, IPoolModule} from "../../contracts/router/interfaces/IPoolModule.sol";
import {IDefaultPool} from "../../contracts/router/interfaces/IDefaultPool.sol";

import {IERC20, SafeERC20} from "@openzeppelin/contracts-4.5.0/token/ERC20/utils/SafeERC20.sol";

/// PoolModule for Default pools. This is not required in production, but could be used to test delegation logic.
contract MockPoolModule is IPoolModule {
    using SafeERC20 for IERC20;

    function poolSwap(
        address pool,
        IndexedToken memory tokenFrom,
        IndexedToken memory tokenTo,
        uint256 amountIn
    ) external returns (uint256 amountOut) {
        _approveToken(tokenFrom.token, pool);
        // Note: we check minDy and deadline outside of this function.
        amountOut = IDefaultPool(pool).swap(tokenFrom.index, tokenTo.index, amountIn, 0, type(uint256).max);
    }

    function getPoolQuote(
        address pool,
        IndexedToken memory tokenFrom,
        IndexedToken memory tokenTo,
        uint256 amountIn,
        bool probePaused
    ) external view returns (uint256 amountOut) {
        if (probePaused) {
            // We issue a static call in case the pool does not conform to IPausable interface.
            (bool success, bytes memory returnData) = pool.staticcall(
                abi.encodeWithSelector(IPausable.paused.selector)
            );
            if (success && abi.decode(returnData, (bool))) {
                // Pool is paused, return zero
                return 0;
            }
        }
        amountOut = IDefaultPool(pool).calculateSwap(tokenFrom.index, tokenTo.index, amountIn);
    }

    function getPoolTokens(address pool) external view returns (address[] memory tokens) {
        uint256 numTokens = 0;
        while (true) {
            try IDefaultPool(pool).getToken(uint8(numTokens)) returns (address) {
                ++numTokens;
            } catch {
                break;
            }
        }
        tokens = new address[](numTokens);
        for (uint8 i = 0; i < numTokens; ++i) {
            tokens[i] = IDefaultPool(pool).getToken(i);
        }
    }

    /// @dev Approves the given spender to spend the given token indefinitely.
    /// Note: doesn't do anything if the spender already has infinite allowance.
    function _approveToken(address token, address spender) internal {
        uint256 allowance = IERC20(token).allowance(address(this), spender);
        if (allowance != type(uint256).max) {
            // if allowance is neither zero nor infinity, reset if first
            if (allowance != 0) {
                IERC20(token).safeApprove(spender, 0);
            }
            IERC20(token).safeApprove(spender, type(uint256).max);
        }
    }
}
