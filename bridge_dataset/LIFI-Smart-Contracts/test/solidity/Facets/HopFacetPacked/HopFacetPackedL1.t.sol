// // SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import { IHopBridge } from "lifi/Interfaces/IHopBridge.sol";
import { ERC20, SafeTransferLib } from "solmate/utils/SafeTransferLib.sol";
import { HopFacetPacked } from "lifi/Facets/HopFacetPacked.sol";
import { HopFacetOptimized } from "lifi/Facets/HopFacetOptimized.sol";
import { TestBase, ILiFi } from "../../utils/TestBase.sol";

contract CallForwarder {
    error DiamondCallFailed();

    function callDiamond(
        uint256 nativeAmount,
        address contractAddress,
        bytes calldata callData
    ) external payable {
        (bool success, ) = contractAddress.call{ value: nativeAmount }(
            callData
        );
        if (!success) {
            revert DiamondCallFailed();
        }
    }
}

contract HopFacetPackedL1Test is TestBase {
    using SafeTransferLib for ERC20;

    address internal constant HOP_USDC_BRIDGE =
        0x3666f603Cc164936C1b87e207F36BEBa4AC5f18a;
    address internal constant HOP_USDT_BRIDGE =
        0x3E4a3a4796d16c0Cd582C382691998f7c06420B6;
    address internal constant HOP_NATIVE_BRIDGE =
        0xb8901acB165ed027E32754E0FFe830802919727f;
    address internal constant WHALE =
        0x72A53cDBBcc1b9efa39c834A540550e23463AAcB; // USDC + ETH
    address internal constant RECEIVER =
        0x552008c0f6870c2f77e5cC1d2eb9bdff03e30Ea0;

    IHopBridge internal hop;
    HopFacetPacked internal hopFacetPacked;
    HopFacetPacked internal standAlone;
    CallForwarder internal callForwarder;

    bytes8 internal transactionId;
    string internal integrator;
    uint256 internal destinationChainId;
    uint256 internal deadline;

    struct BridgeParams {
        uint256 amount;
        uint256 bonderFee;
        uint256 amountOutMin;
        bytes packedData;
    }

    BridgeParams internal usdcParams;
    BridgeParams internal usdtParams;
    BridgeParams internal nativeParams;

    function setUp() public {
        // set custom block number for forking
        customBlockNumberForForking = 15588208;
        initTestBase();

        /// Perpare HopFacetPacked
        hopFacetPacked = new HopFacetPacked(address(this), address(0));
        standAlone = new HopFacetPacked(address(this), address(0));
        hop = IHopBridge(HOP_USDC_BRIDGE);
        callForwarder = new CallForwarder();

        deal(ADDRESS_USDT, address(WHALE), 100000 * 10 ** usdt.decimals());

        bytes4[] memory functionSelectors = new bytes4[](13);
        functionSelectors[0] = hopFacetPacked
            .setApprovalForHopBridges
            .selector;
        functionSelectors[1] = hopFacetPacked
            .startBridgeTokensViaHopL2NativePacked
            .selector;
        functionSelectors[2] = hopFacetPacked
            .startBridgeTokensViaHopL2NativeMin
            .selector;
        functionSelectors[3] = hopFacetPacked
            .encode_startBridgeTokensViaHopL2NativePacked
            .selector;
        functionSelectors[4] = hopFacetPacked
            .startBridgeTokensViaHopL2ERC20Packed
            .selector;
        functionSelectors[5] = hopFacetPacked
            .startBridgeTokensViaHopL2ERC20Min
            .selector;
        functionSelectors[6] = hopFacetPacked
            .encode_startBridgeTokensViaHopL2ERC20Packed
            .selector;
        functionSelectors[7] = hopFacetPacked
            .startBridgeTokensViaHopL1NativePacked
            .selector;
        functionSelectors[8] = hopFacetPacked
            .startBridgeTokensViaHopL1NativeMin
            .selector;
        functionSelectors[9] = hopFacetPacked
            .encode_startBridgeTokensViaHopL1NativePacked
            .selector;
        functionSelectors[10] = hopFacetPacked
            .startBridgeTokensViaHopL1ERC20Packed
            .selector;
        functionSelectors[11] = hopFacetPacked
            .startBridgeTokensViaHopL1ERC20Min
            .selector;
        functionSelectors[12] = hopFacetPacked
            .encode_startBridgeTokensViaHopL1ERC20Packed
            .selector;

        addFacet(diamond, address(hopFacetPacked), functionSelectors);
        hopFacetPacked = HopFacetPacked(address(diamond));

        /// Approval
        address[] memory bridges = new address[](2);
        bridges[0] = HOP_USDC_BRIDGE;
        bridges[1] = HOP_USDT_BRIDGE;
        address[] memory tokens = new address[](2);
        tokens[0] = ADDRESS_USDC;
        tokens[1] = ADDRESS_USDT;

        // > diamond
        HopFacetOptimized hopFacetOptimized = new HopFacetOptimized();
        bytes4[] memory functionSelectorsApproval = new bytes4[](1);
        functionSelectorsApproval[0] = hopFacetOptimized
            .setApprovalForBridges
            .selector;
        addFacet(
            diamond,
            address(hopFacetOptimized),
            functionSelectorsApproval
        );
        hopFacetOptimized = HopFacetOptimized(address(diamond));
        hopFacetOptimized.setApprovalForBridges(bridges, tokens);

        // > standAlone
        standAlone.setApprovalForHopBridges(bridges, tokens);

        /// Perpare parameters
        transactionId = "someID";
        integrator = "demo-partner";
        destinationChainId = 137;
        deadline = block.timestamp + 7 * 24 * 60 * 60;

        // Native params
        uint256 amountNative = 1 ether;
        nativeParams = BridgeParams({
            amount: amountNative,
            bonderFee: amountNative / 100,
            amountOutMin: (amountNative / 100) * 99,
            packedData: hopFacetPacked
                .encode_startBridgeTokensViaHopL1NativePacked(
                    transactionId,
                    RECEIVER,
                    destinationChainId,
                    (amountNative / 100) * 99,
                    address(0),
                    0,
                    HOP_NATIVE_BRIDGE
                )
        });

        // USDC params
        uint256 amountUSDC = 100 * 10 ** usdc.decimals();
        usdcParams = BridgeParams({
            amount: amountUSDC,
            bonderFee: amountUSDC / 100,
            amountOutMin: (amountUSDC / 100) * 99,
            packedData: hopFacetPacked
                .encode_startBridgeTokensViaHopL1ERC20Packed(
                    transactionId,
                    RECEIVER,
                    destinationChainId,
                    ADDRESS_USDC,
                    amountUSDC,
                    (amountUSDC / 100) * 99,
                    address(0),
                    0,
                    HOP_USDC_BRIDGE
                )
        });

        // USDT params
        uint256 amountUSDT = 100 * 10 ** usdt.decimals();
        usdtParams = BridgeParams({
            amount: amountUSDT,
            bonderFee: amountUSDT / 100,
            amountOutMin: (amountUSDT / 100) * 99,
            packedData: hopFacetPacked
                .encode_startBridgeTokensViaHopL1ERC20Packed(
                    transactionId,
                    RECEIVER,
                    destinationChainId,
                    ADDRESS_USDT,
                    amountUSDT,
                    (amountUSDT / 100) * 99,
                    address(0),
                    0,
                    HOP_USDT_BRIDGE
                )
        });

        // set facet address in TestBase
        setFacetAddressInTestBase(address(hopFacetPacked), "HopFacetPackedL1");
    }

    // L1 Native
    function testStartBridgeTokensViaHopL1NativePacked() public {
        vm.startPrank(WHALE);
        (bool success, ) = address(diamond).call{ value: nativeParams.amount }(
            nativeParams.packedData
        );
        if (!success) {
            revert NativeBridgeFailed();
        }
        vm.stopPrank();
    }

    function testStartBridgeTokensViaHopL1NativePackedForwarded() public {
        vm.startPrank(WHALE);
        callForwarder.callDiamond{ value: 2 * nativeParams.amount }(
            nativeParams.amount,
            address(diamond),
            nativeParams.packedData
        );
        vm.stopPrank();
    }

    function testStartBridgeTokensViaHopL1NativePackedStandalone() public {
        vm.startPrank(WHALE);
        (bool success, ) = address(standAlone).call{
            value: nativeParams.amount
        }(nativeParams.packedData);
        if (!success) {
            revert NativeBridgeFailed();
        }
        vm.stopPrank();
    }

    function testStartBridgeTokensViaHopL1NativePackedDecode() public {
        (
            ILiFi.BridgeData memory decodedBridgeData,
            HopFacetOptimized.HopData memory decodedHopData
        ) = standAlone.decode_startBridgeTokensViaHopL1NativePacked(
                nativeParams.packedData
            );

        assertEq(decodedBridgeData.transactionId, transactionId);
        assertEq(
            decodedHopData.destinationAmountOutMin,
            nativeParams.amountOutMin
        );
    }

    function testStartBridgeTokensViaHopL1NativeMin() public {
        vm.startPrank(WHALE);
        hopFacetPacked.startBridgeTokensViaHopL1NativeMin{
            value: nativeParams.amount
        }(
            transactionId,
            RECEIVER,
            destinationChainId,
            nativeParams.amountOutMin,
            address(0),
            0,
            HOP_NATIVE_BRIDGE
        );
        vm.stopPrank();
    }

    function testStartBridgeTokensViaHopL1NativeMinStandalone() public {
        vm.startPrank(WHALE);
        standAlone.startBridgeTokensViaHopL1NativeMin{
            value: nativeParams.amount
        }(
            transactionId,
            RECEIVER,
            destinationChainId,
            nativeParams.amountOutMin,
            address(0),
            0,
            HOP_NATIVE_BRIDGE
        );
        vm.stopPrank();
    }

    // L1 ERC20
    function testStartBridgeTokensViaHopL1ERC20Packed_USDC() public {
        vm.startPrank(WHALE);
        usdc.safeApprove(address(diamond), usdcParams.amount);
        (bool success, ) = address(diamond).call(usdcParams.packedData);
        if (!success) {
            revert ERC20BridgeFailed();
        }
        vm.stopPrank();
    }

    function testStartBridgeTokensViaHopL1ERC20PackedStandalone_USDC() public {
        vm.startPrank(WHALE);
        usdc.safeApprove(address(standAlone), usdcParams.amount);
        (bool success, ) = address(standAlone).call(usdcParams.packedData);
        if (!success) {
            revert ERC20BridgeFailed();
        }
        vm.stopPrank();
    }

    function testStartBridgeTokensViaHopL1ERC20PackedDecode_USDC() public {
        (
            ILiFi.BridgeData memory decodedBridgeData,
            HopFacetOptimized.HopData memory decodedHopData
        ) = standAlone.decode_startBridgeTokensViaHopL1ERC20Packed(
                usdcParams.packedData
            );

        assertEq(decodedBridgeData.transactionId, transactionId);
        assertEq(
            decodedHopData.destinationAmountOutMin,
            usdcParams.amountOutMin
        );
    }

    function testStartBridgeTokensViaHopL1ERC20Min_USDC() public {
        vm.startPrank(WHALE);
        usdc.safeApprove(address(diamond), usdcParams.amount);
        hopFacetPacked.startBridgeTokensViaHopL1ERC20Min(
            transactionId,
            RECEIVER,
            destinationChainId,
            ADDRESS_USDC,
            usdcParams.amount,
            usdcParams.amountOutMin,
            address(0),
            0,
            HOP_USDC_BRIDGE
        );
        vm.stopPrank();
    }

    function testStartBridgeTokensViaHopL1ERC20MinStandalone_USDC() public {
        vm.startPrank(WHALE);
        usdc.safeApprove(address(standAlone), usdcParams.amount);
        standAlone.startBridgeTokensViaHopL1ERC20Min(
            transactionId,
            RECEIVER,
            destinationChainId,
            ADDRESS_USDC,
            usdcParams.amount,
            usdcParams.amountOutMin,
            address(0),
            0,
            HOP_USDC_BRIDGE
        );
        vm.stopPrank();
    }

    function testStartBridgeTokensViaHopL1ERC20Packed_USDT() public {
        vm.startPrank(WHALE);
        usdt.safeApprove(address(diamond), usdtParams.amount);
        (bool success, ) = address(diamond).call(usdtParams.packedData);
        if (!success) {
            revert ERC20BridgeFailed();
        }
        vm.stopPrank();
    }

    function testStartBridgeTokensViaHopL1ERC20PackedStandalone_USDT() public {
        vm.startPrank(WHALE);
        usdt.safeApprove(address(standAlone), usdtParams.amount);
        (bool success, ) = address(standAlone).call(usdtParams.packedData);
        if (!success) {
            revert ERC20BridgeFailed();
        }
        vm.stopPrank();
    }

    function testStartBridgeTokensViaHopL1ERC20PackedDecode_USDT() public {
        (
            ILiFi.BridgeData memory decodedBridgeData,
            HopFacetOptimized.HopData memory decodedHopData
        ) = standAlone.decode_startBridgeTokensViaHopL1ERC20Packed(
                usdtParams.packedData
            );

        assertEq(decodedBridgeData.transactionId, transactionId);
        assertEq(
            decodedHopData.destinationAmountOutMin,
            usdtParams.amountOutMin
        );
    }

    function testStartBridgeTokensViaHopL1ERC20Min_USDT() public {
        vm.startPrank(WHALE);
        usdt.safeApprove(address(diamond), usdtParams.amount);
        hopFacetPacked.startBridgeTokensViaHopL1ERC20Min(
            transactionId,
            RECEIVER,
            destinationChainId,
            ADDRESS_USDT,
            usdtParams.amount,
            usdtParams.amountOutMin,
            address(0),
            0,
            HOP_USDT_BRIDGE
        );
        vm.stopPrank();
    }

    function testStartBridgeTokensViaHopL1ERC20MinStandalone_USDT() public {
        vm.startPrank(WHALE);
        usdt.safeApprove(address(standAlone), usdtParams.amount);
        standAlone.startBridgeTokensViaHopL1ERC20Min(
            transactionId,
            RECEIVER,
            destinationChainId,
            ADDRESS_USDT,
            usdtParams.amount,
            usdtParams.amountOutMin,
            address(0),
            0,
            HOP_USDT_BRIDGE
        );
        vm.stopPrank();
    }

    // Encode
    // function testEncodeNativeValidation() public {
    //     // destinationChainId
    //     // > max allowed
    //     hopFacetPacked.encode_startBridgeTokensViaHopL1NativePacked(
    //         transactionId,
    //         RECEIVER,
    //         uint256(type(uint32).max),
    //         amountBonderFeeNative,
    //         amountOutMinNative,
    //         amountOutMinNative,
    //         deadline,
    //         HOP_NATIVE_BRIDGE
    //     );
    //     // > too big
    //     vm.expectRevert();
    //     hopFacetPacked.encode_startBridgeTokensViaHopL1NativePacked(
    //         transactionId,
    //         RECEIVER,
    //         uint256(type(uint32).max) + 1,
    //         amountBonderFeeNative,
    //         amountOutMinNative,
    //         amountOutMinNative,
    //         deadline,
    //         HOP_NATIVE_BRIDGE
    //     );

    //     // bonderFee
    //     // > max allowed
    //     hopFacetPacked.encode_startBridgeTokensViaHopL1NativePacked(
    //         transactionId,
    //         RECEIVER,
    //         137,
    //         uint256(type(uint128).max),
    //         amountOutMinNative,
    //         amountOutMinNative,
    //         deadline,
    //         HOP_NATIVE_BRIDGE
    //     );
    //     // > too big
    //     vm.expectRevert();
    //     hopFacetPacked.encode_startBridgeTokensViaHopL1NativePacked(
    //         transactionId,
    //         RECEIVER,
    //         137,
    //         uint256(type(uint128).max) + 1,
    //         amountOutMinNative,
    //         amountOutMinNative,
    //         deadline,
    //         HOP_NATIVE_BRIDGE
    //     );

    //     // amountOutMin
    //     // > max allowed
    //     hopFacetPacked.encode_startBridgeTokensViaHopL1NativePacked(
    //         transactionId,
    //         RECEIVER,
    //         137,
    //         amountBonderFeeNative,
    //         uint256(type(uint128).max),
    //         amountOutMinNative,
    //         deadline,
    //         HOP_NATIVE_BRIDGE
    //     );
    //     // > too big
    //     vm.expectRevert();
    //     hopFacetPacked.encode_startBridgeTokensViaHopL1NativePacked(
    //         transactionId,
    //         RECEIVER,
    //         137,
    //         amountBonderFeeNative,
    //         uint256(type(uint128).max) + 1,
    //         amountOutMinNative,
    //         deadline,
    //         HOP_NATIVE_BRIDGE
    //     );

    //     // destinationAmountOutMin
    //     // > max allowed
    //     hopFacetPacked.encode_startBridgeTokensViaHopL1NativePacked(
    //         transactionId,
    //         RECEIVER,
    //         137,
    //         amountBonderFeeNative,
    //         amountOutMinNative,
    //         uint256(type(uint128).max),
    //         deadline,
    //         HOP_NATIVE_BRIDGE
    //     );
    //     // > too big
    //     vm.expectRevert();
    //     hopFacetPacked.encode_startBridgeTokensViaHopL1NativePacked(
    //         transactionId,
    //         RECEIVER,
    //         137,
    //         amountBonderFeeNative,
    //         amountOutMinNative,
    //         uint256(type(uint128).max) + 1,
    //         deadline,
    //         HOP_NATIVE_BRIDGE
    //     );
    // }

    // function testEncodeERC20Validation() public {
    //     // destinationChainId
    //     // > max allowed
    //     hopFacetPacked.encode_startBridgeTokensViaHopL1ERC20Packed(
    //         transactionId,
    //         RECEIVER,
    //         uint256(type(uint32).max),
    //         ADDRESS_USDC,
    //         amountUSDC,
    //         amountBonderFeeUSDC,
    //         amountOutMinUSDC,
    //         amountOutMinUSDC,
    //         deadline,
    //         HOP_USDC_BRIDGE
    //     );
    //     // > too big
    //     vm.expectRevert();
    //     hopFacetPacked.encode_startBridgeTokensViaHopL1ERC20Packed(
    //         transactionId,
    //         RECEIVER,
    //         uint256(type(uint32).max) + 1,
    //         ADDRESS_USDC,
    //         amountUSDC,
    //         amountBonderFeeUSDC,
    //         amountOutMinUSDC,
    //         amountOutMinUSDC,
    //         deadline,
    //         HOP_USDC_BRIDGE
    //     );

    //     // amount
    //     // > max allowed
    //     hopFacetPacked.encode_startBridgeTokensViaHopL1ERC20Packed(
    //         transactionId,
    //         RECEIVER,
    //         137,
    //         ADDRESS_USDC,
    //         uint256(type(uint128).max),
    //         amountBonderFeeUSDC,
    //         amountOutMinUSDC,
    //         amountOutMinUSDC,
    //         deadline,
    //         HOP_USDC_BRIDGE
    //     );
    //     // > too big
    //     vm.expectRevert();
    //     hopFacetPacked.encode_startBridgeTokensViaHopL1ERC20Packed(
    //         transactionId,
    //         RECEIVER,
    //         137,
    //         ADDRESS_USDC,
    //         uint256(type(uint128).max) + 1,
    //         amountBonderFeeUSDC,
    //         amountOutMinUSDC,
    //         amountOutMinUSDC,
    //         deadline,
    //         HOP_USDC_BRIDGE
    //     );

    //     // bonderFee
    //     // > max allowed
    //     hopFacetPacked.encode_startBridgeTokensViaHopL1ERC20Packed(
    //         transactionId,
    //         RECEIVER,
    //         137,
    //         ADDRESS_USDC,
    //         amountUSDC,
    //         uint256(type(uint128).max),
    //         amountOutMinUSDC,
    //         amountOutMinUSDC,
    //         deadline,
    //         HOP_USDC_BRIDGE
    //     );
    //     // > too big
    //     vm.expectRevert();
    //     hopFacetPacked.encode_startBridgeTokensViaHopL1ERC20Packed(
    //         transactionId,
    //         RECEIVER,
    //         137,
    //         ADDRESS_USDC,
    //         amountUSDC,
    //         uint256(type(uint128).max) + 1,
    //         amountOutMinUSDC,
    //         amountOutMinUSDC,
    //         deadline,
    //         HOP_USDC_BRIDGE
    //     );

    //     // amountOutMin
    //     // > max allowed
    //     hopFacetPacked.encode_startBridgeTokensViaHopL1ERC20Packed(
    //         transactionId,
    //         RECEIVER,
    //         137,
    //         ADDRESS_USDC,
    //         amountUSDC,
    //         amountBonderFeeUSDC,
    //         uint256(type(uint128).max),
    //         amountOutMinUSDC,
    //         deadline,
    //         HOP_USDC_BRIDGE
    //     );
    //     // > too big
    //     vm.expectRevert();
    //     hopFacetPacked.encode_startBridgeTokensViaHopL1ERC20Packed(
    //         transactionId,
    //         RECEIVER,
    //         137,
    //         ADDRESS_USDC,
    //         amountUSDC,
    //         amountBonderFeeUSDC,
    //         uint256(type(uint128).max) + 1,
    //         amountOutMinUSDC,
    //         deadline,
    //         HOP_USDC_BRIDGE
    //     );

    //     // destinationAmountOutMin
    //     // > max allowed
    //     hopFacetPacked.encode_startBridgeTokensViaHopL1ERC20Packed(
    //         transactionId,
    //         RECEIVER,
    //         137,
    //         ADDRESS_USDC,
    //         amountUSDC,
    //         amountBonderFeeUSDC,
    //         amountOutMinUSDC,
    //         uint256(type(uint128).max),
    //         deadline,
    //         HOP_USDC_BRIDGE
    //     );
    //     // > too big
    //     vm.expectRevert();
    //     hopFacetPacked.encode_startBridgeTokensViaHopL1ERC20Packed(
    //         transactionId,
    //         RECEIVER,
    //         137,
    //         ADDRESS_USDC,
    //         amountUSDC,
    //         amountBonderFeeUSDC,
    //         amountOutMinUSDC,
    //         uint256(type(uint128).max) + 1,
    //         deadline,
    //         HOP_USDC_BRIDGE
    //     );
    // }
}
