// SPDX-License-Identifier: MIT

pragma solidity 0.8.20;

import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "../contracts/SolvBTCFactory.sol";
import "../contracts/SolvBTCYieldToken.sol";
import "../contracts/SolvBTCYieldTokenV3.sol";
import "../contracts/SolvBTCMultiAssetPool.sol";
import "../contracts/IxSolvBTCPool.sol";
import "../contracts/XSolvBTCPool.sol";
import "../contracts/SolvBTCRouterV2.sol";
import "../contracts/SolvBTCV3_1.sol";
import "../contracts/SolvBTC.sol";
import "../contracts/SolvBTCYieldTokenV3_1.sol";
import "../lib/forge-std/src/Test.sol";
import "../lib/forge-std/src/console.sol";
import "../contracts/oracle/XSolvBTCOracle.sol";

interface IProxyAdmin {
    function upgrade(ITransparentUpgradeableProxy proxy, address implementation) external;
}

contract XSolvBTCOracleTest is Test {
    address internal constant solvBTC = 0x7A56E1C57C7475CCf742a1832B028F0456652F97;
    address internal constant xSolvBTC = 0xd9D920AA40f578ab794426F5C90F6C731D159DEf;
    address internal constant ADMIN = 0x55C09707Fd7aFD670e82A62FaeE312903940013E;
    ProxyAdmin internal constant proxyAdmin = ProxyAdmin(0xD3e96c05F2bED82271B5C9d737C215F6BcadfF68);
    address internal constant USER_1 = 0x3D64cFEEf2B66AdD5191c387E711AF47ab01e296;

    XSolvBTCPool public xSolvBTCPool;
    XSolvBTCOracle public oracle;

    function setUp() public {
        //fork eth mainnet
        vm.createSelectFork(vm.envString("ETH_RPC_URL"));
        xSolvBTCPool = XSolvBTCPool(_deployXSolvBTCPool());
        oracle = XSolvBTCOracle(_deployXSolvBTCOracle());
    }

    function test_SetNav() public {
        vm.startPrank(ADMIN);
        oracle.setNav(1.005e18);
        vm.stopPrank();
        assertEq(oracle.getNav(xSolvBTC), 1.005e18);
    }

    function test_GetLatestUpdatedAt() public {
        vm.startPrank(ADMIN);
        oracle.setNav(1.005e18);
        vm.stopPrank();
        assertEq(oracle.latestUpdatedAt(), block.timestamp);
    }

    function test_RevertWhenSetNavByNonAdmin() public {
        vm.startPrank(USER_1);
        vm.expectRevert("only admin");
        oracle.setNav(1.005e18);
        vm.stopPrank();
    }

    function test_RevertWhenGetNavByInvalidXSolvBTC() public {
        vm.expectRevert("XSolvBTCOracle: invalid erc20 address");
        oracle.getNav(address(0));
    }

    function _deployXSolvBTCPool() internal returns (address) {
        vm.startPrank(ADMIN);
        bytes32 implSalt = keccak256(abi.encodePacked(ADMIN));
        XSolvBTCPool impl = new XSolvBTCPool{salt: implSalt}();
        bytes32 proxySalt = keccak256(abi.encodePacked(impl));
        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy{salt: proxySalt}(
            address(impl),
            address(proxyAdmin),
            abi.encodeWithSignature(
                "initialize(address,address,address,uint64)", solvBTC, xSolvBTC, ADMIN, 100
            )
        );
        vm.stopPrank();
        return address(proxy);
    }

    function _deployXSolvBTCOracle() internal returns (address) {
        vm.startPrank(ADMIN);
        bytes32 implSalt = keccak256(abi.encodePacked(ADMIN));
        XSolvBTCOracle impl = new XSolvBTCOracle{salt: implSalt}();
        bytes32 proxySalt = keccak256(abi.encodePacked(impl));
        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy{salt: proxySalt}(
            address(impl), address(proxyAdmin), abi.encodeWithSignature("initialize(uint8,uint256)", 18, 1e18)
        );
        XSolvBTCOracle(address(proxy)).setXSolvBTC(xSolvBTC);
        XSolvBTCOracle(address(proxy)).setXSolvBTCPool(address(xSolvBTCPool));
        vm.stopPrank();
        return address(proxy);
    }
}
