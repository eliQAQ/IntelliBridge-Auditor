// SPDX-License-Identifier: MIT

pragma solidity 0.8.20;

import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import "./access/AdminControlUpgradeable.sol";
import "./IxSolvBTCPool.sol";
import "./ISolvBTCYieldToken.sol";
import "./ISolvBTCYieldTokenOracle.sol";

/**
 * @title XSolvBTCPool
 * @notice The pool for xSolvBTC, which is a yield token of solvBTC.
 * @dev This contract is a pool that allows users to deposit and withdraw solvBTC and xSolvBTC.
 * @dev Deposit: Burns SolvBTC, mints xSolvBTC.
 * @dev Withdraw: Burns xSolvBTC, mints SolvBTC.
 * @dev The withdraw fee will be deducted from the solvBTC, and the fee will be sent to the fee recipient.
 */
contract XSolvBTCPool is IxSolvBTCPool, ReentrancyGuardUpgradeable, AdminControlUpgradeable {
    struct XSolvBTCPoolStorage {
        address solvBTC;
        address xSolvBTC;
        address feeRecipient;
        uint64 withdrawFeeRate; // 10000 = 100%
        bool depositAllowed;
    }

    struct MultiplierStorage {
        uint256 maxMultiplier;
    }

    // keccak256(abi.encode(uint256(keccak256("solv.storage.xSolvBTCPool")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant XSolvBTCPoolStorageLocation = 0x4142751e4ad30de9575cf73d5fefb7910c20ffeb3557c886f882c49419246b00;

    // keccak256(abi.encode(uint256(keccak256("solv.storage.Multiplier")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant MultiplierStorageLocation = 0xe2416d9034d34fddf7bf2612a1798286ce32da5eaa3b1435acb443ea405c2300;

    function _getXSolvBTCPoolStorage() private pure returns (XSolvBTCPoolStorage storage $) {
        assembly {
            $.slot := XSolvBTCPoolStorageLocation
        }
    }

    function _getMultiplierStorage() private pure returns (MultiplierStorage storage $) {
        assembly {
            $.slot := MultiplierStorageLocation
        }
    }

    event Deposit(
        address indexed owner,
        address indexed solvBTC,
        address indexed xSolvBTC,
        uint256 solvBTCAmount,
        uint256 xSolvBTCAmount
    );
    event Withdraw(
        address indexed owner,
        address indexed solvBTC,
        address indexed xSolvBTC,
        uint256 solvBTCAmount,
        uint256 xSolvBTCAmount
    );

    event SetFeeRecipient(address oldFeeRecipient, address newFeeRecipient);
    event SetWithdrawFeeRate(uint64 oldWithdrawFeeRate, uint64 newWithdrawFeeRate);
    event SetDepositAllowed(bool oldDepositAllowed, bool newDepositAllowed);
    event SetMaxMultiplier(uint256 oldMaxMultiplier, uint256 newMaxMultiplier);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initialize the pool
     * @param solvBTC_ The address of the solvBTC token
     * @param xSolvBTC_ The address of the xSolvBTC token
     * @param feeRecipient_ The address of the fee recipient
     * @param withdrawFeeRate_ The withdraw fee rate, 10000 = 100%
     */
    function initialize(address solvBTC_, address xSolvBTC_, address feeRecipient_, uint64 withdrawFeeRate_)
        external
        virtual
        initializer
    {
        AdminControlUpgradeable.__AdminControl_init(msg.sender);
        ReentrancyGuardUpgradeable.__ReentrancyGuard_init();

        require(solvBTC_ != address(0) && xSolvBTC_ != address(0), "XSolvBTCPool: invalid address");

        XSolvBTCPoolStorage storage $ = _getXSolvBTCPoolStorage();
        $.solvBTC = solvBTC_;
        $.xSolvBTC = xSolvBTC_;

        _setFeeRecipient(feeRecipient_);
        _setWithdrawFeeRate(withdrawFeeRate_);
        _setDepositAllowed(true);
    }

    /**
     * @notice Deposit solvBTC to the pool
     * @param solvBtcAmount_ The amount of solvBTC to deposit
     * @return xSolvBtcAmount The amount of xSolvBTC received
     */
    function deposit(uint256 solvBtcAmount_) external virtual override nonReentrant returns (uint256 xSolvBtcAmount) {
        require(solvBtcAmount_ > 0, "xSolvBTCPool: deposit amount cannot be 0");
        XSolvBTCPoolStorage storage $ = _getXSolvBTCPoolStorage();
        require($.depositAllowed, "xSolvBTCPool: deposit not allowed");

        address solvBTC = $.solvBTC;
        address xSolvBTC = $.xSolvBTC;
        //burn solvBTC
        ISolvBTC(solvBTC).burn(msg.sender, solvBtcAmount_);
        //mint xSolvBTC
        xSolvBtcAmount = ISolvBTCYieldToken(xSolvBTC).getSharesByValue(solvBtcAmount_);
        require(solvBtcAmount_ >= xSolvBtcAmount, "xSolvBTCPool: xSolvBTC amount error");
        ISolvBTCYieldToken(xSolvBTC).mint(msg.sender, xSolvBtcAmount);

        emit Deposit(msg.sender, solvBTC, xSolvBTC, solvBtcAmount_, xSolvBtcAmount);
    }

    /**
     * @notice Withdraw solvBTC from the pool
     * @param xSolvBtcAmount_ The amount of xSolvBTC to withdraw
     * @return solvBtcAmount The amount of solvBTC received
     */
    function withdraw(uint256 xSolvBtcAmount_) external virtual override nonReentrant returns (uint256 solvBtcAmount) {
        require(xSolvBtcAmount_ > 0, "xSolvBTCPool: withdraw amount cannot be 0");

        XSolvBTCPoolStorage storage $ = _getXSolvBTCPoolStorage();
        MultiplierStorage storage $$ = _getMultiplierStorage();
        address solvBTC = $.solvBTC;
        address xSolvBTC = $.xSolvBTC;
        solvBtcAmount = ISolvBTCYieldToken(xSolvBTC).getValueByShares(xSolvBtcAmount_);

        //burn xSolvBTC
        ISolvBTCYieldToken(xSolvBTC).burn(msg.sender, xSolvBtcAmount_);
        //mint solvBTC to fee recipient
        uint256 fee = _calculateWithdrawFee(solvBtcAmount);
        if (fee > 0) {
            ISolvBTC(solvBTC).mint($.feeRecipient, fee);
        }
        //mint solvBTC to user
        require(
            (solvBtcAmount - fee) < (xSolvBtcAmount_ * $$.maxMultiplier / 10000),
            "xSolvBTCPool: solvBTC amount error"
        );
        ISolvBTC(solvBTC).mint(msg.sender, solvBtcAmount - fee);
        emit Withdraw(msg.sender, solvBTC, xSolvBTC, solvBtcAmount, xSolvBtcAmount_);
    }

    /**
     * @notice Set the fee recipient
     * @param feeRecipient_ The address of the fee recipient
     */
    function setFeeRecipientOnlyAdmin(address feeRecipient_) external virtual onlyAdmin {
        _setFeeRecipient(feeRecipient_);
    }

    /**
     * @notice Set the fee recipient
     * @param feeRecipient_ The address of the fee recipient
     */
    function _setFeeRecipient(address feeRecipient_) internal virtual {
        require(feeRecipient_ != address(0), "xSolvBTCPool: fee recipient cannot be 0 address");
        XSolvBTCPoolStorage storage $ = _getXSolvBTCPoolStorage();
        address oldFeeRecipient = $.feeRecipient;
        $.feeRecipient = feeRecipient_;
        emit SetFeeRecipient(oldFeeRecipient, feeRecipient_);
    }

    /**
     * @notice Set the withdraw fee rate
     * @param withdrawFeeRate_ The withdraw fee rate, 10000 = 100%
     */
    function setWithdrawFeeRateOnlyAdmin(uint64 withdrawFeeRate_) external virtual onlyAdmin {
        _setWithdrawFeeRate(withdrawFeeRate_);
    }

    /**
     * @notice Set the withdraw fee rate
     * @param withdrawFeeRate_ The withdraw fee rate, 10000 = 100%
     */
    function _setWithdrawFeeRate(uint64 withdrawFeeRate_) internal virtual {
        require(withdrawFeeRate_ < 10000, "xSolvBTCPool: invalid withdraw fee rate");
        XSolvBTCPoolStorage storage $ = _getXSolvBTCPoolStorage();
        uint64 oldWithdrawFeeRate = $.withdrawFeeRate;
        $.withdrawFeeRate = withdrawFeeRate_;
        emit SetWithdrawFeeRate(oldWithdrawFeeRate, withdrawFeeRate_);
    }

    /**
     * @notice Set the deposit allowed
     * @param depositAllowed_ The deposit allowed
     */
    function setDepositAllowedOnlyAdmin(bool depositAllowed_) external virtual onlyAdmin {
        _setDepositAllowed(depositAllowed_);
    }

    /**
     * @notice Set the deposit allowed
     * @param depositAllowed_ The deposit allowed
     */
    function _setDepositAllowed(bool depositAllowed_) internal virtual {
        XSolvBTCPoolStorage storage $ = _getXSolvBTCPoolStorage();
        bool oldDepositAllowed = $.depositAllowed;
        $.depositAllowed = depositAllowed_;
        emit SetDepositAllowed(oldDepositAllowed, depositAllowed_);
    }

    /**
     * @notice Get the fee recipient
     * @return feeRecipient The address of the fee recipient
     */
    function feeRecipient() external view virtual returns (address) {
        XSolvBTCPoolStorage storage $ = _getXSolvBTCPoolStorage();
        return $.feeRecipient;
    }

    /**
     * @notice Get the withdraw fee rate
     * @return withdrawFeeRate The withdraw fee rate, 10000 = 100%
     */
    function withdrawFeeRate() external view virtual returns (uint64) {
        XSolvBTCPoolStorage storage $ = _getXSolvBTCPoolStorage();
        return $.withdrawFeeRate;
    }

    /**
     * @notice Get the deposit allowed
     * @return depositAllowed The deposit allowed
     */
    function depositAllowed() external view virtual returns (bool) {
        XSolvBTCPoolStorage storage $ = _getXSolvBTCPoolStorage();
        return $.depositAllowed;
    }

    /**
     * @notice Calculate the withdraw fee
     * @param amount_ The amount of solvBTC to withdraw
     * @return fee The withdraw fee
     */
    function _calculateWithdrawFee(uint256 amount_) private view returns (uint256) {
        XSolvBTCPoolStorage storage $ = _getXSolvBTCPoolStorage();
        return (amount_ * $.withdrawFeeRate) / 10000;
    }

    function maxMultiplier() external view virtual returns (uint256) {
        MultiplierStorage storage $ = _getMultiplierStorage();
        return $ .maxMultiplier;
    }

    function setMaxMultiplierOnlyAdmin(uint256 maxMultiplier_) external virtual onlyAdmin {
        _setMaxMultiplier(maxMultiplier_);
    }

    function _setMaxMultiplier(uint256 maxMultiplier_) internal virtual {
        MultiplierStorage storage $ = _getMultiplierStorage();
        emit SetMaxMultiplier($.maxMultiplier, maxMultiplier_);
        $.maxMultiplier = maxMultiplier_;
    }
}
