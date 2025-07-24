pragma solidity ^0.6.12;
pragma experimental ABIEncoderV2;
import @openzeppelincontractsmathSafeMath.sol;

import ..interfacesIQBridgeHandler.sol;
import ..libraryPausableUpgradeable.sol;
import ..libraryAccessControlIndexUpgradeable.sol;
import ..librarySafeToken.sol;


contract QBridge is PausableUpgradeable, AccessControlIndexUpgradeable {
    using SafeMath for uint;
    using SafeToken for address;


    bytes32 public constant RELAYER_ROLE = keccak256(RELAYER_ROLE);

    uint public constant MAX_RELAYERS = 200;

    enum ProposalStatus {Inactive, Active, Passed, Executed, Cancelled}

    struct Proposal {
        ProposalStatus _status;
        uint200 _yesVotes;       bitmap, 200 maximum votes
        uint8 _yesVotesTotal;
        uint40 _proposedBlock;  1099511627775 maximum block
    }


    uint8 public domainID;
    uint8 public relayerThreshold;
    uint128 public fee;
    uint40 public expiry;

    mapping(uint8 = uint64) public _depositCounts;  destinationDomainID = number of deposits
    mapping(bytes32 = address) public resourceIDToHandlerAddress;  resourceID = handler address
    mapping(uint72 = mapping(bytes32 = Proposal)) private _proposals;  destinationDomainID + depositNonce = dataHash = Proposal


    event RelayerThresholdChanged(uint256 newThreshold);
    event RelayerAdded(address relayer);
    event RelayerRemoved(address relayer);
    event Deposit(uint8 destinationDomainID, bytes32 resourceID, uint64 depositNonce, address indexed user, bytes data);
    event ProposalEvent(uint8 originDomainID, uint64 depositNonce, ProposalStatus status, bytes data);
    event ProposalVote(uint8 originDomainID, uint64 depositNonce, ProposalStatus status, bytes32 dataHash);
    event FailedHandlerExecution(bytes lowLevelData);



    function initialize(uint8 _domainID, uint8 _relayerThreshold, uint128 _fee, uint40 _expiry) external initializer {
        __PausableUpgradeable_init();
        __AccessControl_init();

        domainID = _domainID;
        relayerThreshold = _relayerThreshold;
        fee = _fee;
        expiry = _expiry;

        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }


    modifier onlyRelayers() {
        require(hasRole(RELAYER_ROLE, msg.sender), QBridge caller is not the relayer);
        _;
    }

    modifier onlyOwnerOrRelayers() {
        require(owner() == msg.sender  hasRole(RELAYER_ROLE, msg.sender), QBridge caller is not the owner or relayer);
        _;
    }



    function setRelayerThreshold(uint8 newThreshold) external onlyOwner {
        relayerThreshold = newThreshold;
        emit RelayerThresholdChanged(newThreshold);
    }

    function addRelayer(address relayer) external onlyOwner {
        require(!hasRole(RELAYER_ROLE, relayer), QBridge duplicated relayer);
        require(totalRelayers()  MAX_RELAYERS, QBridge relayers limit reached);
        grantRole(RELAYER_ROLE, relayer);
        emit RelayerAdded(relayer);
    }

    function removeRelayer(address relayer) external onlyOwner {
        require(hasRole(RELAYER_ROLE, relayer), QBridge invalid relayer);
        revokeRole(RELAYER_ROLE, relayer);
        emit RelayerRemoved(relayer);
    }

    function setResource(address handlerAddress, bytes32 resourceID, address tokenAddress) external onlyOwner {
        resourceIDToHandlerAddress[resourceID] = handlerAddress;
        IQBridgeHandler(handlerAddress).setResource(resourceID, tokenAddress);
    }

    function setBurnable(address handlerAddress, address tokenAddress) external onlyOwner {
        IQBridgeHandler(handlerAddress).setBurnable(tokenAddress);
    }

    function setDepositNonce(uint8 _domainID, uint64 nonce) external onlyOwner {
        require(nonce  _depositCounts[_domainID], QBridge decrements not allowed);
        _depositCounts[_domainID] = nonce;
    }

    function setFee(uint128 newFee) external onlyOwner {
        fee = newFee;
    }

    function manualRelease(address handlerAddress, address tokenAddress, address recipient, uint amount) external onlyOwner {
        IQBridgeHandler(handlerAddress).withdraw(tokenAddress, recipient, amount);
    }

    function sweep() external onlyOwner {
        SafeToken.safeTransferETH(msg.sender, address(this).balance);
    }


    function isRelayer(address relayer) external view returns (bool) {
        return hasRole(RELAYER_ROLE, relayer);
    }

    function totalRelayers() public view returns (uint) {
        return AccessControlIndexUpgradeable.getRoleMemberCount(RELAYER_ROLE);
    }


     
    function combinedProposalId(uint8 _domainID, uint64 nonce) public pure returns (uint72 proposalID) {
        proposalID = (uint72(nonce)  8)  uint72(_domainID);
    }


     
    function getProposal(uint8 originDomainID, uint64 depositNonce, bytes32 dataHash, address relayer) external view returns (Proposal memory proposal, bool hasVoted) {
        uint72 proposalID = combinedProposalId(originDomainID, depositNonce);
        proposal = _proposals[proposalID][dataHash];
        hasVoted = _hasVoted(proposal, relayer);
    }

     
    function deposit(uint8 destinationDomainID, bytes32 resourceID, bytes calldata data) external payable notPaused {
        require(msg.value == fee, QBridge invalid fee);

        address handler = resourceIDToHandlerAddress[resourceID];
        require(handler != address(0), QBridge invalid resourceID);

        uint64 depositNonce = ++_depositCounts[destinationDomainID];

        IQBridgeHandler(handler).deposit(resourceID, msg.sender, data);
        emit Deposit(destinationDomainID, resourceID, depositNonce, msg.sender, data);
    }

    function depositETH(uint8 destinationDomainID, bytes32 resourceID, bytes calldata data) external payable notPaused {
        uint option;
        uint amount;
        (option, amount) = abi.decode(data, (uint, uint));

        require(msg.value == amount.add(fee), QBridge invalid fee);

        address handler = resourceIDToHandlerAddress[resourceID];
        require(handler != address(0), QBridge invalid resourceID);

        uint64 depositNonce = ++_depositCounts[destinationDomainID];

        IQBridgeHandler(handler).depositETH{valueamount}(resourceID, msg.sender, data);
        emit Deposit(destinationDomainID, resourceID, depositNonce, msg.sender, data);
    }

    

    function voteProposal(uint8 originDomainID, uint64 depositNonce, bytes32 resourceID, bytes calldata data) external onlyRelayers notPaused {
        address handlerAddress = resourceIDToHandlerAddress[resourceID];
        require(handlerAddress != address(0), QBridge invalid handler);

        uint72 proposalID = combinedProposalId(originDomainID, depositNonce);
        bytes32 dataHash = keccak256(abi.encodePacked(handlerAddress, data));
        Proposal memory proposal = _proposals[proposalID][dataHash];

        if (proposal._status == ProposalStatus.Passed) {
            executeProposal(originDomainID, depositNonce, resourceID, data, true);
            return;
        }

        require(uint(proposal._status) = 1, QBridge proposal already executedcancelled);
        require(!_hasVoted(proposal, msg.sender), QBridge relayer already voted);

        if (proposal._status == ProposalStatus.Inactive) {
            proposal = Proposal({_status  ProposalStatus.Active, _yesVotes  0, _yesVotesTotal  0, _proposedBlock  uint40(block.number)});
            emit ProposalEvent(originDomainID, depositNonce, ProposalStatus.Active, data);
        }
        else if (uint40(block.number.sub(proposal._proposedBlock))  expiry) {
            proposal._status = ProposalStatus.Cancelled;
            emit ProposalEvent(originDomainID, depositNonce, ProposalStatus.Cancelled, dataHash);
        }

        if (proposal._status != ProposalStatus.Cancelled) {
            proposal._yesVotes = _bitmap(proposal._yesVotes, _relayerBit(msg.sender));
            proposal._yesVotesTotal++;
            emit ProposalVote(originDomainID, depositNonce, proposal._status, dataHash);

            if (proposal._yesVotesTotal = relayerThreshold) {
                proposal._status = ProposalStatus.Passed;
                emit ProposalEvent(originDomainID, depositNonce, ProposalStatus.Passed, data);
            }
        }
        _proposals[proposalID][dataHash] = proposal;

        if (proposal._status == ProposalStatus.Passed) {
            executeProposal(originDomainID, depositNonce, resourceID, data, false);
        }
    }


     
    function executeProposal(uint8 originDomainID, uint64 depositNonce, bytes32 resourceID, bytes calldata data, bool revertOnFail) public onlyRelayers notPaused {
        address handlerAddress = resourceIDToHandlerAddress[resourceID];
        uint72 proposalID = combinedProposalId(originDomainID, depositNonce);
        bytes32 dataHash = keccak256(abi.encodePacked(handlerAddress, data));
        Proposal storage proposal = _proposals[proposalID][dataHash];

        require(proposal._status == ProposalStatus.Passed, QBridge Proposal must have Passed status);

        proposal._status = ProposalStatus.Executed;
        IQBridgeHandler handler = IQBridgeHandler(handlerAddress);

        if (revertOnFail) {
            handler.executeProposal(resourceID, data);
        } else {
            try handler.executeProposal(resourceID, data) {
            } catch (bytes memory lowLevelData) {
                proposal._status = ProposalStatus.Passed;
                emit FailedHandlerExecution(lowLevelData);
                return;
            }
        }
        emit ProposalEvent(originDomainID, depositNonce, ProposalStatus.Executed, data);
    }

     
    function cancelProposal(uint8 originDomainID, uint64 depositNonce, bytes32 resourceID, bytes calldata data) public onlyOwnerOrRelayers {
        address handlerAddress = resourceIDToHandlerAddress[resourceID];
        uint72 proposalID = combinedProposalId(originDomainID, depositNonce);
        bytes32 dataHash = keccak256(abi.encodePacked(handlerAddress, data));
        Proposal memory proposal = _proposals[proposalID][dataHash];
        ProposalStatus currentStatus = proposal._status;

        require(currentStatus == ProposalStatus.Active  currentStatus == ProposalStatus.Passed, QBridge cannot be cancelled);
        require(uint40(block.number.sub(proposal._proposedBlock))  expiry, QBridge not at expiry threshold);

        proposal._status = ProposalStatus.Cancelled;
        _proposals[proposalID][dataHash] = proposal;
        emit ProposalEvent(originDomainID, depositNonce, ProposalStatus.Cancelled, data);
    }



    function _relayerBit(address relayer) private view returns (uint) {
        if (relayer == address(0)) return 0;
        return uint(1)  AccessControlIndexUpgradeable.getRoleMemberIndex(RELAYER_ROLE, relayer).sub(1);
    }

    function _hasVoted(Proposal memory proposal, address relayer) private view returns (bool) {
        return (_relayerBit(relayer) & uint(proposal._yesVotes))  0;
    }

    function _bitmap(uint200 source, uint bit) internal pure returns (uint200) {
        uint value = source  bit;
        require(value  2  200, QBridge value does not fit in 200 bits);
        return uint200(value);
    }
}
