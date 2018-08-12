pragma solidity ^0.4.24;

import "./SafeMath.sol";
import "./SafeMath32.sol";
import "./proveth/ProvethVerifier.sol";

contract LibSubmarine is ProvethVerifier {

    using SafeMath for uint256;
    using SafeMath32 for uint32;

    uint256 public revealDepositAmount;   /* TODO: check if can be smaller than uint256 */
    uint32 public challengePeriodLength;
    uint8 public vee = 27;

    mapping(bytes32 => Session) public sessions;
    mapping(uint32 => bytes32) public blockNumberToHash;

    struct Session {
        bool unlocked;
        address dappAddress;
        uint256 commitValue; /* TODO: check if can be smaller than uint256 */
        uint256 commitIndex; /* TODO: check if can be smaller than uint256 */
        uint32 commitBlock;
        uint32 revealBlock;
        bytes data;
    }

    event Unlocked(
        bytes32 indexed _sessionId,
        uint256 _commitValue
    );
    event Revealed(
        bytes32 indexed _sessionId,
        uint256 _commitValue,
        bytes _data,
        bytes32 _witness,
        uint32 _commitBlock,
        uint256 _commitIndex
    );
    event Slashed(
        bytes32 indexed _sessionId,
        uint8 _result,
        address indexed _sender,
        address indexed _submarine,
        uint256 _slashAmount,
        bytes _proofBlob,
        bytes _unsignedCommitTx
    );
    event Finalized(
        bytes32 indexed _sessionId,
        address indexed _sender,
        uint256 _amountTemp,
        uint256 _revealDeposit,
        bytes _dataTemp
    );


    constructor(uint256 _revealDepositAmount, uint32 _challengePeriodLength) public {
        revealDepositAmount = _revealDepositAmount;
        challengePeriodLength = _challengePeriodLength;
    }

    /////////////
    // Getters //
    /////////////

    function getSessionId(
        address _sender,
        address _registry,
        uint256 _commitValue,
        bytes _data,
        bytes32 _witness,
        uint256 _gasPrice,
        uint256 _gasLimit
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(_sender, _registry, _commitValue, _data, _witness, _gasPrice, _gasLimit));
    }

    function getSession(bytes32 _sessionId) public view returns (
        bool unlocked,
        uint256 commitValue,
        uint256 commitIndex,
        uint32 commitBlock,
        uint32 revealBlock,
        bytes data,
        address dappAddress
    ) {
        Session memory sesh = sessions[_sessionId];
        return (
            sesh.unlocked,
            sesh.commitValue,
            sesh.commitIndex,
            sesh.commitBlock,
            sesh.revealBlock,
            sesh.data,
            sesh.dappAddress
        );
    }

    /**
     * @notice Checks if the session is ready to be finalized.
     * @param _sessionId Hash of the session instance representing the commit/reveal transaction
     */
    function isFinalizable(bytes32 _sessionId) public view returns (bool finalized, uint256 commitValue, bytes data) {
        if (block.number > sessions[_sessionId].revealBlock.add(challengePeriodLength)
                    && sessions[_sessionId].unlocked
                    && sessions[_sessionId].revealBlock > 0) {
            return (
                true,
                sessions[_sessionId].commitValue,
                sessions[_sessionId].data
            );
        }
        return (false, 0, "");
    }

    /**
     * @notice Function called by the user to reveal the session.
     * @dev @warning Must be called within 256 blocks of the commit transaction to obtain the correct blockhash.
     * @param _commitBlock Block number in which the commit tx was created.
     * @param _commitIndex Index of the commit tx in the block.
     * @param _dappAddress Address which can finalize the tx and retreive the funds.
     * @param _commitValue Value included in the commit tx.
     * @param _data Data to pass to the receiver dApp.
     * @param _witness Witness
     * @param _gasPrice Gas price
     * @param _gasLimit Gas limit
     */
    function reveal(
        uint32 _commitBlock,
        uint256 _commitIndex,
        address _dappAddress,
        uint256 _commitValue,
        bytes _data,
        bytes32 _witness,
        uint256 _gasPrice,
        uint256 _gasLimit
    ) public payable {
        bytes32 sessionId = keccak256(abi.encodePacked(
            msg.sender,
            address(this),
            _commitValue,
            _data, _witness,
            _gasPrice,
            _gasLimit
        )); //implicitly checks msg.sender is A to generate valid sessionId
        require(msg.value >= revealDepositAmount, 'Reveal deposit not provided');
        require(sessions[sessionId].revealBlock == 0, 'The tx is already revealed');
        require(!sessions[sessionId].unlocked, 'The tx should not be already unlocked');
        if (blockhash(_commitBlock) != 0x0) {
            blockNumberToHash[_commitBlock] = blockhash(_commitBlock);
        } // TODO we need to throw or do something to tell people when we can't find the block hash (too old)
        sessions[sessionId].commitValue = _commitValue;
        sessions[sessionId].commitIndex = _commitIndex;
        sessions[sessionId].commitBlock = _commitBlock;
        sessions[sessionId].revealBlock = uint32(block.number);
        sessions[sessionId].data = _data;
        sessions[sessionId].dappAddress = _dappAddress;
        emit Revealed(sessionId, _commitValue, _data, _witness, _commitBlock, _commitIndex);
    }

    /**
     * @notice Function called by the submarine address to unlock the session.
     * @param _sessionId Hash of the session instance representing the commit/reveal transaction
     */
     // TODO: check if enum can be used for state transitions
    function unlock(bytes32 _sessionId) public payable {
        require(sessions[_sessionId].revealBlock > 0
            && !sessions[_sessionId].unlocked,
            'The tx is already unlocked, or not yet revealed'
        );
        require(msg.value == sessions[_sessionId].commitValue, 'The unlocked value does not match the revealed value');
        sessions[_sessionId].unlocked = true;
        emit Unlocked(_sessionId, msg.value);
    }

    // Merkle Patricia Proof Struct
    struct MPProof{
        uint8 result;
        uint256 index;
        uint256 nonce;
        uint256 gasprice;
        uint256 startgas;
        bytes to;
        uint256 value;
        bytes data;
        uint256 v;
        uint256 r;
        uint256 s;
    }

    struct UnsignedTx{
        bool valid;
        bytes32 sigHash;
        uint256 nonce;
        uint256 gasprice;
        uint256 startgas;
        address to;
        uint256 value;
        bytes data;
    }

    /**
     * @notice Allows anyone to submit a proof that the reveal tx does not match the commit tx during the duration of the challenge period
     * @notice If the proof is valid, this means the user cheated and the challenger receives the funds. (TODO: deal with case where funds are locked if challenge submitted before unlock)
     * @param _sessionId Hash of the session instance representing the commit/reveal transaction
     * @param _proofBlob proofBlob
     * @param _unsignedCommitTx unsignedCommitTx
     */
    function challenge(bytes32 _sessionId, bytes _proofBlob, bytes _unsignedCommitTx) public {
        require(block.number < sessions[_sessionId].revealBlock.add(challengePeriodLength), 'Challenge period is not active');
        require(sessions[_sessionId].revealBlock > 0, 'Reveal tx has not yet been sent'); /* TODO: Check if need to require unlock has occured */

        MPProof memory mpProof;
        (mpProof.result, mpProof.index, mpProof.nonce, , , mpProof.to, mpProof.value, mpProof.data, , ,) = txProof(blockNumberToHash[sessions[_sessionId].commitBlock], _proofBlob);

        // TX_PROOF_RESULT_INVALID = 0;
        // TX_PROOF_RESULT_PRESENT = 1;
        // TX_PROOF_RESULT_ABSENT = 2;
        require(mpProof.result != 0, 'The proof is invalid');

        UnsignedTx memory unsignedTx;
        (,unsignedTx.sigHash , , , , , , ) = decodeAndHashUnsignedTx(_unsignedCommitTx);

        //ecrecover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) returns (address)
        address submarine = ecrecover(
            unsignedTx.sigHash,
            vee,
            keccak256(abi.encodePacked(_sessionId, byte(1))),
            keccak256(abi.encodePacked(_sessionId, byte(0)))
        );

        /*
        The condition for slashing are as follows:
        1. Proof result == 2 -> commit tx is absent.
        2. Proof result == 1 -> commit tx is present, but falsified.
           One of the following condition must be true to prove the commit is falsified:
           - proof.to != address(submarine)
           - proof.value <= sessions[_sessionId].commitValue
           - proof.data != 0x0
           - proof.nonce != 0
        */
        if (mpProof.index == sessions[_sessionId].commitIndex
            && (mpProof.result == 2
                || (mpProof.result == 1
                    && (keccak256(abi.encodePacked(mpProof.to)) != keccak256(abi.encodePacked(submarine))
                        || mpProof.value <= sessions[_sessionId].commitValue
                        || mpProof.data.length != 0
                        || mpProof.nonce != 0)))
        ) {
            uint256 slashAmount = sessions[_sessionId].commitValue.add(revealDepositAmount);
            msg.sender.transfer(slashAmount);
            emit Slashed(_sessionId, mpProof.result, msg.sender, submarine, slashAmount, _proofBlob, _unsignedCommitTx);
            delete sessions[_sessionId];
        } else {
            revert("Invalid Challenge");
        }
    }

    /**
     * @notice Allows the dApp to retrieve the commit value and the reveal deposit.
     * @dev The dDapp is responsible for refunding the reveal deposit to the user (TODO: add user address parameter)
     * @param _sessionId Hash of the session instance representing the commit/reveal transaction
     */
    function finalize(bytes32 _sessionId) public returns (uint256 commitValue, bytes memory data) {
        require(msg.sender == sessions[_sessionId].dappAddress, 'The msg.sender does not match the dApp in the reveal tx');
        require(block.number > sessions[_sessionId].revealBlock.add(challengePeriodLength)
            && sessions[_sessionId].unlocked,
            'The challenge period is not over, the tx was not unlocked, or the session was slashed');
        commitValue = sessions[_sessionId].commitValue;
        data = sessions[_sessionId].data;
        sessions[_sessionId].dappAddress.transfer(commitValue.add(revealDepositAmount)); /* TODO: check if it is possible to return the deposit to the user directly */
        emit Finalized(_sessionId, msg.sender, commitValue, revealDepositAmount, data);
        delete sessions[_sessionId];
    }
}
