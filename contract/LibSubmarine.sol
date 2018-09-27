pragma solidity ^0.4.24;

import "./SafeMath.sol";
import "./SafeMath32.sol";
import "./proveth/ProvethVerifier.sol";

contract LibSubmarine is ProvethVerifier {

    using SafeMath for uint256;
    using SafeMath32 for uint32;

    constructor(uint256 _revealDepositAmount, uint32 _challengePeriodLength) public {
        revealDepositAmount = _revealDepositAmount;
        challengePeriodLength = _challengePeriodLength;
    }

    ////////////
    // Events //
    ////////////

    event Unlocked(
        bytes32 indexed _sessionId,
        uint256 _commitValue
    );
    event Revealed(
        bytes32 indexed _sessionId,
        uint256 _commitValue,
        bytes _commitData,
        bytes32 _witness,
        bytes32 _commitBlockHash,
        uint32 _commitBlock,
        uint256 _commitIndex
    );
    event Slashed(
        bytes32 indexed _sessionId,
        uint8 _result,
        address indexed _sender,
        address indexed _submarine,
        uint256 _slashAmount/*,
        bytes _proofBlob,
        bytes _unsignedCommitTx*/ // Removed due to stack limit
    );
    event Finalized(
        bytes32 indexed _sessionId,
        address indexed _sender,
        uint256 _amountTemp,
        uint256 _revealDeposit,
        bytes _commitData
    );

    /////////////
    // Storage //
    /////////////

    uint256 public revealDepositAmount;
    uint32 public challengePeriodLength;
    uint8 public vee = 27;

    mapping(bytes32 => SessionData) public sessionData;

    struct SessionData {
        bool unlocked;        // set in unlock, used in reveal and finalize
        uint32 revealBlock;   // set in reveal, used in unlock, challenge, and finalize
        uint256 commitValue;  // set in reveal, used in unlock, challenge, and finalize
        bytes32 hashedCommit; // set in reveal, used in challenge, and finalize
    }

    /* Layout of hashedCommit

    bytes32 hashedCommit = keccak256(abi.encodePacked(
        _commitBlockHash,
        _commitBlock,
        _commitIndex,
        _dappAddress,
        _commitData
    ));

    require(hashedCommit == sessionData[_sessionId].hashedCommit, "HashedCommit does not match sessionData");

    struct HashedCommit {
        bytes32 commitBlockHash // set in reveal, used in challenge
        uint32 commitBlock;     // set in reveal, used in challenge
        uint256 commitIndex;    // set in reveal, used in challenge
        address dappAddress;    // set in reveal, used in finalize
        bytes commitData;       // set in reveal, used in finalize
    }
    */

    /////////////
    // Getters //
    /////////////

    function getSessionId(
        address _user,
        address _libsubmarine,
        uint256 _commitValue,
        bytes _commitData,
        bytes32 _witness,
        uint256 _gasPrice,
        uint256 _gasLimit
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(_user, _libsubmarine, _commitValue, _commitData, _witness, _gasPrice, _gasLimit));
    }

    function getSession(bytes32 _sessionId) public view returns (
        bool unlocked,
        uint32 revealBlock,
        uint256 commitValue,
        bytes32 hashedCommit
    ) {
        SessionData memory sesh = sessionData[_sessionId];
        return (
            sesh.unlocked,
            sesh.revealBlock,
            sesh.commitValue,
            sesh.hashedCommit
        );
    }

    function getBlockHash(uint32 _blockNumber) public view returns (bytes32 blockHash) {
        blockHash = blockhash(_blockNumber);
    }

    function getHashedCommit(
        bytes32 _commitBlockHash,
        uint32 _commitBlock,
        uint256 _commitIndex,
        address _dappAddress,
        bytes _commitData
    ) public pure returns (bytes32 hashedCommit) {
        hashedCommit = keccak256(abi.encodePacked(
            _commitBlockHash,
            _commitBlock,
            _commitIndex,
            _dappAddress,
            _commitData
        ));
    }

    function isFinalizable(bytes32 _sessionId) public view returns (bool) {
        return (block.number > sessionData[_sessionId].revealBlock.add(challengePeriodLength) && sessionData[_sessionId].unlocked);
    }

    /////////////
    // Setters //
    /////////////

    /**
     * @notice Function called by the user to reveal the session.
     * @dev @warning Must be called within 256 blocks of the commit transaction to obtain the correct blockhash.
     * @param _commitBlock Block number in which the commit tx was created.
     * @param _commitIndex Index of the commit tx in the block.
     * @param _commitValue Value included in the commit tx.
     * @param _dappAddress Address which can finalize the tx and retreive the funds.
     * @param _commitData Data to pass to the receiver dApp.
     * @param _witness Witness
     * @param _gasPrice Gas price
     * @param _gasLimit Gas limit
     */
    function reveal(
        uint32 _commitBlock,
        uint256 _commitIndex,
        uint256 _commitValue,
        address _dappAddress,
        bytes _commitData,
        bytes32 _witness,
        uint256 _gasPrice,
        uint256 _gasLimit
    ) public payable {

        bytes32 commitBlockHash = blockhash(_commitBlock);
        bytes32 sessionId = keccak256(abi.encodePacked(
            msg.sender,
            address(this),
            _commitValue,
            _commitData,
            _witness,
            _gasPrice,
            _gasLimit
        ));

        require(msg.value >= revealDepositAmount, "Reveal deposit not provided");
        require(sessionData[sessionId].revealBlock == 0, "The tx is already revealed");
        require(!sessionData[sessionId].unlocked, "The tx should not be already unlocked");
        require(commitBlockHash != 0x0, "Commit Block is too old to retreive block hash (more than 256 blocks)");

        sessionData[sessionId].revealBlock = uint32(block.number);
        sessionData[sessionId].commitValue = _commitValue;
        sessionData[sessionId].hashedCommit = keccak256(abi.encodePacked(
            commitBlockHash,
            _commitBlock,
            _commitIndex,
            _dappAddress,
            _commitData
        ));
        emit Revealed(sessionId, _commitValue, _commitData, _witness, commitBlockHash, _commitBlock, _commitIndex);
    }

    /**
     * @notice Function called by the submarine address to unlock the session.
     * @param _sessionId Hash of the session instance representing the commit/reveal transaction
     */
    function unlock(bytes32 _sessionId) public payable {
        require(sessionData[_sessionId].revealBlock > 0
            && !sessionData[_sessionId].unlocked,
            "The tx is already unlocked, or not yet revealed"
        );
        require(msg.value == sessionData[_sessionId].commitValue, "The unlocked value does not match the revealed value");
        sessionData[_sessionId].unlocked = true;
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
    function challenge(
        bytes32 _sessionId,
        bytes _proofBlob,
        bytes _unsignedCommitTx,
        bytes32 _commitBlockHash,
        uint32 _commitBlock,
        uint256 _commitIndex,
        address _dappAddress,
        bytes _commitData
    ) public {

        SessionData memory sesh = sessionData[_sessionId];
        bytes32 hashedCommit = keccak256(abi.encodePacked(
            _commitBlockHash,
            _commitBlock,
            _commitIndex,
            _dappAddress,
            _commitData
        ));

        require(hashedCommit == sesh.hashedCommit, "HashedCommit does not match sessionData");
        require(block.number < sesh.revealBlock.add(challengePeriodLength), "Challenge period is not active");
        require(sesh.revealBlock > 0, "Reveal tx has not yet been sent"); /* TODO: Check if need to require unlock has occured */

        MPProof memory mpProof;
        (mpProof.result, mpProof.index, mpProof.nonce, , , mpProof.to, mpProof.value, mpProof.data, , ,) = txProof(_commitBlockHash, _proofBlob);

        // TX_PROOF_RESULT_INVALID = 0;
        // TX_PROOF_RESULT_PRESENT = 1;
        // TX_PROOF_RESULT_ABSENT = 2;
        require(mpProof.result != 0, "The proof is invalid");

        UnsignedTx memory unsignedTx;
        (,unsignedTx.sigHash , , , , , , ) = decodeAndHashUnsignedTx(_unsignedCommitTx);

        //ecrecover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) returns (address)
        // address submarine = ecrecover(
        //     unsignedTx.sigHash,
        //     vee,
        //     keccak256(abi.encodePacked(_sessionId, byte(1))),
        //     keccak256(abi.encodePacked(_sessionId, byte(0)))
        // );

        address submarine = extractAddress(unsignedTx.sigHash, _sessionId);

        /*
        The condition for slashing are as follows:
        1. Proof result == 2 -> commit tx is absent.
        2. Proof result == 1 -> commit tx is present, but falsified.
           One of the following condition must be true to prove the commit is falsified:
           - proof.to != address(submarine)
           - proof.value <= sesh.commitValue
           - proof.data != 0x0
           - proof.nonce != 0
        */
        if (mpProof.index == _commitIndex
            && (mpProof.result == 2
                || (mpProof.result == 1
                    && (keccak256(abi.encodePacked(mpProof.to)) != keccak256(abi.encodePacked(submarine))
                        || mpProof.value <= sesh.commitValue
                        || mpProof.data.length != 0
                        || mpProof.nonce != 0)))
        ) {
            uint256 slashAmount = sesh.commitValue.add(revealDepositAmount);
            msg.sender.transfer(slashAmount);
            emit Slashed(_sessionId, mpProof.result, msg.sender, submarine, slashAmount/*, _proofBlob, _unsignedCommitTx */);
            delete sessionData[_sessionId];
        } else {
            revert("Invalid Challenge");
        }
    }

    function extractAddress(bytes32 _sighash, bytes32 _sessionId) internal returns(address submarine) {
        submarine = ecrecover(
            _sighash,
            vee,
            keccak256(abi.encodePacked(_sessionId, byte(1))),
            keccak256(abi.encodePacked(_sessionId, byte(0)))
        );
    }

    /**
     * @notice Allows the dApp to retrieve the commit value and the reveal deposit.
     * @dev The dDapp is responsible for refunding the reveal deposit to the user (TODO: add user address parameter)
     * @param _sessionId Hash of the session instance representing the commit/reveal transaction
     */
    function finalize(
        bytes32 _sessionId,
        bytes32 _commitBlockHash,
        uint32 _commitBlock,
        uint256 _commitIndex,
        address _dappAddress,
        bytes _commitData
    ) public returns (
        uint256 commitValue,
        bytes memory commitData
    ) {

        SessionData memory sesh = sessionData[_sessionId];
        bytes32 hashedCommit = keccak256(abi.encodePacked(
            _commitBlockHash,
            _commitBlock,
            _commitIndex,
            _dappAddress,
            _commitData
        ));

        require(hashedCommit == sesh.hashedCommit, "HashedCommit does not match sessionData");
        require(msg.sender == _dappAddress, "The msg.sender does not match the dApp in the reveal tx");
        require(block.number > sesh.revealBlock.add(challengePeriodLength) && sesh.unlocked, "The challenge period is not over, the tx was not unlocked, or the session was slashed");

        commitValue = sesh.commitValue;
        commitData = _commitData;
        _dappAddress.transfer(commitValue.add(revealDepositAmount)); /* TODO: check if it is possible to return the deposit to the user directly */

        emit Finalized(_sessionId, msg.sender, commitValue, revealDepositAmount, commitData);

        delete sessionData[_sessionId];
    }
}
