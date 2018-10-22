pragma solidity ^0.4.24;

import "./SafeMath.sol";
import "./proveth/ProvethVerifier.sol";

contract LibSubmarineSimple is ProvethVerifier {

    using SafeMath for uint256;

    ////////////
    // Events //
    ////////////

    event Unlocked(
        bytes32 indexed _commitId,
        uint256 _commitValue
    );
    event Revealed(
        bytes32 indexed _commitId,
        uint256 _commitValue,
        bytes32 _witness,
        bytes32 _commitBlockHash,
        address submarineAddr
    );

    /////////////
    // Storage //
    /////////////

    uint8 public vee = 27; // the ECDSA v parameter: 27 allows us to be broadcast on any network (i.e. mainnet, ropsten, rinkeby etc.)
    uint32 public commitPeriodLength; // How many blocks must a submarine be committed for before being revealed

    mapping(bytes32 => CommitData) public commitData; // stored "session" state information

    // A submarine send is considered "finished" when the amount revealed and unlocked are both greater than zero, and the amount for the unlock is greater than or equal to the reveal amount.
    struct CommitData {
        uint128 amountRevealed; // amount the reveal transaction revealed would be sent in wei. When greater than zero, the submarine has been revealed.
        uint128 amountUnlocked; // amount the unlock transaction recieved in wei. When greater than zero, the submarine has been unlocked; however the submarine may not be finished, until the unlock amount is GREATER than the promised revealed amount.
    }
    
    // Response from proveth Merkle Patricia Proof Struct
    struct ProvenTransaction{
        uint8 result;
        uint256 index;
        uint256 nonce;
        uint256 gasprice;
        uint256 startgas;
        address to;
        uint256 value;
        bytes data;
        uint256 v;
        uint256 r;
        uint256 s;
        bool is_contract_creation;
    }

    /**
     * @notice Constructor. Assigns the commit period length.
     * @param _commitPeriodLength - the length of blocks required after a commit was made before it can be accepted to be revealed. Recommended sane default: 20 blocks
     */
    constructor(uint32 _commitPeriodLength) public {
        commitPeriodLength = _commitPeriodLength;
    }

    /////////////
    // Getters //
    /////////////

    /*
       Keeping these functions makes instantiating a contract more expensive for gas costs, but helps with testing
    */

    function getCommitId(
        address _user,
        address _libsubmarine,
        uint256 _commitValue,
        bytes _embeddedDAppData,
        bytes32 _witness,
        uint256 _gasPrice,
        uint256 _gasLimit
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(_user, _libsubmarine, _commitValue, _embeddedDAppData, _witness, _gasPrice, _gasLimit));
    }
    
    function getCommitState(bytes32 _commitId) public view returns (
        uint128 amountRevealed,
        uint128 amountUnlocked
    ) {
        CommitData memory sesh = commitData[_commitId];
        return (
            sesh.amountRevealed,
            sesh.amountUnlocked
        );
    }

    /////////////
    // Setters //
    /////////////

    /**
     * @notice Function called by the user to reveal the session.
     * @dev warning Must be called within 256 blocks of the commit transaction to obtain the correct blockhash.
     * @param _commitBlockNumber Block number in which the commit tx was included.
     * @param _unlockAmount Value (i.e. how much money was sent) included in the commit tx.
     * @param _embeddedDAppData optional Data passed embedded within the unlock tx. This should probably be null
     * @param _witness Witness "secret" we committed to
     * @param _unlockGasPrice Gas price of the unlock TX
     * @param _unlockGasLimit Gas limit of the unlock TX
     * @param _unlockTXHash full hash of the signed unlock transaction
     * @param _proofBlob the Proof blob that gets passed to ethprove to verify merkle tree inclusion in a prior block.
     */
    function reveal(
        uint32 _commitBlockNumber,
        bytes _embeddedDAppData,
        uint128 _unlockAmount,
        bytes32 _witness,
        uint256 _unlockGasPrice,
        uint256 _unlockGasLimit,
        bytes32 _unlockTXHash,
        bytes _proofBlob
    ) public {
        bytes32 commitBlockHash = blockhash(_commitBlockNumber);
        // fullCommit = (addressA + addressC + aux(sendAmount) + dappData + w + aux(gasPrice) + aux(gasLimit))

        bytes32 commitId = getCommitId(
            msg.sender,
            address(this),
            _unlockAmount,
            _embeddedDAppData,
            _witness,
            _unlockGasPrice,
            _unlockGasLimit
        );

        require(commitData[commitId].amountRevealed == 0, "The tx is already revealed");
        require(commitBlockHash != 0x0, "Commit Block is too old to retreive block hash (more than 256 blocks), or does not exist");
        require(block.number.sub(_commitBlockNumber) > commitPeriodLength, "You must wait long enough to allow the committing period to end before revealing");
        ProvenTransaction memory proven_tx;
        // Commented out for theoretical gas savings
        (proven_tx.result, /* index */, proven_tx.nonce, /* gasprice */, /* startgas */, proven_tx.to, proven_tx.value, /* data */, /* v */ , /* r */, /* s */, proven_tx.is_contract_creation ) = txProof(commitBlockHash, _proofBlob);

        // TX_PROOF_RESULT_PRESENT = 1;
        // TX_PROOF_RESULT_ABSENT = 2;
        require(proven_tx.result == 1, "The proof is invalid");
        require(proven_tx.value >= _unlockAmount);
        require(proven_tx.nonce == 0);
        require(proven_tx.is_contract_creation == false);

        address submarine = ecrecover(
            _unlockTXHash,
            vee,
            keccak256(abi.encodePacked(commitId, byte(1))),
            keccak256(abi.encodePacked(commitId, byte(0)))
        );

        require(keccak256(abi.encodePacked(proven_tx.to)) == keccak256(abi.encodePacked(submarine)), "The proven address should match the revealed address, or the txhash/witness is wrong.");
        commitData[commitId].amountRevealed = _unlockAmount;
        emit Revealed(commitId, _unlockAmount, _witness, commitBlockHash, submarine);
    }
    
    /**
     * @notice Function called by the submarine address to unlock the session.
     * @dev warning this function does NO validation whatsoever. ALL validation is done in the reveal. 
     * @param _commitId committed data; The commit instance representing the commit/reveal transaction
     */
    function unlock(bytes32 _commitId) public payable {
        // Required to prevent an attack where someone would unlock after an unlock had already happened, and try to overwrite the unlock amount.
        require(commitData[_commitId].amountUnlocked < msg.value, "You can never unlock less money than you've already unlocked.");
        commitData[_commitId].amountUnlocked = uint128(msg.value); // right now, a uint128 is enough to store all of the ether/wei in existence. (i.e. 2^128 > 100,000,000 * 10**18)
        emit Unlocked(_commitId, msg.value);
    }
    
    /**
     * @notice Finished function can be called to determine if a submarine send transaction has been successfully completed for a given committed
     * @param _commitId committed data; The commit instance representing the commit/reveal transaction
     * @return bool whether the commit has a stored submarine send that has been completed for it (0 for failure / not yet finished, 1 for successful submarine TX)
     */
    function finished(bytes32 _commitId) public view returns(bool success) {
        return commitData[_commitId].amountUnlocked != 0
            && commitData[_commitId].amountRevealed != 0
            && commitData[_commitId].amountUnlocked >= commitData[_commitId].amountRevealed;
    }

}
