pragma solidity ^0.5.0;

import "./openzeppelin-solidity/contracts/math/SafeMath.sol";
import "./proveth/ProvethVerifier.sol";
import "./proveth/Solidity-RLP/contracts/RLPReader.sol";

contract LibSubmarineSimple is ProvethVerifier {

    using SafeMath for uint256;

    ////////////
    // Events //
    ////////////

    event Unlocked(
        bytes32 indexed _submarineId,
        uint96 _commitValue
    );
    event Revealed(
        bytes32 indexed _submarineId,
        uint96 _commitValue,
        bytes32 _witness,
        bytes32 _commitBlockHash,
        address _submarineAddr
    );

    /////////////
    // Storage //
    /////////////

    // the ECDSA v parameter: 27 allows us to be broadcast on any network (i.e.
    // mainnet, ropsten, rinkeby etc.)
    uint8 public vee = 27;
    // How many blocks must a submarine be committed for before being revealed.
    // For now, we choose a default of 20. Since a contract cannot look back
    // further than 256 blocks (limit comes from EVM BLOCKHASH opcode), we use a
    // uint8.
    uint8 public commitPeriodLength = 20;

    // Stored "session" state information
    mapping(bytes32 => SubmarineSession) public sessions;

    // A submarine send is considered "finished" when the amount revealed and
    // unlocked are both greater than zero, and the amount for the unlock is
    // greater than or equal to the reveal amount.
    struct SubmarineSession {
        // Amount the reveal transaction revealed would be sent in wei. When
        // greater than zero, the submarine has been revealed. A uint96 is large
        // enough to store the entire Ethereum supply (~ 1e26 Wei) 700 times
        // over.
        uint96 amountRevealed;
        // Amount the unlock transaction recieved in wei. When greater than
        // zero, the submarine has been unlocked; however the submarine may not
        // be finished, until the unlock amount is GREATER than the promised
        // revealed amount.
        uint96 amountUnlocked;
        // Block number of block containing commit transaction.
        uint32 commitTxBlockNumber;
        // Index of commit transaction within its block.
        uint16 commitTxIndex;
    }

    /////////////
    // Getters //
    /////////////

    /*
       Keeping these functions makes instantiating a contract more expensive for gas costs, but helps with testing
    */

    /**
     * @notice Helper function to return a submarine ID for associated given
     *         input data
     * @param _user address of the user that initiated the full submarine flow
     * @param _libsubmarine address of submarine contract. Usually address(this)
     * @param _commitValue amount of ether supposed to be sent in this submarine
     *        commit
     * @param _embeddedDAppData  optional Data passed embedded within the unlock
     *        tx. Clients can put whatever data they want committed to for their
     *        specific use case
     * @param _witness random commit secret data
     * @param _gasPrice the gas price that will be paid in the unlock tx
     * @param _gasLimit the gas limit that will be set in the unlock tx
     */
    function getSubmarineId(
        address _user,
        address _libsubmarine,
        uint256 _commitValue,
        bytes memory _embeddedDAppData,
        bytes32 _witness,
        uint256 _gasPrice,
        uint256 _gasLimit
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            _user,
            _libsubmarine,
            _commitValue,
            _embeddedDAppData,
            _witness,
            _gasPrice,
            _gasLimit
        ));
    }

    /**
     * @notice Return the session information associated with a submarine ID.
     * @return amountRevealed amount promised by user to be unlocked in reveal
     * @return amountUnlocked amount actually unlocked by the user at this time
     * @return commitTxBlockNumber block number that the user proved holds the
     *         commit TX.
     * @return commitTxIndex the index in the block where the commit tx is.
     */
    function getSubmarineState(bytes32 _submarineId) public view returns (
        uint96 amountRevealed,
        uint96 amountUnlocked,
        uint32 commitTxBlockNumber,
        uint16 commitTxIndex
    ) {
        SubmarineSession memory sesh = sessions[_submarineId];
        return (
            sesh.amountRevealed,
            sesh.amountUnlocked,
            sesh.commitTxBlockNumber,
            sesh.commitTxIndex
        );
    }

   /**
     * @notice Singleton session getter - amount of money sent in submarine send
     * @return amountRevealed amount promised by user to be unlocked in reveal
     */
    function getSubmarineAmount(bytes32 _submarineId) public view returns (
        uint96 amount
    ) {
        SubmarineSession memory sesh = sessions[_submarineId];
        return sesh.amountRevealed;
    }

    /**
     * @notice Singleton session getter - Commit TX Block number
     * @return commitTxBlockNumber block number that the user proved holds the
     *         commit TX.
     */
    function getSubmarineCommitBlockNumber(bytes32 _submarineId)
        public view returns (uint32 commitTxBlockNumber)
    {
        SubmarineSession memory sesh = sessions[_submarineId];
        return sesh.commitTxBlockNumber;
    }

    /**
     * @notice Singleton session getter - Commit TX Block index inside block
     * @return commitTxIndex the index in the block where the commit tx is.
     */
    function getSubmarineCommitTxIndex(bytes32 _submarineId)
        public view returns(uint16 commitTxIndex)
    {
        SubmarineSession memory sesh = sessions[_submarineId];
        return sesh.commitTxIndex;
    }

    /////////////
    // Setters //
    /////////////

    /**
     * @notice Consumers of this library should implement their custom reveal
     *         logic by overriding this method. This function is a handler that
     *         is called by reveal. A user calls reveal, LibSubmarine does the
     *         required submarine specific stuff, and then calls this handler
     *         for client specific implementation/handling.
     * @param  _submarineId the ID for this submarine workflow
     * @param _embeddedDAppData optional Data passed embedded within the unlock
     *        tx. Clients can put whatever data they want committed to for their
     *        specific use case
     * @param _value amount of ether revealed
     *
     */
    function onSubmarineReveal(
        bytes32 _submarineId,
        bytes memory _embeddedDAppData,
        uint256 _value
    ) internal;

    /**
     * @notice Function called by the user to reveal the session.
     * @dev warning Must be called within 256 blocks of the commit transaction
     *      to obtain the correct blockhash.
     * @param _commitTxBlockNumber Number of block in which the commit tx was
     *        included.
     * @param _embeddedDAppData optional Data passed embedded within the unlock
     * tx. This should probably be null
     * @param _witness Witness "secret" we committed to
     * @param _rlpUnlockTxUnsigned RLP encoded unsigned unlock transaction
     * @param _proofBlob the proof blob that gets passed to proveth to verify
     *        merkle trie inclusion in a prior block.
     */
    function reveal(
        uint32 _commitTxBlockNumber,
        bytes memory _embeddedDAppData,
        bytes32 _witness,
        bytes memory _rlpUnlockTxUnsigned,
        bytes memory _proofBlob
    ) public {
        bytes32 commitBlockHash = blockhash(_commitTxBlockNumber);
        require(
            commitBlockHash != 0x0,
            "Commit Block is too old to retreive block hash or does not exist"
        );
        require(
            block.number.sub(_commitTxBlockNumber) > commitPeriodLength,
            "Wait for commitPeriodLength blocks before revealing");

        UnsignedTransaction memory unsignedUnlockTx =
            decodeUnsignedTx(_rlpUnlockTxUnsigned);
        bytes32 unsignedUnlockTxHash = keccak256(_rlpUnlockTxUnsigned);

        require(unsignedUnlockTx.nonce == 0);
        require(unsignedUnlockTx.to == address(this));

        // fullCommit = (addressA + addressC + aux(sendAmount) + dappData + w + aux(gasPrice) + aux(gasLimit))
        bytes32 submarineId = getSubmarineId(
            msg.sender,
            address(this),
            unsignedUnlockTx.value,
            _embeddedDAppData,
            _witness,
            unsignedUnlockTx.gasprice,
            unsignedUnlockTx.startgas
        );

        require(
            sessions[submarineId].commitTxBlockNumber == 0,
            "The tx is already revealed"
        );

        SignedTransaction memory provenCommitTx;
        uint8 provenCommitTxResultValid;
        uint256 provenCommitTxIndex;
        (
            provenCommitTxResultValid,
            provenCommitTxIndex,
            provenCommitTx.nonce,
            /* gasprice */,
            /* startgas */,
            provenCommitTx.to,
            provenCommitTx.value,
            provenCommitTx.data,
            /* v */ ,
            /* r */,
            /* s */,
            provenCommitTx.isContractCreation
        ) = txProof(commitBlockHash, _proofBlob);

        require(
            provenCommitTxResultValid == TX_PROOF_RESULT_PRESENT,
            "The proof is invalid"
        );
        require(provenCommitTx.value >= unsignedUnlockTx.value);
        require(provenCommitTx.isContractCreation == false);
        require(provenCommitTx.data.length == 0);

        address submarine = ecrecover(
            unsignedUnlockTxHash,
            vee,
            keccak256(abi.encodePacked(submarineId, byte(uint8(1)))),
            keccak256(abi.encodePacked(submarineId, byte(uint8(0))))
        );

        require(provenCommitTx.to == submarine);
        sessions[submarineId].amountRevealed = uint96(unsignedUnlockTx.value);
        sessions[submarineId].commitTxBlockNumber = _commitTxBlockNumber;
        sessions[submarineId].commitTxIndex = uint16(provenCommitTxIndex);
        emit Revealed(
            submarineId,
            uint96(unsignedUnlockTx.value),
            _witness,
            commitBlockHash,
            submarine
        );

        onSubmarineReveal(
            submarineId,
            _embeddedDAppData,
            unsignedUnlockTx.value
        );
    }

    /**
     * @notice Function called by the submarine address to unlock the session.
     * @dev warning this function does NO validation whatsoever.
     *      ALL validation is done in the reveal.
     * @param _submarineId committed data; The commit instance representing the
     *        commit/reveal transaction
     */
    function unlock(bytes32 _submarineId) public payable {
        // Required to prevent an attack where someone would unlock after an
        // unlock had already happened, and try to overwrite the unlock amount.
        require(
            sessions[_submarineId].amountUnlocked < msg.value,
            "You can never unlock less money than you've already unlocked."
        );
        sessions[_submarineId].amountUnlocked = uint96(msg.value);
        emit Unlocked(_submarineId, uint96(msg.value));
    }

    /**
     * @notice revealedAndUnlocked can be called to determine if a submarine
     *         send transaction has been successfully completed for a given
     *         submarineId
     * @param _submarineId committed data; The commit instance representing the
     *        commit/reveal transaction
     * @return bool whether the commit has a stored submarine send that has been
     *         completed for it (0 for failure / not yet finished, 1 for
     *         successful submarine TX)
     */
    function revealedAndUnlocked(
        bytes32 _submarineId
    ) public view returns(bool success) {
        SubmarineSession memory sesh = sessions[_submarineId];
        return sesh.amountUnlocked != 0
            && sesh.amountRevealed != 0
            && sesh.amountUnlocked >= sesh.amountRevealed;
    }
}
