pragma solidity ^0.4.24;

import "./SafeMath.sol";
import "./proveth/ProvethVerifier.sol";

contract LibSubmarine is MerklePatriciaVerifier {

    using SafeMath for uint256;

    uint256 public revealDeposit;
    uint256 public challengePeriod;
    uint8 vee = 27;

    mapping(bytes32 => Session) public sessions; // Does this need to be bytes32?
    mapping(uint256 => bytes32) public blockNumberToHash;

    struct Session {
        bool unlocked; // Can be replaced with
        bool revealed; // Can be replaced with checking deposit > 0
        bool slashed; // Can be replaced with checking deposit > 0
        uint256 unlockAmount;
        uint256 commitBlock; // Check if this value can be smaller than uint256
        uint256 commitIndex; // Check if this value can be smaller than uint256
        uint256 revealBlock; // when is this used? can be smaller than uint256
        bytes data;
        address dappAddress;
    }

    event Unlocked(bytes32 indexed _sessionId, uint256 _unlockAmount);
    event Revealed(bytes32 indexed _sessionId, uint256 _unlockAmount, bytes _data, bytes32 _witness, uint256 _commitBlock, uint256 _commitIndex);
    event Slashed(bytes32 indexed _sessionId, uint8 _result, address indexed _sender, address indexed _proxy, uint256 _slashAmount, bytes _proofBlob, bytes _unsignedCommitTx);
    event Finalized(bytes32 indexed _sessionId, address indexed _sender, uint256 _amountTemp, uint256 _revealDeposit, bytes _dataTemp);

    constructor(uint256 _revealDeposit, uint256 _challengePeriod) public {
        revealDeposit = _revealDeposit;
        challengePeriod = _challengePeriod;
    }

    //////////////////
    // Temp Getters //
    //////////////////

    function getSessionId(address _sender, address _registry, uint256 _unlockAmount, bytes _data, bytes32 _witness, uint256 _gasPrice, uint256 _gasLimit) public pure returns (bytes32) {
        return keccak256(_sender, _registry, _unlockAmount, _data, _witness, _gasPrice, _gasLimit);
    }

    function getSession(bytes32 _sessionId) public view returns (
        bool unlocked,
        bool revealed,
        bool slashed,
        uint256 unlockAmount,
        uint256 commitBlock,
        uint256 commitIndex,
        uint256 revealBlock,
        bytes data,
        address dappAddress
    ) {
        Session memory sesh = sessions[_sessionId];
        return (
            sesh.unlocked,
            sesh.revealed,
            sesh.slashed,
            sesh.unlockAmount,
            sesh.commitBlock,
            sesh.commitIndex,
            sesh.revealBlock,
            sesh.data,
            sesh.dappAddress
        );
    }

    //////////////////
    // Code to Keep //
    //////////////////

    function reveal(uint256 _commitBlock, uint256 _commitIndex, address _dappAddress, uint256 _unlockAmount, bytes _data, bytes32 _witness, uint256 _gasPrice, uint256 _gasLimit) public payable {
        bytes32 sessionId = keccak256(msg.sender, address(this), _unlockAmount, _data, _witness, _gasPrice, _gasLimit); //implicitly checks msg.sender is A to generate valid sessionId
        require(msg.value >= revealDeposit);
        require(!sessions[sessionId].revealed);
        require(!sessions[sessionId].unlocked);
        if (blockhash(_commitBlock) != 0x0) {
            blockNumberToHash[_commitBlock] = blockhash(_commitBlock);
        }
        sessions[sessionId].revealed = true;
        sessions[sessionId].unlockAmount = _unlockAmount;
        sessions[sessionId].commitBlock = _commitBlock;
        sessions[sessionId].commitIndex = _commitIndex;
        sessions[sessionId].revealBlock = block.number;
        sessions[sessionId].data = _data;
        sessions[sessionId].dappAddress = _dappAddress;
        emit Revealed(sessionId, _unlockAmount, _data, _witness, _commitBlock, _commitIndex);
    }

    function unlock(bytes32 _sessionId) public payable {
        require(sessions[_sessionId].revealed && !sessions[_sessionId].unlocked);
        require(msg.value == sessions[_sessionId].unlockAmount);
        // require(msg.sender == ); // not needed because even if someone else commits the funds, the appropriate behaviour is reccorded
        sessions[_sessionId].unlocked = true;
        //sessions[_sessionId].deposit = sessions[_sessionId].deposit.add(msg.value); // Is this needed?
        emit Unlocked(_sessionId, msg.value);
    }

    function isFinalizable(bytes32 _sessionId) public view returns (bool finalized, uint256 unlockAmount, bytes data) {
        if (block.number > sessions[_sessionId].revealBlock.add(challengePeriod) && sessions[_sessionId].unlocked && sessions[_sessionId].revealed) {
            return (true, sessions[_sessionId].unlockAmount, sessions[_sessionId].data);
        }
        return (false, 0, "");
    }

    function finalize(bytes32 _sessionId) public returns (uint256 unlockAmount, bytes data) {
        require(msg.sender == sessions[_sessionId].dappAddress);
        require(block.number > sessions[_sessionId].revealBlock.add(challengePeriod) && sessions[_sessionId].unlocked && sessions[_sessionId].revealed);
        uint256 amountTemp = sessions[_sessionId].unlockAmount;
        bytes memory dataTemp = sessions[_sessionId].data;
        sessions[_sessionId].dappAddress.transfer(amountTemp.add(revealDeposit)); // all user eth is forwarded to the dapp, includes commitment amount and revealDeposit
        delete sessions[_sessionId];
        emit Finalized(_sessionId, msg.sender, amountTemp, revealDeposit, dataTemp);
        return (amountTemp, dataTemp);
    }

    struct MPProof{
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

    function challenge(bytes32 _sessionId, bytes _proofBlob, bytes _unsignedCommitTx) public {
        require(block.number < sessions[_sessionId].revealBlock.add(challengePeriod)); //Should be within challenge period
        require(sessions[_sessionId].revealed); //Should be revealed
        MPProof memory mpProof;
        (mpProof.result, mpProof.index, mpProof.nonce, , , mpProof.to, mpProof.value, mpProof.data, , ,) = txProof(blockNumberToHash[sessions[_sessionId].commitBlock], _proofBlob);
        require(mpProof.result != 0); //index invalid
        UnsignedTx memory unsignedTx;
        (,unsignedTx.sigHash , , , , , , ) = decodeAndHashUnsignedTx(_unsignedCommitTx);
        uint256 slashAmount;
        if (mpProof.result == 2 && mpProof.index == sessions[_sessionId].commitIndex) {
            // if not present, and index == sessions[_sessionId].commitIndex -> slash deposit and give to msg.sender
          slashAmount = sessions[_sessionId].unlockAmount.add(revealDeposit);
          msg.sender.transfer(slashAmount);
          emit Slashed(_sessionId, mpProof.result, msg.sender, proxy, slashAmount, _proofBlob, _unsignedCommitTx);
          //delete sessions[_sessionId];
        }
        if (mpProof.result == 1 && mpProof.index == sessions[_sessionId].commitIndex) {
                // if present and index == sessions[_sessionId].commitIndex ->
                // if proof.to == address(B) // check how to get
                // and proof.value > sessions[_sessionId].unlockAmount
                // and proof.data == 0x0
                // and proof.nonce == 0
          address proxy = ecrecover(unsignedTx.sigHash, vee, keccak256(abi.encodePacked(_sessionId, byte(1))), keccak256(abi.encodePacked(_sessionId, byte(0)))); //ecrecover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) returns (address)
          if (!(
              mpProof.to == proxy &&
              mpProof.value > sessions[_sessionId].unlockAmount &&
              mpProof.data.length == 0 &&
              mpProof.nonce == 0
          )) {
              slashAmount = sessions[_sessionId].unlockAmount.add(revealDeposit);
              msg.sender.transfer(slashAmount);
              emit Slashed(_sessionId, mpProof.result, msg.sender, proxy, slashAmount, _proofBlob, _unsignedCommitTx);
              //delete sessions[_sessionId];
          }
      }
      revert("Invalid Challenge");
    }
}
