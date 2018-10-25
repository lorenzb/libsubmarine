pragma solidity ^0.4.24;

import "../LibSubmarineSimple.sol";
import "../SafeMath.sol";

/**
 * This is an Example Auction contract that enables selling CryptoDogies.
 * They're the hottest new cryptocommodity storming the Ethereum world.
 * This auction contract has a CryptoDogie stored in it, and when the
 * auction is over, the winner becomes the dogieOwner.
 *
 * Note: *********** PLEASE DONT USE THIS CODE IN PRODUCTION ***************
 * this contract is just an example of how libsubmarine can be used.
 * It is not intended to be used verbatim to implement auctions on Ethereum.
 * The code has not been designed to be efficient, performant, or secure, only easy to understand.
 * This code has multiple problems: e.g. no conflict resolution for multiple bids of the same amount,
 * integer underflows, it doesn't handle what happens when there's no bids whatsoever, it is
 * JUST AN EXAMPLE.
 */
contract Auction is LibSubmarineSimple {

    using SafeMath for uint256;

    uint8 public revealPeriodLength;
    uint256 public auctionEndBlock;
    address public dogieOwner;
    address public dogieSeller;
    bool public auctionIsOver;
    uint256 public highestBid;

    struct AuctionBid {
        address bidder;
        bytes32 commitId;
    }

    AuctionBid[] public BidList;

    /**
     * @notice helper function for unit testing to get BidList length
     * @return the length of the bid list
     */
    function getBidListLength() public returns (uint256 listLength) {
        return BidList.length;
    }

    /**
     * @notice Because solidity does not support constructor overloading... Assigns the commit period length.
     * @param _revealPeriodLength - the length of blocks required after a commit was made before it can be accepted to be revealed. Recommended sane default: 20 blocks
     */
    constructor (uint8 _commitPeriodLength, uint8 _revealPeriodLength) public {
        revealPeriodLength =  _revealPeriodLength;
        commitPeriodLength = _commitPeriodLength;
        auctionEndBlock = block.number + commitPeriodLength + revealPeriodLength;
        dogieOwner = msg.sender;
        auctionIsOver = false;
        dogieSeller = msg.sender;
        highestBid = 0;
    }


    /**
     * @notice Function called by the user to reveal the Bid for the product.
     * @dev warning Must be called within 256 blocks of the commit transaction to obtain the correct blockhash.
     * @param _commitBlockNumber Block number in which the commit tx was included.
     * @param _embeddedDAppData optional Data passed embedded within the unlock tx. This is null for this example.
     * @param _witness Witness "secret" we committed to
     * @param _rlpUnlockTxUnsigned RLP encoded Unsigned Unlock Transaction data.
     * @param _proofBlob the Proof blob that gets passed to ethprove to verify merkle tree inclusion in a prior block.
     */
    function revealBid(
        uint32 _commitBlockNumber,
        bytes _embeddedDAppData,
        bytes32 _witness,
        bytes _rlpUnlockTxUnsigned,
        bytes _proofBlob
    ) public {
        reveal(_commitBlockNumber, _embeddedDAppData, _witness, _rlpUnlockTxUnsigned, _proofBlob);
        UnsignedTransaction memory unsignedUnlockTx = decodeUnsignedTx(_rlpUnlockTxUnsigned);
        bytes32 thisCommitId = getCommitId(
            msg.sender,
            address(this),
            unsignedUnlockTx.value,
            _embeddedDAppData,
            _witness,
            unsignedUnlockTx.gasprice,
            unsignedUnlockTx.startgas
        );
        AuctionBid memory pushme = AuctionBid(msg.sender, thisCommitId);
        BidList.push(pushme);
    }

    /**
     * @notice Function anybody can call which will end the auction. Assigns winner, Reimburses losers, and pays seller.
     * As you can see this function is extremely non-performant/expensive. It is just an example.
     * You will probably want to design something better architecturally.
     */
    function endauction() public {
        require(block.number > auctionEndBlock);
        address highestBidder;
        uint96 thisBid;
        uint256 rollingsum = 0;
        for (uint i = 0; i < BidList.length; i++) {
            (thisBid, , , ) = getCommitState(BidList[i].commitId);
            if(finished(BidList[i].commitId)) {
                if(thisBid > highestBid) {
                    highestBid = thisBid;
                    highestBidder = BidList[i].bidder;
                }
                rollingsum = rollingsum.add(thisBid);
            }
        }
        require(rollingsum == address(this).balance);
        for (uint j = 0; j < BidList.length; j++) {
            (thisBid, , , ) = getCommitState(BidList[j].commitId);
            if(BidList[j].bidder != highestBidder) {
                if(finished(BidList[j].commitId)) {
                    BidList[j].bidder.transfer(thisBid);
                }
            }
        }
        require(address(this).balance >= highestBid);
        auctionIsOver = true;
        dogieOwner = highestBidder; // this line is equivalent to whatever "turning over the auctioned item to the winner" would be in a different contract
        dogieSeller.transfer(highestBid);
        delete BidList;
    }


}
