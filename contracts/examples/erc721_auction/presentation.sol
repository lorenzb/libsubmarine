
import "LibSubmarineSimple.sol";

contract ERC721Auction is IERC721Receiver, LibSubmarineSimple {

  // Storage and deployment functions

  function onSubmarineReveal(
    bytes32 _submarineId,
    bytes _embeddedDAppData,
    uint256 _value
  ) internal {
  
    // logical checks
    require(startBlock <= block.number && block.number <= endRevealBlock);
    
    // record bid
    bidders[_submarineId] = msg.sender;
    
    // check if new top bid
    if (getSubmarineAmount(winningSubmarineId) < _value) { 
      winningSubmarineId = _submarineId;
    }
  }
}


contract ERC721Auction is IERC721Receiver {

  // Storage and deployment functions
  
  function bid() payable external {
  
    // logical checks
    require(startBlock <= block.number && block.number <= endBlock);
    
    // record bid
    bids[msg.sender] += msg.value; 
    
    // check if new top bid
    if (bids[msg.sender] > bids[winningBidder]) { 
      winningBidder = msg.sender;
    }
  }
}
  
