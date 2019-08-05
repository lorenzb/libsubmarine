pragma solidity ^0.5.0;

import "../../openzeppelin-solidity/contracts/token/ERC721/IERC721.sol";
import "../../openzeppelin-solidity/contracts/token/ERC721/IERC721Receiver.sol";

contract ERC721Auction is IERC721Receiver {
  IERC721 public erc721;
  uint256 public erc721TokenId;

  address public seller;

  uint32 public startBlock;
  uint32 public endBlock;

  mapping (address => uint256) public bids;
  address public winningBidder;

  /// @notice This creates the auction.
  function onERC721Received(
    address _operator,
    address _from,
    uint256 _tokenId,
    bytes _data
  ) public returns(bytes4) {
    require(address(erc721) == 0x0);


    // In solidity 0.5.0, we can just do this:
    // (startBlock, endBlock) = abi.decode(_data, (uint32, uint32));
    // For now, here is some janky assembly hack that does the same thing,
    // only less efficiently.
    require(_data.length == 8);
    bytes memory data = _data; // Copy to memory;
    uint32 tempStartBlock;
    uint32 tempEndBlock;
    assembly {
      tempStartBlock := div(mload(add(data, 32)), exp(2, 224))
      tempEndBlock := and(div(mload(add(data, 32)), exp(2, 192)), 0xffffffff)
    }

    startBlock = tempStartBlock;
    endBlock = tempEndBlock;

    require(block.number < startBlock);
    require(startBlock < endBlock);
    erc721 = IERC721(msg.sender);
    erc721TokenId = _tokenId;
    seller = _from;

    return bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"));
  }

  function bid() payable external {
    require(address(erc721) != 0x0);
    require(startBlock <= block.number && block.number <= endBlock);
    bids[msg.sender] += msg.value;
    if (bids[msg.sender] > bids[winningBidder]) {
      winningBidder = msg.sender;
    }
  }

  function finalize() external {
    require(address(erc721) != 0x0);
    require(endBlock < block.number);
    uint256 bid = bids[msg.sender];
    bids[msg.sender] = 0;
    if (msg.sender == winningBidder) {
      erc721.safeTransferFrom(address(this), msg.sender, erc721TokenId);
      seller.transfer(bid);
    } else {
      msg.sender.transfer(bid);
    }
  }
}
