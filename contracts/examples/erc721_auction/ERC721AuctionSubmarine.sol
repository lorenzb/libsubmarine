pragma solidity ^0.5.0;

import "LibSubmarineSimple.sol";
import "../../openzeppelin-solidity/contracts/token/ERC721/IERC721.sol";
import "../../openzeppelin-solidity/contracts/token/ERC721/IERC721Receiver.sol";

contract ERC721Auction is IERC721Receiver, LibSubmarineSimple {
  IERC721 public erc721;
  uint256 public erc721TokenId;

  address public seller;

  uint32 public startBlock;
  uint32 public endCommitBlock;
  uint32 public endRevealBlock;

  mapping (bytes32 => address) public bidders;
  bytes32 public winningSubmarineId;

  /// @notice This creates the auction.
  function onERC721Received(
    address _operator,
    address _from,
    uint256 _tokenId,
    bytes _data
  ) public returns(bytes4) {
    require(address(erc721) == 0x0);

    // In solidity 0.5.0, we can just do this:
    // (startBlock, endCommitBlock) = abi.decode(_data, (uint32, uint32));
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
    endCommitBlock = tempEndBlock;
    endRevealBlock = tempEndBlock + 256;

    require(block.number < startBlock);
    require(startBlock < endCommitBlock);
    require(endCommitBlock < endRevealBlock);
    erc721 = IERC721(msg.sender);
    erc721TokenId = _tokenId;
    seller = _from;

    return bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"));
  }

  function onSubmarineReveal(
    bytes32 _submarineId,
    bytes _embeddedDAppData,
    uint256 _value
  ) internal {
    require(address(erc721) != 0x0);
    require(startBlock <= block.number && block.number <= endRevealBlock);


    bidders[_submarineId] = msg.sender;
    if (getSubmarineAmount(winningSubmarineId) < _value) {
      winningSubmarineId = _submarineId;
    }
  }

  function finalize(bytes32 _submarineId) external {
    require(address(erc721) != 0x0);
    require(endRevealBlock < block.number);
    require(revealedAndUnlocked(_submarineId));
    require(bidders[_submarineId] == msg.sender);

    if (_submarineId == winningSubmarineId) {
      erc721.safeTransferFrom(address(this), msg.sender, erc721TokenId);
      seller.transfer(getSubmarineAmount(_submarineId));
    } else {
      msg.sender.transfer(getSubmarineAmount(_submarineId));
    }
  }
}
