pragma solidity ^0.5.0;

import "../../LibSubmarineSimple.sol";
import "../../openzeppelin-solidity/contracts/math/SafeMath.sol";
import "./ERC20Interface.sol";

/**
 * Example Exchange contract that enables trading Ethereum for reserve tokens.
 * This is a similar architecture to some prominent distributed exchanges today.
 *
 * Note: *********** PLEASE DONT USE THIS CODE IN PRODUCTION ***************
 * this contract is just an example of how libsubmarine can be used.
 * It is not intended to be used verbatim to implement DEXes on Ethereum.
 * The code has not been designed to be efficient, performant, or secure,
 * only easy to understand.
 * This code has multiple problems.
 * it is JUST AN EXAMPLE.
 */
contract Exchange is LibSubmarineSimple {

    using SafeMath for uint256;

    //
    // STORAGE
    //

    ERC20Interface token;
    uint256 public ethPool;
    uint256 public tokenPool;
    uint256 public invariant;
    address public tokenAddress;

    /// MODIFIERS
    modifier exchangeInitialized() {
        require(invariant > 0);
        _;
    }

    /**
     * @notice Constructor, creates Exchange contract.
     * @param _tokenAddress The address of a separate ERC20 conforming contract
     */
    constructor(address _tokenAddress) public {
        tokenAddress = _tokenAddress;
        token = ERC20Interface(tokenAddress);
        commitPeriodLength = 5;
    }

    /**
     * @notice "Initializes" the exchange. Basically a second constructor.
     * this is necessary because the ERC20 contract needs to know what the
     * exchange's address is, and you can't know that until after it's been
     * instantiated.
     * @param _tokenAmount How many tokens to initialize the exchange with
     */
    function initializeExchange(uint256 _tokenAmount) external payable {
        require(invariant == 0);
        // Prevents share cost from being too high or too low - potentially needs work
        require(msg.value >= 10000 && _tokenAmount >= 10000 && msg.value <= 5*10**18);
        ethPool = msg.value;
        tokenPool = _tokenAmount;
        invariant = ethPool.mul(tokenPool);
        require(token.transferFrom(msg.sender, address(this), _tokenAmount));
    }

    /**
     * @notice Consumers of this library should implement their custom reveal
     *         logic by overriding this method. This function is a handler that
     *         is called by reveal. A user calls reveal, LibSubmarine does the
     *         required submarine specific stuff, and then calls this handler
     *         for client specific implementation/handling.
     * @param  _submarineId the ID for this submarine workflow
     * @param _embeddedDAppData optional Data passed embedded within the unlock
     *        tx. Clients can put whatever data they want committed to for their
     *        specific use case - in this example, we don't need to use it so
     *        it's null.
     * @param _value amount of ether revealed
     *
     */
    function onSubmarineReveal(
        bytes32 _submarineId,
        bytes _embeddedDAppData,
        uint256 _value
    ) internal {
        // In this specific DEX example, we don't actually need to store any
        // state after the reveal or perform any business logic about it, since
        // we don't really care about the order of reveals or anything like that
        // your use case may wanto take note and store submarine Ids, or
        // process embedded data that was sent through the commit-reveal
        return;
    }


    /**
     * @notice Buyer swaps ETH for Tokens. This is the workflow that we are
     * submarine protecting. The reverse (i.e. swapping tokens for eth) is not
     * using submarine sends in this example.
     * @param _submarineId the ID associated with this eth/token swap.
     */
    function ethToTokenSwap(bytes32 _submarineId)
        external
    {
        require(msg.value == 0);
        require(revealedAndUnlocked(_submarineId));
        ethToToken(msg.sender, getSubmarineAmount(_submarineId));
    }

    /**
     * @notice Buyer swaps Tokens for ETH
     * @param _tokenAmount Amount of tokens being swapped
     */
    function tokenToEthSwap(uint256 _tokenAmount)
        external
    {
        require(_tokenAmount > 0);
        tokenToEth(msg.sender, _tokenAmount);
    }

    /**
     * @notice Helper function recalculates pool of eth held, exchange rate etc.
     * @param recipient Recipient address for the tokens out of the trade
     * @param ethIn amount eth being traded
     */
    function ethToToken(
        address recipient,
        uint256 ethIn
    )
        internal
        exchangeInitialized
    {
        uint256 newEthPool = ethPool.add(ethIn);
        uint256 newTokenPool = invariant.div(newEthPool);
        uint256 tokensOut = tokenPool.sub(newTokenPool);
        require(tokensOut <= tokenPool);
        ethPool = newEthPool;
        tokenPool = newTokenPool;
        invariant = newEthPool.mul(newTokenPool);
        require(token.transfer(recipient, tokensOut));
    }

    /**
     * @notice Helper function recalculates pool of tokens held & exchange rate
     * @param recipient recieving address for the ethereum out of the trade
     * @param tokensIn amount tokens being traded
     */
    function tokenToEth (
        address recipient,
        uint256 tokensIn
    )
        internal
        exchangeInitialized
    {
        uint256 newTokenPool = tokenPool.add(tokensIn);
        uint256 newEthPool = invariant.div(newTokenPool);
        uint256 ethOut = ethPool.sub(newEthPool);
        require(ethOut <= ethPool);
        tokenPool = newTokenPool;
        ethPool = newEthPool;
        invariant = newEthPool.mul(newTokenPool);
        require(token.transferFrom(recipient, address(this), tokensIn));
        recipient.transfer(ethOut);
    }

}
