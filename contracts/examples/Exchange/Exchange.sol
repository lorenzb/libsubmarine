pragma solidity ^0.4.24;

//import "../../LibSubmarineSimple.sol";
import "../../SafeMath.sol";
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
contract Exchange {// is LibSubmarineSimple {

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
     * @notice Buyer swaps ETH for Tokens
     * @param _minTokens minimum amount of tokens to accept for trade
     * @param _timeout trade / offer is valid until this unix time
     */
    function ethToTokenSwap(
        uint256 _minTokens, 
        uint256 _timeout
    ) 
        external 
        payable 
    {
        require(msg.value > 0 && _minTokens > 0 && now < _timeout);
        ethToToken(msg.sender, msg.value,  _minTokens);
    }

    /**
     * @notice Buyer swaps Tokens for ETH
     * @param _tokenAmount Amount of tokens being swapped
     * @param _minEth minimum eth to accept in trade.
     * @param _timeout bid/trade is valid until this unix time
     */
    function tokenToEthSwap(
        uint256 _tokenAmount,
        uint256 _minEth,
        uint256 _timeout
    )
        external
    {
        require(_tokenAmount > 0 && _minEth > 0 && now < _timeout);
        tokenToEth(msg.sender, _tokenAmount, _minEth);
    }

    /**
     * @notice Helper function recalculates pool of eth held, exchange rate etc.
     * @param recipient Recipient address for the tokens out of the trade
     * @param ethIn amount eth being traded
     * @param minTokensOut dont perform the trade unless you get this many tokens
     */
    function ethToToken(
        address recipient,
        uint256 ethIn,
        uint256 minTokensOut
    )
        internal
        exchangeInitialized
    {
        uint256 newEthPool = ethPool.add(ethIn);
        uint256 newTokenPool = invariant.div(newEthPool);
        uint256 tokensOut = tokenPool.sub(newTokenPool);
        require(tokensOut >= minTokensOut && tokensOut <= tokenPool);
        ethPool = newEthPool;
        tokenPool = newTokenPool;
        invariant = newEthPool.mul(newTokenPool);
        require(token.transfer(recipient, tokensOut));
    }
  
    /**
     * @notice Helper function recalculates pool of tokens held & exchange rate 
     * @param recipient recieving address for the ethereum out of the trade
     * @param tokensIn amount tokens being traded
     * @param minEthOut dont perform the trade unless you get this much in Eth
     */    
    function tokenToEth (
        address recipient,
        uint256 tokensIn,
        uint256 minEthOut
    )
        internal
        exchangeInitialized
    {
        uint256 newTokenPool = tokenPool.add(tokensIn);
        uint256 newEthPool = invariant.div(newTokenPool);
        uint256 ethOut = ethPool.sub(newEthPool);
        require(ethOut >= minEthOut && ethOut <= ethPool);
        tokenPool = newTokenPool;
        ethPool = newEthPool;
        invariant = newEthPool.mul(newTokenPool);
        require(token.transferFrom(recipient, address(this), tokensIn));
        recipient.transfer(ethOut);
    }
    
}
