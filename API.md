# LibSubmarine API

This document will attempt to provide the necessary information DApp developers need to add LibSubmarine to their applications. At the time of this writing, our primary interfaces are in Solidity and Python. It would be good to be language agnostic and in the future support Vyper and JavaScript and other environments. Code contributions welcome :)

Definitely look at the contracts/examples folder and the unit tests in the tests folder for references on how to use the onchain and offchain components of LibSubmarine.

## Solidity

You will want to make your contract inherit from LibSubmarineSimple. The LibSubmarineSimple.sol file tries to follow [Ethereum NatSpec](https://github.com/ethereum/wiki/wiki/Ethereum-Natural-Specification-Format), so if you are confused on a function, check out the comments around it in the source. 

```
contract Exchange is LibSubmarineSimple {
```

Since your contract now inherits from LibSubmarineSimple, you will now have to implement the abstract `onSubmarineReveal` function, which is a function that is called upon successful reveal by a user. This function allows you to incorporate your own business logic at reveal-time, if you have any.

Formally, that's all you have to do to now support Submarine Sends. Everything else is implemented for you by the library. Still, to connect the submarine sends to your DApp's business logic you will probably want to do the following:

* Check that a submarine send for a given submarineId is complete: call `revealedAndUnlocked`.
* Use the various getter methods (getSubmarineState, getSubmarineAmount, getSubmarineCommitBlockNumber, getSubmarineCommitTxIndex) to query information about the Submarine Send - the Submarine Amount function, for example, will return the amount of money sent by the user in the Submarine Send.

## Python

To generate some of the required information user-side off-chain for the 3 transactions for a Submarine Send, you will need to make API calls to the following off-chain components of LibSubmarine: `generate_commit.py` and the EthProve `proveth.py` scripts.

### `generate_commit.py`

The `generate_commit.py` script will create a TxUnlock transaction for you, set a random witness, and give you a commit address to work with based on inputs sent to it. See the `-h` flag for the command line tool and refer to the Python code in the unit tests for examples of programmatic access to the generateCommitAddress function:

```python
commitAddress, submarineId, witness, unlock_tx_hex = generate_submarine_commit.generateCommitAddress(
    normalize_address(rec_hex(ALICE_ADDRESS)),
    normalize_address(rec_hex(self.libsubmarine_enabled_dapp.address)),
    UNLOCK_AMOUNT, b'', OURGASPRICE, OURGASLIMIT)
```

This returns to you the commitAddress you need to send money to, the submarineId that will be used for the transactions, the witness secret, and the unlock transaction hex that can be used to broadcast the transaction directly from an RPC node.

### `proveth.py`

The other API you will want to call is the Proveth library. This library provides a proofBlob Merkle-Patricia Proof that is passed to the reveal function of LibSubmarine (see: [proofBlob specification](https://github.com/lorenzb/proveth/blob/master/specification.md)). Provet can be called both as a command line program, or as an imported python module:

```python
commit_proof_blob = proveth.generate_proof_blob(
	proveth_expected_block_format_dict, commit_block_index)
```

The `proveth_expected_block_format_dict` is a Python dict in the format taken from an RPC `get_blockByNumber` or `get_blockByHash` type call. Again, reference the Python unit tests for a live example using this program, an excerpt from the code below shows creating a block with one transaction from scratch. Note that in the block constructed below, the `'transactions'` N-Tuple has only one element in it. Then the `commit_block_index` is a simple int indicating the transaction index of the the transaction in the block that we want to prove.

```python
proveth_expected_block_format_dict = dict()
proveth_expected_block_format_dict['parentHash'] = commit_block_object['prevhash']
proveth_expected_block_format_dict['sha3Uncles'] = commit_block_object['uncles_hash']
proveth_expected_block_format_dict['miner'] = commit_block_object['coinbase']
proveth_expected_block_format_dict['stateRoot'] = commit_block_object['state_root']
proveth_expected_block_format_dict['transactionsRoot'] = commit_block_object['tx_list_root']
proveth_expected_block_format_dict['receiptsRoot'] = commit_block_object['receipts_root']
proveth_expected_block_format_dict['logsBloom'] = commit_block_object['bloom']
proveth_expected_block_format_dict['difficulty'] = commit_block_object['difficulty']
proveth_expected_block_format_dict['number'] = commit_block_object['number']
proveth_expected_block_format_dict['gasLimit'] = commit_block_object['gas_limit']
proveth_expected_block_format_dict['gasUsed'] = commit_block_object['gas_used']
proveth_expected_block_format_dict['timestamp'] = commit_block_object['timestamp']
proveth_expected_block_format_dict['extraData'] = commit_block_object['extra_data']
proveth_expected_block_format_dict['mixHash'] = commit_block_object['mixhash']
proveth_expected_block_format_dict['nonce'] = commit_block_object['nonce']
proveth_expected_block_format_dict['hash'] = commit_block_object.hash
proveth_expected_block_format_dict['uncles'] = []

proveth_expected_block_format_dict['transactions'] = ({
    "blockHash":          commit_block_object.hash,
    "blockNumber":        str(hex((commit_block_object['number']))),
    "from":               checksum_encode(ALICE_ADDRESS),
    "gas":                str(hex(commit_tx_object['startgas'])),
    "gasPrice":           str(hex(commit_tx_object['gasprice'])),
    "hash":               rec_hex(commit_tx_object['hash']),
    "input":              rec_hex(commit_tx_object['data']),
    "nonce":              str(hex(commit_tx_object['nonce'])),
    "to":                 checksum_encode(commit_tx_object['to']),
    "transactionIndex":   str(hex(0)),
    "value":              str(hex(commit_tx_object['value'])),
    "v":                  str(hex(commit_tx_object['v'])),
    "r":                  str(hex(commit_tx_object['r'])),
    "s":                  str(hex(commit_tx_object['s']))
}, )
```

To do [RLP encoding](https://github.com/ethereum/wiki/wiki/RLP) you'll want to use the python [RLP module](https://pypi.org/project/rlp/). As always, refer to the unit tests for an example of how to generate the `_rlpUnlockTxUnsigned` parameter, but basically, it just involves creating a UnsignedTransaction object and then RLP encoding it:

```python
unlock_tx_unsigned_object = transactions.UnsignedTransaction(
    int.from_bytes(0, byteorder="big"),                                                                           # nonce;
    int.from_bytes((10**6), byteorder="big"),                                                                     # gasprice
    int.from_bytes(3712394, byteorder="big"),                                                                     # startgas/gasprice
    bytes.fromhex("999999cf1046e68e36E1aA2E0E07105eDDD1f08E"),                                                    # to addr
    int.from_bytes(unlock_tx_info[4], byteorder="big"),                                                           # value
    bytes.fromhex(unlockFunctionSelector + "04ddcbea9797815f80ae754f0b8552f7694fffcd34e8dc98a3013fd3dfb3bb9c"),   # data
)

unlock_tx_unsigned_rlp = rlp.encode(unlock_tx_unsigned_object, transactions.UnsignedTransaction)
```
