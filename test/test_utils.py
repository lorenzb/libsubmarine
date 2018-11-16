from ethereum.abi import ContractTranslator
from ethereum.tools import tester
from ethereum import utils
from solc import compile_standard

def rec_hex(x):
    if isinstance(x, list):
        return [rec_hex(elem) for elem in x]
    else:
        return "0x" + utils.encode_hex(x)


def rec_bin(x):
    if isinstance(x, list):
        return [rec_bin(elem) for elem in x]
    elif isinstance(x, int):
        return x
    elif isinstance(x, str):
        if x.startswith("0x"):
            return utils.decode_hex(x[2:])
        else:
            return utils.decode_hex(x)


def deploy_solidity_contract_with_args(chain, solc_config_sources, allow_paths, contract_file, contract_name, startgas, args=[], contract_creator=tester.k0):
    compiled = compile_standard({
        'language': 'Solidity',
        'sources': solc_config_sources,
        'settings': {'evmVersion': 'byzantium',
                     'outputSelection': {'*': {'*': ['abi', 'evm.bytecode']}},
                    },
    }, allow_paths=allow_paths)

    abi = compiled['contracts'][contract_file][contract_name]['abi']
    binary = compiled['contracts'][contract_file][contract_name]['evm']['bytecode']['object']
    ct = ContractTranslator(abi)
    address = chain.contract(
        utils.decode_hex(binary) + (ct.encode_constructor_arguments(args) if args else b''),
        language='evm',
        value=0,
        startgas=startgas,
        sender=contract_creator
    )
    contract = tester.ABIContract(chain, ct, address)
    return contract

def proveth_compatible_commit_block(commit_block, commit_tx):
    '''Converts a pyethereum block object (commit_block) that contains
    a single pyethereum transaction object (commit_tx) into
    the format proveth expects.
    '''
    proveth_expected_block_format_dict = dict()
    proveth_expected_block_format_dict['parentHash'] = commit_block.prevhash
    proveth_expected_block_format_dict['sha3Uncles'] = commit_block.uncles_hash
    proveth_expected_block_format_dict['miner'] = commit_block.coinbase
    proveth_expected_block_format_dict['stateRoot'] = commit_block.state_root
    proveth_expected_block_format_dict['transactionsRoot'] = commit_block.tx_list_root
    proveth_expected_block_format_dict['receiptsRoot'] = commit_block.receipts_root
    proveth_expected_block_format_dict['logsBloom'] = commit_block.bloom
    proveth_expected_block_format_dict['difficulty'] = commit_block.difficulty
    proveth_expected_block_format_dict['number'] = commit_block.number
    proveth_expected_block_format_dict['gasLimit'] = commit_block.gas_limit
    proveth_expected_block_format_dict['gasUsed'] = commit_block.gas_used
    proveth_expected_block_format_dict['timestamp'] = commit_block.timestamp
    proveth_expected_block_format_dict['extraData'] = commit_block.extra_data
    proveth_expected_block_format_dict['mixHash'] = commit_block.mixhash
    proveth_expected_block_format_dict['nonce'] = commit_block.nonce
    proveth_expected_block_format_dict['hash'] = commit_block.hash
    proveth_expected_block_format_dict['uncles'] = []

    proveth_expected_block_format_dict['transactions'] = ({
        "blockHash":          commit_block.hash,
        "blockNumber":        str(hex((commit_block['number']))),
        "from":               utils.checksum_encode(commit_tx.sender),
        "gas":                str(hex(commit_tx.startgas)),
        "gasPrice":           str(hex(commit_tx.gasprice)),
        "hash":               rec_hex(commit_tx.hash),
        "input":              rec_hex(commit_tx.data),
        "nonce":              str(hex(commit_tx.nonce)),
        "to":                 utils.checksum_encode(commit_tx.to),
        "transactionIndex":   str(hex(0)),
        "value":              str(hex(commit_tx.value)),
        "v":                  str(hex(commit_tx.v)),
        "r":                  str(hex(commit_tx.r)),
        "s":                  str(hex(commit_tx.s)),
    }, )

    return proveth_expected_block_format_dict

