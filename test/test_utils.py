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


def deploy_solidity_contract(chain, solc_config_sources, allow_paths, contract_file, contract_name, startgas):
    compiled = compile_standard({
        'language': 'Solidity',
        'sources': solc_config_sources,
        'settings': {'evmVersion': 'byzantium',
                     'outputSelection': {'*': {'*': ['abi', 'evm.bytecode']}},
                    },
    }, allow_paths=allow_paths)

    abi = compiled['contracts'][contract_file][contract_name]['abi']
    binary = compiled['contracts'][contract_file][contract_name]['evm']['bytecode']['object']
    address = chain.contract(
        utils.decode_hex(binary), language='evm', value=0, startgas=startgas, sender=tester.k0)
    contract = tester.ABIContract(chain, abi, address)
    return contract


def deploy_solidity_contract_with_args(chain, solc_config_sources, allow_paths, contract_file, contract_name, startgas, args=[], contractDeploySender=tester.k0):
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
        (utils.decode_hex(binary) + ct.encode_constructor_arguments(args) if args else b''), language='evm', value=0, startgas=startgas, sender=contractDeploySender)
    contract = tester.ABIContract(chain, ct, address)
    return contract

