import logging
import os
import rlp
import sys
import unittest
from ethereum import config, transactions
from ethereum.tools import tester as t
from ethereum.utils import checksum_encode, normalize_address, sha3
from test_utils import rec_hex, rec_bin, deploy_solidity_contract_with_args

sys.path.append(
    os.path.join(os.path.dirname(__file__), '..', 'generate_commitment'))
import generate_submarine_commit

sys.path.append(
    os.path.join(os.path.dirname(__file__), '..', 'proveth', 'offchain'))
import proveth

root_repo_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../'))

COMMIT_PERIOD_LENGTH = 16
REVEAL_PERIOD_LENGTH = 14
# internet points to you if you can figure out the references in these amounts
BID_AMOUNT_Alice = 1337000000000000000
BID_AMOUNT_Bob = 5555000000000000000
BID_AMOUNT_Charlie = 8675309000000000000
OURGASLIMIT = 3712394
OURGASPRICE = 10**6
BASIC_SEND_GAS_LIMIT = 21000
extraTransactionFees = 100000000000000000
ACCOUNT_STARTING_BALANCE = 1000000000000000000000000
SOLIDITY_NULL_INITIALVAL = 0
ALICE_ADDRESS = t.a1
ALICE_PRIVATE_KEY = t.k1
BOB_ADDRESS = t.a2
BOB_PRIVATE_KEY = t.k2
CHARLIE_ADDRESS = t.a3
CHARLIE_PRIVATE_KEY = t.k3
RANDO_ADDRESS_PRIVATE_KEY = t.k6
CONTRACT_OWNER_ADDRESS = t.a7
CONTRACT_OWNER_PRIVATE_KEY = t.k7



log = logging.getLogger('TestExampleAuction')
LOGFORMAT = "%(levelname)s:%(filename)s:%(lineno)s:%(funcName)s(): %(message)s"
log.setLevel(logging.getLevelName('INFO'))
logHandler = logging.StreamHandler(stream=sys.stdout)
logHandler.setFormatter(logging.Formatter(LOGFORMAT))
log.addHandler(logHandler)


class TestExampleAuction(unittest.TestCase):
    def setUp(self):
        config.config_metropolis['BLOCK_GAS_LIMIT'] = 2**60
        self.chain = t.Chain(env=config.Env(config=config.config_metropolis))
        self.chain.mine(1)
        contract_dir = os.path.abspath(
            os.path.join(root_repo_dir, 'contracts/'))
        os.chdir(root_repo_dir)

        self.verifier_contract = deploy_solidity_contract_with_args(
            chain=self.chain,
            solc_config_sources={
                'examples/Auction.sol': {
                    'urls':
                    [os.path.join(contract_dir, 'examples/Auction.sol')]
                },
                'LibSubmarineSimple.sol': {
                    'urls':
                    [os.path.join(contract_dir, 'LibSubmarineSimple.sol')]
                },
                'SafeMath.sol': {
                    'urls': [os.path.join(contract_dir, 'SafeMath.sol')]
                },
                'proveth/ProvethVerifier.sol': {
                    'urls': [
                        os.path.join(contract_dir,
                                     'proveth/ProvethVerifier.sol')
                    ]
                },
                'proveth/RLP.sol': {
                    'urls': [os.path.join(contract_dir, 'proveth/RLP.sol')]
                }
            },
            allow_paths=root_repo_dir,
            contract_file='examples/Auction.sol',
            contract_name='Auction',
            startgas=10**7,
            args=[COMMIT_PERIOD_LENGTH, REVEAL_PERIOD_LENGTH],
            contractDeploySender=CONTRACT_OWNER_PRIVATE_KEY)

    def test_auctionWorkflow(self):
        ##
        ## STARTING STATE
        ##
        starting_block_height = self.chain.head_state.block_number
        starting_owner_eth_holdings = self.chain.head_state.get_balance(rec_hex(CONTRACT_OWNER_ADDRESS))
        self.chain.mine(1)

        self.assertEqual(ACCOUNT_STARTING_BALANCE, self.chain.head_state.get_balance(rec_hex(ALICE_ADDRESS)))
        self.assertEqual(ACCOUNT_STARTING_BALANCE, self.chain.head_state.get_balance(rec_hex(BOB_ADDRESS)))
        self.assertEqual(ACCOUNT_STARTING_BALANCE, self.chain.head_state.get_balance(rec_hex(CHARLIE_ADDRESS)))
        self.assertEqual(27, self.verifier_contract.vee())
        self.assertEqual(COMMIT_PERIOD_LENGTH, self.verifier_contract.commitPeriodLength())
        self.assertEqual(REVEAL_PERIOD_LENGTH, self.verifier_contract.revealPeriodLength())
        self.assertEqual(starting_block_height + COMMIT_PERIOD_LENGTH + REVEAL_PERIOD_LENGTH, self.verifier_contract.auctionEndBlock())


        #
        # GENERATE UNLOCK TXs
        #
        commitAddressAlice, commitAlice, witnessAlice, unlock_tx_hexAlice = generate_submarine_commit.generateCommitAddress(
             normalize_address(rec_hex(ALICE_ADDRESS)),
             normalize_address(rec_hex(self.verifier_contract.address)),
             BID_AMOUNT_Alice, b'', OURGASPRICE, OURGASLIMIT)

        unlock_tx_infoAlice = rlp.decode(rec_bin(unlock_tx_hexAlice))
        unlock_tx_objectAlice = transactions.Transaction(
            int.from_bytes(unlock_tx_infoAlice[0], byteorder="big"),  # nonce;
            int.from_bytes(unlock_tx_infoAlice[1], byteorder="big"),  # gasprice
            int.from_bytes(unlock_tx_infoAlice[2], byteorder="big"),  # startgas
            unlock_tx_infoAlice[3],  # to addr
            int.from_bytes(unlock_tx_infoAlice[4], byteorder="big"),  # value
            unlock_tx_infoAlice[5],  # data
            int.from_bytes(unlock_tx_infoAlice[6], byteorder="big"),  # v
            int.from_bytes(unlock_tx_infoAlice[7], byteorder="big"),  # r
            int.from_bytes(unlock_tx_infoAlice[8], byteorder="big")  # s
        )
        commitAddressBob, commitBob, witnessBob, unlock_tx_hexBob = generate_submarine_commit.generateCommitAddress(
             normalize_address(rec_hex(BOB_ADDRESS)),
             normalize_address(rec_hex(self.verifier_contract.address)),
             BID_AMOUNT_Bob, b'', OURGASPRICE, OURGASLIMIT)

        unlock_tx_infoBob = rlp.decode(rec_bin(unlock_tx_hexBob))
        unlock_tx_objectBob = transactions.Transaction(
            int.from_bytes(unlock_tx_infoBob[0], byteorder="big"),  # nonce;
            int.from_bytes(unlock_tx_infoBob[1], byteorder="big"),  # gasprice
            int.from_bytes(unlock_tx_infoBob[2], byteorder="big"),  # startgas
            unlock_tx_infoBob[3],  # to addr
            int.from_bytes(unlock_tx_infoBob[4], byteorder="big"),  # value
            unlock_tx_infoBob[5],  # data
            int.from_bytes(unlock_tx_infoBob[6], byteorder="big"),  # v
            int.from_bytes(unlock_tx_infoBob[7], byteorder="big"),  # r
            int.from_bytes(unlock_tx_infoBob[8], byteorder="big")  # s
        )
        commitAddressCharlie, commitCharlie, witnessCharlie, unlock_tx_hexCharlie = generate_submarine_commit.generateCommitAddress(
             normalize_address(rec_hex(CHARLIE_ADDRESS)),
             normalize_address(rec_hex(self.verifier_contract.address)),
             BID_AMOUNT_Charlie, b'', OURGASPRICE, OURGASLIMIT)

        unlock_tx_infoCharlie = rlp.decode(rec_bin(unlock_tx_hexCharlie))
        unlock_tx_objectCharlie = transactions.Transaction(
            int.from_bytes(unlock_tx_infoCharlie[0], byteorder="big"),  # nonce;
            int.from_bytes(unlock_tx_infoCharlie[1], byteorder="big"),  # gasprice
            int.from_bytes(unlock_tx_infoCharlie[2], byteorder="big"),  # startgas
            unlock_tx_infoCharlie[3],  # to addr
            int.from_bytes(unlock_tx_infoCharlie[4], byteorder="big"),  # value
            unlock_tx_infoCharlie[5],  # data
            int.from_bytes(unlock_tx_infoCharlie[6], byteorder="big"),  # v
            int.from_bytes(unlock_tx_infoCharlie[7], byteorder="big"),  # r
            int.from_bytes(unlock_tx_infoCharlie[8], byteorder="big")  # s
        )

        #
        # GENERATE + BROADCAST COMMIT TXs
        #
        commit_tx_objectAlice = transactions.Transaction(
            0, OURGASPRICE, BASIC_SEND_GAS_LIMIT, rec_bin(commitAddressAlice),
            (BID_AMOUNT_Alice + extraTransactionFees),
            b'').sign(ALICE_PRIVATE_KEY)
        commit_gasAlice = int(self.chain.head_state.gas_used)

        self.chain.direct_tx(commit_tx_objectAlice)
        self.chain.mine(1)

        commit_tx_objectBob = transactions.Transaction(
            0, OURGASPRICE, BASIC_SEND_GAS_LIMIT, rec_bin(commitAddressBob),
            (BID_AMOUNT_Bob + extraTransactionFees),
            b'').sign(BOB_PRIVATE_KEY)
        commit_gasBob = int(self.chain.head_state.gas_used)

        self.chain.direct_tx(commit_tx_objectBob)
        self.chain.mine(1)

        commit_tx_objectCharlie = transactions.Transaction(
            0, OURGASPRICE, BASIC_SEND_GAS_LIMIT, rec_bin(commitAddressCharlie),
            (BID_AMOUNT_Charlie + extraTransactionFees),
            b'').sign(CHARLIE_PRIVATE_KEY)
        commit_gasCharlie = int(self.chain.head_state.gas_used)

        self.chain.direct_tx(commit_tx_objectCharlie)
        self.chain.mine(1)

        ##
        ## CHECK STATE AFTER COMMIT TX
        ##
        commit_block_numberAlice, commit_block_indexAlice = self.chain.chain.get_tx_position(
            commit_tx_objectAlice)
        self.assertEqual(BID_AMOUNT_Alice + extraTransactionFees,
                         self.chain.head_state.get_balance(commitAddressAlice))
        self.assertEqual(
            ACCOUNT_STARTING_BALANCE - (BID_AMOUNT_Alice + extraTransactionFees +
                                        BASIC_SEND_GAS_LIMIT * OURGASPRICE),
            self.chain.head_state.get_balance(rec_hex(ALICE_ADDRESS)))

        session_dataAlice = self.verifier_contract.getCommitState(rec_bin(commitAlice))
        self.assertListEqual(session_dataAlice,
                [SOLIDITY_NULL_INITIALVAL, SOLIDITY_NULL_INITIALVAL, SOLIDITY_NULL_INITIALVAL, SOLIDITY_NULL_INITIALVAL])

        finished_boolAlice = self.verifier_contract.finished(rec_bin(commitAlice))
        self.assertFalse(
            finished_boolAlice,
            "The contract should not be finished before it's even begun.")



        commit_block_numberBob, commit_block_indexBob = self.chain.chain.get_tx_position(
            commit_tx_objectBob)
        self.assertEqual(BID_AMOUNT_Bob + extraTransactionFees,
                         self.chain.head_state.get_balance(commitAddressBob))
        self.assertEqual(
            ACCOUNT_STARTING_BALANCE - (BID_AMOUNT_Bob + extraTransactionFees +
                                        BASIC_SEND_GAS_LIMIT * OURGASPRICE),
            self.chain.head_state.get_balance(rec_hex(BOB_ADDRESS)))

        session_dataBob = self.verifier_contract.getCommitState(rec_bin(commitBob))
        self.assertListEqual(session_dataBob,
                [SOLIDITY_NULL_INITIALVAL, SOLIDITY_NULL_INITIALVAL, SOLIDITY_NULL_INITIALVAL, SOLIDITY_NULL_INITIALVAL])

        finished_boolBob = self.verifier_contract.finished(rec_bin(commitBob))
        self.assertFalse(
            finished_boolBob,
            "The contract should not be finished before it's even begun.")

        commit_block_numberCharlie, commit_block_indexCharlie = self.chain.chain.get_tx_position(
            commit_tx_objectCharlie)
        self.assertEqual(BID_AMOUNT_Charlie + extraTransactionFees,
                         self.chain.head_state.get_balance(commitAddressCharlie))
        self.assertEqual(
            ACCOUNT_STARTING_BALANCE - (BID_AMOUNT_Charlie + extraTransactionFees +
                                        BASIC_SEND_GAS_LIMIT * OURGASPRICE),
            self.chain.head_state.get_balance(rec_hex(CHARLIE_ADDRESS)))

        session_dataCharlie = self.verifier_contract.getCommitState(rec_bin(commitCharlie))
        self.assertListEqual(session_dataCharlie,
                [SOLIDITY_NULL_INITIALVAL, SOLIDITY_NULL_INITIALVAL, SOLIDITY_NULL_INITIALVAL, SOLIDITY_NULL_INITIALVAL])

        finished_boolCharlie = self.verifier_contract.finished(rec_bin(commitCharlie))
        self.assertFalse(
            finished_boolCharlie,
            "The contract should not be finished before it's even begun.")

        ##
        ## GENERATE AND BROADCAST REVEAL BID TXS
        ##
        self.chain.mine(COMMIT_PERIOD_LENGTH)

        commit_block_objectAlice = self.chain.chain.get_block_by_number(commit_block_numberAlice)
        proveth_expected_block_format_dictAlice = dict()
        proveth_expected_block_format_dictAlice['parentHash'] = commit_block_objectAlice['prevhash']
        proveth_expected_block_format_dictAlice['sha3Uncles'] = commit_block_objectAlice['uncles_hash']
        proveth_expected_block_format_dictAlice['miner'] = commit_block_objectAlice['coinbase']
        proveth_expected_block_format_dictAlice['stateRoot'] = commit_block_objectAlice['state_root']
        proveth_expected_block_format_dictAlice['transactionsRoot'] = commit_block_objectAlice['tx_list_root']
        proveth_expected_block_format_dictAlice['receiptsRoot'] = commit_block_objectAlice['receipts_root']
        proveth_expected_block_format_dictAlice['logsBloom'] = commit_block_objectAlice['bloom']
        proveth_expected_block_format_dictAlice['difficulty'] = commit_block_objectAlice['difficulty']
        proveth_expected_block_format_dictAlice['number'] = commit_block_objectAlice['number']
        proveth_expected_block_format_dictAlice['gasLimit'] = commit_block_objectAlice['gas_limit']
        proveth_expected_block_format_dictAlice['gasUsed'] = commit_block_objectAlice['gas_used']
        proveth_expected_block_format_dictAlice['timestamp'] = commit_block_objectAlice['timestamp']
        proveth_expected_block_format_dictAlice['extraData'] = commit_block_objectAlice['extra_data']
        proveth_expected_block_format_dictAlice['mixHash'] = commit_block_objectAlice['mixhash']
        proveth_expected_block_format_dictAlice['nonce'] = commit_block_objectAlice['nonce']
        proveth_expected_block_format_dictAlice['hash'] = commit_block_objectAlice.hash
        proveth_expected_block_format_dictAlice['uncles'] = []
        proveth_expected_block_format_dictAlice['transactions'] = ({
            "blockHash":          commit_block_objectAlice.hash,
            "blockNumber":        str(hex((commit_block_objectAlice['number']))),
            "from":               checksum_encode(ALICE_ADDRESS),
            "gas":                str(hex(commit_tx_objectAlice['startgas'])),
            "gasPrice":           str(hex(commit_tx_objectAlice['gasprice'])),
            "hash":               rec_hex(commit_tx_objectAlice['hash']),
            "input":              rec_hex(commit_tx_objectAlice['data']),
            "nonce":              str(hex(commit_tx_objectAlice['nonce'])),
            "to":                 checksum_encode(commit_tx_objectAlice['to']),
            "transactionIndex":   str(hex(0)),
            "value":              str(hex(commit_tx_objectAlice['value'])),
            "v":                  str(hex(commit_tx_objectAlice['v'])),
            "r":                  str(hex(commit_tx_objectAlice['r'])),
            "s":                  str(hex(commit_tx_objectAlice['s']))
        }, )

        commit_proof_blobAlice = proveth.generate_proof_blob(
            proveth_expected_block_format_dictAlice, commit_block_indexAlice)
        _unlockExtraData = b''  # In this example we dont have any extra embedded data as part of the unlock TX


        unlock_tx_unsigned_objectAlice = transactions.UnsignedTransaction(
            int.from_bytes(unlock_tx_infoAlice[0], byteorder="big"),  # nonce;
            int.from_bytes(unlock_tx_infoAlice[1], byteorder="big"),  # gasprice
            int.from_bytes(unlock_tx_infoAlice[2], byteorder="big"),  # startgas
            unlock_tx_infoAlice[3],  # to addr
            int.from_bytes(unlock_tx_infoAlice[4], byteorder="big"),  # value
            unlock_tx_infoAlice[5],  # data
        )
        unlock_tx_unsigned_rlpAlice = rlp.encode(unlock_tx_unsigned_objectAlice, transactions.UnsignedTransaction)


        self.verifier_contract.revealBid(
            commit_block_numberAlice,  # uint32 _commitBlockNumber,
            _unlockExtraData,  # bytes _commitData,
            rec_bin(witnessAlice),  # bytes32 _witness,
            unlock_tx_unsigned_rlpAlice,  # bytes _rlpUnlockTxUnsigned,
            commit_proof_blobAlice,  # bytes _proofBlob
            sender=ALICE_PRIVATE_KEY)
        reveal_gasAlice = int(self.chain.head_state.gas_used)

        self.chain.mine(1)

        commit_block_objectBob = self.chain.chain.get_block_by_number(commit_block_numberBob)
        proveth_expected_block_format_dictBob = dict()
        proveth_expected_block_format_dictBob['parentHash'] = commit_block_objectBob['prevhash']
        proveth_expected_block_format_dictBob['sha3Uncles'] = commit_block_objectBob['uncles_hash']
        proveth_expected_block_format_dictBob['miner'] = commit_block_objectBob['coinbase']
        proveth_expected_block_format_dictBob['stateRoot'] = commit_block_objectBob['state_root']
        proveth_expected_block_format_dictBob['transactionsRoot'] = commit_block_objectBob['tx_list_root']
        proveth_expected_block_format_dictBob['receiptsRoot'] = commit_block_objectBob['receipts_root']
        proveth_expected_block_format_dictBob['logsBloom'] = commit_block_objectBob['bloom']
        proveth_expected_block_format_dictBob['difficulty'] = commit_block_objectBob['difficulty']
        proveth_expected_block_format_dictBob['number'] = commit_block_objectBob['number']
        proveth_expected_block_format_dictBob['gasLimit'] = commit_block_objectBob['gas_limit']
        proveth_expected_block_format_dictBob['gasUsed'] = commit_block_objectBob['gas_used']
        proveth_expected_block_format_dictBob['timestamp'] = commit_block_objectBob['timestamp']
        proveth_expected_block_format_dictBob['extraData'] = commit_block_objectBob['extra_data']
        proveth_expected_block_format_dictBob['mixHash'] = commit_block_objectBob['mixhash']
        proveth_expected_block_format_dictBob['nonce'] = commit_block_objectBob['nonce']
        proveth_expected_block_format_dictBob['hash'] = commit_block_objectBob.hash
        proveth_expected_block_format_dictBob['uncles'] = []
        proveth_expected_block_format_dictBob['transactions'] = ({
            "blockHash":          commit_block_objectBob.hash,
            "blockNumber":        str(hex((commit_block_objectBob['number']))),
            "from":               checksum_encode(BOB_ADDRESS),
            "gas":                str(hex(commit_tx_objectBob['startgas'])),
            "gasPrice":           str(hex(commit_tx_objectBob['gasprice'])),
            "hash":               rec_hex(commit_tx_objectBob['hash']),
            "input":              rec_hex(commit_tx_objectBob['data']),
            "nonce":              str(hex(commit_tx_objectBob['nonce'])),
            "to":                 checksum_encode(commit_tx_objectBob['to']),
            "transactionIndex":   str(hex(0)),
            "value":              str(hex(commit_tx_objectBob['value'])),
            "v":                  str(hex(commit_tx_objectBob['v'])),
            "r":                  str(hex(commit_tx_objectBob['r'])),
            "s":                  str(hex(commit_tx_objectBob['s']))
        }, )

        commit_proof_blobBob = proveth.generate_proof_blob(
            proveth_expected_block_format_dictBob, commit_block_indexBob)
        _unlockExtraData = b''  # In this example we dont have any extra embedded data as part of the unlock TX


        unlock_tx_unsigned_objectBob = transactions.UnsignedTransaction(
            int.from_bytes(unlock_tx_infoBob[0], byteorder="big"),  # nonce;
            int.from_bytes(unlock_tx_infoBob[1], byteorder="big"),  # gasprice
            int.from_bytes(unlock_tx_infoBob[2], byteorder="big"),  # startgas
            unlock_tx_infoBob[3],  # to addr
            int.from_bytes(unlock_tx_infoBob[4], byteorder="big"),  # value
            unlock_tx_infoBob[5],  # data
        )
        unlock_tx_unsigned_rlpBob = rlp.encode(unlock_tx_unsigned_objectBob, transactions.UnsignedTransaction)


        self.verifier_contract.revealBid(
            commit_block_numberBob,  # uint32 _commitBlockNumber,
            _unlockExtraData,  # bytes _commitData,
            rec_bin(witnessBob),  # bytes32 _witness,
            unlock_tx_unsigned_rlpBob,  # bytes _rlpUnlockTxUnsigned,
            commit_proof_blobBob,  # bytes _proofBlob
            sender=BOB_PRIVATE_KEY)
        reveal_gasBob = int(self.chain.head_state.gas_used)

        self.chain.mine(1)

        commit_block_objectCharlie = self.chain.chain.get_block_by_number(commit_block_numberCharlie)
        proveth_expected_block_format_dictCharlie = dict()
        proveth_expected_block_format_dictCharlie['parentHash'] = commit_block_objectCharlie['prevhash']
        proveth_expected_block_format_dictCharlie['sha3Uncles'] = commit_block_objectCharlie['uncles_hash']
        proveth_expected_block_format_dictCharlie['miner'] = commit_block_objectCharlie['coinbase']
        proveth_expected_block_format_dictCharlie['stateRoot'] = commit_block_objectCharlie['state_root']
        proveth_expected_block_format_dictCharlie['transactionsRoot'] = commit_block_objectCharlie['tx_list_root']
        proveth_expected_block_format_dictCharlie['receiptsRoot'] = commit_block_objectCharlie['receipts_root']
        proveth_expected_block_format_dictCharlie['logsBloom'] = commit_block_objectCharlie['bloom']
        proveth_expected_block_format_dictCharlie['difficulty'] = commit_block_objectCharlie['difficulty']
        proveth_expected_block_format_dictCharlie['number'] = commit_block_objectCharlie['number']
        proveth_expected_block_format_dictCharlie['gasLimit'] = commit_block_objectCharlie['gas_limit']
        proveth_expected_block_format_dictCharlie['gasUsed'] = commit_block_objectCharlie['gas_used']
        proveth_expected_block_format_dictCharlie['timestamp'] = commit_block_objectCharlie['timestamp']
        proveth_expected_block_format_dictCharlie['extraData'] = commit_block_objectCharlie['extra_data']
        proveth_expected_block_format_dictCharlie['mixHash'] = commit_block_objectCharlie['mixhash']
        proveth_expected_block_format_dictCharlie['nonce'] = commit_block_objectCharlie['nonce']
        proveth_expected_block_format_dictCharlie['hash'] = commit_block_objectCharlie.hash
        proveth_expected_block_format_dictCharlie['uncles'] = []
        proveth_expected_block_format_dictCharlie['transactions'] = ({
            "blockHash":          commit_block_objectCharlie.hash,
            "blockNumber":        str(hex((commit_block_objectCharlie['number']))),
            "from":               checksum_encode(CHARLIE_ADDRESS),
            "gas":                str(hex(commit_tx_objectCharlie['startgas'])),
            "gasPrice":           str(hex(commit_tx_objectCharlie['gasprice'])),
            "hash":               rec_hex(commit_tx_objectCharlie['hash']),
            "input":              rec_hex(commit_tx_objectCharlie['data']),
            "nonce":              str(hex(commit_tx_objectCharlie['nonce'])),
            "to":                 checksum_encode(commit_tx_objectCharlie['to']),
            "transactionIndex":   str(hex(0)),
            "value":              str(hex(commit_tx_objectCharlie['value'])),
            "v":                  str(hex(commit_tx_objectCharlie['v'])),
            "r":                  str(hex(commit_tx_objectCharlie['r'])),
            "s":                  str(hex(commit_tx_objectCharlie['s']))
        }, )

        commit_proof_blobCharlie = proveth.generate_proof_blob(
            proveth_expected_block_format_dictCharlie, commit_block_indexCharlie)
        _unlockExtraData = b''  # In this example we dont have any extra embedded data as part of the unlock TX


        unlock_tx_unsigned_objectCharlie = transactions.UnsignedTransaction(
            int.from_bytes(unlock_tx_infoCharlie[0], byteorder="big"),  # nonce;
            int.from_bytes(unlock_tx_infoCharlie[1], byteorder="big"),  # gasprice
            int.from_bytes(unlock_tx_infoCharlie[2], byteorder="big"),  # startgas
            unlock_tx_infoCharlie[3],  # to addr
            int.from_bytes(unlock_tx_infoCharlie[4], byteorder="big"),  # value
            unlock_tx_infoCharlie[5],  # data
        )
        unlock_tx_unsigned_rlpCharlie = rlp.encode(unlock_tx_unsigned_objectCharlie, transactions.UnsignedTransaction)


        self.verifier_contract.revealBid(
            commit_block_numberCharlie,  # uint32 _commitBlockNumber,
            _unlockExtraData,  # bytes _commitData,
            rec_bin(witnessCharlie),  # bytes32 _witness,
            unlock_tx_unsigned_rlpCharlie,  # bytes _rlpUnlockTxUnsigned,
            commit_proof_blobCharlie,  # bytes _proofBlob
            sender=CHARLIE_PRIVATE_KEY)
        reveal_gasCharlie = int(self.chain.head_state.gas_used)

        self.chain.mine(1)

        ##
        ## CHECK THE STATE AFTER REVEAL
        ##

        bidListLength = self.verifier_contract.getBidListLength()
        self.assertEqual(bidListLength, 3, "Number of bids should match the number of participants in the auction")

        bidListItemAlice = self.verifier_contract.BidList(0)
        self.assertListEqual(["0x" + ALICE_ADDRESS.hex(), bytearray.fromhex(commitAlice)], bidListItemAlice)
        session_dataAlice = self.verifier_contract.getCommitState(rec_bin(commitAlice))
        self.assertListEqual(session_dataAlice, [BID_AMOUNT_Alice, SOLIDITY_NULL_INITIALVAL, commit_block_numberAlice, commit_block_indexAlice])
        finished_boolAlice = self.verifier_contract.finished(rec_bin(commitAlice))
        self.assertFalse(finished_boolAlice)

        bidListItemBob = self.verifier_contract.BidList(1)
        self.assertListEqual(["0x" + BOB_ADDRESS.hex(), bytearray.fromhex(commitBob)], bidListItemBob)
        session_dataBob = self.verifier_contract.getCommitState(rec_bin(commitBob))
        self.assertListEqual(session_dataBob, [BID_AMOUNT_Bob, SOLIDITY_NULL_INITIALVAL, commit_block_numberBob, commit_block_indexBob])
        finished_boolBob = self.verifier_contract.finished(rec_bin(commitBob))
        self.assertFalse(finished_boolBob)

        bidListItemCharlie = self.verifier_contract.BidList(2)
        self.assertListEqual(["0x" + CHARLIE_ADDRESS.hex(), bytearray.fromhex(commitCharlie)], bidListItemCharlie)
        session_dataCharlie = self.verifier_contract.getCommitState(rec_bin(commitCharlie))
        self.assertListEqual(session_dataCharlie, [BID_AMOUNT_Charlie, SOLIDITY_NULL_INITIALVAL, commit_block_numberCharlie, commit_block_indexCharlie])
        finished_boolCharlie = self.verifier_contract.finished(rec_bin(commitCharlie))
        self.assertFalse(finished_boolCharlie)

        ##
        ## BROADCAST UNLOCK
        ##
        self.chain.mine(1)
        self.chain.direct_tx(unlock_tx_objectAlice)
        unlock_gasAlice = int(self.chain.head_state.gas_used)
        self.chain.mine(1)

        self.chain.mine(1)
        self.chain.direct_tx(unlock_tx_objectBob)
        unlock_gasBob = int(self.chain.head_state.gas_used)
        self.chain.mine(1)

        self.chain.mine(1)
        self.chain.direct_tx(unlock_tx_objectCharlie)
        unlock_gasCharlie = int(self.chain.head_state.gas_used)
        self.chain.mine(1)

        ##
        ## CHECK STATE AFTER UNLOCK
        ##

        # stuff to help with debugging
        # unlock_block_numberAlice, unlock_block_indexAlice = self.chain.chain.get_tx_position(
        #         unlock_tx_objectAlice)
        # unlock_block_objectAlice = self.chain.chain.get_block_by_number(unlock_block_numberAlice)
        # print(unlock_block_objectAlice.as_dict())

        self.assertEqual(
            self.chain.head_state.get_balance(commitAddressAlice),
            (extraTransactionFees - unlock_gasAlice*OURGASPRICE),
            "Commit address should send along the money and have almost 0 money left."
        )

        self.assertEqual(
            self.chain.head_state.get_balance(commitAddressBob),
            (extraTransactionFees - unlock_gasBob*OURGASPRICE),
            "Commit address should send along the money and have almost 0 money left."
        )

        self.assertEqual(
            self.chain.head_state.get_balance(commitAddressCharlie),
            (extraTransactionFees - unlock_gasCharlie*OURGASPRICE),
            "Commit address should send along the money and have almost 0 money left."
        )

        self.assertEqual(
            self.chain.head_state.get_balance(self.verifier_contract.address),
            (BID_AMOUNT_Alice + BID_AMOUNT_Bob + BID_AMOUNT_Charlie),
            "Contract address should have the sum of the bids balance."
        )


        session_dataAlice = self.verifier_contract.getCommitState(rec_bin(commitAlice))
        self.assertListEqual(session_dataAlice, [BID_AMOUNT_Alice, BID_AMOUNT_Alice, commit_block_numberAlice, commit_block_indexAlice])
        finished_boolAlice = self.verifier_contract.finished(rec_bin(commitAlice))
        self.assertTrue(finished_boolAlice)

        session_dataBob = self.verifier_contract.getCommitState(rec_bin(commitBob))
        self.assertListEqual(session_dataBob, [BID_AMOUNT_Bob, BID_AMOUNT_Bob, commit_block_numberBob, commit_block_indexBob])
        finished_boolBob = self.verifier_contract.finished(rec_bin(commitBob))
        self.assertTrue(finished_boolBob)

        session_dataCharlie = self.verifier_contract.getCommitState(rec_bin(commitCharlie))
        self.assertListEqual(session_dataCharlie, [BID_AMOUNT_Charlie, BID_AMOUNT_Charlie, commit_block_numberCharlie, commit_block_indexCharlie])
        finished_boolCharlie = self.verifier_contract.finished(rec_bin(commitCharlie))
        self.assertTrue(finished_boolCharlie)

        self.assertFalse(self.verifier_contract.auctionIsOver())

        ##
        ## END AUCTION
        ##

        self.chain.mine(REVEAL_PERIOD_LENGTH)
        self.verifier_contract.endauction(sender=RANDO_ADDRESS_PRIVATE_KEY)

        ##
        ## CHECK STATE NOW THAT AUCTION IS OVER

        self.assertTrue(self.verifier_contract.auctionIsOver())
        self.assertEqual(rec_hex(CHARLIE_ADDRESS), self.verifier_contract.dogieOwner())

        self.assertEqual(
            ACCOUNT_STARTING_BALANCE - (extraTransactionFees + BASIC_SEND_GAS_LIMIT * OURGASPRICE),
            self.chain.head_state.get_balance(rec_hex(ALICE_ADDRESS)))

        self.assertEqual(
            ACCOUNT_STARTING_BALANCE - (extraTransactionFees + BASIC_SEND_GAS_LIMIT * OURGASPRICE),
            self.chain.head_state.get_balance(rec_hex(BOB_ADDRESS)))

        self.assertEqual(
            ACCOUNT_STARTING_BALANCE - (BID_AMOUNT_Charlie + extraTransactionFees + BASIC_SEND_GAS_LIMIT * OURGASPRICE),
            self.chain.head_state.get_balance(rec_hex(CHARLIE_ADDRESS)))

        self.assertEqual(starting_owner_eth_holdings + BID_AMOUNT_Charlie, self.chain.head_state.get_balance(rec_hex(CONTRACT_OWNER_ADDRESS)))


if __name__ == "__main__":
    unittest.main()
