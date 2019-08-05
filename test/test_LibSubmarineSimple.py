import logging
import os
import rlp
import sys
import unittest
from ethereum import config, transactions
from ethereum.tools import tester as t
from ethereum.utils import checksum_encode, normalize_address, sha3, ecrecover_to_pub
from ethereum.exceptions import InvalidTransaction
from test_utils import rec_hex, rec_bin, deploy_solidity_contract_with_args, proveth_compatible_commit_block

sys.path.append(
    os.path.join(os.path.dirname(__file__), '..', 'generate_commitment'))
import generate_submarine_commit

sys.path.append(
    os.path.join(os.path.dirname(__file__), '..', 'proveth', 'offchain'))
import proveth

root_repo_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../'))

COMMIT_PERIOD_LENGTH = 3
UNLOCK_AMOUNT = 1337000000000000000
OURGASLIMIT = 3712394
OURGASPRICE = 10**6
BASIC_SEND_GAS_LIMIT = 21000
extraTransactionFees = 100000000000000000
ACCOUNT_STARTING_BALANCE = 1000000000000000000000000
SOLIDITY_NULL_INITIALVAL = 0

log = logging.getLogger('TestLibSubmarineSimple')
LOGFORMAT = "%(levelname)s:%(filename)s:%(lineno)s:%(funcName)s(): %(message)s"
log.setLevel(logging.getLevelName('INFO'))
logHandler = logging.StreamHandler(stream=sys.stdout)
logHandler.setFormatter(logging.Formatter(LOGFORMAT))
log.addHandler(logHandler)


class TestLibSubmarineSimple(unittest.TestCase):
    def setUp(self):
        config.config_metropolis['BLOCK_GAS_LIMIT'] = 2**60
        self.chain = t.Chain(env=config.Env(config=config.config_metropolis))
        self.chain.mine()
        contract_dir = os.path.abspath(
            os.path.join(root_repo_dir, 'contracts/'))
        os.chdir(root_repo_dir)

        self.verifier_contract = deploy_solidity_contract_with_args(
            chain=self.chain,
            solc_config_sources={
                'LibSubmarineSimpleTestHelper.sol': {
                    'urls':
                    [os.path.join(contract_dir, 'LibSubmarineSimpleTestHelper.sol')]
                },
                'LibSubmarineSimple.sol': {
                    'urls':
                    [os.path.join(contract_dir, 'LibSubmarineSimple.sol')]
                },
                'openzeppelin-solidity/contracts/math/SafeMath.sol': {
                    'urls': [os.path.join(contract_dir, 'openzeppelin-solidity/contracts/math/SafeMath.sol')]
                },
                'proveth/ProvethVerifier.sol': {
                    'urls': [
                        os.path.join(contract_dir,
                                     'proveth/ProvethVerifier.sol')
                    ]
                },
                'proveth/Solidity-RLP/contracts/RLPReader.sol': {
                    'urls': [os.path.join(contract_dir, 'proveth/Solidity-RLP/contracts/RLPReader.sol')]
                }
            },
            allow_paths=root_repo_dir,
            contract_file='LibSubmarineSimpleTestHelper.sol',
            contract_name='LibSubmarineSimpleTestHelper',
            startgas=10**7)

    def generateInvalidUnlockTx(self, userAddress, contractAddress, maliciousAddress):
        commit, witness, R, S = generate_submarine_commit._generateRS(
            normalize_address(rec_hex(userAddress)),
            normalize_address(rec_hex(contractAddress)),
            UNLOCK_AMOUNT, b'', OURGASPRICE, OURGASLIMIT)

        unlockFunctionSelector = b"\xec\x9b\x5b\x3a"
        submarineData = unlockFunctionSelector + commit

        # need the unsigned TX hash for ECRecover
        unlock_tx_unsigned_object = transactions.UnsignedTransaction(
            0,                                                   # nonce;
            OURGASPRICE,                                         # gasprice
            OURGASLIMIT,                                         # startgas
            normalize_address(maliciousAddress),                 # to addr
            UNLOCK_AMOUNT,                                       # value
            submarineData,                                       # data
        )
        unlock_tx_unsigned_hash = sha3(
            rlp.encode(unlock_tx_unsigned_object,
                  transactions.UnsignedTransaction))

        unlock_tx_object = transactions.Transaction(
            0,                                                   # nonce;
            OURGASPRICE,                                         # gasprice
            OURGASLIMIT,                                         # startgas
            normalize_address(maliciousAddress),                 # to addr
            UNLOCK_AMOUNT,                                       # value
            submarineData,                                       # data
            27,                                                  # v
            R,                                                   # r
            S                                                    # s
        )

        try:
            pub = ecrecover_to_pub(unlock_tx_unsigned_hash, 27, R, S)
            if pub ==  b"\x00" * 64:
                log.info("Address no good, retrying")
                return self.generateInvalidUnlockTx(userAddress, contractAddress, maliciousAddress)
            else:
                commit_addr = sha3(pub)[-20:]
                log.info("Fake Unlock TX Dict: {}".format(unlock_tx_unsigned_object.as_dict()))
                log.info("Fake Unlock TX Commit B: {}".format(commit_addr))
                return unlock_tx_object, unlock_tx_unsigned_object, commit_addr, commit, witness

        except (ValueError, InvalidTransaction) as e:
            if isinstance(e, ValueError) and "VRS" not in str(e):
                raise
            log.info("Address no good (%s), retrying" % e)
            return self.generateInvalidUnlockTx(userAddress, contractAddress, maliciousAddress)

    def test_workflow(self):
        ##
        ## STARTING STATE
        ##
        ALICE_ADDRESS = t.a1
        ALICE_PRIVATE_KEY = t.k1

        log.info("Contract Address: {}".format(
            rec_hex(self.verifier_contract.address)))
        log.info("State: Starting A1 has {} and has address {}".format(
            self.chain.head_state.get_balance(rec_hex(ALICE_ADDRESS)),
            rec_hex(ALICE_ADDRESS)))

        self.chain.mine(1)

        ##
        ## GENERATE UNLOCK AND BROADCAST TX, THEN BROADCAST JUST COMMIT TX
        ##
        addressB, commit, witness, unlock_tx_hex = generate_submarine_commit.generateCommitAddress(
            normalize_address(rec_hex(ALICE_ADDRESS)),
            normalize_address(rec_hex(self.verifier_contract.address)),
            UNLOCK_AMOUNT, b'', OURGASPRICE, OURGASLIMIT)
        log.info("Precomputed address of commit target: {}".format(addressB))

        assert (isinstance(witness, str))

        unlock_tx_info = rlp.decode(rec_bin(unlock_tx_hex))
        log.info("Unlock tx hex object: {}".format(rec_hex(unlock_tx_info)))

        unlock_tx_object = transactions.Transaction(
            int.from_bytes(unlock_tx_info[0], byteorder="big"),  # nonce;
            int.from_bytes(unlock_tx_info[1], byteorder="big"),  # gasprice
            int.from_bytes(unlock_tx_info[2], byteorder="big"),  # startgas
            unlock_tx_info[3],  # to addr
            int.from_bytes(unlock_tx_info[4], byteorder="big"),  # value
            unlock_tx_info[5],  # data
            int.from_bytes(unlock_tx_info[6], byteorder="big"),  # v
            int.from_bytes(unlock_tx_info[7], byteorder="big"),  # r
            int.from_bytes(unlock_tx_info[8], byteorder="big")  # s
        )
        log.info("Unlock tx hash: {}".format(rec_hex(unlock_tx_object.hash)))
        unlock_tx_unsigned_object = transactions.UnsignedTransaction(
            int.from_bytes(unlock_tx_info[0], byteorder="big"),  # nonce;
            int.from_bytes(unlock_tx_info[1], byteorder="big"),  # gasprice
            int.from_bytes(unlock_tx_info[2], byteorder="big"),  # startgas
            unlock_tx_info[3],  # to addr
            int.from_bytes(unlock_tx_info[4], byteorder="big"),  # value
            unlock_tx_info[5],  # data
        )

        unlock_tx_unsigned_rlp = rlp.encode(unlock_tx_unsigned_object, transactions.UnsignedTransaction)

        commit_tx_object = transactions.Transaction(
            0, OURGASPRICE, BASIC_SEND_GAS_LIMIT, rec_bin(addressB),
            (UNLOCK_AMOUNT + extraTransactionFees),
            b'').sign(ALICE_PRIVATE_KEY)
        log.info("Commit TX Object: {}".format(
            str(commit_tx_object.to_dict())))
        log.info("Commit TX gas used Intrinsic: {}".format(
            str(commit_tx_object.intrinsic_gas_used)))
        commit_gas = int(self.chain.head_state.gas_used)

        self.chain.direct_tx(commit_tx_object)
        log.info("Commit TX Gas Used HeadState {}".format(
            self.chain.head_state.gas_used))
        self.chain.mine(1)


        ##
        ## CHECK STATE AFTER COMMIT TX
        ##
        commit_block_number, commit_block_index = self.chain.chain.get_tx_position(
            commit_tx_object)
        log.info("Commit Tx block number {} and tx block index {}".format(
            commit_block_number, commit_block_index))
        log.info("State: After commit A1 has {} and has address {}".format(
            self.chain.head_state.get_balance(rec_hex(ALICE_ADDRESS)),
            rec_hex(ALICE_ADDRESS)))
        log.info("State: After commit B has {} and has address {}".format(
            self.chain.head_state.get_balance(addressB), addressB))
        self.assertEqual(UNLOCK_AMOUNT + extraTransactionFees,
                         self.chain.head_state.get_balance(addressB))
        self.assertEqual(
            ACCOUNT_STARTING_BALANCE - (UNLOCK_AMOUNT + extraTransactionFees +
                                        BASIC_SEND_GAS_LIMIT * OURGASPRICE),
            self.chain.head_state.get_balance(rec_hex(ALICE_ADDRESS)))

        session_data = self.verifier_contract.getSubmarineState(rec_bin(commit))
        self.assertListEqual(
            session_data, [SOLIDITY_NULL_INITIALVAL, SOLIDITY_NULL_INITIALVAL, SOLIDITY_NULL_INITIALVAL, SOLIDITY_NULL_INITIALVAL],
            "The contract should not know anything about the commit until after it's been revealed... "
        )

        finished_bool = self.verifier_contract.revealedAndUnlocked(rec_bin(commit))
        self.assertFalse(
            finished_bool,
            "The contract should not be finished before it's even begun.")

        ##
        ## GENERATE AND BROADCAST REVEAL TX
        ##
        commit_block_object = self.chain.chain.get_block_by_number(
            commit_block_number)
        log.info("Block information: {}".format(
            str(commit_block_object.as_dict())))
        log.info("Block header: {}".format(
            str(commit_block_object.as_dict()['header'].as_dict())))
        log.info("Block transactions: {}".format(
            str(commit_block_object.as_dict()['transactions'][0].as_dict())))

        proveth_commit_block = proveth_compatible_commit_block(commit_block_object, commit_tx_object)
        commit_proof_blob = proveth.generate_proof_blob(
            proveth_commit_block, commit_block_index)

        log.info("Proof Blob generate by proveth.py: {}".format(
            rec_hex(commit_proof_blob)))

        # Solidity Event log listener
        def _event_listener(llog):
            log.info('Solidity Event listener log fire: {}'.format(str(llog)))
            log.info('Solidity Event listener log fire hex: {}'.format(
                str(rec_hex(llog['data']))))

        self.chain.head_state.log_listeners.append(_event_listener)
        _unlockExtraData = b''  # In this example we dont have any extra embedded data as part of the unlock TX

        self.chain.mine(20)
        self.verifier_contract.reveal(
            #print(
            commit_block_number,  # uint32 _commitBlockNumber,
            _unlockExtraData,  # bytes _commitData,
            rec_bin(witness),  # bytes32 _witness,
            unlock_tx_unsigned_rlp,  # bytes _rlpUnlockTxUnsigned,
            commit_proof_blob,  # bytes _proofBlob
            sender=ALICE_PRIVATE_KEY)
        log.info("Reveal TX Gas Used HeadState {}".format(
            self.chain.head_state.gas_used))
        reveal_gas = int(self.chain.head_state.gas_used)

        self.chain.mine(1)

        ##
        ## CHECK STATE AFTER REVEAL TX
        ##
        session_data = self.verifier_contract.getSubmarineState(rec_bin(commit))
        self.assertListEqual(
            session_data, [UNLOCK_AMOUNT, SOLIDITY_NULL_INITIALVAL, commit_block_number, commit_block_index ],
            "After the Reveal, the state should report revealed but not unlocked."
        )
        finished_bool = self.verifier_contract.revealedAndUnlocked(rec_bin(commit))
        self.assertFalse(
            finished_bool,
            "The contract is only revealed, not unlocked and therefore finished."
        )

        ##
        ## BROADCAST UNLOCK
        ##
        self.chain.direct_tx(unlock_tx_object)
        log.info("Unlock TX Gas Used HeadState {}".format(
            self.chain.head_state.gas_used))
        unlock_gas = int(self.chain.head_state.gas_used)

        ##
        ## CHECK STATE AFTER UNLOCK
        ##
        log.info("State: After unlock B has {} and has address {}".format(
            self.chain.head_state.get_balance(addressB), addressB))

        self.assertLess(
            self.chain.head_state.get_balance(addressB),
            UNLOCK_AMOUNT + extraTransactionFees,
            "Address B should send along the money and have almost 0 money left."
        )
        self.assertEqual(
            999998562999979000000000,
            self.chain.head_state.get_balance(rec_hex(ALICE_ADDRESS)))

        session_data = self.verifier_contract.getSubmarineState(rec_bin(commit))
        self.assertListEqual(
            session_data, [UNLOCK_AMOUNT, UNLOCK_AMOUNT, commit_block_number, commit_block_index ],
            "State does not match expected value after unlock.")

        finished_bool = self.verifier_contract.revealedAndUnlocked(rec_bin(commit))
        self.assertTrue(finished_bool,
                        "After unlock, contract should be finished.")

        sumGas = commit_gas + reveal_gas + unlock_gas
        log.info("Final Gas Estimation {}".format(str(sumGas)))


    # Unlocking before revealing should still yield a usable result
    def test_unlock_before_reveal(self):
        ##
        ## STARTING STATE
        ##
        ALICE_ADDRESS = t.a1
        ALICE_PRIVATE_KEY = t.k1

        self.chain.mine(1)

        ##
        ## GENERATE UNLOCK TX
        ##
        addressB, commit, witness, unlock_tx_hex = generate_submarine_commit.generateCommitAddress(
            normalize_address(rec_hex(ALICE_ADDRESS)),
            normalize_address(rec_hex(self.verifier_contract.address)),
            UNLOCK_AMOUNT, b'', OURGASPRICE, OURGASLIMIT)

        unlock_tx_info = rlp.decode(rec_bin(unlock_tx_hex))

        unlock_tx_object = transactions.Transaction(
            int.from_bytes(unlock_tx_info[0], byteorder="big"),  # nonce;
            int.from_bytes(unlock_tx_info[1], byteorder="big"),  # gasprice
            int.from_bytes(unlock_tx_info[2], byteorder="big"),  # startgas
            unlock_tx_info[3],  # to addr
            int.from_bytes(unlock_tx_info[4], byteorder="big"),  # value
            unlock_tx_info[5],  # data
            int.from_bytes(unlock_tx_info[6], byteorder="big"),  # v
            int.from_bytes(unlock_tx_info[7], byteorder="big"),  # r
            int.from_bytes(unlock_tx_info[8], byteorder="big")  # s
        )
        unlock_tx_unsigned_object = transactions.UnsignedTransaction(
            int.from_bytes(unlock_tx_info[0], byteorder="big"),  # nonce;
            int.from_bytes(unlock_tx_info[1], byteorder="big"),  # gasprice
            int.from_bytes(unlock_tx_info[2], byteorder="big"),  # startgas
            unlock_tx_info[3],  # to addr
            int.from_bytes(unlock_tx_info[4], byteorder="big"),  # value
            unlock_tx_info[5],  # data
        )

        unlock_tx_unsigned_rlp = rlp.encode(unlock_tx_unsigned_object, transactions.UnsignedTransaction)




        ##
        ## GENERATE COMMIT
        ##
        commit_tx_object = transactions.Transaction(
            0, OURGASPRICE, BASIC_SEND_GAS_LIMIT, rec_bin(addressB),
            (UNLOCK_AMOUNT + extraTransactionFees),
            b'').sign(ALICE_PRIVATE_KEY)

        self.chain.direct_tx(commit_tx_object)

        self.chain.mine(4)

        session_data = self.verifier_contract.getSubmarineState(rec_bin(commit))
        self.assertListEqual(session_data, [SOLIDITY_NULL_INITIALVAL, SOLIDITY_NULL_INITIALVAL, SOLIDITY_NULL_INITIALVAL, SOLIDITY_NULL_INITIALVAL])

        finished_bool = self.verifier_contract.revealedAndUnlocked(rec_bin(commit))
        self.assertFalse(
            finished_bool,
            "The contract should not be finished until after the reveal.")

        commit_block_number, commit_block_index = self.chain.chain.get_tx_position(commit_tx_object)

        ##
        ## BROADCAST UNLOCK BEFORE REVEAL
        ##
        self.chain.direct_tx(unlock_tx_object)

        ##
        ## CHECK STATE AFTER UNLOCK
        ##
        session_data = self.verifier_contract.getSubmarineState(rec_bin(commit))
        self.assertListEqual(
            session_data, [SOLIDITY_NULL_INITIALVAL, UNLOCK_AMOUNT, SOLIDITY_NULL_INITIALVAL, SOLIDITY_NULL_INITIALVAL],
            "State does not match expected value after unlock.")

        finished_bool = self.verifier_contract.revealedAndUnlocked(rec_bin(commit))
        self.assertFalse(finished_bool)

        ##
        ## GENERATE AND BROADCAST REVEAL TX
        ##
        assert (isinstance(witness, str))
        commit_block_object = self.chain.chain.get_block_by_number(
            commit_block_number)
        log.info("Block information: {}".format(
            str(commit_block_object.as_dict())))
        log.info("Block header: {}".format(
            str(commit_block_object.as_dict()['header'].as_dict())))
        log.info("Block transactions: {}".format(
            str(commit_block_object.as_dict()['transactions'][0].as_dict())))

        proveth_commit_block = proveth_compatible_commit_block(commit_block_object, commit_tx_object)
        commit_proof_blob = proveth.generate_proof_blob(
            proveth_commit_block, commit_block_index)
        log.info("Proof Blob generate by proveth.py: {}".format(
            rec_hex(commit_proof_blob)))

        # Solidity Event log listener
        def _event_listener(llog):
            log.info('Solidity Event listener log fire: {}'.format(str(llog)))
            log.info('Solidity Event listener log fire hex: {}'.format(
                str(rec_hex(llog['data']))))

        self.chain.head_state.log_listeners.append(_event_listener)
        _unlockExtraData = b''  # In this example we dont have any extra embedded data as part of the unlock TX

        self.chain.mine(20)
        self.verifier_contract.reveal(
            #print(
            commit_block_number,  # uint32 _commitBlockNumber,
            _unlockExtraData,  # bytes _commitData,
            rec_bin(witness),  # bytes32 _witness,
            unlock_tx_unsigned_rlp,  # bytes _rlpUnlockTxUnsigned,
            commit_proof_blob,  # bytes _proofBlob
            sender=ALICE_PRIVATE_KEY)

        log.info("Reveal TX Gas Used HeadState {}".format(
            self.chain.head_state.gas_used))
        reveal_gas = int(self.chain.head_state.gas_used)

        self.chain.mine(1)

        ##
        ## CHECK STATE AFTER REVEAL TX
        ##
        session_data = self.verifier_contract.getSubmarineState(rec_bin(commit))
        self.assertListEqual(
            session_data, [UNLOCK_AMOUNT, UNLOCK_AMOUNT, commit_block_number, commit_block_index],
            "After the Reveal, the state should report both revealed and unlocked."
        )
        finished_bool = self.verifier_contract.revealedAndUnlocked(rec_bin(commit))
        self.assertTrue(
            finished_bool,
            "The contract was unlocked first and then revealed, it should be finished"
        )

    # Spam collisions should not happen with the unlock TX because of infinitesimally small probability of collision
    # But even if they do it should *still* not be an issue
    def test_spam_unlock_small_spam(self):
        ##
        ## STARTING STATE
        ##
        ALICE_ADDRESS = t.a1
        ALICE_PRIVATE_KEY = t.k1
        SPAM_PRIVATE_KEY_MALLORY = t.k7


        self.chain.mine(1)

        ##
        ## GENERATE UNLOCK TX
        ##
        addressB, commit, witness, unlock_tx_hex = generate_submarine_commit.generateCommitAddress(
            normalize_address(rec_hex(ALICE_ADDRESS)),
            normalize_address(rec_hex(self.verifier_contract.address)),
            UNLOCK_AMOUNT, b'', OURGASPRICE, OURGASLIMIT)

        unlock_tx_info = rlp.decode(rec_bin(unlock_tx_hex))

        unlock_tx_object = transactions.Transaction(
            int.from_bytes(unlock_tx_info[0], byteorder="big"),  # nonce;
            int.from_bytes(unlock_tx_info[1], byteorder="big"),  # gasprice
            int.from_bytes(unlock_tx_info[2], byteorder="big"),  # startgas
            unlock_tx_info[3],                                   # to addr
            int.from_bytes(unlock_tx_info[4], byteorder="big"),  # value
            unlock_tx_info[5],                                   # data
            int.from_bytes(unlock_tx_info[6], byteorder="big"),  # v
            int.from_bytes(unlock_tx_info[7], byteorder="big"),  # r
            int.from_bytes(unlock_tx_info[8], byteorder="big")   # s
        )
        unlock_tx_unsigned_object = transactions.UnsignedTransaction(
            int.from_bytes(unlock_tx_info[0], byteorder="big"),  # nonce;
            int.from_bytes(unlock_tx_info[1], byteorder="big"),  # gasprice
            int.from_bytes(unlock_tx_info[2], byteorder="big"),  # startgas
            unlock_tx_info[3],  # to addr
            int.from_bytes(unlock_tx_info[4], byteorder="big"),  # value
            unlock_tx_info[5],  # data
        )

        unlock_tx_unsigned_rlp = rlp.encode(unlock_tx_unsigned_object, transactions.UnsignedTransaction)
        ##
        ## SPAM THE UNLOCK FUNCTION
        ##
        SPAM_AMOUNT = 3
        spam_tx_object = transactions.Transaction(
            0,
            OURGASPRICE,
            OURGASLIMIT,
            normalize_address(rec_hex(self.verifier_contract.address)),
            SPAM_AMOUNT,
            unlock_tx_object[5]).sign(SPAM_PRIVATE_KEY_MALLORY)

        self.chain.direct_tx(spam_tx_object)
        session_data = self.verifier_contract.getSubmarineState(rec_bin(commit))
        self.assertListEqual(session_data, [SOLIDITY_NULL_INITIALVAL, SPAM_AMOUNT, SOLIDITY_NULL_INITIALVAL, SOLIDITY_NULL_INITIALVAL])
        self.chain.mine(1)

        ##
        ## GENERATE COMMIT
        ##
        commit_tx_object = transactions.Transaction(
            0, OURGASPRICE, BASIC_SEND_GAS_LIMIT, rec_bin(addressB),
            (UNLOCK_AMOUNT + extraTransactionFees),
            b'').sign(ALICE_PRIVATE_KEY)

        self.chain.direct_tx(commit_tx_object)

        self.chain.mine(4)

        session_data = self.verifier_contract.getSubmarineState(rec_bin(commit))
        self.assertListEqual(session_data, [SOLIDITY_NULL_INITIALVAL, SPAM_AMOUNT, SOLIDITY_NULL_INITIALVAL, SOLIDITY_NULL_INITIALVAL])

        finished_bool = self.verifier_contract.revealedAndUnlocked(rec_bin(commit))
        self.assertFalse(
            finished_bool,
            "The contract should not be finished until after the reveal.")

        commit_block_number, commit_block_index = self.chain.chain.get_tx_position(commit_tx_object)

        ##
        ## BROADCAST UNLOCK BEFORE REVEAL
        ##
        self.chain.direct_tx(unlock_tx_object)

        ##
        ## CHECK STATE AFTER UNLOCK
        ##
        session_data = self.verifier_contract.getSubmarineState(rec_bin(commit))
        self.assertListEqual(
            session_data, [SOLIDITY_NULL_INITIALVAL, UNLOCK_AMOUNT, SOLIDITY_NULL_INITIALVAL, SOLIDITY_NULL_INITIALVAL],
            "State does not match expected value after unlock.")

        finished_bool = self.verifier_contract.revealedAndUnlocked(rec_bin(commit))
        self.assertFalse(finished_bool)

        ##
        ## GENERATE AND BROADCAST REVEAL TX
        ##
        assert (isinstance(witness, str))
        commit_block_object = self.chain.chain.get_block_by_number(
            commit_block_number)
        log.info("Block information: {}".format(
            str(commit_block_object.as_dict())))
        log.info("Block header: {}".format(
            str(commit_block_object.as_dict()['header'].as_dict())))
        log.info("Block transactions: {}".format(
            str(commit_block_object.as_dict()['transactions'][0].as_dict())))

        proveth_commit_block = proveth_compatible_commit_block(commit_block_object, commit_tx_object)
        commit_proof_blob = proveth.generate_proof_blob(
            proveth_commit_block, commit_block_index)
        log.info("Proof Blob generate by proveth.py: {}".format(
            rec_hex(commit_proof_blob)))

        # Solidity Event log listener
        def _event_listener(llog):
            log.info('Solidity Event listener log fire: {}'.format(str(llog)))
            log.info('Solidity Event listener log fire hex: {}'.format(
                str(rec_hex(llog['data']))))

        self.chain.head_state.log_listeners.append(_event_listener)
        _unlockExtraData = b''  # In this example we dont have any extra embedded data as part of the unlock TX

        self.chain.mine(20)
        self.verifier_contract.reveal(
            #print(
            commit_block_number,  # uint32 _commitBlockNumber,
            _unlockExtraData,  # bytes _commitData,
            rec_bin(witness),  # bytes32 _witness,
            unlock_tx_unsigned_rlp,  # bytes _rlpUnlockTxUnsigned,
            commit_proof_blob,  # bytes _proofBlob
            sender=ALICE_PRIVATE_KEY)

        log.info("Reveal TX Gas Used HeadState {}".format(
            self.chain.head_state.gas_used))
        reveal_gas = int(self.chain.head_state.gas_used)

        self.chain.mine(1)

        ##
        ## CHECK STATE AFTER REVEAL TX
        ##
        session_data = self.verifier_contract.getSubmarineState(rec_bin(commit))
        self.assertListEqual(
            session_data, [UNLOCK_AMOUNT, UNLOCK_AMOUNT, commit_block_number, commit_block_index],
            "After the Reveal, the state should report both revealed and unlocked."
        )
        finished_bool = self.verifier_contract.revealedAndUnlocked(rec_bin(commit))
        self.assertTrue(
            finished_bool,
            "The contract was unlocked first and then revealed, it should be finished"
        )

    # Spam collisions should not happen with the unlock TX because of infinitesimally small probability of collision
    # But even if they do it should *still* not be an issue
    def test_spam_unlock_large_spam(self):
        ##
        ## STARTING STATE
        ##
        ALICE_ADDRESS = t.a1
        ALICE_PRIVATE_KEY = t.k1
        SPAM_PRIVATE_KEY_MALLORY = t.k7


        self.chain.mine(1)

        ##
        ## GENERATE UNLOCK TX
        ##
        addressB, commit, witness, unlock_tx_hex = generate_submarine_commit.generateCommitAddress(
            normalize_address(rec_hex(ALICE_ADDRESS)),
            normalize_address(rec_hex(self.verifier_contract.address)),
            UNLOCK_AMOUNT, b'', OURGASPRICE, OURGASLIMIT)

        unlock_tx_info = rlp.decode(rec_bin(unlock_tx_hex))

        unlock_tx_object = transactions.Transaction(
            int.from_bytes(unlock_tx_info[0], byteorder="big"),  # nonce;
            int.from_bytes(unlock_tx_info[1], byteorder="big"),  # gasprice
            int.from_bytes(unlock_tx_info[2], byteorder="big"),  # startgas
            unlock_tx_info[3],                                   # to addr
            int.from_bytes(unlock_tx_info[4], byteorder="big"),  # value
            unlock_tx_info[5],                                   # data
            int.from_bytes(unlock_tx_info[6], byteorder="big"),  # v
            int.from_bytes(unlock_tx_info[7], byteorder="big"),  # r
            int.from_bytes(unlock_tx_info[8], byteorder="big")   # s
        )
        unlock_tx_unsigned_object = transactions.UnsignedTransaction(
            int.from_bytes(unlock_tx_info[0], byteorder="big"),  # nonce;
            int.from_bytes(unlock_tx_info[1], byteorder="big"),  # gasprice
            int.from_bytes(unlock_tx_info[2], byteorder="big"),  # startgas
            unlock_tx_info[3],  # to addr
            int.from_bytes(unlock_tx_info[4], byteorder="big"),  # value
            unlock_tx_info[5],  # data
        )

        unlock_tx_unsigned_rlp = rlp.encode(unlock_tx_unsigned_object, transactions.UnsignedTransaction)



        ##
        ## SPAM THE UNLOCK FUNCTION
        ##
        SPAM_AMOUNT = UNLOCK_AMOUNT + 3235
        spam_tx_object = transactions.Transaction(
            0,
            OURGASPRICE,
            OURGASLIMIT,
            normalize_address(rec_hex(self.verifier_contract.address)),
            SPAM_AMOUNT,
            unlock_tx_object[5]).sign(SPAM_PRIVATE_KEY_MALLORY)

        self.chain.direct_tx(spam_tx_object)
        session_data = self.verifier_contract.getSubmarineState(rec_bin(commit))
        self.assertListEqual(session_data, [SOLIDITY_NULL_INITIALVAL, SPAM_AMOUNT, SOLIDITY_NULL_INITIALVAL, SOLIDITY_NULL_INITIALVAL])
        self.chain.mine(1)

        ##
        ## GENERATE COMMIT
        ##
        commit_tx_object = transactions.Transaction(
            0, OURGASPRICE, BASIC_SEND_GAS_LIMIT, rec_bin(addressB),
            (UNLOCK_AMOUNT + extraTransactionFees),
            b'').sign(ALICE_PRIVATE_KEY)

        self.chain.direct_tx(commit_tx_object)

        self.chain.mine(4)

        session_data = self.verifier_contract.getSubmarineState(rec_bin(commit))
        self.assertListEqual(session_data, [SOLIDITY_NULL_INITIALVAL, SPAM_AMOUNT, SOLIDITY_NULL_INITIALVAL, SOLIDITY_NULL_INITIALVAL])

        finished_bool = self.verifier_contract.revealedAndUnlocked(rec_bin(commit))
        self.assertFalse(
            finished_bool,
            "The contract should not be finished until after the reveal.")

        commit_block_number, commit_block_index = self.chain.chain.get_tx_position(commit_tx_object)

        ##
        ## BROADCAST UNLOCK (this should cause an exception since someone else donated money to your cause)
        ##
        with self.assertRaises(t.TransactionFailed):
            self.chain.direct_tx(unlock_tx_object)

        ##
        ## CHECK STATE AFTER UNLOCK
        ##
        session_data = self.verifier_contract.getSubmarineState(rec_bin(commit))
        self.assertListEqual(
            session_data, [SOLIDITY_NULL_INITIALVAL, SPAM_AMOUNT, SOLIDITY_NULL_INITIALVAL, SOLIDITY_NULL_INITIALVAL],
            "State does not match expected value after unlock.")

        finished_bool = self.verifier_contract.revealedAndUnlocked(rec_bin(commit))
        self.assertFalse(finished_bool)

        ##
        ## GENERATE AND BROADCAST REVEAL TX
        ##
        assert (isinstance(witness, str))
        commit_block_object = self.chain.chain.get_block_by_number(
            commit_block_number)
        log.info("Block information: {}".format(
            str(commit_block_object.as_dict())))
        log.info("Block header: {}".format(
            str(commit_block_object.as_dict()['header'].as_dict())))
        log.info("Block transactions: {}".format(
            str(commit_block_object.as_dict()['transactions'][0].as_dict())))

        proveth_commit_block = proveth_compatible_commit_block(commit_block_object, commit_tx_object)
        commit_proof_blob = proveth.generate_proof_blob(
            proveth_commit_block, commit_block_index)
        log.info("Proof Blob generate by proveth.py: {}".format(
            rec_hex(commit_proof_blob)))

        # Solidity Event log listener
        def _event_listener(llog):
            log.info('Solidity Event listener log fire: {}'.format(str(llog)))
            log.info('Solidity Event listener log fire hex: {}'.format(
                str(rec_hex(llog['data']))))

        self.chain.head_state.log_listeners.append(_event_listener)
        _unlockExtraData = b''  # In this example we dont have any extra embedded data as part of the unlock TX

        self.chain.mine(20)
        self.verifier_contract.reveal(
            #print(
            commit_block_number,  # uint32 _commitBlockNumber,
            _unlockExtraData,  # bytes _commitData,
            rec_bin(witness),  # bytes32 _witness,
            unlock_tx_unsigned_rlp,  # bytes _rlpUnlockTxUnsigned,
            commit_proof_blob,  # bytes _proofBlob
            sender=ALICE_PRIVATE_KEY)

        log.info("Reveal TX Gas Used HeadState {}".format(
            self.chain.head_state.gas_used))
        reveal_gas = int(self.chain.head_state.gas_used)

        self.chain.mine(1)

        ##
        ## CHECK STATE AFTER REVEAL TX
        ##
        session_data = self.verifier_contract.getSubmarineState(rec_bin(commit))
        self.assertListEqual(
            session_data, [UNLOCK_AMOUNT, SPAM_AMOUNT, commit_block_number, commit_block_index],
            "After the Reveal, the state should report both revealed and unlocked."
        )
        finished_bool = self.verifier_contract.revealedAndUnlocked(rec_bin(commit))
        self.assertTrue(
            finished_bool,
            "The contract was unlocked first and then revealed, it should be finished"
        )

    def test_fake_unlock_commit_does_not_match_to_address(self):
        ##
        ## STARTING STATE
        ##
        ALICE_ADDRESS = t.a1
        ALICE_PRIVATE_KEY = t.k1
        MALICIOUS_ADDRESS = t.a7

        self.chain.mine(1)

        ##
        ## GENERATE FAKE UNLOCK TX
        ##
        unlock_tx_object, unlock_tx_unsigned_object, commit_addr, commit, witness = self.generateInvalidUnlockTx(ALICE_ADDRESS, self.verifier_contract.address, MALICIOUS_ADDRESS)
        unlock_tx_unsigned_rlp = rlp.encode(unlock_tx_unsigned_object, transactions.UnsignedTransaction)

        ##
        ## GENERATE COMMIT
        ##
        commit_tx_object = transactions.Transaction(
            0, OURGASPRICE, BASIC_SEND_GAS_LIMIT, commit_addr,
            (UNLOCK_AMOUNT + extraTransactionFees),
            b'').sign(ALICE_PRIVATE_KEY)

        self.chain.direct_tx(commit_tx_object)

        self.chain.mine(4)

        commit_block_number, commit_block_index = self.chain.chain.get_tx_position(commit_tx_object)
        log.info("Commit Tx block number {} and tx block index {}".format(
            commit_block_number, commit_block_index))
        log.info("State: After commit A1 has {} and has address {}".format(
            self.chain.head_state.get_balance(rec_hex(ALICE_ADDRESS)),
            rec_hex(ALICE_ADDRESS)))
        log.info("State: After commit B has {} and has address {}".format(
            self.chain.head_state.get_balance(commit_addr), commit_addr))
        log.info("State: After commit C has {} and has address {}".format(
            self.chain.head_state.get_balance(MALICIOUS_ADDRESS), MALICIOUS_ADDRESS))
        afterCommitCommitAddressAmount = UNLOCK_AMOUNT + extraTransactionFees
        afterCommitAliceAddressAmount = ACCOUNT_STARTING_BALANCE - (UNLOCK_AMOUNT + extraTransactionFees + BASIC_SEND_GAS_LIMIT * OURGASPRICE)
        self.assertEqual(afterCommitCommitAddressAmount,
                         self.chain.head_state.get_balance(commit_addr))
        self.assertEqual(afterCommitAliceAddressAmount,
            self.chain.head_state.get_balance(rec_hex(ALICE_ADDRESS)))

        ##
        ## GENERATE AND BROADCAST REVEAL TX
        ##
        commit_block_object = self.chain.chain.get_block_by_number(
            commit_block_number)
        log.info("Block information: {}".format(
            str(commit_block_object.as_dict())))
        log.info("Block header: {}".format(
            str(commit_block_object.as_dict()['header'].as_dict())))
        log.info("Block transactions: {}".format(
            str(commit_block_object.as_dict()['transactions'][0].as_dict())))

        proveth_commit_block = proveth_compatible_commit_block(commit_block_object, commit_tx_object)
        commit_proof_blob = proveth.generate_proof_blob(
            proveth_commit_block, commit_block_index)
        log.info("Proof Blob generate by proveth.py: {}".format(
            rec_hex(commit_proof_blob)))

        # Solidity Event log listener
        def _event_listener(llog):
            log.info('Solidity Event listener log fire: {}'.format(str(llog)))
            log.info('Solidity Event listener log fire hex: {}'.format(
                str(rec_hex(llog['data']))))

        self.chain.head_state.log_listeners.append(_event_listener)
        _unlockExtraData = b''  # In this example we dont have any extra embedded data as part of the unlock TX


        self.chain.direct_tx(unlock_tx_object)

        log.info("State: After unlock A1 has {} and has address {}".format(
            self.chain.head_state.get_balance(rec_hex(ALICE_ADDRESS)),
            rec_hex(ALICE_ADDRESS)))
        log.info("State: After unlock B has {} and has address {}".format(
            self.chain.head_state.get_balance(commit_addr), commit_addr))
        log.info("State: After unlock C has {} and has address {}".format(
            self.chain.head_state.get_balance(MALICIOUS_ADDRESS), MALICIOUS_ADDRESS))
        self.assertLess(self.chain.head_state.get_balance(commit_addr), afterCommitCommitAddressAmount)
        self.assertGreater(self.chain.head_state.get_balance(rec_hex(MALICIOUS_ADDRESS)), ACCOUNT_STARTING_BALANCE)

        self.chain.mine(20)
        ##
        ## THE REVEAL SHOULD NOW FAIL
        ##
        with self.assertRaises(t.TransactionFailed):
            self.verifier_contract.reveal(
                commit_block_number,  # uint32 _commitBlockNumber,
                _unlockExtraData,  # bytes _commitData,
                witness,  # bytes32 _witness,
                unlock_tx_unsigned_rlp,  # bytes _rlpUnlockTxUnsigned,
                commit_proof_blob,  # bytes _proofBlob
                sender=ALICE_PRIVATE_KEY
            )

if __name__ == "__main__":
    unittest.main()
