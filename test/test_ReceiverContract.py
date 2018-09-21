import logging
import os
import rlp
import sys
import unittest
from ethereum import config, transactions
from ethereum.tools import tester as t
from ethereum.utils import checksum_encode, normalize_address
from test_utils import rec_hex, rec_bin, deploy_solidity_contract_with_args

sys.path.append(
    os.path.join(os.path.dirname(__file__), '..', 'generate_commitment'))
import generate_submarine_commit

root_repo_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../'))

REVEAL_DEPOSIT = 1000
CHALLENGE_PERIOD_LENGTH = 10
UNLOCK_AMOUNT = 1337000000000000000
OURGASLIMIT = 3712394
OURGASPRICE = 10**6
extraTransactionFees = 100000000000000000

log = logging.getLogger('TestLibSubmarine')
LOGFORMAT = "%(levelname)s:%(filename)s:%(lineno)s:%(funcName)s(): %(message)s"
log.setLevel(logging.getLevelName('INFO'))
logHandler = logging.StreamHandler(stream=sys.stdout)
logHandler.setFormatter(logging.Formatter(LOGFORMAT))
log.addHandler(logHandler)

#logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format=FORMAT)


class TestLibSubmarine(unittest.TestCase):
    def null_address(self):
        return '0x' + '0' * 40

    def assertEqualAddr(self, *args, **kwargs):
        return self.assertEqual(
            checksum_encode(args[0]), checksum_encode(args[1]), *args[2:],
            **kwargs)

    def setUp(self):
        config.config_metropolis['BLOCK_GAS_LIMIT'] = 2**60
        self.chain = t.Chain(env=config.Env(config=config.config_metropolis))
        self.chain.mine()
        contract_dir = os.path.abspath(
            os.path.join(root_repo_dir, 'contract/'))
        os.chdir(root_repo_dir)

        self.verifier_contract = deploy_solidity_contract_with_args(
            self.chain, {
                'LibSubmarine.sol': {
                    'urls': [os.path.join(contract_dir, 'LibSubmarine.sol')]
                },
                'SafeMath.sol': {
                    'urls': [os.path.join(contract_dir, 'SafeMath.sol')]
                },
                'SafeMath32.sol': {
                    'urls': [os.path.join(contract_dir, 'SafeMath32.sol')]
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
            root_repo_dir,
            'LibSubmarine.sol',
            'LibSubmarine',
            10**7,
            args=[REVEAL_DEPOSIT, CHALLENGE_PERIOD_LENGTH])

    ## DATA parameter?
    def test_workflow(self):
        ##
        ## STARTING STATE
        ##
        DAPP_ADDRESS = t.a2
        DAPP_PRIVATE_KEY = t.k2

        log.info("Contract Address: {}".format(
            rec_hex(self.verifier_contract.address)))
        log.info("State: Starting A1 has {} and has address {}".format(
            self.chain.head_state.get_balance(rec_hex(t.a1)), rec_hex(t.a1)))

        self.chain.mine(1)

        ##
        ## GENERATE UNLOCK AND BROADCAST TX, THEN BROADCAST COMMIT TX
        ##
        addressB, commit, witness, unlock_tx_hex = generate_submarine_commit.generateCommitAddress(
            normalize_address(rec_hex(t.a1)),
            normalize_address(rec_hex(self.verifier_contract.address)),
            UNLOCK_AMOUNT, b'', OURGASPRICE, OURGASLIMIT)
        log.info("Precomputed address of commit target: {}".format(addressB))

        commit_tx_object = transactions.Transaction(
            0, OURGASPRICE, OURGASLIMIT, rec_bin(addressB),
            (UNLOCK_AMOUNT + extraTransactionFees), b'').sign(t.k1)
        log.info("Commit TX transaction hash {}".format(
            rec_hex(commit_tx_object.hash)))
        log.info("Commit TX gas used: {}".format(
            str(commit_tx_object.intrinsic_gas_used)))

        self.chain.direct_tx(commit_tx_object)

        log.info("XXXXXXXXXXXXXXXXXXXXXXXXXXXX Commit() {}".format(self.chain.head_state.gas_used))
        commitGas = self.chain.head_state.gas_used
        self.chain.mine(1)

        ##
        ## CHECK STATE AFTER COMMIT TX
        ##
        commitBlockNumber, commitBlockIndex = self.chain.chain.get_tx_position(
            commit_tx_object)
        log.info("Commit Tx block number {} and tx block index {}".format(
            commitBlockNumber, commitBlockIndex))
        # tx_reciept = self.chain.tx(t.k1, rec_bin(addressB), (UNLOCK_AMOUNT + extraTransactionFees), b'', 21000, 10**6)
        log.info("State: After commit A1 has {} and has address {}".format(
            self.chain.head_state.get_balance(rec_hex(t.a1)), rec_hex(t.a1)))
        log.info("State: After commit B has {} and has address {}".format(
            self.chain.head_state.get_balance(addressB), addressB))
        self.assertEqual(1437000000000000000,
                         self.chain.head_state.get_balance(addressB))
        self.assertEqual(999998562999979000000000,
                         self.chain.head_state.get_balance(rec_hex(t.a1)))

        ##
        ## GENERATE AND BROADCAST REVEAL TX
        ##
        assert (isinstance(witness, str))
        self.verifier_contract.reveal(
            commitBlockNumber,
            commitBlockIndex,
            UNLOCK_AMOUNT,
            DAPP_ADDRESS,
            b'',
            rec_bin(witness),
            OURGASPRICE,
            OURGASLIMIT,
            sender=t.k1,
            to=self.verifier_contract.address,
            value=1009,
            gasprice=OURGASPRICE,
            startgas=OURGASLIMIT)

        log.info("XXXXXXXXXXXXXXXXXXXXXXXXXXXX Reveal() {}".format(self.chain.head_state.gas_used))
        revealGas = self.chain.head_state.gas_used
        self.chain.mine(1)

        ##
        ## CHECK STATE AFTER REVEAL TX
        ##
        sessionData = self.verifier_contract.getSession(rec_bin(commit))
        blockHash = self.verifier_contract.getBlockHash(commitBlockNumber)
        hashedCommit = self.verifier_contract.getHashedCommit(
            blockHash,
            commitBlockNumber,
            commitBlockIndex,
            DAPP_ADDRESS,
            b'')
        log.info("Contract Session after Reveal: {}".format(sessionData))
        # Assert Session checks
        # todo make revealBlock check by instantiating transaction class so that
        # todo we can get the tx hash and look up the block instead of hard coding
        # todo based on the state of the testing jig, this isn't nicely portable
        self.assertEqual(False, sessionData[0], "Session.unlocked wrong")
        self.assertEqual(4, sessionData[1], "Session.revealBlock wrong")
        self.assertEqual(UNLOCK_AMOUNT, sessionData[2], "Session.commitValue wrong")
        self.assertEqual(hashedCommit, sessionData[3], "Session.hashedCommit wrong")

        isfine = self.verifier_contract.isFinalizable(rec_bin(commit))
        self.assertFalse(isfine)

        ##
        ## GENERATE UNLOCK TX
        ##
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
        log.info("Unlock TX gas used: {}".format(
            str(unlock_tx_object.intrinsic_gas_used)))

        self.chain.direct_tx(unlock_tx_object)

        log.info("XXXXXXXXXXXXXXXXXXXXXXXXXXXX Unlock() {}".format(self.chain.head_state.gas_used))
        unlockGas = self.chain.head_state.gas_used
        self.chain.mine(1)

        ##
        ## CHECK STATE AFTER UNLOCK
        ##
        sessionData = self.verifier_contract.getSession(rec_bin(commit))
        blockHash = self.verifier_contract.getBlockHash(commitBlockNumber)
        hashedCommit = self.verifier_contract.getHashedCommit(
            blockHash,
            commitBlockNumber,
            commitBlockIndex,
            DAPP_ADDRESS,
            b'')
        log.info("Contract Session after Unlock: {}".format(sessionData))

        # Assert Session checks
        # todo make revealBlock check by instantiating transaction class so that
        # todo we can get the tx hash and look up the block instead of hard coding
        # todo based on the state of the testing jig, this isn't nicely portable
        self.assertEqual(True, sessionData[0], "Session.unlocked wrong")
        self.assertEqual(4, sessionData[1], "Session.revealBlock wrong")
        self.assertEqual(UNLOCK_AMOUNT, sessionData[2], "Session.commitValue wrong")
        self.assertEqual(hashedCommit, sessionData[3], "Session.hashedCommit wrong")

        unlockBlockNumber, unlockBlockIndex = self.chain.chain.get_tx_position(
            unlock_tx_object)
        log.info("Unlock tx block number {} and tx block index: {}".format(
            unlockBlockNumber, unlockBlockIndex))
        self.chain.mine(CHALLENGE_PERIOD_LENGTH)

        isfine = self.verifier_contract.isFinalizable(rec_bin(commit))
        self.assertTrue(isfine)

        log.info(
            "DAPP Address has balance {} and has address {} before unlock finalized".
            format(
                self.chain.head_state.get_balance(rec_hex(DAPP_ADDRESS)),
                rec_hex(DAPP_ADDRESS)))
        self.assertEqual(
            "1000000000000000000000000",
            str(self.chain.head_state.get_balance(rec_hex(DAPP_ADDRESS))),
            "dApp address should be unfunded prior to finalize")
        ##
        ## FINALIZE
        ##
        finalizedAmount, finalizedData = self.verifier_contract.finalize(
            rec_bin(commit),
            self.verifier_contract.getBlockHash(commitBlockNumber),
            commitBlockNumber,
            commitBlockIndex,
            DAPP_ADDRESS,
            b'',
            sender=DAPP_PRIVATE_KEY,
            to=self.verifier_contract.address,
            value=0,
            gasprice=OURGASPRICE,
            startgas=OURGASLIMIT)

        log.info("XXXXXXXXXXXXXXXXXXXXXXXXXXXX Finalize() {}".format(self.chain.head_state.gas_used))
        finalizeGas = self.chain.head_state.gas_used
        self.chain.mine(1)

        self.assertEqual(UNLOCK_AMOUNT, finalizedAmount)
        self.assertEqual(b'', finalizedData)
        log.info(self.chain.head_state.block_number)
        #log.info(self.chain.last_gas_used(with_tx=unlock_tx_object.hash))
        #finalizedBlock = get_block_by_number(21)
        #log.info(get_children(finalizedBlock))
        log.info(
            "DAPP Address has {} and has address {} after unlock finalized".
            format(
                self.chain.head_state.get_balance(rec_hex(DAPP_ADDRESS)),
                rec_hex(DAPP_ADDRESS)))
        # TODO I have no idea how to do a better gas cost estimation than this
        # TODO and the gas cost isn't the same each time which is strange... maybe EVM bug? unsure
        self.assertLessEqual(
            1000000000000000000000000 + UNLOCK_AMOUNT -
            (OURGASPRICE * OURGASLIMIT),
            self.chain.head_state.get_balance(rec_hex(DAPP_ADDRESS)))
        self.assertGreater(
            1000000000000000000000000 + UNLOCK_AMOUNT,
            self.chain.head_state.get_balance(rec_hex(DAPP_ADDRESS)))

        print("""
    ***** Gas Used *****
    Commit TX:     {}
    Reveal TX:     {}
    Unlock TX:     {}
    Finalize TX:   {}

    Total:        {}
    ********************
        """.format(commitGas,revealGas,unlockGas,finalizeGas,(commitGas+revealGas+unlockGas+finalizeGas)))

    def test_dishonest_party(self):
        ADDR_A = rec_hex(t.a1)
        PKEY_A = t.k1
        ADDR_B = rec_hex(t.a2)
        PKEY_B = t.k2
        DAPP_ADDRESS = "0xDEADbEeF000000000000000000000000DeaDbeEf"
        fake_tx_commit_object = transactions.Transaction(
            0, OURGASPRICE, OURGASLIMIT, ADDR_B,
            (UNLOCK_AMOUNT + extraTransactionFees), b'').sign(PKEY_A)

        self.chain.direct_tx(fake_tx_commit_object)
        self.chain.mine(1)
        witness = "0x03"
        fakecommitBlockNumber, fakecommitBlockIndex = self.chain.chain.get_tx_position(
            fake_tx_commit_object)
        log.info("tx block number {} and tx block index {}".format(
            fakecommitBlockNumber, fakecommitBlockIndex))

        ##
        ## CHECK STATE AFTER COMMIT TX
        ##
        log.info(
            "Dishonest Commit Tx block number {} and tx block index {}".format(
                fakecommitBlockNumber, fakecommitBlockIndex))
        # tx_reciept = self.chain.tx(t.k1, rec_bin(addressB), (UNLOCK_AMOUNT + extraTransactionFees), b'', 21000, 10**6)
        log.info("Dishonest State: After commit A1 has {} and has address {}".
                 format(self.chain.head_state.get_balance(ADDR_A), ADDR_A))
        log.info(
            "Dishonest State: After commit B has {} and has address {}".format(
                self.chain.head_state.get_balance(ADDR_B), ADDR_B))
        self.assertEqual(
            1000000000000000000000000 + UNLOCK_AMOUNT + extraTransactionFees,
            self.chain.head_state.get_balance(ADDR_B))
        self.assertEqual(999998562999979000000000,
                         self.chain.head_state.get_balance(ADDR_A))

        ##
        ## REVEAL
        ##
        def _listener(llog):
            log.info('Solidity Event listener log fire: {}'.format(str(llog)))
            log.info('Solidity Event listener log fire hex: {}'.format(
                str(rec_hex(llog['data']))))

        self.chain.head_state.log_listeners.append(_listener)

        self.verifier_contract.reveal(
            fakecommitBlockNumber,
            fakecommitBlockIndex,
            UNLOCK_AMOUNT,
            DAPP_ADDRESS,
            b'',
            rec_bin(witness),
            OURGASPRICE,
            OURGASLIMIT,
            sender=PKEY_A,
            to=self.verifier_contract.address,
            value=1009,
            gasprice=OURGASPRICE,
            startgas=OURGASLIMIT)
        self.chain.mine(1)

        # revealBlockNumber, revealBlockIndex = self.chain.chain.get_tx_position()
        # log.info("reveal block number {} and reveal block index {}".format(revealBlockNumber, revealBlockIndex))

        def aux(x):
            return x.to_bytes(32, byteorder='big')

        fakeSessionId = self.verifier_contract.getSessionId(
            ADDR_A, self.verifier_contract.address, UNLOCK_AMOUNT, b'',
            rec_bin(witness), OURGASPRICE, OURGASLIMIT)
        log.info(fakeSessionId)
        fakeSession = self.verifier_contract.getSession(fakeSessionId)
        fakeBlockHash = self.verifier_contract.getBlockHash(fakecommitBlockNumber)
        fakeHashedCommit = self.verifier_contract.getHashedCommit(
            fakeBlockHash,
            fakecommitBlockNumber,
            fakecommitBlockIndex,
            DAPP_ADDRESS,
            b'')
        log.info("Dishonest fake session " + str(fakeSession))
        self.assertListEqual(
            [
                False,  # sesh.unlocked
                3,  # sesh.revealBlock,
                1337000000000000000,  # sesh.commitValue,
                fakeHashedCommit # sesh.hashedCommit
                # 1,  # sesh.commitIndex,
                # 2,  # sesh.commitBlock,
                # b'',  # sesh.data,
                # '0xdeadbeef000000000000000000000000deadbeef'  # sesh.dappAddress
            ],
            fakeSession,
            "Session State is wrong")

        ##
        ## FAKE AN "UNLOCK" TX
        ##
        c_addr = self.verifier_contract.address
        fakeDataUnlock = generate_submarine_commit.unlockFunctionSelector + fakeSessionId
        unlock_tx_object = transactions.Transaction(
            0,  # nonce;
            OURGASPRICE,  # gasprice
            OURGASLIMIT,  # startgas
            c_addr,  # to addr
            UNLOCK_AMOUNT,  # value
            fakeDataUnlock,  # data
        ).sign(PKEY_B)
        log.info("Fake Unlock tx hash: {}".format(
            rec_hex(unlock_tx_object.hash)))
        self.chain.direct_tx(unlock_tx_object)
        self.chain.mine(1)

        ##
        ## CHECK UNLOCKED STATE
        ##
        fakeSession = self.verifier_contract.getSession(fakeSessionId)
        fakeBlockHash = self.verifier_contract.getBlockHash(fakecommitBlockNumber)
        fakeHashedCommit = self.verifier_contract.getHashedCommit(
            fakeBlockHash,
            fakecommitBlockNumber,
            fakecommitBlockIndex,
            DAPP_ADDRESS,
            b'')
        log.info("Dishonest fake session post unlock " + str(fakeSession))
        self.assertListEqual(
            [
                True,  # sesh.unlocked
                3,  # sesh.revealBlock,
                1337000000000000000,  # sesh.commitValue,
                fakeHashedCommit # sesh.hashedCommit
                # 1,  # sesh.commitIndex,
                # 2,  # sesh.commitBlock,
                # b'',  # sesh.data,
                # '0xdeadbeef000000000000000000000000deadbeef'  # sesh.dappAddress
            ],
            fakeSession,
            "Session State is wrong")

        unlockBlockNumber, unlockBlockIndex = self.chain.chain.get_tx_position(
            unlock_tx_object)
        log.info("Unlock tx block number {} and tx block index: {}".format(
            unlockBlockNumber, unlockBlockIndex))

        ##
        ## CHALLENGE THE FAKE TX
        ##

        # TODO generate the proof blob using proveth.py generate_proof_blob()
        # TODO then call the challenge function


if __name__ == "__main__":
    unittest.main()
