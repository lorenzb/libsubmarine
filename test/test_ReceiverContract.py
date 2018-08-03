import logging
import os
import rlp
import sys
import unittest
from ethereum import config, transactions
from ethereum.tools import tester as t
from ethereum.utils import checksum_encode, normalize_address, sha3_256
from test_utils import rec_hex, rec_bin, deploy_solidity_contract_with_args

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'generate_commitment'))
import generate_submarine_commit

root_repo_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../'))

REVEAL_DEPOSIT = 1000
CHALLENGE_PERIOD_LENGTH = 10
UNLOCK_AMOUNT = 1337000000000000000
OURGASLIMIT = 3712394
OURGASPRICE = 10 ** 6
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
        return self.assertEqual(checksum_encode(args[0]), checksum_encode(args[1]), *args[2:], **kwargs)

    def setUp(self):
        config.config_metropolis['BLOCK_GAS_LIMIT'] = 2 ** 60
        self.chain = t.Chain(env=config.Env(config=config.config_metropolis))
        self.chain.mine()
        contract_dir = os.path.abspath(os.path.join(root_repo_dir, 'contract/'))
        os.chdir(root_repo_dir)

        self.verifier_contract = deploy_solidity_contract_with_args(
            self.chain,
            {'LibSubmarine.sol': {'urls': [os.path.join(contract_dir, 'LibSubmarine.sol')]},
             'SafeMath.sol': {'urls': [os.path.join(contract_dir, 'SafeMath.sol')]},
             'proveth/ProvethVerifier.sol': {'urls': [os.path.join(contract_dir, 'proveth/ProvethVerifier.sol')]},
             'proveth/RLP.sol': {'urls': [os.path.join(contract_dir, 'proveth/RLP.sol')]}
             },
            root_repo_dir,
            'LibSubmarine.sol',
            'LibSubmarine',
            10 ** 7,
            args=[REVEAL_DEPOSIT, CHALLENGE_PERIOD_LENGTH]
        )

    ##NEED DATA
    def test_workflow(self):
        DAPP_ADDRESS = t.a2
        DAPP_PRIVATE_KEY = t.k2

        log.info("Contract Address: {}".format(rec_hex(self.verifier_contract.address)))
        log.info(
            "State: Starting A1 has {} and has address {}".format(self.chain.head_state.get_balance(rec_hex(t.a1)),
                                                           rec_hex(t.a1)))

        addressB, commit, witness, tx_hex = generate_submarine_commit.generateAddressBexport(
            normalize_address(rec_hex(t.a1)),
            normalize_address(rec_hex(self.verifier_contract.address)),
            UNLOCK_AMOUNT,
            b'',
            OURGASPRICE,
            OURGASLIMIT
        )
        log.info("Precomputed address of commit target: {}".format(addressB))

        commit_tx_object = transactions.Transaction(
            0, OURGASPRICE, OURGASLIMIT, rec_bin(addressB), (UNLOCK_AMOUNT + extraTransactionFees), b'').sign(t.k1)
        log.info("Commit TX transaction hash {}".format(rec_hex(commit_tx_object.hash)))

        self.chain.mine(3)
        self.chain.direct_tx(commit_tx_object)
        self.chain.mine(3)

        commitBlockNumber, commitBlockIndex = self.chain.chain.get_tx_position(commit_tx_object)
        log.info("Commit Tx block number {} and tx block index {}".format(commitBlockNumber, commitBlockIndex))
        # tx_reciept = self.chain.tx(t.k1, rec_bin(addressB), (UNLOCK_AMOUNT + extraTransactionFees), b'', 21000, 10**6)
        log.info(
            "State: After commit A1 has {} and has address {}".format(self.chain.head_state.get_balance(rec_hex(t.a1)),
                                                         rec_hex(t.a1)))
        log.info("State: After commit B has {} and has address {}".format(self.chain.head_state.get_balance(addressB), addressB))
        self.assertEqual(1437000000000000000, self.chain.head_state.get_balance(addressB))
        self.assertEqual(999998562999979000000000, self.chain.head_state.get_balance(rec_hex(t.a1)))

        assert (isinstance(witness, str))
        self.verifier_contract.reveal(
            commitBlockNumber, commitBlockIndex, DAPP_ADDRESS, UNLOCK_AMOUNT, b'', rec_bin(witness), OURGASPRICE,
            OURGASLIMIT,
            sender=t.k1,
            to=self.verifier_contract.address,
            value=1009,
            gasprice=OURGASPRICE,
            startgas=OURGASLIMIT)

        revealTestSession = self.verifier_contract.getSession(rec_bin(commit))
        log.info("Contract Session after Reveal: {}".format(str(revealTestSession)))

        # Assert Session checks
        # todo make revealBlock check by instantiating transaction class so that
        # todo we can get the tx hash and look up the block instead of hard coding
        # todo based on the state of the testing jig, this isn't nicely portable
        self.assertEqual(False, revealTestSession[0],                   "Session.unlocked wrong")
        self.assertEqual(True, revealTestSession[1],                    "Session.revealed wrong")
        self.assertEqual(False, revealTestSession[2],                   "Session.slashed wrong")
        self.assertEqual(UNLOCK_AMOUNT, revealTestSession[3],           "Session.unlockAmount wrong")
        self.assertEqual(commitBlockNumber, revealTestSession[4],       "Session.commitBlock wrong")
        self.assertEqual(commitBlockIndex, revealTestSession[5],        "Session.commitIndex wrong")
        self.assertEqual(8, revealTestSession[6],                       "Session.revealBlock wrong")
        self.assertEqual(b'', revealTestSession[7],                     "Session.data wrong")
        self.assertEqual(rec_hex(DAPP_ADDRESS), revealTestSession[8],   "Session.dappAddress wrong")

        isfine, unlockAmount, unlockdata = self.verifier_contract.isFinalizable(rec_bin(commit))
        self.assertFalse(isfine)
        unlock_tx_info = rlp.decode(rec_bin(tx_hex))
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

        self.chain.direct_tx(unlock_tx_object)
        self.chain.mine(3)

        unlockTestSession = self.verifier_contract.getSession(rec_bin(commit))
        log.info("Contract Session after Unlock: {}".format(unlockTestSession))

        # Assert Session checks
        # todo make revealBlock check by instantiating transaction class so that
        # todo we can get the tx hash and look up the block instead of hard coding
        # todo based on the state of the testing jig, this isn't nicely portable
        self.assertEqual(True, unlockTestSession[0],                    "Session.unlocked wrong")
        self.assertEqual(True, revealTestSession[1],                    "Session.revealed wrong")
        self.assertEqual(False, revealTestSession[2],                   "Session.slashed wrong")
        self.assertEqual(UNLOCK_AMOUNT, revealTestSession[3],           "Session.unlockAmount wrong")
        self.assertEqual(commitBlockNumber, revealTestSession[4],       "Session.commitBlock wrong")
        self.assertEqual(commitBlockIndex, revealTestSession[5],        "Session.commitIndex wrong")
        self.assertEqual(8, revealTestSession[6],                       "Session.revealBlock wrong")
        self.assertEqual(b'', revealTestSession[7],                     "Session.data wrong")
        self.assertEqual(rec_hex(DAPP_ADDRESS), revealTestSession[8],   "Session.dappAddress wrong")

        unlockBlockNumber, unlockBlockIndex = self.chain.chain.get_tx_position(unlock_tx_object)
        log.info("Unlock tx block number {} and tx block index: {}".format(unlockBlockNumber, unlockBlockIndex))
        self.chain.mine(CHALLENGE_PERIOD_LENGTH)

        isfine, unlockAmount, unlockData = self.verifier_contract.isFinalizable(rec_bin(commit))
        self.assertTrue(isfine)
        self.assertEqual(UNLOCK_AMOUNT, unlockAmount)
        self.assertEqual(b'', unlockData)

        log.info(
            "DAPP Address has balance {} and has address {} before unlock finalized".format(self.chain.head_state.get_balance(rec_hex(DAPP_ADDRESS)),
                                                            rec_hex(DAPP_ADDRESS)))
        unlockAmount, unlockData = self.verifier_contract.finalize(
            rec_bin(commit),
            sender=DAPP_PRIVATE_KEY,
            to=self.verifier_contract.address,
            value=0,
            gasprice=OURGASPRICE,
            startgas=OURGASLIMIT
        )
        self.chain.mine(1)
        self.assertEqual(UNLOCK_AMOUNT, unlockAmount)
        self.assertEqual(b'', unlockData)
        log.info(
            "DAPP Address has {} and has address {} after unlock finalized".format(
                self.chain.head_state.get_balance(rec_hex(DAPP_ADDRESS)),
                rec_hex(DAPP_ADDRESS)))
        # debugging getting sample gas costs for benchmarking
        # unlockBlockNumber = self.chain.chain.get_block_by_number(21)
        # pprint.pprint(unlockBlockNumber.__dict__, width=1)
        # pprint.pprint(unlockBlockNumber._transactions[0].intrinsic_gas_used, width=1)

    def test_dishonest_party(self):
        ADDR_A = rec_hex(t.a1)
        PKEY_A = t.k1
        ADDR_B = rec_hex(t.a2)
        PKEY_B = t.k2
        DAPP_ADDRESS = "0xDEADbEeF000000000000000000000000DeaDbeEf"
        fake_tx_commit_object = transactions.Transaction(
            0, OURGASPRICE, OURGASLIMIT, ADDR_B, (UNLOCK_AMOUNT + extraTransactionFees), b'').sign(PKEY_A)

        self.chain.direct_tx(fake_tx_commit_object)
        self.chain.mine(1)
        witness = "0x03"
        fakecommitBlockNumber, fakecommitBlockIndex = self.chain.chain.get_tx_position(fake_tx_commit_object)
        log.info("tx block number {} and tx block index {}".format(fakecommitBlockNumber, fakecommitBlockIndex))

        def _listener(llog):
            log.info('Solidity Event listener log fire: {}'.format(str(llog)))
            log.info('Solidity Event listener log fire hex: {}'.format(str(rec_hex(llog['data']))))

        self.chain.head_state.log_listeners.append(_listener)

        self.verifier_contract.reveal(
            fakecommitBlockNumber, fakecommitBlockIndex, DAPP_ADDRESS, UNLOCK_AMOUNT, b'', rec_bin(witness),
            OURGASPRICE, OURGASLIMIT,
            sender=PKEY_A,
            to=self.verifier_contract.address,
            value=1009,
            gasprice=OURGASPRICE,
            startgas=OURGASLIMIT
        )
        self.chain.mine(1)

        # revealBlockNumber, revealBlockIndex = self.chain.chain.get_tx_position()
        # log.info("reveal block number {} and reveal block index {}".format(revealBlockNumber, revealBlockIndex))

        def aux(x):
            return x.to_bytes(32, byteorder='big')

        computedfakecommit = (rec_bin(ADDR_A) + self.verifier_contract.address + aux(UNLOCK_AMOUNT) + b'' + rec_bin(
            witness) + aux(OURGASPRICE) + aux(OURGASLIMIT))
        sessionID = sha3_256(computedfakecommit)
        log.info(rec_hex(sessionID))

        revealTestSession = self.verifier_contract.getSession(
            rec_bin("000000000000000000000000000000000000000000000000128dfa6a90b28000"))
        log.info(revealTestSession)


if __name__ == "__main__":
    unittest.main()
