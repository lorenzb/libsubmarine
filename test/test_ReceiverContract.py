import collections
import os
import unittest

from test_utils import rec_hex, rec_bin, deploy_solidity_contract_with_args

from ethereum import utils
from ethereum import config
from ethereum import transactions
from ethereum.tools import tester as t
from ethereum.utils import mk_contract_address, checksum_encode, normalize_address, sha3_256

import rlp

import pprint

import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'generate_commitment'))
import generate_submarine_commit

REVEAL_DEPOSIT = 1000
CHALLENGE_PERIOD_LENGTH = 10
UNLOCK_AMOUNT = 1337000000000000000
OURGASLIMIT = 3712394
OURGASPRICE = 10**6
extraTransactionFees = 100000000000000000


class TestLibSubmarine(unittest.TestCase):

    def null_address(self):
        return '0x' + '0' * 40

    def assertEqualAddr(self, *args, **kwargs):
        return self.assertEqual(checksum_encode(args[0]), checksum_encode(args[1]), *args[2:], **kwargs)

    def setUp(self):
        config.config_metropolis['BLOCK_GAS_LIMIT'] = 2**60
        self.chain = t.Chain(env=config.Env(config=config.config_metropolis))
        self.chain.mine()

        self.verifier_contract = deploy_solidity_contract_with_args(
            self.chain,
            {'LibSubmarine.sol': {'urls': ['contract/LibSubmarine.sol']},
             'SafeMath.sol': {'urls': ['contract/SafeMath.sol']},
             'proveth/ProvethVerifier.sol': {'urls': ['contract/proveth/ProvethVerifier.sol']},
             'proveth/RLP.sol': {'urls': ['contract/proveth/RLP.sol']}
            },
            os.path.abspath(os.getcwd()),
            'LibSubmarine.sol',
            'LibSubmarine',
            10**7,
            args=[REVEAL_DEPOSIT, CHALLENGE_PERIOD_LENGTH]
        )

    ##NEED DATA
    def test_workflow(self):
        DAPP_ADDRESS = t.a2
        DAPP_PRIVATE_KEY = t.k2

        print("Contract Address:", rec_hex(self.verifier_contract.address))
        print("A1 has {} and has address {}".format(self.chain.head_state.get_balance(rec_hex(t.a1)), rec_hex(t.a1)))

        addressB, commit, witness, tx_hex = generate_submarine_commit.generateAddressBexport(
            normalize_address(rec_hex(t.a1)),
            normalize_address(rec_hex(self.verifier_contract.address)),
            UNLOCK_AMOUNT,
            b'',
            OURGASPRICE,
            OURGASLIMIT
        )
        print("Address of commit: {}".format(addressB))
        commit_tx_object = transactions.Transaction(
            0, OURGASPRICE, OURGASLIMIT, rec_bin(addressB), (UNLOCK_AMOUNT + extraTransactionFees), b'').sign(t.k1)
        print("New transaction hash")
        print(rec_hex(commit_tx_object.hash))
        self.chain.mine(3)
        self.chain.direct_tx(commit_tx_object)
        self.chain.mine(3)
        commitBlockNumber, commitBlockIndex = self.chain.chain.get_tx_position(commit_tx_object)
        print("tx block number {} and tx block index {}".format( commitBlockNumber, commitBlockIndex))
        #tx_reciept = self.chain.tx(t.k1, rec_bin(addressB), (UNLOCK_AMOUNT + extraTransactionFees), b'', 21000, 10**6)
        print("A1 has {} and has address {}".format(self.chain.head_state.get_balance(rec_hex(t.a1)), rec_hex(t.a1)))
        print("B has {} and has address {}".format(self.chain.head_state.get_balance(addressB), addressB))
        self.assertEqual(1437000000000000000, self.chain.head_state.get_balance(addressB))
        self.assertEqual(999998562999979000000000, self.chain.head_state.get_balance(rec_hex(t.a1)))

        assert(isinstance(witness, str))
        self.verifier_contract.reveal(
            commitBlockNumber, commitBlockIndex, DAPP_ADDRESS, UNLOCK_AMOUNT, b'',  rec_bin(witness), OURGASPRICE, OURGASLIMIT,
            sender=t.k1,
            to=self.verifier_contract.address,
            value=1009,
            gasprice=OURGASPRICE,
            startgas=OURGASLIMIT)
        revealTestSession = self.verifier_contract.getSession(rec_bin(commit))
        print(revealTestSession)
        # see getSession function return values for reference
        self.assertEqual(False, revealTestSession[0])
        self.assertEqual(True, revealTestSession[1])
        self.assertEqual(False, revealTestSession[2])
        self.assertEqual(UNLOCK_AMOUNT, revealTestSession[3])
        self.assertEqual(commitBlockNumber, revealTestSession[4])
        self.assertEqual(commitBlockIndex, revealTestSession[5])
        # todo make reveal by instatiating transaction class so that
        # todo we can get the tx hash and look up the block instead of hard coding
        self.assertEqual(8, revealTestSession[6])
        self.assertEqual(b'', revealTestSession[7])
        self.assertEqual(rec_hex(DAPP_ADDRESS), revealTestSession[8])

        isfine, unlockAmount, unlockdata = self.verifier_contract.isFinalizable(rec_bin(commit))
        self.assertFalse(isfine)
        unlock_tx_info = rlp.decode(rec_bin(tx_hex))
        print(rec_hex(unlock_tx_info))

        unlock_tx_object = transactions.Transaction(
            int.from_bytes(unlock_tx_info[0], byteorder="big"), #  nonce;
            int.from_bytes(unlock_tx_info[1], byteorder="big"), # gasprice
            int.from_bytes(unlock_tx_info[2], byteorder="big"), # startgas
            unlock_tx_info[3], # to addr
            int.from_bytes(unlock_tx_info[4], byteorder="big"), # value
            unlock_tx_info[5], # data
            int.from_bytes(unlock_tx_info[6], byteorder="big"), # v
            int.from_bytes(unlock_tx_info[7], byteorder="big"), # r
            int.from_bytes(unlock_tx_info[8], byteorder="big") # s
        )
        print("Unlock hash: ")
        print(rec_hex(unlock_tx_object.hash))

        self.chain.direct_tx(unlock_tx_object)
        self.chain.mine(3)

        unlockTestSession = self.verifier_contract.getSession(rec_bin(commit))
        print(unlockTestSession)
        self.assertEqual(True, unlockTestSession[0])
        self.assertEqual(True, unlockTestSession[1])
        self.assertEqual(False, unlockTestSession[2])
        self.assertEqual(UNLOCK_AMOUNT, unlockTestSession[3])
        self.assertEqual(commitBlockNumber, unlockTestSession[4])
        self.assertEqual(commitBlockIndex, unlockTestSession[5])
        # todo make reveal by instatiating transaction class so that
        # todo we can get the tx hash and look up the block instead of hard coding
        self.assertEqual(8, unlockTestSession[6])
        self.assertEqual(b'', unlockTestSession[7])
        self.assertEqual(rec_hex(DAPP_ADDRESS), unlockTestSession[8])
        unlockBlockNumber, unlockBlockIndex = self.chain.chain.get_tx_position(unlock_tx_object)
        print("tx block number {} and tx block index {}".format( unlockBlockNumber, unlockBlockIndex))
        self.chain.mine(CHALLENGE_PERIOD_LENGTH)

        isfine, unlockAmount, unlockData = self.verifier_contract.isFinalizable(rec_bin(commit))
        self.assertTrue(isfine)
        self.assertEqual(UNLOCK_AMOUNT, unlockAmount)
        self.assertEqual(b'', unlockData)

        print("DAPP Address has {} and has address {}".format(self.chain.head_state.get_balance(rec_hex(DAPP_ADDRESS)), rec_hex(DAPP_ADDRESS)))
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
        print("DAPP Address has {} and has address {}".format(self.chain.head_state.get_balance(rec_hex(DAPP_ADDRESS)), rec_hex(DAPP_ADDRESS)))
        print()
        # getting gas costs
        #unlockBlockNumber = self.chain.chain.get_block_by_number(21)
        #pprint.pprint(unlockBlockNumber.__dict__, width=1)
        #pprint.pprint(unlockBlockNumber._transactions[0].intrinsic_gas_used, width=1)

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
        print("tx block number {} and tx block index {}".format( fakecommitBlockNumber, fakecommitBlockIndex))

        def _listener(log):
            print('LOG:', )
            print('LOG:', log)
            print(rec_hex(log['data']))
        self.chain.head_state.log_listeners.append(_listener)


        self.verifier_contract.reveal(
            fakecommitBlockNumber, fakecommitBlockIndex, DAPP_ADDRESS, UNLOCK_AMOUNT, b'',  rec_bin(witness), OURGASPRICE, OURGASLIMIT,
            sender=PKEY_A,
            to=self.verifier_contract.address,
            value=1009,
            gasprice=OURGASPRICE,
            startgas=OURGASLIMIT
        )
        self.chain.mine(1)

        #revealBlockNumber, revealBlockIndex = self.chain.chain.get_tx_position()
        #print("reveal block number {} and reveal block index {}".format(revealBlockNumber, revealBlockIndex))

        def aux(x):
            return x.to_bytes(32, byteorder='big')

        computedfakecommit = (rec_bin(ADDR_A) + self.verifier_contract.address + aux(UNLOCK_AMOUNT) + b'' + rec_bin(witness) + aux(OURGASPRICE) + aux(OURGASLIMIT))
        sessionID = sha3_256(computedfakecommit)
        print(rec_hex(sessionID))

        revealTestSession = self.verifier_contract.getSession(rec_bin("000000000000000000000000000000000000000000000000128dfa6a90b28000"))
        print(revealTestSession)



if __name__ == "__main__":
    unittest.main()
