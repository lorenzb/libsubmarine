from ethereum.transactions import Transaction

import random
import logging
import sys
import rlp
import argparse
import os

from ethereum.utils import check_checksum, decode_hex, normalize_address, encode_hex, bytearray_to_int, sha3_256  # sha3_256 is same as Keccak256
from ethereum.exceptions import InvalidTransaction
from py_ecc.secp256k1 import N as secp256k1n

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'test'))
from test_utils import rec_bin

# Logging
log = logging.getLogger('SubmarineCommitGenerator')
LOGFORMAT = "%(levelname)s:%(filename)s:%(lineno)s:%(funcName)s(): %(message)s"
log.setLevel(logging.getLevelName('INFO'))
logHandler = logging.StreamHandler(stream=sys.stdout)
logHandler.setFormatter(logging.Formatter(LOGFORMAT))
log.addHandler(logHandler)

unlockFunctionSelector = decode_hex("ec9b5b3a")


def _generateRS(addressA, addressC, sendAmount, dappData, gasPrice, gasLimit):
    '''
    Internal Function
    Calculates R & S in a way that

    0 < R < secp256k1n
    0 < S < secp256k1n / 2

    if not recursively runs itself til satisfied \_:)_/

    :param addressA: Sender's Address
    :param addressC: Smart Contracts Address
    :param sendAmount: Send Amount (in Wei)
    :param data: Data for smart contract
    :return:

    commit, randw, R, S

    '''
    #TODO: validate AddressA and AddressC
    commit, randw = _generateCommit(addressA, addressC, sendAmount, dappData,
                                    gasPrice, gasLimit)

    R = bytearray_to_int(sha3_256(commit + bytes(1)))
    S = bytearray_to_int(sha3_256(commit + bytes(0)))

    if (0 < R < secp256k1n) & (0 < S < (secp256k1n / 2)):
        return commit, randw, R, S
    else:
        log.info("Invalid R,S. Regenerating the hashes...")
        return _generateRS(addressA, addressC, sendAmount, dappData, gasPrice,
                           gasLimit)


def _generateCommit(addressA, addressC, sendAmount, dappData, gasPrice,
                    gasLimit):
    '''
    Internal Function
    Generates a random number (w for witness) and calculates the Keccak256 hash of (AddressA | Address C | sendAmount | data | w)
    Called from _generateRS()
    :param addressA: Sender's Address
    :param addressC: Smart Contracts Address
    :param sendAmount: Send Amount (in Wei)
    :param data: Data for smart contract
    :return:

    FullCommit : Keccak256 (sha3_256) hash of full commit (AddressA | Address C | sendAmount | data | w)
    w: Random number w for witness

    '''
    rand_gen = random.SystemRandom()  # This uses os.urandom() . Secure enough?
    w = bytes([rand_gen.randrange(256)
               for _ in range(256 // 8)])  # random bytes

    def aux(x):
        return x.to_bytes(32, byteorder='big')

    fullCommit = (addressA + addressC + aux(sendAmount) + dappData + w +
                  aux(gasPrice) + aux(gasLimit))

    return sha3_256(fullCommit), w


def _generateAddressBInternal(addressA,
                              addressC,
                              sendAmount,
                              dappData,
                              gasPrice,
                              gasLimit,
                              nonce=0,
                              V=27):
    '''
    Main function

    Generates the Reveal Transaction, commit and generates addressB

    :param addressA: Sender's Address
    :param addressC: Smart Contracts Address
    :param sendAmount: Send Amount (in Wei)
    :param data: Data for smart contract C
    :param gasPrice: Gas Price
    :param gasLimit: Gas Limit
    :param nonce: default 0
    :param V: default 27 --> no replay protection.
    :return:

    tx obj, addressB, commit, randw

    tx object --> reveal transaction (addressB to addressC), includes commit in data
    addressB : Commit transaction receiver
    commit : commit message
    randw: w (witness) random number
    '''

    commit, randw, R, S = _generateRS(addressA, addressC, sendAmount, dappData,
                                      gasPrice, gasLimit)

    submarineData = unlockFunctionSelector + commit
    # assert(len(commit) == 36)
    tx = Transaction(
        nonce,
        gasPrice,
        gasLimit,
        addressC,
        sendAmount,
        data=submarineData,
        v=V,
        r=R,
        s=S)

    try:
        log.info(tx.to_dict())
        addressB = tx.to_dict().get("sender")
        return tx, addressB, commit, randw

    except InvalidTransaction as e:
        log.info("Address no good (%s), retrying" % e)
        return _generateAddressBInternal(addressA, addressC, sendAmount,
                                         dappData, gasPrice, gasLimit, nonce,
                                         V)


def printRemix(fromAddress, tx, w):
    # sender registry unlockamt data wit gasprice gaslimit
    sender = "0x" + encode_hex(fromAddress)  #tx.to_dict().get("sender")
    registry = tx.to_dict().get("to")
    unlockamt = tx.to_dict().get("value")
    data = '0x' + encode_hex(b'')
    wit = "0x" + w
    gasprice = tx.to_dict().get("gasprice")
    gaslimit = tx.to_dict().get("startgas")
    print('"{}","{}",{},"{}","{}",{},{}'.format(sender, registry, unlockamt,
                                                data, wit, gasprice, gaslimit))


def generateCommitAddress(fromAddress, toAddress, sendAmount, dappData,
                          gasPrice, gasLimit):
    '''
    Exportable _generateAddressBInternal

    returns all the values in Hex

    :return: all in hex


    addressB, commit, w (witness), tx_hex

    addressB: AddressB
    commit: SessionId
    w (witness):
    tx_hex : B -> C (txUnlock) transactions


    '''
    tx, addressB, commit, randw = _generateAddressBInternal(
        fromAddress, toAddress, sendAmount, dappData, gasPrice, gasLimit)

    return addressB, encode_hex(commit), encode_hex(randw), encode_hex(
        rlp.encode(tx))


def _get_args():
    '''
    Internal function. Creates an argparser for the main method to use.

    :return: parser: argparse object for parsing program arguments.
    '''
    parser = argparse.ArgumentParser(
        description=
        "Tool to create a TXUnlock transaction for submarine commitments",
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument(
        '-t',
        '--target-address',
        required=True,
        type=str,
        default="",
        help="Target end address to send the money to in the end. "
        "Probably this should be the LibSubmarine contract address.")
    parser.add_argument(
        '-f',
        '--from-address',
        required=True,
        type=str,
        default="",
        help=
        "From address that starts the submarine process. This should be an address "
        "that you control.")
    parser.add_argument(
        '-a',
        '--amount',
        required=True,
        type=int,
        default=0,
        help=
        "Amount of money you are sending through the submarine transaction in Wei."
    )
    parser.add_argument(
        '-d',
        '--dapp-data',
        required=False,
        type=str,
        default="",
        help=
        "Optional DApp Data field. Pass any additional function parameters here "
        "as needed. Data will be interpreted as a hex string, e.g. 0x414243... "
        "In most cases this should be left blank.")
    parser.add_argument(
        '-p',
        '--gas-price',
        required=False,
        type=int,
        default=50000000000,
        help="Optional Gas price for TX Unlock transaction. Default is 50 GWei"
    )
    parser.add_argument(
        '-l',
        '--gas-limit',
        required=False,
        type=int,
        default=3712394,
        help=
        "Optional Gas limit for TX Unlock transaction. Default is 3.7 million gas.")
    return parser.parse_args()


def main():
    '''
    Main method. Runs the program if it is used standalone (rather than as an exported library).
    '''

    parser = _get_args()

    if len(parser.target_address) != 42:
        log.error(
            "Target Address length does not appear to match the correct length of an Ethereum address"
        )
        sys.exit(1)
    if len(parser.from_address) != 42:
        log.error(
            "From Address length does not appear to match the correct length of an Ethereum address"
        )
        sys.exit(1)
    if parser.target_address[0:2] != "0x":
        log.error(
            "Target address not in expected format, expected address to start with 0x"
        )
        sys.exit(1)
    if parser.from_address[0:2] != "0x":
        log.error(
            "From address not in expected format, expected address to start with 0x"
        )
        sys.exit(1)

    if not check_checksum(parser.target_address):
        log.error(
            "Target address is not correctly encoded using EIP-55 {}".format(
                parser.target_address))
        sys.exit(1)
    if not check_checksum(parser.from_address):
        log.error(
            "From address is not correctly encoded using EIP-55 {}".format(
                parser.from_address))
        sys.exit(1)

    toAddress = normalize_address(parser.target_address)
    fromAddress = normalize_address(parser.from_address)
    gasPrice = parser.gas_price
    gasLimit = parser.gas_limit
    sendAmount = parser.amount
    if (parser.dapp_data):
        dappData = rec_bin(parser.dapp_data)
    else:
        dappData = b""

    tx, addressB, commit, randw = _generateAddressBInternal(
        fromAddress, toAddress, sendAmount, dappData, gasPrice, gasLimit)

    # print("-"* 35)
    # printRemix(fromAddress, tx, encode_hex(randw))
    print("-" * 35)

    print("AddressB: {}".format(addressB)
          )  # addressB also can retrieved using tx.to_dict().get("sender")
    print("commit: {}".format(encode_hex(commit)))
    print("witness (w): {}".format(encode_hex(randw)))
    # print("Reveal Transation (json): {}".format(tx.to_dict()))
    print("Reveal Transaction (hex): {}".format(encode_hex(rlp.encode(tx))))
    print(
        "You can use the reveal transaction hex to broadcast with any service you like, e.g.: https://ropsten.etherscan.io/pushTx"
    )


if __name__ == "__main__":
    main()
