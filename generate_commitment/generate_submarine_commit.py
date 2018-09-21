
from ethereum.transactions import Transaction

import random
import logging
import sys
import rlp

from ethereum.utils import decode_hex, normalize_address,  encode_hex, bytearray_to_int, sha3_256  # sha3_256 is same as Keccak256
from ethereum.exceptions import InvalidTransaction
from py_ecc.secp256k1 import N as secp256k1n


# Logging
log = logging.getLogger('SubmarineCommit')
level = logging.getLevelName('INFO')
log.setLevel(level)
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)


unlockFunctionSelector = decode_hex("ec9b5b3a")

'''
Test Account
'''
testPassword = "password123"
testKeystore = '{"version":3,"id":"e61c089a-270d-489c-b656-2c9c091edd12","address":"aac9c2b37d61099e72070f4fd1dafefd4852fbfd","Crypto":{"ciphertext":"67ce3a0b673f37e68f67a9a9b0c5def1877cbf3204927e18ac6de1bef1e3b8ad","cipherparams":{"iv":"2b09235abb0f6b7ce3157b58860cce38"},"cipher":"aes-128-ctr","kdf":"scrypt","kdfparams":{"dklen":32,"salt":"36eda2b0ad220c988b9a1db9b7c3524818b4408ca91668ed7dc49e33538d079e","n":8192,"r":8,"p":1},"mac":"043a427c5659141aa34c56e61646cb53e4e80401f96e243d89aef51a4a3ed7d4"}}'
testPriv = "a12bba0934d2cc5bafd214656fc9a11963074cb045c462b5dffae4168599c5c3"
testAccount = "0xAAc9C2B37D61099e72070f4Fd1DAFeFd4852fBfd"


def generateRS(addressA , addressC , sendAmount , dappData, gasPrice, gasLimit):
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
    commit, randw = generateCommit(addressA, addressC, sendAmount, dappData, gasPrice, gasLimit)

    R = bytearray_to_int(sha3_256(commit + bytes(1)))
    S = bytearray_to_int(sha3_256(commit + bytes(0)))

    if (0 < R < secp256k1n) & (0 < S < (secp256k1n/2)):
        return commit, randw, R, S
    else:
        log.info("Invalid R,S. Regenerating the hashes...")
        return generateRS(addressA, addressC, sendAmount, dappData, gasPrice, gasLimit)


def generateCommit(addressA , addressC , sendAmount , dappData, gasPrice, gasLimit):
    '''
    Internal Function
    Generates a random number (w for witness) and calculates the Keccak256 hash of (AddressA | Address C | sendAmount | data | w)
    Called from generateRS()
    :param addressA: Sender's Address
    :param addressC: Smart Contracts Address
    :param sendAmount: Send Amount (in Wei)
    :param data: Data for smart contract
    :return:

    FullCommit : Keccak256 (sha3_256) hash of full commit (AddressA | Address C | sendAmount | data | w)
    w: Random number w for witness

    '''
    rand_gen = random.SystemRandom()  # This uses os.urandom() . Secure enough?
    w = bytes([rand_gen.randrange(256) for _ in range(256//8)])  # random bytes

    def aux(x):
        return x.to_bytes(32, byteorder='big')

    fullCommit = (addressA + addressC + aux(sendAmount) + dappData + w + aux(gasPrice) + aux(gasLimit))

    return sha3_256(fullCommit), w


def generateAddressB(addressA, addressC, sendAmount, dappData, gasPrice, gasLimit, nonce=0, V=27):
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

    commit, randw, R, S = generateRS(addressA, addressC, sendAmount, dappData, gasPrice, gasLimit)

    submarineData =  unlockFunctionSelector + commit
   # assert(len(commit) == 36)
    tx = Transaction(nonce, gasPrice, gasLimit, addressC, sendAmount, data=submarineData, v=V, r=R, s=S)

    try:
        log.info(tx.to_dict())
        addressB = tx.to_dict().get("sender")
        return tx, addressB, commit, randw

    except (ValueError, InvalidTransaction) as e:
        if isinstance(e, ValueError) and "VRS" not in str(e):
            raise
        log.info("Address no good (%s), retrying" % e)
        return generateAddressB(addressA, addressC, sendAmount, dappData, gasPrice, gasLimit, nonce, V)




def printRemix(fromAddress, tx, w):
    # sender registry unlockamt data wit gasprice gaslimit
    sender = "0x" + encode_hex(fromAddress)#tx.to_dict().get("sender")
    registry = tx.to_dict().get("to")
    unlockamt = tx.to_dict().get("value")
    data = '0x' + encode_hex(b'')
    wit = "0x"+w
    gasprice = tx.to_dict().get("gasprice")
    gaslimit = tx.to_dict().get("startgas")
    print('"{}","{}",{},"{}","{}",{},{}'.format(sender, registry, unlockamt, data, wit, gasprice, gaslimit))




def generateAddressBexport(fromAddress, toAddress, sendAmount, dappData, gasPrice, gasLimit):
    '''
    Exportable generateAddressB

    returns all the values in Hex

    :return: all in hex


    addressB, commit, w (witness), tx_hex

    addressB: AddressB
    commit: SessionId
    w (witness):
    tx_hex : B -> C (txUnlock) transactions


    '''
    tx, addressB, commit, randw = generateAddressB(fromAddress, toAddress, sendAmount, dappData, gasPrice, gasLimit)

    return addressB, encode_hex(commit),encode_hex(randw), encode_hex(rlp.encode(tx))


def main():

    #init test variables
    gasPrice = 50000000000  # 50 gwei
    gasLimit = 3712394  # startgas
    toAddress = normalize_address("0x7AEB1Fd3A42731c4Ae80870044C992eb689fb2Fe")
    fromAddress = normalize_address("0x94146296881b3322838cFF5f2d50fdde841928D8")
    sendAmount = 123000000000000
    dappData = b""

    tx, addressB, commit, randw = generateAddressB(fromAddress, toAddress, sendAmount, dappData, gasPrice, gasLimit)

    # print("-"* 35)
    # printRemix(fromAddress, tx, encode_hex(randw))
    print("-"* 35)

    print("AddressB: %s" % addressB)  # addressB also can retreived using tx.to_dict().get("sender")
    print("commit: %s" % encode_hex(commit))
    print("witness (w): %s" % encode_hex(randw))
    # print("Reveal Transation (json): %s" % tx.to_dict())
    print("Reveal Transaction (hex): %s" % encode_hex(rlp.encode(tx)))
    #TODO: broadcast using web3.py?  for now broadcast hex using https://ropsten.etherscan.io/pushTx



if __name__ == "__main__": #make this file importable
    main()
