package main

import (
	"fmt"

	"github.com/ethereum/go-ethereum/core/types"

	//"github.com/ethereum/go-ethereum/accounts/keystore"
	//"github.com/ethereum/go-ethereum/ethclient"
	//"github.com/ethereum/go-ethereum/params"
	"math/big"
	"sync/atomic"

	"github.com/davecgh/go-spew/spew"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"crypto/rand"
	"encoding/json"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto/sha3"
	"github.com/ethereum/go-ethereum/rlp"
)

//Network variables
//var netId = big.NewInt(3) //ropsten = 3 , mainnet = 1
//var homestead = false     //testnet = false, mainnet = true

var (
	secp256k1N, _  = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	secp256k1halfN = new(big.Int).Div(secp256k1N, big.NewInt(2))
)

type Transaction struct {
	// Transaction object

	data txdata
	// caches
	hash atomic.Value
	size atomic.Value
	from atomic.Value
}

type txdata struct {
	//txdata object. includes Transaction details

	AccountNonce uint64         `json:"nonce"    gencodec:"required"`
	Price        *big.Int       `json:"gasPrice" gencodec:"required"`
	GasLimit     uint64         `json:"gas"      gencodec:"required"`
	Recipient    common.Address `json:"to"       rlp:"nil"` // nil means contract creation
	Amount       *big.Int       `json:"value"    gencodec:"required"`
	Payload      []byte         `json:"input"    gencodec:"required"`

	// Signature values
	V *big.Int `json:"v" gencodec:"required"`
	R *big.Int `json:"r" gencodec:"required"`
	S *big.Int `json:"s" gencodec:"required"`

	// This is only used when marshaling to JSON.
	Hash *common.Hash `json:"hash" rlp:"-"`
}

func generateCommit(addressA common.Address, addressC common.Address, value *big.Int, data []byte) ([]byte, []byte) {
	/*
		Generates commit value:
			Address A	common.Address	# The originating address, sender
			Address C	common.Address	# Final destination, Receiving Smart Contract
			value 		big.Int			#Transaction $value
			data		[]byte			# Data to be included in the payload, e.g. smart contract function calls, arguments, etc
	*/

	//TODO: error handling?
	w := make([]byte, 32)
	rand.Read(w) //crypto.rand, secure random

	fullCommit := append(addressA.Bytes(), addressC.Bytes()...) // , value.Bytes(), data, w ...[]byte)
	fullCommit = append(fullCommit, value.Bytes()...)           //https://golang.org/ref/spec#Passing_arguments_to_..._parameters
	fullCommit = append(fullCommit, data...)
	fullCommit = append(fullCommit, w...) //TODO: make this concatenation smarter!

	return crypto.Keccak256(fullCommit), w //TODO: should this be bytes or Keccak256Hash ?
}



func generateRS(fromAddress common.Address, toAddress common.Address, sendAmount *big.Int, data []byte) ([]byte, []byte) {
	/*
	Generate valid R and S by regenerating the commit (random W) recursively ¯\_(ツ)_/¯
	returns commit value and w (witness w)

	 0 < R < secp256k1N and 0 < S < secp256k1halfN

	 */
	commit, randW := generateCommit(fromAddress, toAddress, sendAmount, data)

	R := new(big.Int).SetBytes(crypto.Keccak256(append(commit, 0x0)))
	S := new(big.Int).SetBytes(crypto.Keccak256(append(commit, 0x1)))

	// 0 < R < secp256k1N and 0 < S < secp256k1halfN
	if (big.NewInt(0).Cmp(R) == -1 && R.Cmp(secp256k1N) == -1) && (big.NewInt(0).Cmp(S) == -1 && S.Cmp(secp256k1halfN) == -1) {
		return commit, randW

	} else {
		fmt.Printf("Possibly invalid R & S values, trying again...")
		return generateRS(fromAddress, toAddress, sendAmount, data)
	}

}

func generateAddressB(tx *Transaction, fromAddress common.Address, toAddress common.Address, sendAmount *big.Int, data []byte) (types.Transaction, common.Address, []byte) {
	/*
	Generates AddressB and reveal transaction
	Makes sure the addressB is a valid address (again recursively ¯\_(ツ)_/¯)

	returns Reveal Transaction, AddressB, W (witness w).

	 */
	commit, randW := generateRS(fromAddress, toAddress, sendAmount, data)
	tx.data.Payload = commit

	tx.data.R = new(big.Int).SetBytes(crypto.Keccak256(append(commit, 0x0)))
	tx.data.S = new(big.Int).SetBytes(crypto.Keccak256(append(commit, 0x1)))

	//In order to use chainId (protected V for replay protection) use this code. and also change FrontierSigner to EIP155Signer
	//var big2 = big.NewInt(2)
	//var big35 = big.NewInt(35)
	//tx.data.V = new(big.Int).Add(new(big.Int).Mul(netId, big2), big35)

	var big27 = big.NewInt(27)
	tx.data.V = big27

	//stupid way to do less copy pasting with more copy pasting
	newTx := types.Transaction{}
	marshaledTx, _ := tx.MarshalJSON()
	newTx.UnmarshalJSON(marshaledTx)

	frontierSigner := types.FrontierSigner{}

	address, err := frontierSigner.Sender(&newTx)
	if err == nil {
		return newTx, address, randW
	} else {
		fmt.Println("DEBUG generated failed address, retrying...") //DEBUG
		return generateAddressB(tx, fromAddress, toAddress, sendAmount, data)
	}
}


func main() {

	// test value assignments
	nonce := uint64(0) // nonce = 0 . only 1 outgoing transaction
	sendAmount := big.NewInt(123000000000000) //0.000123
	gasLimit := uint64(10000000)
	gasPrice := big.NewInt(50000)
	toAddress := common.HexToAddress(`0xc2285f89B5b228E9a51f2B80dd0712F0ac071C9e`)
	fromAddress := common.HexToAddress(`0xc2285f89B5b228E9a51f2B80dd0712F0ac071C9e`)

	//tx := newTransaction(nonce, toAddress, sendAmount, gasLimit, gasPrice, nil)
	tx := newTransaction(nonce, toAddress, sendAmount, gasLimit, gasPrice, nil)

	newTx, address, _ := generateAddressB(&tx, fromAddress, toAddress, sendAmount, nil)

	spew.Dump(newTx)

	spew.Dump(address)

	revealTx, _ := newTx.MarshalJSON()

	fmt.Println("--------------------------------------------------")
	fmt.Println("Commit AddressB: ", address.String())
	fmt.Println("Reveal Transaction: ", common.Bytes2Hex(revealTx))

	fmt.Println("Reveal Total (Cost): ", newTx.Cost())
	fmt.Println("Reveal Value: ", newTx.Value())
	fmt.Println("Reveal To: ", newTx.To().Hex())
	fmt.Println("Reveal Gas: ", newTx.Gas())



}

// Copied & slightly modified from go-ethereum/core/types/transaction.go
func newTransaction(nonce uint64, to common.Address, amount *big.Int, gasLimit uint64, gasPrice *big.Int, data []byte) Transaction {
	if len(data) > 0 {
		data = common.CopyBytes(data)
	}
	d := txdata{
		AccountNonce: nonce,
		Recipient:    to,
		Payload:      data,
		Amount:       new(big.Int),
		GasLimit:     gasLimit,
		Price:        new(big.Int),
		V:            new(big.Int),
		R:            new(big.Int),
		S:            new(big.Int),
	}
	if amount != nil {
		d.Amount.Set(amount)
	}
	if gasPrice != nil {
		d.Price.Set(gasPrice)
	}

	return Transaction{data: d}
}

// These has been copied from transaction.go to make it possible to export local Transaction object to types.Transaction so
// we won't copy and paste crypto codes from go-ethereum
// MarshalJSON encodes the web3 RPC transaction format.
func (tx *Transaction) MarshalJSON() ([]byte, error) {
	hash := tx.Hash()
	data := tx.data
	data.Hash = &hash
	return data.MarshalJSON()
}

func (t txdata) MarshalJSON() ([]byte, error) {
	type txdata struct {
		AccountNonce hexutil.Uint64 `json:"nonce"    gencodec:"required"`
		Price        *hexutil.Big   `json:"gasPrice" gencodec:"required"`
		GasLimit     hexutil.Uint64 `json:"gas"      gencodec:"required"`
		Recipient    common.Address `json:"to"       rlp:"nil"`
		Amount       *hexutil.Big   `json:"value"    gencodec:"required"`
		Payload      hexutil.Bytes  `json:"input"    gencodec:"required"`
		V            *hexutil.Big   `json:"v" gencodec:"required"`
		R            *hexutil.Big   `json:"r" gencodec:"required"`
		S            *hexutil.Big   `json:"s" gencodec:"required"`
		Hash         *common.Hash   `json:"hash" rlp:"-"`
	}
	var enc txdata
	enc.AccountNonce = hexutil.Uint64(t.AccountNonce)
	enc.Price = (*hexutil.Big)(t.Price)
	enc.GasLimit = hexutil.Uint64(t.GasLimit)
	enc.Recipient = t.Recipient
	enc.Amount = (*hexutil.Big)(t.Amount)
	enc.Payload = t.Payload
	enc.V = (*hexutil.Big)(t.V)
	enc.R = (*hexutil.Big)(t.R)
	enc.S = (*hexutil.Big)(t.S)
	enc.Hash = t.Hash
	return json.Marshal(&enc)
}

// Hash hashes the RLP encoding of tx.
// It uniquely identifies the transaction.
func (tx *Transaction) Hash() common.Hash {
	if hash := tx.hash.Load(); hash != nil {
		return hash.(common.Hash)
	}
	v := rlpHash(tx)
	tx.hash.Store(v)
	return v
}



func rlpHash(x interface{}) (h common.Hash) {
	hw := sha3.NewKeccak256()
	rlp.Encode(hw, x)
	hw.Sum(h[:0])
	return h
}
