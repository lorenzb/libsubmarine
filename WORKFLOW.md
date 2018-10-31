# LibSubmarine Workflow

Naturally, the user experience for an Ethereum DApp will vary depending on the functionality provided by DApp in question. Regardless, in this document we attempt to explain the common workflow elements that most LibSubmarine clients will share.

### Order

- `A` User
- `B` Commit Address (No Private key)
- `C` Libsubmarine

|Order of Transactions | Order of Generation Client-Side|
| --- | --- |
| 1. Commit (`A` --> `B`) | 1. Unlock (`B` --> `C`) |
| 2. Reveal (`A` --> `C`) | 2. Commit (`A` --> `B`) |
| 3. Unlock (`B` --> `C`) | 3. Reveal (`A` --> `C`) |

All LibSubmarine conforming clients will have at minimum the 3 transactions above broadcast to the network as a part of their DApp workflow. Many may want keep track of the `commitTxBlockNumber` and the `commitTxIndex` to keep track of commit transaction order and/or add a 4th transaction that waits and queries the `revealedAndUnlocked(submarineId)` function to ensure that business logic is only executed after the full submarine send is done.

### Generate `TxUnlock`

The very first thing that will happen during a submarine send is that the end-user (e.g. JavaScript code running on the DApp's website, or perhaps a native or mobile application) will first generate a specially formatted "TxUnlock" transaction. This unlock transaction "unlocks" committed funds from the commit address and sends those to your DApp. It also calls the `unlock(submarineId)` function on LibSubmarine/your DApp. We provide the `generate_commit.py` program that generates this TxUnlock transaction, and also informs you of what your associated Commit address will be. This program can be imported as a python module (you can refer to the unit tests to see how they do this) or run on the command line (see `generate_commit.py -h` for help). What this program does is described below:

The end-user `A` chooses a (e.g. 256-bit) witness `w` uniformly at random, and computes
`commit = Keccak256(addr(End User) | addr(DApp Contract/LibSubmarine) | value | optionalDAppData | w | gasPrice | gasLimit)`.

Where `value` is the amount of Wei committed to in this Submarine Send workflow, `optionalDAppData` is any arbitrary data you would like to embed inside the Submarine Send, and gasPrice and gasLimit are the gas price and limit you will be using in the unlock transaction.

This computed `commit` is then used as the `submarineId` for the LibSubmarine contract.

Next, using this `commit` or `submarineId`, `A` then generates the following transaction `TxUnlock` which calls `unlock(submarineId)` on LibSubmarine.

```javascript
to: C
value: $value
nonce: 0
data: commit
gasPrice: $gp
gasLimit: $gl
r: Keccak256(commit | 1)
s: Keccak256(commit | 0)
v: 27 // This makes TxUnlock replayable across chains ¯\_(ツ)_/¯
```

Note that `TxUnlock` is replay-able across chains because we use the pre-EIP155 `v = 27`. We don't really care because the commit address (let's call this `B`) needs to be funded explicitly anyways, greatly reducing the potential for replay attacks.

`A` then computes `ECRECOVER(TxUnlock)` which outputs either `B` or ⊥ (Invalid signature). If the output is ⊥, `A` picks a new `w` and repeats this step. Otherwise, `A` now knows `B` - the commit address.

This is all done for you in generate_commitment.py.

### Commit

The end-user `A` generates and broadcasts `TxCommit`, which is a simple send transaction of Ether from `A` to `B` of `$value + $unlockgas`, where `$unlockgas = $gp * gl`.

From this, let `commitTxBlockNumber` be the block in which `TxCommit` was mined. Let `commitTxIndex` be the index position inside the block at which `TxCommit` was included.

### Reveal

Next, `A` calls the `reveal( _commitTxBlockNumber, _embeddedDAppData, _witness, _rlpUnlockTxUnsigned, _proofBlob)` function on the DApp/LibSubmarine contract `C`. Let's call this transaction `TxReveal`. These function parameters provide information to the DApp `C` about the commit and unlock transactions. `A` provides the commit block number, the optional DApp data, the witness, the full unlock transaction in its unsigned form RLP encoded, and a merkle-patricia proof blob (see the EthProve repo / refer to the unit tests for documentation and examples around the structure of this blob). 

`C` recomputes the `submarineId` from the provided information and is able to verify the validity of the Merkle Proof and TxUnlock / original commit address of the transaction on chain. At this point, LibSubmarine will call the onSubmarineReveal() function from the DApp, which allows the DApp to record and perform any application specific business logic at reveal-time.

### Unlock

`A` (or any party) broadcasts `TxUnlock`. Upon receiving `TxUnlock`, `C` will set the state of the contract so revealedAndUnlocked() returns true, assuming that `A` performed a valid reveal.

`C` can associate `TxUnlock` with `A` thanks to `commit` data contained in it (a.k.a `submarineId`).

The unlock function does no validation or logic checking whatsoever. This is to keep the gas costs of the unlock transaction low, and to hopefully ensure that the unlock transaction fails as little as possible so funds do not become stuck in the commit address with no way out.

### After

After both the Reveal and Unlock transactions have been executed, business logic for the application can query revealedAndUnlocked() and the getter functions (getSubmarineAmount, getSubmarineCommitBlockNumber, getSubmarineCommitTxIndex) in order to perform whatever actions the DApp would like to do.

Note that the order between the Unlock and Reveal transaction can in practice occur in any order, since network monitoring parties will have all of the information provided in the rlpUnlockTx parameter to the reveal to broadcast the unlock as well, and miners can put transactions in arbitrary orders in a block. LibSubmarine has purposefully been architected to be order agnostic between the reveal and unlock. DApps should check the revealedAndUnlocked() function and only use this function to determine whether a submarine send has successfully completed.
