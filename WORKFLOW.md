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

### Generate `TXunlock`

The very first thing that will happen during a submarine send is that the end-user (e.g. JavaScript code running on the DApp's website, or perhaps a native or mobile application) will first generate a specially formatted "TxUnlock" transaction. This unlock transaction "unlocks" committed funds from the commit address and sends those to your DApp. It also calls the `unlock(submarineId)` function on LibSubmarine/your DApp. We provide the `generate_commit.py` program that generates this TxUnlock transaction, and also informs you of what your associated Commit address will be. This program can be imported as a python module (you can refer to the unit tests to see how they do this) or run on the command line (see `generate_commit.py -h` for help). What this program does is described below:

The end-user `A` chooses a (e.g. 256-bit) witness `w` uniformly at random, and computes
`commit = Keccak256(addr(End User) | addr(DApp Contract/LibSubmarine) | value | optionalDAppData | w | gasPrice | gasLimit)`.

Where `value` is the amount of Wei committed to in this Submarine Send workflow, `optionalDAppData` is any arbitrary data you would like to embed inside the Submarine Send, and gasPrice and gasLimit are the gas price and limit you will be using in the unlock transaction.

This computed `commit` is then used as the `submarineId` for the LibSubmarine contract.

Next, using this `commit` or `submarineId`, `A` then generates the following transaction `TXunlock` which calls `unlock(submarineId)` on LibSubmarine.

```javascript
to: C
value: $value
nonce: 0
data: commit
gasPrice: $gp
gasLimit: $gl
r: Keccak256(commit | 1)
s: Keccak256(commit | 0)
v: 27 // This makes TXunlock replayable across chains ¯\_(ツ)_/¯
```

Note that `TXunlock` is replay-able across chains because we use the pre-EIP155 `v = 27`. We don't really care because the commit address (let's call this `B`) needs to be funded explicitly anyways, greatly reducing the potential for replay attacks.

`A` then computes `ECRECOVER(Txunlock)` which outputs either `B` or ⊥ (Invalid signature). If the output is ⊥, `A` picks a new `w` and repeats this step. Otherwise, `A` now knows `B` - the commit address.

This is all done for you in generate_commitment.py.

### Commit

`A` generates `TXcommit`, sending `$value + $unlockgas` to `B`, where `$unlockgas = $gp * gl`.
Let `commitBlock` be the block in which `TXcommit` was mined. Let `commitIndex` be the index at which `TXcommit` was included in the block.

### Reveal

`A` sends `TXreveal` to `C`, containing `$value`, `d`, `w`, `commitBlock`, and `commitIndex`.
`C` Checks for the `sessionId` and save the variables in `Sessions[sessionId]`. validates the reveal and performs application specific logic.
Reveal transaction should include a deposit `revealDeposit` which will be refunded later if `A` is honest. This is to prevent DoS and cover the Cheat/Fraud Proof gas fees.

`C` also records the blockHash of `commitBlock` to process future fraud proofs.

### Unlock

`A` (or any other party) broadcasts `TXunlock`. Upon receiving `TXunlock`, `C` will "finalize" the status of the session for `A` (assuming that `A` performed a valid reveal).

`C` can associate `TXunlock` with `A` thanks to `commit` data contained in it(a.k.a `sessionId`).

### Finalize
`A` calls the Dapp `D` to check for the finalization state. if:
- Not finalized, returns `False`
- finalized, return `True`, `unlockAmount`, `d`

-------

