# LibSubmarine Workflow

### Order

|Order of Transactions | Order of Generation Client-Side|
| --- | --- |
| 1. Commit (`A` --> `B`) | 1. Unlock (`B` --> `C`) |
| 2. Reveal (`A` --> `C`) | 2. Commit (`A` --> `B`) |
| 3. Unlock (`B` --> `C`) | 3. Reveal (`A` --> `C`) |
| 4. Finalize (`A` --> `D`) | 4. Finalize (`A` --> `D`) |


### Generate `TXunlock`

`A` chooses a (e.g. 256-bit) witness `w` uniformly at random and computes
`commit = Keccak256(addr(A) | addr(C) | $value | d | w | gasPrice | gasLimit)`.

`commit` also used as `sessionId` in the other
`A` then generates a transaction `TXunlock` committing to data `d`.

```javascript
to: C
value: $value
nonce: 0
data: commit
gasPrice: $gp
gasLimit: gl
r: Keccak256(commit | 0)
s: Keccak256(commit | 1)
v: 27 // This makes TXunlock replayable across chains ¯\_(ツ)_/¯
```

Note that `TXunlock` is replay-able across chains because we use the pre-EIP155 `v = 27`. We don't really care because `B` needs to be funded explicitly anyways, greatly reducing the potential for replay attacks.

`A` then computes `ECRECOVER(Txunlock)` which outputs either `B` or ⊥ (Invalid signature). If the output is ⊥, `A` picks a new `w` and repeats this step. Otherwise, `A` now knows `B`.

Done in [generate_commitment](/generate_commitment/README.md)

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

# LibSubmarine.sol
LibSubmarine Registry in `contract/LibSubmarine.sol`.

### Constructor
```javascript
constructor(uint256 _revealDeposit, uint256 _challengePeriod)
```
- **uint256 revealDeposit** : Minimum deposit require for Reveal(). This is to cover costs for challenge() //Cheat/Fraud Proof.

- **uint256 challengePeriod** : Number of blocks to wait for possible challenge. Sessions would not be finalized in the challenge period.

## Reveal
Reveal the commit transaction details
```javascript
reveal(uint256 _commitBlock, uint256 _commitIndex, address _dappAddress, uint256 _unlockAmount,\
   bytes _data, bytes32 _witness, uint256 _gasPrice, uint256 _gasLimit)
```
- **uint256 _commitBlock**: The block number transaction ()`A` -> `B`) was confirmed in
- **uint256 _commitIndex**: The index of the transaction within the block (a.k.a *Position*)
- **address _dappAddress**: The address of the DApp using the libsubmarine registry. The funds will be transferred to this address after finalization
- **uint256 _unlockAmount**: unlockAmount included in the unlock transaction `TXunlock` (`B` -> `C`)
- **bytes _data**: DApp specific Data included in the `TXunlock`
- **bytes32 _witness**: Random bytes (witness) included in `TXunlock`
- **uint256 _gasPrice**: Gas Price specified for `TXunlock`
- **uint256 _gasLimit**: gasLimit specified `TXunlock`


## Unlock
Receives the `TXunlock` (`B` -> `C`) and changes the state of the session accordingly

```javascript
unlock(bytes32 _sessionId)
```
- **bytes32 _sessionId**: sessionId which is the commit message: `sessionId = Keccak256(addr(A) | addr(C) | $value | d | w | gasPrice | gasLimit)`


## Finalize
Finalizes the state of the session(sessionId) and releases the funds

```javascript
finalize(bytes32 _sessionId)
```
- **bytes32 _sessionId**: sessionId

#### isFinalizable
View function to show if the state is finalizable.
> isFinalizable(bytes32 _sessionId)

Returns:
```javascript
(true, unlockAmount, DAppData)

OR

(false, 0, "")
```

## Challenge
Anyone can challenge a reveal to prove `A` cheated and the commit transaction has not happened they way it was revealed.

If proven right (`A` has cheated), unLockAmount will be transferred to the user reporting the fraud.

```javascript
challenge(bytes32 _sessionId, bytes _proofBlob, bytes _unsignedCommitTx)
```
- **bytes32 _sessionId**: sessionId
- **bytes _proofBlob**: //TODO
- **bytes _unsignedCommitTx**: // TODO



