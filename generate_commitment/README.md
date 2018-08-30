# Generate Submarine Commitment

Generates `TXunlock` transaction and Address `B`.


```
     TXcommit (1)

A +-------------------> B

+                       +
|                       | TXunlock (3)
|                       v
|
+---------------------> C

    TXreveal (2)
```

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


### Python Implementation
generate_submarine_commit.py

> tx, addressB, commit, randw = generateAddressB(addressA, addressC, sendAmount, data, gasPrice, gasLimit)

`generateAddressB` Returns:
```
tx (obj) --> reveal transaction (addressB to addressC), includes unlock(commit) in data field
addressB : Commit transaction receiver
commit : commit message
randw: w (witness) random bytes
```

Note: `unlockFunctionSelector = decode_hex("ec9b5b3a")` is added to the final value of `d` to call proper function in `C`

Example:
```javascript
AddressB: 0x5338d846d05448d44138cd19982bf3cb0c87a756
commit: 79ae69adf744d9ccc88d487d7bb7be0f948c2902b016abb5b34bec2b554c4561
witness (w): f84bbef61a49dc60088b877a64e8fc7b6e62a787a745563d07849461db4bd9ea
Reveal Transaction (hex): f88f80850ba43b74008338a58a947aeb1fd3a42731c4ae80870044c992eb689fb2fe866fde2b4eb000a4ec9b5b3a79ae69adf744d9ccc88d487d7bb7be0f948c2902b016abb5b34bec2b554c45611ba0a70e779dca3a47d95401253d02a82ced651a1b934ec88e5c8736f7dd6ee4e374a015aa9000feec7034f94ad3bba2234310015a82e6d11acf1a0f900129a001e5b4
```
Sample Commit Transaction on Ropsten: [0x8345f014dc005a207f0eece7246d83b10b4cabe1f63cfe8dde3d5e82a21fd290](https://ropsten.etherscan.io/tx/0x8345f014dc005a207f0eece7246d83b10b4cabe1f63cfe8dde3d5e82a21fd290)

