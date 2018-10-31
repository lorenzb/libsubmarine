# LibSubmarine

[![Build Status](https://travis-ci.org/lorenzb/libsubmarine.svg?branch=master)](https://travis-ci.org/lorenzb/libsubmarine)

```                 _
                    | \
                     '.|
     _-   _-    _-  _-||    _-    _-  _-   _-    _-    _-
       _-    _-   - __||___    _-       _-    _-    _-
    _-   _-    _-  |   _   |       _-   _-    _-
      _-    _-    /_) (_) (_\        _-    _-       _-
              _.-'           `-._      ________       _-
        _..--`                   `-..'       .'
    _.-'  o/o                     o/o`-..__.'        ~  ~
 .-'      o|o                     o|o      `.._.  // ~  ~
 `-._     o|o                     o|o        |||<|||~  ~
     `-.__o\o                     o|o       .'-'  \\ ~  ~
LGB       `-.______________________\_...-``'.       ~  ~
                                    `._______'.
```
-------------------

**A work-in-progress implementation of better submarine sends for Ethereum.**

# Submarine Steps

- `A` User
- `B` Commit Address (No Private key)
- `C` Libsubmarine
- `D` Dapp, Application (e.g Auction, DEX, ICO, etc.)
- `MPT` Merkle-Patricia Proof of TxCommit Inclusion on-chain

```
     TxCommit (1)
A +-------------------> B
+                       +
|                       |   TxUnlock (3)
|                       | (calls unlock)
|                       v
+---------------------> C < - - - - - - - - - - - - -+ D
                         (overload) onSubmarin
    TxReveal (2)           (query) revealedAndUnlocked(submarineId)
 (call reveal+MPT)         
                                                        
```

----------
# Workflow

For a more in-depth discussion of what the workflow / steps from a user's perspective 
for a Submarine transaction looks like, refer to WORKFLOW.md

-----------
# Contract Unit Tests / Examples / Offchain Components

Install Solc ([Installation guide]( http://solidity.readthedocs.io/en/v0.4.24/installing-solidity.html#binary-packages))

Use pip to install python dependencies (we recommend using a virtualenv with >= python3.6)

```
pip3 install -r requirements.txt
```

run the tests:
```
python3 test/test_whateverComponent.py
```

-----------
# Disclaimer
This project is a Work in Progress.

For a high level discussion around the research of Submarine Sends and some historical implementations, please refer to the blog post: [To Sink Frontrunners, Send in the Submarines](http://hackingdistributed.com/2017/08/28/submarine-sends/).

-----------
## Authors

LibSubmarine's development was started by the *Submarines* group at the [2018 IC3 Ethereum bootcamp](http://www.initc3.org/events/2018-07-12-IC3-Ethereum-Crypto-Boot-Camp.html), but is now an open source project. Anyone is encouraged to contribute.

IC3 Ethereum Bootcamp <3 2018
