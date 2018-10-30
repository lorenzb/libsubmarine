# Simple "Uniswap"-like DEX example

This is based on the code from the [Uniswap Solidity repo](https://github.com/Uniswap/old-solidity-contracts). Most function have been simplified as much as possible to make this example easy to understand. You'll probably want to start by comparing the `ethToTokenSwap` function with the original one.

In this example, we use Submarine Sends as a "speed bump" mechanism. The `commitPeriodLength` variable sets the size of the speed bump, ensuring that one must wait a certain number of blocks between registering (committing) a trade and executing (revealing) it. This prevents front-running, because a front-runner would have to convince miners to censor the victim's reveal transaction for `commitPeriodLength` blocks.

An arguably sounder alternative, which is left as an exercise for the reader (actually, because it's hard to implement properly), would be to execute  the trades strictly by the order in which they are committed. Doing this well, would probably require implementing a priority queue/heap data structure in the smart contract.

