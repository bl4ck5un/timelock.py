CHECKLOCKTIMEVERIY Demos
========================

Requirements: Python3 (python-bitcoinlib included in repo as subtree)

Steps to run the demo
=====================

> Tip: use a local testnet (regtest) for faster confirmation.

This demo consists of two steps. First we create a P2SH script address; then
we spend the UTXO sent to it, demonstrating the use of P2SH scriptSigs.

First, pick a secret key and a timelock, and create a P2SH address:

```
private_key=cURgah32X7tNqK9NCkpXVVd4bbocWm3UjgwyAGpdVfxicAZynLs5
timelock=1547578486 # Tuesday, January 15, 2019 1:54:46 PM ET
python3 hodl.py -t $private_key $timelock create
2N7GnzMovd5tq1DpMQXDx6KfuGW2m6RbXpN
```

Now send some money to the newly created address. (For public testnet you can
get fund from one of the faucets. For local testnet (regtest), you can use
`bitcoin-cli -regtest generate 101` to get 50 BTC.

```
bitcoin-cli sendtoaddress 2N7GnzMovd5tq1DpMQXDx6KfuGW2m6RbXpN 0.001234
7c7e40a94c4bb52f51e78299e6b504323babd0245aaaf2cff288c4d05c1180dc # txid
```

Then, look up the transaction and determine the P2SH output (the other is the
change). Create a spending transaction (suppose the target address is
`2MtntiYA2DtFEmTV1dkfMVT4GVg4MYxN2pX`):

```
python3 hodl.py -t $private_key $timelock spend 7c7e40a94c4bb52f51e78299e6b504323babd0245aaaf2cff288c4d05c1180dc:1 2MtntiYA2DtFEmTV1dkfMVT4GVg4MYxN2pX # the last piece is the target address.
```

Finally, send the raw transaction to Bitcoin by `bitcoin-cli sendrawtransaction hexstring`.
One of my spending tx can be examined here `a4f9e5cb8a0a283da33e226c2131e36ed50da362df8822422fdb26f659bb4033`.

Tips
====

- Using the attached `bitcoin.conf` to run local testnet.
- Read `demo.sh` for how to use the script.
