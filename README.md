timelock.py
===========

`timelock.py` is a command line tool for creating "retractable" coins.
A "sender" can use this tool to send coins to a "receiver" with a specified
timeout, after which the sender can retract the coins.

Requirements: Python3 (and package `python-bitcoinlib`), running Bitcon Core, `bitcoin-cli`.

Synopsis
========

A "sender" can use this tool to create a timelock script (and its address).
We will use the following script. `<nLockTime>` is the timeout (a [Unix timestamp](https://www.unixtimestamp.com/)).
`<senderkey>` and `<receiverkey>` are the sender's and the receiver's public key. The receiver can spend coins at any time, but the sender can retract the coins
after `<nLockTime>`.

```commandline
    OP_IF <receiverkey>
    OP_ELSE <nLockTime> OP_CHECKLOCKTIMEVERIFY OP_DROP <senderkey>
    OP_ENDIF
    OP_CHECKSIG
```

The receiver can use this tool to construct transactions that can spend this script.


### To create a P2SH address

```
$ ./timelock.py nLockTime sender_pubkey receiver_pubkey create
```

Coins sent to this address will be "time locked".

Example:

```
$ ./timelock.py 1707426000 02df7ec340931b4d039b205116d02fdd649af0094096fd2c9a32ef572a1696538d 0245d34b08de02c6b0e10018c8d42a631bc7e5dad0b5d1fd9c97ce057623e2968f create
2MvfcVVEmVqBvThtsEHzpTUnmVDjFgRyWH7
```

This command returns a P2SH address `2MvfcVVEmVqBvThtsEHzpTUnmVDjFgRyWH7` corresponding
to the above script with the given parameters.

### To spend a timelocked coin as the receiver

The receiver can spend the coins at any time.

```
usage: ./timelock.py nLockTime sender_pubkey receiver_pubkey spend [-h] privkey txid:n [txid:n ...] addr

positional arguments:
  privkey     Private key
  txid:n      Transaction output
  addr        Address to send the funds to

optional arguments:
  -h, --help  show this help message and exit
```

Example:

Transaction [b30376...cb633](https://blockstream.info/testnet/tx/b303760f5d1d35660255544d0fe5da4f7abcb456e754dbefda5e38e9609cb633) sent 0.0001 tBTC
to the address created in the previous step. Output #1 is the resultant UTXO.

To spend this UTXO as the receiver:

```
timelock=1707426000
sender_pk=02df7ec340931b4d039b205116d02fdd649af0094096fd2c9a32ef572a1696538d
receiver_pk=0245d34b08de02c6b0e10018c8d42a631bc7e5dad0b5d1fd9c97ce057623e2968f
receiver_privkey=cUK6YYbqhkfs55pX3wQ3qiLsUSWDCdAckfAtxaeB4WGrRoXwTnoP
txid=b303760f5d1d35660255544d0fe5da4f7abcb456e754dbefda5e38e9609cb633
index=1
addr=tb1qk3r0e7lwqp45k5s0rvw2kz7nh0uf6kq8xwt6jl
./timelock.py $timelock $sender_pk $receiver_pk spend $receiver_privkey $txid:$index $addr
```

For this to work, `$receiver_privkey` must be the private key of `$receiver_pk`.
`addr` can be any address of choice.

This command outputs a raw Bitcoin transaction encoded as a hex string:
```commandline
tx: 010000000133b69c60e9385edaefdb54e756b4bc7a4fdae50f4d54550266351d5d0f7603b3010000009a47304402204146747d058dd55702ee3c1462c703dfdbb74ccff58af9a7ddc5e57350f624c0022014a8f61b46ae94b178bedc39e9d6d7f93430d5a37227dfd653beaf57e27681ee01514c4f63210245d34b08de02c6b0e10018c8d42a631bc7e5dad0b5d1fd9c97ce057623e2968f6704d040c565b1752102df7ec340931b4d039b205116d02fdd649af0094096fd2c9a32ef572a1696538d68ac00000000011626000000000000160014b446fcfbee006b4b520f1b1cab0bd3bbf89d580700000000
```

Sending this raw transaction to the Bitcoin network will spend the UTXO (identified by `$txid:$index`) and send the
coins to `$addr`.

You can send raw transactions using `bitcoin-cli sendrawtransaction` or using the Console tab in
Bitcoin Core.

### To retract

After the timeout, the sender can retract with the `retract` command:

```commandline
usage: timelock.py nLockTime sender_pubkey receiver_pubkey retract [-h] privkey txid:n [txid:n ...] addr

positional arguments:
  privkey     Private key
  txid:n      Transaction output
  addr        Address to send the funds to

optional arguments:
  -h, --help  show this help message and exit

```


Example:

Transaction [b30376...cb633](https://blockstream.info/testnet/tx/b303760f5d1d35660255544d0fe5da4f7abcb456e754dbefda5e38e9609cb633) sent 0.0001 tBTC
to the address created in the previous step. Output #1 is the resultant UTXO.

To use the `retract` command:

```
timelock=1707426000
sender_pk=02df7ec340931b4d039b205116d02fdd649af0094096fd2c9a32ef572a1696538d
receiver_pk=0245d34b08de02c6b0e10018c8d42a631bc7e5dad0b5d1fd9c97ce057623e2968f
sender_privkey=XXX
txid=b303760f5d1d35660255544d0fe5da4f7abcb456e754dbefda5e38e9609cb633
index=1
addr=tb1qk3r0e7lwqp45k5s0rvw2kz7nh0uf6kq8xwt6jl
./timelock.py $timelock $sender_pk $receiver_pk spend $receiver_privkey $txid:$index $addr
```

For this to work, `sender_privkey` must be the private key of `sender_pk`.
`addr` can be any address of choice.

This command outputs a raw Bitcoin transaction encoded as a hex string, similar to `spend`.

# FAQ

1. `No module named 'bitcoin'`: You need to install the Python package `python-bitcoinlib`. If you use pip,
    then `pip3 install python-bitcoinlib` does the job.
2. `Outpoint scriptPubKey does not match` : you are trying to spend a wrong UTXO.

# License

GPTv3. A (small) part of the code is based on the CLTV example by Peter Todd <pete@petertodd.org>.