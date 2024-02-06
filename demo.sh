#!/usr/bin/env bash

private_key=cURgah32X7tNqK9NCkpXVVd4bbocWm3UjgwyAGpdVfxicAZynLs5
address=mpvu1CZbTQE9fiJ82b8UxQYTWy1z62eeAA

which bitcoin-cli || {
    echo "Please install bitcoin-cli to use this demo script (see https://bitcoin.org/en/full-node)"
    exit -1
}

if [[ -e $(pgrep bitcoin) ]]; then
    echo "Please start bitcoind or bitcoin-qt prior to running this script."
fi

echo "Using private key ${private_key}"

time="2024-02-06 12:00:00"
timelock=$(date -jf "%Y-%m-%d %H:%M:%S" "$time" +%s)

echo "Creating a P2SH address with a timelock ${timelock}"

p2shaddr=$(python3 hodl.py -t $private_key $timelock create)

echo "address created: $p2shaddr"

exit;
sleep 2

echo "sending 10 BTC -> $p2shaddr"
p2shtxid=$(bitcoin-cli sendtoaddress $p2shaddr 10)

echo "txid: $p2shtxid"

sleep 1 && bitcoin-cli generate 1
sleep 1 && rawtx=$(bitcoin-cli getrawtransaction $p2shtxid)

echo "Now let's spend the newly created UTXO"

python3 hodl.py -vt $private_key $timelock spend $p2shtxid:0 ${address} 2>&1
# if outpoint 0 is invalid, then try outpoint 1
if [[ $? != 0 ]]; then
    outpoint=1
    python3 hodl.py -vt $private_key $timelock spend $p2shtxid:1 ${address} 2>&1
else
    outpoint=0
fi

echo "Done."