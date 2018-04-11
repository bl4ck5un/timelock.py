#!/bin/bash

private_key=cURgah32X7tNqK9NCkpXVVd4bbocWm3UjgwyAGpdVfxicAZynLs5

time=$(date +%s)
timelock=$(($time + 60))
echo python3 hodl.py -vt $private_key $timelock create
p2shaddr=$(python3 hodl.py -vt $private_key $timelock create)

echo "address created: $p2shaddr"

sleep 2

echo "sending 50 BTC -> $p2shaddr"
p2shtxid=$(bitcoin-cli sendtoaddress $p2shaddr 50)

echo txid: $p2shtxid

sleep 1 && bitcoin-cli generate 1
sleep 1 && rawtx=$(bitcoin-cli getrawtransaction $p2shtxid)

echo "reference spending tx:"

python3 hodl.py -vt $private_key $timelock spend $p2shtxid:0 mpvu1CZbTQE9fiJ82b8UxQYTWy1z62eeAA 2>&1
# if outpoint 1 is invalid, then try output 1
if [[ $? != 0 ]]; then
    outpoint=1
    python3 hodl.py -vt $private_key $timelock spend $p2shtxid:1 mpvu1CZbTQE9fiJ82b8UxQYTWy1z62eeAA 2>&1
else
    outpoint=0
fi

cat << EOF
//===PASTE THIS INTO C++ CODE====
const string sgxPrivKey = "$private_key";
const uint32_t cltvTimeout = $timelock;
const int nIn = $outpoint;

// txid = $p2shtxid
const string rawPrevTxP2SH = "$rawtx";
// to generate rereference spend transaction
// python3 hodl.py -vt $private_key $timelock spend $p2shtxid:$outpoint mpvu1CZbTQE9fiJ82b8UxQYTWy1z62eeAA
//===END OF PASTE THIS INTO C++ CODE====
EOF
