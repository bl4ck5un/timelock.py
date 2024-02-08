#!/usr/bin/env bash

# sender
private_key=cRhCGdT5P85Gkr69HGwfEUhKzr9i733pKPnUZvePPMWj3WqPeFuz
public_key="02df7ec340931b4d039b205116d02fdd649af0094096fd2c9a32ef572a1696538d"

# receiver
privkey2="cUK6YYbqhkfs55pX3wQ3qiLsUSWDCdAckfAtxaeB4WGrRoXwTnoP"
pubkey2="0245d34b08de02c6b0e10018c8d42a631bc7e5dad0b5d1fd9c97ce057623e2968f"


# spend as receiver: ./hodl.py 1708549200 02df7ec340931b4d039b205116d02fdd649af0094096fd2c9a32ef572a1696538d 0245d34b08de02c6b0e10018c8d42a631bc7e5dad0b5d1fd9c97ce057623e2968f spend cUK6YYbqhkfs55pX3wQ3qiLsUSWDCdAckfAtxaeB4WGrRoXwTnoP 9f296f3c5d7e3d2bede5268db976e07f1b7a1b7a975ed0948a677106dcffc975:0 tb1qtrwe8c7l67ykuxe0000uvu6dcugfx2ukql59j0

# spend as sender: ./hodl.py 1708549200 02df7ec340931b4d039b205116d02fdd649af0094096fd2c9a32ef572a1696538d 0245d34b08de02c6b0e10018c8d42a631bc7e5dad0b5d1fd9c97ce057623e2968f spend cRhCGdT5P85Gkr69HGwfEUhKzr9i733pKPnUZvePPMWj3WqPeFuz 9f296f3c5d7e3d2bede5268db976e07f1b7a1b7a975ed0948a677106dcffc975:0 tb1qtrwe8c7l67ykuxe0000uvu6dcugfx2ukql59j0

which bitcoin-cli || {
    echo "Please install bitcoin-cli to use this demo script (see https://bitcoin.org/en/full-node)"
    exit -1
}

if [[ -e $(pgrep bitcoin) ]]; then
    echo "Please start bitcoind or bitcoin-qt prior to running this script."
fi

echo "Using private key ${private_key}"
echo "Using public key ${public_key}"
echo "Using pk2 ${pubkey2}"

# time="2024-02-21 11:00:00"  # that's 11 am on Feb 21
time="2024-02-08 11:00:00"  # that's 11 am on Feb 8
timelock=$(date -jf "%Y-%m-%d %H:%M:%S" "$time" +%s)

echo "Creating a P2SH address with a timelock ${timelock} (${time})"

p2shaddr=$(python3 hodl.py -vt $timelock $public_key $pubkey2 create)

echo "address created: $p2shaddr"

exit;
sleep 2

echo "sending 10 BTC -> $p2shaddr"
# p2shtxid=$(bitcoin-cli sendtoaddress $p2shaddr 10)

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