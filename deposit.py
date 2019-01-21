#!/usr/bin/python3
# Copyright (C) 2015 Peter Todd <pete@petertodd.org>
#
# This file is subject to the license terms in the LICENSE file found in the
# top-level directory of this distribution.

import logging

from typing import List

import bitcoin.rpc
from bitcoin.core import (
    b2x, b2lx, lx,
    str_money_value, COIN,
    Hash,
    COutPoint, CTxIn, CTxOut, CTransaction,
)
from bitcoin.core.script import (
    OP_IF, OP_ENDIF, OP_ELSE, OP_FALSE, OP_TRUE,
    OP_NOP2, OP_DROP, OP_CHECKSIG, OP_CHECKSIGVERIFY,
    CScript,
    SignatureHash, SIGHASH_ALL,
)
from bitcoin.wallet import P2PKHBitcoinAddress, P2SHBitcoinAddress, CBitcoinSecret, CBitcoinAddress


class DepositParams:
    def __init__(self, user_scriptPubKey, exch_scriptPubkey, locktime):
        self.user_scriptPubKey = user_scriptPubKey
        self.exch_scriptPubkey = exch_scriptPubkey
        self.locktime = locktime

    @property
    def address(self):
        return P2SHBitcoinAddress.from_redeemScript(self.deposit_redeemScript)

    @property
    def deposit_redeemScript(self):
        return CScript([OP_IF] + list(self.exch_scriptPubkey) +
                       [OP_ELSE, self.locktime, OP_NOP2, OP_DROP] +
                       list(self.user_scriptPubKey) +
                       [OP_ENDIF])

    def spend_redeemScript(self, who, privkey, unsigned_tx: CTransaction, n_in):
        if who not in ('user', 'exch'):
            raise ValueError("who must be either user or exch")

        branch = OP_FALSE if who == 'user' else OP_TRUE
        redeemScript = self.deposit_redeemScript
        sighash = SignatureHash(redeemScript, unsigned_tx, n_in, SIGHASH_ALL)
        sig = privkey.sign(sighash) + bytes([SIGHASH_ALL])
        return CScript([sig, branch, redeemScript])


class Deposit:
    def __init__(self, params: DepositParams, txid, nout):
        self.params = params
        self.txid = txid
        self.nout = nout


def settle_to_single_addr(deposits: List[Deposit], addr: CBitcoinAddress):
    prevouts = []
    for d in deposits:
        try:
            txid, n = d.txid, d.nout

            txid = lx(txid)
            n = int(n)

            outpoint = COutPoint(txid, n)
        except ValueError:
            raise ValueError('Invalid output: %s' % d)

        try:
            prevout = proxy.gettxout(outpoint)
        except IndexError:
            raise ValueError('Outpoint %s not found' % outpoint)

        prevout = prevout['txout']
        if prevout.scriptPubKey != d.params.deposit_redeemScript.to_p2sh_scriptPubKey():
            raise Exception('Outpoint not correct scriptPubKey')

        prevouts.append((outpoint, prevout))

    sum_in = sum(prev_txout.nValue for _, prev_txout in prevouts)

    tx_size = (4 +  # version field
               2 +  # # of txins
               len(prevouts) * 153 +  # txins, including sigs
               1 +  # # of txouts
               34 +  # txout
               4  # nLockTime field
               )

    estimated_fee = proxy._call('estimatesmartfee', 1)

    if 'errors' in estimated_fee:
        print(estimated_fee['errors'])
        feerate = -1
    else:
        feerate = int(estimated_fee['feerate'] * COIN)  # satoshi's per KB

    if feerate <= 0:
        feerate = 10000
    fees = int(tx_size / 1000 * feerate)

    print('fee: %f' % fees)
    print('amount: %f' % (sum_in - fees))

    # lock until the next block
    nLockTime = proxy.getblockcount()

    unsigned_tx = CTransaction([CTxIn(outpoint, nSequence=0) for outpoint, _ in prevouts],
                               [CTxOut(sum_in - fees, addr.to_scriptPubKey())],
                               nLockTime=nLockTime)

    # sign the inputs
    signed_ins = [CTxIn(unsigned_tx.vin[i].prevout,
                        d.params.spend_redeemScript('exch', exch_seckey, unsigned_tx, i),
                        nSequence=0) for i, d in enumerate(deposits)]

    signed_tx = CTransaction(
        signed_ins,
        unsigned_tx.vout,
        unsigned_tx.nLockTime)

    print(b2x(signed_tx.serialize()))


# test script
logging.root.setLevel('DEBUG')
bitcoin.SelectParams('testnet')

proxy = bitcoin.rpc.Proxy()

user_a_seckey = CBitcoinSecret.from_secret_bytes(Hash(b'alice'))
user_b_seckey = CBitcoinSecret.from_secret_bytes(Hash(b'bob'))
exch_seckey = CBitcoinSecret.from_secret_bytes(Hash(b'exch'))

users = [user_a_seckey, user_b_seckey]

params = []

for ukey in users:
    params.append(DepositParams(
        user_scriptPubKey=P2PKHBitcoinAddress.from_pubkey(ukey.pub).to_scriptPubKey(),
        exch_scriptPubkey=P2PKHBitcoinAddress.from_pubkey(exch_seckey.pub).to_scriptPubKey(),
        locktime=1000000,  # block 1 million
    ))

# print(b2x(params[0].deposit_redeemScript))
# print(b2x(params[0].deposit_redeemScript.to_p2sh_scriptPubKey()))

print("Alice will deposit at: {}".format(params[0].address))
print("Bob will deposit at: {}".format(params[1].address))
print("exch's address is at: {}".format(P2PKHBitcoinAddress.from_pubkey(exch_seckey.pub)))

# utxo = proxy.listunspent()
# print(utxo)
# deposits = []
#
# for u in utxo:
#     print(u['address'])
#
# for p in params:
#     print(p.address)
#     deposits.extend([Deposit(p, u["txid"], u['vout']) for u in filter(lambda unspent: unspent["address"] == str(p.address), utxo)])
#
# if deposits:
#     settle_to_single_addr(deposits, CBitcoinAddress("2NCoX4m42XUEypfdaWo8m58s1hiMu55gbVv"))
# else:
#     print('no deposit at this point')

# alice = Deposit(params[0], "2077114532b6baa43b8d6173d61c5db8f4f6cce20f3a83ea0de59616e006d418", 1)
# bob = Deposit(params[1], "2077114532b6baa43b8d6173d61c5db8f4f6cce20f3a83ea0de59616e006d418", 2)
#
# settle_to_single_addr([alice, bob], CBitcoinAddress("2NCoX4m42XUEypfdaWo8m58s1hiMu55gbVv"))