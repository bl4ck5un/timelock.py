#!/usr/bin/env python3
# A small part of code is from the CLTV example by Peter Todd <pete@petertodd.org>
# This file is subject to the license terms in the LICENSE file found in the
# top-level directory of this distribution.

import argparse
import binascii
import bitcoin
import bitcoin.rpc
import logging
import math

import bitcoin.rpc
from bitcoin.core import (
    b2x, b2lx, lx, x,
    str_money_value, COIN,
    COutPoint, CTxIn, CTxOut, CTransaction,
)
from bitcoin.core.script import (
    OP_IF, OP_ELSE, OP_ENDIF,
    OP_TRUE, OP_FALSE,
    OP_NOP2, OP_DROP, OP_CHECKSIG,
    CScript,
    SignatureHash, SIGHASH_ALL,
)
from bitcoin.wallet import P2SHBitcoinAddress, CBitcoinSecret, CBitcoinAddress
from bitcoin.core.key import CPubKey

parser = argparse.ArgumentParser(description="retractable bitcoins with CHECKLOCKTIMEVERIFY")
parser.add_argument('-v', action='store_true',
                    dest='verbose',
                    help='Verbose')
parser.add_argument('-t', action='store_true',
                    dest='testnet',
                    default=True,
                    help='Enable testnet')
parser.add_argument('nLockTime', action='store', type=int,
                    help='nLockTime')
parser.add_argument('sender_pubkey', action='store',
                    help='Sender Public key')
parser.add_argument('receiver_pubkey', action='store',
                    help='Receiver Public key')
subparsers = parser.add_subparsers(title='Subcommands',
                                   description='All operations are done through subcommands:')


def timelock_redeemScript(sender_pubkey, receiver_pubkey, nLockTime):
    # OP_IF <receiverkey>
    # OP_ELSE nLockTime OP_NOP2 OP_DROP <senderkey>
    # OP_ENDIF
    # OP_CHECKSIG

    # spend before timeout: script = <sig_receiver> OP_TRUE
    # spend after timeout: script = <sig_sender> OP_FALSE
    return CScript([OP_IF, receiver_pubkey,
                    OP_ELSE, nLockTime, OP_NOP2, OP_DROP, sender_pubkey,
                    OP_ENDIF, OP_CHECKSIG])


def sign_by_receiver(sender_pubkey, receiver_privkey, nLockTime, unsigned_tx, n):
    """Spend before timeout

    Returns the complete scriptSig: <sig_receiver> OP_TRUE <redeemScript>
    """
    redeemScript = timelock_redeemScript(sender_pubkey, receiver_privkey.pub, nLockTime)
    logging.debug('redeemScript: %s' % b2x(redeemScript))
    sighash = SignatureHash(redeemScript, unsigned_tx, n, SIGHASH_ALL)
    logging.debug('sighash: %s' % b2x(sighash))
    sig = receiver_privkey.sign(sighash) + bytes([SIGHASH_ALL])
    return CScript([sig, OP_TRUE, redeemScript])


def sign_by_sender(sender_privkey, receiver_pubkey, nLockTime, unsigned_tx, n):
    """Spend after timeout

    Returns the complete scriptSig: <sig_sender> OP_FALSE <redeemScript>
    """
    redeemScript = timelock_redeemScript(sender_privkey.pub, receiver_pubkey, nLockTime)
    logging.debug('redeemScript: %s' % b2x(redeemScript))
    sighash = SignatureHash(redeemScript, unsigned_tx, n, SIGHASH_ALL)
    logging.debug('sighash: %s' % b2x(sighash))
    sig = sender_privkey.sign(sighash) + bytes([SIGHASH_ALL])
    return CScript([sig, OP_FALSE, redeemScript])


def fetch_utxo(raw_tx, output_idx):
    tx = CTransaction.deserialize(bytes.fromhex(raw_tx))
    return tx.vout[output_idx]

def build_tx(args, tx_nLockTime, signer):
    redeemScript = timelock_redeemScript(args.sender_pubkey, args.receiver_pubkey, args.nLockTime)
    scriptPubKey = redeemScript.to_p2sh_scriptPubKey()

    logging.debug('redeemScript: %s' % b2x(redeemScript))
    logging.debug('scriptPubKey: %s' % b2x(scriptPubKey))

    prevouts = []
    for prevout in args.prevouts:
        try:
            txid, n = prevout.split(':')

            txid = lx(txid)
            n = int(n)

            outpoint = COutPoint(txid, n)
        except ValueError:
            args.parser.error('Invalid output: %s' % prevout)

        if args.rawtx:
            prevout = fetch_utxo(args.rawtx, n)
        else:
            try:
                proxy = bitcoin.rpc.Proxy()
                prevout = proxy.gettxout(outpoint)
                prevout = prevout['txout']
            except IndexError:
                args.parser.error('Outpoint %s not found' % outpoint)
        if prevout.scriptPubKey != scriptPubKey:
            args.parser.error('Outpoint scriptPubKey does not match')

        prevouts.append((outpoint, prevout))

    sum_in = sum(prev_txout.nValue for outpoint, prev_txout in prevouts)

    tx_size = (4 +  # version field
               2 +  # # of txins
               len(prevouts) * 153 +  # txins, including sigs
               1 +  # # of txouts
               34 +  # txout
               4  # nLockTime field
               )


    # estimated_fee = proxy._call('estimatesmartfee', 1)
    # if 'errors' in estimated_fee:
    #     print(estimated_fee['errors'])
    #     feerate = -1
    # else:
    #     feerate = int(estimated_fee['feerate'] * COIN)  # satoshi's per KB
    #
    # if feerate <= 0:
    #     feerate = 10000

    # 25 satoshi/B is a good estimate
    # TODO: allow changes
    feerate = 25000
    fees = int(tx_size / 1000 * feerate)

    if fees < 236:  # to prevent  min relay fee not met, 198 < 236 (code -26)
        fees = 250

    logging.debug('fee: %f' % fees)
    logging.debug('amount: %f' % (sum_in - fees))

    unsigned_tx = CTransaction([CTxIn(outpoint, nSequence=0) for outpoint, prevout in prevouts],
                               [CTxOut(sum_in - fees,
                                       args.addr.to_scriptPubKey())],
                               tx_nLockTime)

    signed_tx = CTransaction(
        [CTxIn(txin.prevout,
               signer(unsigned_tx, i),
               nSequence=0)
         for i, txin in enumerate(unsigned_tx.vin)],
        unsigned_tx.vout,
        unsigned_tx.nLockTime)

    raw_tx = b2x(signed_tx.serialize())
    print(f"tx: {raw_tx}")


# ----- create -----
parser_create = subparsers.add_parser('create',
                                      help='Create an address for hodling')


def create_command(args):
    redeemScript = timelock_redeemScript(args.sender_pubkey, args.receiver_pubkey, args.nLockTime)
    scriptPubKey = redeemScript.to_p2sh_scriptPubKey()

    logging.debug('redeemScript: %s' % b2x(redeemScript))
    logging.debug('scriptPubKey: %s' % b2x(scriptPubKey))

    addr = P2SHBitcoinAddress.from_redeemScript(redeemScript)
    print(addr)


parser_create.set_defaults(cmd_func=create_command)

# ----- spend -----
parser_spend = subparsers.add_parser('spend',
                                     help='Spend (all) your hodled coins')
parser_spend.add_argument('privkey', action='store',
                          help='Private key')
parser_spend.add_argument('prevouts', nargs='+',
                          metavar='txid:n',
                          help='Transaction output')
parser_spend.add_argument('addr', action='store',
                          help='Address to send the funds to')
parser_spend.add_argument('--rawtx',
                          help='The raw tx from which UTXO can be extracted. Use this when RPC is not available.')


def spend_command(args):
    """ Spend the funds using receiver's private key.
    """
    args.privkey = CBitcoinSecret(args.privkey)
    args.addr = CBitcoinAddress(args.addr)

    print(args.rawtx)

    sigScriptF = None
    nLockTime = 0
    if args.privkey.pub != args.receiver_pubkey:
        args.parser.error("invalid private key (not receiver's)")

    sigScriptF = lambda unsigned_tx, n: sign_by_receiver(args.sender_pubkey, args.privkey, args.nLockTime,
                                                         unsigned_tx, n)

    build_tx(args, 0, sigScriptF)


parser_spend.set_defaults(cmd_func=spend_command)

# ----- retract -----
parser_retract = subparsers.add_parser('retract',
                                       help='Sender uses this to spend the coins after the timeout')
parser_retract.add_argument('privkey', action='store',
                            help='Private key')
parser_retract.add_argument('prevouts', nargs='+',
                            metavar='txid:n',
                            help='Transaction output')
parser_retract.add_argument('addr', action='store',
                            help='Address to send the funds to')


def retract_command(args):
    """ Retract funds using sender's private key.
    """
    args.privkey = CBitcoinSecret(args.privkey)
    args.addr = CBitcoinAddress(args.addr)

    if args.privkey.pub != args.sender_pubkey:
        args.parser.error("invalid private key (not sender's)")

    signer = lambda unsigned_tx, n: sign_by_sender(args.privkey, args.receiver_pubkey, args.nLockTime,
                                                   unsigned_tx, n)

    # nLockTime set to args.nLockTime as required by CLTV
    build_tx(args, args.nLockTime, signer)


parser_retract.set_defaults(cmd_func=retract_command)

args = parser.parse_args()
args.parser = parser

if args.verbose:
    logging.root.setLevel('DEBUG')

if args.testnet:
    bitcoin.SelectParams('testnet')

args.sender_pubkey = CPubKey(x(args.sender_pubkey))
args.receiver_pubkey = CPubKey(x(args.receiver_pubkey))

if not hasattr(args, 'cmd_func'):
    parser.error('No command specified')

args.cmd_func(args)
