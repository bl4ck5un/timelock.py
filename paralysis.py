from typing import List

import bitcoin
from bitcoin.wallet import P2PKHBitcoinAddress, P2SHBitcoinAddress, CBitcoinSecret
from bitcoin.core.key import CPubKey
from bitcoin.core import Hash, b2x, b2lx, Hash160, COutPoint, COIN, CTransaction, CTxIn, CTxOut
from bitcoin.core.script import *

import logging
import secrets


class Party:
    def __init__(self, name, pubkey: CPubKey):
        self.name = name
        self.pubkey = pubkey

    @property
    def P2PKHScriptAddress(self):
        return P2PKHBitcoinAddress.from_pubkey(self.pubkey)

    @property
    def P2PKHScriptPubkey(self):
        return self.P2PKHScriptAddress.to_scriptPubKey()

    @property
    def keyhash(self):
        return Hash160(self.pubkey)

    def __str__(self):
        return "name={}, addr={}, pubkey={}, keyhash={}".format(self.name, self.P2PKHScriptAddress, b2x(self.pubkey),
                                                                b2x(self.keyhash)).replace(",", "\t")


def pubkey_to_P2PKH_scriptPubkey(pubkey: CPubKey) -> CScript:
    return P2PKHBitcoinAddress.from_pubkey(pubkey).to_scriptPubKey()


def dummy_user(name: str):
    secret = CBitcoinSecret.from_secret_bytes(Hash(name.encode()))
    return secret, Party(name, secret.pub)


def dummy_users():
    names = ["alice", "bob", "char", "david", "eve"]

    _users = dict(dummy_user(name) for name in names)
    return list(_users.keys()), list(_users.values())


def encode_const(N):
    if 1 <= N <= 16:
        return CScriptOp.encode_op_n(N)
    else:
        return CScriptOp.encode_op_pushdata(N)


class Wallet:
    def __init__(self, users: List[Party], sgx: Party):
        self.users = users
        self.sgx = sgx
        self.relative_timeout = 144  # blocks

    @property
    def n_user(self):
        return len(self.users)

    @property
    def redeemScript(self):
        """
        OP_IF sgxScriptPubkey OP_ELSE N <pubkey1> ... <pubkeyN> N OP_CHECKMULTISIG
        """

        if_branch = [OP_IF] + list(self.sgx.P2PKHScriptPubkey)
        else_branch = [OP_ELSE, encode_const(self.n_user)] + [u.pubkey for u in users] + [encode_const(self.n_user),
                                                                                          OP_CHECKMULTISIG, OP_ENDIF]

        return CScript(if_branch + else_branch)

    @property
    def scriptPubkey(self):
        return self.redeemScript.to_p2sh_scriptPubKey()

    @property
    def P2SHAddress(self):
        return P2SHBitcoinAddress.from_scriptPubKey(self.scriptPubkey)

    def spend_by_all_users(self, list_of_secret_keys: List[CBitcoinSecret]):
        pass

    def scriptSig_by_sgx(self, seckey_sgx: CBitcoinSecret, unsigned_tx, n_in):
        # sgx spends the true branch
        branch = OP_TRUE
        sighash = SignatureHash(self.redeemScript, unsigned_tx, n_in, SIGHASH_ALL)

        sig = seckey_sgx.sign(sighash) + bytes([SIGHASH_ALL])
        return CScript([sig, branch, self.redeemScript])

    def set_dust_outpoint(self, txid, n_out):
        self.dust_outpoint = COutPoint(txid, n_out)

    def generate_life_signal(self, secret_sgx: CBitcoinSecret, i, feerate):
        assert self.dust_outpoint

        try:
            dust_utxo = proxy.gettxout(self.dust_outpoint)['txout']
        except IndexError:
            raise ValueError('Outpoint %s not found' % self.dust_outpoint)

        # FIXME this is wrong. I need to check dust_utxo.scriptPubKey is P2PKH
        if dust_utxo.scriptPubKey != self.redeemScript.to_p2sh_scriptPubKey():
            raise Exception("Outpoint have incorrect scriptPubKey")

        sum_in = dust_utxo.nValue

        tx_size = (4 +  # version field
                   2 +  # # of txins
                   153 +  # txins, including sigs
                   1 +  # # of txouts
                   34 +  # txout
                   4  # nLockTime field
                   )

        fees = int(tx_size / 1000 * feerate)

        print('fee: %f' % fees)
        print('amount: %f' % (sum_in - fees))

        tmp_key = CBitcoinSecret.from_secret_bytes(secrets.token_bytes(32))

        life_signal_redeemScript = CScript(
            [OP_IF, self.users[i].pubkey, OP_CHECKSIG] + [OP_ELSE, self.relative_timeout, OP_NOP3, OP_DROP] + list(
                pubkey_to_P2PKH_scriptPubkey(tmp_key.pub)) + [OP_ENDIF])

        unsigned_tx = CTransaction([CTxIn(dust_utxo, nSequence=self.relative_timeout)],
                                   [CTxOut(sum_in - fees, life_signal_redeemScript.to_p2sh_scriptPubKey())])

        # spend the dust input
        sighash = SignatureHash(dust_utxo.scriptPubKey, unsigned_tx, 0, SIGHASH_ALL)
        sig = secret_sgx.sign(sighash) + bytes([SIGHASH_ALL])
        # FIXME double check on this
        sigScript = CScript([sig])

        signed_input = [CTxIn(unsigned_tx.vin[0].prevout,
                              sigScript,
                              nSequence=unsigned_tx.vin[0].nSequence)]

        signed_tx = CTransaction(
            signed_input,
            unsigned_tx.vout,
            unsigned_tx.nLockTime)

        print(b2x(signed_tx.serialize()))

    def accuse(self, secret_sgx: CBitcoinSecret, i, feerate):
        assert 0 <= i < self.n_user
        assert self.dust_outpoint

        life_signal = self.generate_life_signal(secret_sgx, i, feerate)

    def __str__(self):
        return "wallet_address={}, script={}".format(self.P2SHAddress, b2x(self.redeemScript)).replace(",", "\t")


# test script
proxy = bitcoin.rpc.Proxy()

logging.root.setLevel('DEBUG')
bitcoin.SelectParams('testnet')

secrets_users, users = dummy_users()
sgx_secret, sgx = dummy_user("sgx")

for user in users:
    print(user)
print(sgx)

w = Wallet(users, sgx)
print(w)

# try accuse Alice
w.accuse(0)
