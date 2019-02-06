from typing import List

import bitcoin.rpc
from bitcoin.wallet import P2PKHBitcoinAddress, P2SHBitcoinAddress, CBitcoinSecret
from bitcoin.core.key import CPubKey
from bitcoin.core import Hash, b2x, b2lx, lx, x, Hash160, COutPoint, COIN, CTransaction, CTxIn, CTxOut
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


def tx_size(nin, nout):
    return (4 +  # version field
            2 +  # # of txins
            nin * 153 +  # txins, including sigs
            1 +  # # of txouts
            nout * 34 +  # txout
            4  # nLockTime field
            )


class OutPointWithTx:
    def __init__(self, tx_hex, targetScriptPubkey: CScript):
        self.tx = CTransaction.deserialize(x(tx_hex))
        self.txid = b2lx(self.tx.GetTxid())

        for i, out in enumerate(self.tx.vout):
            # TODO: assuming there is only one output with targetScriptPubkey
            if out.scriptPubKey == targetScriptPubkey:
                self.nout = i
                break

        self.outpoint = COutPoint(lx(self.txid), self.nout)

    @property
    def prevout(self):
        return self.tx.vout[self.nout]


class LifeSignal:
    def __init__(self, key1: CPubKey, relative_timeout):
        """
        a life signal is a coin that can be spent by key1 immediately or a tmp key after a relative_timeout
        :param key1:
        :param relative_timeout:
        """
        self._key1 = key1
        self._key2 = CBitcoinSecret.from_secret_bytes(Hash("tmpsecret".encode()))
        self._relative_timeout = relative_timeout
        self._life_signal_amount = 0.0001 * COIN

    @property
    def redeemScript(self):
        return CScript([OP_IF, self._key1, OP_CHECKSIG] + [OP_ELSE, self._relative_timeout, OP_NOP3, OP_DROP] + list(
            pubkey_to_P2PKH_scriptPubkey(self._key2.pub)) + [OP_ENDIF])

    @property
    def relative_timeout(self):
        return self._relative_timeout

    def scriptSig_by_key2(self, unsigned_tx: CTransaction, which_to_sign):
        branch = OP_FALSE
        sighash = SignatureHash(self.redeemScript, unsigned_tx, which_to_sign, SIGHASH_ALL)

        sig = self._key2.sign(sighash) + bytes([SIGHASH_ALL])

        return CScript([sig, self._key2.pub, branch, self.redeemScript])

    def into_transaction(self, dust_secret: CBitcoinSecret, dust_outpoint: OutPointWithTx, feerate):
        if dust_outpoint.prevout.scriptPubKey != pubkey_to_P2PKH_scriptPubkey(dust_secret.pub):
            print(b2x(dust_outpoint.prevout.scriptPubKey))
            print(b2x(pubkey_to_P2PKH_scriptPubkey(dust_secret.pub)))
            raise Exception("Outpoint have incorrect scriptPubKey")

        sum_in = dust_outpoint.prevout.nValue

        fees = int(tx_size(1, 2) / 1000 * feerate)
        refund = sum_in - fees - self._life_signal_amount

        print('fee: %f' % fees)
        print('amount: %f' % (sum_in - fees))

        redeemScript = self.redeemScript

        unsigned_tx = CTransaction([CTxIn(dust_outpoint.outpoint)],
                                   [CTxOut(self._life_signal_amount, redeemScript.to_p2sh_scriptPubKey()),
                                    CTxOut(refund, pubkey_to_P2PKH_scriptPubkey(dust_secret.pub))])

        # spend the dust input
        sighash = SignatureHash(dust_outpoint.prevout.scriptPubKey, unsigned_tx, 0, SIGHASH_ALL)
        sig = dust_secret.sign(sighash) + bytes([SIGHASH_ALL])
        sigScript = CScript([sig, dust_secret.pub])

        signed_input = [CTxIn(unsigned_tx.vin[0].prevout, sigScript)]

        return CTransaction(
            signed_input,
            unsigned_tx.vout,
            unsigned_tx.nLockTime)


class Wallet:
    def __init__(self, users: List[Party], sgx: Party):
        self.users = users
        self.sgx = sgx

        self.life_signals = []
        for i, _ in enumerate(users):
            self.life_signals.append(LifeSignal(users[i].pubkey, relative_timeout=10))

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

    def _scriptSig_by_sgx(self, seckey_sgx: CBitcoinSecret, unsigned_tx, n_in):
        # sgx spends the true branch
        branch = OP_TRUE
        sighash = SignatureHash(self.redeemScript, unsigned_tx, n_in, SIGHASH_ALL)

        sig = seckey_sgx.sign(sighash) + bytes([SIGHASH_ALL])
        return CScript([sig, seckey_sgx.pub, branch, self.redeemScript])

    def accuse(self, dust_op: OutPointWithTx, wallet_op: OutPointWithTx, user_index, secret_sgx):
        ls_tx = self.life_signals[user_index].into_transaction(secret_sgx, dust_op, feerate)
        # FIXME: hardcode zero here because life signal is always the first output in a life signal tx
        nOut_for_ls = 0

        ls = self.life_signals[user_index]

        if ls_tx.vout[nOut_for_ls].scriptPubKey != ls.redeemScript.to_p2sh_scriptPubKey():
            raise Exception("SGX can't spend the life signal")

        if wallet_op.prevout.scriptPubKey != self.scriptPubkey:
            raise Exception("wallet utxo mismatch")

        print('ls value: %f' % ls_tx.vout[nOut_for_ls].nValue)
        sum_in = ls_tx.vout[0].nValue + wallet_op.prevout.nValue
        fees = int(tx_size(2, 1) / 1000 * feerate)

        print('fee: %f' % fees)
        print('amount: %f' % (sum_in - fees))

        # todo: remove the user from self.scriptPubkey
        # note: nVersion=2 is required by CSV
        unsigned_tx = CTransaction([CTxIn(COutPoint(ls_tx.GetTxid(), nOut_for_ls), nSequence=ls.relative_timeout),
                                    CTxIn(wallet_op.outpoint)],
                                   [CTxOut(wallet_op.prevout.nValue, self.scriptPubkey)],
                                   nVersion=2)

        # spend the life signal
        lifesignal_sigScript = self.life_signals[user_index].scriptSig_by_key2(unsigned_tx, 0)

        # spend the wallet
        wallet_sigScript = self._scriptSig_by_sgx(secret_sgx, unsigned_tx, 1)

        # return both transactions
        return ls_tx, CTransaction(
            [CTxIn(unsigned_tx.vin[0].prevout, scriptSig=lifesignal_sigScript, nSequence=ls.relative_timeout),
             CTxIn(wallet_op.outpoint, wallet_sigScript)],
            unsigned_tx.vout,
            unsigned_tx.nLockTime,
            unsigned_tx.nVersion)

    def __str__(self):
        return "wallet_address={}, script={}".format(self.P2SHAddress, b2x(self.redeemScript)).replace(",", "\t")


# test script
proxy = bitcoin.rpc.Proxy()

logging.root.setLevel('DEBUG')
bitcoin.SelectParams('testnet')

secrets_users, users = dummy_users()
sgx_seckey, sgx = dummy_user("sgx")

for user in users:
    print(user)
print(sgx)

w = Wallet(users, sgx)
print(w)

feerate = 10000

dust_tx_hex = "02000000000101b5bf56e209f5d8a9afcd5e27b283c9bcc3bcc245c2f60cfa2c6240343926ff930100000017160014510255d77b393e80d68ee33579c015d6236aa5acfdffffff0300e1f505000000001976a914567827d4bedca8a476fc0d6ab47dad54ad52379688ac00ca9a3b0000000017a91400593b17f9ff1e272c0086b46ec4161de2e89b438724a4496b0000000017a9142e7b9ee58864176e5b7aba2d1fba097a54c11968870247304402207a8d8c614328e94d1b2fad42e202b74e743c6bdf4f017317460450b5c3803c8c022027602bf5401a6ab66a96a1c4f7a1e61e6d6cf7acd2be686864cfe5f5ba0966df012102f3cf8c4bd7cb4b0bfceb34f773afff0a4e8af2e3b6e52ad490db5b7278f14c44d3000000"
dust_outpoint = OutPointWithTx(dust_tx_hex, sgx.P2PKHScriptPubkey)

wallet_deposit_tx_hex = "02000000000101b5bf56e209f5d8a9afcd5e27b283c9bcc3bcc245c2f60cfa2c6240343926ff930100000017160014510255d77b393e80d68ee33579c015d6236aa5acfdffffff0300e1f505000000001976a914567827d4bedca8a476fc0d6ab47dad54ad52379688ac00ca9a3b0000000017a91400593b17f9ff1e272c0086b46ec4161de2e89b438724a4496b0000000017a9142e7b9ee58864176e5b7aba2d1fba097a54c11968870247304402207a8d8c614328e94d1b2fad42e202b74e743c6bdf4f017317460450b5c3803c8c022027602bf5401a6ab66a96a1c4f7a1e61e6d6cf7acd2be686864cfe5f5ba0966df012102f3cf8c4bd7cb4b0bfceb34f773afff0a4e8af2e3b6e52ad490db5b7278f14c44d3000000"
wallet_depo_outpoint = OutPointWithTx(wallet_deposit_tx_hex, w.scriptPubkey)

# try accuse Alice
tx1, tx2 = w.accuse(dust_outpoint, wallet_depo_outpoint, 0, sgx_seckey)
print('tx1 (hex):', b2x(tx1.serialize()))
print('tx2 (hex):', b2x(tx2.serialize()))
