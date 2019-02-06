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
    def __init__(self, tx_hex, txid, nout):
        # TODO: test if de-serialization works
        self.tx = CTransaction.deserialize(x(tx_hex))
        self.nout = nout
        self.outpoint = COutPoint(lx(txid), nout)

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

        return CScript([sig, branch, self.redeemScript])

    def generate_life_signal(self, dust_secret: CBitcoinSecret, dust_outpoint: OutPointWithTx, feerate):
        if dust_outpoint.prevout.scriptPubKey != pubkey_to_P2PKH_scriptPubkey(dust_secret.pub):
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

        signed_input = [CTxIn(unsigned_tx.vin[0].prevout,
                              sigScript,
                              nSequence=unsigned_tx.vin[0].nSequence)]

        return CTransaction(
            signed_input,
            unsigned_tx.vout,
            unsigned_tx.nLockTime)


class Wallet:
    def __init__(self, users: List[Party], sgx: Party):
        self.users = users
        self.sgx = sgx
        self.relative_timeout = 144  # blocks

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

    def scriptSig_by_sgx(self, seckey_sgx: CBitcoinSecret, unsigned_tx, n_in):
        # sgx spends the true branch
        branch = OP_TRUE
        sighash = SignatureHash(self.redeemScript, unsigned_tx, n_in, SIGHASH_ALL)

        sig = seckey_sgx.sign(sighash) + bytes([SIGHASH_ALL])
        return CScript([sig, branch, self.redeemScript])

    def generate_life_signal(self, dust_outpoint: OutPointWithTx, secret_sgx: CBitcoinSecret, i, feerate):
        return self.life_signals[i].generate_life_signal(secret_sgx, dust_outpoint, feerate)

    def set_life_signal_outpoint(self, txid: str, n_out):
        self.life_signal_outpoint = COutPoint(lx(txid), n_out)

    def set_wallet_outopint(self, txid: str, n_out):
        self.wallet_outpoint = COutPoint(lx(txid), n_out)

    def spend_life_signal_and_update_wallet(self, user_index, secret_sgx):
        assert self.life_signal_outpoint
        assert self.wallet_outpoint

        try:
            lifesignal_utxo = proxy.gettxout(self.life_signal_outpoint)['txout']
            wallet_utxo = proxy.gettxout(self.wallet_outpoint)['txout']
        except IndexError:
            raise ValueError('Outpoint %s not found' % self.life_signal_outpoint)

        if lifesignal_utxo.scriptPubKey != pubkey_to_P2PKH_scriptPubkey(secret_sgx.pub):
            raise Exception("SGX can't spend the life signal")

        if wallet_utxo.scriptPubKey != self.scriptPubkey:
            raise Exception("wallet utxo mismatch")

        sum_in = lifesignal_utxo.nValue + wallet_utxo.nValue
        fees = int(tx_size(2, 1) / 1000 * feerate)

        print('fee: %f' % fees)
        print('amount: %f' % (sum_in - fees))

        unsigned_tx = CTransaction([CTxIn(self.life_signal_outpoint, nSequence=self.relative_timeout),
                                    CTxIn(self.wallet_outpoint)],
                                   [CTxOut(wallet_utxo.nValue, self.scriptPubkey)])

        # spend the life signal
        lifesignal_sigScript = self.life_signals[user_index].scriptSig_by_key2(unsigned_tx, 0)

        # spend the wallet
        wallet_sigScript = self.scriptSig_by_sgx(secret_sgx, unsigned_tx, 1)

        return CTransaction([CTxIn(unsigned_tx.vin[0].prevout, lifesignal_sigScript, unsigned_tx.vin[0].nSequence),
                             CTxIn(unsigned_tx.vin[1].prevout, wallet_sigScript, unsigned_tx.vin[1].nSequence)],
                            unsigned_tx.vout,
                            unsigned_tx.nLockTime)

    def accuse(self, dust_outpoint, secret_sgx: CBitcoinSecret, i, feerate):
        assert 0 <= i < self.n_user

        life_signal = self.generate_life_signal(dust_outpoint, secret_sgx, i, feerate)
        print("life signal tx: {}".format(b2x(life_signal.serialize())))

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

feerate = 10000

dust_tx_hex = "020000000184b9e9fc7e0de3040d3df835c2f8a1ac603840ba07a2ae91b7349f57b49fee2700000000484730440220633e7218eb0971ec46246dc9a176239563f969ad8f7226a5cc3a90403c868ec002205c01a8e18b5ce5403447adc9a6327b5614624cd086c7347f6e1e0b6fc5d4360c01fdffffff0200ca9a3b000000001976a914567827d4bedca8a476fc0d6ab47dad54ad52379688ac3e196bee0000000017a91457e70919a54efea88b9e222d270fba970e219a8087a5000000"
dust_outpoint = OutPointWithTx(dust_tx_hex, "b46217251be56c5c3a80d6144eccb3628156b1dfe8a99bd959b29df80c53c8ab", 0)

# try accuse Alice
w.accuse(dust_outpoint, sgx_secret, 0, feerate)
