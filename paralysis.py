from typing import List

import bitcoin.rpc
from bitcoin.wallet import P2PKHBitcoinAddress, P2SHBitcoinAddress, CBitcoinSecret
from bitcoin.core.key import CPubKey
from bitcoin.core import Hash, b2x, b2lx, lx, x, Hash160, COutPoint, COIN, CTransaction, CTxIn, CTxOut
from bitcoin.core.script import *

import logging


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

        # TODO: assuming there is only one output with targetScriptPubkey
        self.nout = None
        for i, out in enumerate(self.tx.vout):
            if out.scriptPubKey == targetScriptPubkey:
                self.nout = i
                break

        assert self.nout is not None
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
        return CScript(
            [OP_IF] + list(pubkey_to_P2PKH_scriptPubkey(self._key1)) + [OP_ELSE, self._relative_timeout,
                                                                        OP_NOP3, OP_DROP] + list(
                pubkey_to_P2PKH_scriptPubkey(self._key2.pub)) + [OP_ENDIF])

    @property
    def relative_timeout(self):
        return self._relative_timeout

    def scriptSig_by_key1(self, secret_key: CBitcoinSecret, unsigned_tx: CTransaction, which_to_sign):
        assert secret_key.pub == self._key1
        branch = OP_TRUE
        sighash = SignatureHash(self.redeemScript, unsigned_tx, which_to_sign, SIGHASH_ALL)

        sig = secret_key.sign(sighash) + bytes([SIGHASH_ALL])

        return CScript([sig, self._key1, branch, self.redeemScript])

    def scriptSig_by_key2(self, unsigned_tx: CTransaction, which_to_sign):
        branch = OP_FALSE
        sighash = SignatureHash(self.redeemScript, unsigned_tx, which_to_sign, SIGHASH_ALL)

        sig = self._key2.sign(sighash) + bytes([SIGHASH_ALL])

        return CScript([sig, self._key2.pub, branch, self.redeemScript])

    def into_transaction(self, dust_secret: CBitcoinSecret, dust_outpoint: OutPointWithTx, feerate):
        if dust_outpoint.prevout.scriptPubKey != pubkey_to_P2PKH_scriptPubkey(dust_secret.pub):
            print(b2x(dust_outpoint.prevout.scriptPubKey))
            print(b2x(pubkey_to_P2PKH_scriptPubkey(dust_secret.pub)))
            raise Exception("Outpoint has incorrect scriptPubKey")

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
        self._users = users
        self._sgx = sgx

        self._life_signals = []
        for i, _ in enumerate(users):
            self._life_signals.append(LifeSignal(users[i].pubkey, relative_timeout=10))

    @property
    def n_user(self):
        return len(self._users)

    @property
    def _redeemScript(self):
        """
        OP_IF sgxScriptPubkey OP_ELSE N <pubkey1> ... <pubkeyN> N OP_CHECKMULTISIG
        """
        if_branch = [OP_IF] + list(self._sgx.P2PKHScriptPubkey)
        else_branch = [OP_ELSE, encode_const(self.n_user)] + [u.pubkey for u in self._users] + [
            encode_const(self.n_user),
            OP_CHECKMULTISIG, OP_ENDIF]

        return CScript(if_branch + else_branch)

    @property
    def scriptPubkey(self):
        return self._redeemScript.to_p2sh_scriptPubKey()

    @property
    def P2SHAddress(self):
        return P2SHBitcoinAddress.from_scriptPubKey(self.scriptPubkey)

    def _remove_user(self, user_index):
        self._users.pop(user_index)

    def spend_by_all_users(self, list_of_secret_keys: List[CBitcoinSecret]):
        pass

    def _scriptSig_by_sgx(self, seckey_sgx: CBitcoinSecret, unsigned_tx, n_in):
        # sgx spends the true branch
        branch = OP_TRUE
        sighash = SignatureHash(self._redeemScript, unsigned_tx, n_in, SIGHASH_ALL)

        sig = seckey_sgx.sign(sighash) + bytes([SIGHASH_ALL])
        return CScript([sig, seckey_sgx.pub, branch, self._redeemScript])

    def appeal(self, user_index, user_secret: CBitcoinSecret, lifesignal_op: OutPointWithTx):
        ls = self._life_signals[user_index]
        if lifesignal_op.prevout.scriptPubKey != ls.redeemScript.to_p2sh_scriptPubKey():
            raise Exception("mismatch scriptPubkey")

        # spend the life signal into a black hole
        unsigned_tx = CTransaction([CTxIn(lifesignal_op.outpoint)],
                                   [CTxOut(0, CScript([True]))],
                                   nVersion=2)

        return CTransaction(
            [CTxIn(lifesignal_op.outpoint, scriptSig=ls.scriptSig_by_key1(user_secret, unsigned_tx, 0))],
            unsigned_tx.vout,
            nVersion=2)

    def accuse(self, dust_op: OutPointWithTx, wallet_op: OutPointWithTx, user_index, secret_sgx):
        ls_tx = self._life_signals[user_index].into_transaction(secret_sgx, dust_op, feerate)
        # FIXME: hardcode zero here because life signal is always the first output in a life signal tx
        nOut_for_ls = 0

        ls = self._life_signals[user_index]

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
        self._remove_user(user_index)
        unsigned_tx = CTransaction([CTxIn(COutPoint(ls_tx.GetTxid(), nOut_for_ls), nSequence=ls.relative_timeout),
                                    CTxIn(wallet_op.outpoint)],
                                   [CTxOut(wallet_op.prevout.nValue, self.scriptPubkey)],
                                   nVersion=2)

        # spend the life signal
        lifesignal_sigScript = self._life_signals[user_index].scriptSig_by_key2(unsigned_tx, 0)

        # spend the wallet
        wallet_sigScript = self._scriptSig_by_sgx(secret_sgx, unsigned_tx, 1)

        # return the life signal as well as both transactions
        return ls, ls_tx, CTransaction(
            [CTxIn(unsigned_tx.vin[0].prevout, scriptSig=lifesignal_sigScript, nSequence=ls.relative_timeout),
             CTxIn(wallet_op.outpoint, wallet_sigScript)],
            unsigned_tx.vout,
            unsigned_tx.nLockTime,
            unsigned_tx.nVersion)

    def __str__(self):
        return "wallet_address={}, script={}".format(self.P2SHAddress, b2x(self._redeemScript)).replace(",", "\t")


# test script
proxy = bitcoin.rpc.Proxy()

logging.root.setLevel('DEBUG')
bitcoin.SelectParams('testnet')

user_seckeys, users = dummy_users()
sgx_seckey, sgx = dummy_user("sgx")

for user in users:
    print(user)
print(sgx)

wallet = Wallet(users, sgx)
print(wallet)

feerate = 10000

dust_tx_hex = "020000000001023ae39b3324379dcb2258f42e6270155f8393e5d14976b8bc419f1875ff3b5d890100000017160014ed3947e5a8992aae50d06f7f4375857503791076fdffffffb4fc5d489c3b238d98718b9a3ade94921f7cd4bf9a9e5962594e064fab626fa20200000017160014201b558498b581d9675074287f47482cbd228664fdffffff033c6ff4050000000017a914ebc8580e10c803ebe70d3fdd8ffb5ab2d8269a0b8750c30000000000001976a914567827d4bedca8a476fc0d6ab47dad54ad52379688ac00ca9a3b0000000017a91400593b17f9ff1e272c0086b46ec4161de2e89b4387024730440220371c07b2942339012aabfa70d6ae9bbe1d951db4d5e1952c5c1bd264e443432402201b7d5469eb0252735c64d3361215cd7849d4b38a8655de48d6e3463a8760519f01210387fb76f2352dfcc94ce2fe6b6a5af86c70a07cacd422c9362d99b5827a211b4a0247304402203a928bf0291936697bb9462f5c75431e2fcdb888e904df329aaf53e4942187480220331a0f23cc6055537a2287e34ae974d77705e02580ef4d467f5c82fa8b58789e01210234446fb0f7bc2b53ac063672e15da59a62f029770d83400b9fd5ada38f0fefa9ea000000"
dust_outpoint = OutPointWithTx(dust_tx_hex, sgx.P2PKHScriptPubkey)

wallet_deposit_tx_hex = "020000000001023ae39b3324379dcb2258f42e6270155f8393e5d14976b8bc419f1875ff3b5d890100000017160014ed3947e5a8992aae50d06f7f4375857503791076fdffffffb4fc5d489c3b238d98718b9a3ade94921f7cd4bf9a9e5962594e064fab626fa20200000017160014201b558498b581d9675074287f47482cbd228664fdffffff033c6ff4050000000017a914ebc8580e10c803ebe70d3fdd8ffb5ab2d8269a0b8750c30000000000001976a914567827d4bedca8a476fc0d6ab47dad54ad52379688ac00ca9a3b0000000017a91400593b17f9ff1e272c0086b46ec4161de2e89b4387024730440220371c07b2942339012aabfa70d6ae9bbe1d951db4d5e1952c5c1bd264e443432402201b7d5469eb0252735c64d3361215cd7849d4b38a8655de48d6e3463a8760519f01210387fb76f2352dfcc94ce2fe6b6a5af86c70a07cacd422c9362d99b5827a211b4a0247304402203a928bf0291936697bb9462f5c75431e2fcdb888e904df329aaf53e4942187480220331a0f23cc6055537a2287e34ae974d77705e02580ef4d467f5c82fa8b58789e01210234446fb0f7bc2b53ac063672e15da59a62f029770d83400b9fd5ada38f0fefa9ea000000"
wallet_depo_outpoint = OutPointWithTx(wallet_deposit_tx_hex, wallet.scriptPubkey)

# try accuse Alice
life_signal, tx1, tx2 = wallet.accuse(dust_outpoint, wallet_depo_outpoint, 0, sgx_seckey)
print('tx1 (hex):', b2x(tx1.serialize()))
print('tx2 (hex):', b2x(tx2.serialize()))

# life_signal_tx_hex = "0100000001b4fc5d489c3b238d98718b9a3ade94921f7cd4bf9a9e5962594e064fab626fa2000000006b48304502210092118be3693405f8ab2476ae4f9b28981c60b014cd8118d33d748dda6eb1651d0220162e0e1d59f790f7ac2582df86aef9dc5b33bd90695f86d800e28b434a813600012102f820895591103d4fa7c7bcb30f8c2a994641be4c8d8587415e70ae0a92fccf99ffffffff02102700000000000017a914eeaf2e143a578e234331ed362faa5d99080d9f5a87e0b0f505000000001976a914567827d4bedca8a476fc0d6ab47dad54ad52379688ac00000000"
life_signal_tx_hex = b2x(tx1.serialize())
tx_appeal = wallet.appeal(0, user_seckeys[0], OutPointWithTx(tx_hex=life_signal_tx_hex,
                                                             targetScriptPubkey=life_signal.redeemScript.to_p2sh_scriptPubKey()))
print('tx_appeal (hex):', b2x(tx_appeal.serialize()))
