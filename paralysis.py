from typing import List

from bitcoin.core.key import CPubKey


class Party:
    def __init__(self, name, pubkey: CPubKey):
        self.name = name
        self.pubkey = pubkey


class Wallet:
    def __init__(self, users: List[Party], sgx: Party):
        self.users = users
        self.sgx = sgx

    @property
    def redeemScript(self):
        """
        OP_IF
        """
        return ""