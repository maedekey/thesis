
import copy
import pickle

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512


class Ratchets:
    def __init__(self, username, baseKey):
        self.username = username
        self.baseKey = baseKey
        self.senderRatchet = [copy.deepcopy(baseKey)]
        self.receiverRatchet = [copy.deepcopy(baseKey)]

    def tickSenderRatchet(self, counter):
        key = PBKDF2(self.senderRatchet[-1], counter, 32, count=1000000, hmac_hash_module=SHA512)
        self.senderRatchet.append(key)

    def tickReceiverRatchet(self, counter):
        key = PBKDF2(self.receiverRatchet[-1], counter, 32, count=1000000, hmac_hash_module=SHA512)
        self.receiverRatchet.append(key)

    def resetRatchets(self):
        self.senderRatchet = []
        self.receiverRatchet = []

    def save(self, recipient):
        with open("saved/" + self.username + "/" + recipient + "/ratchets", "wb") as f:
            pickle.dump(self, f)  # jsp si ça va marcher
        f.close()

    def getSenderKey(self):
        return self.senderRatchet[-1]

    def getReceiverKey(self):
        return self.receiverRatchet[-1]


def load(sender, receiver):
    with open("saved/" + sender + "/" + receiver + "/ratchets", "rb") as f:
        ratchet = pickle.load(f)
    f.close()
    return ratchet