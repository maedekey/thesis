import pickle

from client import util

from dilithium import Dilithium2
from client import clientinterface


def PQverify(PQidKey, PQSignatures, keys):
    res = True
    for i in range(len(PQSignatures)):
        verif = Dilithium2.verify(PQidKey, pickle.dumps(keys[i]), PQSignatures[i])
        if not verif:
            res = False
    return res


def simpleVerify(idKey, signatures, keys):
    res = True
    for i in range(len(signatures)):
        verif = idKey.verify(signatures[i], keys[i])
        if not verif:
            res = False
    return res


def verifySignatures(conn, username, recipient):
    signatures = clientinterface.getSignatures(conn, recipient, username)
    if signatures is not None:
        signatures = signatures.split(b'SEPARATOR')[:-1]
        idKeys = clientinterface.getIdKeys(conn, recipient)
        if len(idKeys) > 0:
            messageKeys = clientinterface.getClientMessageKeys(conn, recipient, username)
            if len(messageKeys) > 0:
                PQIdKey = pickle.loads(idKeys[0])
                idKey = pickle.loads(idKeys[1])

                PQSignatures, simpleSignatures, keys = util.getSignaturesAndKeys(signatures, messageKeys)

                PQVerif = PQverify(PQIdKey, PQSignatures, keys)
                simpleVerif = simpleVerify(idKey, simpleSignatures, keys)
                return PQVerif and simpleVerif
            else:
                print("There was a problem retrieving the recipient's key.")
        else:
            print("The user you wish to contact does not exist.")
