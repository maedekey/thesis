import hashlib
import pickle
import time

import clientinterface

globalDHModulo = 255
globalDHGenerator = 42

def toInt(key):
    bKey = pickle.dumps(key)

    hashedKey = hashlib.sha256(bKey).hexdigest()
    intKey = int(hashedKey, 16) % 32
    return intKey


def getSignaturesAndKeys(signatures, messageKeys):
    PQSignatures = (pickle.loads(signatures[0]), pickle.loads(signatures[1]), pickle.loads(signatures[2]))
    simpleSignatures = (pickle.loads(signatures[3]), pickle.loads(signatures[4]), pickle.loads(signatures[5]))
    keys = (pickle.loads(messageKeys[0]), pickle.loads(messageKeys[1]), pickle.loads(messageKeys[2]))
    return PQSignatures, simpleSignatures, keys


def generatePrekey(conn, user1, user2):
    signatures = clientinterface.getSignatures(conn, user1, user2)
    if signatures is not None:
        signatures = signatures.split(b'SEPARATOR')[:-1]
        messageKeys = clientinterface.getClientMessageKeys(conn, user1, user2)

        PQSignatures, simpleSignatures, keys = getSignaturesAndKeys(signatures, messageKeys)
        prekey = (pickle.dumps(PQSignatures[0]), pickle.dumps(PQSignatures[1]), pickle.dumps(
            PQSignatures[2]), pickle.dumps(simpleSignatures[0]), pickle.dumps(simpleSignatures[1]), pickle.dumps(
            simpleSignatures[2]), keys[0], keys[1], keys[2])
        return prekey


def generateSID(conn, sender, receiver):
    time.sleep(0.2)
    idKeysSender = clientinterface.getIdKeys(conn, sender)
    idKeySender = idKeysSender[1]
    PQIdKeySender = idKeysSender[0]
    idKeysReceiver = clientinterface.getIdKeys(conn, receiver)
    idKeyReceiver = idKeysReceiver[1]
    PQIdKeyReceiver = idKeysReceiver[0]
    senderPrekey = generatePrekey(conn, sender, receiver)
    receiverPrekey = generatePrekey(conn, receiver, sender)
    premessage = clientinterface.getPremessages(conn, sender, receiver)
    SID = bytes(idKeySender) + bytes(PQIdKeySender) + bytes(idKeyReceiver) + bytes(PQIdKeyReceiver) + bytes(
        pickle.dumps(senderPrekey)) + bytes(pickle.dumps(receiverPrekey)) + bytes(premessage)
    return SID
