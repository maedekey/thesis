import os
import pickle
from client.clientManager import transformToLargeMessage
from client.clientinterface import getClientMessageKeys
from client.cryptog.FXKey import FXKey
from client.cryptog.FMKey import FMKey


class MessageKeys:
    def __init__(self, sender, receiver, fk):
        self.sender = sender
        self.receiver = receiver
        self.EKey = None  #frodokem
        self.SKey = None
        self.LKey = None  #frodokem
        self.fk = fk

    def createSenderKeys(self, conn):
        self.EKey = FMKey(self.fk)
        self.EKey.createFrodokemKeys(conn, self.sender, self.receiver)
        self.SKey = FXKey()
        self.SKey.createSenderKeys()
        self.LKey = FMKey(self.fk)
        self.LKey.createFrodokemKeys(conn, self.sender, self.receiver)
        self.saveKeys(conn)

    def createReceiverKeys(self, conn):
        self.EKey = FMKey(self.fk)
        self.EKey.createFrodokemKeys(conn, self.sender, self.receiver)
        self.SKey = FXKey()
        self.SKey.createReceiverKeys()
        self.LKey = FMKey(self.fk)
        self.LKey.createFrodokemKeys(conn, self.sender, self.receiver)
        self.saveKeys(conn)

    def saveKeys(self, conn):
        self.savePublickeys(conn)
        self.savePrivateKeys()

    def savePrivateKeys(self):
        os.makedirs("saved/" + self.sender + "/" + self.receiver, exist_ok=True)
        with open("saved/" + self.sender + "/" + self.receiver + "/privateEkey.pkl", "wb") as f:
            pickle.dump(self.EKey.getPrivateKey(), f)
        f.close()
        with open("saved/" + self.sender + "/" + self.receiver + "/privateSkey.pkl", "wb") as f:
            pickle.dump(self.SKey.getPrivateKey(), f)
        f.close()
        with open("saved/" + self.sender + "/" + self.receiver + "/privateLkey.pkl", "wb") as f:
            pickle.dump(self.LKey.getPrivateKey(), f)
        f.close()

    def updatePublicEkey(self, conn):
        transformToLargeMessage(conn, ["LARGEMESSAGE".encode(), "updateMessageKeys".encode(), self.sender.encode(),
                                       self.receiver.encode(), pickle.dumps(self.EKey.getPublicKey())])

    def savePublickeys(self, conn):
        transformToLargeMessage(conn, ["LARGEMESSAGE".encode(), "addMessageKeys".encode(), self.sender.encode(),
                                       self.receiver.encode(), pickle.dumps(self.EKey.getPublicKey()),
                                       pickle.dumps(self.SKey.getPublicKey()), pickle.dumps(self.LKey.getPublicKey()),
                                       pickle.dumps(self.SKey.getVector())])

    def loadKeys(self, conn):
        self.loadPublicKeys(conn)

    def loadPublicKeys(self, conn):
        pubKeys = getClientMessageKeys(conn, self.sender, self.receiver)
        privKeys = self.loadPrivateKeys()
        pubEKey = pickle.loads(pubKeys[0])
        self.EKey = FMKey(self.fk)
        self.EKey.loadKeys(pubEKey, privKeys[0])

        pubSKey = pickle.loads(pubKeys[1])
        sVec = pickle.loads(pubKeys[3])
        self.SKey = FXKey()
        self.SKey.loadKeys(pubSKey, privKeys[1], sVec)

        pubLKey = pickle.loads(pubKeys[2])
        self.LKey = FMKey(self.fk)
        self.LKey.loadKeys(pubLKey, privKeys[2])

    def loadPrivateKeys(self):
        with open("saved/" + self.sender + "/" + self.receiver + "/privateEkey.pkl", "rb") as f:
            privEkey = pickle.load(f)
        f.close()
        with open("saved/" + self.sender + "/" + self.receiver + "/privateSkey.pkl", "rb") as f:
            privSkey = pickle.load(f)
        f.close()
        with open("saved/" + self.sender + "/" + self.receiver + "/privateLkey.pkl", "rb") as f:
            privLkey = pickle.load(f)
        f.close()
        return privEkey, privSkey, privLkey
