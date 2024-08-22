from client import clientinterface, iofile


class FMKey:
    def __init__(self, fk):
        self.publicKey = None
        self.privateKey = None
        self.fk = fk

    def createFrodokemKeys(self, conn, username, receiver):
        self.publicKey, self.privateKey = self.fk.kem_keygen()
        clientinterface.saveFrodoKey(conn, username, receiver, self.publicKey)
        iofile.savePrivateEkey(self.privateKey, username, receiver)

    def updateEFrodokemKeys(self, conn, username, receiver):
        self.publicKey, self.privateKey = self.fk.kem_keygen()
        clientinterface.updateEFrodoKey(conn, username, receiver, self.publicKey)
        iofile.savePrivateEkey(self.privateKey, username, receiver)

    def loadKeys(self, publicKey, privateKey):
        self.publicKey = publicKey
        self.privateKey = privateKey

    def getPublicKey(self):
        return self.publicKey

    def getPrivateKey(self):
        return self.privateKey
