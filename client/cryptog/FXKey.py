from client.cryptog import frodokex


class FXKey:
    def __init__(self):
        self.publicKey = None
        self.privateKey = None
        self.vector = None

    def createSenderKeys(self):

        with open("cryptog/frodokex_seed.bin", "rb") as f:
            seed = f.read()
        self.privateKey, self.vector, self.publicKey = frodokex.generate_A_Key(seed)

    def createReceiverKeys(self):
        with open("cryptog/frodokex_seed.bin", "rb") as f:
            seed = f.read()
        self.privateKey, self.vector, self.publicKey = frodokex.generate_B_Key(seed)

    def loadKeys(self, publicKey, privateKey, vector):
        self.publicKey = publicKey
        self.privateKey = privateKey
        self.vector = vector

    def getPublicKey(self):
        return self.publicKey

    def getPrivateKey(self):
        return self.privateKey

    def getVector(self):
        return self.vector


