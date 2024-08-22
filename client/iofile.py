import os
import pickle


def getMessageCounter(username, receiver):
    ctr = 0
    filePath = "saved/" + username + "/" + receiver + "/ctr"
    if os.path.exists(filePath):
        with open(filePath, "r") as f:
            ctr = int(f.read())
        f.close()
    return ctr


def resetCounter(username, recipient):
    with open("saved/" + username + "/" + recipient + "/ctr", "w") as f:
        f.write(str(0))
    f.close()


def saveMessageCounter(username, ctr, receiver):
    os.makedirs("saved/" + username + "/" + receiver, exist_ok=True)
    with open("saved/" + username + "/" + receiver + "/ctr", "w") as f:
        f.write(str(ctr))
    f.close()


def saveSecretKey(username, sharedSecret, recipient):
    with open("saved/" + username + "/" + recipient + "/sharedSecret.pkl", "wb") as f:
        pickle.dump(sharedSecret, f)
    f.close()


def getSecretKey(username, recipient):
    with open("saved/" + username + "/" + recipient + "/sharedSecret.pkl", "rb") as f:
        secretKey = pickle.load(f)
    f.close()

    return secretKey


def loadPrivateKey(username):
    with open(username + "/privatepqsignkey.pkl", "rb") as f:
        PQSignKey = pickle.load(f)
    f.close()
    with open(username + "/privatesignkey.pkl", "rb") as f:
        signKey = pickle.load(f)
    f.close()
    return PQSignKey, signKey


def savePrivateKeys(username, privateKey):
    os.makedirs(username, exist_ok=True)
    with open(username + "/privatepqsignkey.pkl", "wb") as f:
        pickle.dump(privateKey[0], f)
    f.close()
    with open(username + "/privatesignkey.pkl", "wb") as f:
        pickle.dump(privateKey[1], f)
    f.close()


def getPrivateEkey(sender, receiver):
    with open("saved/" + sender + "/" + receiver + "/privateEkey.pkl", "rb") as f:
        frodokey = pickle.load(f)
        f.close()
    return frodokey


def savePrivateEkey(Ekey, sender, receiver):
    with open("saved/" + sender + "/" + receiver + "/privateEkey.pkl", "wb") as f:
        pickle.dump(Ekey, f)
    f.close()


def createConvDir(sender, receiver):
    if not os.path.exists("saved/" + sender + "/" + receiver):
        os.makedirs("saved/" + sender + "/" + receiver)
