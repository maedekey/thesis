from client import util


def DiffieHellman(sKey, A):
    sharedSecret = (A ** util.toInt(sKey)) % util.globalDHModulo
    return sharedSecret
