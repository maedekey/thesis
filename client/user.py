import pickle
import time

from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from Crypto.Protocol.KDF import PBKDF2
from ecdsa import SigningKey, Ed25519

from client.cryptog.FMKey import FMKey
from cryptog import diffiehellman, doubleratchet, frodokex, messageKeys, signatures, frodokem
import util
import clientinterface
import iofile
from dilithium import Dilithium2
import clientManager


class User:
    def __init__(self, username):
        """
        Class that represents a user. It has definite idkeys (privateKey and publicKey), as well as message keys, which
        are loaded and unloaded in function of who the user talks to. It has a connection to the server, and for
        optimisation reasons, has a frodoKEM instance.
        :param username:
        """
        self.privateKey = None
        self.publicKey = None
        self.username = username
        self.messageKeys = None
        self.conn = clientManager.connectToServer()
        self.ratchets = None
        self.fk = frodokem.FrodoKEM("FrodoKEM-1344-AES")

    def getMessageKeys(self):
        return self.messageKeys

    def createUser(self):
        self.createUserKeys()

    def createUserKeys(self):
        """
        Method that create 2 pairs of identity keys: one that is pre-quantum, with Elliptic Curves, and another one,
        which is post-quantum, generated with Dilithium.
        :return:
        """
        PQSignKeys = Dilithium2.keygen()
        sk = SigningKey.generate(curve=Ed25519)
        pk = sk.verifying_key
        signKeys = (pk, sk)
        self.publicKey = (PQSignKeys[0], signKeys[0])
        self.privateKey = (PQSignKeys[1], signKeys[1])
        self.saveKeys()

    def saveKeys(self):
        """
        Method that saves public and private IDKeys.
        :return:
        """
        clientinterface.savePublicKeys(self.conn, self.username, self.publicKey)
        iofile.savePrivateKeys(self.username, self.privateKey)

    def loadUser(self):
        """
        Method that loads the public and private keys of a user who just logged in.
        :return:
        """
        received = clientinterface.getIdKeys(self.conn, self.username)
        if len(received) > 0:
            self.publicKey = (pickle.loads(received[0]), pickle.loads(received[1]))
            PQprivKey, privKey = iofile.loadPrivateKey(self.username)
            self.privateKey = (PQprivKey, privKey)
        else:
            print("Your account doesn't exist. Please create one")

    def loadMessageKeys(self, receiver):
        """
        Method that loads message keys between 2 users.
        :param receiver: the recipient with who the user has the conversation
        :return:
        """
        self.messageKeys = messageKeys.MessageKeys(self.username, receiver, self.fk)
        self.messageKeys.loadKeys(self.conn)

    def signKeys(self, recipient):
        """
        Method that signs message keys: once pre-quantumly, and once post-quantumly.
        :param recipient: the recipient name with who the user has the conversation
        :return:
        """
        Esign, Ssign, Lsign = self.simpleSign()
        PQEsign, PQSsign, PQLsign, = self.PQsignKeys()
        clientinterface.addSignatures(self.conn, self.username, PQEsign, PQSsign, PQLsign, Esign, Ssign, Lsign,
                                      recipient)

    def PQsignKeys(self):
        """
        Method that signs post-quantumly each message key, with dilithium.
        :return: The post-quantum signature of each key
        """
        PQEsign = pickle.dumps(Dilithium2.sign(self.privateKey[0], pickle.dumps(self.messageKeys.EKey.getPublicKey())))
        PQSsign = pickle.dumps(Dilithium2.sign(self.privateKey[0], pickle.dumps(self.messageKeys.SKey.getPublicKey())))
        PQLsign = pickle.dumps(Dilithium2.sign(self.privateKey[0], pickle.dumps(self.messageKeys.LKey.getPublicKey())))
        return PQEsign, PQSsign, PQLsign

    def simpleSign(self):
        """
        Method that signs pre-quantumly each message key, with Elliptic Curves.
        :return: The signature of each key
        :return: The pre-quantum signature of each key
        """
        Esign = pickle.dumps(self.privateKey[1].sign(self.messageKeys.EKey.getPublicKey()))
        Ssign = pickle.dumps(self.privateKey[1].sign(self.messageKeys.SKey.getPublicKey()))
        Lsign = pickle.dumps(self.privateKey[1].sign(self.messageKeys.LKey.getPublicKey()))
        return Esign, Ssign, Lsign

    def createSenderMessageKeys(self, receiver):
        """
        Due to the asymmetrical nature of split-KEMs, sender and receiver keys are not created the same way.
        As we use one split-KEM during the X3DH adaptation, we have to create sender and receiver message keys
        separately.
        Method that first creates a directory for a conversation between 2 users, then create the message keys for a
        conversation between such users, then signs these keys.
        :param receiver: the recipient name with whom the user has the conversation.
        :return:
        """
        iofile.createConvDir(self.username, receiver)
        self.messageKeys = messageKeys.MessageKeys(self.username, receiver, self.fk)
        self.messageKeys.createSenderKeys(self.conn)
        self.signKeys(receiver)

    def createReceiverMessageKeys(self, sender):
        """
        Method that creates the message keys for a conversation between such users, then signs these keys.
        :param sender: the recipient with whom the user has the conversation.
        :return:
        """
        self.messageKeys = messageKeys.MessageKeys(self.username, sender, self.fk)
        self.messageKeys.createReceiverKeys(self.conn)
        self.signKeys(sender)

    def encapsulate(self, sender, sharedDH):
        """
        Method that retrieves message keys of the conversation, then, through them, encapsulates twice with FrodoKEM and
        once with FrodoKEX+. The generated ciphertexts are added in the database, an SID is generated, and used as a
        salt for a Key Derivation Function, in which we enter all the obtained shared secrets out of the KEMs and split-
        KEM, as well as the Diffie Hellman shared secret. Finally, we store in local the obtained final secret.
        :param sender: the recipient name with whom the user has the conversation.
        :param sharedDH: shared secret generated through DH.
        :return:
        """
        senderMessageKeys = clientinterface.getClientMessageKeys(self.conn, sender, self.username)
        senderEKey = pickle.loads(senderMessageKeys[0])
        senderSKey = pickle.loads(senderMessageKeys[1])
        senderLKey = pickle.loads(senderMessageKeys[2])
        ctE, keyE = self.fk.kem_encaps(senderEKey)
        keyS, ctS = frodokex.encaps(senderSKey, self.messageKeys.SKey.getPrivateKey())
        ctL, keyL = self.fk.kem_encaps(senderLKey)
        clientinterface.addPremessage(self.conn, sender, self.username, pickle.dumps((ctE, ctS, ctL)))
        SID = util.generateSID(self.conn, sender, self.username)
        sharedSecret = PBKDF2(
            pickle.dumps((pickle.dumps(keyE), pickle.dumps(keyS), pickle.dumps(keyL), pickle.dumps(sharedDH))), SID, 32,
            count=1000000,
            hmac_hash_module=SHA512)
        iofile.saveSecretKey(self.username, sharedSecret, sender)

    def decapsulate(self, receiver, sharedDH):
        """
        Method that retrieves message keys of the conversation as well as the ciphertexts, performs decapsulation with
        such variables; then, an SID is generated, and used as a salt for a Key Derivation Function, in which we enter
        all the obtained shared secrets out of the KEMs and split-KEM, as well as the Diffie Hellman shared secret.
        Finally, we store in local the obtained final secret.
        :param receiver: the recipient name with whom the user has the conversation.
        :param sharedDH: shared secret generated through DH.
        :return:
        """
        receiverMessageKeys = clientinterface.getClientMessageKeys(self.conn, receiver, self.username)
        premessages = pickle.loads(clientinterface.getPremessages(self.conn, self.username, receiver))
        receiverSKey = pickle.loads(receiverMessageKeys[1])
        keyE = self.fk.kem_decaps(self.messageKeys.EKey.getPrivateKey(), premessages[0])

        keyS = frodokex.decaps(receiverSKey, self.messageKeys.SKey.getPrivateKey(), self.messageKeys.SKey.getVector(),
                               premessages[1])

        keyL = self.fk.kem_decaps(self.messageKeys.LKey.getPrivateKey(), premessages[2])
        SID = util.generateSID(self.conn, self.username, receiver)
        sharedSecret = PBKDF2(
            pickle.dumps((pickle.dumps(keyE), pickle.dumps(keyS), pickle.dumps(keyL), pickle.dumps(sharedDH))), SID, 32,
            count=1000000,
            hmac_hash_module=SHA512)
        iofile.saveSecretKey(self.username, sharedSecret, receiver)

    def getRequests(self):
        """
        Method that retrieves all the requests that have been sent to the currently logged-in user, and asks for an
        answer from him.
        :return:
        """
        requests = clientinterface.getReceivedRequests(self.conn, self.username)

        for request in requests:
            request = request.decode()
            request = request.split(" ")
            res = input(request[0] + " sent you a request. Do you accept? (y/n)")
            if res == "y":
                self.acceptRequest(request)
            else:
                print("You successfully rejected the request.")
                clientinterface.updateRequest(self.conn, "rejected", request[0], self.username)

    def acceptRequest(self, request):
        """
        Method that accepts a request that has been sent to a user. First, the message key signatures are verified. If
        correct, a contact is added to the user's friend list, the status of the request is updated, a directory for
        the conversation is created, and message keys for the current user are created.
        :param request: request that has been sent to the currently logged in user.
        :return:
        """
        recipient = request[0]
        if signatures.verifySignatures(self.conn, self.username, recipient):
            clientinterface.addContact(self.conn, self.username, recipient)
            clientinterface.updateRequest(self.conn, "validated", recipient, self.username)
            iofile.createConvDir(self.username, recipient)
            self.createReceiverMessageKeys(recipient)

            self.prepareEncaps(recipient)
        else:
            print("Verification failed")

    def prepareEncaps(self, recipient):
        """
        Method that is called for preparing an encapsulation. First, we generate a new DH public and private value, then
         we perform an encapsulation, and finally, we create ratchets and save them locally.
        :param recipient: the recipient name with whom the user has the conversation.
        :return:
        """
        self.saveComputedValue(self.username, recipient)
        A = clientinterface.getDHVal(self.conn, recipient, self.username)
        sharedSecret = diffiehellman.DiffieHellman(self.messageKeys.EKey.getPrivateKey(), A)
        self.encapsulate(recipient, sharedSecret)
        self.initRatchets(recipient)
        self.saveRatchets(recipient)

    def saveComputedValue(self, sender, receiver):
        """
        Method that generates a DH public value, and stores it in a DB.
        :param sender: the name of the first party of the exchange
        :param receiver: the name of the second party of the exchange
        :return:
        """
        computedValue = (util.globalDHGenerator ** util.toInt(
            self.messageKeys.EKey.getPrivateKey())) % util.globalDHModulo
        time.sleep(0.2)
        clientinterface.addComputedValue(self.conn, sender, computedValue, receiver)

    def createRequest(self, receiver):
        """
        Method that adds request for a given user in the DB and that creates a public DH value.
        :param receiver: the name of the user to who we send the request
        :return:
        """
        time.sleep(0.2)
        clientinterface.addRequest(self.conn, self.username, receiver)
        self.saveComputedValue(self.username, receiver)

    def checkRequests(self):
        """
        Method that retrieves all the requests we have sent, and processes them. We also retrieve the keys of the user to
        whom we sent the request, verify them, and if they are correct, we prepare a decapsulation.
        :return:
        """
        time.sleep(0.1)
        validatedRequests = clientinterface.getValidatedRequests(self.conn, self.username)
        for recipient in validatedRequests:
            print(recipient + " has accepted your request.")
            clientinterface.processValidatedRequest(self.username, self.conn, recipient)
            if signatures.verifySignatures(self.conn, self.username, recipient):
                self.prepareDecaps(recipient)
            else:
                print("Verification failed.")

    def prepareDecaps(self, recipient):
        """
        Method that is called for preparing a decapsulation. First, we load the message keys of the recipient, then we
        create new public and private DH values, we perform the decapsulation, and finally, we create ratchets and save
        them locally.
        :param recipient: the recipient name with whom the user has the conversation.
        :return:
        """
        self.loadMessageKeys(recipient)
        B = clientinterface.getDHVal(self.conn, recipient, self.username)
        sharedSecret = diffiehellman.DiffieHellman(self.messageKeys.EKey.getPrivateKey(), B)
        self.decapsulate(recipient, sharedSecret)
        self.initRatchets(recipient)
        self.saveRatchets(recipient)

    def getMessages(self, conn, username):
        """
        Method that is called to get all the messages that have been sent to the currently logged-in user. Then, we get
        the senders of such messages, and decrypt them.
        :param conn: database connection, needed for client interface
        :param username: the currently logged-in user
        :return:
        """
        messages = clientinterface.clGetMessages(conn, username)
        senders = self.getMessageSenders(messages)

        discussions = []
        for sender in senders:
            self.processSenders(discussions, sender, senders, username)
        return discussions

    def processSenders(self, discussions, sender, senders, username):
        """
        Method that is called to decrypt and decode messages, then show them to the logged-in user. Then, we check if a
        ratchet reset has been initiated by the recipient. If so, a new encapsulation is performed, otherwise, we
        check if we should initiate a ratchet reset.
        :param discussions: All the discussions that have been sent to the user
        :param sender: a specific user that has sent messages
        :param senders: all users that have sent messages
        :param username: currently logged-in user
        :return:
        """
        discussions.append(sender)
        print(sender + " sent you the messages: ")
        for m in reversed(senders[sender]):
            print(">", m.decode())
        iofile.resetCounter(self.username, sender)
        encapsReset = clientinterface.getResetMessage(self.conn, sender, self.username)
        if encapsReset == "True":

            self.DREncaps(sender)
        else:
            count = clientinterface.getMessageCount(self.conn, self.username, sender)
            if count % 5 == 0:
                self.initiateDRReset(sender, username)

    def initiateDRReset(self, sender, username):
        """
        Method that is called to initiate a ratchet reset. First, we load message keys, and reset our ephemeral keys.
        Then, we clear all the ciphertexts that have been sent until now, and reset our DH public value. Finally, we
        save the ephemeral DH value.
        :param sender: the recipient name with whom the user has the conversation.
        :param username: currently logged-in user
        :return:
        """
        self.loadMessageKeys(sender)
        self.resetEphemeralKeys(sender)
        clientinterface.resetMessage(self.conn, self.username, sender)
        clientinterface.resetPremessage(self.conn, self.username, sender)
        clientinterface.resetDH(self.conn, username, sender)
        self.saveEDH(sender)

    def DREncaps(self, sender):
        """
        Method that is called when performing a ratchet reset to encapsulate the recipient's public key and generate a
        new secret. First, we load the current message keys, and retrieve the ephemeral key of the recipient. We perform
        an encapsulation with it, then add the obtained ciphertext in a DB, create a new DH value, and finally, we
        generate a final secret with the KEM secret and the private DH value.
        :param sender: the recipient name with whom the user has the conversation.
        :return:
        """
        self.loadMessageKeys(sender)
        recipientPFKey = clientinterface.getEFrodoKey(self.conn, sender, self.username)
        ciphertext, sharedFrodoVal = self.fk.kem_encaps(recipientPFKey)
        clientinterface.addPremessage(self.conn, sender, self.username, pickle.dumps(ciphertext))
        self.resetEphemeralKeys(sender)
        self.saveEDH(sender)
        DHVal = clientinterface.getDHVal(self.conn, sender, self.username)
        sharedValue = self.computeDH(sender, DHVal)
        self.generateDRSecret(sender, sharedFrodoVal, sharedValue)

    def generateDRSecret(self, sender, sharedFrodoVal, sharedValue):
        """
        method that is called upon generating a new shared secret for ratchet reset. We use the secret KEM and DH values
        to generate a salt, with which we use a KDF to derive the current secret.
        :param sender: the recipient name with whom the user has the conversation.
        :param sharedFrodoVal: KEM secret
        :param sharedValue: DH secret
        :return:
        """
        salt = pickle.dumps((sharedFrodoVal, sharedValue))
        sharedSecret = PBKDF2(pickle.dumps(iofile.getSecretKey(self.username, sender)),
                              pickle.dumps(salt), 32, count=1000000, hmac_hash_module=SHA512)
        iofile.saveSecretKey(self.username, sharedSecret, sender)
        self.initRatchets(sender)
        self.saveRatchets(sender)

    def computeDH(self, sender, B):
        """
        Method that retrieves the private ephemeral key of the user to compute a DH secret with it, and the public DH
        value of the recipient.
        :param sender: the recipient name with whom the user has the conversation.
        :param B: public DH value of the recipient
        :return:
        """
        with open("saved/" + self.username + "/" + sender + "/privateEkey.pkl", "rb") as f:
            a = pickle.load(f)
        f.close()
        aSH = diffiehellman.DiffieHellman(a, B)
        return aSH

    def saveEDH(self, sender):
        """
        Method retrieving DH private value, and generating a new DH public value.
        :param sender: the recipient name with whom the user has the conversation.
        :return:
        """
        with open("saved/" + self.username + "/" + sender + "/privateEkey.pkl", "rb") as f:
            a = pickle.load(f)
        f.close()
        A = (util.globalDHGenerator ** util.toInt(a)) % util.globalDHModulo
        time.sleep(0.2)  # todo: same remarque
        clientinterface.addComputedValue(self.conn, self.username, A, sender)

    def resetEphemeralKeys(self, sender):
        """
        Method resetting ephemeral keys.
        :param sender: the recipient name with whom the user has the conversation.
        :return:
        """
        EKey = FMKey(self.fk)
        self.messageKeys.EKey = EKey
        self.messageKeys.EKey.updateEFrodokemKeys(self.conn, self.username, sender)

    def getMessageSenders(self, messages):
        """
        Method that first checks if the user should do a decapsulation. If so, decapsulates for ratchet reset. Otherwise,
        loads preexisting ratchets. Finally, decrypts the message, using the shared secret.
        :param messages: messages to decrypt
        :return: dictiionary of senders with their sent messages
        """
        senders = {}
        for m in messages:
            m = m.split(b"BLOCK")
            sender = m[0].decode()
            decapsReset = clientinterface.getDecapsResetMessage(self.conn, self.username, sender)
            if decapsReset:
                self.DRDecaps(sender)
            else:
                self.loadRatchets(sender)
            self.decrypt(m, sender, senders)
        return senders

    def decrypt(self, m, sender, senders):
        """
        Method that decrypts (with AES) the messages that have been sent to the currently logged-in user, using the
        last key of its receiving ratchet. Then, ticks the ratchet and saves the new state of the ratchet.
        :param m: message to decrypt
        :param sender: sender who sent the message
        :param senders: list of all senders
        :return:
        """
        cipher = AES.new(self.ratchets.getReceiverKey(), AES.MODE_EAX, nonce=m[4])
        plaintext = cipher.decrypt(m[3])
        if sender not in senders:
            senders[sender] = [plaintext]
        else:
            senders[sender].append(plaintext)
        self.ratchets.tickReceiverRatchet(int(m[2].decode()))
        self.saveRatchets(sender)

    def DRDecaps(self, sender):
        """
        Method that decapsulates a new secret during the ratchet reset. First, we retrieve the ciphertexts, and our
        secret key. Then, we decapsulate the secret KEM value, and compute the secret DH value. Finally, we can generate
        the new secret and reset the ratchets.
        :param sender: the recipient name with whom the user has the conversation.
        :return:
        """
        ciphertext = pickle.loads(clientinterface.getPremessages(self.conn, self.username, sender))
        secretKey = iofile.getPrivateEkey(self.username, sender)
        sharedFrodoVal = self.fk.kem_decaps(secretKey, ciphertext)
        DHVal = clientinterface.getDHVal(self.conn, sender, self.username)
        self.loadMessageKeys(sender)
        sharedValue = diffiehellman.DiffieHellman(self.messageKeys.EKey.getPrivateKey(), DHVal)
        self.generateDRSecret(sender, sharedFrodoVal, sharedValue)

    def initRatchets(self, recipient):

        self.ratchets = doubleratchet.Ratchets(self.username, iofile.getSecretKey(self.username, recipient))

    def loadRatchets(self, recipient):
        self.ratchets = doubleratchet.load(self.username, recipient)

    def saveRatchets(self, recipient):
        self.ratchets.save(recipient)

    def clearMessages(self, sender):
        clientinterface.clearMessages(self.conn, self.username, sender)
