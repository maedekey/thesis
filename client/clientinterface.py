import pickle
import time

from Crypto.Cipher import AES
import clientManager


def getClientMessageKeys(conn, user1, user2):
    messageKeysFlag = "getMessageKeys"
    message = messageKeysFlag + "SEPARATOR" + user1 + "SEPARATOR" + user2 + "SEPARATOR" + "END"
    clientManager.sendToServer(conn, message)
    messageKeys = clientManager.receive(conn, messageKeysFlag)
    if messageKeys is not None:
        messageKeys = messageKeys.split(b'SEPARATOR')[:-1]
    else:
        messageKeys = []
    return messageKeys


def getPremessages(conn, sender, receiver):
    getPremFlag = "getPremessage"
    message = getPremFlag + "SEPARATOR" + sender + "SEPARATOR" + receiver + "SEPARATOR" + "END"
    clientManager.sendToServer(conn, message)

    received = clientManager.receive(conn, getPremFlag)
    return received


def addPremessage(conn, sender, username, bytesCt):
    addPremFlag = "addPremessage"
    clientManager.transformToLargeMessage(conn, ["LARGEMESSAGE".encode(), addPremFlag.encode(), sender.encode(),
                                                 username.encode(), bytesCt])


def getDHVal(conn, recipient, username):
    getDHFlag = "getDHVal"
    message = getDHFlag + "SEPARATOR" + recipient + "SEPARATOR" + username + "SEPARATOR" + "END"
    clientManager.sendToServer(conn, message)
    received = clientManager.receive(conn, getDHFlag)
    dhval = int(received.decode())
    return dhval


def addRequest(conn, username, receiver):
    addReqFlag = "addRequest"
    message = addReqFlag + "SEPARATOR" + username + "SEPARATOR" + receiver + "SEPARATOR" + "END"
    clientManager.sendToServer(conn, message)


def addComputedValue(conn, username, computedValue, recipient):
    DHflag = b"addDHVal"
    message = DHflag + b"SEPARATOR" + username.encode() + b"SEPARATOR" + str(
        computedValue).encode() + b"SEPARATOR" + recipient.encode() + b"SEPARATOR" + b"END"
    clientManager.sendAsBytes(conn, message)


def addSignatures(conn, username, PQEsign, PQSsign, PQLsign, Esign, Ssign, Lsign, recipient):
    signatureFlag = "addSignatures"
    clientManager.transformToLargeMessage(conn, ["LARGEMESSAGE".encode(), signatureFlag.encode(), username.encode(),
                                                 PQEsign, PQSsign, PQLsign, Esign, Ssign, Lsign, recipient.encode()])


def updateRequest(conn, status, sender, receiver):
    messageFlag = "UpdateRequest"
    message = messageFlag + "SEPARATOR" + status + "SEPARATOR" + sender + "SEPARATOR" + receiver + "SEPARATOR" + "END"
    clientManager.sendToServer(conn, message)


def getValidatedRequests(conn, username):
    flag = "checkRequests"
    message = flag + "SEPARATOR" + username + "SEPARATOR" + "END"
    clientManager.sendToServer(conn, message)
    validatedRequests = clientManager.receive(conn, flag)
    if validatedRequests is not None:
        validatedRequests = validatedRequests.decode()
        validatedRequests = validatedRequests.split("SEPARATOR")[:-1]
    else:
        validatedRequests = []
    return validatedRequests


def processValidatedRequest(username, conn, recipient):
    proValReqFlag = "processValidatedRequests"
    message = proValReqFlag + "SEPARATOR" + username + "SEPARATOR" + recipient + "SEPARATOR" + "END"
    clientManager.sendToServer(conn, message)
    time.sleep(0.2)


def getContacts(conn, username):
    contactFlag = "getContacts"
    message = contactFlag + "SEPARATOR" + username + "SEPARATOR" + "END"
    clientManager.sendToServer(conn, message)
    contacts = clientManager.receive(conn, contactFlag)
    contacts = contacts.split(b"SEPARATOR")
    for i in range(len(contacts)):
        contacts[i] = contacts[i].decode()
    return contacts


def getReceivedRequests(conn, username):
    requestFlag = "getRequests"
    message = requestFlag + "SEPARATOR" + username + "SEPARATOR" + "END"
    clientManager.sendToServer(conn, message)
    requests = clientManager.receive(conn, requestFlag)
    requests = list(filter(None, requests.split(b"SEPARATOR")))
    return requests


def addContact(conn, username, recipient):
    addContactFlag = "addContact"
    message = addContactFlag + "SEPARATOR" + username + "SEPARATOR" + recipient + "SEPARATOR" + "END"
    clientManager.sendToServer(conn, message)
    time.sleep(0.2)

    message = addContactFlag + "SEPARATOR" + recipient + "SEPARATOR" + username + "SEPARATOR" + "END"
    clientManager.sendToServer(conn, message)
    time.sleep(0.2)


def getIdKeys(conn, recipient):
    message = "getIdKeys" + "SEPARATOR" + recipient + "SEPARATOR" + "END"
    clientManager.sendToServer(conn, message)
    received = clientManager.receive(conn, "getIdKeys")
    if received is not None:
        received = received.split(b'SEPARATOR')
    else:
        received = []
    return received


def clGetMessages(conn, username):
    getMessFlag = "getMessages"
    message = getMessFlag + "SEPARATOR" + username + "SEPARATOR" + "END"
    clientManager.sendToServer(conn, message)
    received = clientManager.receive(conn, getMessFlag)
    messages = received.split(b"SEPARATOR")[:-1]
    return messages


def getSignatures(conn, sender, receiver):
    getsignaturesFlag = "getSignatures"
    message = getsignaturesFlag + "SEPARATOR" + sender + "SEPARATOR" + receiver + "SEPARATOR" + "END"
    clientManager.sendToServer(conn, message)
    signatures = clientManager.receive(conn, getsignaturesFlag)
    return signatures


def savePublicKeys(conn, username, publicKey):
    clientManager.transformToLargeMessage(conn,
                                          ["LARGEMESSAGE".encode(), "addUserKeys".encode(), username.encode(),
                                           pickle.dumps(publicKey[0]), pickle.dumps(publicKey[1])])


def sendMessage(conn, ratchets, username, message, receiver, ctr):
    sendMessFlag = b"sendMessage"

    cipher = AES.new(ratchets.getSenderKey(),
                     AES.MODE_EAX)

    nonce = cipher.nonce
    ciphertext = cipher.encrypt(message.encode())
    clientManager.transformToLargeMessage(conn, [
        b"LARGEMESSAGE" + b"SEPARATOR" + sendMessFlag + b"SEPARATOR" + nonce + b"SEPARATOR" + str(
            ctr).encode() + b"SEPARATOR" + username.encode() + b"SEPARATOR" + receiver.encode() + b"SEPARATOR" + ciphertext + b"SEPARATOR" + b"END"])

    ratchets.tickSenderRatchet(ctr)
    ratchets.save(receiver)


def resetMessage(conn, sender, receiver):
    resetFlag = "resetMessage"
    message = resetFlag + "SEPARATOR" + sender + "SEPARATOR" + receiver + "SEPARATOR" + "END"
    clientManager.sendToServer(conn, message)
    time.sleep(0.2)


def getResetMessage(conn, sender, receiver):
    getResetFlag = "getResetMessage"
    message = getResetFlag + "SEPARATOR" + sender + "SEPARATOR" + receiver + "SEPARATOR" + "END"
    clientManager.sendToServer(conn, message)
    reset = clientManager.receive(conn, getResetFlag)
    return reset.decode()


def getDecapsResetMessage(conn, sender, receiver):
    getResetDecapsFlag = "getResetDecapsFlag"
    message = getResetDecapsFlag + "SEPARATOR" + sender + "SEPARATOR" + receiver + "SEPARATOR" + "END"
    clientManager.sendToServer(conn, message)
    reset = clientManager.receive(conn, getResetDecapsFlag)
    return reset.decode() == "True"


def getMessageCount(conn, username, recipient):
    getMessageCountFlag = "getMessageCount"
    message = getMessageCountFlag + "SEPARATOR" + username + "SEPARATOR" + recipient + "SEPARATOR" + "END"
    clientManager.sendToServer(conn, message)
    received = clientManager.receive(conn, getMessageCountFlag)
    return int(received.decode())


def isSender(conn, username, sender):
    getSorRFlag = "isSender"
    message = getSorRFlag + "SEPARATOR" + username + "SEPARATOR" + sender + "SEPARATOR" + "END"
    clientManager.sendToServer(conn, message)
    received = clientManager.receive(conn, getSorRFlag)
    return bool(received.decode())


def resetDH(conn, username, sender):
    resetDhFlag = "resetDH"
    message = resetDhFlag + "SEPARATOR" + username + "SEPARATOR" + sender + "SEPARATOR" + "END"
    clientManager.sendToServer(conn, message)
    time.sleep(0.2)


def resetPremessage(conn, username, sender):
    resetPremessagesFlag = "resetPremesages"
    message = resetPremessagesFlag + "SEPARATOR" + username + "SEPARATOR" + sender + "SEPARATOR" + "END"
    clientManager.sendToServer(conn, message)
    time.sleep(0.2)


def saveFrodoKey(conn, username, receiver, apk):
    saveFrodoKeyFlag = "saveFrodokey"
    clientManager.transformToLargeMessage(conn, ["LARGEMESSAGE".encode(), saveFrodoKeyFlag.encode(), username.encode(),
                                                 receiver.encode(), pickle.dumps(apk)])


def updateEFrodoKey(conn, username, receiver, apk):
    saveFrodoKeyFlag = "updateEFrodokey"
    clientManager.transformToLargeMessage(conn, ["LARGEMESSAGE".encode(), saveFrodoKeyFlag.encode(), username.encode(),
                                                 receiver.encode(), pickle.dumps(apk)])


def getEFrodoKey(conn, sender, receiver):
    getEFrodoFlag = "getEFrodoKey"
    message = getEFrodoFlag + "SEPARATOR" + sender + "SEPARATOR" + receiver + "SEPARATOR" + "END"
    clientManager.sendToServer(conn, message)
    key = clientManager.receive(conn, getEFrodoFlag)
    return pickle.loads(key)


def addFrodoCt(conn, sender, receiver, ct):
    addFrodoCtFlag = "addFrodoCt"
    clientManager.transformToLargeMessage(conn, ["LARGEMESSAGE".encode(), addFrodoCtFlag.encode(), sender.encode(),
                                                 receiver.encode(), ct])
    time.sleep(0.2)


def getFrodoCt(conn, sender, receiver):
    getFrodoCtFlag = "getFrodoCt"
    message = getFrodoCtFlag + "SEPARATOR" + sender + "SEPARATOR" + receiver + "SEPARATOR" + "END"
    clientManager.sendToServer(conn, message)
    ct = clientManager.receive(conn, getFrodoCtFlag)
    if ct != b'0':
        return pickle.loads(ct)
    else:
        return None


def clearMessages(conn, username, sender):
    clearMessagesFlag = "clearMsgFlag"
    message = clearMessagesFlag + "SEPARATOR" + username + "SEPARATOR" + sender + "SEPARATOR" + "END"
    clientManager.sendToServer(conn, message)
    time.sleep(0.2)
