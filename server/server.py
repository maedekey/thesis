import socket

import database

import threading




def processContacts(contacts):
    res = b'getContacts '
    for contact in contacts:
        res += contact[0].encode()
        res += b"SEPARATOR"
    res += b"END"
    return res


def processReceivedRequests(requests):
    res = b'getRequests '
    for request in requests:
        res += request[0].encode('utf-8')
        res += b' '
        res += request[2].encode('utf-8')
        res += b'SEPARATOR'
    res += b"END"
    return res


def processValidatedRequests(flag, requests):
    res = flag
    for request in requests:
        res += request[0].encode("utf-8")
        res += b"SEPARATOR"

    res += b"END"
    return res


def processSignatures(signatures):
    res = b"getSignatures "
    for i in range(1, 7):
        res += signatures[i]
        res += b"SEPARATOR"
    res += b"END"
    return res


def processMessageKeys(messageKeys):
    res = b"getMessageKeys "
    for i in range(len(messageKeys)):
        if i != 0 and i != 4:
            res += messageKeys[i]
            res += b"SEPARATOR"
    res += b"END"
    return res


def processPremessage(premessage):
    res = b"getPremessage " + premessage + b"SEPARATOR" + b"END"
    return res


def processMessages(messages):
    res = b"getMessages "

    for message in messages:
        for i in range(len(message) - 2):
            if i == 2:
                res += str(message[i]).encode()
            elif i == 4 or i == 3:
                res += message[i]
            else:
                res += message[i].encode()
            res += b"BLOCK"
        res += b"SEPARATOR"
    res += b"END"
    return res


def processGetFrodoCt(frodoCt):
    flag = b"getFrodoCt "
    if frodoCt is None:
        frodoCt = 0
    message = flag + frodoCt + b"SEPARATOR" + b"END"
    return message


class ClientThread(threading.Thread):
    def __init__(self, conn, addr, db):
        super().__init__()
        print("on a crée une nouvelle co")
        self.conn = conn
        self.addr = addr
        self.db = db
        self.handleClient()

    def processData(self, data):
        data = data.split("SEPARATOR")[:-1]
        data = list(filter(None, data))
        if data[0] == "getIdKeys":
            pubKey = self.db.getIdKeys(data[1])
            tosend = b"getIdKeys" + b" " + pubKey[1] + b"SEPARATOR" + pubKey[2] + b"END"
            self.conn.sendall(tosend)
        elif data[0] == "checkRequests":
            validatedRequests = self.db.getValidatedRequests(data[1])
            flag = b"checkRequests "
            tosend = processValidatedRequests(flag, validatedRequests)
            self.conn.sendall(tosend)
        elif data[0] == "checkReceivedRequests":
            flag = b'checkReceivedRequests '
            validatedRequests = self.db.getRecipientValidatedRequests(data[1])
            tosend = processValidatedRequests(flag, validatedRequests)
            self.conn.sendall(tosend)

        elif data[0] == "getSignatures":
            signatures = self.db.getSignatures(data[1], data[2])
            tosend = processSignatures(signatures)
            self.conn.sendall(tosend)
        elif data[0] == "getMessageKeys":
            messageKeys = self.db.getMessageKeys(data[1], data[2])
            tosend = processMessageKeys(messageKeys)
            self.conn.sendall(tosend)
        elif data[0] == "getRequests":
            requests = self.db.getRequests(data[1])
            tosend = processReceivedRequests(requests)
            self.conn.sendall(tosend)
        elif data[0] == "getDHVal":
            dhval = self.db.getComputedValue(data[1], data[2])
            tosend = "getDHVal " + str(dhval) + "END"
            self.conn.sendall(tosend.encode())
        elif data[0] == "getPremessage":
            premessage = self.db.getPremessages(data[1], data[2])
            tosend = processPremessage(premessage)
            self.conn.sendall(tosend)
        elif data[0] == "UpdateRequest":
            self.db.updateRequest(data[1], data[2], data[3])
        elif data[0] == "addDHVal":
            self.db.addComputedValue(data[1], int(data[2]), data[3])
        elif data[0] == "addRequest":
            self.db.addRequest(data[1], data[2])
        elif data[0] == "getMessages":
            messages = self.db.getMessages(data[1])
            tosend = processMessages(messages)
            self.conn.sendall(tosend)
        elif data[0] == "getContacts":
            contacts = self.db.getContacts(data[1])
            tosend = processContacts(contacts)
            self.conn.sendall(tosend)
        elif data[0] == "addContact":
            self.db.addContact(data[1], data[2])
        elif data[0] == "processValidatedRequests":
            self.db.processValidatedRequests(data[1], data[2])
        elif data[0] == "getMessageCount":
            flag = b'getMessageCount '
            count = str(self.db.countMessages(data[1], data[2]))
            tosend = flag + count.encode() + b"END"
            self.conn.sendall(tosend)
        elif data[0] == 'isSender':
            flag = b'isSender '
            sender = self.db.isSender(data[1], data[2])
            tosend = flag + str(sender).encode() + b'END'
            self.conn.sendall(tosend)
        elif data[0] == "resetMessage":
            self.db.resetMessage(data[1], data[2])
        elif data[0] == "getResetMessage":
            flag = b"getResetMessage "
            reset = self.db.getResetMessage(data[1], data[2])
            tosend = flag + str(reset).encode() + b'END'
            self.conn.sendall(tosend)
        elif data[0] == "resetDH":
            self.db.resetDH(data[1], data[2])
        elif data[0] == "resetPremesages":
            self.db.resetPremessages(data[1], data[2])
        elif data[0] == "getResetDecapsFlag":
            flag = b"getResetDecapsFlag "
            reset = self.db.getUpdatedResetMessage(data[1], data[2])
            tosend = flag + str(reset).encode() + b'END'
            self.conn.sendall(tosend)
        elif data[0] == "getEFrodoKey":
            flag = b"getEFrodoKey "
            frodokey = self.db.getEFrodoKey(data[1], data[2])[0]
            tosend = flag + frodokey + b'END'
            self.conn.sendall(tosend)
        elif data[0] == "getFrodoCt":
            frodoCt = self.db.getFrodoCt(data[1], data[2])
            tosend = processGetFrodoCt(frodoCt[0])
            self.conn.sendall(tosend)
        elif data[0] == "clearMsgFlag":
            self.db.clearMessages(data[1], data[2])


    def getUser(self, username):
        ipaddr = self.db.getUser(username)
        return ipaddr[1]

    def handleClient(self):
        print(f'Connected by {self.addr}')
        counter = 0
        try:
            received = b''
            while True:
                data = self.conn.recv(1024)
                if not data:
                    break
                largemessage = data.split(b"SEPARATOR")[0]
                if largemessage.decode() == "LARGEMESSAGE":

                    received += data.split(b"SEPARATOR", 1)[1]
                    while b'END' not in data:
                        data = self.conn.recv(1024)
                        received += data
                    if received.split(b'SEPARATOR')[0].decode() == "addUserKeys":
                        self.processUserKeys(received)
                        received = b''
                        continue
                    elif received.split(b'SEPARATOR')[0].decode() == "addSignatures":
                        self.processSignatures(received)
                        received = b''
                        continue
                    elif received.split(b'SEPARATOR')[0].decode() == "addPremessage":
                        self.processReceivedPremessage(received)
                        received = b''
                        continue
                    elif received.split(b'SEPARATOR')[0].decode() == "addMessageKeys":
                        self.processMessageKeys(received)
                        received = b''
                        continue
                    elif received.split(b'SEPARATOR')[0].decode() == "sendMessage":
                        self.processAddMessages(received)
                        received = b''
                        continue
                    elif received.split(b'SEPARATOR')[0].decode() == "updateMessageKeys":
                        self.processUpdateMessageKeys(received)
                        received = b''
                        continue
                    elif received.split(b'SEPARATOR')[0].decode() == "saveFrodokey":
                        self.processAddFrodoKey(received)
                        received = b''
                        continue
                    elif received.split(b'SEPARATOR')[0].decode() == "updateEFrodokey":
                        self.processUpdateEFrodoKey(received)
                        received = b''
                        continue
                    elif received.split(b'SEPARATOR')[0].decode() == "addFrodoCt":
                        self.processAddFrodoCt(received)
                        received = b''
                        continue
                    else:
                        received = received.decode("utf-8")
                else:
                    received = data.decode("utf-8")
                self.processData(received)
                received = b''

            self.conn.close()
        except ConnectionResetError:
            print(f'Client {self.addr} disconnected')

    def processSignatures(self, received):
        data = received.split(b"SEPARATOR")
        self.db.addSignatures(data[1].decode(), data[2], data[3], data[4], data[5], data[6], data[7], data[8].decode())

    def processUserKeys(self, received):
        data = received.split(b'SEPARATOR')
        self.db.addUserKeys(data[1].decode(), data[2], data[3])

    def processReceivedPremessage(self, received):
        data = received.split(b'SEPARATOR')
        self.db.addPremessage(data[1].decode(), data[2].decode(), data[3])

    def processMessageKeys(self, received):
        data = received.split(b'SEPARATOR')
        self.db.addMessageKeys(data[1].decode(), data[2].decode(), data[3], data[4], data[5], data[6])

    def processAddMessages(self, received):
        data = received.split(b'SEPARATOR')
        self.db.addMessage(data[1], int(data[2].decode()), data[3].decode(), data[4].decode(), data[5])

    def processUpdateMessageKeys(self, received):
        data = received.split(b'SEPARATOR')
        self.db.updateMessageKeys(data[1].decode(), data[2].decode(), data[3], data[4])

    def processAddFrodoKey(self, received):
        data = received.split(b'SEPARATOR')
        self.db.addFrodoKeys(data[1].decode(), data[2].decode(), data[3])

    def processUpdateEFrodoKey(self, received):
        data = received.split(b'SEPARATOR')
        self.db.updateFrodoKeys(data[1].decode(), data[2].decode(), data[3])

    def processAddFrodoCt(self, received):
        data = received.split(b'SEPARATOR')
        self.db.addFrodoCt(data[1].decode(), data[2].decode(), data[3])


class Server:
    def __init__(self):
        self.host = 'localhost'
        self.port = 8080
        self.db = database.Database()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.host, self.port))
            s.listen()
            print(f'Server listening on {self.host}:{self.port}')
            while True:
                conn, addr = s.accept()
                print("on a accepté")
                client_thread = ClientThread(conn, addr, self.db)
                client_thread.start()


def translateToAnswer(received):
    res = ""
    for word in received:
        res += word
        res += " "
    return res


server = Server()
