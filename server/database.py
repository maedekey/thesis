import psycopg2


class Database:
    def __init__(self):
        self.conn = psycopg2.connect(
            dbname="postgres",
            user="YOUR USERNAME",
            password="YOUR PASSWORD",
            host="localhost",
            port="5432"
        )
        self.cursor = self.conn.cursor()

    def addUserKeys(self, username, PQidKey, idKey):
        res = self.cursor.execute('INSERT INTO identitykey (username, pqsignpkey, signpkey) VALUES (%s, %s, %s)',
                                  (username, PQidKey, idKey))
        self.conn.commit()

    def addMessage(self, nonce, id, sendername, receivername, message):
        res = self.cursor.execute(
            'insert into messages (id, sendername, receivername, message, nonce, read, reset) VALUES (%s, %s, %s, '
            '%s, %s, %s, %s)', (id, sendername, receivername, message, nonce, False, False))
        self.conn.commit()

    def getMessages(self, receivername):
        res = self.cursor.execute('select * from messages where receivername = %s and read = %s and reset = %s',
                                  (receivername, False, "false"))
        rows = self.cursor.fetchall()
        res = self.cursor.execute('UPDATE messages SET read = %s WHERE receivername = %s',
                                  (True, receivername))
        return rows

    def updateIP(self, receivername, receiverip):
        res = self.cursor.execute('UPDATE messages SET receiverip = %s WHERE receivername = %s',
                                  (receiverip, receivername))
        self.conn.commit()

    def getIdKeys(self, username):
        res = self.cursor.execute('SELECT * FROM identitykey WHERE username = %s', (username,))
        row = self.cursor.fetchone()
        return row

    def addMessageKeys(self, sender, receiver, EKey, SKey, LKey, Svec):
        res = self.cursor.execute(
            'INSERT INTO keys (sender, receiver, ekey, skey, lkey, fsvec) VALUES(%s, %s, %s, %s, '
            '%s, %s)', (sender, receiver, EKey, SKey, LKey, Svec))
        self.conn.commit()

    def getMessageKeys(self, sender, receiver):
        res = self.cursor.execute('SELECT * FROM keys WHERE sender = %s AND receiver = %s', (sender, receiver))
        row = self.cursor.fetchone()
        return row

    def addRequest(self, sender, receiver):
        res = self.cursor.execute("INSERT INTO requests (sender, receiver, status) VALUES (%s, %s, %s)",
                                  (sender, receiver, "pending"))
        self.conn.commit()

    def updateRequest(self, status, sender, receiver):
        self.cursor.execute('UPDATE requests SET status = %s WHERE sender = %s AND receiver = %s',
                            (status, sender, receiver))
        self.conn.commit()

    def getValidatedRequests(self, sender):
        res = self.cursor.execute('SELECT receiver FROM requests WHERE sender = %s AND status = %s',
                                  (sender, "validated"))
        rows = self.cursor.fetchall()

        return rows

    def getRecipientValidatedRequests(self, sender):
        res = self.cursor.execute('SELECT sender FROM requests WHERE receiver = %s AND status = %s',
                                  (sender, "validated"))
        rows = self.cursor.fetchall()
        return rows

    def getRequests(self, receiver):
        res = self.cursor.execute('SELECT * FROM requests WHERE receiver = %s AND status = %s', (receiver, "pending"))
        rows = self.cursor.fetchall()
        return rows

    def addPremessage(self, sender, receiver, premessage):
        res = self.cursor.execute('INSERT INTO premessages (sender, receiver, premessage) VALUES (%s, %s, %s)',
                                  (sender, receiver, premessage))
        self.conn.commit()

    def getPremessages(self, sender, receiver):
        res = self.cursor.execute('SELECT premessage FROM premessages WHERE sender = %s AND receiver = %s',
                                  (sender, receiver))
        row = self.cursor.fetchone()
        return row[0]

    def addComputedValue(self, sender, computedValue, receiver):
        res = self.cursor.execute('INSERT INTO diffiehellman (sender, computedValue, receiver) VALUES (%s, %s, %s)',
                                  (sender, computedValue, receiver))
        self.conn.commit()

    def getComputedValue(self, sender, receiver):
        res = self.cursor.execute('SELECT computedvalue FROM diffiehellman WHERE sender = %s AND receiver = %s',
                                  (sender, receiver))
        row = self.cursor.fetchone()
        return row[0]

    def addSignatures(self, sender, pqesign, pqssign, pqlsign, esign, ssign, lsign, receiver):
        res = self.cursor.execute(
            'INSERT INTO signature (sender, pqesign, pqssign, pqlsign, esign, ssign, lsign, receiver) VALUES (%s, %s, %s, %s, '
            '%s, %s, %s, %s)', (sender, pqesign, pqssign, pqlsign, esign, ssign, lsign, receiver))
        self.conn.commit()

    def getSignatures(self, sender, receiver):
        res = self.cursor.execute('select * from signature WHERE sender = %s AND receiver = %s', (sender, receiver))
        row = self.cursor.fetchone()
        return row

    def getUser(self, username):
        res = self.cursor.execute('select * from address where username = %s', (username,))
        row = self.cursor.fetchone()
        return row

    def getContacts(self, username):
        res = self.cursor.execute('select friend from contacts where username = %s', (username,))
        rows = self.cursor.fetchall()
        return rows

    def addContact(self, username, friend):
        res = self.cursor.execute('INSERT INTO contacts (username, friend) VALUES (%s, %s)', (username, friend))
        self.conn.commit()

    def processValidatedRequests(self, sender, receiver):
        res = self.cursor.execute('UPDATE requests SET status = %s WHERE sender = %s AND receiver = %s',
                                  ("processed", sender, receiver))
        self.conn.commit()

    def updateMessageKeys(self, sender, receiver, EKey, Evec):
        res = self.cursor.execute('UPDATE keys SET ekey = %s, fevec = %s WHERE sender = %s AND receiver = %s',
                                  (EKey, Evec, sender, receiver))
        self.conn.commit()

    def resetMessage(self, sender, receiver):
        res = self.cursor.execute(
            'insert into messages (sendername, receivername, read, reset) VALUES (%s, %s, %s, '
            '%s)', (sender, receiver, False, "pending"))
        self.conn.commit()

    def resetDH(self, sender, receiver):
        res = self.cursor.execute(
            'delete FROM diffiehellman WHERE (sender = %s AND receiver = %s) or (sender = %s and receiver = %s)',
            (sender, receiver, receiver, sender))
        self.conn.commit()

    def resetPremessages(self, sender, receiver):
        res = self.cursor.execute('delete from premessages where (sender = %s AND receiver = %s)', (sender, receiver))
        if res == 0:
            res = self.cursor.execute('delete from premessages where (sender = %s AND receiver = %s)',
                                      (receiver, sender))
        self.conn.commit()

    def getFinishedResetMessage(self, sender, receiver):
        res = self.cursor.execute(
            "select * from messages where sendername = %s AND receivername = %s and read = %s and reset = %s",
            (sender, receiver, True, "finished")),
        row = self.cursor.fetchone()
        if len(row) > 0:
            res = self.cursor.execute(
                "delete from messages where reset = %s, sender = %s, receiver = %s, read = %s",
                ("finished", sender, receiver, True, "accepted"))
            self.conn.commit()

    def getUpdatedResetMessage(self, sender, receiver):
        ret = False
        res = self.cursor.execute(
            "select * from messages where sendername = %s AND receivername = %s and reset = %s",
            (sender, receiver, "accepted")),
        row = self.cursor.fetchone()
        if row is not None:
            if len(row) > 0:
                res = self.cursor.execute(
                    "update messages set reset = %s where sendername = %s AND receivername = %s and read = %s and "
                    "reset =%s", ("finished", sender, receiver, True, "accepted"))
                self.conn.commit()
            ret = True
        return ret

    def getResetMessage(self, sender, receiver):
        res = self.cursor.execute("select * from messages where sendername = %s AND receivername = %s and "
                                  "reset = %s", (sender, receiver, "pending"))
        row = self.cursor.fetchone()
        if row is None:
            res = self.cursor.execute("select * from messages where sendername = %s AND receivername = %s and "
                                      "reset = %s", (receiver, sender, "pending"))
            row = self.cursor.fetchone()
        if row is not None:
            if len(row) > 0:
                res = self.cursor.execute(
                    "update messages set reset = %s where sendername = %s AND receivername = %s"
                    "and reset = %s", ("accepted", sender, receiver, "pending"))
                self.conn.commit()
                ret = True
            else:
                ret = False
        else:
            ret = False
        return ret

    def addFrodoKeys(self, sender, receiver, publickey):
        res = self.cursor.execute('INSERT INTO frodokemkeys (publickey, sender, receiver) VALUES (%s, %s, %s)',
                                  (publickey, sender, receiver))
        self.conn.commit()

    def addFrodoCt(self, sender, receiver, ct):
        res = self.cursor.execute('update frodokemkeys set ciphertext = %s WHERE sender = %s AND receiver = %s',
                                  (ct, sender, receiver))
        self.conn.commit()

    def updateFrodoKeys(self, sender, receiver, publickey):
        res = self.cursor.execute('UPDATE keys SET ekey = %s WHERE sender = %s AND receiver = %s',
                                  (publickey, sender, receiver))
        self.conn.commit()

    def getEFrodoKey(self, sender, receiver):
        res = self.cursor.execute("select ekey from keys WHERE sender = %s AND receiver = %s",
                                  (sender, receiver))
        rows = self.cursor.fetchone()
        return rows

    def getFrodoCt(self, sender, receiver):
        res = self.cursor.execute("select ciphertext from frodokemkeys WHERE sender = %s AND receiver = %s",
                                  (sender, receiver))
        row = self.cursor.fetchone()
        return row

    def isSender(self, sender, receiver):
        ret = None
        res = self.cursor.execute('SELECT * FROM requests WHERE sender = %s and receiver = %s and status = %s',
                                  (sender, receiver, "processed"))
        rows = self.cursor.fetchone()
        if rows is not None:
            if len(rows) > 0:
                ret = True
            else:
                ret = False
        else:
            ret = False
        return ret

    def countMessages(self, user1, user2):
        self.cursor.execute(
            "SELECT COUNT(*) AS message_count FROM messages WHERE (sendername = %s AND receivername = %s ) OR (sendername = %s AND receivername = %s)",
            (user1, user2, user2, user1)
        )
        message_count_row = self.cursor.fetchone()
        if message_count_row is not None:
            message_count = message_count_row[0]  # Access the first element (count)
            return message_count
        else:
            return 0

    def clearMessages(self, user1, user2):
        res = self.cursor.execute(
            'delete FROM messages WHERE (sender = %s AND receiver = %s) or (sender = %s and receiver = %s)',
            (user1, user2, user2, user1))
        self.conn.commit()
