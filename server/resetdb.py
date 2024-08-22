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
        self.resetAll()

    def resetAll(self):
        res = self.cursor.execute("delete from contacts")
        res = self.cursor.execute("delete from diffiehellman")
        res = self.cursor.execute("delete from frodokemkeys")
        res = self.cursor.execute("delete from identitykey")
        res = self.cursor.execute("delete from keys")
        res = self.cursor.execute("delete from messages")
        res = self.cursor.execute("delete from premessages")
        res = self.cursor.execute("delete from requests")
        res = self.cursor.execute("delete from signature")
        self.conn.commit()

db = Database()
