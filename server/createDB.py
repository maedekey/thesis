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

        self.cursor.execute("""
            CREATE TABLE contacts (
            username VARCHAR,
            friend VARCHAR
            );
        """)
        self.conn.commit()

        self.cursor.execute("""
                    CREATE TABLE diffiehellman (
                    sender VARCHAR,
                    computedvalue BIGINT,
                    receiver VARCHAR
                    );
                """)
        self.conn.commit()

        self.cursor.execute("""
                            CREATE TABLE frodokemkeys (
                            sender VARCHAR,
                            publickey bytea,
                            receiver VARCHAR,
                            ciphertext bytea
                            );
                        """)
        self.conn.commit()

        self.cursor.execute("""
                            CREATE TABLE identitykey (
                            username VARCHAR,
                            pqsignpkey bytea,
                            signpkey bytea
                            );
                        """)
        self.conn.commit()

        self.cursor.execute("""
                            CREATE TABLE keys (
                            sender VARCHAR,
                            ekey bytea,
                            skey bytea,
                            lkey bytea,
                            receiver VARCHAR,
                            fsvec bytea
                            );
                        """)
        self.conn.commit()

        self.cursor.execute("""
                            CREATE TABLE messages (
                            sendername VARCHAR,
                            receivername VARCHAR,
                            id BIGINT, 
                            message bytea,
                            nonce bytea,
                            read boolean, 
                            reset VARCHAR
                            );
                        """)
        self.conn.commit()

        self.cursor.execute("""
                            CREATE TABLE premessages (
                            sender VARCHAR,
                            premessage bytea,
                            receiver VARCHAR
                            );
                        """)
        self.conn.commit()

        self.cursor.execute("""
                            CREATE TABLE requests (
                            sender VARCHAR,
                            receiver VARCHAR,
                            status VARCHAR
                            );
                        """)
        self.conn.commit()

        self.cursor.execute("""
                            CREATE TABLE signature (
                            sender VARCHAR,
                            pqesign bytea,
                            pqssign bytea,
                            pqlsign bytea,
                            esign bytea,
                            ssign bytea,
                            lsign bytea,
                            receiver VARCHAR
                            );
                        """)
        self.conn.commit()

Database()
