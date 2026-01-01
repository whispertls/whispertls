from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import os
import secrets
import pysqlcipher3.dbapi2 as sqlcipher
import traceback

class DoubleRatchetDB:
    def __init__(self,database_name : str, masterkey : bytes):
        self.conn = None
        self.cursor = None
        self.masterkey = masterkey
        self.database_name = database_name
        if not self.connect():
            raise Exception(f"Failed to connect to database: {database_name}")

    def rowdict(cursor, row):
        return {col[0]: row[i] for i, col in enumerate(cursor.description)}
        
    def assert_sqlcipher_linked(cur):
        v = cur.execute("PRAGMA cipher_version;").fetchone() 
        if v is None or v['cipher_version'] == '':
            raise RuntimeError("is sqlcipher but no cipher_version")

    def connect(self) -> bool:
        try:
            self.conn = sqlcipher.connect(self.database_name)
            self.conn.row_factory = DoubleRatchetDB.rowdict
            self.cursor = self.conn.cursor()
            self.cursor.execute("PRAGMA key = '{}';".format(self.masterkey.hex()))
            DoubleRatchetDB.assert_sqlcipher_linked(self.cursor)
            self.cursor.execute("CREATE TABLE IF NOT EXISTS messages (id TEXT PRIMARY KEY,publickey BLOB NOT NULL,n INTEGER NOT NULL,mk BLOB);")
            self.conn.commit()      
            return True
        except Exception as e:
            print(f"connect error: {e}")
            tb = e.__traceback__
            for frame in traceback.extract_tb(tb):
                print(frame.filename, frame.lineno, frame.name, frame.line)
            return False
    
    def put_message(self, publickey, n, mk) -> bool:
        try:
            id =  HKDF(algorithm=hashes.SHA256(),length=8,salt=None,info=n.to_bytes(2, "big")).derive(publickey).hex()
            self.cursor.execute('INSERT INTO messages (id, publickey, n, mk) VALUES (?, ?, ?, ?)', (id, publickey, n, mk))
            self.conn.commit()
            return True
        except Exception as e:
            print(f"Error put_message: {e}")
            return False

    def mkskipped(self, publickey, n) -> dict:
        try:
            self.cursor.execute('select id, mk from messages where publickey = ? and  n = ? ', (publickey, n))
            result = self.cursor.fetchone()
            return result
        except Exception as e:
            print(f"Error mkskipped: {e}")
            return None
           
    def del_allmessages(self) -> bool:
        try:
            #we must first overwrite the current row
            self.cursor.execute("UPDATE messages set publickey = ? , n = ? ,mk = ?",(os.urandom(32),secrets.randbelow(255),os.urandom(32)))
            self.conn.commit()
            #and the delete it
            self.cursor.execute('DELETE FROM messages')
            self.conn.commit()
            self.vacuum_database()
            return self.cursor.rowcount > 0
        except Exception as e:
            print(f"Error del_allmessages: {e}")
            return False
            
    def del_message(self, id)  -> bool:
        try:
            #we must first overwrite the current row
            self.cursor.execute("UPDATE messages set publickey = ? , n = ? ,mk = ? where id = ?",(os.urandom(32),secrets.randbelow(255),os.urandom(32),id))
            self.conn.commit()
            #and the delete it
            self.cursor.execute('DELETE FROM messages WHERE id = ?', (id,))
            self.conn.commit()
            self.vacuum_database()
            return self.cursor.rowcount > 0
        except Exception as e:
            print(f"Error del_message: {e}")
            return False
    
    def vacuum_database(self)  -> bool:
        try:
            self.cursor.execute('VACUUM')
            self.conn.commit()
            return True
        except Exception as e:
            print(f"Error vacuum_database: {e}")
            return False
    
    def close(self):
        try:
            self.conn.close()
        except:
            pass