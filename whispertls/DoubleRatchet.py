#import asyncio
import json
import secrets
import pysqlcipher3.dbapi2 as sqlcipher
import traceback
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from whispertls.MasterKey import MasterKey
import os

class DRDatabase:
    def __init__(self,database_name : str, masterkey : bytes,error_handler_callback = None):
        #print("Database name",database_name,masterkey.hex())
        self.conn = None
        self.cursor = None
        self.masterkey = masterkey
        self.database_name = database_name
        if error_handler_callback == None:
            self.display_error = print
        else:
            self.display_error = error_handler_callback

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
            self.conn.row_factory = DRDatabase.rowdict
            self.cursor = self.conn.cursor()
            self.cursor.execute("PRAGMA key = '{}';".format(self.masterkey.hex()))
            DRDatabase.assert_sqlcipher_linked(self.cursor)
            self.cursor.execute("CREATE TABLE IF NOT EXISTS messages (id TEXT PRIMARY KEY,publickey BLOB NOT NULL,n INTEGER NOT NULL,mk BLOB);")
            self.cursor.execute("CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY, state TEXT);")
            self.conn.commit()
            return True
        except Exception as e:
            self.display_error(f"connect error: {e}")
            tb = e.__traceback__
            for frame in traceback.extract_tb(tb):
                errorline = "{} {} {} {}".format(frame.filename, frame.lineno, frame.name, frame.line)
                self.display_error(errorline)
            return False
    
    def is_stateready(self):
        self.cursor.execute("SELECT count(*) as counter from state;")
        result = self.cursor.fetchone()
        return result['counter'] > 0

    def get_state(self):
        self.cursor.execute("SELECT s.state from state s where id = 1;")
        result = self.cursor.fetchone()
        return result['state']
    
    def put_message(self, publickey, n, mk) -> bool:
        try:
            id =  HKDF(algorithm=hashes.SHA256(),length=8,salt=None,info=n.to_bytes(2, "big")).derive(publickey).hex()
            self.cursor.execute('INSERT INTO messages (id, publickey, n, mk) VALUES (?, ?, ?, ?);', (id, publickey, n, mk))
            self.conn.commit()
            return True
        except Exception as e:
            self.display_error(f"Error put_message: {e}")
            return False

    def save_state(self,state : str) -> bool:
        try:
            self.cursor.execute("INSERT OR REPLACE INTO state (id, state) VALUES (1, ? );",(state,))
            affected_rows = self.cursor.rowcount
            self.conn.commit()
            return affected_rows > 0
        except Exception as e:
            self.display_error(f"Error save_state: {e}")
            return False

    def mkskipped(self, publickey, n) -> dict:
        try:
            self.cursor.execute('select id, mk from messages where publickey = ? and  n = ?;', (publickey, n))
            #print(self.database_name,"mkskipped",publickey.hex(),n,self.cursor.rowcount)
            result = self.cursor.fetchone()
            return result
        except Exception as e:
            self.display_error(f"Error mkskipped: {e}")
            return None
           
    def del_allmessages(self) -> bool:
        try:
            #we must first overwrite the current row
            self.cursor.execute("UPDATE messages set publickey = ? , n = ? ,mk = ?;",(os.urandom(32),secrets.randbelow(255),os.urandom(32)))
            self.conn.commit()
            #and the delete it
            self.cursor.execute('DELETE FROM messages;')
            self.conn.commit()
            self.vacuum_database()
            return self.cursor.rowcount > 0
        except Exception as e:
            self.display_error(f"Error del_allmessages: {e}")
            return False
            
    def del_message(self, id)  -> bool:
        try:
            #we must first overwrite the current row
            self.cursor.execute("UPDATE messages set publickey = ? , n = ? ,mk = ? where id = ?;",(os.urandom(32),secrets.randbelow(255),os.urandom(32),id))
            self.conn.commit()
            #and the delete it
            self.cursor.execute('DELETE FROM messages WHERE id = ?;', (id,))
            self.conn.commit()
            self.vacuum_database()
            return self.cursor.rowcount > 0
        except Exception as e:
            self.display_error(f"Error del_message: {e}")
            return False
    
    def vacuum_database(self)  -> bool:
        try:
            self.cursor.execute('VACUUM;')
            self.conn.commit()
            return True
        except Exception as e:
            self.display_error(f"Error vacuum_database: {e}")
            return False
    
    def close(self):
        try:
            self.conn.close()
        except:
            pass

class DoubleRatchetHeader:
    def __init__(self,header: bytes):
        self.dh_bytes = header[0:32]
        self.dh = x25519.X25519PublicKey.from_public_bytes(header[0:32])
        self.n  = int.from_bytes(header[32:34], "big")
        self.pn  = int.from_bytes(header[34:36], "big")
        
class DoubleRatchet:
    def __init__(self,contact=None,password=None,error_handler_callback = None):
        self.db = None
        if error_handler_callback == None:
            self.display_error = print
        else:
            self.display_error = error_handler_callback
        state_dict = None
        if password is not None and contact is not None:
            db_file = ".db/"+contact + ".db"
            key_file = ".db/"+contact +".key"
            self.db_key = MasterKey(password.encode(),file=key_file)
            self.db = DRDatabase(database_name = db_file,masterkey=self.db_key.masterkey,error_handler_callback=self.display_error)
        
        #self.display_error("DoubleRatchet is_stateready {}".format(self.db.is_stateready()))
        
        if self.db and self.db.is_stateready():
            state_dict_str = self.db.get_state()
            #self.display_error("DoubleRatchet get_state {}".format(state_dict_str[:20]))
            state_dict = json.loads(state_dict_str)
        else:
            state_dict = DoubleRatchet.GetEmptyState()
            
        self.DHs = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(state_dict['DHs']))
        self.DHs_public =  self.DHs.public_key()
        self.DHr = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(state_dict['DHr']))
        self.RK = bytes.fromhex(state_dict['RK'])
        self.CKs = bytes.fromhex(state_dict['CKs'])
        self.CKr = bytes.fromhex(state_dict['CKr'])
        self.Ns = state_dict['Ns']
        self.Nr = state_dict['Nr']
        self.PN = state_dict['PN']
        #self.print_state()
                
    def generate_dh():
        key = x25519.X25519PrivateKey.generate()
        return key
    
    def dh(self):
        secret = self.DHs.exchange(self.DHr)
        return secret
        
    def kdf_rk(rk,dh_out):
        kdf_output = HKDF( 
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=dh_out,
        ).derive(rk)
        message_key = kdf_output[:32]
        next_chain_key = kdf_output[32:64]
        return message_key, next_chain_key

    def kdf_ck(ck):
        if ck is None:
            raise ValueError("Chain key cannot be None")
        kdf_output = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=b"whispertls",
        ).derive(ck)
        message_key = kdf_output[:32]
        next_chain_key = kdf_output[32:]
        return message_key, next_chain_key

    def header(dh_public, pn, n):
        header = bytearray(36)
        header[0:32] = dh_public.public_bytes_raw()  # Always 32 bytes
        header[32:34] = n.to_bytes(2, "big")
        header[34:36] = pn.to_bytes(2, "big")
        return bytes(header)

    def encrypt(mk, plaintext : bytes, associated_data : bytes ):
        aesgcm = AESGCM(mk)
        nonce = HKDF(algorithm=hashes.SHA256(),length=12,salt=None,info=b"nonce").derive(mk)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
        return ciphertext

    def decrypt(mk, ciphertext : bytes, associated_data : bytes):
        aesgcm = AESGCM(mk)
        nonce = HKDF(algorithm=hashes.SHA256(),length=12,salt=None,info=b"nonce").derive(mk)
        return aesgcm.decrypt(nonce, ciphertext, associated_data)
    
    def GetEmptyState() -> dict:
        return {
            'DHs' : '0000000000000000000000000000000000000000000000000000000000000000',
            'DHr' : '0000000000000000000000000000000000000000000000000000000000000000',
            'RK' : '0000000000000000000000000000000000000000000000000000000000000000',
            'CKs' : '0000000000000000000000000000000000000000000000000000000000000000',
            'CKr' : '0000000000000000000000000000000000000000000000000000000000000000',
            'Ns' : 0,
            'Nr' : 0,
            'PN' : 0,
            'MKSKIPPED' : {}
        }

    def RatchetInitAlice(self, SK, bob_dh_public_key):
        self.DHs = DoubleRatchet.generate_dh()
        self.DHs_public = self.DHs.public_key()
        self.DHr = bob_dh_public_key
        self.RK = SK
        self.RK, self.CKs = DoubleRatchet.kdf_rk(self.RK, self.dh())
        self.Ns = 0
        self.Nr = 0
        self.PN = 0
        self.MKSKIPPED = {}
        
    def RatchetInitBob(self, SK, bob_dh_key_pair):
        self.DHs = bob_dh_key_pair
        self.DHs_public = self.DHs.public_key()
        self.RK = SK
        self.Ns = 0
        self.Nr = 0
        self.PN = 0
    
    def get_state(self) -> dict:
        return {
            'DHs' : self.DHs.private_bytes_raw().hex(),
            'DHs_public' : self.DHs_public.public_bytes_raw().hex(),
            'DHr' : self.DHr.public_bytes_raw().hex(),
            'RK' : self.RK.hex(),
            'CKs' : self.CKs.hex(),
            'CKr' : self.CKr.hex(),
            'Ns' : self.Ns,
            'Nr' : self.Nr,
            'PN' : self.PN
        }
    
    def print_state(self):
        self.display_error("="*80)
        for k, v in self.get_state().items():
            self.display_error("{} - {} ".format(k, v))
        self.display_error("="*80)
    

    def RatchetEncrypt(self, plaintext):
        Ns, mk = self.RatchetSendKey()
        header = DoubleRatchet.header(self.DHs_public, self.PN, Ns)
        ciphertext = DoubleRatchet.encrypt(mk, plaintext, header)
        return header, ciphertext

    def RatchetSendKey(self):
        self.CKs, mk = DoubleRatchet.kdf_ck(self.CKs)
        Ns = self.Ns
        self.Ns += 1
        return Ns, mk

    def RatchetReceiveKey(self, header):
        mk = self.TrySkippedMessageKeys(header)
        if mk != None:
            return mk
        if header.dh != self.DHr:
            self.SkipMessageKeys(header.pn)
            self.DHRatchet(header)
        self.SkipMessageKeys(header.n)
        self.CKr, mk = DoubleRatchet.kdf_ck(self.CKr)
        self.Nr += 1
        return mk
    
    def recv(blob):
        header = blob[:36]
        ciphertext = blob[36:]
        return header,ciphertext
    
    def RatchetDecrypt(self, header, ciphertext):
        try:
            #    print(f"header {header.hex()} ciphertext {ciphertext.hex()}")
            obj_header = DoubleRatchetHeader(header)
            mk = self.RatchetReceiveKey(obj_header)
            plaintext = DoubleRatchet.decrypt(mk, ciphertext, header)
            return plaintext
        except Exception as e:
            self.display_error(f"RatchetDecrypt Error: {e}")
            tb = e.__traceback__
            for frame in traceback.extract_tb(tb):
                errorline = "{} {} {} {}".format(frame.filename, frame.lineno, frame.name, frame.line)
                self.display_error(errorline)
            return None

    def DHRatchet(self, header):
        self.PN = self.Ns
        self.Ns = 0
        self.Nr = 0
        self.DHr = header.dh
        self.RK, self.CKr = DoubleRatchet.kdf_rk(self.RK, self.dh()) 
        self.DHs = DoubleRatchet.generate_dh()
        self.DHs_public = self.DHs.public_key()
        self.RK, self.CKs = DoubleRatchet.kdf_rk(self.RK, self.dh())

    def TrySkippedMessageKeys(self, header):
        row = self.db.mkskipped(header.dh_bytes, header.n)
        if row:
            mk = row['mk']
            self.db.del_message(row['id'])
            return mk
        else:
            return None

    def SkipMessageKeys(self, until):
        if self.CKr != None:
            while self.Nr < until:
                self.CKr, mk = DoubleRatchet.kdf_ck(self.CKr)
                self.db.put_message(self.DHr.public_bytes_raw(),self.Nr,mk)
                self.Nr += 1

    def save_state(self):
        state = self.get_state()
        state_json = json.dumps(state,separators=(',', ':'),sort_keys=True,ensure_ascii=False)
        self.db.save_state(state_json)

    def shutdown(self):
        self.save_state()
        if self.db:
            self.db.close()
