import base64
import pysqlcipher3.dbapi2 as sqlcipher
import queue
import os
import random
import secrets
import threading
import traceback
import time
from whispertls.Future import Future
from whispertls.Aux import Aux

class WhisperTLSDatabase:
    def rowdict(cursor, row):
        return {col[0]: row[i] for i, col in enumerate(cursor.description)}

    def assert_sqlcipher_linked(cursor):
        v = cursor.execute("PRAGMA cipher_version;").fetchone()
        if v is None or v['cipher_version'] == '':
            raise RuntimeError("sqlcipher but no cipher_version")

    def __init__(self,masterkey : bytes,error_handler_callback = None):
        # conn and cursor must only be access by thread _run and subfunction handle_requests
        self.conn = None
        self.cursor = None
        self.requests = queue.Queue()
        self.masterkey = masterkey
        self.database_name = 'whispertls.db'
        if error_handler_callback:
            self.error_handler = error_handler_callback
        else:
            self.error_handler = print
        self.is_running = False 
        self._db_thread = None
        self._db_thread = threading.Thread(target=self._run, daemon=True)
        self._db_thread.start()

    def _run(self):
        #self.error_handler("Masterkey: {}".format(self.masterkey.hex()))
        if not os.path.exists(self.database_name):  #database doesn't exist
            self.conn = sqlcipher.connect(self.database_name)
            self.conn.row_factory = WhisperTLSDatabase.rowdict
            self.cursor = self.conn.cursor()
            #self.error_handler("Current Masterkey '{}'".format(self.masterkey.hex()))
            self.cursor.execute("PRAGMA key = '{}';".format(self.masterkey.hex()))
            self.cursor.execute("PRAGMA foreign_keys = ON;")
            WhisperTLSDatabase.assert_sqlcipher_linked(self.cursor)
            with open("./app.sql", "r", encoding="utf-8") as f:
                script = f.read()
            for stmt in filter(None, map(str.strip, script.split(";"))):
                #self.error_handler("Executing {}".format(stmt))
                self.cursor.execute(stmt)
        else:
            self.conn = sqlcipher.connect(self.database_name)
            self.conn.row_factory = WhisperTLSDatabase.rowdict
            self.cursor = self.conn.cursor()   
            self.cursor.execute("PRAGMA key = '{}';".format(self.masterkey.hex()) )
            self.cursor.execute("PRAGMA foreign_keys = ON;")
            WhisperTLSDatabase.assert_sqlcipher_linked(self.cursor) 
        self.conn.commit()
        self.handle_requests()

    def handle_requests(self):
        self.is_running = True
        while self.is_running:
            try:
                query, params, fut, special_command, fetchall =  self.requests.get()
                if query is None:
                    continue
                if query == "STOP":
                    fut.set("DB is STOPPING")
                    self.requests.task_done()
                    break;
                if special_command:
                    self.cursor.execute(query)
                    self.conn.commit()
                    fut.set(True)
                else:
                    self.conn.execute('BEGIN')
                    self.cursor.execute(query, params)
                    if query.strip().upper().startswith("SELECT"):
                        if fetchall:
                            result = self.cursor.fetchall()
                        else:
                            result = self.cursor.fetchone()
                        fut.set(result)
                    else:
                        affected_rows = self.cursor.rowcount
                        self.conn.commit()
                        fut.set(affected_rows)
                self.requests.task_done()
            except Exception as e:
                self.error_handler("handle_requests exception: {}".format(e))
                tb = e.__traceback__
                for frame in traceback.extract_tb(tb):
                    errorline = "{} {} {} {}".format(frame.filename, frame.lineno, frame.name, frame.line)
                    self.error_handler(errorline)
                self.conn.rollback()
        if self.cursor:
            self.cursor.close()
        if self.conn:
            self.conn.close()

    def execute_query(self, query, params=(), special_command=False, fetchall = True):
        fut = Future()
        self.requests.put((query, params, fut, special_command,fetchall))
        result = fut.wait()
        return result

    def create_contact(self, id : str, nickname : str) -> dict:
        try:
            contact = {}
            query = "INSERT into contacts (id,nickname) VALUES (?, ?)"
            if self.execute_query(query,(id,nickname,)) > 0:
                contact['id'] = id
                contact['nickname'] = nickname
            return contact
        except sqlcipher.IntegrityError:
            self.error_handler("🎉 Something exceptionally rare happened! Buy a lottery ticket if you feel lucky enough! 🎉")
            new_id = secrets.token_hex(8)
            return self.create_contact(new_id,'new oob user '+new_id)
        except Exception as e:
            self.error_handler(f"create_contact failed: {e}")
            return {}

    def insert_identity(self, identity) -> bool:
        try:
            insert = 'INSERT INTO identities (contact_id,purpose,network_address,network_key,network_type,tls_cert_pem,tls_key_pem,tls_key_password,private_bytes,public_bytes,ratchet_password) VALUES (?,?,?,?,?,?,?,?,?,?,?);'
            affected_rows = self.execute_query(insert,(
                identity['contact_id'],
                identity['purpose'],
                identity['network_address'],
                identity['network_key'],
                identity['network_type'],
                identity['tls_cert_pem'],
                identity['tls_key_pem'],
                identity['tls_key_password'],
                identity['private_bytes'],
                identity['public_bytes'],
                identity['ratchet_password'],))
            return  affected_rows
        except Exception as e:
            self.error_handler(f"Error: {e}")
            tb = e.__traceback__
            for frame in traceback.extract_tb(tb):
                errorline = "{} {} {} {}".format(frame.filename, frame.lineno, frame.name, frame.line)
                self.error_handler(errorline)
            return 0
    
    def insert_verificationcode(self,contact_id : str, verification_code : bytes):
        try:
            insert = 'INSERT INTO oob_verification (contact_id,verification_code) values (?,?);'
            affected_rows = self.execute_query(insert,(contact_id,verification_code.hex()))
            return affected_rows
        except Exception as e:
            self.error_handler(f"Error: {e}")
            tb = e.__traceback__
            for frame in traceback.extract_tb(tb):
                errorline = "{} {} {} {}".format(frame.filename, frame.lineno, frame.name, frame.line)
                self.error_handler(errorline)
            return 0

    def delete_contact(self,contact_id : str) -> bool:
        try:
            #overwriting identities bofere delete the related contact_id
            update = "UPDATE identities SET purpose = ?,network_address = ?,network_key = ?,network_type = ?,tls_cert_pem = ?,tls_key_pem = ?,tls_key_password = ?,private_bytes = ?,public_bytes = ?,ratchet_password = ?,is_ready = ? WHERE contact_id = ? ;"
            affected_rows = self.execute_query(update,
                (secrets.randbits(63), #purpose, integer
                base64.b32encode(os.urandom(35)).decode().lower(), #network_address onion address format
                base64.b64encode(os.urandom(64)).decode(),    #network_key ...<base64>...
                secrets.randbits(63), #network_type integer
                os.urandom(1024),      #tls_certificate in text format just random bytes
                os.urandom(512),       #tls_key 
                os.urandom(32).hex(),       #tls_password
                os.urandom(32),             #private_bytes
                os.urandom(32),             #public_bytes
                os.urandom(32).hex(),       #ratchet_password
                secrets.randbits(63),       #is_ready
                contact_id,)
            )
            #overwriting identities bofere delete the related contact_id
            update = "UPDATE contacts_bundles SET  network_type= ?, network_address = ?, tls_cert_pem = ?, public_bytes = ? WHERE contact_id = ?"
            affected_rows = self.execute_query(update,
                (secrets.randbits(63),
                base64.b32encode(os.urandom(35)).decode().lower(),
                os.urandom(1024),
                os.urandom(32),
                contact_id,)
            )

            #overwriting messages bofere delete the related contact_id
            update = "UPDATE messages SET display_id = ? ,message = ?, message_type = ?,direction = ?, is_sent = ?, is_received = ?, is_readed = ?, send_queue = ? , receive_queue = ? , read_queue = ? WHERE contact_id = ?"
            affected_rows = self.execute_query(update,
                (
                os.urandom(8).hex(), 
                os.urandom(2048), 
                os.urandom(20).hex(), 
                secrets.randbits(63),
                secrets.randbits(63),
                secrets.randbits(63),
                secrets.randbits(63),
                secrets.randbits(63),
                secrets.randbits(63),
                secrets.randbits(63),
                contact_id,)
            )

            #On delele CASCADE  will delete all related records on other tables
            delete = "delete from contacts where id = ?"
            affected_rows = self.execute_query(delete,
                 (contact_id,)
            )
            self.vacuum_database()
            return  True
        except Exception as e:
            self.error_handler(f"Error: {e}")
            tb = e.__traceback__
            for frame in traceback.extract_tb(tb):
                errorline = "{} {} {} {}".format(frame.filename, frame.lineno, frame.name, frame.line)
                self.error_handler(errorline)
            return False

    def get_contact_list(self) -> list:
        try:
            contacts  =  self.execute_query("select id,nickname from contacts c left join identities i on c.id = i.contact_id where i.is_ready = 1;")
            return contacts
        except Exception as e:
            self.error_handler(f"Error: {e}")
            tb = e.__traceback__
            for frame in traceback.extract_tb(tb):
                errorline = "{} {} {} {}".format(frame.filename, frame.lineno, frame.name, frame.line)
                self.error_handler(errorline)

    def get_identities(self) -> list:
        try:
            identities  =  self.execute_query("SELECT i.contact_id, i.purpose, i.network_address, i.network_key, i.network_type, i.tls_cert_pem, i.tls_key_pem, i.tls_key_password, i.private_bytes, i.public_bytes, i.ratchet_password, i.is_ready, cb.network_address as contact_network_address, cb.public_bytes as contact_public_bytes, cb.tls_cert_pem as contact_cert_pem FROM identities i LEFT JOIN contacts_bundles cb on cb.contact_id = i.contact_id WHERE i.purpose = 1 and i.is_ready = 1")
            return identities
        except Exception as e:
            self.error_handler(f"Error: {e}")
            tb = e.__traceback__
            for frame in traceback.extract_tb(tb):
                errorline = "{} {} {} {}".format(frame.filename, frame.lineno, frame.name, frame.line)
                self.error_handler(errorline)

    def get_identity(self,contac_id) -> list:
        try:
            identity  =  self.execute_query("SELECT i.contact_id, i.purpose, i.network_address, i.network_key, i.network_type, i.tls_cert_pem, i.tls_key_pem, i.tls_key_password, i.private_bytes, i.public_bytes, i.ratchet_password, i.is_ready, cb.network_address as contact_network_address, cb.public_bytes as contact_public_bytes, cb.tls_cert_pem as contact_cert_pem FROM identities i LEFT JOIN contacts_bundles cb on cb.contact_id = i.contact_id WHERE i.purpose = 1 and i.is_ready = 1 and i.contact_id = ?",(contac_id,),fetchall=False)
            return identity
        except Exception as e:
            self.error_handler(f"Error: {e}")
            tb = e.__traceback__
            for frame in traceback.extract_tb(tb):
                errorline = "{} {} {} {}".format(frame.filename, frame.lineno, frame.name, frame.line)
                self.error_handler(errorline)

    
    def insert_contactbundle(self,contact_id :str,network_type: int, network_address: str,tls_cert_pem : bytes, public_bytes : bytes):
        try :
            insert = 'INSERT INTO contacts_bundles (contact_id,network_type,network_address,tls_cert_pem,public_bytes) values (?,?,?,?,?);'
            affected_rows = self.execute_query(insert,(contact_id,network_type,network_address,tls_cert_pem,public_bytes,))
            return affected_rows
        except Exception as e:
            self.error_handler(f"Error: {e}")
            tb = e.__traceback__
            for frame in traceback.extract_tb(tb):
                errorline = "{} {} {} {}".format(frame.filename, frame.lineno, frame.name, frame.line)
                self.error_handler(errorline)
            return 0

    def get_messages(self,contact_id : str, last_message_id = 0 ,  limit = 10) -> list:
        try:
            messages = []
            query = "select id,message,direction from messages where contact_id = ? and id > ? order by id asc limit ? ;"
            rows  =  self.execute_query(query,(contact_id,last_message_id,limit))
            for row in rows: 
                messages.append({
                    'id': row['id'],
                    'message': row['message'],
                    'direction': row['direction']
                })
            return contacts
        except Exception as e:
            self.error_handler(f"Error: {e}")
            tb = e.__traceback__
            for frame in traceback.extract_tb(tb):
                errorline = "{} {} {} {}".format(frame.filename, frame.lineno, frame.name, frame.line)
                self.error_handler(errorline)

    def saveandget_config(self,unsaved : dict ) -> dict:
        if unsaved:
            for unsaved_key, unsaved_value in unsaved.items():
                self.put_config(unsaved_key,unsaved_value)
        config_temp = self.execute_query("select * from config;")
        config = {}
        for item in config_temp:
            #errorline = "saveandget_config: Adding config {} {}".format(item['config_key'],  item['config_value'])
            #self.error_handler(errorline)
            config[item['config_key']] = item['config_value']
        #self.error_handler(f"saveandget_config: {config}")
        return config

    def put_config(self,new_key,new_value) -> bool:
        try:
            query = "select config_key from config where config_key = ?;"
            row = self.execute_query(query,(new_key,),fetchall = False)
            if row:
                update = "UPDATE config SET config_value = ? where  config_key = ?;"
                afected_rows = self.execute_query(update,(new_value,new_key,))
            else:
                insert = "INSERT into config (config_key,config_value) values (?,?);"
                afected_rows = self.execute_query(insert,(new_key,new_value,))
            return afected_rows
        except Exception as e:
            self.error_handler(f"Error: {e}")
            return False
            
    def get_realidentity_from_oob(self, address) -> dict:
        try:
            query = "select contact_id from identities i where i.network_address = ? ;"
            row = self.execute_query(query,(address,),fetchall = False)
            if row:
                contact_id = row['contact_id']
                self.error_handler(f"get_realidentity_from_oob: {contact_id}")
                query2 = "select * from  identities i where contact_id = ?  and purpose = 1;"
                row2 = self.execute_query(query2,(contact_id,),fetchall = False)
                return row2
            else:
                return {}
        except Exception as e:
            self.error_handler(f"get_realidentity_from_oob: {e}")
            return False

    def get_identity_from_contact(self, contact_id) -> dict:
        try:
            query2 = "select * from  identities i where contact_id = ?  and purpose = 1;"
            row2 = self.execute_query(query2,(contact_id,),fetchall = False)
            return row2
        except Exception as e:
            self.error_handler(f"get_identity_from_contact: {e}")
            return False

    def get_code(self, contact_id) -> dict:
        try:
            query = "select * from  oob_verification where contact_id = ?;"
            row = self.execute_query(query,(contact_id,),fetchall = False)
            return row
        except Exception as e:
            self.error_handler(f"get_code: {e}")
            return None
    
    def get_unsentmessages(self,contact_id) -> dict:
        try:
            query = "select * from messages where direction = 2 and is_sent = 0 and send_queue = 0 and contact_id = ? order by id asc;"
            messages = self.execute_query(query,(contact_id,))
            return messages
        except Exception as e:
            self.error_handler(f"get_unsendmessages: {e}")
            return None
     
    def set_contactready(self,contact_id) -> int:
        try:
            query = "UPDATE identities set is_ready = 1 where contact_id = ?;"
            result = self.execute_query(query,(contact_id,))
            return result
        except Exception as e:
            self.error_handler(f"set_contactready: {e}")
            return 0
        
     
    def take_message(self,message_id,field) -> int:
        try:
            if field not in ['send_queue','receive_queue','read_queue']:
                return 0
            query = "UPDATE messages set {} = 1 where id = ?;".format(field)
            result = self.execute_query(query,(message_id,))
            return result
        except Exception as e:
            self.error_handler(f"take_message: {e}")
            return 0
    
    def set_nick(self,contact_id,nickname) -> bool:
        try:
            query = "UPDATE contacts set nickname = ? where id = ?;"
            result = self.execute_query(query,(nickname,contact_id))
            return result == 1
        except Exception as e:
            self.error_handler(f"take_message: {e}")
            return False

    def verify_code(self,code : str) -> dict:
        try:
            code = code.lower()
            query = "select contact_id from oob_verification where verification_code like ?;"
            result = self.execute_query(query,(code + "%",),fetchall = False)
            return result
        except Exception as e:
            self.error_handler(f"verify_code: {e}")
            return None
    
    def insert_msg(self,contact_id,direction,message_id,message_type,message):
        try:
            insert = "INSERT INTO messages (display_id,contact_id,message,message_type,direction) values (?,?,?,?,?);"
            result = self.execute_query(insert,(message_id,contact_id,message,message_type,direction,))
            return result
        except Exception as e:
            self.error_handler(f"verify_code: {e}")
            return 0
        
    def is_valid_contact(self,contact_id) -> int:
        try:
            query = "select count(*) as total from contacts c left join  identities i on i.contact_id = c.id where c.id like ? or c.nickname like ?;"
            result = self.execute_query(query,("%" +contact_id + "%", "%" +contact_id + "%"),fetchall = False)
            return int(result['total'])
        except Exception as e:
            self.error_handler(f"is_valid_contact: {e}")
            return 0
        

    def del_config(self,new_key : str) -> bool:
        try:
            delete = "delete from config where config_key = ?;"
            afected_rows = self.execute_query(delete,(new_key,))
            return afected_rows
        except Exception as e:
            if self.error_handler:
                self.error_handler(f"del_config: {e}")
            return False

    def vacuum_database(self)  -> bool:
        try:
            self.execute_query('VACUUM;',None,True)
            return True
        except Exception as e:
            self.error_handler(f"Error vacuum_database: {e}")
            return False

    def shutdown(self):
        self.is_running = False
        self.error_handler(self.execute_query("STOP"))
