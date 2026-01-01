import base64
import json
import getpass
import datetime
#import logging
import os
import random
import secrets
import traceback
import threading
import time
from cryptography import x509
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519, ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import NameOID
from whispertls.SNIServer import OOBServer
from whispertls.ClientManager import ClientManager
from whispertls.ClientManager import OOBClient
from whispertls.NcursesUI import NcursesUI
from whispertls.MasterKey import MasterKey
from whispertls.RatchetQueue import RatchetQueue
from whispertls.SNIServer import SNIServer
from whispertls.TorManager import TorManager
from whispertls.WhisperTLSDatabase import WhisperTLSDatabase
from whispertls.Aux import Aux

class WhisperTLS:
    def __init__(self):
        self.masterkey_path = "whispertls.enc"
        self.masterkey = b'';
        self.sslserver = None 
        self.ratchetqueue = None #
        self.clientmanager = None
        self.ui = NcursesUI(self)
        self.webui = None
        self.is_running = True
        self.password = ""
        self.is_lock = True
        self.db  = None
        self.unsavedconfig = {}
        self.config = {}
        self.networkcontroller = None
        self.sslserver = SNIServer(self,error_handler_callback=self.display_error)
        
    def log(self,message):
        with open("whispertls.log", "a") as f:
            f.write(message + "\n")
    
    def message_sent(self,msg_id):
        #What we need to do with messages that where send?
        #self.display_message("Message sent id: {}".format(msg_id))
        pass

    def display_message(self,msg):
        if self.ui:
           self.ui.add_message(msg)

    def display_error(self,error):
        if self.ui:
           self.ui.add_message(error)
        if self.webui:
            self.webui.notify_error(error)
        now = datetime.datetime.now()
        formatted = now.strftime("%Y%m%d %H:%M:%S")
        self.log("{} - {}".format(formatted,error))
    
    def start(self):
        task1 = threading.Thread(target=self.ui.start,name="UI",daemon=True)
        task2 = threading.Thread(target=self.sslserver.start,name="Server",daemon=True)
        task1.start()
        task2.start()
        task1.join()
        task2.join()
    
    def get_contacts(self) -> list:
        contacts = self.db.get_contact_list()
        return contacts

    def generate_identity(self,certificate_minutes = 10,purpose = 1,network_type = 1):
        contact_id = secrets.token_hex(8)

        #network
        if purpose == 1:
            network_address,network_key = self.networkcontroller.create_ephemeral_hidden_service()
        else:
            network_address,network_key = self.networkcontroller.create_ephemeral_hidden_service(tor_port = 13444,os_port = 13444 )

        #TLS
        tls_cert_pem,tls_key_pem,tls_key_password = Aux.generate_tlsidentity(network_address,certificate_minutes)

        #identity
        private,public = Aux.generate_keypair('ed25519','bytes')
        
        ratchet_password = secrets.token_hex(32)
        return {
            "contact_id": contact_id,
            "purpose": purpose,
            "network_address": network_address,
            "network_key": network_key,
            "network_type": network_type,
            "tls_cert_pem": tls_cert_pem,
            "tls_key_pem": tls_key_pem,
            "tls_key_password": tls_key_password,
            "private_bytes": private,
            "public_bytes": public,
            "ratchet_password": ratchet_password,
            "is_ready": 0
        }

    def set_contactready(self,contact_id):
        return self.db.set_contactready(contact_id)

    def get_contact_details(self):
        pass
        
    def add_contact(self,oob_code) -> dict:
        identity = self.generate_identity(certificate_minutes = int(self.config['core_certificate_minutes']))

        contact = self.create_contact(identity['contact_id'])
        self.display_message("Contac ID: {}".format(contact['id']))
        identity['contact_id'] = contact['id']

        self.db.insert_identity(identity)
        #if r  == 1:
        #    self.display_message("Final data Inserted")
        #else :
        #    self.display_message("Final data Falied")
        
        
        client = OOBClient(self,identity,oob_code,int(self.config['core_timeout_seconds']),self.display_error)
        client.start()
        
        row = self.db.get_code(contact['id'])
        if row is None:
            return None
        
        identity = self.db.get_identity(contact['id'])   # This ensure that full identity/contact bundle is already on database
        self.loadcontact(identity,network=False)    #Tor Service should be 
            
        return {
            "full": row['verification_code'],
            "partial": row['verification_code'][:10]
        }

    def get_realidentity_from_oob(self,oob_address) -> dict:
        identity = self.db.get_realidentity_from_oob(oob_address)
        return identity
    
    def get_identity_from_hs(self,address) -> dict:
        identity = self.db.get_identity_from_hs(address)
        return identity
    
    def get_messages(self,contact_id : str,number : int)  -> list:
        messages =[
            {"id": "028c073b9ccb4a6a",
             "msg":"Hello Alice",
             "direction": "send"},
            {"id": "cc9827403e10e096",
             "msg":"Hello Bob",
             "direction": "recv"}, 
            {"id":"fb08666ccc625072",
             "msg" : "How are you been today?",
             "direction": "send"},
            {"id":"fb08666ccc625072",
             "msg" : "I’ve been doing great today!",
             "direction": "recv"}
        ]
        return messages

    def oob_start_request(self) -> str:
        identity     = self.generate_identity(certificate_minutes = int(self.config['core_certificate_minutes']))
        oob_identity = self.generate_identity(certificate_minutes = 10,purpose = 2)
        contact = self.create_contact(identity['contact_id'])
        identity['contact_id'] = contact['id']
        oob_identity['contact_id'] = contact['id']
        #self.display_message("Contac ID: {}".format(contact['id']))
        self.db.insert_identity(identity)
        oobserver = OOBServer(self,identity,oob_identity,int(self.config['core_timeout_seconds']),self.display_error)
        threading.Thread(target=oobserver.start,name="OOBServer_{}".format(identity['contact_id']), daemon=True).start()     
        return oob_identity['network_address']
    
    def debug(self):
        result = self.sslserver.debug()
        self.display_message("debug {}".format(result))
        
    def create_contact(self,id = None):
        try:
            if id is None:
                id = secrets.token_hex(8) 
            contact_id = self.db.create_contact(id,'new oob user ' + id)
            return contact_id
        except Exception as e:
            self.display_error(f"Error: {e}")
            tb = e.__traceback__
            for frame in traceback.extract_tb(tb):
                line_errror = "{} {} {} {}".format(frame.filename, frame.lineno, frame.name, frame.line)
                self.display_error(line_errror)
    
    def delete_contact(self,contact_id):
        return self.db.delete_contact(contact_id)

    def reset_communication(self) -> bool:
        return True
        
    def get_status(self) -> dict:
        #FIXME
        return {
            "tor": "running",
            "tls": "running",
            "tls_version": "1.3",
            "double_ratchet": "enabled",
            "key": "value",
            "k1": "v1"
        }
        
    def search_messages(self,search_value:str) -> list:
        conversations = [ {"contact" : {"id": "028c073b9ccb4a6a","nickname":"Alice"} , 
                           "message" : {"id":"fb08666ccc625072","msg" : "I've been doing great today!","direction": "recv"}
                          }]
        return conversations
        
    def verify(self,code :str) -> dict:
        row = self.db.verify_code(code)
        if row:
            if self.set_contactready(row['contact_id']) == 0:
                raise ValueError("Database error set_contactready")

            identity = self.db.get_identity(row['contact_id'])   # This ensure that full identity/contact bundle is already on database
            self.loadcontact(identity,network=False)    #Tor Service should be
            return row
        else:
            return row
    
    def reset_network(self) -> bool:
        return True

    def list_hs(self):
        return self.networkcontroller.list_ephemeral_hidden_services()

    def set_nick(self, contact_id : str,nickname :str) -> bool:
        return self.db.set_nick(contact_id,nickname);

    def is_valid_contact(self,contact :str) -> bool:
        result = self.db.is_valid_contact(contact)
        if result == 0:
            return False;
        elif result == 1:
            return True;
        else:
            self.display_error("There is more than one contact for your selection")
            return False;
            

    def shutdown(self):
        if self.is_running:
            self.is_running = False
            if self.sslserver:
                self.sslserver.shutdown()
            time.sleep(0.15)
            if self.db:
                self.db.shutdown()
            time.sleep(0.15)
            if self.networkcontroller:
                self.networkcontroller.shutdown()
            time.sleep(0.15)
            if self.ui:
                self.ui.shutdown()
            time.sleep(0.15)
            if self.ratchetqueue:
                self.ratchetqueue.shutdown()
            time.sleep(0.15)

    def existsmasterkey(self) -> bool:
        return os.path.exists(self.masterkey_path)
    
    def set_password(self, password :str) -> bool:
        if not os.path.exists(self.masterkey_path):
            self.password = password.encode()
            v_mk = MasterKey(self.password,self.masterkey_path)
            self.masterkey = v_mk.masterkey
            return True
        else:
            return False
        
    def change_password(self,oldpassword, newpassword) -> bool:
        v_mk = MasterKey(self.password,self.masterkey_path)
        if v_mk.change_password(oldpassword.encode(),newpassword.encode()):
            return True
        return False

    def login(self,password : str) -> bool:
        v_mk = MasterKey(password.encode(),self.masterkey_path)
        if v_mk.success:
            if self.is_lock:
                self.password = password.encode()
                self.masterkey = v_mk.masterkey
                self.unlock()
        return v_mk.success

    def unlock(self):
        #self.display_message("Unlocking")
        self.is_lock = False
        if self.masterkey == b'':
            return
        #self.display_message("DB Masterkey = {}".format(Aux.HKDF(self.masterkey,"DB").hex()))
        self.db = WhisperTLSDatabase(masterkey = Aux.HKDF(self.masterkey,"DB"),error_handler_callback = self.display_error)
        self.config = self.db.saveandget_config(self.unsavedconfig)
        self.sslserver.timeout_seconds = int(self.config["core_timeout_seconds"])
        self.loadnetwork()

    def loadnetwork(self):
        #self.sslserver = SNIServer(self,error_handler_callback=self.display_error,timeout = int(self.config['core_timeout_seconds']))
        
        if self.config['tor_password'] == '':
            self.networkcontroller = TorManager(9051,error_handler_callback = self.display_error)
        else:
            self.networkcontroller = TorManager(9051,password = self.config['tor_password'],error_handler_callback = self.display_error)
        
        self.ratchetqueue = RatchetQueue(self)
        threading.Thread(target=self.ratchetqueue.start,name="RatchetQueue",daemon=True).start()
        
        self.clientmanager = ClientManager(self)
        threading.Thread(target=self.clientmanager.start,name="ClientManager",daemon=True).start()
        
        identities = self.db.get_identities()
        for identity in identities:
            self.loadcontact(identity)

    def loadcontact(self,identity,server = True,network=True ,client=True):
        #self.display_message("Loading contact {}".format(identity["contact_id"]))
        #self.display_message("Loading local  address {}".format(identity["network_address"]))
        #self.display_message("Loading remote address {}".format(identity["contact_network_address"]))
        if server:
            self.sslserver.add_context(identity)
        if network:
            domain = self.networkcontroller.resume_ephemeral_hidden_service(identity['network_key'],os_port = self.sslserver.port)
            #self.display_message("Setting up Tor HS {}".format(domain))
        if client:
            self.clientmanager.add_client(identity,identity['contact_network_address'])
    
    def add_verificationcode(self,contact_id,verification_code):
        return self.db.insert_verificationcode(contact_id,verification_code)
    
    def add_contactbundle(self,contact_id :str,network_type: int, network_address: str,tls_cert_pem : bytes, public_bytes : bytes):
        return self.db.insert_contactbundle(contact_id,network_type, network_address,tls_cert_pem, public_bytes)
        
    def set_config(self,config_key,config_value):
        #self.display_error("set_config : {} : {}".format(config_key,config_value))
        if self.is_lock:
            if config_value == 'None':
                del self.unsavedconfig[config_key]
            else:
                self.unsavedconfig[config_key] = config_value
        else:
            if config_value == 'None':
                del self.config[config_key]
                self.db.del_config(config_key)
            else:
                self.config[config_key] = config_value
                self.db.put_config(config_key,config_value)

    def process_blob(self,contact_id,encrypted_data,password):
        #self.display_message("Processing blog encrypted {} - {}".format(len(encrypted_data),encrypted_data.hex()[:30]))
        plaintext = self.ratchetqueue.set_task(contact_id,password,encrypted_data,'decrypt')
        dictionary = json.loads(plaintext.decode())
        #self.display_message("Processing blog plaintext: {} - {}".format(len(plaintext),plaintext.decode()[:30]))
        messages = dictionary.get("messages")
        if messages:
            for msg in messages:
                data =  base64.b64decode(msg['data'])
                self.db.insert_msg(contact_id,1,msg['id'],msg['type'],data)
                self.display_message("-> {}".format(data.decode()))
        #if dictionary['rece'] is not None:

    def process_plaintext(self,contact_id,plaintext,password):
        encrypted = self.ratchetqueue.set_task(contact_id,password,plaintext,'encrypt')
        return encrypted

    def get_unsentmessages(self,contact_id):
        return self.db.get_unsentmessages(contact_id)

    def take_message(self,message_id,field):
        return self.db.take_message(message_id,field)

    def send_text_message(self,contact_id,msg):
        message_id = secrets.token_hex(8)
        self.db.insert_msg(contact_id,2,message_id,"txt",msg.encode())
        self.display_message("<- {}".format(msg))
        