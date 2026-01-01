import base64
import os
import socket
import socks
import ssl
import tempfile
import time
import threading
from cryptography import x509
from cryptography.x509 import load_der_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519,ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID
from whispertls.DoubleRatchet import DoubleRatchet
from whispertls.Aux import Aux
from datetime import datetime, timezone

class OOBClient:
    def __init__(self,main_app,identity,server_address,timeout = 30,error_handler_callback = None):
        self.identity = identity
        self.proxy_host = '127.0.0.1'
        self.proxy_port = 9050
        self.target_port = 13444
        self.main_app = main_app
        self.timeout_seconds = timeout
        self.is_running = False 
        self.server_address = server_address + ".onion"
        if error_handler_callback:
            self.error_handler = error_handler_callback
        else:
            self.error_handler = print

    def load_cert(self,context):
        identity = self.identity
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as cert_file:
            cert_file.write(identity['tls_cert_pem'])
            cert_path = cert_file.name
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as key_file:
            key_file.write(identity['tls_key_pem']) 
            key_path = key_file.name
        try:
            context.load_cert_chain(certfile=cert_path, keyfile=key_path, password=identity['tls_key_password'])
        finally:
            os.unlink(cert_path)
            os.unlink(key_path)

    def start(self):
        self.is_running = True
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        self.load_cert(context)
        clientsocket = socks.socksocket()
        try:
            clientsocket.set_proxy(socks.SOCKS5, self.proxy_host, self.proxy_port)
            clientsocket.connect((self.server_address, self.target_port))
            clientsocket.settimeout(self.timeout_seconds)
            
            
            with context.wrap_socket(clientsocket, server_hostname=self.server_address) as tls_sock:
                self.oob_process_client(tls_sock)
        except (socket.timeout, ssl.SSLError) as e:
            self.error_handler(f"Timeout/SSL error: {e}")
        except OSError as e:
            self.error_handler(f"Socket error: {e}")
        except Exception as e:
            self.error_handler(f"Unexpected error: {e}")
        finally:
            clientsocket.close()
        
        self.is_running = False

    def oob_process_client(self,tls_sock): 
        remote = {}
        identity = self.identity
        identity['privatekey'] = ed25519.Ed25519PrivateKey.from_private_bytes(identity['private_bytes'])
        
        identity['tls_privatekey'] = serialization.load_pem_private_key(
            identity['tls_key_pem'],
            password=identity['tls_key_password'].encode(),
            backend=default_backend())

        #ephemeral key Used only for this one Diffie-Hellman and Double ratchet initializaciont secret
        xkey = x25519.X25519PrivateKey.generate()
        xkey_public = xkey.public_key()
        xkey_public_bytes = xkey_public.public_bytes_raw()
        xkey_public_signature = identity['privatekey'].sign(xkey_public_bytes)

        tls_cert_pem_signature =identity['privatekey'].sign(identity['tls_cert_pem'])
        entropy = os.urandom(32)
        entropy_signature = identity['privatekey'].sign(entropy)
        
        remote['identity_public_bytes']  = Aux.recv(tls_sock)
        remote['tls_cert_pem']           = Aux.recv(tls_sock)
        remote['tls_cert_pem_signature'] = Aux.recv(tls_sock)
        remote['xkey_public_bytes']      = Aux.recv(tls_sock)
        remote['xkey_public_signature']  = Aux.recv(tls_sock)
        remote['entropy']                = Aux.recv(tls_sock)
        remote['entropy_signature']      = Aux.recv(tls_sock)
        
        
        for item in remote.keys():
            if remote[item] is None:
                return False

        Aux.send(tls_sock,identity['public_bytes'])
        Aux.send(tls_sock,identity['tls_cert_pem'])
        Aux.send(tls_sock,tls_cert_pem_signature)
        Aux.send(tls_sock,xkey_public_bytes)
        Aux.send(tls_sock,xkey_public_signature)
        Aux.send(tls_sock,entropy)
        Aux.send(tls_sock,entropy_signature)
        
        remote['tls_certificate'] = x509.load_pem_x509_certificate(remote['tls_cert_pem'], default_backend())
        remote['tls_publickey']   =  remote['tls_certificate'].public_key()
        remote['network_address'] = Aux.get_issuer_clean(remote['tls_certificate'].issuer)
        
        if not isinstance(remote['tls_publickey'], ec.EllipticCurvePublicKey):
            return False
            
        remote['identity_public'] = ed25519.Ed25519PublicKey.from_public_bytes(remote['identity_public_bytes'])
        #Validate remote signatures
        try:
            remote['identity_public'].verify(remote['tls_cert_pem_signature'], remote['tls_cert_pem'])
            remote['identity_public'].verify(remote['xkey_public_signature'], remote['xkey_public_bytes'])
            remote['identity_public'].verify(remote['entropy_signature'], remote['entropy'])
        except Exception as e:
            self.error_handler(f"Signature verification failed: {e}")
            return False

        remote['xkey_public'] = x25519.X25519PublicKey.from_public_bytes(remote['xkey_public_bytes'])
        
        
        # TLS LAYER SHARED SECRET using ECDH
        tls_shared_secret = identity['tls_privatekey'].exchange(ec.ECDH(), remote['tls_publickey'])

        # APP LAYER SHARED SECRET using an ephemral ED25519 keys with DH
        app_shared_secret = xkey.exchange(remote['xkey_public'])    # Diffie-Helman

        derived_entropy    = Aux.HKDF(remote['entropy'] + entropy,"verification")
        derived_network    = Aux.HKDF(remote['network_address'].encode() + identity['network_address'].encode(),"verification")
        derived_identities = Aux.HKDF(remote['identity_public_bytes'] + identity['public_bytes'],"verification")

        #At this point Alice and Bob should have the same verification_code
        verification_code = Aux.HKDF(
            derived_entropy    + # entropy data from both sides
            derived_network    + # Alice Address + Bob Address
            derived_identities + # Alice identity public key +  Bob identity public key
            tls_shared_secret  + # Alice and Bob TLS shared secret with certificates ECDH
            app_shared_secret,    # Alice and Bob APP shared secret with ephemeral keys
                                 # We put together all layers: Network layer,  identity layer, TLS shared secret, + ephemeral shared_secret
            "Verification Code")

        #self.error_handler("derived_entropy   : {}".format(derived_entropy.hex()))
        #self.error_handler("derived_network   : {}".format(derived_network.hex()))
        #self.error_handler("derived_identities: {}".format(derived_identities.hex()))
        #self.error_handler("tls_shared_secret : {}".format(tls_shared_secret.hex()))
        #self.error_handler("app_shared_secret : {}".format(app_shared_secret.hex()))
        #self.error_handler("verification_code : {}".format(verification_code.hex()))


        #bob generate a challenge code for alice
        verification_code_alice = Aux.HKDF(verification_code,"Alice")
        
        verification_code_alice_signature = identity['privatekey'].sign(verification_code_alice)

        verification_code_bob = Aux.recv(tls_sock)
        verification_code_bob_signature = Aux.recv(tls_sock)
        
        Aux.send(tls_sock,verification_code_alice)
        Aux.send(tls_sock,verification_code_alice_signature)

        try:
            remote['identity_public'].verify(verification_code_bob_signature, verification_code_bob)
        except Exception as e:
            raise ValueError(f"Signature verification failed: {e}")
        
        # Bob compare the verfication code send by Alice
        expected_verification_code_bob = Aux.HKDF(verification_code,"Bob")
        if (expected_verification_code_bob != verification_code_bob):
            return False
            
        ratchet_secret = Aux.HKDF(verification_code,"Double Ratchet")
        
        #Here we should initialize the Double Ratchet
        ratchet_state = DoubleRatchet(contact=identity['contact_id'],password=identity['ratchet_password'])
        ratchet_state.RatchetInitBob(ratchet_secret,xkey)
        alice_message = Aux.recv(tls_sock)
        header,encryptedtext = DoubleRatchet.recv(alice_message)
        plaintext = ratchet_state.RatchetDecrypt(header ,  encryptedtext)
        
        if(plaintext.decode() != "hello bob!"):
            raise ValueError("Double Ratchet expected message mismatch")

        header,encryptedtext = ratchet_state.RatchetEncrypt("hello alice!".encode())
        ratchet_state.shutdown()
        
        Aux.send(tls_sock,header+encryptedtext)
        
        if self.main_app.add_contactbundle(identity['contact_id'],1,remote['network_address'],remote['tls_cert_pem'],remote['identity_public_bytes']) == 0:
            raise ValueError("Database error add_contactbundle")
        
        user_verification = Aux.HKDF(verification_code,"user verification")
        
        if self.main_app.add_verificationcode(identity['contact_id'],user_verification) == 0:
            raise ValueError("Database error add_verificationcode")

        if self.main_app.set_contactready(identity['contact_id']) == 0:
            raise ValueError("Database error set_contactready")

class Client:
    def __init__(self,main_app,identity,server_address,timeout = 30):
        self.main_app = main_app
        self.identity = identity
        self.is_ready = False
        self.is_running = False
        self.clientsocket = None
        self.tls_sock = None
        self.server_address = server_address + ".onion"
        self.proxy_host = '127.0.0.1'
        self.proxy_port = 9050
        self.target_port = 13443
        self.timeout_seconds = timeout
        self.is_conecting = False
        self.error_handler = self.main_app.display_error
        self.context = None
        self.define_context()
        
    def define_context(self):
        self.context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.context.maximum_version = ssl.TLSVersion.TLSv1_3
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_REQUIRED
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as cert_file:
            cert_file.write(self.identity['tls_cert_pem'])
            cert_path = cert_file.name
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as key_file:
            key_file.write(self.identity['tls_key_pem']) 
            key_path = key_file.name
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as contactcert_file:
            contactcert_file.write(self.identity['contact_cert_pem'])
            contactcert_path = contactcert_file.name
        try:
            self.context.load_cert_chain(certfile=cert_path, keyfile=key_path, password=self.identity['tls_key_password'])
            self.context.load_verify_locations(cafile=contactcert_path)
            #self.error_handler("network_address  : {}.onion".format(self.identity['network_address']))
            #self.error_handler("tls_cert_pem     : {}".format(cert_path))
            #self.error_handler("tls_key_pem      : {}".format(key_path))
            #self.error_handler("tls_key_password : {}".format(self.identity['tls_key_password']))
            #self.error_handler("contact_cert_pem : {}".format(contactcert_path))
            #self.error_handler("contact_address  : {}".format(self.identity['contact_network_address']))
        finally:
            pass
            os.unlink(cert_path)
            os.unlink(key_path)
            os.unlink(contactcert_path)
    
    def connect(self):
        self.is_conecting = True
        self.clientsocket = socks.socksocket()
        try:
            self.clientsocket.set_proxy(socks.SOCKS5, self.proxy_host, self.proxy_port)
            #self.main_app.display_message("connecting to {}:{}".format(self.server_address, self.target_port))
            #self.main_app.display_message("timeout {}".format(self.timeout_seconds))
            self.clientsocket.connect((self.server_address, self.target_port))
            self.clientsocket.settimeout(self.timeout_seconds)
            self.tls_sock =  self.context.wrap_socket(self.clientsocket, server_hostname=self.server_address)
            self.is_ready = True
        except Exception as e:
            #self.error_handler(f"connect Unexpected error: {e}")
            #Silent drop the connection
            self.is_ready = False
            if self.tls_sock:
                self.tls_sock.close()
                self.tls_sock = None
            if self.clientsocket:
                self.clientsocket.close()
                self.clientsocket = None
            self.is_ready = False
        self.is_conecting = False
        self.process()
        
    def process(self):
        if self.tls_sock is None:
            self.is_ready = False
            return
        self.is_running = True
        kib_size = int(self.main_app.config['core_fixed_message_size_KiB'])
        expected_size = 1024 * kib_size
        #received = self.main_app.get_receivedmessages(self.identity['contact_id'])
        
        unsentmessages = self.main_app.get_unsentmessages(self.identity['contact_id'])
        prev_content = {}
        content = {}
        counter = 0
        pending_messages = False
        if unsentmessages:
            
            pending_messages = True
            content["messages"]  = []
            for msgdb in unsentmessages:
                msg = {
                    'id' : msgdb['display_id'],
                    'type' : msgdb['message_type'],
                    'data' : base64.b64encode(msgdb['message']).decode("ascii")
                }
                if self.main_app.config['messages_send_timestamp'] == 'enabled':
                    msg['utcts'] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                #self.main_app.display_message("Pending Message: {}".format(msg))
                #self.main_app.display_message("Pending Message hex: {}".format(msgdb['message'].hex()))
                content["messages"].append(msg)
                #self.main_app.display_message("content: {}".format(content))
                temp = Aux.serialize(content,expected_size)
                #self.main_app.display_message("Pending Message: {}".format(msg))
                temp_len = len(temp)
                #self.main_app.display_message("serialize size: {}, expected_size {}".format(temp_len,expected_size))
                if temp_len <= expected_size:
                    prev_content = content.copy()
                    content.pop("r", None)
                    self.main_app.take_message(msgdb['id'],"send_queue")
                    counter +=1
                else:
                    break

        plaintext = Aux.serialize(prev_content,expected_size)
        if pending_messages and counter == 0:
            self.main_app.display_message("Pending Messages not send, increment core_fixed_message_size_KiB")
        
        #self.main_app.display_message("About to send {} plain: {}".format(len(plaintext),plaintext.decode()[:20]))
        encrypted_blob = self.main_app.process_plaintext(self.identity['contact_id'],plaintext,self.identity['ratchet_password'])
        
        #self.main_app.display_message("About to send {} encrypted: {}".format(len(encrypted_blob),encrypted_blob.hex()[:20]))
        if Aux.send(self.tls_sock,encrypted_blob) == False:
            self.main_app.display_message("Client process Aux.send return False")
            self.shutdown()

        if prev_content:
            messages = prev_content.get("messages")
            for msg in messages or []:
                self.main_app.message_sent(msg['id'])
        
        self.is_running = False
                
    def shutdown(self):
        try:
            if self.tls_sock:
                self.tls_sock.close()
            if self.clientsocket:
                self.clientsocket.close()
            self.is_ready = False
            self.is_running = False
        except Exception as e:
            self.main_app.display_message(f"Client shutdown : {e}")

class ClientManager:
    def __init__(self,main_app):
        self.main_app = main_app
        self.is_running = False
        self.interval_seconds = int(self.main_app.config['core_interval_seconds'])
        self.timeout_seconds = int(self.main_app.config['core_timeout_seconds'])
        self.clients = []
        
    def start(self):
        self.is_running = True
        counter = 0
        while self.is_running:
            time.sleep(self.interval_seconds)
            threading.Thread(target=self.process_clients, name="ClientManager_process_clients_{}".format(counter) ,daemon=True).start()
            counter += 1
            
    def process_clients(self):
        for client in self.clients:
            if client.is_ready and not client.is_running:
                #self.main_app.display_message("ClientManager process_clients process: {} -> {}".format(client.identity['contact_id'],client.identity['contact_network_address'] ))
                threading.Thread(target=client.process,name = "client_process_{}".format(client.identity['contact_id']),daemon=True).start()
            if not client.is_ready and not client.is_conecting:
                #self.main_app.display_message("ClientManager process_clients connect: {} -> {}".format(client.identity['contact_id'],client.identity['contact_network_address'] ))
                threading.Thread(target=client.connect,name = "client_connect_{}".format(client.identity['contact_id']),daemon=True).start()
    
    def add_client(self,identity,server_address):
        #self.main_app.display_message("Adding client {} to connect with {}".format(identity['contact_id'],server_address))
        client = Client(self.main_app,identity,server_address,self.timeout_seconds)
        self.clients.append(client)

    def shutdown(self):
        self.is_running = False
