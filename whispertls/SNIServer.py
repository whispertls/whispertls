import hashlib
from cryptography import x509
from cryptography.x509 import load_der_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519,ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID
from whispertls.Aux import Aux
from whispertls.DoubleRatchet import DoubleRatchet
import os
import socket
import ssl
import tempfile
import traceback
import threading

class OOBServer:
    
    def __init__(self,main_app,identity,oob_identity,timeout = 30,error_handler_callback = None):
        self.port = 13444
        self.identity = identity
        self.oob_identity = oob_identity
        self.main_app = main_app
        self.timeout_seconds  = timeout
        self.is_running = False
        if error_handler_callback:
            self.error_handler = error_handler_callback
        else:
            self.error_handler = print
        self.context = self.create_context()
        
        
    def create_context(self):
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as cert_file:
            cert_file.write(self.oob_identity['tls_cert_pem'])
            cert_path = cert_file.name

        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as key_file:
            key_file.write(self.oob_identity['tls_key_pem']) 
            key_path = key_file.name

        try:
            context.load_cert_chain(certfile=cert_path, keyfile=key_path, password=self.oob_identity['tls_key_password'])
        finally:
            os.unlink(cert_path)
            os.unlink(key_path)
        return context
    
    def sni_callback(self, ssl_conn, server_name, context):
        #self.error_handler("sni_callback")
        if server_name.endswith('.onion'):
            server_name = server_name[:-6]
        #self.error_handler("Checking for incomming connection to: {}".format(server_name))
        if server_name != self.oob_identity['network_address']:
            raise ssl.SSLError("Unexpected SNI: {}".format(server_name))

        ssl_conn.context = self.context
        ssl_conn.server_hostname = server_name  

    def start(self):
        self.is_running = True
        conn = None
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.sni_callback = self.sni_callback
        bindsocket = socket.socket()
        #self.error_handler("starting server for {}:{}".format(self.oob_identity['network_address'],self.port))
        try:
            bindsocket.bind(('127.0.0.1', self.port))
            #self.error_handler("bind")
            bindsocket.listen(1)    #We only accept one connection for current OOB exchange
            #self.error_handler("listen")
            bindsocket.settimeout(self.timeout_seconds)
            #self.error_handler("settimeout")
            conn, address = bindsocket.accept()
            #self.error_handler("accept")
            conn.settimeout(self.timeout_seconds )
            with context.wrap_socket(conn, server_side=True) as tls_sock:
                #self.error_handler("wrap_socket")
                self.oob_process_server(tls_sock)
        except (socket.timeout, ssl.SSLError) as e:
            self.error_handler(f"Timeout/SSL error: {e}")
        except OSError as e:
            self.error_handler(f"Socket error: {e}")
        except Exception as e:
            self.error_handler(f"OOBServer start: Unexpected error: {e}")
            tb = e.__traceback__
            for frame in traceback.extract_tb(tb):
                self.error_handler("{} {} {} {}".format(frame.filename, frame.lineno, frame.name, frame.line))

        finally:
            if conn:
                conn.close()
            if bindsocket:
                bindsocket.close()

        self.is_running = False

    def oob_process_server(self,tls_sock):
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
        #self.error_handler("Generated: xkey_public")
        
        tls_cert_pem_signature =identity['privatekey'].sign(identity['tls_cert_pem'])
        entropy = os.urandom(32)
        entropy_signature = identity['privatekey'].sign(entropy)
        #self.error_handler("Generated: entropy")
        
        r = Aux.send(tls_sock,identity['public_bytes'])
        #self.error_handler("Sending to Conctact: public_bytes {}".format(r))
        r = Aux.send(tls_sock,identity['tls_cert_pem'])
        #self.error_handler("Sending to Conctact: tls_cert_pem {}".format(r))
        r = Aux.send(tls_sock,tls_cert_pem_signature)
        #self.error_handler("Sending to Conctact: tls_cert_pem_signature {}".format(r))
        r = Aux.send(tls_sock,xkey_public_bytes)
        #self.error_handler("Sending to Conctact: xkey_public_bytes {}".format(r))
        r = Aux.send(tls_sock,xkey_public_signature)
        #self.error_handler("Sending to Conctact: xkey_public_signature {}".format(r))
        r = Aux.send(tls_sock,entropy)
        #self.error_handler("Sending to Conctact: entropy {}".format(r))
        r = Aux.send(tls_sock,entropy_signature)
        #self.error_handler("Sending to Conctact: entropy_signature {}".format(r))
        
        remote['public_bytes']           = Aux.recv(tls_sock)
        remote['tls_cert_pem']           = Aux.recv(tls_sock)
        remote['tls_cert_pem_signature'] = Aux.recv(tls_sock)
        remote['xkey_public_bytes']      = Aux.recv(tls_sock)
        remote['xkey_public_signature']  = Aux.recv(tls_sock)
        remote['entropy']                = Aux.recv(tls_sock)
        remote['entropy_signature']      = Aux.recv(tls_sock)
                    
        for item in remote.keys():
            if remote[item] is None:
                return False

        remote['identity_public'] = ed25519.Ed25519PublicKey.from_public_bytes(remote['public_bytes'])
        try:
            remote['identity_public'].verify(remote['tls_cert_pem_signature'], remote['tls_cert_pem'])
            remote['identity_public'].verify(remote['xkey_public_signature'], remote['xkey_public_bytes'])
            remote['identity_public'].verify(remote['entropy_signature'], remote['entropy'])
        except Exception as e:
            raise ValueError(f"Signature verification failed: {e}")
        
        remote['tls_certificate'] = x509.load_pem_x509_certificate(remote['tls_cert_pem'], default_backend())
        remote['tls_publickey']   = remote['tls_certificate'].public_key()
        remote['network_address'] = Aux.get_issuer_clean(remote['tls_certificate'].issuer)
        remote['xkey_public'] = x25519.X25519PublicKey.from_public_bytes(remote['xkey_public_bytes'])
        
        if not isinstance(remote['tls_publickey'], ec.EllipticCurvePublicKey):
            raise ValueError(f"tls_publickey is not instance ec.EllipticCurvePublicKey")
        
        # TLS LAYER SHARED SECRET using ECDH
        tls_shared_secret = identity['tls_privatekey'].exchange(ec.ECDH(), remote['tls_publickey'])
        
        # APP LAYER SHARED SECRET using an ephemral ED25519 keys with DH
        app_shared_secret = xkey.exchange(remote['xkey_public'])
        
        derived_entropy    = Aux.HKDF(entropy + remote['entropy'],"verification")
        derived_network    = Aux.HKDF(identity['network_address'].encode() + remote['network_address'].encode(),"verification")
        derived_identities = Aux.HKDF(identity['public_bytes'] + remote['public_bytes'],"verification")
        
        #At this point Alice and Bob should have the same verification_code
        verification_code = Aux.HKDF(
            derived_entropy    + # entropy data from both sides
            derived_network    + # Alice Address + Bob Address
            derived_identities + # Alice identity public key +  Bob identity public key
            tls_shared_secret  + # Alice and Bob TLS shared secret with certificates ECDH
            app_shared_secret,   # Alice and Bob APP shared secret with ephemeral keys
                                 # We put together all layers: Network layer,  identity layer, TLS shared secret, + ephemeral shared_secret
            "Verification Code")
        
        #alice generate a challenge code for bob
        verification_code_bob = Aux.HKDF(verification_code,"Bob")
        verification_code_bob_signature = identity['privatekey'].sign(verification_code_bob)
        
        Aux.send(tls_sock,verification_code_bob)
        Aux.send(tls_sock,verification_code_bob_signature)

        verification_code_alice = Aux.recv(tls_sock)
        verification_code_alice_signature = Aux.recv(tls_sock)
        
        try:
            remote['identity_public'].verify(verification_code_alice_signature, verification_code_alice)
        except Exception as e:
            raise ValueError(f"Signature verification failed: {e}")

        # Alice compare the verfication code send by Bob
        expected_verification_code_alice = Aux.HKDF(verification_code,"Alice")
        if (expected_verification_code_alice != verification_code_alice):
            raise ValueError("Verification code mismatch")

        ratchet_secret = Aux.HKDF(verification_code,"Double Ratchet")
        
        #Here we should initialize the Double Ratchet
        ratchet_state = DoubleRatchet(contact=identity['contact_id'],password=identity['ratchet_password'],error_handler_callback=self.main_app.display_error)
        ratchet_state.RatchetInitAlice(ratchet_secret,remote['xkey_public'])
        header,encryptedtext = ratchet_state.RatchetEncrypt("hello bob!".encode())
        Aux.send(tls_sock,header+encryptedtext)
        
        bob_message = Aux.recv(tls_sock)
        header,encryptedtext = DoubleRatchet.recv(bob_message)
        plaintext = ratchet_state.RatchetDecrypt(header ,  encryptedtext)
        ratchet_state.shutdown()
        
        if(plaintext.decode() != "hello alice!"):
            raise ValueError("Double Ratchet expected message mismatch")

        if self.main_app.add_contactbundle(identity['contact_id'],1,remote['network_address'],remote['tls_cert_pem'],remote['public_bytes']) == 0:
            raise ValueError("Database error add_contactbundle")

        user_verification = Aux.HKDF(verification_code,"user verification")
        if self.main_app.add_verificationcode(identity['contact_id'],user_verification) == 0:
            raise ValueError("Database error add_verificationcode")
        
        self.main_app.display_message("OOB Exchange Success, ask to your contact for the verification code.")
        self.main_app.display_message("Verify it with /verify <code>")


class SNIServer:
    def __init__(self,main_app,error_handler_callback = None,timeout = 30):
        self.main_app = main_app
        self.contexts = {}
        self.is_running = False
        self.timeout_seconds = timeout
        self.port = 0
        if error_handler_callback:
            self.error_handler = error_handler_callback
        else:
            self.error_handler = print
    
    def add_context(self,identity):
        #self.error_handler("SNIServer adding context for this domaina : {}.onion".format(identity['network_address']))
        try:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.maximum_version = ssl.TLSVersion.TLSv1_3
            context.check_hostname = False
            context.verify_mode = ssl.CERT_REQUIRED
            
            with tempfile.NamedTemporaryFile(mode='wb', delete=False) as cert_file:
                cert_file.write(identity['tls_cert_pem'])
                cert_path = cert_file.name
            
            with tempfile.NamedTemporaryFile(mode='wb', delete=False) as key_file:
                key_file.write(identity['tls_key_pem']) 
                key_path = key_file.name
                
            with tempfile.NamedTemporaryFile(mode='wb', delete=False) as clientcert_file:
                clientcert_file.write(identity['contact_cert_pem'])
                clientcert_path = clientcert_file.name

            try:
                context.load_cert_chain(certfile=cert_path, keyfile=key_path,password=identity['tls_key_password'])
                context.load_verify_locations(cafile=clientcert_path)   #For MutualTLS
            finally:
                os.unlink(cert_path)
                os.unlink(key_path)
                os.unlink(clientcert_path)
            
            self.contexts[identity['network_address']] = {
                'identity': identity,
                'context': context
            }
        except Exception as e:
            self.error_handler(f"add_context: {e}")

            
        #self.error_handler(f"✓ Added SSL context for: {hostname}")
    

    def sni_callback(self, ssl_conn, server_name, context):
        #self.error_handler("sni_callback SNI: {}".format(server_name))
        if server_name.endswith('.onion'):
            server_name = server_name[:-6]
        ssl_conn.server_hostname = server_name
        if self.contexts and server_name in self.contexts.keys():
            #self.error_handler("Expected SNI found: {}".format(server_name))
            ssl_conn.context = self.contexts[server_name]['context']
            #self.error_handler("Context Loaded!")
        else:
            raise ssl.SSLError("Unexpected SNI: {}".format(server_name))

    def handle_client(self, conn,address):
        try:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.maximum_version = ssl.TLSVersion.TLSv1_3
            context.verify_mode = ssl.CERT_REQUIRED         # For MutualTLS
            context.sni_callback = self.sni_callback
            with context.wrap_socket(conn, server_side=True) as tls_sock:
                identity = self.contexts[tls_sock.server_hostname]['identity']
                while True:
                    blob = Aux.recv(tls_sock)
                    if blob == None:
                        break
                    self.main_app.process_blob(identity['contact_id'],blob,identity['ratchet_password'])
        except ssl.SSLError as e:
            self.error_handler(f"Server handle_client SSL error: {e}")
        except socket.timeout as e:
            self.error_handler(f"Server handle_client Timeout: {e}")
        except OSError as e:
            self.error_handler(f"Server handle_client Socket error: {e}")
        finally:
            conn.close()
    
    def start(self):
        self.is_running = True
        bindsocket = socket.socket()
        try:
            bindsocket.bind(('127.0.0.1', self.port))
            host, self.port = bindsocket.getsockname()
            #self.error_handler("Server started on port: {}".format(self.port))
            bindsocket.listen(8)
            bindsocket.settimeout(1)
            counter = 0
            while self.is_running:
                try:
                    conn, address = bindsocket.accept()
                    conn.settimeout(self.timeout_seconds)
                    threading.Thread(target=self.handle_client, args=(conn,address), name="SNIServer_handle_client_{}".format(counter),daemon=True).start()
                    counter+=1
                except socket.timeout as e:
                    #self.error_handler(f"Timeout/SSL error: {e}")
                    pass
                except Exception as e:
                    self.error_handler(f"Unexpected error: {e}")
                    tb = e.__traceback__
                    for frame in traceback.extract_tb(tb):
                        errorline = "{} {} {} {}".format(frame.filename, frame.lineno, frame.name, frame.line)
                        self.error_handler(errorline)
        except Exception as e:
            self.error_handler(f"SNIServer:start Unexpected error: {e}")
        finally:
            bindsocket.close()

                
    def shutdown(self):
        self.is_running = False
        
    def get_cert_info_from_der(der_cert):
        certificate = load_der_x509_certificate(der_cert)
        subject = certificate.subject
        public_key = certificate.public_key()
        public_key_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_key_fingerprint = hashlib.sha256(public_key_der).digest()
        return {
            'subject': subject,
            'publickey': public_key,
            'publickey_fingerprint': public_key_fingerprint
        }
        
    def pem_to_der(pem_cert: bytes) -> bytes:
        cert = serialization.load_pem_x509_certificate(pem_cert)
        der_cert = cert.public_bytes(serialization.Encoding.DER)
        return der_cert
        