import datetime
import getpass
import json
import os
import random
import secrets
import struct
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

class Aux:
    def generate_keypair(curve,type):
        private = None
        public = None
        if curve == 'x25519':
            private = x25519.X25519PrivateKey.generate()
        elif curve == 'ed25519':
            private = ed25519.Ed25519PrivateKey.generate()
        else:
            raise Exception("unknown curve: {}".format(curve))
        public = private.public_key()
        if type == 'object':
            return private,public
        elif type == 'bytes':
            return private.private_bytes_raw(),public.public_bytes_raw()
        else:
            raise Exception("unknown type: {}".format(type))

    @staticmethod
    def serialize(data,expected_size = 2):
        temp =  json.dumps(
            data,
            separators=(',', ':'),
            sort_keys=True,
            ensure_ascii=False
        ).encode('utf-8')
        current_size = len(temp)
        overhead = len(b',"r":""')
        while True:
            padding_bytes_needed = expected_size - current_size -overhead
            if padding_bytes_needed < 0:
                expected_size *= 2
            else:
                break
            
        urandom_bytes = padding_bytes_needed // 2
        data["r"] = os.urandom(urandom_bytes).hex()
        temp =  json.dumps(
            data,
            separators=(',', ':'),
            sort_keys=True,
            ensure_ascii=False
        )
        current_size = len(temp)
        while current_size < expected_size:
            temp += ' '
            current_size = len(temp)    
        return temp.encode('utf-8')

    @staticmethod
    def generate_tlsidentity(hostname,minutes = 10):
        private_key = ec.generate_private_key(ec.SECP256R1(),default_backend())
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(minutes=minutes)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]),
            critical=True
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        ).add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=False
        ).sign(
            private_key, hashes.SHA256(), default_backend()
        )    
        password = secrets.token_hex(32)
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        encrypted_key = private_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.BestAvailableEncryption(password.encode()))
        return cert_pem, encrypted_key, password

    @staticmethod
    def HKDF(data,purpose):
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=purpose.encode()
            ).derive(data)

    @staticmethod    
    def send(tls_sock,data):
        try:
            message_length = len(data)
            length_prefix = struct.pack('!H', message_length)
            tls_sock.sendall(length_prefix)
            tls_sock.sendall(data)
            return True
        except Exception as e:
            return False

    @staticmethod
    def recv(tls_sock):
        length_bytes = Aux.recv_exact(tls_sock,2)
        if length_bytes is None or len(length_bytes) < 2:
            return None
        message_length = struct.unpack('!H', length_bytes)[0]

        data = Aux.recv_exact(tls_sock,message_length)
        if data is None or len(data) < message_length:
            return None
        return data

    @staticmethod
    def recv_exact(tls_sock,n):
        buf = b''
        while len(buf) < n:
            chunk = tls_sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf   

    def get_issuer_clean(issuer):
        issuer_str = ', '.join([f"{attribute.oid._name}={attribute.value}" for attribute in issuer])
        return issuer_str.replace("CN=", "").replace("commonName=", "")
