from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.exceptions import InvalidTag
import os

class MasterKey:
    def __init__(self, password: bytes, file = "masterkey.enc",app_path = os.getcwd()):
        self.password = password
        self.masterkey_path = app_path + "/"+ file
        self.masterkey = b'';
        self.success = False
        if not os.path.exists(self.masterkey_path):
            self.masterkey = os.urandom(32)
            encrypted_data = self.encrypt(self.password)
            (encrypted_masterkey, salt, tag, iv) = encrypted_data
            with open(self.masterkey_path, 'wb') as f:
                f.write(encrypted_masterkey + salt + tag + iv)    
                self.success = True
        else:
            with open(self.masterkey_path, 'rb') as f:
                data = f.read()
                encrypted_masterkey = data[:32]
                salt = data[32:48] 
                tag = data[48:64]
                iv = data[64:]
                encrypted_data = (encrypted_masterkey, salt, tag, iv)
                self.masterkey = self.decrypt(encrypted_data,self.password)
                if self.masterkey == b'':
                    self.success = False
                else:
                    self.success = True

    def derive(self, salt: bytes, password:bytes) -> bytes:
        kdf = Argon2id(salt=salt,length=32,iterations=3,memory_cost= 128 * 1024,lanes=1)
        return kdf.derive(password)
        
    def encrypt(self,password : bytes) -> tuple:
        salt = os.urandom(16)
        iv = os.urandom(12)
        derived_key = self.derive(salt,password)
        cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        encrypted_masterkey = encryptor.update(self.masterkey) + encryptor.finalize()
        return (encrypted_masterkey, salt, encryptor.tag, iv)
        
    def decrypt(self,encrypted_data: tuple,password : bytes) -> bytes:
        try:
            (encrypted_masterkey, salt, tag,iv) = encrypted_data
            derived_key = self.derive(salt,password)
            cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv, tag))
            decryptor = cipher.decryptor()
            return decryptor.update(encrypted_masterkey) + decryptor.finalize()
        except InvalidTag:
            return b''
    
    def change_password(self, old_password : bytes,new_password : bytes) -> bool:
        old_masterkey = b''
        with open(self.masterkey_path, 'rb') as f:
            data = f.read()
            encrypted_masterkey = data[:32]
            salt = data[32:48] 
            tag = data[48:64]
            iv = data[64:]
            encrypted_data = (encrypted_masterkey, salt, tag, iv)
            old_masterkey = self.decrypt(encrypted_data,old_password)
        if old_masterkey == self.masterkey:
            encrypted_data = self.encrypt(new_password)
            (encrypted_masterkey, salt, tag, iv) = encrypted_data
            with open(self.masterkey_path, 'wb') as f:
                f.write(encrypted_masterkey + salt + tag + iv)                   
            self.success = True
            self.password = new_password
            return True
        return False
