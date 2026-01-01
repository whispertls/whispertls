from whispertls.DoubleRatchet import DoubleRatchet
from whispertls.Future import Future
import queue

class RatchetQueue:

    def __init__(self,main_app):
        self.requests = queue.Queue()
        self.is_running = False
        self.main_app = main_app

    def start(self):
        self.is_running = True
        while self.is_running:
            try:
                contact_id,password, data, action, fut = self.requests.get()
                if action == "encrypt":
                    #self.main_app.display_message("About to encrypt: {}".format(data.decode()[:20]))
                    doubleratchet = DoubleRatchet(contact=contact_id,password=password,error_handler_callback=self.main_app.display_error)
                    header,encryptedtext = doubleratchet.RatchetEncrypt(data)
                    #self.main_app.display_message("header: {}".format(header.hex()[:10]))
                    #self.main_app.display_message("encryptedtext: {} ".format(encryptedtext.hex()[:10]))
                    #self.main_app.display_message("together: {} ".format((header+encryptedtext).hex()[:10]))
                    fut.set((header+encryptedtext))
                    doubleratchet.shutdown()
                elif action == "decrypt":
                    doubleratchet = DoubleRatchet(contact=contact_id,password=password,error_handler_callback=self.main_app.display_error)
                    header,encryptedtext = DoubleRatchet.recv(data)
                    plaintext = doubleratchet.RatchetDecrypt(header,encryptedtext)
                    doubleratchet.shutdown()
                    fut.set(plaintext)
                elif action == "shutdown":
                    fut.set("RatchetQueue: SHUDOWN".encode())
                    break
                else:
                    raise ValueError(f"Unexpected action value {action}")
            except Exception as e:
                self.main_app.display_message(f"Unexpected error: {e}")
            finally:
                self.requests.task_done()

    def shutdown(self):
        self.is_running = False
        self.set_task(None,None, None, "shutdown")
    
    def set_task(self,contact_id,password, data, action):
        fut = Future()
        self.requests.put((contact_id,password, data, action,fut))
        result = fut.wait()
        #if result is not None:
        #    self.main_app.display_message("set_task fut result {}".format(result.hex()[:10]))
        return result
