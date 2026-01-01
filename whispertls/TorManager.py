from time import sleep
from stem.control import Controller
from stem import Signal

class TorManager:

    def __init__(self, control_port=9051, password=None,error_handler_callback = None):
        self.known_services = {}
        self.control_port = control_port
        self.defult_clientport = 13443
        self.controller = None
        self.password = password
        if error_handler_callback:
            self.error_handler = error_handler_callback
        else:
            self.error_handler  = print
        self.connect()


    def connect(self):
        try:
            self.controller = Controller.from_port(port=self.control_port)
            if self.password:
                self.controller.authenticate(self.password)
        except Exception as e:
            self.error_handler(f"Tor control connection failed: {e}")
            return False

    def create_ephemeral_hidden_service(self,tor_port = None,os_port = None):
        if tor_port is None:
                tor_port = self.defult_clientport
        if os_port is None:
                os_port = self.defult_clientport
        
        service = self.controller.create_ephemeral_hidden_service({tor_port: os_port}, await_publication = False)
        self.known_services[service.service_id] = {}
        self.known_services[service.service_id]['private_key'] = service.private_key
        self.known_services[service.service_id]['service_id'] = service.service_id
        self.known_services[service.service_id]['tor_port'] = tor_port
        self.known_services[service.service_id]['os_port'] = os_port
        return service.service_id, service.private_key

    def resume_ephemeral_hidden_service(self,private_key,tor_port = None,os_port = None):
        if tor_port is None:
                tor_port = self.defult_clientport
        if os_port is None:
                os_port = self.defult_clientport
        service = self.controller.create_ephemeral_hidden_service({tor_port: os_port}, key_type = 'ED25519-V3', key_content = private_key, await_publication = False)
        self.known_services[service.service_id] = {}
        self.known_services[service.service_id]['private_key'] = service.private_key
        self.known_services[service.service_id]['service_id'] = service.service_id
        self.known_services[service.service_id]['tor_port'] = tor_port
        self.known_services[service.service_id]['os_port'] = os_port
        return service.service_id

    def list_ephemeral_hidden_services(self):
        return list(self.known_services.values())

    def remove_ephemeral_hidden_service(self, domain):
        self.controller.remove_ephemeral_hidden_service(domain)
        self.known_services.pop(domain)
        #self.error_handler("Removed HD {}".format(domain))

    def force_new_circuit_for_hs(self,hs_address):
        for circuit in self.controller.get_circuits():
            if circuit.status == 'BUILT':
                for stream in self.controller.get_streams():
                    if stream.target_address == hs_address.replace('.onion', ''):
                        # Kill the stream, which forces a new circuit on next connection
                        self.controller.close_stream(stream.id)
        self.controller.signal(Signal.NEWNYM)

    def force_new_circuit_for_all(self):
        for circuit in self.controller.get_circuits():
            if circuit.status == 'BUILT':
                for stream in self.controller.get_streams():
                    self.controller.close_stream(stream.id)
        self.controller.signal(Signal.NEWNYM)

    def shutdown(self):
        for key in list(self.known_services):
            self.remove_ephemeral_hidden_service(key)
            
            
