import threading
#import queue
#import time

class Future:
    def __init__(self):
        self.event = threading.Event()
        self.result = None

    def set(self, value):
        self.result = value
        self.event.set()

    def wait(self):
        self.event.wait()
        return self.result