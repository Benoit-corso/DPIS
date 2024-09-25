from libs import packet as lpkt
from libs import logger

class settings:
    proto = None

# this function isn't multi threaded
class injector:
    # execute events from proto
    def hook(pkt):
        True

    # inject packet from proto
    def inject(pkt):
        True

    def __init__(self):
        global settings

def init(proto = None):
    global settings
    if proto is None:
        # actually don't have simple tcp session handler
        print("can't use injector without protocol.")
        return;
    settings.proto = importlib.import_module("libs.proto"+proto)
