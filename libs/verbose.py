
class display_settings:
    enabled = False

class logger:
    def __init__(self):
        global display_settings


def init(verbose):
    global display_settings
    display_settings.enabled = verbose
