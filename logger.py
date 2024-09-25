
class settings:
    enabled = False
    level = 0

class logger:
    global settings
    def print(*args, **kargs):
        if settings.level == 0:
            return;
        print(*args)
        for key, value in kargs.items():
            print("{} is {}".format(key,value)) 

    def __init__(self):
        global settings
        print("Logger initialized with level "+str(settings.level)+".")

def init(verbose, level = 1):
    global settings
    settings.enabled = verbose
    settings.level = level
