# Store the configuration value
class settings:
    enabled = False
    #Level of the verbosity
    level = 0

class logger:
    # Access the global settings
    global settings
    # Custom print function that handles logging messages and keyword arguments
    def print(*args, **kargs):
        # If verbosity == 0 quit the function
        if settings.level == 0:
            return;
        # elseIf logging enable, print all the arguments passed to the function 
        print(*args)
        # Loop throught keyxord argulents, and print them.
        for key, value in kargs.items():
            print("{} is {}".format(key,value)) 

    def __init__(self):
        # Access the global settings
        global settings
        # Print the current verbosity level
        print("Logger initialized with level "+str(settings.level)+".")

# Fonction to initialize logging settings
def init(verbose, level = 1):
    # Get the global settings object
    global settings
    # Set the 'enable' flag in setting to verbose
    settings.enabled = verbose
    # Set the logging level, default to 1 if not specified
    settings.level = level
    
