

def modify_module_name(module_name):
    """Returns a valid modified module to get imported
    """
    return ".".join(module_name.split("/"))