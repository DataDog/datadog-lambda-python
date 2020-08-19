
def conditional_decorator(dec, condition):
    def decorator(func):
        if condition:
            return func
        return dec(func)
    return decorator
