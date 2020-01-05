_cold_start = True
_lambda_container_initialized = False


def set_cold_start():
    """Set the value of the cold start global

    This should be executed once per Lambda execution before the execution
    """
    global _cold_start
    global _lambda_container_initialized
    _cold_start = not _lambda_container_initialized
    _lambda_container_initialized = True


def is_cold_start():
    """Returns the value of the global cold_start
    """
    return _cold_start


def get_cold_start_tag():
    """Returns the cold start tag to be used in metrics
    """
    return f"cold_start:{str(is_cold_start()).lower()}"
