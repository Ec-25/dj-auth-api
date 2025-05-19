from os import getenv


def getenv_or_error(key: str):
    """Get an environment variable or raise an error if it's not set."""
    value = getenv(key)
    if value is None:
        raise ValueError(f"Environment variable {key} is not set")
    return value
