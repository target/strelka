class QuitStrelka(Exception):
    """Raised when Strelka server exits."""
    pass


class QuitWorker(Exception):
    """Raised when Strelka worker exits."""
    pass


class RequestTimeout(Exception):
    """Raised when request times out."""
    pass


class DistributionTimeout(Exception):
    """Raised when file distribution times out."""
    pass


class ScannerTimeout(Exception):
    """Raised when scanner `scan` times out."""
    pass


class CloseTimeout(Exception):
    """Raised when scanner `close` times out."""
    pass
