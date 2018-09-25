"""Defines error classes."""


class DistributionTimeout(RuntimeError):
    """Raised when files timeout during file distribution."""
    pass


class ScannerTimeout(RuntimeError):
    """Raised when scanners timeout during file scanning."""
    pass


class CloseTimeout(RuntimeError):
    """Raised when scanners timeout during scanner closing."""
    pass


class QuitDirStream(RuntimeError):
    """Raised when dirstream.py shuts down."""
    pass


class QuitStrelka(RuntimeError):
    """Raised when strelka.py shuts down."""
    pass


class QuitBroker(RuntimeError):
    """Raised when a broker shuts down."""
    pass


class QuitLogRotate(RuntimeError):
    """Raised when a log rotation process shuts down."""
    pass


class QuitWorker(RuntimeError):
    """Raised when a worker shuts down."""
    pass
