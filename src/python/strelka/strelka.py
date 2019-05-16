import json
import logging
import re
import time
import uuid

from boltons import iterutils
import inflection
import interruptingcow


class RequestTimeout(Exception):
    """Raised when request times out."""
    pass


class DistributionTimeout(Exception):
    """Raised when file distribution times out."""
    pass


class ScannerTimeout(Exception):
    """Raised when scanner times out."""
    pass


class File(object):
    """Defines a file that will be scanned.

    This object contains metadata that describes files input into the
    system. The object should only contain data is that is not stored
    elsewhere (e.g. file bytes stored in Redis). In future releases this
    object may be removed in favor of a pure-Redis design.

    Attributes:
        flavors: Dictionary of flavors assigned to the file during distribution.
        uid: String that contains a universally unique identifier (UUIDv4)
            used to uniquely identify the file.
        depth: Integer that represents how deep the file was embedded.
        parent: UUIDv4 of the file that produced this file.
        pointer: String that contains the location of the file bytes in Redis.
        name: String that contains the name of the file.
        source: String that describes which scanner the file originated from.
    """
    def __init__(self, pointer='',
                 parent='', depth=0,
                 name='', source=''):
        """Inits file object."""
        self.flavors = {}
        self.uid = str(uuid.uuid4())
        self.depth = depth
        self.name = name
        self.parent = parent
        self.pointer = pointer or self.uid
        self.source = source

    def add_flavors(self, flavors):
        """Adds flavors to the file.

        In cases where flavors and self.flavors share duplicate keys, flavors
        will overwrite the duplicate value.
        """
        self.flavors = {**self.flavors, **flavors}


class Scanner(object):
    """Defines a scanner that scans File objects.

    Each scanner inherits this class and overrides methods (init and scan)
    to perform scanning functions.

    Attributes:
        name: String that contains the scanner class name.
            This is referenced in the scanner metadata.
        key: String that contains the scanner's metadata key.
            This is used to identify the scanner metadata in scan results.
        backend_cfg: Dictionary that contains the parsed backend configuration.
        scanner_timeout: Amount of time (in seconds) that a scanner can spend
            scanning a file. Can be overridden on a per-scanner basis
            (see scan_wrapper).
        cache: Redis client connection to the cache.
    """
    def __init__(self, backend_cfg, cache):
        """Inits scanner with scanner name and metadata key."""
        self.name = self.__class__.__name__
        self.key = inflection.underscore(
            self.name.replace('Scan', '', 1),
        )
        self.scanner_timeout = backend_cfg.get('limits').get('scanner')
        self.cache = cache
        self.init()

    def init(self):
        """Overrideable init.

        This method can be used to setup one-time variables required
        during scanning."""
        pass

    def scan(self,
             data,
             file,
             options,
             expire_at):
        """Overrideable scan method.

        Args:
            data: Data associated with file that will be scanned.
            file: File associated with data that will be scanned (see File()).
            options: Options to be applied during scan.
            expire_at: Expiration date for any files extracted during scan.
        """
        pass

    def scan_wrapper(self,
                     data,
                     file,
                     options,
                     expire_at):
        """Sets up scan attributes and calls scan method.

        Scanning code is wrapped in try/except for error handling.
        The scanner always returns a list of extracted files (which may be
        empty) and metadata regardless of whether the scanner completed
        successfully or hit an exception.

        Args:
            data: Data associated with file that will be scanned.
            file: File associated with data that will be scanned (see File()).
            options: Options to be applied during scan.
            expire_at: Expiration date for any files extracted during scan.
        Returns:
            List of extracted File objects (may be empty).
            Dictionary of scanner metadata.
        Raises:
            DistributionTimeout: interrupts the scan when distribution times out.
            RequestTimeout: interrupts the scan when request times out.
            Exception: Unknown exception occurred.
        """
        start = time.time()
        self.files = []
        self.flags = []
        self.event = {}
        self.scanner_timeout = options.get('scanner_timeout',
                                           self.scanner_timeout)

        try:
            with interruptingcow.timeout(self.scanner_timeout,
                                         ScannerTimeout):
                self.scan(data, file, options, expire_at)

        except ScannerTimeout:
            self.flags.append('timed_out')
        except (DistributionTimeout, RequestTimeout):
            raise
        except Exception:
            logging.exception(f'{self.name}: exception while scanning'
                              f' uid {file.uid} (see traceback below)')
            self.flags.append('uncaught_exception')

        self.event = {
            **{'elapsed': (time.time() - start)},
            **{'flags': self.flags},
            **self.event,
        }
        return (
            self.files,
            {self.key: self.event}
        )

    def upload_to_cache(self, pointer, chunk, expire_at):
        """Uploads data to cache.

        This method is used during scanning to upload data to cache,
        where the data is later pulled from during file distribution.

        Args:
            pointer: String that contains the location of the file bytes
                in Redis.
            chunk: String that contains a chunk of data to be added to
                the cache.
            expire_at: Expiration date for data stored in pointer.
        """
        p = self.cache.pipeline(transaction=False)
        p.rpush(pointer, chunk)
        p.expireat(pointer, expire_at)
        p.execute()


def chunk_string(s, chunk=1024 * 16):
    """Takes an input string and turns it into smaller byte pieces.

    This method is required for inserting data into cache.

    Yields:
        Chunks of the input string.
    """
    if isinstance(s, bytearray):
        s = bytes(s)

    for c in range(0, len(s), chunk):
        yield s[c:c + chunk]


def normalize_whitespace(text):
    """Normalizes whitespace in text.

    Scanners that parse text generally need whitespace normalized, otherwise
    metadata parsed from the text may be unreliable. This function normalizes
    whitespace characters to a single space.

    Args:
        text: Text that needs whitespace normalized.
    Returns:
        Text with whitespace normalized.
    """
    if isinstance(text, bytes):
        text = re.sub(br'\s+', b' ', text)
        text = re.sub(br'(^\s+|\s+$)', b'', text)
    elif isinstance(text, str):
        text = re.sub(r'\s+', ' ', text)
        text = re.sub(r'(^\s+|\s+$)', '', text)
    return text


def format_event(metadata):
    """Formats file metadata into an event.

    This function must be used on file metadata before the metadata is
    pushed to Redis. The function takes a dictionary containing a
    complete file event and runs the following (sequentially):
        * Replaces all bytes with strings
        * Removes all values that are empty strings, empty lists,
            empty dictionaries, or None
        * Dumps dictionary as JSON

    Args:
        metadata: Dictionary that needs to be formatted into an event.

    Returns:
        JSON-formatted file event.
    """
    def visit(path, key, value):
        if isinstance(value, (bytes, bytearray)):
            value = str(value, encoding='UTF-8', errors='replace')
        return key, value

    remap1 = iterutils.remap(metadata, visit=visit)
    remap2 = iterutils.remap(
        remap1,
        lambda p, k, v: v != '' and v != [] and v != {} and v is not None,
    )
    return json.dumps(remap2)
