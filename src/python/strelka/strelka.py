import json
import logging
import re
import signal
import time
import uuid

from boltons import iterutils
import inflection
from tldextract import TLDExtract
import ipaddress
import validators


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


class IocOptions(object):
    """
    Defines an ioc options object that can be used to specify the ioc_type for developers as opposed to using a
    string.
    """

    domain = 'domain'
    url = 'url'
    md5 = 'md5'
    sha1 = 'sha1'
    sha256 = 'sha256'
    email = 'email'
    ip = 'ip'


class Scanner(object):
    """Defines a scanner that scans File objects.

    Each scanner inherits this class and overrides methods (init and scan)
    to perform scanning functions.

    Attributes:
        name: String that contains the scanner class name.
            This is referenced in the scanner metadata.
        key: String that contains the scanner's metadata key.
            This is used to identify the scanner metadata in scan results.
        event: Dictionary containing the result of scan
        backend_cfg: Dictionary that contains the parsed backend configuration.
        scanner_timeout: Amount of time (in seconds) that a scanner can spend
            scanning a file. Can be overridden on a per-scanner basis
            (see scan_wrapper).
        coordinator: Redis client connection to the coordinator.
    """
    def __init__(self, backend_cfg, coordinator):
        """Inits scanner with scanner name and metadata key."""
        self.name = self.__class__.__name__
        self.key = inflection.underscore(self.name.replace('Scan', ''))
        self.scanner_timeout = backend_cfg.get('limits').get('scanner')
        self.coordinator = coordinator
        self.event = dict()
        self.iocs = []
        self.type = IocOptions
        self.extract = TLDExtract(suffix_list_urls=None)
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
        self.event = dict()
        self.scanner_timeout = options.get('scanner_timeout',
                                           self.scanner_timeout)

        try:
            self.signal = signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(self.scanner_timeout)
            self.scan(data, file, options, expire_at)
            signal.alarm(0)
        except ScannerTimeout:
            self.flags.append('timed_out')
        except Exception as e:
            signal.alarm(0)
            if isinstance(e, DeprecationWarning) or (e, RequestTimeout):
                raise
            logging.exception(f'{self.name}: exception while scanning'
                              f' uid {file.uid} (see traceback below)')
            self.flags.append('uncaught_exception')

        self.event = {
            **{'elapsed': round(time.time() - start, 6)},
            **{'flags': self.flags},
            **self.event,
        }
        return (
            self.files,
            {self.key: self.event}
        )

    def upload_to_coordinator(self, pointer, chunk, expire_at):
        """Uploads data to coordinator.

        This method is used during scanning to upload data to coordinator,
        where the data is later pulled from during file distribution.

        Args:
            pointer: String that contains the location of the file bytes
                in Redis.
            chunk: String that contains a chunk of data to be added to
                the coordinator.
            expire_at: Expiration date for data stored in pointer.
        """
        p = self.coordinator.pipeline(transaction=False)
        p.rpush(f'data:{pointer}', chunk)
        p.expireat(f'data:{pointer}', expire_at)
        p.execute()

    def process_ioc(self, ioc, ioc_type, scanner_name, description='', malicious=False):
        if not ioc:
            return
        if ioc_type == 'url':
            if validators.ipv4(self.extract(ioc).domain):
                self.process_ioc(self.extract(ioc).domain, 'ip', scanner_name, description, malicious)
            else:
                self.process_ioc(self.extract(ioc).registered_domain, 'domain', scanner_name, description, malicious)
            if not validators.url(ioc):
                logging.warning(f"{ioc} is not a valid url")
                return
        elif ioc_type == 'ip':
            try:
                ipaddress.ip_address(ioc)
            except ValueError:
                logging.warning(f"{ioc} is not a valid IP")
                return
        elif ioc_type == 'domain':
            if not validators.domain(ioc):
                logging.warning(f"{ioc} is not a valid domain")
                return
        elif ioc_type == 'email':
            if not validators.email(ioc):
                logging.warning(f"{ioc} is not a valid email")
                return

        if malicious:
            self.iocs.append({'ioc': ioc, 'ioc_type': ioc_type, 'scanner': scanner_name, 'description': description,
                              'malicious': True})
        else:
            self.iocs.append({'ioc': ioc, 'ioc_type': ioc_type, 'scanner': scanner_name, 'description': description})

    def add_iocs(self, ioc, ioc_type, description='', malicious=False):
        """Adds ioc to the iocs.
        :param ioc: The IOC or list of IOCs to be added. All iocs must be of the same type. Must be type String or Bytes.
        :param ioc_type: Must be one of md5, sha1, sha256, domain, url, email, ip, either as string or type object (e.g. self.type.domain).
        :param description (Optional): Description of the IOCs.
        :param malicious (Optional): Reasonable determination whether the indicator is or would be used maliciously. Example:
          Malware Command and Control. Should not be used solely for determining maliciousness since testing values may be present.
        """
        try:
            accepted_iocs = ['md5', 'sha1', 'sha256', 'domain', 'url', 'email', 'ip']
            if ioc_type not in accepted_iocs:
                logging.warning(f"{ioc_type} not in accepted range. Acceptable ioc types are: {accepted_iocs}")
                return
            if isinstance(ioc, list):
                for i in ioc:
                    if isinstance(i, bytes):
                        i = i.decode()
                    if not isinstance(i, str):
                        logging.warning(f"Could not process {i} from {self.name}: Type {type(i)} is not type Bytes or String")
                        continue
                    self.process_ioc(i, ioc_type, self.name, description=description, malicious=malicious)
            else:
                if isinstance(ioc, bytes):
                    ioc = ioc.decode()
                if not isinstance(ioc, str):
                    logging.warning(f"Could not process {ioc} from {self.name}: Type {type(ioc)} is not type Bytes or String")
                    return
                self.process_ioc(ioc, ioc_type, self.name, description=description, malicious=malicious)
        except Exception as e:
            logging.error(f"Failed to add {ioc} from {self.name}: {e}")

def chunk_string(s, chunk=1024 * 16):
    """Takes an input string and turns it into smaller byte pieces.

    This method is required for inserting data into coordinator.

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

def timeout_handler(signum, frame):
    """Signal ScannerTimeout"""
    raise ScannerTimeout
