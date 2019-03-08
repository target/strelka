from datetime import datetime
import glob
import hashlib
import importlib
import json
import logging
import multiprocessing
import os
import re
import string
import threading
import time
import uuid

from boltons import iterutils
# import boto3
# from google.cloud.storage import Client
import grpc
import inflection
import interruptingcow
import magic
import requests
# import swiftclient
import yara

from etc import conf

client_amazon = None
client_google = None
client_openstack = None
compiled_magic = None
compiled_yara = None
scanner_cache = {}


class DistributionTimeout(Exception):
    """Raised when file distribution times out."""
    pass


class ScannerTimeout(Exception):
    """Raised when a scanner times out."""
    pass


class StrelkaFile(object):
    """Defines a Strelka file object.

    Attributes:
        data: Byte string that contains the file content.
        filename: String that contains the name of the file.
        source: String that describes where the file originated.
        depth: Int that represents how deep the file was embedded.
        parent_hash: SHA256 hash of the parent file.
        root_hash: SHA256 hash of the root file.
        parent_uid: UUID of the parent file.
        root_uid: UUID of the root file.
        flags: List of flags appended during scanning.
        flavors: Dictionary of flavors identified during scanning.
        metadata: Dictionary of metadata appended during scanning.
        scanner_list: List of scanners assigned to the file during distribution.
    """
    def __init__(self, data=b'', depth=0,
                 filename='', source='',
                 hash='', parent_hash='', root_hash='',
                 uid=uuid.uuid4(), parent_uid='', root_uid=''):
        """Inits file object."""
        self.data = data
        self.depth = depth
        self.filename = filename
        self.source = source
        self.hash = hash
        self.parent_hash = parent_hash
        self.root_hash = root_hash
        self.uid = uid
        self.parent_uid = parent_uid
        self.root_uid = root_uid
        self.flags = []
        self.flavors = {}
        self.metadata = {}
        self.scanner_list = []

    def format_data(self):
        """Ensures data is always a byte string."""
        if isinstance(self.data, bytearray):
            self.data = bytes(self.data)
        elif isinstance(self.data, str):
            self.data = self.data.encode('utf-8')

    def calculate_hash(self):
        """Calculates SHA256 hash of data."""
        self.hash = hashlib.sha256(self.data).hexdigest()

    def add_flavors(self, flavors):
        """Merges object flavors with new flavors.

        In cases where flavors and self.flavors share duplicate keys, flavors
        will overwrite the duplicate value.
        """
        self.flavors = {**self.flavors, **ensure_utf8(flavors)}

    def add_ext_flavors(self, ext_flavors):
        """Convenience method for external flavors.

        Calling this method will overwrite previously written external flavors.
        """
        self.add_flavors({'external': ext_flavors})

    def add_metadata(self, metadata):
        """Merges object metadata with new metadata.

        In cases where metadata and self.metadata share duplicate keys, metadata
        will overwrite the duplicate value."""
        self.metadata = {**self.metadata, **ensure_utf8(metadata)}

    def add_ext_metadata(self, ext_metadata):
        """Convenience method for external metadata.

        Calling this method will overwrite previously written external metadata.
        """
        self.add_metadata({'externalMetadata': ext_metadata})

    def taste_mime(self):
        """Tastes file data with libmagic.

        Tastes file data with libmagic and appends the MIME type as a flavor.
        MIME database is configurable via 'scan.yaml'. Method should only be
        called after data is fully written to.

        Raises:
            MagicException: Unknown magic error.
        """
        try:
            global compiled_magic
            if compiled_magic is None:
                taste_mime_db = conf.scan_cfg.get('taste_mime_db')
                compiled_magic = magic.Magic(magic_file=taste_mime_db,
                                             mime=True)
            mime_type = compiled_magic.from_buffer(self.data)
            self.add_flavors({'mime': [mime_type]})

        except magic.MagicException:
            self.flags.append('StrelkaFile::magic_exception')
            logging.exception('Exception while tasting with magic'
                              f' ({taste_mime_db}) (see traceback below)')

    def taste_yara(self):
        """Tastes file data with YARA.

        Tastes file data with YARA and appends the matches as a flavor.
        Whitespace is stripped from the leftside of the file data to increase
        the reliability of YARA matching. YARA rules are configurable via
        'scan.yaml' and may be applied as either a single file or a directory
        of rules. Method should only be called after data is fully written to.

        Raises:
            YaraError: Unknown YARA error or YARA timeout.
        """
        try:
            global compiled_yara
            if compiled_yara is None:
                taste_yara_rules = conf.scan_cfg.get('taste_yara_rules')
                if os.path.isdir(taste_yara_rules):
                    yara_filepaths = {}
                    globbed_yara_paths = glob.iglob(f'{taste_yara_rules}/**/*.yar*',
                                                    recursive=True)
                    for (idx, entry) in enumerate(globbed_yara_paths):
                        yara_filepaths[f'namespace_{idx}'] = entry
                    compiled_yara = yara.compile(filepaths=yara_filepaths)
                else:
                    compiled_yara = yara.compile(filepath=taste_yara_rules)

            encoded_whitespace = string.whitespace.encode()
            stripped_data = self.data.lstrip(encoded_whitespace)
            yara_matches = compiled_yara.match(data=stripped_data)
            self.add_flavors({'yara': [match.rule for match in yara_matches]})

        except (yara.Error, yara.TimeoutError) as YaraError:
            self.flags.append('StrelkaFile::yara_scan_error')
            logging.exception('Exception while tasting with YARA'
                              f' ({taste_yara_rules}) (see traceback below)')


class StrelkaScanner(object):
    """Defines a Strelka scanner.

    Each scanner inherits this class and overrides methods (init and scan)
    within the class to perform scanning functions.

    Attributes:
        scanner_name: String that contains the scanner class name.
            This is referenced in flags and child filenames.
        metadata_key: String that contains the scanner's metadata key.
            This is used to identify the scanner metadata in scan results.
        scanner_timeout: Amount of time (in seconds) that a scanner can spend
            scanning a file. Can be overridden on a per-scanner basis
            (see scan_wrapper).
            Defaults to 600 seconds / 5 minutes.
        metadata: Dictionary where scanner metadata is stored.
        children: List where scanner child files are stored.
    """
    def __init__(self):
        """Inits scanner with scanner name and metadata key."""
        self.scanner_name = self.__class__.__name__
        metadata_key = self.scanner_name.replace('Scan', '', 1) + 'Metadata'
        self.metadata_key = inflection.camelize(metadata_key, False)
        self.scanner_timeout = conf.scan_cfg.get('scanner_timeout', 300)
        self.init()

    def init(self):
        """Overrideable init."""
        pass

    def scan(self,
             file_object,
             options):
        """Overrideable scan method.

        Args:
            file_object: StrelkaFile to be scanned.
            options: Options to be applied during scan.
        """
        pass

    def scan_wrapper(self,
                     file_object,
                     options):
        """Sets up scan attributes and calls scan method.

        Scanning code is wrapped in try/except to handle error handling.
        The file object is always appended with metadata regardless of whether
        the scanner completed successfully or hit an exception. This method
        always returns the list of children.

        Args:
            file_object: StrelkaFile to be scanned.
            options: Options to be applied during scan.
        Returns:
            Children files (whether they exist or not).
        Raises:
            Exception: Unknown exception occurred.
        """
        self.metadata = {}
        self.children = []
        self.scanner_timeout = options.get('scanner_timeout',
                                           self.scanner_timeout)

        try:
            with interruptingcow.timeout(self.scanner_timeout,
                                         ScannerTimeout):
                self.scan(file_object, options)

        except DistributionTimeout:
            raise
        except ScannerTimeout:
            file_object.flags.append(f'{self.scanner_name}::timed_out')
        except Exception:
            logging.exception(f'{self.scanner_name}: exception while scanning'
                              f' file with hash {file_object.hash} and uid'
                              f' {file_object.uid} (see traceback below)')

        file_object.add_metadata({self.metadata_key: self.metadata})
        return self.children


def ensure_utf8(value):
    """Recursively converts bytes, bytearrays, and UUIDs to strings.

    Scanners may output data that contains bytes, bytearrays, or UUIDs and
    these types need to be converted to strings to be encoded as JSON.

    Args:
        value: Value that needs values (bytes, bytearrays, or UUIDs) recursively
            converted to UTF-8 encoded strings.
    Returns:
        A UTF-8 encoded string representation of value.
    """
    def visit(path, key, value):
        if isinstance(value, (bytes, bytearray)):
            value = str(value, encoding='UTF-8', errors='replace')
        elif isinstance(value, uuid.UUID):
            value = str(value)
        return key, value

    return iterutils.remap(value, visit=visit)


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


def schedule_data(file_object, cli_request, tmp_file):
    """Processes request from StreamData.

    This function is called by the gRPC servicer and kicks off a file data scan.
    Data from the temporary file is stored in the file object then removed from
    disk. File object is recursively sent through the distribution function and
    resulting scan results are sent back to the gRPC servicer.

    Args:
        file_object: StrelkaFile to be scanned.
        cli_request: Dictionary containing client request metadata.
        tmp_file: Location of the tmp_file to be loaded as data.
    """
    if not conf.scan_cfg:
        conf.load_scan(conf.server_cfg.get('scan_cfg'))
        logging.info(f'{multiprocessing.current_process().name}: loaded scan cfg')

    # terrible, awful hack to get interruptingcow to play nicely in a subprocess
    if threading.current_thread().name != 'MainThread':
        threading.current_thread().name = 'MainThread'

    with open(tmp_file, 'rb') as f:
        file_object.data = f.read()
    os.remove(tmp_file)

    scan_result = {'request': cli_request, 'results': []}
    start_time = datetime.utcnow()
    distribute(file_object, scan_result)
    finish_time = datetime.utcnow()
    elapsed_time = (finish_time - start_time).total_seconds()
    scan_result['startTime'] = start_time.isoformat(timespec='seconds')
    scan_result['finishTime'] = finish_time.isoformat(timespec='seconds')
    scan_result['elapsedTime'] = elapsed_time

    return scan_result


def schedule_location(file_object, cli_request, location):
    """Processes request from SendLocation.

    This function is called by the gRPC servicer and kicks off a file location
    scan. The location is retrieved and data is stored in the file object. The
    file object is recursively sent through the distribution function and
    resulting scan results are sent back to the gRPC servicer.

    Args:
        file_object: StrelkaFile to be scanned.
        cli_request: Dictionary containing client request metadata.
        location: Location of the data to be retrieved.
    """
    if not conf.scan_cfg:
        conf.load_scan(conf.server_cfg.get('scan_cfg'))
        logging.info(f'{multiprocessing.current_process().name}: loaded scan cfg')

    # terrible, awful hack to get interruptingcow to play nicely in a subprocess
    if threading.current_thread().name != 'MainThread':
        threading.current_thread().name = 'MainThread'

    location_type = location.get('type')
    if location_type == 'amazon':
        pass  # not currently supported
    elif location_type == 'google':
        pass  # not currently supported
    elif location_type == 'swift':
        pass  # not currently supported
    elif location_type == 'http':
        file_object.data = retrieve_from_http(location)

    scan_result = {'request': cli_request, 'results': []}
    start_time = datetime.utcnow()
    distribute(file_object, scan_result)
    finish_time = datetime.utcnow()
    elapsed_time = (finish_time - start_time).total_seconds()
    scan_result['startTime'] = start_time.isoformat(timespec='seconds')
    scan_result['finishTime'] = finish_time.isoformat(timespec='seconds')
    scan_result['elapsedTime'] = elapsed_time

    return scan_result


def distribute(file_object, scan_result):
    """Distributes a file through scanners.

    This method defines how files are assigned scanners:
        1. File data is formatted to bytes.
        2. File hash is calculated and roots assigned.
        3. File flavors are tasted via MIME and YARA.
        4. Scanner mapping from scan configuration is applied to flavors.
        5. File is recursively sent to the mapped scanners.

    Args:
        file_object: StrelkaFile to be scanned.
        scan_result: Dictionary that scan results are appended to.
    """
    file_object.format_data()
    file_object.calculate_hash()
    if file_object.depth == 0:
        file_object.root_hash = file_object.hash
        file_object.root_uid = file_object.uid
    file_object.taste_mime()
    file_object.taste_yara()
    scanner_cfg = conf.scan_cfg.get('scanners', [])
    merged_flavors = (file_object.flavors.get('external', []) +
                      file_object.flavors.get('mime', []) +
                      file_object.flavors.get('yara', []))
    scanner_list = []
    for scanner_name in scanner_cfg:
        scanner_mappings = scanner_cfg.get(scanner_name, {})
        assigned_scanner = assign_scanner(scanner_name,
                                          scanner_mappings,
                                          merged_flavors,
                                          file_object.filename,
                                          file_object.source)
        if assigned_scanner is not None:
            scanner_list.append(assigned_scanner)
            file_object.scanner_list.append(scanner_name)

    scanner_list.sort(key=lambda k: k.get('priority', 5), reverse=True)
    maximum_depth = conf.scan_cfg.get('maximum_depth')
    if file_object.depth <= maximum_depth:
        children = []

        try:
            with interruptingcow.timeout(conf.scan_cfg.get('distribution_timeout', 600),
                                         exception=DistributionTimeout):
                for scanner in scanner_list:
                    try:
                        scanner_name = scanner['scanner_name']
                        und_scanner_name = inflection.underscore(scanner_name)
                        scanner_import = f'server.scanners.{und_scanner_name}'
                        module = importlib.import_module(scanner_import)
                        if und_scanner_name not in scanner_cache:
                            scanner_cache[und_scanner_name] = getattr(module,
                                                                      scanner_name)()
                        scanner_options = scanner.get('options', {})
                        scanner_plugin = scanner_cache[und_scanner_name]
                        file_children = scanner_plugin.scan_wrapper(file_object,
                                                                    scanner_options)
                        children.extend(file_children)

                    except ModuleNotFoundError:
                        logging.exception(f'scanner {scanner_name} not found')

                unique_flags = list(dict.fromkeys(file_object.flags))
                result_output = {'flags': ensure_utf8(unique_flags),
                                 'flavors': file_object.flavors,
                                 **file_object.metadata}
                scan_result['results'].append(result_output)

        except DistributionTimeout:
            logging.exception(f'file with hash {file_object.hash} (uid'
                              f' {file_object.uid}) timed out')

        for child in children:
            distribute(child, scan_result)

    else:
        logging.info(f'file with hash {file_object.hash} (root hash'
                     f' {file_object.root_hash}) exceeded maximum depth')


def assign_scanner(scanner, mappings, flavors, filename, source):
    """Assigns scanners based on mappings and file data.

    Performs the task of assigning scanners based on the scan configuration
    mappings and file flavors, filename, and source. Assignment supports
    positive and negative matching: scanners are assigned if any positive
    categories are matched and no negative categories are matched. Flavors are
    literal matches, filename and source matches uses regular expressions.

    Args:
        scanner: Name of the scanner to be assigned.
        mappings: List of dictionaries that contain values used to assign
            the scanner.
        flavors: List of file flavors to use during scanner assignment.
        filename: Filename to use during scanner assignment.
        source: File source to use during scanner assignment.
    Returns:
        Dictionary containing the assigned scanner or None.
    """
    for mapping in mappings:
        negatives = mapping.get('negative', {})
        positives = mapping.get('positive', {})
        neg_flavors = negatives.get('flavors', [])
        neg_filename = negatives.get('filename', None)
        neg_source = negatives.get('source', None)
        pos_flavors = positives.get('flavors', [])
        pos_filename = positives.get('filename', None)
        pos_source = positives.get('source', None)
        assigned_scanner = {'scanner_name': scanner,
                            'priority': mapping.get('priority', 5),
                            'options': mapping.get('options', {})}

        for neg_flavor in neg_flavors:
            if neg_flavor in flavors:
                return None
        if neg_filename is not None:
            if re.search(neg_filename, filename) is not None:
                return None
        if neg_source is not None:
            if re.search(neg_source, source) is not None:
                return None
        for pos_flavor in pos_flavors:
            if pos_flavor == '*' or pos_flavor in flavors:
                return assigned_scanner
        if pos_filename is not None:
            if re.search(pos_filename, filename) is not None:
                return assigned_scanner
        if pos_source is not None:
            if re.search(pos_source, source) is not None:
                return assigned_scanner
    return None


def result_to_evt(scan_result, bundle=False, case='snake'):
    """Transforms scan result into JSON events.

    Takes a scan result and returns it as a JSON-formatted list of strings with
    empty values (strings, lists, and dictionaries) removed, the keys formatted
    according to case, and the results arranged according to bundle.

    Args:
        scan_result: Scan result to be remapped and formatted.
        case: Format (camel or snake) of the dictionary keys.
    Returns:
        List of JSON-formatted 'event' strings.
    """
    empty_lambda = lambda p, k, v: v != '' and v != [] and v != {}

    def snake(path, key, value):
        if not isinstance(key, int):
            return (inflection.underscore(key), value)
        return (key, value)

    if case == 'snake':
        remapped = iterutils.remap(scan_result, empty_lambda)
        result = iterutils.remap(remapped, visit=snake)
    else:  # default case is 'camel'
        result = iterutils.remap(scan_result, empty_lambda)

    if not bundle:
        result_list = []
        results = result.pop('results')
        for r in results:
            result_list.append(json.dumps({**r, **result}))
        return result_list
    return [json.dumps(result)]


def retrieve_from_amazon(location):  # untested in gRPC migration
    """Retrieves file from Amazon AWS.

    Args:
        location: Location of AWS object.

    Returns:
        AWS object data.
    """
    global client_amazon
    if client_amazon is None:
        client_amazon = boto3.client('s3',
                                     aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
                                     aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'))
    return client_amazon.get_object(Bucket=location.get('bucket'), Key=location.get('object'))['Body'].read()


def retrieve_from_google(location):  # untested in gRPC migration
    """Retrieves file from Google GCP.

    Args:
        location: Location of GCP object.

    Returns:
        GCP object data.
    """
    global client_google
    if client_google is None:
        client_google = Client.from_service_account_json(os.environ.get('GOOGLE_APPLICATION_CREDENTIALS'))
    return client_google.get_bucket(location.get('bucket')).get_blob(location.get('object')).download_as_string()


def retrieve_from_http(location):
    """Retrieves file from HTTP.

    Args:
        location: Location of HTTP object.

    Returns:
        HTTP response data.
    """
    try:
        response = requests.get(location.get('object'),
                                allow_redirects=True,
                                stream=True,
                                auth=(os.environ.get('HTTP_BASIC_USER'),
                                      os.environ.get('HTTP_BASIC_PASS')),
                                timeout=os.environ.get('HTTP_TIMEOUT'),
                                verify=os.environ.get('HTTP_VERIFY'))
        if response.status_code == 200:
            return response.raw.read()
        elif response.status_code:
            return b''
    except requests.exceptions.ConnectTimeout:
        logging.exception(f'Exception while retrieving file with HTTP'
                          ' (see traceback below)')


def retrieve_from_openstack(location):  # untested in gRPC migration
    """Retrieves file from OpenStack Swift.

    Args:
        location: Location of Swift object.

    Returns:
        Swift object data.
    """
    global client_openstack
    if client_openstack is None:
        client_openstack = swiftclient.Connection(auth_version=os.environ.get('ST_AUTH_VERSION'),
                                                  authurl=os.environ.get('ST_AUTH_URL'),
                                                  user=os.environ.get('OS_USERNAME'),
                                                  key=os.environ.get('OS_PASSWORD'),
                                                  cert=os.environ.get('OS_CERT'),
                                                  cacert=os.environ.get('OS_CACERT'))
        os_options = {'user_domain_name': os.environ.get('OS_USER_DOMAIN_NAME'),
                      'project_domain_name': os.environ.get('OS_PROJECT_DOMAIN_NAME'),
                      'project_name': os.environ.get('OS_PROJECT_NAME')}
        if not all(value is None for value in os_options.values()):
            client_openstack.os_options = os_options
    (response_headers,
     object_data) = client_openstack.get_object(location.get('bucket'),
                                                location.get('object'))
    return object_data
