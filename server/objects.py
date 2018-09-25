"""Defines classes and related functions that are used to process files."""
import hashlib
import logging
import re
import string
import time
import uuid
import zlib

from boltons import iterutils
import boto3
import botocore.client
from google.cloud.storage import Client
import inflection
import interruptingcow
import magic
import requests
import swiftclient
import yara

from server import strelka_pb2
from shared import conf
from shared import errors

gcs_client = None
s3_client = None
swift_client = None
compiled_magic = None
compiled_yara = None


def ensure_bytes(value):
    """Converts value to bytes.

    Converts bytearray and str to bytes. Scanners may create
    child files that are one of these types, this method is used on
    every file object to ensure the file data is always bytes.

    Args:
        value: Value that needs conversion to bytes.

    Returns:
        A byte representation of value.
    """
    if isinstance(value, bytearray):
        return bytes(value)
    elif isinstance(value, str):
        return value.encode('utf-8')
    return value


def ensure_utf8(value):
    """Converts value to UTF-8 encoded string.

    Recursively converts bytes, bytearrays, and uuids to str. Scanners
    may output metadata that is one of these types and they need to be
    converted to str to be encoded as JSON, so this method is used on
    every metadata dictionary.

    Args:
        value: Value that needs recursive conversion to a UTF-8 encoded
            string.

    Returns:
        A UTF-8 encoded string representation of value.
    """
    def visit(path, key, value):
        if isinstance(value, (bytes, bytearray)):
            value = str(value, encoding="UTF-8", errors="replace")
        elif isinstance(value, uuid.UUID):
            value = str(value)
        return key, value

    return iterutils.remap(value, visit=visit)


def normalize_whitespace(text):
    """Normalizes whitespace in text.

    Scanners that parse text generally need the whitespace normalized,
    otherwise metadata parsed from the text may be unreliable. This function
    normalizes whitespace characters to a single space. This can also be used
    on scanner metadata.

    Args:
        text: Text that needs whitespace normalized.

    Returns:
        Text with whitespace normalized.
    """
    if isinstance(text, bytes):
        text = re.sub(br"\s+", b" ", text)
        text = re.sub(br"(^\s+|\s+$)", b"", text)
    elif isinstance(text, str):
        text = re.sub(r"\s+", " ", text)
        text = re.sub(r"(^\s+|\s+$)", "", text)
    return text


def protobuf_to_file_object(task):
    """Converts protobuf strelka_pb2.FileRequest to StrelkaFile.

    Args:
        task: Task received by the worker from the broker.

    Returns:
        Instance of StrelkaFile derived from task.
    """
    file_request = strelka_pb2.FileRequest()
    file_request.ParseFromString(task)

    flavors = [flavor for flavor in file_request.flavors]
    metadata = {key: value for (key, value) in file_request.metadata.items()}

    if file_request.data:
        return StrelkaFile(data=zlib.decompress(file_request.data),
                           filename=file_request.filename,
                           source=file_request.source,
                           external_flavors=flavors,
                           external_metadata=metadata)
    elif file_request.location:
        location = {key:
                    value for (key, value) in file_request.location.items()}
        return StrelkaFile(location=location,
                           filename=file_request.filename,
                           source=file_request.source,
                           external_flavors=flavors,
                           external_metadata=metadata)


class StrelkaFile(object):
    """Class that defines files distributed through the system.

    Attributes:
        data: Byte string that contains the file content. This is a
            read-only attribute.
        location: Dictionary that contains details on where to retrieve a
            remote file. Files will be retrieved if data is None and location
            contains data. See README for more details. This is a read-only
            attribute.
        hash: SHA256 hash of data. This is a read-only attribute.
        uid: UUID that is used to uniquely identify the file. This is a
            read-only attribute.
        filename: String that contains the name of the file.
        depth: Integer that represents how deep the file was embedded in a
            root file.
        source: String that describes where the file originated.
        scanner_list: List of scanners that were assigned to the file during
            distribution.
        external_flavors: List of flavors assigned to the file when the file
            was created.
        external_metadata: Dictionary of external metadata related to
            the file.
        parent_uid: UUID of the parent file.
        root_uid: UUID of the root file.
        parent_hash: SHA256 hash of the parent file.
        root_hash: SHA256 hash of the root file.
        flags: List of flags that are appended during scanning.
        metadata: Dictionary of metadata that is appended during scanning.
    """
    def __init__(self,
                 data=None,
                 location=None,
                 filename=None,
                 depth=None,
                 parent_uid=None,
                 root_uid=None,
                 parent_hash=None,
                 root_hash=None,
                 source=None,
                 scanner_list=None,
                 external_flavors=None,
                 external_metadata=None):
        """Initializes file object."""
        self._data = data or b""
        self._location = location or {}
        if self._location and not self._data:
            type = self._location.get("type")
            bucket = self._location.get("bucket")
            object = self._location.get("object")

            try:
                if type == "amazon":
                    self._data = self.retrieve_from_amazon(bucket, object)
                elif type == "google":
                    self._data = self.retrieve_from_google(bucket, object)
                elif type == "openstack":
                    self._data = self.retrieve_from_openstack(bucket, object)
                elif type == "http":
                    self._data = self.retrieve_from_http(object)

            except Exception:
                logging.exception("File: exception while creating file from"
                                  f" location {self._location} (see traceback"
                                  " below)")

        self._data = ensure_bytes(self._data)
        self._hash = hashlib.sha256(self._data).hexdigest()
        self._size = len(self._data)
        self._uid = uuid.uuid4()
        self.filename = filename or ""
        self.depth = depth or 0
        self.source = source or ""
        self.scanner_list = scanner_list or []
        self.external_flavors = external_flavors or []
        self.external_metadata = external_metadata or {}
        self.parent_uid = parent_uid or ""
        self.parent_hash = parent_hash or ""
        if self.depth == 0:
            self.root_uid = self.uid
            self.root_hash = self.hash
        else:
            self.root_uid = root_uid or ""
            self.root_hash = root_hash or ""
        self.flags = []
        self._flavors = {"external": ensure_utf8(self.external_flavors),
                         "mime": ensure_utf8(self.taste_mime()),
                         "yara": ensure_utf8(self.taste_yara())}
        self.metadata = {}
        self.append_metadata({"externalMetadata": self.external_metadata})

    @property
    def data(self):
        return self._data

    @property
    def flavors(self):
        return self._flavors

    @property
    def hash(self):
        return self._hash

    @property
    def location(self):
        return self._location

    @property
    def size(self):
        return self._size

    @property
    def uid(self):
        return self._uid

    def append_metadata(self, meta_dictionary):
        """Merges scanner metadata with file object metadata."""
        self.metadata = {**self.metadata, **ensure_utf8(meta_dictionary)}

    def retrieve_from_amazon(self, bucket, object):
        """Retrieves file from Amazon S3.

        Args:
            bucket: Bucket to retrieve file from.
            object: File object to retrieve.

        Returns:
            A byte string containing the file content.
        """
        global s3_client
        if s3_client is None:
            s3_client = boto3.client("s3",
                                     aws_access_key_id=conf.remote_cfg["aws_access_key_id"],
                                     aws_secret_access_key=conf.remote_cfg["aws_secret_access_key"],
                                     config=botocore.client.Config(
                                         connect_timeout=conf.remote_cfg["remote_timeout"],
                                         read_timeout=conf.remote_cfg["remote_timeout"],
                                         region_name=conf.remote_cfg["aws_default_region"],
                                         retries={"max_attempts": conf.remote_cfg["remote_retries"]}
                                     ))
        return s3_client.get_object(Bucket=bucket, Key=object)['Body'].read()

    def retrieve_from_google(self, bucket, object):
        """Retrieves file from Google Cloud Storage.

        Args:
            bucket: Bucket to retrieve file from.
            object: File object to retrieve.

        Returns:
            A byte string containing the file content.
        """
        global gcs_client
        if gcs_client is None:
            gcs_client = Client.from_service_account_json(conf.remote_cfg["google_application_credentials"])
        return gcs_client.get_bucket(bucket).get_blob(object).download_as_string()

    def retrieve_from_http(self, url):
        """Retrieves file from HTTP server.

        Args:
            url: URL where file is hosted.

        Returns:
            A byte string containing the file content.
        """
        retry_counter = 0
        while retry_counter < conf.remote_cfg["remote_retries"] + 1:
            if retry_counter != 0:
                time.sleep(retry_counter * 5)

            try:
                response = requests.get(url,
                                        allow_redirects=True,
                                        stream=True,
                                        auth=(conf.remote_cfg["http_basic_user"],
                                              conf.remote_cfg["http_basic_pass"]),
                                        timeout=conf.remote_cfg["remote_timeout"],
                                        verify=conf.remote_cfg["http_verify"])
                if response.status_code == 200:
                    return response.raw.read()
                elif response.status_code:
                    return b""
            except requests.exceptions.ConnectTimeout:
                retry_counter += 1

    def retrieve_from_openstack(self, container, object):
        """Retrieves file from OpenStack Swift.

        Args:
            container: Container to retrieve file from.
            object: File object to retrieve.

        Returns:
            A byte string containing the file content.
        """
        global swift_client
        if swift_client is None:
            swift_client = swiftclient.Connection(auth_version=conf.remote_cfg["st_auth_version"],
                                                  authurl=conf.remote_cfg["os_auth_url"],
                                                  user=conf.remote_cfg["os_username"],
                                                  key=conf.remote_cfg["os_password"],
                                                  cert=conf.remote_cfg["os_cert"],
                                                  cacert=conf.remote_cfg["os_cacert"],
                                                  retries=conf.remote_cfg["remote_retries"],
                                                  timeout=conf.remote_cfg["remote_timeout"])
            os_options = {"user_domain_name": conf.remote_cfg["os_user_domain_name"],
                          "project_domain_name": conf.remote_cfg["os_project_domain_name"],
                          "project_name": conf.remote_cfg["os_project_name"]}
            if not all(value is None for value in os_options.values()):
                swift_client.os_options = os_options
        (response_headers,
         object_data) = swift_client.get_object(container,
                                                object)
        return object_data

    def taste_mime(self):
        """Tastes file data with libmagic.

        Tastes file data with libmagic and appends the MIME type to the
        file object.

        Args:
            magic_file: Location of the MIME database used to taste files.
                Defaults to system default.
        """
        try:
            global compiled_magic
            if compiled_magic is None:
                distro_cfg = conf.scan_cfg.get("distribution", {})
                taste_mime_db = distro_cfg.get("taste_mime_db", None)
                compiled_magic = magic.Magic(magic_file=taste_mime_db,
                                             mime=True)
            mime_type = compiled_magic.from_buffer(self._data)
            return [mime_type]

        except magic.MagicException:
            self.flags.append("StrelkaFile::magic_exception")
            logging.exception(f"Exception while tasting with magic"
                              " (see traceback below)")

    def taste_yara(self):
        """Taste files with YARA.

        Tastes file data with YARA and appends the matches to the file object.
        Whitespace is stripped from the leftside of the file data to increase
        the reliability of YARA matching.

        Args:
            yara_file: Location of the YARA file that contains rules used
                to taste files.
        """
        try:
            global compiled_yara
            if compiled_yara is None:
                distro_cfg = conf.scan_cfg.get("distribution", {})
                taste_yara_file = distro_cfg.get("taste_yara_rules",
                                                 "etc/strelka/taste.yara")
                compiled_yara = yara.compile(taste_yara_file)
            encoded_whitespace = string.whitespace.encode()
            stripped_data = self._data.lstrip(encoded_whitespace)
            yara_matches = compiled_yara.match(data=stripped_data)
            return [match.rule for match in yara_matches]

        except (yara.Error, yara.TimeoutError) as YaraError:
            self.flags.append("StrelkaFile::yara_scan_error")
            logging.exception("Exception while tasting with YARA file"
                              f" {yara_file} (see traceback below)")


class StrelkaScanner(object):
    """Class that defines scanners used in the system.

    Each scanner inherits this class and overrides methods within the class
    to perform their scanning functions.

    Attributes:
        scanner_name: String that contains the scanner class name.
            This is referenced in flags and child filenames.
        scanner_timeout: Amount of time (in seconds) that a scanner can spend
            scanning a file. Can be overridden on a per-scanner basis
            (see scan_wrapper).
            Defaults to 600 seconds / 5 minutes.
        close_timeout: Amount of time (in seconds) that a scanner can spend
            closing itself.
            Defaults to 30 seconds.
        metadata_key: String that contains the scanner's metadata key. This is
            used to identify the scanner's metadata in the scan results.
        file_object: Instance of File that will be scanned by the scanner.
        options: Dictionary of options associated with the scanner that was
            assigned when the file was distributed.
        metadata: Dictionary where scanner metadata is stored.
        children: List where scanner child files are stored.
    """
    def __init__(self):
        """Initializes scanner."""
        distro_cfg = conf.scan_cfg.get("distribution", {})
        self.scanner_name = self.__class__.__name__
        self.scanner_timeout = distro_cfg.get("scanner_timeout", 600)
        self.close_timeout = distro_cfg.get("close_timeout", 30)
        metadata_key = self.scanner_name.replace("Scan", "", 1) + "Metadata"
        self.metadata_key = inflection.camelize(metadata_key, False)
        self.init()

    def init(self):
        """Method to be overridden by scanner initialization."""
        pass

    def close(self):
        """Method to be overridden by scanner closing code."""
        pass

    def close_wrapper(self):
        """Calls close method with timeout and error handling.

        Raises:
            errors.DistributionTimeout: Timeout occurred during distribution
                that halted the close.
            Exception: Unknown exception occurred.
        """
        try:
            with interruptingcow.timeout(self.close_timeout,
                                         exception=errors.CloseTimeout):
                self.close()

        except errors.DistributionTimeout:
            raise
        except errors.CloseTimeout:
            pass
        except errors.QuitWorker:
            logging.info(f"{self.scanner_name}: shutdown while closing")
            raise
        except Exception:
            logging.exception(f"{self.scanner_name}: exception while closing"
                              "(see traceback below)")

    def scan(self,
             file_object,
             options):
        """Method to be overridden by scanner processing code."""
        pass

    def scan_wrapper(self,
                     file_object,
                     options):
        """Sets up scan attributes and calls scan method.

        Scanning code is wrapped in interruptingcow and try/except to handle
        timeout and error handling. The file object is always appended with
        metadata, regardless of whether the scanner completed successfully,
        timed out, or hit an exception.

        Returns:
            Children files, whether they exist or not.

        Raises:
            errors.DistributionTimeout: Timeout occurred during distribution
                that halted the scan.
            errors.ScannerTimeout: Timeout occurred during scan that halted
                the scan.
            Exception: Unknown exception occurred.
        """
        self.metadata = {}
        self.children = []
        self.scanner_timeout = options.get("scanner_timeout",
                                           self.scanner_timeout)

        try:
            with interruptingcow.timeout(self.scanner_timeout,
                                         exception=errors.ScannerTimeout):
                self.scan(file_object, options)

        except errors.DistributionTimeout:
            raise
        except errors.ScannerTimeout:
            file_object.flags.append(f"{self.scanner_name}::timed_out")
        except errors.QuitWorker:
            logging.info(f"{self.scanner_name}: shutdown while scanning file"
                         f" with hash {file_object.hash} and uid"
                         f" {file_object.uid}")
            raise
        except Exception:
            logging.exception(f"{self.scanner_name}: exception while scanning"
                              f" file with hash {file_object.hash} and uid"
                              f" {file_object.uid} (see traceback below)")

        file_object.append_metadata({self.metadata_key: self.metadata})
        return self.children
