from datetime import datetime
import glob
import hashlib
import json
import logging
import os
import re
import string
import uuid

from boltons import iterutils
import boto3
from google.cloud.storage import Client
import grpc
import inflection
import magic
import requests
import swiftclient
import yara

from etc import conf

client_amazon = None
client_google = None
client_openstack = None
compiled_magic = None
compiled_yara = None
scanner_cache = {}


class StrelkaFile(object):
    def __init__(self, data=b'', filename='', source='',
                 depth=0, parent_hash='', root_hash='',
                 parent_uid='', root_uid=''):
        self.data = data
        self.filename = filename
        self.source = source
        self.depth = depth
        self.uid = uuid.uuid4()
        self.parent_uid = parent_uid
        self.root_uid = root_uid
        self.parent_hash = parent_hash
        self.root_hash = root_hash
        if not self.root_uid and self.depth == 0:
            self.root_uid = self.uid

        self.flags = []
        self.flavors = {}
        self.metadata = {}
        self.scanner_list = []

    def append_data(self, data):
        self.data += data

    def append_flavors(self, flavors):
        self.flavors = {**self.flavors, **ensure_utf8(flavors)}

    def append_metadata(self, metadata):
        self.metadata = {**self.metadata, **ensure_utf8(metadata)}

    def calculate_hash(self):
        self.hash = hashlib.sha256(self.data).hexdigest()
        if not self.root_hash and self.depth == 0:
            self.root_hash = self.hash

    def ensure_data(self):
        self.data = ensure_bytes(self.data)

    def update_filename(self, filename):
        self.filename = filename

    def update_source(self, source):
        self.source = source

    def update_ext_flavors(self, ext_flavors):
        self.append_flavors({'external': ext_flavors})

    def update_ext_metadata(self, ext_metadata):
        self.append_metadata({'externalMetadata': ext_metadata})

    def taste_mime(self):
        try:
            global compiled_magic
            if compiled_magic is None:
                taste_mime_db = conf.scan_cfg.get('taste_mime_db')
                compiled_magic = magic.Magic(magic_file=taste_mime_db,
                                             mime=True)
            mime_type = compiled_magic.from_buffer(self.data)
            self.append_flavors({'mime': [mime_type]})

        except magic.MagicException:
            self.flags.append('StrelkaFile::magic_exception')
            logging.exception(f'Exception while tasting with magic'
                              ' (see traceback below)')

    def taste_yara(self):
        try:
            global compiled_yara
            if compiled_yara is None:
                taste_yara_dir = conf.scan_cfg.get('taste_yara_rules')
                if os.path.isdir(taste_yara_dir):
                    yara_filepaths = {}
                    globbed_yara_paths = glob.iglob(f'{taste_yara_dir}/**/*.yar*', recursive=True)
                    for (idx, entry) in enumerate(globbed_yara_paths):
                        yara_filepaths[f'namespace_{idx}'] = entry
                    compiled_yara = yara.compile(filepaths=yara_filepaths)
                else:
                    compiled_yara = yara.compile(filepath=taste_yara_dir)

            encoded_whitespace = string.whitespace.encode()
            stripped_data = self.data.lstrip(encoded_whitespace)
            yara_matches = compiled_yara.match(data=stripped_data)
            self.append_flavors({'yara': [match.rule for match in yara_matches]})

        except (yara.Error, yara.TimeoutError) as YaraError:
            self.flags.append('StrelkaFile::yara_scan_error')
            logging.exception('Exception while tasting with YARA directory'
                              f' {taste_yara_dir} (see traceback below)')


class StrelkaScanner(object):
    def __init__(self):
        self.scanner_name = self.__class__.__name__
        metadata_key = self.scanner_name.replace('Scan', '', 1) + 'Metadata'
        self.metadata_key = inflection.camelize(metadata_key, False)
        self.init()

    def init(self):
        pass

    def close(self):
        pass

    def close_wrapper(self):
        try:
            self.close()

        except Exception:
            logging.exception(f'{self.scanner_name}: exception while closing'
                              '(see traceback below)')

    def scan(self,
             file_object,
             options):
        pass

    def scan_wrapper(self,
                     file_object,
                     options,
                     context):
        if not context.is_active():
            context.abort(grpc.StatusCode.CANCELLED, 'Cancelled')

        self.metadata = {}
        self.children = []

        try:
            self.scan(file_object, options)

        except Exception:
            logging.exception(f'{self.scanner_name}: exception while scanning'
                              f' file with hash {file_object.hash} and uid'
                              f' {file_object.uid} (see traceback below)')

        file_object.append_metadata({self.metadata_key: self.metadata})
        return self.children


def ensure_bytes(value):
    if isinstance(value, bytearray):
        return bytes(value)
    elif isinstance(value, str):
        return value.encode('utf-8')
    return value


def ensure_utf8(value):
    def visit(path, key, value):
        if isinstance(value, (bytes, bytearray)):
            value = str(value, encoding='UTF-8', errors='replace')
        elif isinstance(value, uuid.UUID):
            value = str(value)
        return key, value

    return iterutils.remap(value, visit=visit)


def normalize_whitespace(text):
    if isinstance(text, bytes):
        text = re.sub(br'\s+', b' ', text)
        text = re.sub(br'(^\s+|\s+$)', b'', text)
    elif isinstance(text, str):
        text = re.sub(r'\s+', ' ', text)
        text = re.sub(r'(^\s+|\s+$)', '', text)
    return text


def distribute(file_object, scan_result, context):
    if not context.is_active():
        context.abort(grpc.StatusCode.CANCELLED, 'Cancelled')

    file_object.ensure_data()
    file_object.calculate_hash()
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
        for scanner in scanner_list:
            try:
                scanner_name = scanner['scanner_name']
                und_scanner_name = inflection.underscore(scanner_name)
                scanner_import = f'server.scanners.{und_scanner_name}'
                module = __import__(scanner_import,
                                    fromlist=[und_scanner_name])
                if und_scanner_name not in scanner_cache:
                    if hasattr(module, scanner_name):
                        scanner_cache[und_scanner_name] = getattr(module,
                                                                  scanner_name)()
                scanner_options = scanner.get('options', {})
                scanner_plugin = scanner_cache[und_scanner_name]
                file_children = scanner_plugin.scan_wrapper(file_object,
                                                            scanner_options,
                                                            context)
                children.extend(file_children)

            except ModuleNotFoundError:
                logging.exception(f'scanner {scanner_name} not found')

        unique_flags = list(dict.fromkeys(file_object.flags))
        result_output = {'flags': ensure_utf8(unique_flags),
                         'flavors': file_object.flavors,
                         **file_object.metadata}
        scan_result['results'].append(result_output)

        for child in children:
            distribute(child, scan_result, context)

    else:
        logging.info(f'file with hash {file_object.hash} (root hash'
                     f' {file_object.root_hash}) exceeded maximum depth')


def assign_scanner(scanner, mappings, flavors, filename, source):
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


def reset_server():
    global compiled_magic
    global compiled_yara
    compiled_magic = None
    compiled_yara = None
    for (scanner_name, scanner_pointer) in list(scanner_cache.items()):
        scanner_pointer.close_wrapper()
        scanner_cache.pop(scanner_name)


def remap_scan_result(scan_result, field_case):
    empty_lambda = lambda p, k, v: v != '' and v != [] and v != {}

    def snake(path, key, value):
        if not isinstance(key, int):
            return (inflection.underscore(key), value)
        return (key, value)

    if field_case == 'snake':
        remapped = iterutils.remap(scan_result, empty_lambda)
        return iterutils.remap(remapped, visit=snake)
    return iterutils.remap(scan_result, empty_lambda)


def split_scan_result(scan_result):
    results = scan_result.pop('results')
    individual_result = scan_result
    for result in results:
        yield {**individual_result, **result}


def format_bundled_event(scan_result, field_case):
    return json.dumps(remap_scan_result(scan_result, field_case))


def init_scan_result():
    scan_result = {'startTime': datetime.utcnow(),
                   'results': []}
    return scan_result


def fin_scan_result(scan_result):
    finish_time = datetime.utcnow()
    elapsed_time = (finish_time - scan_result['startTime']).total_seconds()
    scan_result['startTime'] = scan_result['startTime'].isoformat(timespec='seconds')
    scan_result['finishTime'] = finish_time.isoformat(timespec='seconds')
    scan_result['elapsedTime'] = elapsed_time
    return scan_result


def retrieve_from_amazon(location):
    global client_amazon
    if client_amazon is None:
        client_amazon = boto3.client("s3",
                                     aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
                                     aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'))
    return client_amazon.get_object(Bucket=location.get('bucket'), Key=location.get('object'))['Body'].read()


def retrieve_from_google(location):
    global client_google
    if client_google is None:
        client_google = Client.from_service_account_json(os.environ.get('GOOGLE_APPLICATION_CREDENTIALS'))
    return client_google.get_bucket(location.get('bucket')).get_blob(location.get('object')).download_as_string()


def retrieve_from_http(location):
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
            return b""
    except requests.exceptions.ConnectTimeout:
        logging.exception(f'Exception while retrieving file with HTTP'
                          ' (see traceback below)')


def retrieve_from_openstack(location):
    global client_openstack
    if client_openstack is None:
        client_openstack = swiftclient.Connection(auth_version=os.environ.get('ST_AUTH_VERSION'),
                                                  authurl=os.environ.get('ST_AUTH_URL'),
                                                  user=os.environ.get('OS_USERNAME'),
                                                  key=os.environ.get('OS_PASSWORD'),
                                                  cert=os.environ.get('OS_CERT'),
                                                  cacert=os.environ.get('OS_CACERT'))
        os_options = {"user_domain_name": os.environ.get('OS_USER_DOMAIN_NAME'),
                      "project_domain_name": os.environ.get('OS_PROJECT_DOMAIN_NAME'),
                      "project_name": os.environ.get("OS_PROJECT_NAME")}
        if not all(value is None for value in os_options.values()):
            client_openstack.os_options = os_options
    (response_headers,
     object_data) = client_openstack.get_object(location.get('bucket'),
                                                location.get('object'))
    return object_data
