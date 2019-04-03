import datetime
import functools
import glob
import importlib
import json
import logging
import multiprocessing
import os
import signal
import string
import time
import uuid

from boltons import iterutils
import inflection
import interruptingcow
import magic
import redis
import yaml
import yara

from strelka import errors

compiled_magic = None
compiled_yara = None
scanner_cache = {}
backend_cfg = {}


# def format_meta(value):
def ensure_utf8(value):
    """Recursively converts bytes, bytearrays, and UUIDs to strings.

    Scanners may output data that contains bytes, bytearrays, or UUIDs and
    these types need to be converted to strings to be encoded as JSON.

    Args:
        value: Value that needs values (bytes, bytearrays, or UUIDs) recursively
            converted to UTF-8 encoded strings.
    Returns:
        A UTF-8 encoded string representation of value.

    # TODO: needs new name and documentation
    """
    def visit(path, key, value):
        if isinstance(value, (bytes, bytearray)):
            value = str(value, encoding='UTF-8', errors='replace')
        elif isinstance(value, uuid.UUID):
            value = str(value)
        elif isinstance(value, set):
            value = list(value)
        return key, value

    return iterutils.remap(value, visit=visit)


def taste_mime(data):
    """Tastes file data with libmagic.

    # TODO: needs updating, move to Worker?
    """
    try:
        global compiled_magic
        if compiled_magic is None:
            taste_mime_db = backend_cfg.get('tasting').get('mime_db')
            compiled_magic = magic.Magic(magic_file=taste_mime_db,
                                         mime=True)
        mime_type = compiled_magic.from_buffer(data)
        return [mime_type]

    except magic.MagicException:
        self.flags.append('StrelkaFile::magic_exception')
        logging.exception('Exception while tasting with magic'
                          f' ({taste_mime_db}) (see traceback below)')


def taste_yara(data):
    """Tastes file data with YARA.

    # TODO: needs updating, move to Worker?
    """
    try:
        global compiled_yara
        if compiled_yara is None:
            taste_yara_rules = backend_cfg.get('tasting').get('yara_rules')
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
        stripped_data = data.lstrip(encoded_whitespace)
        yara_matches = compiled_yara.match(data=stripped_data)
        return [match.rule for match in yara_matches]

    except (yara.Error, yara.TimeoutError) as YaraError:
        self.flags.append('StrelkaFile::yara_scan_error')
        logging.exception('Exception while tasting with YARA'
                          f' ({taste_yara_rules}) (see traceback below)')


class StrelkaFile(object):
    """Defines a Strelka file object.

    # TODO: needs updating
    """
    def __init__(self, pointer='',
                 parent='', depth=0,
                 name='', source=''):
        """Inits file object."""
        self.uid = uuid.uuid4().hex
        self.pointer = pointer or self.uid
        self.parent = parent
        self.depth = depth
        self.name = name
        self.source = source
        self.flavors = {}

    def add_flavors(self, flavors):
        """Merges object flavors with new flavors.

        In cases where flavors and self.flavors share duplicate keys, flavors
        will overwrite the duplicate value.
        """
        self.flavors = {**self.flavors, **ensure_utf8(flavors)}


class StrelkaScanner(object):
    """Defines a Strelka scanner.

    Each scanner inherits this class and overrides methods (init and scan)
    within the class to perform scanning functions.

    Attributes:
        name: String that contains the scanner class name.
            This is referenced in flags and child filenames.
        key: String that contains the scanner's metadata key.
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
        self.name = self.__class__.__name__
        key = self.name.replace('Scan', '', 1) + 'Metadata'
        self.key = inflection.camelize(key, False)
        self.close_timeout = backend_cfg.get('timeout').get('close')
        self.scanner_timeout = backend_cfg.get('timeout').get('scanner')
        filekeeper = backend_cfg.get('filekeeper')
        self.fk = redis.StrictRedis(
            host=filekeeper.get('host'),
            port=filekeeper.get('port'),
            db=0,
        )
        self.init()

    def init(self):
        """Overrideable init."""
        pass

    def close(self):
        """Method to be overridden by scanner closing code."""
        pass

    def close_wrapper(self):
        """Calls close method with timeout and error handling.
        Raises:
            DistributionTimeout: Timeout occurred during distribution
                that halted the close.
            Exception: Unknown exception occurred.
        """
        try:
            with interruptingcow.timeout(self.close_timeout,
                                         exception=errors.CloseTimeout):
                self.close()

        except errors.CloseTimeout:
            pass
        except (
            errors.RequestTimeout,
            errors.DistributionTimeout,
            errors.QuitWorker,
        ):
            raise
        except Exception:
            logging.exception(f'{self.name}: exception while closing'
                              ' (see traceback below)')

    def scan(self,
             st_file,
             options):
        """Overrideable scan method.

        Args:
            st_file: StrelkaFile to be scanned.
            options: Options to be applied during scan.
        """
        pass

    def scan_wrapper(self,
                     data,
                     expire,
                     st_file,
                     options):
        """Sets up scan attributes and calls scan method.

        Scanning code is wrapped in try/except to handle error handling.
        The file object is always appended with metadata regardless of whether
        the scanner completed successfully or hit an exception. This method
        always returns the list of children.

        Args:
            st_file: StrelkaFile to be scanned.
            options: Options to be applied during scan.
        Returns:
            Children files (whether they exist or not).
        Raises:
            Exception: Unknown exception occurred.
        """
        start = datetime.datetime.utcnow()
        self.files = []
        self.flags = set()
        self.metadata = {}
        self.data = data
        self.expire = expire
        self.scanner_timeout = options.get('scanner_timeout',
                                           self.scanner_timeout)

        try:
            with interruptingcow.timeout(self.scanner_timeout,
                                         errors.ScannerTimeout):
                self.scan(st_file, options)

        except errors.ScannerTimeout:
            self.flags.add(f'{self.name}::timed_out')
        except (
            errors.RequestTimeout,
            errors.DistributionTimeout,
            errors.QuitWorker,
        ):
            raise
        except Exception:
            logging.exception(f'{self.name}: exception while scanning'
                              f' uid {st_file.uid} (see traceback below)')

        self.metadata = {
            **{'elapsed': (datetime.datetime.utcnow() - start).total_seconds()},
            **{'flags': self.flags},
            **self.metadata,
        }
        return (
            self.files,
            {self.key: self.metadata}
        )


class Worker(multiprocessing.Process):
    """
    # TODO: needs documentation, refactor/cleanup
    """
    def __init__(self, backend_cfg_path):
        super().__init__()
        load_scan(backend_cfg_path)
        self.max = backend_cfg.get('processes').get('max_files')
        self.ttl = backend_cfg.get('processes').get('time_to_live')
        self.distribution_timeout = backend_cfg.get('timeout').get('distribution')
        self.max_depth = backend_cfg.get('timeout').get('max_depth')
        filekeeper = backend_cfg.get('filekeeper')
        jobkeeper = backend_cfg.get('jobkeeper')
        # file data
        self.fk = redis.StrictRedis(
            host=filekeeper.get('host'),
            port=filekeeper.get('port'),
            db=0,
        )
        # task queue, status/result data
        self.jk = redis.StrictRedis(
            host=jobkeeper.get('host'),
            port=jobkeeper.get('port'),
            db=0,
        )

    def shutdown(self):
        """Defines worker shutdown."""
        logging.debug(f'{self.name}: shutdown handler received')
        raise errors.QuitWorker()

    def run(self):
        logging.info(f'{self.name}: starting up')
        signal.signal(signal.SIGUSR1,
                      functools.partial(shutdown_handler, self))

        try:
            count = 0
            work_start = datetime.datetime.utcnow()
            work_expire = work_start + datetime.timedelta(0, self.ttl)

            while 1:
                if count >= self.max:
                    break
                if datetime.datetime.utcnow() >= work_expire:
                    break

                pop = self.jk.blpop('queue', timeout=1)
                if pop is None:
                    continue

                task = json.loads(pop[1])
                check = self.jk.get(f'{task["root"]}:alive')
                if check is None:
                    continue

                st_file = StrelkaFile(
                    pointer=task['root'],
                )
                st_file.add_flavors({'external': task['flavors']})

                try:
                    with interruptingcow.timeout(task['expire'],
                                                 errors.RequestTimeout):
                        self.distribute(task['root'], task['expire'], st_file)
                        self.jk.setex(
                            f'{task["root"]}:complete',
                            task['expire'],
                            '1',
                        )

                except errors.RequestTimeout:
                    logging.debug(f'{self.name}: request'
                                  f' {task["root"]} timed out')
                except (errors.QuitWorker) as e:
                    logging.debug(f'{self.name}: quit while scanning'
                                  f' request {task["root"]}')
                    raise
                except Exception:
                    logging.exception(f'{self.name}: unknown exception'
                                      ' (see traceback below)')

                count += 1

        except errors.QuitWorker:
            logging.debug(f'{self.name}: received shutdown signal')

        self.close_scanners()
        logging.info(f'{self.name}: shutdown after scanning'
                     f' {count} file(s) and'
                     f' {(datetime.datetime.utcnow() - work_start).total_seconds()} second(s)')

    def distribute(self, root, expire, st_file):
        """Distributes a file through scanners.

        This method defines how files are assigned scanners:
            1. File data is formatted to bytes.
            2. File hash is calculated and roots assigned.
            3. File flavors are tasted via MIME and YARA.
            4. Scanner mapping from scan configuration is applied to flavors.
            5. File is recursively sent to the mapped scanners.

        Args:
            st_file: StrelkaFile to be scanned.
            scan_result: Dictionary that scan results are appended to.
        """
        try:
            files = []

            try:
                with interruptingcow.timeout(self.distribution_timeout,
                                             exception=errors.DistributionTimeout):
                    if st_file.depth > self.max_depth:
                        logging.info(f'request {root} exceeded maximum depth')
                        return

                    data = b''.join(self.fk.lrange(st_file.pointer, 0, -1))
                    st_file.add_flavors({'mime': taste_mime(data)})
                    st_file.add_flavors({'yara': taste_yara(data)})
                    scanner_cfg = backend_cfg.get('scanners')
                    flavors = (
                        st_file.flavors.get('external', [])
                        + st_file.flavors.get('mime', [])
                        + st_file.flavors.get('yara', [])
                    )

                    scanner_list = []
                    for name in scanner_cfg:
                        mappings = scanner_cfg.get(name, {})
                        assigned = assign_scanner(
                            name,
                            mappings,
                            flavors,
                            st_file.name,
                            st_file.source,
                        )
                        if assigned is not None:
                            scanner_list.append(assigned)
                    scanner_list.sort(
                        key=lambda k: k.get('priority', 5),
                        reverse=True,
                    )

                    metadata = {
                        **{
                            'tree': {
                                'node': st_file.uid,
                                'parent': st_file.parent,
                            },
                        },
                        **{
                            'file': {
                                'name': st_file.name,
                                'source': st_file.source,
                                'depth': st_file.depth,
                                'size': len(data),
                                'scannerList': [s.get('name')
                                                for s in scanner_list],
                            }
                        },
                        **{'flavors': st_file.flavors},
                    }

                    for scanner in scanner_list:
                        try:
                            name = scanner['name']
                            und_name = inflection.underscore(name)
                            scanner_import = f'strelka.scanners.{und_name}'
                            module = importlib.import_module(scanner_import)
                            if und_name not in scanner_cache:
                                scanner_cache[und_name] = getattr(module, name)()
                            options = scanner.get('options', {})
                            plugin = scanner_cache[und_name]
                            (f, m) = plugin.scan_wrapper(
                                data,
                                expire,
                                st_file,
                                options
                            )

                            metadata = {
                                **metadata,
                                **m,
                            }
                            files.extend(f)

                        except ModuleNotFoundError:
                            logging.exception(f'scanner {name} not found')

                    self.fk.delete(st_file.uid)
                    p = self.jk.pipeline()
                    p.rpush(
                        f'{root}:results',
                        json.dumps(ensure_utf8(metadata)),
                    )
                    p.expire(
                        f'{root}:results',
                        expire,
                    )
                    p.execute()

            except errors.DistributionTimeout:
                logging.exception(f'node {st_file.uid} timed out')

            for f in files:
                f.parent = st_file.uid
                f.depth = st_file.depth + 1
                self.distribute(root, expire, f)

        except (errors.RequestTimeout, errors.QuitWorker) as e:
            raise

    def close_scanners(self):
        """Runs the `close_wrapper` method on open scanners."""
        for (name, pointer) in list(scanner_cache.items()):
            pointer.close_wrapper()
            logging.debug(f'{self.name}: closed'
                          f' scanner {inflection.camelize(name)}')


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
        assigned = {'name': scanner,
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
                return assigned
        if pos_filename is not None:
            if re.search(pos_filename, filename) is not None:
                return assigned
        if pos_source is not None:
            if re.search(pos_source, source) is not None:
                return assigned
    return None


# Process handling funcs start here
def shutdown_handler(process, signum, frame):
    """Runs shutdown on child process.

    This function is wrapped in functools to pass the signal to the child
    process.

    Args:
        process: Process to shutdown.
        signum: Signal passed to process shutdown.
    """
    logging.debug(f'{process.name}: shutdown handler triggered'
                  f' (signal {signum})')
    process.shutdown()


def load_scan(path):
    """Loads 'worker.yaml' into memory.

    # TODO: move to Worker?
    """
    global backend_cfg
    with open(path) as f:
        backend_cfg = yaml.safe_load(f.read())
