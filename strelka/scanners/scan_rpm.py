from datetime import datetime
import tempfile

import rpmfile

from strelka import core
from strelka.scanners import util


class ScanRpm(core.StrelkaScanner):
    """Collects metadata and extracts files from RPM files.

    Options:
        tmp_directory: Location where tempfile writes temporary files.
            Defaults to '/tmp/'.
    """
    def scan(self, st_file, options):
        tmp_directory = options.get('tmp_directory', '/tmp/')

        with tempfile.NamedTemporaryFile(dir=tmp_directory) as st_tmp:
            st_tmp.write(self.data)
            st_tmp.flush()

            try:
                with rpmfile.open(st_tmp.name) as rpm:
                    ex_name = ''
                    for (key, value) in rpm.headers.items():
                        if key == 'arch':
                            self.metadata['architecture'] = value
                        elif key == 'archive_compression':
                            self.metadata['archiveCompression'] = value
                        elif key == 'archive_format':
                            self.metadata['archiveFormat'] = value
                        elif key == 'authors':
                            self.metadata['authors'] = value
                        elif key == 'buildhost':
                            self.metadata['buildHost'] = value
                        elif key == 'buildtime':
                            if value is not None:
                                self.metadata['buildTime'] = datetime.utcfromtimestamp(value).isoformat(timespec='seconds')
                        elif key == 'copyright':
                            self.metadata['copyright'] = value
                        elif key == 'description':
                            if value is not None:
                                self.metadata['description'] = value.replace(b'\n', b' ')
                        elif key == 'filenames':
                            self.metadata['filenames'] = value
                        elif key == 'group':
                            self.metadata['group'] = value
                        elif key == 'name':
                            self.metadata['name'] = value
                            ex_name = f'{value.decode()}'
                        elif key == 'os':
                            self.metadata['os'] = value
                        elif key == 'packager':
                            self.metadata['packager'] = value
                        elif key == 'provides':
                            self.metadata['provides'] = value
                        elif key == 'release':
                            self.metadata['release'] = value
                        elif key == 'requirename':
                            self.metadata['requireName'] = value
                        elif key == 'rpmversion':
                            self.metadata['rpmVersion'] = value
                        elif key == 'serial':
                            self.metadata['serial'] = value
                        elif key == 'sourcerpm':
                            self.metadata['sourceRpm'] = value
                        elif key == 'summary':
                            self.metadata['summary'] = value
                        elif key == 'vendor':
                            self.metadata['vendor'] = value
                        elif key == 'version':
                            self.metadata['version'] = value
                        elif key == 'url':
                            self.metadata['url'] = value

                    ex_file = core.StrelkaFile(
                        name=ex_name,
                        source=self.name,
                    )
                    for c in util.chunk_string(data[rpm.data_offset:]):
                        p = self.fk.pipeline()
                        p.rpush(ex_file.uid, c)
                        p.expire(ex_file.uid, self.expire)
                        p.execute()
                    self.files.append(ex_file)

            except ValueError:
                self.flags.add('value_error')
