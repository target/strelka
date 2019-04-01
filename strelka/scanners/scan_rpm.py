from datetime import datetime
import tempfile

import rpmfile

from strelka import core


class ScanRpm(core.StrelkaScanner):
    """Collects metadata and extracts files from RPM files.

    Options:
        tmp_directory: Location where tempfile writes temporary files.
            Defaults to '/tmp/'.
    """
    def scan(self, data, file_object, options):
        tmp_directory = options.get('tmp_directory', '/tmp/')

        with tempfile.NamedTemporaryFile(dir=tmp_directory) as tmp:
            tmp.write(data)
            tmp.flush()

            try:
                with rpmfile.open(tmp.name) as rpm:
                    file_name = ''
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
                            file_name = f'{value.decode()}'
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

                    file_ = core.StrelkaFile(
                        name=file_name,
                        source=self.scanner_name,
                    )
                    self.r0.setex(
                        file_.uid,
                        self.expire,
                        data[rpm.data_offset:],
                    )
                    self.files.append(file_)

            except ValueError:
                self.flags.add(f'{self.scanner_name}::value_error')
