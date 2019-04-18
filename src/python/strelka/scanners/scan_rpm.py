from datetime import datetime
import tempfile

import rpmfile

from strelka import strelka


class ScanRpm(strelka.Scanner):
    """Collects metadata and extracts files from RPM files.

    Options:
        tmp_directory: Location where tempfile writes temporary files.
            Defaults to '/tmp/'.
    """
    def scan(self, data, file, options, expire_at):
        tmp_directory = options.get('tmp_directory', '/tmp/')

        with tempfile.NamedTemporaryFile(dir=tmp_directory) as st_tmp:
            st_tmp.write(data)
            st_tmp.flush()

            try:
                with rpmfile.open(st_tmp.name) as rpm:
                    extract_name = ''
                    for (key, value) in rpm.headers.items():
                        if key == 'arch':
                            self.metadata['architecture'] = value
                        elif key == 'archive_compression':
                            self.metadata['archive_compression'] = value
                        elif key == 'archive_format':
                            self.metadata['archive_format'] = value
                        elif key == 'authors':
                            self.metadata['authors'] = value
                        elif key == 'buildhost':
                            self.metadata['build_host'] = value
                        elif key == 'buildtime':
                            if value is not None:
                                self.metadata['build_time'] = datetime.utcfromtimestamp(value).isoformat()
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
                            extract_name = f'{value.decode()}'
                        elif key == 'os':
                            self.metadata['os'] = value
                        elif key == 'packager':
                            self.metadata['packager'] = value
                        elif key == 'provides':
                            self.metadata['provides'] = value
                        elif key == 'release':
                            self.metadata['release'] = value
                        elif key == 'requirename':
                            self.metadata['require_name'] = value
                        elif key == 'rpmversion':
                            self.metadata['rpm_version'] = value
                        elif key == 'serial':
                            self.metadata['serial'] = value
                        elif key == 'sourcerpm':
                            self.metadata['source_rpm'] = value
                        elif key == 'summary':
                            self.metadata['summary'] = value
                        elif key == 'vendor':
                            self.metadata['vendor'] = value
                        elif key == 'version':
                            self.metadata['version'] = value
                        elif key == 'url':
                            self.metadata['url'] = value

                    extract_file = strelka.File(
                        name=extract_name,
                        source=self.name,
                    )

                    for c in strelka.chunk_string(data[rpm.data_offset:]):
                        self.upload_to_cache(
                            extract_file.pointer,
                            c,
                            expire_at,
                        )

                    self.files.append(extract_file)

            except ValueError:
                self.flags.append('value_error')
