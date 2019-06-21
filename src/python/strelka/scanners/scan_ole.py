import re

import olefile
import oletools

from strelka import strelka


class ScanOle(strelka.Scanner):
    """Extracts files from OLECF files."""
    def scan(self, data, file, options, expire_at):
        self.event['total'] = {'streams': 0, 'extracted': 0}

        try:
            ole = olefile.OleFileIO(data)
            ole_streams = ole.listdir(streams=True)
            self.event['total']['streams'] = len(ole_streams)
            for stream in ole_streams:
                file = ole.openstream(stream)
                extract_data = file.read()
                extract_name = f'{"_".join(stream)}'
                extract_name = re.sub(r'[\x00-\x1F]', '', extract_name)
                if extract_name.endswith('Ole10Native'):
                    native_stream = oletools.oleobj.OleNativeStream(
                        bindata=extract_data,
                    )
                    if native_stream.filename:
                        extract_name = extract_name + f'_{str(native_stream.filename)}'
                    else:
                        extract_name = extract_name + '_native_data'

                    extract_file = strelka.File(
                        name=extract_name,
                        source=self.name,
                    )

                    for c in strelka.chunk_string(native_stream.data):
                        self.upload_to_coordinator(
                            extract_file.pointer,
                            c,
                            expire_at,
                        )

                else:
                    extract_file = strelka.File(
                        name=extract_name,
                        source=self.name,
                    )

                    for c in strelka.chunk_string(extract_data):
                        self.upload_to_coordinator(
                            extract_file.pointer,
                            c,
                            expire_at,
                        )

                self.files.append(extract_file)
                self.event['total']['extracted'] += 1

        except OSError:
            self.flags.append('os_error')
        finally:
            # TODO this should be wrapped with another try / catch as the variable assignment is not guaranteed
            ole.close()
