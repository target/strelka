import re

import olefile
import oletools

from strelka import core


class ScanOle(core.StrelkaScanner):
    """Extracts files from OLECF files."""
    def scan(self, data, file_object, options):
        self.metadata['total'] = {'streams': 0, 'extracted': 0}

        try:
            ole = olefile.OleFileIO(data)
            ole_streams = ole.listdir(streams=True)
            self.metadata['total']['streams'] = len(ole_streams)
            for stream in ole_streams:
                file = ole.openstream(stream)
                file_data = file.read()
                file_name = f'{"_".join(stream)}'
                file_name = re.sub(r'[\x00-\x1F]', '', file_name)
                if file_name.endswith('Ole10Native'):
                    native_stream = oletools.oleobj.OleNativeStream(bindata=file_data)
                    if native_stream.filename:
                        file_name = file_name + f'_{str(native_stream.filename)}'
                    else:
                        file_name = file_name + '_native_data'

                    file_ = core.StrelkaFile(
                        name=file_name,
                        source=self.scanner_name,
                    )
                    self.r0.setex(
                        file_.uid,
                        self.expire,
                        native_stream.data,
                    )
                    self.files.append(file_)

                else:
                    file_ = core.StrelkaFile(
                        name=file_name,
                        source=self.scanner_name,
                    )
                    self.r0.setex(
                        file_.uid,
                        self.expire,
                        file_data,
                    )
                    self.files.append(file_)
                self.metadata['total']['extracted'] += 1

        except OSError:
            self.flags.add(f'{self.scanner_name}::os_error')
        finally:
            ole.close()
