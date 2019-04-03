import re

import olefile
import oletools

from strelka import core
from strelka.scanners import util


class ScanOle(core.StrelkaScanner):
    """Extracts files from OLECF files."""
    def scan(self, st_file, options):
        self.metadata['total'] = {'streams': 0, 'extracted': 0}

        try:
            ole = olefile.OleFileIO(self.data)
            ole_streams = ole.listdir(streams=True)
            self.metadata['total']['streams'] = len(ole_streams)
            for stream in ole_streams:
                file = ole.openstream(stream)
                ex_data = file.read()
                ex_name = f'{"_".join(stream)}'
                ex_name = re.sub(r'[\x00-\x1F]', '', ex_name)
                if ex_name.endswith('Ole10Native'):
                    native_stream = oletools.oleobj.OleNativeStream(
                        bindata=ex_data,
                    )
                    if native_stream.filename:
                        ex_name = ex_name + f'_{str(native_stream.filename)}'
                    else:
                        ex_name = ex_name + '_native_data'

                    ex_file = core.StrelkaFile(
                        name=ex_name,
                        source=self.name,
                    )
                    for c in util.chunk_string(native_stream.data):
                        p = self.fk.pipeline()
                        p.rpush(ex_file.uid, c)
                        p.expire(ex_file.uid, self.expire)
                        p.execute()
                    self.files.append(ex_file)

                else:
                    ex_file = core.StrelkaFile(
                        name=ex_name,
                        source=self.name,
                    )
                    for c in util.chunk_string(ex_data):
                        p = self.fk.pipeline()
                        p.rpush(ex_file.uid, c)
                        p.expire(ex_file.uid, self.expire)
                        p.execute()
                    self.files.append(ex_file)

                self.metadata['total']['extracted'] += 1

        except OSError:
            self.flags.add('os_error')
        finally:
            ole.close()
