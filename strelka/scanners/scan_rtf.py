from oletools import rtfobj

from strelka import core
from strelka.scanners import util


class ScanRtf(core.StrelkaScanner):
    """Extracts files from RTF files.

    Options:
        limit: Maximum number of files to extract.
            Defaults to 1000.
    """
    def scan(self, st_file, options):
        file_limit = options.get('limit', 1000)

        self.metadata['total'] = {'objects': 0, 'extracted': 0}

        rtf = rtfobj.RtfObjParser(self.data)
        rtf.parse()
        self.metadata['total']['objects'] = len(rtf.objects)

        for object in rtf.objects:
            if self.metadata['total']['extracted'] >= file_limit:
                break

            index = rtf.server.index(object)
            if object.is_package:
                ex_file = core.StrelkaFile(
                    name=f'{object.filename}',
                    source=self.name,
                )
                for c in util.chunk_string(object.olepkgdata):
                    p = self.fk.pipeline()
                    p.rpush(ex_file.uid, c)
                    p.expire(ex_file.uid, self.expire)
                    p.execute()

            elif object.is_ole:
                ex_file = core.StrelkaFile(
                    name=f'object_{index}',
                    source=self.name,
                )
                for c in util.chunk_string(object.oledata):
                    p = self.fk.pipeline()
                    p.rpush(ex_file.uid, c)
                    p.expire(ex_file.uid, self.expire)
                    p.execute()

            else:
                ex_file = core.StrelkaFile(
                    name=f'object_{index}',
                    source=self.name,
                )
                for c in util.chunk_string(object.rawdata):
                    p = self.fk.pipeline()
                    p.rpush(ex_file.uid, c)
                    p.expire(ex_file.uid, self.expire)
                    p.execute()

            self.files.append(ex_file)
            self.metadata['total']['extracted'] += 1
