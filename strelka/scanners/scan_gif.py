from strelka import core
from strelka.scanners import util


class ScanGif(core.StrelkaScanner):
    """Extracts data embedded in GIF files.

    This scanner extracts data that is inserted past the GIF trailer.
    """
    def scan(self, st_file, options):
        if not self.data.endswith(b'\x00\x3b'):
            trailer_index = self.data.rfind(b'\x00\x3b')
            if trailer_index == -1:
                self.flags.add('no_trailer')
            else:
                trailer_data = self.data[trailer_index + 2:]
                if trailer_data:
                    self.metadata['trailerIndex'] = trailer_index

                    ex_file = core.StrelkaFile(
                        source=self.name,
                    )
                    for c in util.chunk_string(trailer_data):
                        p = self.fk.pipeline()
                        p.rpush(ex_file.uid, c)
                        p.expire(ex_file.uid, self.expire)
                        p.execute()
                    self.files.append(ex_file)
