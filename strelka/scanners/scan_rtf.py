from oletools import rtfobj

from strelka import core


class ScanRtf(core.StrelkaScanner):
    """Extracts files from RTF files.

    Options:
        limit: Maximum number of files to extract.
            Defaults to 1000.
    """
    def scan(self, data, file_object, options):
        file_limit = options.get('limit', 1000)

        self.metadata['total'] = {'objects': 0, 'extracted': 0}

        rtf = rtfobj.RtfObjParser(data)
        rtf.parse()
        self.metadata['total']['objects'] = len(rtf.objects)

        for object in rtf.objects:
            if self.metadata['total']['extracted'] >= file_limit:
                break

            index = rtf.server.index(object)
            if object.is_package:
                file_ = core.StrelkaFile(
                    name=f'{object.filename}',
                    source=self.scanner_name,
                )
                self.r0.setex(
                    file_.uid,
                    self.expire,
                    object.olepkgdata,
                )
            elif object.is_ole:
                file_ = core.StrelkaFile(
                    name=f'object_{index}',
                    source=self.scanner_name,
                )
                self.r0.setex(
                    file_.uid,
                    self.expire,
                    object.oledata,
                )
            else:
                file_ = core.StrelkaFile(
                    name=f'object_{index}',
                    source=self.scanner_name,
                )
                self.r0.setex(
                    file_.uid,
                    self.expire,
                    object.rawdata,
                )

            self.files.append(file_)
            self.metadata['total']['extracted'] += 1
