from oletools import rtfobj

from strelka import strelka


class ScanRtf(strelka.Scanner):
    """Extracts files from RTF files.

    Options:
        limit: Maximum number of files to extract.
            Defaults to 1000.
    """
    def scan(self, data, file, options, expire_at):
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
                extract_file = strelka.File(
                    name=object.filename,
                    source=self.name,
                )

                for c in strelka.chunk_string(object.olepkgdata):
                    self.upload_to_cache(
                        extract_file.pointer,
                        c,
                        expire_at,
                    )

            elif object.is_ole:
                extract_file = strelka.File(
                    name=f'object_{index}',
                    source=self.name,
                )

                for c in strelka.chunk_string(object.oledata):
                    self.upload_to_cache(
                        extract_file.pointer,
                        c,
                        expire_at,
                    )

            else:
                extract_file = strelka.File(
                    name=f'object_{index}',
                    source=self.name,
                )

                for c in strelka.chunk_string(object.rawdata):
                    self.upload_to_cache(
                        extract_file.pointer,
                        c,
                        expire_at,
                    )

            self.files.append(extract_file)
            self.metadata['total']['extracted'] += 1
