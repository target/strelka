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

        self.event['total'] = {'rtf_objects': 0, 'extracted': 0}

        rtf = rtfobj.RtfObjParser(data)
        rtf.parse()
        self.event['total']['rtf_objects'] = len(rtf.rtf_objects)

        for rtf_object in rtf.rtf_objects:
            if self.event['total']['extracted'] >= file_limit:
                break

            index = rtf.server.index(rtf_object)
            if rtf_object.is_package:
                extract_file = strelka.File(
                    name=rtf_object.filename,
                    source=self.name,
                )

                for c in strelka.chunk_string(rtf_object.olepkgdata):
                    self.upload_to_coordinator(
                        extract_file.pointer,
                        c,
                        expire_at,
                    )

            elif rtf_object.is_ole:
                extract_file = strelka.File(
                    name=f'rtf_object_{index}',
                    source=self.name,
                )

                for c in strelka.chunk_string(rtf_object.oledata):
                    self.upload_to_coordinator(
                        extract_file.pointer,
                        c,
                        expire_at,
                    )

            else:
                extract_file = strelka.File(
                    name=f'rtf_object_{index}',
                    source=self.name,
                )

                for c in strelka.chunk_string(rtf_object.rawdata):
                    self.upload_to_coordinator(
                        extract_file.pointer,
                        c,
                        expire_at,
                    )

            self.files.append(extract_file)
            self.event['total']['extracted'] += 1
