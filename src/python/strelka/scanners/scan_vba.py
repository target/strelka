from oletools import olevba3

from strelka import strelka


class ScanVba(strelka.Scanner):
    """Extracts and analyzes VBA from document files.

    Options:
        analyze_macros: Boolean that determines if macros should be analyzed.
            Defaults to True.
    """
    def scan(self, data, file, options, expire_at):
        analyze_macros = options.get('analyze_macros', True)

        self.metadata['total'] = {'files': 0, 'extracted': 0}

        try:
            vba = olevba3.VBA_Parser(filename=file.name, data=data)
            if vba.detect_vba_macros():
                extract_macros = list(vba.extract_macros())
                self.metadata['total']['files'] = len(extract_macros)
                for (filename, stream_path, vba_filename, vba_code) in extract_macros:
                    extract_file = strelka.File(
                        name=f'{vba_filename}',
                        source=self.name,
                    )

                    for c in strelka.chunk_string(vba_code):
                        self.upload_to_cache(
                            extract_file.pointer,
                            c,
                            expire_at,
                        )

                    self.files.append(extract_file)
                    self.metadata['total']['extracted'] += 1

                if analyze_macros:
                    self.metadata.setdefault('auto_exec', [])
                    self.metadata.setdefault('base64', [])
                    self.metadata.setdefault('dridex', [])
                    self.metadata.setdefault('hex', [])
                    self.metadata.setdefault('ioc', [])
                    self.metadata.setdefault('suspicious', [])
                    macros = vba.analyze_macros()
                    for (type, keyword, description) in macros:
                        if type == 'AutoExec':
                            self.metadata['auto_exec'].append(keyword)
                        elif type == 'Base64 String':
                            self.metadata['base64'].append(keyword)
                        elif type == 'Dridex String':
                            self.metadata['dridex'].append(keyword)
                        elif type == 'Hex String':
                            self.metadata['hex'].append(keyword)
                        elif type == 'IOC':
                            self.metadata['ioc'].append(keyword)
                        elif type == 'Suspicious':
                            self.metadata['suspicious'].append(keyword)

        except olevba3.FileOpenError:
            self.flags.append('file_open_error')
        finally:
            vba.close()
