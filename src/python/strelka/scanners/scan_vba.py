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

        self.event['total'] = {'files': 0, 'extracted': 0}

        try:
            vba = olevba3.VBA_Parser(filename=file.name, data=data)
            if vba.detect_vba_macros():
                extract_macros = list(vba.extract_macros())
                self.event['total']['files'] = len(extract_macros)
                for (filename, stream_path, vba_filename, vba_code) in extract_macros:
                    extract_file = strelka.File(
                        name=f'{vba_filename}',
                        source=self.name,
                    )

                    for c in strelka.chunk_string(vba_code):
                        self.upload_to_coordinator(
                            extract_file.pointer,
                            c,
                            expire_at,
                        )

                    self.files.append(extract_file)
                    self.event['total']['extracted'] += 1

                if analyze_macros:
                    self.event.setdefault('auto_exec', [])
                    self.event.setdefault('base64', [])
                    self.event.setdefault('dridex', [])
                    self.event.setdefault('hex', [])
                    self.event.setdefault('ioc', [])
                    self.event.setdefault('suspicious', [])
                    macros = vba.analyze_macros()
                    for (macro_type, keyword, description) in macros:
                        if macro_type == 'AutoExec':
                            self.event['auto_exec'].append(keyword)
                        elif macro_type == 'Base64 String':
                            self.event['base64'].append(keyword)
                        elif macro_type == 'Dridex String':
                            self.event['dridex'].append(keyword)
                        elif macro_type == 'Hex String':
                            self.event['hex'].append(keyword)
                        elif macro_type == 'IOC':
                            self.event['ioc'].append(keyword)
                        elif macro_type == 'Suspicious':
                            self.event['suspicious'].append(keyword)

        except olevba3.FileOpenError:
            self.flags.append('file_open_error')
        finally:
            # TODO referenced before potential assignment as vba is opened in a try / catch block
            vba.close()
