from oletools import olevba3

from server import lib


class ScanVba(lib.StrelkaScanner):
    """Extracts and analyzes VBA from document files.

    Options:
        analyze_macros: Boolean that determines if macros should be analyzed.
            Defaults to True.
    """
    def scan(self, file_object, options):
        analyze_macros = options.get('analyze_macros', True)

        self.metadata['total'] = {'files': 0, 'extracted': 0}

        try:
            vba_parser = olevba3.VBA_Parser(filename=file_object.filename, data=file_object.data)
            if vba_parser.detect_vba_macros():
                extract_macros = list(vba_parser.extract_macros())
                self.metadata['total']['files'] = len(extract_macros)
                for (filename, stream_path, vba_filename, vba_code) in extract_macros:
                    child_filename = f'{self.scanner_name}::{vba_filename}'
                    child_fo = lib.StrelkaFile(data=vba_code,
                                               filename=child_filename,
                                               depth=file_object.depth + 1,
                                               parent_uid=file_object.uid,
                                               root_uid=file_object.root_uid,
                                               parent_hash=file_object.hash,
                                               root_hash=file_object.root_hash,
                                               source=self.scanner_name)
                    self.children.append(child_fo)
                    self.metadata['total']['extracted'] += 1

                if analyze_macros:
                    self.metadata.setdefault('autoExec', [])
                    self.metadata.setdefault('base64', [])
                    self.metadata.setdefault('dridex', [])
                    self.metadata.setdefault('hex', [])
                    self.metadata.setdefault('ioc', [])
                    self.metadata.setdefault('suspicious', [])
                    macros = vba_parser.analyze_macros()
                    for (type, keyword, description) in macros:
                        if type == 'AutoExec':
                            self.metadata['autoExec'].append(keyword)
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
            vba_parser.close()

        except olevba3.FileOpenError:
            file_object.flags.append(f'{self.scanner_name}::file_open_error')
