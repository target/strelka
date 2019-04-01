import jsbeautifier
import pyjsparser

from strelka import core


class ScanJavascript(core.StrelkaScanner):
    """Collects metadata from JavaScript files.

    Options:
        beautify: Boolean that determines if JavaScript should be deobfuscated.
            Defaults to True.
    """
    def scan(self, data, file_object, options):
        beautify = options.get('beautify', True)

        self.metadata.setdefault('literals', [])
        self.metadata.setdefault('functions', [])
        self.metadata.setdefault('variables', [])

        try:
            if beautify:
                js = jsbeautifier.beautify(data.decode())
            else:
                js = data.decode()
            parser = pyjsparser.PyJsParser()
            parsed = parser.parse(js)
            self._javascript_recursion(self, parsed)

        except AttributeError:
            self.flags.add(f'{self.scanner_name}::attribute_error')
        except IndexError:
            self.flags.add(f'{self.scanner_name}::index_error')
        except KeyError:
            self.flags.add(f'{self.scanner_name}::key_error')
        except NotImplementedError:
            self.flags.add(f'{self.scanner_name}::not_implemented_error')
        except RecursionError:
            self.flags.add(f'{self.scanner_name}::recursion_depth_exceeded')
        except UnicodeDecodeError:
            self.flags.add(f'{self.scanner_name}::unicode_decode_error')
        except pyjsparser.pyjsparserdata.JsSyntaxError:
            self.flags.add(f'{self.scanner_name}::js_syntax_error')

    @staticmethod
    def _javascript_recursion(self, input, previous_token=None):
        """Recursively parses parsed Javascript.

        Args:
            input: Parsed Javascript to be recursively processed.
            previous_token: Previous token type parsed during recursion.
        """
        if isinstance(input, dict):
            type = input.get('type', None)
            if type == 'Literal':
                regex_pattern = input.get('regex', {}).get('pattern', '')
                value = input.get('value')
                if regex_pattern and regex_pattern not in self.metadata['literals']:
                    self.metadata['literals'].append(regex_pattern)
                elif value is not None:
                    if not isinstance(value, str):
                        value = str(value)
                    if value not in self.metadata['literals']:
                        self.metadata['literals'].append(value)
            elif type == 'FunctionDeclaration':
                function_name = input.get('id', {}).get('name', '')
                if function_name and function_name not in self.metadata['functions']:
                    self.metadata['functions'].append(function_name)
            elif type == 'VariableDeclaration':
                declarations = input.get('declarations')
                if declarations is not None:
                    for declaration in declarations:
                        variable_name = declaration.get('id', {}).get('name', '')
                        if variable_name and variable_name not in self.metadata['variables']:
                            self.metadata['variables'].append(variable_name)

            for v in input.values():
                self._javascript_recursion(self, v, type)
        elif isinstance(input, list):
            for i in input:
                self._javascript_recursion(self, i)
