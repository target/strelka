import io

from elftools.common import exceptions
from elftools.elf import descriptions
from elftools.elf import dynamic
from elftools.elf import elffile
from elftools.elf import sections

from strelka import strelka


class ScanElf(strelka.Scanner):
    """Collects metadata from ELF files."""
    def scan(self, data, file, options, expire_at):
        with io.BytesIO(data) as elf_io:
            try:
                elf = elffile.ELFFile(elf_io)

                self.event.setdefault('header', {})
                for (key, value) in elf.header.items():
                    if key == 'e_flags':
                        self.event['header']['flags'] = value
                    elif key == 'e_shnum':
                        self.event['header']['section_headers'] = value
                    elif key == 'e_phnum':
                        self.event['header']['program_headers'] = value
                    elif key == 'e_version':
                        self.event['header']['file_version'] = descriptions.describe_e_version_numeric(value)
                    elif key == 'e_machine':
                        self.event['header']['machine'] = descriptions.describe_e_machine(value)
                    elif key == 'e_type':
                        self.event['header']['file_type'] = descriptions.describe_e_type(value)
                    elif key == 'e_ident':
                        for x, y in value.items():
                            if x == 'EI_DATA':
                                self.event['header']['data'] = descriptions.describe_ei_data(y)
                            elif x == 'EI_OSABI':
                                self.event['header']['os_abi'] = descriptions.describe_ei_osabi(y)
                            elif x == 'EI_VERSION':
                                self.event['header']['header_version'] = descriptions.describe_ei_version(y)
                            elif x == 'EI_CLASS':
                                self.event['header']['class'] = descriptions.describe_ei_class(y)
                            elif x == 'EI_ABIVERSION':
                                self.event['header']['abi_version'] = y

                try:
                    self.event.setdefault('shared_libraries', [])
                    self.event.setdefault('imports', [])
                    self.event.setdefault('exports', [])
                    for section in elf.iter_sections():
                        if not section.is_null():
                            if isinstance(section, dynamic.DynamicSection):
                                for tag in section.iter_tags():
                                    if tag.entry.d_tag == 'DT_NEEDED':
                                        if tag.needed not in self.event['shared_libraries']:
                                            self.event['shared_libraries'].append(tag.needed)

                            # Attempt to organize symbols into imports and exports
                            # This is the most comprehensive explanation I've seen for organizing these symbols: http://www.m4b.io/elf/export/binary/analysis/2015/05/25/what-is-an-elf-export.html
                            if isinstance(section, sections.SymbolTableSection):
                                for symbol in section.iter_symbols():
                                    if descriptions.describe_symbol_type(symbol['st_info']['type']) in ['FUNC', 'OBJECT']:
                                        if descriptions.describe_symbol_bind(symbol['st_info']['bind']) in ['GLOBAL', 'WEAK']:
                                            if descriptions.describe_symbol_shndx(symbol['st_shndx']) == 'UND':
                                                if symbol.name not in self.event['imports']:
                                                    self.event['imports'].append(symbol.name)
                                            else:
                                                if symbol.name not in self.event['exports']:
                                                    self.event['exports'].append(symbol.name)

                except OverflowError:
                    self.flags.append('overflow_error')

                self.event.setdefault('segments', [])
                segment_cache = {}
                for segment in elf.iter_segments():
                    for section in elf.iter_sections():
                        if not section.is_null() and segment.section_in_segment(section):
                            key = segment.header['p_type']
                            if key not in self.event['segments']:
                                self.event['segments'].append(key)
                                segment_cache.setdefault(key, [])
                            segment_cache[key].append(section.name)

                self.event.setdefault('segment_sections', [])
                for (key, value) in segment_cache.items():
                    section_dict = {'segment': key, 'sections': value}
                    if section_dict not in self.event['segment_sections']:
                        self.event['segment_sections'].append(section_dict)

            except exceptions.ELFParseError:
                self.flags.append('elf_parse_error')
