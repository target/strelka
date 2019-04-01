import binascii
from datetime import datetime
import hashlib
import struct

import pefile

from strelka import core

IMAGE_MAGIC_LOOKUP = {
    0x10b: '32_BIT',
    0x20b: '64_BIT',
    0x107: 'ROM_IMAGE',
}


class ScanPe(core.StrelkaScanner):
    """Collects metadata from PE files."""
    def scan(self, data, file_object, options):
        self.metadata['total'] = {'sections': 0}

        try:
            pe = pefile.PE(data=data)
            pe_dict = pe.dump_dict()

            self.metadata['total']['sections'] = pe.FILE_HEADER.NumberOfSections
            self.metadata['warnings'] = pe.get_warnings()
            self.metadata['timestamp'] = datetime.utcfromtimestamp(pe.FILE_HEADER.TimeDateStamp).isoformat(timespec='seconds')
            machine = pe.FILE_HEADER.Machine
            self.metadata['machine'] = {
                'id': machine,
                'type': pefile.MACHINE_TYPE.get(machine),
            }
            # Reference: http://msdn.microsoft.com/en-us/library/windows/desktop/ms680339%28v=vs.85%29.aspx
            self.metadata['imageMagic'] = IMAGE_MAGIC_LOOKUP.get(pe.OPTIONAL_HEADER.Magic, 'Unknown')
            subsystem = pe.OPTIONAL_HEADER.Subsystem
            self.metadata['subsystem'] = pefile.SUBSYSTEM_TYPE.get(subsystem)
            self.metadata['stackReserveSize'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
            self.metadata['stackCommitSize'] = pe.OPTIONAL_HEADER.SizeOfStackCommit
            self.metadata['heapReserveSize'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
            self.metadata['heapCommitSize'] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
            self.metadata['imageBase'] = pe.OPTIONAL_HEADER.ImageBase
            self.metadata['entryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            self.metadata['imageCharacteristics'] = pe_dict.get('Flags')
            self.metadata['dllCharacteristics'] = pe_dict.get('DllCharacteristics')

            try:
                self.metadata['imphash'] = pe.get_imphash()

            except AttributeError:
                self.flags.add(f'{self.scanner_name}::no_imphash')

            self.metadata.setdefault('exportFunctions', [])
            export_symbols = pe_dict.get('Exported symbols', [])
            for symbols in export_symbols:
                name = symbols.get('Name')
                if name is not None and isinstance(name, bytes) and name not in self.metadata['exportFunctions']:
                    self.metadata['exportFunctions'].append(name)

            import_cache = {}
            self.metadata.setdefault('imports', [])
            import_symbols = pe_dict.get('Imported symbols', [])
            for symbol in import_symbols:
                for import_ in symbol:
                    dll = import_.get('DLL')
                    if dll is not None:
                        if dll not in self.metadata['imports']:
                            self.metadata['imports'].append(dll)
                            import_cache.setdefault(dll, [])
                        ordinal = import_.get('Ordinal')
                        if ordinal is not None:
                            ordinal = pefile.ordlookup.ordLookup(dll.lower(), ordinal, make_name=True)
                            import_cache[dll].append(ordinal)
                        name = import_.get('Name')
                        if name is not None:
                            import_cache[dll].append(name)

            self.metadata.setdefault('importFunctions', [])
            for (import_, functions) in import_cache.items():
                import_entry = {'import': import_, 'functions': functions}
                if import_entry not in self.metadata['importFunctions']:
                    self.metadata['importFunctions'].append(import_entry)

            self.metadata.setdefault('resources', [])
            try:
                for resource in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    res_type = pefile.RESOURCE_TYPE.get(resource.id, 'Unknown')
                    for entry in resource.directory.entries:
                        for e_entry in entry.directory.entries:
                            sublang = pefile.get_sublang_name_for_lang(
                                e_entry.data.lang,
                                e_entry.data.sublang,
                            )
                            offset = e_entry.data.struct.OffsetToData
                            size = e_entry.data.struct.Size
                            r_data = pe.get_data(offset, size)
                            language = pefile.LANG.get(e_entry.data.lang, 'Unknown')
                            data = {
                                'type': res_type,
                                'id': e_entry.id,
                                'name': e_entry.data.struct.name,
                                'offset': offset,
                                'size': size,
                                'sha256': hashlib.sha256(r_data).hexdigest(),
                                'sha1': hashlib.sha1(r_data).hexdigest(),
                                'md5': hashlib.md5(r_data).hexdigest(),
                                'language': language,
                                'subLanguage': sublang,
                            }
                            if data not in self.metadata['resources']:
                                self.metadata['resources'].append(data)

            except AttributeError:
                self.flags.add(f'{self.scanner_name}::no_resources')

            if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
                debug = dict()
                for e in pe.DIRECTORY_ENTRY_DEBUG:
                    rawData = pe.get_data(e.struct.AddressOfRawData, e.struct.SizeOfData)
                    if rawData.find(b'RSDS') != -1 and len(rawData) > 24:
                        pdb = rawData[rawData.find(b'RSDS'):]
                        debug['guid'] = b'%s-%s-%s-%s' % (
                            binascii.hexlify(pdb[4:8]),
                            binascii.hexlify(pdb[8:10]),
                            binascii.hexlify(pdb[10:12]),
                            binascii.hexlify(pdb[12:20]),
                        )
                        debug['age'] = struct.unpack('<L', pdb[20:24])[0]
                        debug['pdb'] = pdb[24:].rstrip(b'\x00')
                        self.metadata['rsds'] = debug
                    elif rawData.find(b'NB10') != -1 and len(rawData) > 16:
                        pdb = rawData[rawData.find(b'NB10') + 8:]
                        debug['created'] = struct.unpack('<L', pdb[0:4])[0]
                        debug['age'] = struct.unpack('<L', pdb[4:8])[0]
                        debug['pdb'] = pdb[8:].rstrip(b'\x00')
                        self.metadata['nb10'] = debug

            self.metadata.setdefault('sections', [])
            sections = pe_dict.get('PE Sections', [])
            for section in sections:
                section_entry = {
                    'name': section.get('Name', {}).get('Value', '').replace('\\x00', ''),
                    'flags': section.get('Flags', []),
                    'structure': section.get('Structure', ''),
                }
                if section_entry not in self.metadata['sections']:
                    self.metadata['sections'].append(section_entry)

            security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
            digital_signature_virtual_address = security.VirtualAddress
            if security.Size > 0:
                file_data = pe.write()[digital_signature_virtual_address + 8:]
                if len(file_data) > 0:
                    self.flags.add(f'{self.scanner_name}::signed')
                    file_ = core.StrelkaFile(
                        name='digital_signature',
                        source=self.scanner_name,
                    )
                    self.r0.setex(
                        file_.uid,
                        self.expire,
                        file_data,
                    )
                    self.files.append(file_)

                else:
                    self.flags.add(f'{self.scanner_name}::empty_signature')

            if hasattr(pe, 'FileInfo'):
                self.metadata.setdefault('versionInfo', [])
                for structure in pe.FileInfo:
                    for fileinfo in structure:
                        if fileinfo.Key.decode() == 'StringFileInfo':
                            for block in fileinfo.StringTable:
                                for name, value in block.entries.items():
                                    fixedinfo = {
                                        'name': name.decode(),
                                        'value': value.decode(),
                                    }
                                    if fixedinfo not in self.metadata['versionInfo']:
                                        self.metadata['versionInfo'].append(fixedinfo)
            else:
                self.flags.add(f'{self.scanner_name}::no_version_info')

        except IndexError:
            self.flags.add(f'{self.scanner_name}::pe_index_error')
        except pefile.PEFormatError:
            self.flags.add(f'{self.scanner_name}::pe_format_error')
