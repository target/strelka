import binascii
import struct

import pefile

from strelka import strelka

CHARACTERISTICS_DLL = {
    0x0020: 'HIGH_ENTROPY_VA',
    0x0040: 'DYNAMIC_BASE',
    0x0080: 'FORCE_INTEGRITY',
    0x0100: 'NX_COMPAT',
    0x0200: 'NO_ISOLATION',
    0x0400: 'NO_SEH',
    0x0800: 'NO_BIND',
    0x1000: 'APPCONTAINER',
    0x2000: 'WDM_DRIVER',
    0x4000: 'GUARD_CF',
    0x8000: 'TERMINAL_SERVER_AWARE',
}
CHARACTERISTICS_IMAGE = {
    0x0001: 'RELOCS_STRIPPED',
    0x0002: 'EXECUTABLE_IMAGE',
    0x0004: 'LINE_NUMS_STRIPPED',
    0x0008: 'LOCAL_SYMS_STRIPPED',
    0x0010: 'AGGRESIVE_WS_TRIM',
    0x0020: 'LARGE_ADDRESS_AWARE',
    0x0040: '16BIT_MACHINE',
    0x0080: 'BYTES_REVERSED_LO',
    0x0100: '32BIT_MACHINE',
    0x0200: 'DEBUG_STRIPPED',
    0x0400: 'REMOVABLE_RUN_FROM_SWAP',
    0x0800: 'NET_RUN_FROM_SWAP',
    0x1000: 'SYSTEM',
    0x2000: 'DLL',
    0x4000: 'UP_SYSTEM_ONLY',
    0x8000: 'BYTES_REVERSED_HI',
}
CHARACTERISTICS_SECTION = {
    0x00000000: 'TYPE_REG',
    0x00000001: 'TYPE_DSECT',
    0x00000002: 'TYPE_NOLOAD',
    0x00000004: 'TYPE_GROUP',
    0x00000008: 'TYPE_NO_PAD',
    0x00000010: 'TYPE_COPY',
    0x00000020: 'CNT_CODE',
    0x00000040: 'CNT_INITIALIZED_DATA',
    0x00000080: 'CNT_UNINITIALIZED_DATA',
    0x00000100: 'LNK_OTHER',
    0x00000200: 'LNK_INFO',
    0x00000400: 'LNK_OVER',
    0x00000800: 'LNK_REMOVE',
    0x00001000: 'LNK_COMDAT',
    0x00004000: 'MEM_PROTECTED',
    0x00004000: 'NO_DEFER_SPEC_EXC',
    0x00008000: 'GPREL',
    0x00008000: 'MEM_FARDATA',
    0x00010000: 'MEM_SYSHEAP',
    0x00020000: 'MEM_PURGEABLE',
    0x00020000: 'MEM_16BIT',
    0x00040000: 'MEM_LOCKED',
    0x00080000: 'MEM_PRELOAD',
    0x00100000: 'ALIGN_1BYTES',
    0x00200000: 'ALIGN_2BYTES',
    0x00300000: 'ALIGN_4BYTES',
    0x00400000: 'ALIGN_8BYTES',
    0x00500000: 'ALIGN_16BYTES',
    0x00600000: 'ALIGN_32BYTES',
    0x00700000: 'ALIGN_64BYTES',
    0x00800000: 'ALIGN_128BYTES',
    0x00900000: 'ALIGN_256BYTES',
    0x00A00000: 'ALIGN_512BYTES',
    0x00B00000: 'ALIGN_1024BYTES',
    0x00C00000: 'ALIGN_2048BYTES',
    0x00D00000: 'ALIGN_4096BYTES',
    0x00E00000: 'ALIGN_8192BYTES',
    0x00F00000: 'ALIGN_MASK',
    0x01000000: 'LNK_NRELOC_OVFL',
    0x02000000: 'MEM_DISCARDABLE',
    0x04000000: 'MEM_NOT_CACHED',
    0x08000000: 'MEM_NOT_PAGED',
    0x10000000: 'MEM_SHARED',
    0x20000000: 'MEM_EXECUTE',
    0x40000000: 'MEM_READ',
    0x80000000: 'MEM_WRITE',
}
# https://docs.microsoft.com/en-us/windows/win32/api/verrsrc/ns-verrsrc-tagvs_fixedfileinfo
FIXED_FILE_INFO_FLAGS = {
    0x00000001: 'DEBUG',
    0x00000010: 'INFOINFERRED',
    0x00000004: 'PATCHED',
    0x00000002: 'PRERELEASE',
    0x00000008: 'PRIVATEBUILD',
    0x00000020: 'SPECIALBUILD',
}
FIXED_FILE_INFO_OS = {
    0x00000000: 'UNKNOWN',
    0x00000001: 'WINDOWS16',
    0x00000002: 'PM16',
    0x00000003: 'PM32',
    0x00000004: 'WINDOWS32',
    0x00010000: 'DOS',
    0x00040000: 'NT',
    0x00020000: 'OS216',
    0x00030000: 'OS232',
}
FIXED_FILE_INFO_SUBTYPE = {
    (0x00000003, 0x00000000): 'UNKNOWN',
    (0x00000003, 0x00000001): 'DRV_PRINTER',
    (0x00000003, 0x00000002): 'DRV_KEYBOARD',
    (0x00000003, 0x00000003): 'DRV_LANGUAGE',
    (0x00000003, 0x00000004): 'DRV_DISPLAY',
    (0x00000003, 0x00000005): 'DRV_MOUSE',
    (0x00000003, 0x00000006): 'DRV_NETWORK',
    (0x00000003, 0x00000007): 'DRV_SYSTEM',
    (0x00000003, 0x00000008): 'DRV_INSTALLABLE',
    (0x00000003, 0x00000009): 'DRV_SOUND',
    (0x00000003, 0x0000000A): 'DRV_COMM',
    (0x00000003, 0x0000000C): 'DRV_VERSIONED_PRINTER',
    (0x00000004, 0x00000000): 'UNKNOWN',
    (0x00000004, 0x00000001): 'FONT_RASTER',
    (0x00000004, 0x00000002): 'FONT_VECTOR',
    (0x00000004, 0x00000003): 'FONT_TRUETYPE',
}
FIXED_FILE_INFO_TYPE = {
    0x00000000: 'UNKNOWN',
    0x00000001: 'APP',
    0x00000002: 'DLL',
    0x00000003: 'DRV',
    0x00000004: 'FONT',
    0x00000005: 'VXD',
    0x00000007: 'STATIC_LIB',
}
MAGIC_DOS = {
    0x5A4D: 'DOS',
    0x4D5A: 'DOSZM',
    0x454E: 'NE',
    0x454C: 'LE',
    0x584C: 'LX',
    0x5A56: 'TE',
    0x00004550: 'NT',
}
MAGIC_IMAGE = {
    0x10b: '32_BIT',
    0x20b: '64_BIT',
    0x107: 'ROM_IMAGE',
}
VAR_FILE_INFO_LANGS = {
    0x0401: 'Arabic',
    0x0415: 'Polish',
    0x0402: 'Bulgarian',
    0x0416: 'Portuguese (Brazil)',
    0x0403: 'Catalan',
    0x0417: 'Rhaeto-Romanic',
    0x0404: 'Traditional Chinese',
    0x0418: 'Romanian',
    0x0405: 'Czech',
    0x0419: 'Russian',
    0x0406: 'Danish',
    0x041A: 'Croato-Serbian (Latin)',
    0x0407: 'German',
    0x041B: 'Slovak',
    0x0408: 'Greek',
    0x041C: 'Albanian',
    0x0409: 'U.S. English',
    0x041D: 'Swedish',
    0x040A: 'Castilian Spanish',
    0x041E: 'Thai',
    0x040B: 'Finnish',
    0x041F: 'Turkish',
    0x040C: 'French',
    0x0420: 'Urdu',
    0x040D: 'Hebrew',
    0x0421: 'Bahasa',
    0x040E: 'Hungarian',
    0x0804: 'Simplified Chinese',
    0x040F: 'Icelandic',
    0x0807: 'Swiss German',
    0x0410: 'Italian',
    0x0809: 'U.K. English',
    0x0411: 'Japanese',
    0x080A: 'Spanish (Mexico)',
    0x0412: 'Korean',
    0x080C: 'Belgian French',
    0x0413: 'Dutch',
    0x0C0C: 'Canadian French',
    0x0414: 'Norwegian – Bokmal',
    0x100C: 'Swiss French',
    0x0810: 'Swiss Italian',
    0x0816: 'Portuguese (Portugal)',
    0x0813: 'Belgian Dutch',
    0x081A: 'Serbo-Croatian (Cyrillic)',
    0x0814: 'Norwegian – Nynorsk',
}
VAR_FILE_INFO_CHARS = {
    0: '7-bit ASCII',
    932: 'Japan (Shift – JIS X-0208)',
    949: 'Korea (Shift – KSC 5601)',
    950: 'Taiwan (Big5)',
    1200: 'Unicode',
    1250: 'Latin-2 (Eastern European)',
    1251: 'Cyrillic',
    1252: 'Multilingual',
    1253: 'Greek',
    1254: 'Turkish',
    1255: 'Hebrew',
    1256: 'Arabic',
}


class ScanPe(strelka.Scanner):
    """Collects metadata from PE files."""
    def scan(self, data, file, options, expire_at):
        try:
            pe = pefile.PE(data=data)
        except pefile.PEFormatError:
            self.flags.append('pe_format_error')
            return

        self.event['total'] = {
            'libraries': 0,
            'resources': 0,
            'sections': len(pe.sections),
            'symbols': 0,
        }

        if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
            for d in pe.DIRECTORY_ENTRY_DEBUG:
                data = pe.get_data(d.struct.AddressOfRawData, d.struct.SizeOfData)
                if data.find(b'RSDS') != -1 and len(data) > 24:
                    pdb = data[data.find(b'RSDS'):]
                    self.event['debug'] = {
                        'type': 'rsds',
                        'guid': b'%s-%s-%s-%s' % (
                            binascii.hexlify(pdb[4:8]),
                            binascii.hexlify(pdb[8:10]),
                            binascii.hexlify(pdb[10:12]),
                            binascii.hexlify(pdb[12:20]),
                        ),
                        'age': struct.unpack('<L', pdb[20:24])[0],
                        'pdb': pdb[24:].rstrip(b'\x00')
                    }
                elif data.find(b'NB10') != -1 and len(data) > 16:
                    pdb = data[data.find(b'NB10') + 8:]
                    self.event['debug'] = {
                        'type': 'nb10',
                        'created': struct.unpack('<L', pdb[0:4])[0],
                        'age': struct.unpack('<L', pdb[4:8])[0],
                        'pdb': pdb[8:].rstrip(b'\x00'),
                    }

        self.event['file_info'] = {
            'fixed': {},
            'string': [],
            'var': {},
        }

        if hasattr(pe, 'FileInfo'):
            fi = pe.FileInfo[0]  # contains a single element
            for i in fi:
                if i.Key == b'StringFileInfo':
                    for st in i.StringTable:
                        for k, v in st.entries.items():
                            self.event['file_info']['string'].append({
                                'name': k.decode(),
                                'value': v.decode(),
                            })
                elif i.Key == b'VarFileInfo':
                    for v in i.Var:
                        translation = v.entry.get(b'Translation')
                        (lang, char) = (translation.split())
                        self.event['file_info']['var'] = {
                            'language': VAR_FILE_INFO_LANGS.get(int(lang, 16)),
                            'character_set': VAR_FILE_INFO_CHARS.get(int(char, 16)),
                        }

        if hasattr(pe, 'VS_FIXEDFILEINFO'):
            vs_ffi = pe.VS_FIXEDFILEINFO[0]  # contains a single element
            self.event['file_info']['fixed'] = {
                'flags': [],
                'operating_systems': [],
                'type': {
                    'primary': FIXED_FILE_INFO_TYPE.get(vs_ffi.FileType),
                    'sub': FIXED_FILE_INFO_SUBTYPE.get((vs_ffi.FileType, vs_ffi.FileSubtype), ''),
                }
            }

            # http://www.jasinskionline.com/windowsapi/ref/v/vs_fixedfileinfo.html
            ff_flags = vs_ffi.FileFlagsMask & vs_ffi.FileFlags
            for f in FIXED_FILE_INFO_FLAGS:
                if ff_flags & f:
                    self.event['file_info']['fixed']['flags'].append(FIXED_FILE_INFO_FLAGS[f])
            for o in FIXED_FILE_INFO_OS:
                if vs_ffi.FileOS & o:
                    self.event['file_info']['fixed']['operating_systems'].append(FIXED_FILE_INFO_OS[o])

        self.event['header'] = {
            'address': {
                'code': pe.OPTIONAL_HEADER.BaseOfCode,
                'entry_point': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                'image': pe.OPTIONAL_HEADER.ImageBase,
            },
            'alignment': {
                'file': pe.OPTIONAL_HEADER.FileAlignment,
                'section': pe.OPTIONAL_HEADER.SectionAlignment,
            },
            'characteristics': {
                'dll': [],
                'image': [],
            },
            'checksum': pe.OPTIONAL_HEADER.CheckSum,
            'machine': {
                'id': pe.FILE_HEADER.Machine,
                'type': pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine).replace('IMAGE_FILE_MACHINE_', ''),
            },
            'magic': {
                'dos': MAGIC_DOS.get(pe.DOS_HEADER.e_magic, ''),
                'image': MAGIC_IMAGE.get(pe.OPTIONAL_HEADER.Magic, ''),
            },
            'size': {
                'code': pe.OPTIONAL_HEADER.SizeOfCode,
                'data': {
                    'initialized': pe.OPTIONAL_HEADER.SizeOfInitializedData,
                    'uninitialized': pe.OPTIONAL_HEADER.SizeOfUninitializedData,
                },
                'headers': pe.OPTIONAL_HEADER.SizeOfHeaders,
                'heap': {
                    'reserve': pe.OPTIONAL_HEADER.SizeOfHeapReserve,
                    'commit': pe.OPTIONAL_HEADER.SizeOfHeapCommit,
                },
                'image': pe.OPTIONAL_HEADER.SizeOfImage,
                'stack': {
                    'commit': pe.OPTIONAL_HEADER.SizeOfStackCommit,
                    'reserve': pe.OPTIONAL_HEADER.SizeOfStackReserve,
                },
            },
            'subsystem': pefile.SUBSYSTEM_TYPE.get(pe.OPTIONAL_HEADER.Subsystem).replace('IMAGE_SUBSYSTEM_', ''),
            'timestamp': pe.FILE_HEADER.TimeDateStamp,
            'version': {
                'image': float(f'{pe.OPTIONAL_HEADER.MajorImageVersion}.{pe.OPTIONAL_HEADER.MinorImageVersion}'),
                'linker': float(f'{pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}'),
                'operating_system': float(f'{pe.OPTIONAL_HEADER.MajorOperatingSystemVersion}.{pe.OPTIONAL_HEADER.MinorOperatingSystemVersion}'),
                'subsystem': float(f'{pe.OPTIONAL_HEADER.MajorSubsystemVersion}.{pe.OPTIONAL_HEADER.MinorSubsystemVersion}'),
            },
        }

        if hasattr(pe.OPTIONAL_HEADER, 'BaseOfData'):
            self.event['header']['address']['data'] = pe.OPTIONAL_HEADER.BaseOfData

        for o in CHARACTERISTICS_DLL:
            if pe.OPTIONAL_HEADER.DllCharacteristics & o:
                self.event['header']['characteristics']['dll'].append(CHARACTERISTICS_DLL[o])

        for o in CHARACTERISTICS_IMAGE:
            if pe.FILE_HEADER.Characteristics & o:
                self.event['header']['characteristics']['image'].append(CHARACTERISTICS_IMAGE[o])

        self.event['resources'] = []
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for res0 in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                for res1 in res0.directory.entries:
                    name = ''
                    if res1.name:
                        name = str(res1.name)

                    for res2 in res1.directory.entries:
                        lang = res2.data.lang
                        sub = res2.data.sublang
                        sub = pefile.get_sublang_name_for_lang(lang, sub)
                        lang = pefile.LANG.get(lang, '')
                        self.event['resources'].append({
                            'id': res1.id,
                            'name': name,
                            'language': {
                                'primary': lang.replace('LANG_', ''),
                                'sub': sub.replace('SUBLANG_', '')
                            },
                            'type': pefile.RESOURCE_TYPE.get(res0.id, '').replace('RT_', ''),
                        })

                        data = pe.get_data(res2.data.struct.OffsetToData, res2.data.struct.Size)
                        if len(data) > 0:
                            extract_file = strelka.File(
                                name=f'{name or res1.id}',
                                source=f'{self.name}::Resource',
                            )
                            for c in strelka.chunk_string(data):
                                self.upload_to_coordinator(
                                    extract_file.pointer,
                                    c,
                                    expire_at,
                                )
                            self.files.append(extract_file)

        self.event['total']['resources'] = len(self.event['resources'])

        self.event['sections'] = []
        for sec in pe.sections:
            name = sec.Name.rstrip(b'\x00').decode()
            row = {
                'address': {
                    'physical': sec.Misc_PhysicalAddress,
                    'virtual': sec.VirtualAddress,
                },
                'characteristics': [],
                'entropy': sec.get_entropy(),
                'name': name,
                'size': sec.SizeOfRawData,
            }
            for o in CHARACTERISTICS_SECTION:
                if sec.Characteristics & o:
                    row['characteristics'].append(CHARACTERISTICS_SECTION[o])

            if sec.SizeOfRawData > 0:
                extract_file = strelka.File(
                    name=name,
                    source=f'{self.name}::Section',
                )
                for c in strelka.chunk_string(sec.get_data()):
                    self.upload_to_coordinator(
                        extract_file.pointer,
                        c,
                        expire_at,
                    )
                self.files.append(extract_file)

            self.event['sections'].append(row)

        self.event['symbols'] = {
            'exported': [],
            'imported': [],
            'libraries': [],
            'table': [],
        }

        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            self.event['imphash'] = pe.get_imphash()

            for imp in pe.DIRECTORY_ENTRY_IMPORT:
                lib = imp.dll.decode()
                if lib not in self.event['symbols']['libraries']:
                    self.event['symbols']['libraries'].append(lib)

                row = {
                    'library': lib,
                    'symbols': [],
                    'type': 'import',
                }
                for e in imp.imports:
                    if not e.name:
                        name = f'ord{e.ordinal}'
                    else:
                        name = e.name.decode()
                    self.event['symbols']['imported'].append(name)
                    row['symbols'].append(name)
                self.event['symbols']['table'].append(row)

        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if not exp.name:
                    name = f'ord{exp.ordinal}'
                else:
                    name = exp.name
                self.event['symbols']['exported'].append(name)
                self.event['symbols']['table'].append({
                    'address': exp.address,
                    'symbol': name,
                    'type': 'export',
                })

        self.event['total']['libraries'] = len(self.event['symbols']['libraries'])
        self.event['total']['symbols'] = len(self.event['symbols']['table'])

        security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
        sec_addr = security.VirtualAddress
        if security.Size > 0:
            data = pe.write()[sec_addr + 8:]
            if len(data) > 0:
                self.flags.append('signed')

                extract_file = strelka.File(
                    name='signature',
                    source=f'{self.name}::Security',
                )
                for c in strelka.chunk_string(data):
                    self.upload_to_coordinator(
                        extract_file.pointer,
                        c,
                        expire_at,
                    )
                self.files.append(extract_file)
