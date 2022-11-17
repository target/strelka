import base64
import binascii
import datetime
import hashlib
import pefile
import struct
from io import BytesIO
from signify.exceptions import *
from signify.authenticode import SignedPEFile
from strelka import strelka

# Disable Signifiy Debugging Logging
import logging
logger = logging.getLogger('signify')
logger.propagate = False

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
COMMON_FILE_INFO_NAMES = {
    "Assembly Version": "assembly_version",
    "Build Description": "build_description",
    "Comments": "comments",
    "CompanyName": "company_name",
    "FileDescription": "file_description",
    "FileVersion": "file_version",
    "InternalName": "internal_name",
    "LegalCopyright": "legal_copyright",
    "LegalTrademarks": "legal_trademarks",
    "License": "license",
    "OLESelfRegister": "ole_self_register",
    "OriginalFilename": "original_filename",
    "PrivateBuild": "private_build",
    "ProductName": "product_name",
    "ProductVersion": "product_version"
}


def parse_rich(pe):
    try:
        if rich_data := pe.parse_rich_header():
            rich_dict = {
                'key': rich_data['key'].hex(),
                'clear_data': {
                    'data': base64.b64encode(rich_data['clear_data']),
                    'md5': hashlib.md5(rich_data['clear_data']).hexdigest(),
                },
                'raw_data': {
                    'data': base64.b64encode(rich_data['raw_data']),
                    'md5': hashlib.md5(rich_data['raw_data']).hexdigest(),
                },
            }

            return rich_dict
    except pefile.PEFormatError:
        return 'pe_format_error'


def parse_certificates(data):
    # set up string io as we get data
    buffer = BytesIO()
    buffer.write(data)
    buffer.seek(0)

    try:
        pefile = SignedPEFile(buffer)
        try:
            signed_datas = list(pefile.signed_datas)
        except:
            return "no_certs_found"
    except (SignedPEParseError, SignerInfoParseError, AuthenticodeParseError, VerificationError,
            CertificateVerificationError, SignerInfoVerificationError, AuthenticodeVerificationError) as e:
        return "pe_certificate_error"

    cert_list = []
    signer_list = []
    counter_signer_list = []
    for signed_data in signed_datas:
        try:
            certs = signed_data.certificates
            for cert in certs:
                asn1 = cert.to_asn1crypto
                issuer = asn1.issuer.native
                try:
                    cert_dict = {
                        "country_name": issuer.get("country_name"),
                        "organization_name": issuer.get("organization_name"),
                        "organizational_unit_name": issuer.get("organizational_unit_name"),
                        "common_name": issuer.get("common_name"),
                        "serial_number": str(cert.serial_number),
                        "issuer_dn": cert.issuer.dn,
                        "subject_dn": cert.subject.dn,
                        "valid_from": cert.valid_from.isoformat(),
                        "valid_to": cert.valid_to.isoformat(),
                        "signature_algorithim": str(cert.signature_algorithm['algorithm'])
                    }
                    cert_list.append(cert_dict)
                except Exception as e:
                    return "exception parsing certificate exception"

            signer_dict = {
                'issuer_dn': signed_data.signer_info.issuer.dn,
                'serial_number': str(signed_data.signer_info.serial_number),
                'program_name': signed_data.signer_info.program_name,
                'more_info': signed_data.signer_info.more_info
            }
            # signer information
            signer_list.append(signer_dict)

            if signed_data.signer_info.countersigner:
                if hasattr(signed_data.signer_info.countersigner, 'issuer'):
                    counter_signer_issuer_dn = signed_data.signer_info.countersigner.issuer.dn
                else:
                    counter_signer_issuer_dn = signed_data.signer_info.countersigner.signer_info.issuer.dn

                if hasattr(signed_data.signer_info.countersigner, 'serial_number'):
                    counter_signer_sn = signed_data.signer_info.countersigner.serial_number
                else:
                    counter_signer_sn = signed_data.signer_info.countersigner.signer_info.serial_number
                counter_signer_dict = {
                    'issuer_dn': counter_signer_issuer_dn,
                    'serial_number': str(counter_signer_sn),
                    'signing_time': signed_data.signer_info.countersigner.signing_time.isoformat()
                }
                counter_signer_list.append(counter_signer_dict)

        except SignedPEParseError:
            return "no certificate in signed data"

    security_dict = {
        'certificates': cert_list,
        'signers': signer_list,
        'counter_signers': counter_signer_list
    }

    try:
        pefile.verify()
        security_dict["verification"] = True
    except Exception as e:
        security_dict['verification'] = False
        security_dict['verification_error'] = str(e)

    return security_dict


class ScanPe(strelka.Scanner):
    """Collects metadata from PE files."""

    def scan(self, data, file, options, expire_at):
        try:
            pe = pefile.PE(data=data)
        except pefile.PEFormatError:
            self.flags.append('pe_format_error')
            return

        if rich_dict := parse_rich(pe):
            if type(rich_dict) != str:
                self.event['rich'] = rich_dict
            else:
                self.flags.append(rich_dict)

        if cert_dict := parse_certificates(data):
            if type(cert_dict) != str:
                self.event['security'] = cert_dict
            else:
                self.flags.append(cert_dict)

        self.event['total'] = {
            'libraries': 0,
            'resources': 0,
            'sections': len(pe.sections),
            'symbols': 0,
        }
        self.event['summary'] = {}

        if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
            for d in pe.DIRECTORY_ENTRY_DEBUG:
                try:
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
                            'pdb': pdb[24:].split(b'\x00')[0]
                        }
                    elif data.find(b'NB10') != -1 and len(data) > 16:
                        pdb = data[data.find(b'NB10') + 8:]
                        self.event['debug'] = {
                            'type': 'nb10',
                            'created': struct.unpack('<L', pdb[0:4])[0],
                            'age': struct.unpack('<L', pdb[4:8])[0],
                            'pdb': pdb[8:].split(b'\x00')[0],
                        }
                except pefile.PEFormatError:
                    self.flags.append('corrupt_debug_header')

        self.event['file_info'] = {
            'fixed': {},
            'string': [],
            'var': {},
        }

        # https://github.com/erocarrera/pefile/blob/master/pefile.py#L3553
        if hasattr(pe, 'FileInfo'):
            fi = pe.FileInfo[0]  # contains a single element
            for i in fi:
                if i.Key == b'StringFileInfo':
                    for st in i.StringTable:
                        for k, v in st.entries.items():
                            if k.decode() in COMMON_FILE_INFO_NAMES:
                                self.event['file_info'][COMMON_FILE_INFO_NAMES[k.decode()]] = v.decode()
                            else:
                                self.event['file_info']['string'].append({
                                    'name': k.decode(),
                                    'value': v.decode(),
                                })
                elif i.Key == b'VarFileInfo':
                    for v in i.Var:
                        if translation := v.entry.get(b'Translation'):
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
            'machine': {
                'id': pe.FILE_HEADER.Machine,
                'type': pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine).replace('IMAGE_FILE_MACHINE_', ''),
            },
            'magic': {
                'dos': MAGIC_DOS.get(pe.DOS_HEADER.e_magic, ''),
                'image': MAGIC_IMAGE.get(pe.OPTIONAL_HEADER.Magic, ''),
            },
            'subsystem': pefile.SUBSYSTEM_TYPE.get(pe.OPTIONAL_HEADER.Subsystem).replace('IMAGE_SUBSYSTEM_', ''),
        }

        self.event['base_of_code'] = pe.OPTIONAL_HEADER.BaseOfCode
        self.event['address_of_entry_point'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        self.event['image_base'] = pe.OPTIONAL_HEADER.ImageBase
        self.event['size_of_code'] = pe.OPTIONAL_HEADER.SizeOfCode
        self.event['size_of_initialized_data'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
        self.event['size_of_headers'] = pe.OPTIONAL_HEADER.SizeOfHeaders
        self.event['size_of_heap_reserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
        self.event['size_of_image'] = pe.OPTIONAL_HEADER.SizeOfImage
        self.event['size_of_stack_commit'] = pe.OPTIONAL_HEADER.SizeOfStackCommit
        self.event['size_of_stack_reserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
        self.event['size_of_heap_commit'] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
        self.event['size_of_uninitialized_data'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
        self.event['file_alignment'] = pe.OPTIONAL_HEADER.FileAlignment
        self.event['section_alignment'] = pe.OPTIONAL_HEADER.SectionAlignment
        self.event['checksum'] = pe.OPTIONAL_HEADER.CheckSum

        self.event['major_image_version'] = pe.OPTIONAL_HEADER.MajorImageVersion
        self.event['minor_image_version'] = pe.OPTIONAL_HEADER.MinorImageVersion
        self.event['major_linker_version'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
        self.event['minor_linker_version'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
        self.event['major_operating_system_version'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
        self.event['minor_operating_system_version'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
        self.event['major_subsystem_version'] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
        self.event['minor_subsystem_version'] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
        self.event['image_version'] = float(
            f'{pe.OPTIONAL_HEADER.MajorImageVersion}.{pe.OPTIONAL_HEADER.MinorImageVersion}')
        self.event['linker_version'] = float(
            f'{pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}')
        self.event['operating_system_version'] = float(
            f'{pe.OPTIONAL_HEADER.MajorOperatingSystemVersion}.{pe.OPTIONAL_HEADER.MinorOperatingSystemVersion}')
        self.event['subsystem_version'] = float(
            f'{pe.OPTIONAL_HEADER.MajorSubsystemVersion}.{pe.OPTIONAL_HEADER.MinorSubsystemVersion}')

        try:
            self.event['compile_time'] = datetime.datetime.utcfromtimestamp(pe.FILE_HEADER.TimeDateStamp).isoformat()
        except OverflowError:
            self.flags.append("invalid compile time caused an overflow error")

        if hasattr(pe.OPTIONAL_HEADER, 'BaseOfData'):
            self.event['base_of_data'] = pe.OPTIONAL_HEADER.BaseOfData

        dll_characteristics = []
        for o in CHARACTERISTICS_DLL:
            if pe.OPTIONAL_HEADER.DllCharacteristics & o:
                dll_characteristics.append(CHARACTERISTICS_DLL[o])

        if dll_characteristics:
            self.event['dll_characteristics'] = dll_characteristics

        image_characteristics = []
        for o in CHARACTERISTICS_IMAGE:
            if pe.FILE_HEADER.Characteristics & o:
                image_characteristics.append(CHARACTERISTICS_IMAGE[o])

        if image_characteristics:
            self.event['image_characteristics'] = image_characteristics

        self.event['resources'] = []
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            resource_md5_set = set()
            resource_sha1_set = set()
            resource_sha256_set = set()

            for res0 in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                for res1 in res0.directory.entries:
                    for res2 in res1.directory.entries:
                        lang = res2.data.lang
                        sub = res2.data.sublang
                        sub = pefile.get_sublang_name_for_lang(lang, sub)
                        data = pe.get_data(res2.data.struct.OffsetToData, res2.data.struct.Size)

                        resource_md5 = hashlib.md5(data).hexdigest()
                        resource_sha1 = hashlib.sha1(data).hexdigest()
                        resource_sha256 = hashlib.sha256(data).hexdigest()

                        resource_md5_set.add(resource_md5)
                        resource_sha1_set.add(resource_sha1)
                        resource_sha256_set.add(resource_sha256)

                        resource_dict = {
                            'id': res1.id,
                            'language': {
                                'sub': sub.replace('SUBLANG_', '')
                            },
                            'type': pefile.RESOURCE_TYPE.get(res0.id, '').replace('RT_', ''),
                            'md5': resource_md5,
                            'sha1': resource_sha1,
                            'sha256': resource_sha256,
                        }

                        if lang in pefile.LANG:
                            resource_dict['language']['primary'] = pefile.LANG[lang].replace('LANG_', '')

                        if res1.name:
                            resource_dict['name'] = str(res1.name)

                        self.event['resources'].append(resource_dict)

                        # TODO (swack) add option to enable / disable
                        # if len(data) > 0:
                        #     extract_file = strelka.File(
                        #         name=f'{resource_name or res1.id}',
                        #         source=f'{self.name}::Resource',
                        #     )
                        #     for c in strelka.chunk_string(data):
                        #         self.upload_to_coordinator(
                        #             extract_file.pointer,
                        #             c,
                        #             expire_at,
                        #         )
                        #     self.files.append(extract_file)

            self.event['summary']['resource_md5'] = list(resource_md5_set)
            self.event['summary']['resource_sha1'] = list(resource_sha1_set)
            self.event['summary']['resource_sha256'] = list(resource_sha256_set)

        self.event['total']['resources'] = len(self.event['resources'])

        self.event['sections'] = []
        section_md5_set = set()
        section_sha1_set = set()
        section_sha256_set = set()

        for sec in pe.sections:
            try:
                name = sec.Name.rstrip(b'\x00').decode()
                section_md5 = sec.get_hash_md5()
                section_sha1 = sec.get_hash_sha1()
                section_sha256 = sec.get_hash_sha256()

                section_md5_set.add(section_md5)
                section_sha1_set.add(section_sha1)
                section_sha256_set.add(section_sha256)

                row = {
                    'address': {
                        'physical': sec.Misc_PhysicalAddress,
                        'virtual': sec.VirtualAddress,
                    },
                    'characteristics': [],
                    'entropy': sec.get_entropy(),
                    'name': name,
                    'size': sec.SizeOfRawData,
                    'md5': section_md5,
                    'sha1': section_sha1,
                    'sha256': section_sha256,
                }
                for o in CHARACTERISTICS_SECTION:
                    if sec.Characteristics & o:
                        row['characteristics'].append(CHARACTERISTICS_SECTION[o])

                # TODO (swack) add option to enable / disable
                # if sec.SizeOfRawData > 0:
                #     extract_file = strelka.File(
                #         name=name,
                #         source=f'{self.name}::Section',
                #     )
                #     for c in strelka.chunk_string(sec.get_data()):
                #         self.upload_to_coordinator(
                #             extract_file.pointer,
                #             c,
                #             expire_at,
                #         )
                #     self.files.append(extract_file)

                self.event['sections'].append(row)
                self.event['summary']['section_md5'] = list(section_md5_set)
                self.event['summary']['section_sha1'] = list(section_sha1_set)
                self.event['summary']['section_sha256'] = list(section_sha256_set)
            except Exception as e:
                self.flags.append(f"exception thrown when parsing section's {e}")

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
            self.event['dll_name'] = pe.DIRECTORY_ENTRY_EXPORT.name
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

        # TODO (swack) add option to enable / disable
        # security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
        # sec_addr = security.VirtualAddress
        #
        # if security.Size > 0:
        #     data = pe.write()[sec_addr + 8:]
        #
        #     if len(data) > 0:
        #         self.flags.append('signed')
        #
        #         extract_file = strelka.File(
        #             name='signature',
        #             source=f'{self.name}::Security',
        #         )
        #         for c in strelka.chunk_string(data):
        #             self.upload_to_coordinator(
        #                 extract_file.pointer,
        #                 c,
        #                 expire_at,
        #             )
        #         self.files.append(extract_file)