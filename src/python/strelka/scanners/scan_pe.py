import hashlib
import tempfile

from boltons import setutils
from lief import PE
import pefile

from strelka import strelka


IMPHASH = {
    'ws2_32': {
        1: 'accept',
        2: 'bind',
        3: 'closesocket',
        4: 'connect',
        5: 'getpeername',
        6: 'getsockname',
        7: 'getsockopt',
        8: 'htonl',
        9: 'htons',
        10: 'ioctlsocket',
        11: 'inet_addr',
        12: 'inet_ntoa',
        13: 'listen',
        14: 'ntohl',
        15: 'ntohs',
        16: 'recv',
        17: 'recvfrom',
        18: 'select',
        19: 'send',
        20: 'sendto',
        21: 'setsockopt',
        22: 'shutdown',
        23: 'socket',
        24: 'GetAddrInfoW',
        25: 'GetNameInfoW',
        26: 'WSApSetPostRoutine',
        27: 'FreeAddrInfoW',
        28: 'WPUCompleteOverlappedRequest',
        29: 'WSAAccept',
        30: 'WSAAddressToStringA',
        31: 'WSAAddressToStringW',
        32: 'WSACloseEvent',
        33: 'WSAConnect',
        34: 'WSACreateEvent',
        35: 'WSADuplicateSocketA',
        36: 'WSADuplicateSocketW',
        37: 'WSAEnumNameSpaceProvidersA',
        38: 'WSAEnumNameSpaceProvidersW',
        39: 'WSAEnumNetworkEvents',
        40: 'WSAEnumProtocolsA',
        41: 'WSAEnumProtocolsW',
        42: 'WSAEventSelect',
        43: 'WSAGetOverlappedResult',
        44: 'WSAGetQOSByName',
        45: 'WSAGetServiceClassInfoA',
        46: 'WSAGetServiceClassInfoW',
        47: 'WSAGetServiceClassNameByClassIdA',
        48: 'WSAGetServiceClassNameByClassIdW',
        49: 'WSAHtonl',
        50: 'WSAHtons',
        51: 'gethostbyaddr',
        52: 'gethostbyname',
        53: 'getprotobyname',
        54: 'getprotobynumber',
        55: 'getservbyname',
        56: 'getservbyport',
        57: 'gethostname',
        58: 'WSAInstallServiceClassA',
        59: 'WSAInstallServiceClassW',
        60: 'WSAIoctl',
        61: 'WSAJoinLeaf',
        62: 'WSALookupServiceBeginA',
        63: 'WSALookupServiceBeginW',
        64: 'WSALookupServiceEnd',
        65: 'WSALookupServiceNextA',
        66: 'WSALookupServiceNextW',
        67: 'WSANSPIoctl',
        68: 'WSANtohl',
        69: 'WSANtohs',
        70: 'WSAProviderConfigChange',
        71: 'WSARecv',
        72: 'WSARecvDisconnect',
        73: 'WSARecvFrom',
        74: 'WSARemoveServiceClass',
        75: 'WSAResetEvent',
        76: 'WSASend',
        77: 'WSASendDisconnect',
        78: 'WSASendTo',
        79: 'WSASetEvent',
        80: 'WSASetServiceA',
        81: 'WSASetServiceW',
        82: 'WSASocketA',
        83: 'WSASocketW',
        84: 'WSAStringToAddressA',
        85: 'WSAStringToAddressW',
        86: 'WSAWaitForMultipleEvents',
        87: 'WSCDeinstallProvider',
        88: 'WSCEnableNSProvider',
        89: 'WSCEnumProtocols',
        90: 'WSCGetProviderPath',
        91: 'WSCInstallNameSpace',
        92: 'WSCInstallProvider',
        93: 'WSCUnInstallNameSpace',
        94: 'WSCUpdateProvider',
        95: 'WSCWriteNameSpaceOrder',
        96: 'WSCWriteProviderOrder',
        97: 'freeaddrinfo',
        98: 'getaddrinfo',
        99: 'getnameinfo',
        101: 'WSAAsyncSelect',
        102: 'WSAAsyncGetHostByAddr',
        103: 'WSAAsyncGetHostByName',
        104: 'WSAAsyncGetProtoByNumber',
        105: 'WSAAsyncGetProtoByName',
        106: 'WSAAsyncGetServByPort',
        107: 'WSAAsyncGetServByName',
        108: 'WSACancelAsyncRequest',
        109: 'WSASetBlockingHook',
        110: 'WSAUnhookBlockingHook',
        111: 'WSAGetLastError',
        112: 'WSASetLastError',
        113: 'WSACancelBlockingCall',
        114: 'WSAIsBlocking',
        115: 'WSAStartup',
        116: 'WSACleanup',
        151: '__WSAFDIsSet',
        500: 'WEP',
    },
    'wsock32': {
        1: 'accept',
        2: 'bind',
        3: 'closesocket',
        4: 'connect',
        5: 'getpeername',
        6: 'getsockname',
        7: 'getsockopt',
        8: 'htonl',
        9: 'htons',
        10: 'ioctlsocket',
        11: 'inet_addr',
        12: 'inet_ntoa',
        13: 'listen',
        14: 'ntohl',
        15: 'ntohs',
        16: 'recv',
        17: 'recvfrom',
        18: 'select',
        19: 'send',
        20: 'sendto',
        21: 'setsockopt',
        22: 'shutdown',
        23: 'socket',
        24: 'GetAddrInfoW',
        25: 'GetNameInfoW',
        26: 'WSApSetPostRoutine',
        27: 'FreeAddrInfoW',
        28: 'WPUCompleteOverlappedRequest',
        29: 'WSAAccept',
        30: 'WSAAddressToStringA',
        31: 'WSAAddressToStringW',
        32: 'WSACloseEvent',
        33: 'WSAConnect',
        34: 'WSACreateEvent',
        35: 'WSADuplicateSocketA',
        36: 'WSADuplicateSocketW',
        37: 'WSAEnumNameSpaceProvidersA',
        38: 'WSAEnumNameSpaceProvidersW',
        39: 'WSAEnumNetworkEvents',
        40: 'WSAEnumProtocolsA',
        41: 'WSAEnumProtocolsW',
        42: 'WSAEventSelect',
        43: 'WSAGetOverlappedResult',
        44: 'WSAGetQOSByName',
        45: 'WSAGetServiceClassInfoA',
        46: 'WSAGetServiceClassInfoW',
        47: 'WSAGetServiceClassNameByClassIdA',
        48: 'WSAGetServiceClassNameByClassIdW',
        49: 'WSAHtonl',
        50: 'WSAHtons',
        51: 'gethostbyaddr',
        52: 'gethostbyname',
        53: 'getprotobyname',
        54: 'getprotobynumber',
        55: 'getservbyname',
        56: 'getservbyport',
        57: 'gethostname',
        58: 'WSAInstallServiceClassA',
        59: 'WSAInstallServiceClassW',
        60: 'WSAIoctl',
        61: 'WSAJoinLeaf',
        62: 'WSALookupServiceBeginA',
        63: 'WSALookupServiceBeginW',
        64: 'WSALookupServiceEnd',
        65: 'WSALookupServiceNextA',
        66: 'WSALookupServiceNextW',
        67: 'WSANSPIoctl',
        68: 'WSANtohl',
        69: 'WSANtohs',
        70: 'WSAProviderConfigChange',
        71: 'WSARecv',
        72: 'WSARecvDisconnect',
        73: 'WSARecvFrom',
        74: 'WSARemoveServiceClass',
        75: 'WSAResetEvent',
        76: 'WSASend',
        77: 'WSASendDisconnect',
        78: 'WSASendTo',
        79: 'WSASetEvent',
        80: 'WSASetServiceA',
        81: 'WSASetServiceW',
        82: 'WSASocketA',
        83: 'WSASocketW',
        84: 'WSAStringToAddressA',
        85: 'WSAStringToAddressW',
        86: 'WSAWaitForMultipleEvents',
        87: 'WSCDeinstallProvider',
        88: 'WSCEnableNSProvider',
        89: 'WSCEnumProtocols',
        90: 'WSCGetProviderPath',
        91: 'WSCInstallNameSpace',
        92: 'WSCInstallProvider',
        93: 'WSCUnInstallNameSpace',
        94: 'WSCUpdateProvider',
        95: 'WSCWriteNameSpaceOrder',
        96: 'WSCWriteProviderOrder',
        97: 'freeaddrinfo',
        98: 'getaddrinfo',
        99: 'getnameinfo',
        101: 'WSAAsyncSelect',
        102: 'WSAAsyncGetHostByAddr',
        103: 'WSAAsyncGetHostByName',
        104: 'WSAAsyncGetProtoByNumber',
        105: 'WSAAsyncGetProtoByName',
        106: 'WSAAsyncGetServByPort',
        107: 'WSAAsyncGetServByName',
        108: 'WSACancelAsyncRequest',
        109: 'WSASetBlockingHook',
        110: 'WSAUnhookBlockingHook',
        111: 'WSAGetLastError',
        112: 'WSASetLastError',
        113: 'WSACancelBlockingCall',
        114: 'WSAIsBlocking',
        115: 'WSAStartup',
        116: 'WSACleanup',
        151: '__WSAFDIsSet',
        500: 'WEP',
    },
    'oleaut32': {
        2: 'SysAllocString',
        3: 'SysReAllocString',
        4: 'SysAllocStringLen',
        5: 'SysReAllocStringLen',
        6: 'SysFreeString',
        7: 'SysStringLen',
        8: 'VariantInit',
        9: 'VariantClear',
        10: 'VariantCopy',
        11: 'VariantCopyInd',
        12: 'VariantChangeType',
        13: 'VariantTimeToDosDateTime',
        14: 'DosDateTimeToVariantTime',
        15: 'SafeArrayCreate',
        16: 'SafeArrayDestroy',
        17: 'SafeArrayGetDim',
        18: 'SafeArrayGetElemsize',
        19: 'SafeArrayGetUBound',
        20: 'SafeArrayGetLBound',
        21: 'SafeArrayLock',
        22: 'SafeArrayUnlock',
        23: 'SafeArrayAccessData',
        24: 'SafeArrayUnaccessData',
        25: 'SafeArrayGetElement',
        26: 'SafeArrayPutElement',
        27: 'SafeArrayCopy',
        28: 'DispGetParam',
        29: 'DispGetIDsOfNames',
        30: 'DispInvoke',
        31: 'CreateDispTypeInfo',
        32: 'CreateStdDispatch',
        33: 'RegisterActiveObject',
        34: 'RevokeActiveObject',
        35: 'GetActiveObject',
        36: 'SafeArrayAllocDescriptor',
        37: 'SafeArrayAllocData',
        38: 'SafeArrayDestroyDescriptor',
        39: 'SafeArrayDestroyData',
        40: 'SafeArrayRedim',
        41: 'SafeArrayAllocDescriptorEx',
        42: 'SafeArrayCreateEx',
        43: 'SafeArrayCreateVectorEx',
        44: 'SafeArraySetRecordInfo',
        45: 'SafeArrayGetRecordInfo',
        46: 'VarParseNumFromStr',
        47: 'VarNumFromParseNum',
        48: 'VarI2FromUI1',
        49: 'VarI2FromI4',
        50: 'VarI2FromR4',
        51: 'VarI2FromR8',
        52: 'VarI2FromCy',
        53: 'VarI2FromDate',
        54: 'VarI2FromStr',
        55: 'VarI2FromDisp',
        56: 'VarI2FromBool',
        57: 'SafeArraySetIID',
        58: 'VarI4FromUI1',
        59: 'VarI4FromI2',
        60: 'VarI4FromR4',
        61: 'VarI4FromR8',
        62: 'VarI4FromCy',
        63: 'VarI4FromDate',
        64: 'VarI4FromStr',
        65: 'VarI4FromDisp',
        66: 'VarI4FromBool',
        67: 'SafeArrayGetIID',
        68: 'VarR4FromUI1',
        69: 'VarR4FromI2',
        70: 'VarR4FromI4',
        71: 'VarR4FromR8',
        72: 'VarR4FromCy',
        73: 'VarR4FromDate',
        74: 'VarR4FromStr',
        75: 'VarR4FromDisp',
        76: 'VarR4FromBool',
        77: 'SafeArrayGetVartype',
        78: 'VarR8FromUI1',
        79: 'VarR8FromI2',
        80: 'VarR8FromI4',
        81: 'VarR8FromR4',
        82: 'VarR8FromCy',
        83: 'VarR8FromDate',
        84: 'VarR8FromStr',
        85: 'VarR8FromDisp',
        86: 'VarR8FromBool',
        87: 'VarFormat',
        88: 'VarDateFromUI1',
        89: 'VarDateFromI2',
        90: 'VarDateFromI4',
        91: 'VarDateFromR4',
        92: 'VarDateFromR8',
        93: 'VarDateFromCy',
        94: 'VarDateFromStr',
        95: 'VarDateFromDisp',
        96: 'VarDateFromBool',
        97: 'VarFormatDateTime',
        98: 'VarCyFromUI1',
        99: 'VarCyFromI2',
        100: 'VarCyFromI4',
        101: 'VarCyFromR4',
        102: 'VarCyFromR8',
        103: 'VarCyFromDate',
        104: 'VarCyFromStr',
        105: 'VarCyFromDisp',
        106: 'VarCyFromBool',
        107: 'VarFormatNumber',
        108: 'VarBstrFromUI1',
        109: 'VarBstrFromI2',
        110: 'VarBstrFromI4',
        111: 'VarBstrFromR4',
        112: 'VarBstrFromR8',
        113: 'VarBstrFromCy',
        114: 'VarBstrFromDate',
        115: 'VarBstrFromDisp',
        116: 'VarBstrFromBool',
        117: 'VarFormatPercent',
        118: 'VarBoolFromUI1',
        119: 'VarBoolFromI2',
        120: 'VarBoolFromI4',
        121: 'VarBoolFromR4',
        122: 'VarBoolFromR8',
        123: 'VarBoolFromDate',
        124: 'VarBoolFromCy',
        125: 'VarBoolFromStr',
        126: 'VarBoolFromDisp',
        127: 'VarFormatCurrency',
        128: 'VarWeekdayName',
        129: 'VarMonthName',
        130: 'VarUI1FromI2',
        131: 'VarUI1FromI4',
        132: 'VarUI1FromR4',
        133: 'VarUI1FromR8',
        134: 'VarUI1FromCy',
        135: 'VarUI1FromDate',
        136: 'VarUI1FromStr',
        137: 'VarUI1FromDisp',
        138: 'VarUI1FromBool',
        139: 'VarFormatFromTokens',
        140: 'VarTokenizeFormatString',
        141: 'VarAdd',
        142: 'VarAnd',
        143: 'VarDiv',
        144: 'DllCanUnloadNow',
        145: 'DllGetClassObject',
        146: 'DispCallFunc',
        147: 'VariantChangeTypeEx',
        148: 'SafeArrayPtrOfIndex',
        149: 'SysStringByteLen',
        150: 'SysAllocStringByteLen',
        151: 'DllRegisterServer',
        152: 'VarEqv',
        153: 'VarIdiv',
        154: 'VarImp',
        155: 'VarMod',
        156: 'VarMul',
        157: 'VarOr',
        158: 'VarPow',
        159: 'VarSu',
        160: 'CreateTypeLi',
        161: 'LoadTypeLi',
        162: 'LoadRegTypeLi',
        163: 'RegisterTypeLi',
        164: 'QueryPathOfRegTypeLi',
        165: 'LHashValOfNameSys',
        166: 'LHashValOfNameSysA',
        167: 'VarXor',
        168: 'VarAbs',
        169: 'VarFix',
        170: 'OaBuildVersion',
        171: 'ClearCustData',
        172: 'VarInt',
        173: 'VarNeg',
        174: 'VarNot',
        175: 'VarRound',
        176: 'VarCmp',
        177: 'VarDecAdd',
        178: 'VarDecDiv',
        179: 'VarDecMul',
        180: 'CreateTypeLib2',
        181: 'VarDecSu',
        182: 'VarDecAbs',
        183: 'LoadTypeLibEx',
        184: 'SystemTimeToVariantTime',
        185: 'VariantTimeToSystemTime',
        186: 'UnRegisterTypeLi',
        187: 'VarDecFix',
        188: 'VarDecInt',
        189: 'VarDecNeg',
        190: 'VarDecFromUI1',
        191: 'VarDecFromI2',
        192: 'VarDecFromI4',
        193: 'VarDecFromR4',
        194: 'VarDecFromR8',
        195: 'VarDecFromDate',
        196: 'VarDecFromCy',
        197: 'VarDecFromStr',
        198: 'VarDecFromDisp',
        199: 'VarDecFromBool',
        200: 'GetErrorInfo',
        201: 'SetErrorInfo',
        202: 'CreateErrorInfo',
        203: 'VarDecRound',
        204: 'VarDecCmp',
        205: 'VarI2FromI1',
        206: 'VarI2FromUI2',
        207: 'VarI2FromUI4',
        208: 'VarI2FromDec',
        209: 'VarI4FromI1',
        210: 'VarI4FromUI2',
        211: 'VarI4FromUI4',
        212: 'VarI4FromDec',
        213: 'VarR4FromI1',
        214: 'VarR4FromUI2',
        215: 'VarR4FromUI4',
        216: 'VarR4FromDec',
        217: 'VarR8FromI1',
        218: 'VarR8FromUI2',
        219: 'VarR8FromUI4',
        220: 'VarR8FromDec',
        221: 'VarDateFromI1',
        222: 'VarDateFromUI2',
        223: 'VarDateFromUI4',
        224: 'VarDateFromDec',
        225: 'VarCyFromI1',
        226: 'VarCyFromUI2',
        227: 'VarCyFromUI4',
        228: 'VarCyFromDec',
        229: 'VarBstrFromI1',
        230: 'VarBstrFromUI2',
        231: 'VarBstrFromUI4',
        232: 'VarBstrFromDec',
        233: 'VarBoolFromI1',
        234: 'VarBoolFromUI2',
        235: 'VarBoolFromUI4',
        236: 'VarBoolFromDec',
        237: 'VarUI1FromI1',
        238: 'VarUI1FromUI2',
        239: 'VarUI1FromUI4',
        240: 'VarUI1FromDec',
        241: 'VarDecFromI1',
        242: 'VarDecFromUI2',
        243: 'VarDecFromUI4',
        244: 'VarI1FromUI1',
        245: 'VarI1FromI2',
        246: 'VarI1FromI4',
        247: 'VarI1FromR4',
        248: 'VarI1FromR8',
        249: 'VarI1FromDate',
        250: 'VarI1FromCy',
        251: 'VarI1FromStr',
        252: 'VarI1FromDisp',
        253: 'VarI1FromBool',
        254: 'VarI1FromUI2',
        255: 'VarI1FromUI4',
        256: 'VarI1FromDec',
        257: 'VarUI2FromUI1',
        258: 'VarUI2FromI2',
        259: 'VarUI2FromI4',
        260: 'VarUI2FromR4',
        261: 'VarUI2FromR8',
        262: 'VarUI2FromDate',
        263: 'VarUI2FromCy',
        264: 'VarUI2FromStr',
        265: 'VarUI2FromDisp',
        266: 'VarUI2FromBool',
        267: 'VarUI2FromI1',
        268: 'VarUI2FromUI4',
        269: 'VarUI2FromDec',
        270: 'VarUI4FromUI1',
        271: 'VarUI4FromI2',
        272: 'VarUI4FromI4',
        273: 'VarUI4FromR4',
        274: 'VarUI4FromR8',
        275: 'VarUI4FromDate',
        276: 'VarUI4FromCy',
        277: 'VarUI4FromStr',
        278: 'VarUI4FromDisp',
        279: 'VarUI4FromBool',
        280: 'VarUI4FromI1',
        281: 'VarUI4FromUI2',
        282: 'VarUI4FromDec',
        283: 'BSTR_UserSize',
        284: 'BSTR_UserMarshal',
        285: 'BSTR_UserUnmarshal',
        286: 'BSTR_UserFree',
        287: 'VARIANT_UserSize',
        288: 'VARIANT_UserMarshal',
        289: 'VARIANT_UserUnmarshal',
        290: 'VARIANT_UserFree',
        291: 'LPSAFEARRAY_UserSize',
        292: 'LPSAFEARRAY_UserMarshal',
        293: 'LPSAFEARRAY_UserUnmarshal',
        294: 'LPSAFEARRAY_UserFree',
        295: 'LPSAFEARRAY_Size',
        296: 'LPSAFEARRAY_Marshal',
        297: 'LPSAFEARRAY_Unmarshal',
        298: 'VarDecCmpR8',
        299: 'VarCyAdd',
        300: 'DllUnregisterServer',
        301: 'OACreateTypeLib2',
        303: 'VarCyMul',
        304: 'VarCyMulI4',
        305: 'VarCySu',
        306: 'VarCyAbs',
        307: 'VarCyFix',
        308: 'VarCyInt',
        309: 'VarCyNeg',
        310: 'VarCyRound',
        311: 'VarCyCmp',
        312: 'VarCyCmpR8',
        313: 'VarBstrCat',
        314: 'VarBstrCmp',
        315: 'VarR8Pow',
        316: 'VarR4CmpR8',
        317: 'VarR8Round',
        318: 'VarCat',
        319: 'VarDateFromUdateEx',
        322: 'GetRecordInfoFromGuids',
        323: 'GetRecordInfoFromTypeInfo',
        325: 'SetVarConversionLocaleSetting',
        326: 'GetVarConversionLocaleSetting',
        327: 'SetOaNoCache',
        329: 'VarCyMulI8',
        330: 'VarDateFromUdate',
        331: 'VarUdateFromDate',
        332: 'GetAltMonthNames',
        333: 'VarI8FromUI1',
        334: 'VarI8FromI2',
        335: 'VarI8FromR4',
        336: 'VarI8FromR8',
        337: 'VarI8FromCy',
        338: 'VarI8FromDate',
        339: 'VarI8FromStr',
        340: 'VarI8FromDisp',
        341: 'VarI8FromBool',
        342: 'VarI8FromI1',
        343: 'VarI8FromUI2',
        344: 'VarI8FromUI4',
        345: 'VarI8FromDec',
        346: 'VarI2FromI8',
        347: 'VarI2FromUI8',
        348: 'VarI4FromI8',
        349: 'VarI4FromUI8',
        360: 'VarR4FromI8',
        361: 'VarR4FromUI8',
        362: 'VarR8FromI8',
        363: 'VarR8FromUI8',
        364: 'VarDateFromI8',
        365: 'VarDateFromUI8',
        366: 'VarCyFromI8',
        367: 'VarCyFromUI8',
        368: 'VarBstrFromI8',
        369: 'VarBstrFromUI8',
        370: 'VarBoolFromI8',
        371: 'VarBoolFromUI8',
        372: 'VarUI1FromI8',
        373: 'VarUI1FromUI8',
        374: 'VarDecFromI8',
        375: 'VarDecFromUI8',
        376: 'VarI1FromI8',
        377: 'VarI1FromUI8',
        378: 'VarUI2FromI8',
        379: 'VarUI2FromUI8',
        401: 'OleLoadPictureEx',
        402: 'OleLoadPictureFileEx',
        411: 'SafeArrayCreateVector',
        412: 'SafeArrayCopyData',
        413: 'VectorFromBstr',
        414: 'BstrFromVector',
        415: 'OleIconToCursor',
        416: 'OleCreatePropertyFrameIndirect',
        417: 'OleCreatePropertyFrame',
        418: 'OleLoadPicture',
        419: 'OleCreatePictureIndirect',
        420: 'OleCreateFontIndirect',
        421: 'OleTranslateColor',
        422: 'OleLoadPictureFile',
        423: 'OleSavePictureFile',
        424: 'OleLoadPicturePath',
        425: 'VarUI4FromI8',
        426: 'VarUI4FromUI8',
        427: 'VarI8FromUI8',
        428: 'VarUI8FromI8',
        429: 'VarUI8FromUI1',
        430: 'VarUI8FromI2',
        431: 'VarUI8FromR4',
        432: 'VarUI8FromR8',
        433: 'VarUI8FromCy',
        434: 'VarUI8FromDate',
        435: 'VarUI8FromStr',
        436: 'VarUI8FromDisp',
        437: 'VarUI8FromBool',
        438: 'VarUI8FromI1',
        439: 'VarUI8FromUI2',
        440: 'VarUI8FromUI4',
        441: 'VarUI8FromDec',
        442: 'RegisterTypeLibForUser',
        443: 'UnRegisterTypeLibForUser',
    },
}


class ScanPe(strelka.Scanner):
    """Collects metadata from PE files."""
    def scan(self, data, file, options, expire_at):
        tmp_directory = options.get('tmp_directory', '/tmp/')

        exe = PE.parse(raw=data)

        self.event['total'] = {
            'debugs': len(exe.debug),
            'directories': exe.optional_header.numberof_rva_and_size,
            'libraries': len(exe.libraries),
            'sections': exe.header.numberof_sections,
            'symbols': exe.header.numberof_symbols,
        }

        self.event['entrypoint'] = exe.entrypoint
        self.event['nx'] = exe.has_nx
        self.event['pie'] = exe.is_pie

        self.event['header'] = {
            'address': {
                'code': exe.optional_header.baseof_code,
                'data': exe.optional_header.baseof_data,
                'image': exe.optional_header.imagebase,
            },
            'alignment': {
                'file': exe.optional_header.file_alignment,
                'section': exe.optional_header.section_alignment,
            },
            'characteristics': {
                'dll': [str(d).split('.')[1] for d in exe.optional_header.dll_characteristics_lists],
                'image': [str(c).split('.')[1] for c in exe.header.characteristics_list],
            },
            'checksum': exe.optional_header.checksum,
            'machine': str(exe.header.machine).split('.')[1],
            'magic': str(exe.optional_header.magic).split('.')[1],
            'size': {
                'code': exe.optional_header.sizeof_code,
                'data': {
                    'initialized': exe.optional_header.sizeof_initialized_data,
                    'uninitialized': exe.optional_header.sizeof_uninitialized_data,
                },
                'headers': exe.optional_header.sizeof_headers,
                'heap': {
                    'reserve': exe.optional_header.sizeof_heap_reserve,
                    'commit': exe.optional_header.sizeof_heap_commit,
                },
                'image': exe.optional_header.sizeof_image,
                'stack': {
                    'commit': exe.optional_header.sizeof_stack_commit,
                    'reserve': exe.optional_header.sizeof_stack_reserve,
                },
            },
            'subsystem': str(exe.optional_header.subsystem).split('.')[1],
            'timestamp': exe.header.time_date_stamps,
            'version': {
                'image': f'{exe.optional_header.major_image_version}.{exe.optional_header.minor_image_version}',
                'linker': f'{exe.optional_header.major_linker_version}.{exe.optional_header.minor_linker_version}',
                'operating_system': f'{exe.optional_header.major_operating_system_version}.{exe.optional_header.minor_operating_system_version}',
                'subsystem': f'{exe.optional_header.major_subsystem_version}.{exe.optional_header.minor_subsystem_version}',
            },
        }

        # mimics the pefile imphash calculation
        # per @williballenthin, this is the official implementation of the spec
        imphash_imports = []
        for imp in exe.imports:
            imp_name = imp.name.lower()
            p = imp_name.rsplit('.', 1)
            if len(p) > 1 and p[1] in ['ocx', 'sys', 'dll']:
                imp_name = p[0]

            for entry in imp.entries:
                if entry.is_ordinal:
                    ord_name = IMPHASH.get(imp_name, {}).get(entry.ordinal, None)
                    if ord_name:
                        imphash_imports.append(f'{imp_name}.{ord_name.lower()}')
                    else:
                        imphash_imports.append(f'{imp_name}.ord{entry.ordinal}')
                else:
                    imphash_imports.append(f'{imp_name}.{entry.name.lower()}')

        self.event['imphash'] = hashlib.md5(','.join(imphash_imports).encode()).hexdigest()

        self.event['functions'] = {
            'exported': [e.name for e in exe.exported_functions],
            'imported': [i.name for i in exe.imported_functions],
            'libraries': list(setutils.IndexedSet(exe.libraries)),
            'table': [],
        }

        if exe.has_imports:
            for i in exe.imports:
                row = {
                    'library': i.name,
                    'rva': {
                        'address': i.import_address_table_rva,
                        'lookup': i.import_lookup_table_rva,
                    }
                }

                row['functions'] = []
                for e in i.entries:
                    if e.is_ordinal:
                        row['functions'].append(f'ord{e.ordinal}')
                    else:
                        row['functions'].append(e.name)
                self.event['functions']['table'].append(row)

        resources = {
            'dialogs': [],
            'icons': [],
            'file_info': {},
            'languages': {
                'primary': [str(l).rsplit('.')[1] for l in exe.resources_manager.langs_available],
                'secondary': [str(s).rsplit('.')[1] for s in exe.resources_manager.sublangs_available],
            },
            'types': [str(t).rsplit('.')[1] for t in exe.resources_manager.types_available]
        }

        if exe.resources_manager.has_dialogs:
            self.event['total']['dialogs'] = len(exe.resources_manager.dialogs)
            for d in exe.resources_manager.dialogs:
                resources['dialogs'].append({
                    'character_set': d.charset,
                    'font': {
                        'size': d.point_size,
                        'typeface': d.typeface,
                        'weight': d.weight,
                    },
                    'height': d.cy,
                    'help_id': d.help_id,
                    'language': {
                        'primary': str(d.lang).split('.')[1],
                        'secondary': str(d.sub_lang).split('.')[1],
                    },
                    'signature': d.signature,
                    'styles': {
                        'dialog_box': [str(s).split('.')[1] for s in d.dialogbox_style_list],
                        'extended_window': [str(s).split('.')[1] for s in d.extended_style_list],
                        'window': [str(s).split('.')[1] for s in d.style_list],
                    },
                    'title': d.title,
                    'width': d.cx,
                })

        if exe.resources_manager.has_icons:
            self.event['total']['icons'] = len(exe.resources_manager.icons)
            for i in exe.resources_manager.icons:
                resources['icons'].append({
                    'count': {
                        'bit': i.bit_count,
                        'color': i.color_count,
                    },
                    'height': i.height,
                    'id': i.id,
                    'language': {
                        'primary': str(i.lang).split('.')[1],
                        'secondary': str(i.sublang).split('.')[1],
                    },
                    'width': i.width,
                })

                with tempfile.NamedTemporaryFile(dir=tmp_directory) as tmp_data:
                    i.save(tmp_data.name)
                    tmp_data.flush()

                    with open(tmp_data.name, 'rb') as f:
                        extract_file = strelka.File(
                            name=f'icon_{i.id}',
                            source=self.name,
                        )

                        for c in strelka.chunk_string(f.read()):
                            self.upload_to_coordinator(
                                extract_file.pointer,
                                c,
                                expire_at,
                            )

                        self.files.append(extract_file)

        if exe.resources_manager.has_version:
            if exe.resources_manager.version.has_fixed_file_info:
                ffi = exe.resources_manager.version.fixed_file_info
                resources['file_info']['fixed'] = {
                    'function': str(ffi.file_subtype).split('.')[1],
                    'operating_system': str(ffi.file_os).split('.')[1],
                    'type': str(ffi.file_type).split('.')[1],
                }
            if exe.resources_manager.version.has_string_file_info:
                sfi = exe.resources_manager.version.string_file_info
                string_info = []
                for i in sfi.langcode_items:
                    info = {
                        'code_page': str(i.code_page).split('.')[1],
                        'items': [],
                        'language': {
                            'primary': str(i.lang).split('.')[1],
                            'secondary': str(i.sublang).split('.')[1],
                        },
                    }

                    for k, v in i.items.items():
                        info['items'].append({
                            'name': k,
                            'value': v,
                        })
                    string_info.append(info)
                resources['file_info']['string'] = string_info
        self.event['resources'] = resources

        if exe.resources_manager.has_manifest:
            extract_file = strelka.File(
                name='manifest',
                source=self.name,
            )

            for c in strelka.chunk_string(exe.resources_manager.manifest):
                self.upload_to_coordinator(
                    extract_file.pointer,
                    c,
                    expire_at,
                )

            self.files.append(extract_file)

        self.event['debug'] = []
        if exe.has_debug:
            for d in exe.debug:
                row = {
                    'address': d.addressof_rawdata,
                    'offset': d.pointerto_rawdata,
                    'timestamp': d.timestamp,
                    'type': str(d.type).split('.')[1],
                    'version': f'{d.major_version}.{d.minor_version}',
                }

                if d.has_code_view:
                    cv = d.code_view
                    row['code_view'] = {
                        'age': cv.age,
                        'path': cv.filename,
                        'type': str(cv.cv_signature).split('.')[1],
                    }
                self.event['debug'].append(row)

        self.event['sections'] = []
        for s in exe.sections:
            section = {
                'address': {
                    'virtual': s.virtual_address,
                },
                'characteristics': [str(c).split('.')[1] for c in s.characteristics_lists],
                'entropy': s.entropy,
                'name': s.name,
                'offset': s.offset,
                'size': s.size,
                'size': {
                    'raw': s.size,
                    'virtual': s.virtual_size,
                },
            }
            self.event['sections'].append(section)

        if exe.has_tls:
            self.event['tls'] = {
                'address': {
                    'callbacks': exe.tls.addressof_callbacks,
                    'data': {
                        'start': exe.tls.addressof_raw_data[0],
                        'end': exe.tls.addressof_raw_data[1],
                    },
                    'index': exe.tls.addressof_index,
                },
                'callbacks': exe.tls.callbacks,
            }

            if exe.tls.has_section:
                self.event['tls']['section'] = exe.tls.section.name

        try:
            pe = pefile.PE(data=data, fast_load=True)
            security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
            security_address = security.VirtualAddress
            if security.Size > 0:
                extract_data = pe.write()[security_address + 8:]
                if len(extract_data) > 0:
                    extract_file = strelka.File(
                        name='digital_signature',
                        source=self.name,
                    )
                    for c in strelka.chunk_string(extract_data):
                        self.upload_to_coordinator(
                            extract_file.pointer,
                            c,
                            expire_at,
                        )
                    self.files.append(extract_file)

        except pefile.PEFormatError:
            self.flags.append('pe_format_error')
