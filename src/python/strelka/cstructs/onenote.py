# Authors: Ryan Borre

from construct import this, Struct, BitStruct, Enum, Bytes, Int8ul, Int32ul, Int64ul, BitsInteger

FileNodeHeader = "FileNodeHeader" / Struct(
    "guidFileType" / Bytes(16),
    "guidFile" / Bytes(16),
    "guidLegacyFileVersion" / Bytes(16),
    "guidFileFormat" / Bytes(16),
    "ffvLastCodeThatWroteToThisFile" / Enum(Int32ul,
                                            one=0x0000002a,
                                            onetoc2=0x0000001b
                                            ),
    "ffvOldestCodeThatHasWrittenToThisFile" / Enum(Int32ul,
                                                   one=0x0000002a,
                                                   onetoc2=0x0000001b
                                                   ),
    "ffvNewestCodeThatHasWrittenToThisFile" / Enum(Int32ul,
                                                   one=0x0000002a,
                                                   onetoc2=0x0000001b
                                                   ),
    "ffvOldestCodeThatMayReadThisFile" / Enum(Int32ul,
                                              one=0x0000002a,
                                              onetoc2=0x0000001b
                                              ),
    "fcrLegacyFreeChunkList" / Struct(
        "stp" / Int32ul,
        "cb" / Int32ul
    ),
    "fcrLegacyTransactionLog" / Struct(
        "stp" / Int32ul,
        "cb" / Int32ul
    ),
    "cTransactionsInLog" / Int32ul,
    "cbLegacyExpectedFileLength" / Int32ul,
    "rgbPlaceholder" / Int64ul,
    "fcrLegacyFileNodeListRoot" / Struct(
        "stp" / Int32ul,
        "cb" / Int32ul
    ),
    "cbLegacyFreeSpaceInFreeChunkList" / Int32ul,
    "fNeedsDefrag" / Int8ul,
    "fRepairedFile" / Int8ul,
    "fNeedsGarbageCollect" / Int8ul,
    "fHasNoEmbeddedFileObjects" / Int8ul,
    "guidAncestor" / Bytes(16),
    "crcName" / Int32ul,
    "fcrHashedChunkList" / Struct(
        "stp" / Int64ul,
        "cb" / Int32ul
    ),
    "fcrTransactionLog" / Struct(
        "stp" / Int64ul,
        "cb" / Int32ul
    ),
    "fcrFileNodeListRoot" / Struct(
        "stp" / Int64ul,
        "cb" / Int32ul
    ),
    "fcrFreeChunkList" / Struct(
        "stp" / Int64ul,
        "cb" / Int32ul
    ),
    "cbExpectedFileLength" / Int64ul,
    "cbFreeSpaceInFreeChunkList" / Int64ul,
    "guidFileVersion" / Bytes(16),
    "nFileVersionGeneration" / Int64ul,
    "guidDenyReadFileVersion" / Bytes(16),
    "grfDebugLogFlags" / Int32ul,
    "fcrDebugLog" / Struct(
        "stp" / Int64ul,
        "cb" / Int32ul
    ),
    "fcrAllocVerificationFreeChunkList" / Bytes(12),
    "bnCreated" / Int32ul,
    "bnLastWroteToThisFile" / Int32ul,
    "bnOldestWritten" / Int32ul,
    "bnNewestWritten" / Int32ul,
    "rgbReserved" / Bytes(728),
)


FileNodeListFragment = "FileNodeListFragment" / Struct(
    "FileNodeListHeader" / Struct(
            "uintMagic" / Int64ul,
            "FileNodeListID" / Int32ul,
            "nFragmentSequence" / Int32ul
    ),

    "FileNode" / BitStruct(
            "FileNodeID" / BitsInteger(10),
            "Size" / BitsInteger(13),
            "StpFormat" / BitsInteger(2),
            "CbFormat" / BitsInteger(2),
            "BaseType" / BitsInteger(4),
            "Reserved" / BitsInteger(1)
    ),
    "nextFragment" / Bytes(12),
    "footer" / Bytes(8),
)

FileDataStoreObject = "FileDataStoreObject" / Struct(
    "guidHeader" / Bytes(16),
    "cbLength" / Int64ul,
    Bytes(4),
    Bytes(8),
    "FileData" / Bytes(this.cbLength),
)
