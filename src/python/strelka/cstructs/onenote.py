# Authors: Ryan Borre

from construct import Bytes, Int64ul, Struct, this

FileDataStoreObject = "FileDataStoreObject" / Struct(
    "guidHeader" / Bytes(16),
    "cbLength" / Int64ul,
    Bytes(4),
    Bytes(8),
    "FileData" / Bytes(this.cbLength),
)
