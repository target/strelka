# Authors: Ryan Borre

from construct import this, Struct, Bytes, Int64ul

FileDataStoreObject = "FileDataStoreObject" / Struct(
    "guidHeader" / Bytes(16),
    "cbLength" / Int64ul,
    Bytes(4),
    Bytes(8),
    "FileData" / Bytes(this.cbLength),
)
