# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description: Microsoft Extensible Storage Engine parser
# Author: Alberto Solino (@agsolino)

from collections import OrderedDict
from .structure import Structure
from struct import unpack, pack

# Constants

FILE_TYPE_DATABASE       = 0
FILE_TYPE_STREAMING_FILE = 1

# Database state
JET_dbstateJustCreated    = 1
JET_dbstateDirtyShutdown  = 2
JET_dbstateCleanShutdown  = 3
JET_dbstateBeingConverted = 4
JET_dbstateForceDetach    = 5

# Page Flags
FLAGS_ROOT         = 1
FLAGS_LEAF         = 2
FLAGS_PARENT       = 4
FLAGS_EMPTY        = 8
FLAGS_SPACE_TREE   = 0x20
FLAGS_INDEX        = 0x40
FLAGS_LONG_VALUE   = 0x80
FLAGS_NEW_FORMAT   = 0x2000
FLAGS_NEW_CHECKSUM = 0x2000

# Tag Flags
TAG_UNKNOWN = 0x1
TAG_DEFUNCT = 0x2
TAG_COMMON  = 0x4

# Fixed Page Numbers
DATABASE_PAGE_NUMBER           = 1
CATALOG_PAGE_NUMBER            = 4
CATALOG_BACKUP_PAGE_NUMBER     = 24

# Fixed FatherDataPages
DATABASE_FDP         = 1
CATALOG_FDP          = 2
CATALOG_BACKUP_FDP   = 3

# Catalog Types
CATALOG_TYPE_TABLE        = 1
CATALOG_TYPE_COLUMN       = 2
CATALOG_TYPE_INDEX        = 3
CATALOG_TYPE_LONG_VALUE   = 4
CATALOG_TYPE_CALLBACK     = 5

# Column Types
JET_coltypNil          = 0
JET_coltypBit          = 1
JET_coltypUnsignedByte = 2
JET_coltypShort        = 3
JET_coltypLong         = 4
JET_coltypCurrency     = 5
JET_coltypIEEESingle   = 6
JET_coltypIEEEDouble   = 7
JET_coltypDateTime     = 8
JET_coltypBinary       = 9
JET_coltypText         = 10
JET_coltypLongBinary   = 11
JET_coltypLongText     = 12
JET_coltypSLV          = 13
JET_coltypUnsignedLong = 14
JET_coltypLongLong     = 15
JET_coltypGUID         = 16
JET_coltypUnsignedShort= 17
JET_coltypMax          = 18

ColumnTypeToName = {
    JET_coltypNil          : 'NULL',
    JET_coltypBit          : 'Boolean',
    JET_coltypUnsignedByte : 'Signed byte',
    JET_coltypShort        : 'Signed short',
    JET_coltypLong         : 'Signed long',
    JET_coltypCurrency     : 'Currency',
    JET_coltypIEEESingle   : 'Single precision FP',
    JET_coltypIEEEDouble   : 'Double precision FP',
    JET_coltypDateTime     : 'DateTime',
    JET_coltypBinary       : 'Binary',
    JET_coltypText         : 'Text',
    JET_coltypLongBinary   : 'Long Binary',
    JET_coltypLongText     : 'Long Text',
    JET_coltypSLV          : 'Obsolete',
    JET_coltypUnsignedLong : 'Unsigned long',
    JET_coltypLongLong     : 'Long long',
    JET_coltypGUID         : 'GUID',
    JET_coltypUnsignedShort: 'Unsigned short',
    JET_coltypMax          : 'Max',
}

ColumnTypeSize = {
    JET_coltypNil          : None,
    JET_coltypBit          : (1,'B'),
    JET_coltypUnsignedByte : (1,'B'),
    JET_coltypShort        : (2,'<h'),
    JET_coltypLong         : (4,'<l'),
    JET_coltypCurrency     : (8,'<Q'),
    JET_coltypIEEESingle   : (4,'<f'),
    JET_coltypIEEEDouble   : (8,'<d'),
    JET_coltypDateTime     : (8,'<Q'),
    JET_coltypBinary       : None,
    JET_coltypText         : None, 
    JET_coltypLongBinary   : None,
    JET_coltypLongText     : None,
    JET_coltypSLV          : None,
    JET_coltypUnsignedLong : (4,'<L'),
    JET_coltypLongLong     : (8,'<Q'),
    JET_coltypGUID         : (16,'16s'),
    JET_coltypUnsignedShort: (2,'<H'),
    JET_coltypMax          : None,
}

# Tagged Data Type Flags
TAGGED_DATA_TYPE_VARIABLE_SIZE = 1
TAGGED_DATA_TYPE_COMPRESSED    = 2
TAGGED_DATA_TYPE_STORED        = 4
TAGGED_DATA_TYPE_MULTI_VALUE   = 8
TAGGED_DATA_TYPE_WHO_KNOWS     = 10

# Code pages
CODEPAGE_UNICODE = 1200
CODEPAGE_ASCII   = 20127
CODEPAGE_WESTERN = 1252

StringCodePages = {
    CODEPAGE_UNICODE : 'utf-16le', 
    CODEPAGE_ASCII   : 'ascii',
    CODEPAGE_WESTERN : 'cp1252',
}

# Structures

TABLE_CURSOR = {
    'TableData' : b'',
    'FatherDataPageNumber': 0,
    'CurrentPageData' : b'',
    'CurrentTag' : 0,
}

class ESENT_JET_SIGNATURE(Structure):
    structure = (
        ('Random','<L=0'),
        ('CreationTime','<Q=0'),
        ('NetBiosName','16s=b""'),
    )

class ESENT_DB_HEADER(Structure):
    structure = (
        ('CheckSum','<L=0'),
        ('Signature','"\xef\xcd\xab\x89'),
        ('Version','<L=0'),
        ('FileType','<L=0'),
        ('DBTime','<Q=0'),
        ('DBSignature',':',ESENT_JET_SIGNATURE),
        ('DBState','<L=0'),
        ('ConsistentPosition','<Q=0'),
        ('ConsistentTime','<Q=0'),
        ('AttachTime','<Q=0'),
        ('AttachPosition','<Q=0'),
        ('DetachTime','<Q=0'),
        ('DetachPosition','<Q=0'),
        ('LogSignature',':',ESENT_JET_SIGNATURE),
        ('Unknown','<L=0'),
        ('PreviousBackup','24s=b""'),
        ('PreviousIncBackup','24s=b""'),
        ('CurrentFullBackup','24s=b""'),
        ('ShadowingDisables','<L=0'),
        ('LastObjectID','<L=0'),
        ('WindowsMajorVersion','<L=0'),
        ('WindowsMinorVersion','<L=0'),
        ('WindowsBuildNumber','<L=0'),
        ('WindowsServicePackNumber','<L=0'),
        ('FileFormatRevision','<L=0'),
        ('PageSize','<L=0'),
        ('RepairCount','<L=0'),
        ('RepairTime','<Q=0'),
        ('Unknown2','28s=b""'),
        ('ScrubTime','<Q=0'),
        ('RequiredLog','<Q=0'),
        ('UpgradeExchangeFormat','<L=0'),
        ('UpgradeFreePages','<L=0'),
        ('UpgradeSpaceMapPages','<L=0'),
        ('CurrentShadowBackup','24s=b""'),
        ('CreationFileFormatVersion','<L=0'),
        ('CreationFileFormatRevision','<L=0'),
        ('Unknown3','16s=b""'),
        ('OldRepairCount','<L=0'),
        ('ECCCount','<L=0'),
        ('LastECCTime','<Q=0'),
        ('OldECCFixSuccessCount','<L=0'),
        ('ECCFixErrorCount','<L=0'),
        ('LastECCFixErrorTime','<Q=0'),
        ('OldECCFixErrorCount','<L=0'),
        ('BadCheckSumErrorCount','<L=0'),
        ('LastBadCheckSumTime','<Q=0'),
        ('OldCheckSumErrorCount','<L=0'),
        ('CommittedLog','<L=0'),
        ('PreviousShadowCopy','24s=b""'),
        ('PreviousDifferentialBackup','24s=b""'),
        ('Unknown4','40s=b""'),
        ('NLSMajorVersion','<L=0'),
        ('NLSMinorVersion','<L=0'),
        ('Unknown5','148s=b""'),
        ('UnknownFlags','<L=0'),
    )

class ESENT_PAGE_HEADER(Structure):
    structure_2003_SP0 = (
        ('CheckSum','<L=0'),
        ('PageNumber','<L=0'),
    )
    structure_0x620_0x0b = (
        ('CheckSum','<L=0'),
        ('ECCCheckSum','<L=0'),
    )
    structure_win7 = (
        ('CheckSum','<Q=0'),
    )
    common = (
        ('LastModificationTime','<Q=0'),
        ('PreviousPageNumber','<L=0'),
        ('NextPageNumber','<L=0'),
        ('FatherDataPage','<L=0'),
        ('AvailableDataSize','<H=0'),
        ('AvailableUncommittedDataSize','<H=0'),
        ('FirstAvailableDataOffset','<H=0'),
        ('FirstAvailablePageTag','<H=0'),
        ('PageFlags','<L=0'),
    )
    extended_win7 = (
        ('ExtendedCheckSum1','<Q=0'),
        ('ExtendedCheckSum2','<Q=0'),
        ('ExtendedCheckSum3','<Q=0'),
        ('PageNumber','<Q=0'),
        ('Unknown','<Q=0'),
    )
    def __init__(self, version, revision, pageSize=8192, data=None):
        if (version < 0x620) or (version == 0x620 and revision < 0x0b):
            # XP format
            self.structure = self.structure_2003_SP0 + self.common
        elif version == 0x620 and revision < 0x11:
            # Exchange 2003 SP1 and Windows Vista and later
            self.structure = self.structure_0x620_0x0b + self.common
        else:
            # Windows 7 and later
            self.structure = self.structure_win7 + self.common
            if pageSize > 8192:
                self.structure += self.extended_win7

        Structure.__init__(self,data)

class ESENT_ROOT_HEADER(Structure):
    structure = (
        ('InitialNumberOfPages','<L=0'),
        ('ParentFatherDataPage','<L=0'),
        ('ExtentSpace','<L=0'),
        ('SpaceTreePageNumber','<L=0'),
    )

class ESENT_BRANCH_HEADER(Structure):
    structure = (
        ('CommonPageKey',':'),
    )

class ESENT_BRANCH_ENTRY(Structure):
    common = (
        ('CommonPageKeySize','<H=0'),
    )
    structure = (
        ('LocalPageKeySize','<H=0'),
        ('_LocalPageKey','_-LocalPageKey','self["LocalPageKeySize"]'),
        ('LocalPageKey',':'),
        ('ChildPageNumber','<L=0'),
    )
    def __init__(self, flags, data=None):
        if flags & TAG_COMMON > 0:
            self.structure = self.common + self.structure
        Structure.__init__(self,data)

class ESENT_LEAF_HEADER(Structure):
    structure = (
        ('CommonPageKey',':'),
    )

class ESENT_LEAF_ENTRY(Structure):
    common = (
        ('CommonPageKeySize','<H=0'),
    )
    structure = (
        ('LocalPageKeySize','<H=0'),
        ('_LocalPageKey','_-LocalPageKey','self["LocalPageKeySize"]'),
        ('LocalPageKey',':'),
        ('EntryData',':'),
    )
    def __init__(self, flags, data=None):
        if flags & TAG_COMMON > 0:
            self.structure = self.common + self.structure
        Structure.__init__(self,data)

class ESENT_SPACE_TREE_HEADER(Structure):
    structure = (
        ('Unknown','<Q=0'),
    )

class ESENT_SPACE_TREE_ENTRY(Structure):
    structure = (
        ('PageKeySize','<H=0'),
        ('LastPageNumber','<L=0'),
        ('NumberOfPages','<L=0'),
    )

class ESENT_INDEX_ENTRY(Structure):
    structure = (
        ('RecordPageKey',':'),
    )

class ESENT_DATA_DEFINITION_HEADER(Structure):
    structure = (
        ('LastFixedSize','<B=0'),
        ('LastVariableDataType','<B=0'),
        ('VariableSizeOffset','<H=0'),
    )

class ESENT_CATALOG_DATA_DEFINITION_ENTRY(Structure):
    fixed = (
        ('FatherDataPageID','<L=0'),
        ('Type','<H=0'),
        ('Identifier','<L=0'),
    )

    column_stuff = (
        ('ColumnType','<L=0'),
        ('SpaceUsage','<L=0'),
        ('ColumnFlags','<L=0'),
        ('CodePage','<L=0'),
    )

    other = (
        ('FatherDataPageNumber','<L=0'),
    )

    table_stuff = (
        ('SpaceUsage','<L=0'),
    )

    index_stuff = (
        ('SpaceUsage','<L=0'),
        ('IndexFlags','<L=0'),
        ('Locale','<L=0'),
    )

    lv_stuff = (
        ('SpaceUsage','<L=0'),
    )
    common = (
        ('Trailing',':'),
    )

    def __init__(self,data):
        # Depending on the type of data we'll end up building a different struct
        dataType = unpack('<H', data[4:][:2])[0]
        self.structure = self.fixed

        if dataType == CATALOG_TYPE_TABLE:
            self.structure += self.other + self.table_stuff
        elif dataType == CATALOG_TYPE_COLUMN:
            self.structure += self.column_stuff
        elif dataType == CATALOG_TYPE_INDEX:
            self.structure += self.other + self.index_stuff
        elif dataType == CATALOG_TYPE_LONG_VALUE:
            self.structure += self.other + self.lv_stuff
        elif dataType == CATALOG_TYPE_CALLBACK:
            raise Exception('CallBack types not supported!')
        else:
            self.structure = ()
            Structure.__init__(self,data)

        self.structure += self.common

        Structure.__init__(self,data)

class ESENT_PAGE:
    def __init__(self, db, data=None):
        self.__DBHeader = db
        self.data = data
        self.record = None
        if data is not None:
            self.record = ESENT_PAGE_HEADER(self.__DBHeader['Version'], self.__DBHeader['FileFormatRevision'], self.__DBHeader['PageSize'], data)

    def getTag(self, tagNum):
        """Gets the next tag from this page"""
        # Make sure the tag number is valid for this page
        if tagNum >= self.record['FirstAvailablePageTag']:
            raise Exception(f'Requested tag number 0x{tagNum:X} exceeds page limit')

        # The tags are in an array at the end of the page (4 bytes each)
        if tagNum == 0:
            tag = self.data[-4:]
        else:
            tag = self.data[-4*(tagNum+1):-4*tagNum]

        # Offsets are relative to the ESENT_PAGE struct
        baseOffset = len(self.record)

        # New database format uses 15-bit numbers for size and offset
        if self.__DBHeader['Version'] == 0x620 and self.__DBHeader['FileFormatRevision'] >= 17 and self.__DBHeader['PageSize'] > 8192:
            valueSize = unpack('<H', tag[:2])[0] & 0x7fff
            valueOffset = unpack('<H',tag[2:])[0] & 0x7fff
            tmpData = bytearray(self.data[baseOffset+valueOffset:][:valueSize])
            pageFlags = tmpData[1] >> 5
            tmpData[1] = tmpData[1] & 0x1f
            tagData = bytes(tmpData)
        else:
            valueSize = unpack('<H', tag[:2])[0] & 0x1fff
            pageFlags = (unpack('<H', tag[2:])[0] & 0xe000) >> 13
            valueOffset = unpack('<H',tag[2:])[0] & 0x1fff
            tagData = self.data[baseOffset+valueOffset:][:valueSize]

        return pageFlags, tagData

class ESENT_DB:
    def __init__(self, fileData):
        self.__fileData = fileData
        self.__DBHeader = None
        self.__totalPages = None
        self.__tables = OrderedDict()
        self.__currentTable = None
        self.mountDB()

    def mountDB(self):
        self.__pageSize = 8192
        mainHeader = self.getPage(-1)
        self.__DBHeader = ESENT_DB_HEADER(mainHeader)
        self.__pageSize = self.__DBHeader['PageSize']
        self.__totalPages = (len(self.__fileData) // self.__pageSize) -2
        self.parseCatalog(CATALOG_PAGE_NUMBER)

    def __addItem(self, entry):
        dataDefinitionHeader = ESENT_DATA_DEFINITION_HEADER(entry['EntryData'])
        catalogEntry = ESENT_CATALOG_DATA_DEFINITION_ENTRY(entry['EntryData'][len(dataDefinitionHeader):])
        itemName = self.__parseItemName(entry, dataDefinitionHeader)

        if catalogEntry['Type'] == CATALOG_TYPE_TABLE:
            self.__tables[itemName] = OrderedDict()
            self.__tables[itemName]['TableEntry'] = entry
            self.__tables[itemName]['Columns']    = OrderedDict()
            self.__tables[itemName]['Indexes']    = OrderedDict()
            self.__tables[itemName]['LongValues'] = OrderedDict()
            self.__currentTable = itemName
        elif catalogEntry['Type'] == CATALOG_TYPE_COLUMN:
            self.__tables[self.__currentTable]['Columns'][itemName] = entry
            self.__tables[self.__currentTable]['Columns'][itemName]['Header'] = dataDefinitionHeader
            self.__tables[self.__currentTable]['Columns'][itemName]['Record'] = catalogEntry
        elif catalogEntry['Type'] == CATALOG_TYPE_INDEX:
            self.__tables[self.__currentTable]['Indexes'][itemName] = entry
        elif catalogEntry['Type'] == CATALOG_TYPE_LONG_VALUE:
            self.__addLongValue(catalogEntry)
        else:
            raise Exception('Unknown type 0x%x' % catalogEntry['Type'])

    def __parseItemName(self, entry, dataDefinitionHeader):
        if dataDefinitionHeader['LastVariableDataType'] > 127:
            numEntries =  dataDefinitionHeader['LastVariableDataType'] - 127
        else:
            numEntries =  dataDefinitionHeader['LastVariableDataType']

        itemLen = unpack('<H',entry['EntryData'][dataDefinitionHeader['VariableSizeOffset']:][:2])[0]
        itemName = entry['EntryData'][dataDefinitionHeader['VariableSizeOffset']:][2*numEntries:][:itemLen]
        return itemName

    def __addLongValue(self, catalogEntry):
        # Adds a long value entry from the catalog and associates with the current table
        self.__tables[self.__currentTable]['LongValues'] = catalogEntry

    def __getLongValues(self, pageNum):
        """Builds a dict of all key/value mappings in the long values tree by enumerating all pages and tags"""

        # Get the current page and process each tag in the page
        page = self.getPage(pageNum)
        longValues = {}
        for i in range(1, page.record['FirstAvailablePageTag']):
            # Enumerate tags and skip deleted entries
            tag_flags, data = page.getTag(i)
            if tag_flags & TAG_DEFUNCT:
                continue

            # Recursively process branch pages
            if page.record['PageFlags'] & FLAGS_LEAF == 0:
                branchEntry = ESENT_BRANCH_ENTRY(tag_flags, data)
                longValues.update(self.__getLongValues(branchEntry['ChildPageNumber']))

            # Parse the key/value pair from leaf pages
            else:
                cur_offset = 0
                # If this tag contains a common key size, get it
                common_key_data = None
                if tag_flags & TAG_COMMON:
                    common_key_size = unpack("<H", data[cur_offset:cur_offset+2])[0]
                    # The common key data is actually the first value on the page
                    _, common_key_data = page.getTag(0)
                    common_key_data = common_key_data[:common_key_size]
                    cur_offset += 2
                key_size = unpack("<H", data[cur_offset:cur_offset+2])[0]
                cur_offset += 2
                if cur_offset + key_size > len(data):
                    continue

                # If there is common key data defined, prepend it to the current key data
                if common_key_data:
                    key_data = common_key_data + data[cur_offset:cur_offset+key_size]
                else:
                    key_data = data[cur_offset:cur_offset+key_size]

                cur_offset += key_size
                # The value contains all data in the tag after the key
                value_size = len(data) - cur_offset
                value_data = data[cur_offset:cur_offset+value_size]
                longValues[key_data] = value_data

        return longValues

    def getLongValue(self, cursor, data):
        """Gets the long value for the given data by looking up references in the already-parsed long values table"""
        try:
            # For some reason the ID is stored big endian
            data_be = data[::-1]
            long_data = cursor['LongValues'].get(data_be)
            # The initial long entry contains an unknown value and total long data size
            _, long_data_size = unpack("<II", long_data)

            # Get the long data segments and combine into a bytearray
            combined_data = bytearray()
            cur_offset = 0
            while cur_offset < long_data_size:
                # The segment offset is big endian like the key in the long values table
                cur_key = data_be + pack(">I", cur_offset)
                cur_data = cursor['LongValues'].get(cur_key)
                # If there was no more data but we still had some data, return it
                if not cur_data and len(combined_data) > 0:
                    return bytes(combined_data)

                combined_data.extend(cur_data)
                cur_offset += len(cur_data)

            # Return the combined long data as bytes
            return bytes(combined_data)

        # If an exception occurs, just return the original data
        except Exception:
            return data

    def parsePage(self, page):
        """Parses a catalog page and adds relevant information to the table structures"""

        # Safety check to exclude page types that should not be in the catalog
        if page.record['PageFlags'] & (FLAGS_LEAF | FLAGS_SPACE_TREE | FLAGS_INDEX | FLAGS_LONG_VALUE) == 0:
            return

        # Enumerate tags in the page
        for tagNum in range(1,page.record['FirstAvailablePageTag']):
            flags, data = page.getTag(tagNum)
            leafEntry = ESENT_LEAF_ENTRY(flags, data)
            self.__addItem(leafEntry)

    def parseCatalog(self, pageNum):
        """Parse all the catalog pages starting at pageNum and adds relevant information to the table structures"""
        page = self.getPage(pageNum)
        self.parsePage(page)

        # Recursively process referenced pages from branch page tags
        if page.record['PageFlags'] & FLAGS_LEAF == 0:
            for i in range(1, page.record['FirstAvailablePageTag']):
                flags, data = page.getTag(i)
                branchEntry = ESENT_BRANCH_ENTRY(flags, data)
                self.parseCatalog(branchEntry['ChildPageNumber'])

    def getPage(self, pageNum):
        """Reads the specified page and parses headers (except on the root page)"""
        offset = (pageNum+1)*self.__pageSize
        data = self.__fileData[offset:offset+self.__pageSize]

        # Special case for the first page
        if pageNum <= 0:
            return data
        else:
            return ESENT_PAGE(self.__DBHeader, data)

    def openTable(self, tableName):
        """Opens and retunrs a cursor to enumerate entries in the specified table"""

        if not isinstance(tableName, bytes):
            tableName = tableName.encode("latin-1")

        # Get the cached table object
        cur_table = self.__tables.get(tableName)
        if not cur_table:
            return None

        entry = cur_table['TableEntry']
        dataDefinitionHeader = ESENT_DATA_DEFINITION_HEADER(entry['EntryData'])
        catalogEntry = ESENT_CATALOG_DATA_DEFINITION_ENTRY(entry['EntryData'][len(dataDefinitionHeader):])
            
        # Find the first leaf node
        pageNum = catalogEntry['FatherDataPageNumber']
        done = False
        while not done:
            page = self.getPage(pageNum)
            # If there are no records, return the first page
            if page.record['FirstAvailablePageTag'] <= 1:
                done = True

            # Enumerate tags for the current page
            for i in range(1, page.record['FirstAvailablePageTag']):
                flags, data = page.getTag(i)

                # If this is a branch node, check child page
                if page.record['PageFlags'] & FLAGS_LEAF == 0:
                    branchEntry = ESENT_BRANCH_ENTRY(flags, data)
                    pageNum = branchEntry['ChildPageNumber']
                    break
                # Otherwise, stop
                else:
                    done = True
                    break
                
        cursor = TABLE_CURSOR
        cursor['TableData'] = self.__tables[tableName]
        cursor['FatherDataPageNumber'] = catalogEntry['FatherDataPageNumber']
        cursor['CurrentPageData'] = page
        cursor['CurrentTag']  = 0

        # Create a mapping of the long values tree
        cursor['LongValues'] = self.__getLongValues(cursor['TableData']['LongValues']['FatherDataPageNumber'])

        return cursor

    def __getNextTag(self, cursor):
        """
        Given a cursor, finds the next valid tag in the page.  Returns None when the end of the tags are reached for the
        current page or if the current page is not a leaf since the tags are actually branches.
        """
        page = cursor['CurrentPageData']

        # If this isn't a leaf page, move to the next page
        if page.record['PageFlags'] & FLAGS_LEAF == 0:
            return None

        # Find the next non-defunct tag
        tag_flags = None
        tag_data = None
        while cursor['CurrentTag'] < page.record['FirstAvailablePageTag']:
            tag_flags, tag_data = page.getTag(cursor['CurrentTag'])
            if tag_flags & TAG_DEFUNCT:
                cursor['CurrentTag'] += 1
                continue
            else:
                break

        # If we have reached the last tag of this page, return None to move to the next page
        if cursor['CurrentTag'] >= page.record['FirstAvailablePageTag']:
            return None

        # Check for unexpected page flags
        if page.record['PageFlags'] & FLAGS_SPACE_TREE > 0:
            raise Exception('FLAGS_SPACE_TREE > 0')
        elif page.record['PageFlags'] & FLAGS_INDEX > 0:
            raise Exception('FLAGS_INDEX > 0')
        elif page.record['PageFlags'] & FLAGS_LONG_VALUE > 0:
            raise Exception('FLAGS_LONG_VALUE > 0')

        # Return the tag entry
        leafEntry = ESENT_LEAF_ENTRY(tag_flags, tag_data)
        return leafEntry

    def getNextRow(self, cursor):
        """Retrieves the next row (aka tag) for the given cursor position in the table"""

        # Increment the tag number and get the next valid tag from the current page
        cursor['CurrentTag'] += 1
        tag = self.__getNextTag(cursor)

        # If there are no more tags on this page, try the next page
        if tag is None:
            page = cursor['CurrentPageData']
            if page.record['NextPageNumber'] == 0:
                return None
            else:
                cursor['CurrentPageData'] = self.getPage(page.record['NextPageNumber'])
                cursor['CurrentTag'] = 0
                return self.getNextRow(cursor)

        # Otherwise, parse the current tag data into a record (resolving columns, long values, etc.)
        else:
            return self.__tagToRecord(cursor, tag['EntryData'])

    def __tagToRecord(self, cursor, tag):
        # So my brain doesn't forget, the data record is composed of:
        # Header
        # Fixed Size Data (ID < 127)
        #     The easiest to parse. Their size is fixed in the record. You can get its size
        #     from the Column Record, field SpaceUsage
        # Variable Size Data (127 < ID < 255)
        #     At VariableSizeOffset you get an array of two bytes per variable entry, pointing
        #     to the length of the value. Values start at:
        #                numEntries = LastVariableDataType - 127
        #                VariableSizeOffset + numEntries * 2 (bytes)
        # Tagged Data ( > 255 )
        #     After the Variable Size Value, there's more data for the tagged values.
        #     Right at the beginning there's another array (taggedItems), pointing to the
        #     values, size.
        #
        # The interesting thing about this DB records is there's no need for all the columns to be there, hence
        # saving space. That's why I got over all the columns, and if I find data (of any type), i assign it. If 
        # not, the column's empty.

        record = OrderedDict()
        taggedItems = OrderedDict()
        taggedItemsParsed = False

        dataDefinitionHeader = ESENT_DATA_DEFINITION_HEADER(tag)
        variableDataBytesProcessed = (dataDefinitionHeader['LastVariableDataType'] - 127) * 2
        prevItemLen = 0
        tagLen = len(tag)
        fixedSizeOffset = len(dataDefinitionHeader)
        variableSizeOffset = dataDefinitionHeader['VariableSizeOffset'] 
 
        columns = cursor['TableData']['Columns'] 
        
        for column in list(columns.keys()):
            columnRecord = columns[column]['Record']
            if columnRecord['Identifier'] <= dataDefinitionHeader['LastFixedSize']:
                # Fixed Size column data type, still available data
                record[column] = tag[fixedSizeOffset:][:columnRecord['SpaceUsage']]
                fixedSizeOffset += columnRecord['SpaceUsage']

            elif 127 < columnRecord['Identifier'] <= dataDefinitionHeader['LastVariableDataType']:
                # Variable data type
                index = columnRecord['Identifier'] - 127 - 1
                itemLen = unpack('<H',tag[variableSizeOffset+index*2:][:2])[0]

                if itemLen & 0x8000:
                    # Empty item
                    itemLen = prevItemLen
                    record[column] = None
                else:
                    itemValue = tag[variableSizeOffset+variableDataBytesProcessed:][:itemLen-prevItemLen]
                    record[column] = itemValue

                #if columnRecord['Identifier'] <= dataDefinitionHeader['LastVariableDataType']:
                variableDataBytesProcessed +=itemLen-prevItemLen

                prevItemLen = itemLen

            elif columnRecord['Identifier'] > 255:
                # Have we parsed the tagged items already?
                if taggedItemsParsed is False and (variableDataBytesProcessed+variableSizeOffset) < tagLen:
                    index = variableDataBytesProcessed+variableSizeOffset
                    endOfVS = self.__pageSize
                    firstOffsetTag = (unpack('<H', tag[index+2:][:2])[0] & 0x3fff) + variableDataBytesProcessed+variableSizeOffset
                    while True:
                        taggedIdentifier = unpack('<H', tag[index:][:2])[0]
                        index += 2
                        taggedOffset = (unpack('<H', tag[index:][:2])[0] & 0x3fff) 
                        # As of Windows 7 and later ( version 0x620 revision 0x11) the tagged data type flags are always present
                        if self.__DBHeader['Version'] == 0x620 and self.__DBHeader['FileFormatRevision'] >= 17 and self.__DBHeader['PageSize'] > 8192: 
                            flagsPresent = 1
                        else:
                            flagsPresent = (unpack('<H', tag[index:][:2])[0] & 0x4000)
                        index += 2
                        if taggedOffset < endOfVS:
                            endOfVS = taggedOffset
                        taggedItems[taggedIdentifier] = (taggedOffset, tagLen, flagsPresent)
                        if index >= firstOffsetTag:
                            # We reached the end of the variable size array
                            break
                
                    # Calculate length of variable items
                    prevKey = list(taggedItems.keys())[0]
                    for i in range(1,len(taggedItems)):
                        offset0, length, flags = taggedItems[prevKey]
                        offset, _, _ = list(taggedItems.items())[i][1]
                        taggedItems[prevKey] = (offset0, offset-offset0, flags)
                        prevKey = list(taggedItems.keys())[i]
                    taggedItemsParsed = True
 
                # Tagged data type
                if columnRecord['Identifier'] in taggedItems:
                    offsetItem = variableDataBytesProcessed + variableSizeOffset + taggedItems[columnRecord['Identifier']][0] 
                    itemSize = taggedItems[columnRecord['Identifier']][1]
                    # If the item has flags, get them and adjust offset
                    if taggedItems[columnRecord['Identifier']][2] > 0:
                        itemFlag = ord(tag[offsetItem:offsetItem+1])
                        record.flags = itemFlag
                        offsetItem += 1
                        itemSize -= 1
                    else:
                        itemFlag = 0

                    # Compressed data not currently handled
                    if itemFlag & (TAGGED_DATA_TYPE_COMPRESSED ):
                        record[column] = None
                    # Long values
                    elif itemFlag & TAGGED_DATA_TYPE_STORED:
                        data = tag[offsetItem:offsetItem+itemSize]
                        record[column] = self.getLongValue(cursor, data)

                    elif itemFlag & TAGGED_DATA_TYPE_MULTI_VALUE:
                        record[column] = (tag[offsetItem:offsetItem+itemSize],)
                    else:
                        record[column] = tag[offsetItem:offsetItem+itemSize]

                else:
                    record[column] = None
            else:
                record[column] = None

            # If we understand the data type, we unpack it and cast it accordingly otherwise, we just encode it in hex
            if type(record[column]) is tuple:
                # Not decoding multi value data
                record[column] = record[column][0]
            elif columnRecord['ColumnType'] == JET_coltypText or columnRecord['ColumnType'] == JET_coltypLongText: 
                # Strings
                if record[column] is not None:
                    if columnRecord['CodePage'] not in StringCodePages:
                        raise Exception('Unknown codepage 0x%x'% columnRecord['CodePage'])
                    stringDecoder = StringCodePages[columnRecord['CodePage']]

                    try:
                        record[column] = record[column].decode(stringDecoder)
                    except Exception:
                        record[column] = record[column].decode(stringDecoder, "replace")
                        pass
            else:
                unpackData = ColumnTypeSize[columnRecord['ColumnType']]
                if record[column] is not None and unpackData is not None:
                    unpackStr = unpackData[1]
                    record[column] = unpack(unpackStr, record[column])[0]

        return record
