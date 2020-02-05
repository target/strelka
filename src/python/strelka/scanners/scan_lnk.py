import uuid
import io
from construct import Struct, Int16ul, GreedyRange, Bytes, StringEncoded, this, Int32ul, If, Enum, CString, IfThenElse, BitsSwapped, BitStruct, Flag, Int32sl, Int8ul

from strelka import strelka

class ScanLNK(strelka.Scanner):
        """Collects metadata from lnk files."""
    def scan(self, data, file, options, expire_at):
        with io.BytesIO(data) as lnk_io:
            lnk_data = lnk_io.read()
            StringData = "StringData" / Struct(
                "CountCharacters" / Int16ul,
                "String" / StringEncoded(Bytes(this.CountCharacters * 2), "utf16")
            )

            LinkTargetIDList = "LinkTargetIDList" / Struct(
                "IDListSize" / Int16ul,
                "ItemID" / GreedyRange(Struct(
                    "ItemIDSize" / Int16ul,
                    "Data" / Bytes(this.ItemIDSize - 2),
                )),
                "TerminalID" / Int16ul
            )

            ExtraData = "ExtraData" / Struct(
                "BlockSize" / Int32ul,
                "BlockSignature" / Int32ul,
                "ConsoleDataBlock" / If(this.BlockSignature == 0xA0000002, Struct(
                    "FileAttributes" / Enum(Int16ul,
                        FOREGROUND_BLUE=0x001,
                        FOREGROUND_GREEN=0x002,
                        FOREGROUND_RED=0x004,
                        FOREGROUND_INTENSITY=0x008,
                        BACKGROUND_BLUE=0x010,
                        BACKGROUND_GREEN=0x020,
                        BACKGROUND_RED=0x040,
                        BACKGROUND_INTENSITY=0x0080
                    ),
                    "PopupFillAttributes" / Enum(Int16ul,
                        FOREGROUND_BLUE=0x001,
                        FOREGROUND_GREEN=0x002,
                        FOREGROUND_RED=0x004,
                        FOREGROUND_INTENSITY=0x008,
                        BACKGROUND_BLUE=0x010,
                        BACKGROUND_GREEN=0x020,
                        BACKGROUND_RED=0x040,
                        BACKGROUND_INTENSITY=0x0080
                    ),
                    "ScreenBufferSizeX" / Int16ul,
                    "ScreenBufferSizeY" / Int16ul,
                    "WindowSizeX" / Int16ul,
                    "WindowSizeY" / Int16ul,
                    "WindowOriginX" / Int16ul,
                    "WindowOriginY" / Int16ul,
                    "Unused1" / Bytes(4),
                    "Unused2" / Bytes(4),
                    "FontSize" / Int32ul,
                    "FontFamily" / Enum(Int32ul,
                        FF_DONTCARE=0x0000,
                        FF_ROMAN=0x0010,
                        FF_SWISS=0x0020,
                        FF_MODERN=0x0030,
                        FF_SCRIPT=0x0040,
                        FF_DECORATIVE=0x0050,
                        TMPF_NONE=0x0000,
                        TMPF_FIXED_PITCH=0x0001,
                        TMPF_VECTOR=0x0002,
                        TMPF_TRUETYPE=0x0004,
                        TMPF_DEVICE=0x0004
                    ),
                    "FontWeight" / Int32ul,
                    "FaceName" / Bytes(64),
                    "CursorSize" / Int32ul,
                    "FullScreen" / Int32ul,
                    "QuickEdit" / Int32ul,
                    "InsertMode" / Int32ul,
                    "AutoPosition" / Int32ul,
                    "HistoryBufferSize" / Int32ul,
                    "NumberOfHistoryBuffers" / Int32ul,
                    "HistoryNoDup" / Int32ul,
                    "ColorTable"/ Bytes(64)
                )),
                "ConsoleFEDataBlock" / If(this.BlockSignature == 0xA0000004, Struct(
                    "CodePage" / Int32ul
                )),
                "DarwinDataBlock" / If(this.BlockSignature == 0xA0000006, Struct(
                    "TargetAnsi" / CString("utf8"),
                    "TargetUnicode" / CString("utf16")
                )),
                "EnvironmentVariableDataBlock" / If(this.BlockSignature == 0xA0000001, Struct(
                    "TargetAnsi" / CString("utf8"),
                    "TargetUnicode" / CString("utf16")
                )),
                "IconEnvironmentDataBlock" / If(this.BlockSignature == 0xA0000007, Struct(
                    "TargetAnsi" / CString("utf8"),
                    "TargetUnicode" / CString("utf16")
                )),
                "KnownFolderDataBlock" / If(this.BlockSignature == 0xA000000B, Struct(
                    "KnownFolderID" / Bytes(16),
                    "Offset" / Int32ul,
                )),
                "PropertyStoreDataBlock" / If(this.BlockSignature == 0xA0000009, Struct(
                    "PropertyStore" / Struct(
                        "StoreSize" / Int32ul,
                        "SerializedPropertyStorage" / Struct(
                            "Version" / Int32ul,
                            "StorageSize" / Int32ul,
                            "FormatID" / Bytes(16),
                            "StringName" / IfThenElse(this.FormatID == b'\xd5\xcd\xd5\x05\x2e\x9c\x10\x1b\x93\x97\x08\x00\x2b\x2c\xf9\xae',
                                Struct(
                                    "ValueSize" / Int32ul,
                                    "NameSize" / Int32ul,
                                    "Reserved" / Bytes(1),
                                    "Name" / CString("utf16"),
                                    "Value" / CString('utf16')
                                ),
                                Struct(
                                    "ValueSize" / Int32ul,
                                    "Id" / Int32ul,
                                    "Reserved" / Bytes(1),
                                    "Size" / Int32ul,
                                    "Value" / CString('utf16')
                                )),
                        )
                    )
                )),
                "ShimDataBlock" / If(this.BlockSignature == 0xA0000008, Struct(
                    "LayerName" / CString("utf16")
                )),
                "SpecialFolderDataBlock" / If(this.BlockSignature == 0xA0000005, Struct(
                    "SpecialFolderID" / Int32ul,
                    "Offset" / Int32ul,
                    "LinkTargetIDList" / LinkTargetIDList,
                )),
                "TrackerDataBlock" / If(this.BlockSignature == 0xA0000003, Struct(
                    "Length" / Int32ul,
                    "Version" / Int32ul,
                    "MachineID" / Bytes(16),
                    "Droid" / Bytes(32),
                    "DroidBirth" / Bytes(32)
                )),
                "VistaAndAboveIDListDataBlock" / If(this.BlockSignature == 0xA000000C, Struct(
                    "LinkTargetIDList" / LinkTargetIDList,
                )),
                "TERMINAL_BLOCK" / Int32ul
            )

            ShellLinkHeader = "ShellLinkHeader" / Struct(
                "HeaderSize" / Int32ul,
                "LinkCLSID" / Bytes(16),
                "LinkFlags" / BitsSwapped(BitStruct(
                    "HasLinkTargetIDList" / Flag,
                    "HasLinkInfo" / Flag,
                    "HasName" / Flag,
                    "HasRelativePath" / Flag,
                    "HasWorkingDir" / Flag,
                    "HasArguments" / Flag,
                    "HasIconLocation" / Flag,
                    "IsUnicode" / Flag,
                    "ForceNoLinkInfo" / Flag,
                    "HasExpString" / Flag,
                    "RunInSeparateProcess" / Flag,
                    "Unused1" / Flag,
                    "HasDarwinID" / Flag,
                    "RunAsUser" / Flag,
                    "HasExpIcon" / Flag,
                    "NoPidlAlias" / Flag,
                    "Unused2" / Flag,
                    "RunWithShimLayer" / Flag,
                    "ForceNoLinkTrack" / Flag,
                    "EnableTargetMetadata" / Flag,
                    "DisableLinkPathTracking" / Flag,
                    "DisableKnownFolderTracking" / Flag,
                    "DisableKnownFolderAlias" / Flag,
                    "AllowLinkToLink" / Flag,
                    "UnaliasOnSave" / Flag,
                    "PreferEnvironmentPath" / Flag,
                    "KeepLocalIDListForUNCTarget" / Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag
                )),
                "FileAttributes" / BitsSwapped(BitStruct(
                    "FILE_ATTRIBUTE_READONLY" / Flag,
                    "FILE_ATTRIBUTE_READONLY" / Flag,
                    "FILE_ATTRIBUTE_SYSTEM" / Flag,
                    "Reserved1" / Flag,
                    "FILE_ATTRIBUTE_DIRECTORY" / Flag,
                    "FILE_ATTRIBUTE_ARCHIVE" / Flag,
                    "Reserved2" / Flag,
                    "FILE_ATTRIBUTE_NORMAL" / Flag,
                    "FILE_ATTRIBUTE_TEMPORARY" / Flag,
                    "FILE_ATTRIBUTE_SPARSE_FILE" / Flag,
                    "FILE_ATTRIBUTE_REPARSE_POINT" / Flag,
                    "FILE_ATTRIBUTE_COMPRESSED" / Flag,
                    "FILE_ATTRIBUTE_OFFLINE" / Flag,
                    "FILE_ATTRIBUTE_NOT_CONTENT_INDEXED" / Flag,
                    "FILE_ATTRIBUTE_ENCRYPTED" / Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag
                )),
                "CreationTime" / Bytes(8),
                "AccessTime" / Bytes(8),
                "WriteTime" / Bytes(8),
                "FileSize" / Int32ul,
                "IconIndex" / Int32sl,
                "ShowCommand" / Enum(Int32ul,
                                    SW_HIDE=0x00000000,
                                    SW_NORMAL=0x00000001,
                                    SW_SHOWMINIMIZED=0x00000002,
                                    SW_SHOWMAXIMIZED=0x00000003,
                                    SW_SHOWNOACTIVATE=0x00000004,
                                    SW_SHOW=0x00000005,
                                    SW_MINIMIZE=0x00000006,
                                    SW_SHOWMINNOACTIVE=0x00000007,
                                    SW_SHOWNA=0x00000008,
                                    SW_RESTORE=0x00000009,
                                    SW_SHOWDEFAULT=0x0000000a,
                                    ),
                "HotKey" / Struct(
                    "LowByte" / Int8ul,
                    "HighByte" / Int8ul
                ),
                "Reserved1" / Bytes(2),
                "Reserved2" / Bytes(4),
                "Reserved3" / Bytes(4)
            )

            CommonNetworkRelativeLink = "CommonNetworkRelativeLink" / Struct(
                "CommonNetworkRelativeLinkSize" / Int32ul,
                "CommonNetworkRelativeLinkFlags" / BitsSwapped(BitStruct(
                    "ValidDevice" / Flag,
                    "ValideNetType" / Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag
                )),
                "NetNameOffset" / Int32ul,
                "DeviceNameOffset" / Int32ul,
                If(this.CommonNetworkRelativeLinkFlags.ValideNetType, "NetworkProviderType" / Enum(Int32ul,
                    WNNC_NET_AVID=0x001A0000,
                    WNNC_NET_DOCUSPACE=0x001B0000,
                    WNNC_NET_MANGOSOFT=0x001C0000,
                    WNNC_NET_SERNET=0x001D0000,
                    WNNC_NET_RIVERFRONT1=0X001E0000,
                    WNNC_NET_RIVERFRONT2=0x001F0000,
                    WNNC_NET_DECORB=0x00200000,
                    WNNC_NET_PROTSTOR=0x00210000,
                    WNNC_NET_FJ_REDIR=0x00220000,
                    WNNC_NET_DISTINCT=0x00230000,
                    WNNC_NET_TWINS=0x00240000,
                    WNNC_NET_RDR2SAMPLE=0x00250000,
                    WNNC_NET_CSC=0x00260000,
                    WNNC_NET_3IN1=0x00270000,
                    WNNC_NET_EXTENDNET=0x00290000,
                    WNNC_NET_STAC=0x002A0000,
                    WNNC_NET_FOXBAT=0x002B0000,
                    WNNC_NET_YAHOO=0x002C0000,
                    WNNC_NET_EXIFS=0x002D0000,
                    WNNC_NET_DAV=0x002E0000,
                    WNNC_NET_KNOWARE=0x002F0000,
                    WNNC_NET_OBJECT_DIRE=0x00300000,
                    WNNC_NET_MASFAX=0x00310000,
                    WNNC_NET_HOB_NFS=0x00320000,
                    WNNC_NET_SHIVA=0x00330000,
                    WNNC_NET_IBMAL=0x00340000,
                    WNNC_NET_LOCK=0x00350000,
                    WNNC_NET_TERMSRV=0x00360000,
                    WNNC_NET_SRT=0x00370000,
                    WNNC_NET_QUINCY=0x00380000,
                    WNNC_NET_OPENAFS=0x00390000,
                    WNNC_NET_AVID1=0X003A0000,
                    WNNC_NET_DFS=0x003B0000,
                    WNNC_NET_KWNP=0x003C0000,
                    WNNC_NET_ZENWORKS=0x003D0000,
                    WNNC_NET_DRIVEONWEB=0x003E0000,
                    WNNC_NET_VMWARE=0x003F0000,
                    WNNC_NET_RSFX=0x00400000,
                    WNNC_NET_MFILES=0x00410000,
                    WNNC_NET_MS_NFS=0x00420000,
                    WNNC_NET_GOOGLE=0x00430000
                )),
                If(this.NetNameOffset > 0x00000014, "NetNameOffsetUnicode" / Int32ul),
                If(this.NetNameOffset > 0x00000014, "DeviceNameOffsetUnicode" / Int32ul),
                "NetName" / CString("utf8"),
                If(this.NetNameOffset > 0x00000014, "DeviceName" / CString("utf8")),
                If(this.NetNameOffset > 0x00000014, "NetNameUnicode" / CString("utf16")),
            )

            LinkInfo = "LinkInfo" / Struct(
                "LinkInfoSize" / Int32ul,
                "LinkInfoHeaderSize" / Int32ul,
                "LinkInfoFlags" / BitsSwapped(BitStruct(
                    "VolumeIDAndLocalBasePath" / Flag,
                    "CommonNetworkRelativeLinkAndPathSuffix" / Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag,
                    Flag
                )),
                "VolumeIDOffset" / If(this.LinkInfoFlags.VolumeIDAndLocalBasePath, Int32ul),
                "LocalBasePathOffset" / If(this.LinkInfoFlags.VolumeIDAndLocalBasePath, Int32ul),
                "CommonNetworkRelativeLinkOffset" / If(this.LinkInfoFlags.CommonNetworkRelativeLinkAndPathSuffix, Int32ul),
                "CommonPathSuffixOffset" / Int32ul,
                "LocalBasePathOffsetUnicode" / If(this.LinkInfoFlags.VolumeIDAndLocalBasePath, Int32ul),
                "CommonPathSuffixOffsetUnicode" / If(this.LinkInfoHeaderSize >= 0x24, Int32ul),
                "VolumeID" / Struct(
                    "VolumeIDSize" / Int32ul,
                    "DriveType" / Enum(Int32ul,
                                    DRIVE_UNKNOWN=0x00000000,
                                    DRIVE_NO_ROOT_DIR=0x00000001,
                                    DRIVE_REMOVABLE=0x00000002,
                                    DRIVE_FIXED=0x00000003,
                                    DRIVE_REMOTE=0x00000004,
                                    DRIVE_CDROM=0x00000005,
                                    DRIVE_RAMDISK=0x00000006
                                    ),
                    "DriveSerialNumber" / Int32ul,
                    "VolumeLabelOffset" / Int32ul,
                    "VolumeLabelOffsetUnicode" / If(this.VolumeLabelOffset == 0x14, Int32ul),
                    "Data" / CString("utf8")
                ),
                "LocalBasePath" / If(this.LinkInfoFlags.VolumeIDAndLocalBasePath, CString("utf8")),
                "CommonNetworkRelativeLink" / If(this.CommonNetworkRelativeLinkOffset, CommonNetworkRelativeLink),
                "CommonPathSuffix" / CString("utf8"),
                "LocalBasePathUnicode" / If(this.LinkInfoHeaderSize == 0x24, If(this.LocalBasePathOffsetUnicode, CString("utf16"))),
                "CommonPathSuffixUnicode" / If(this.LinkInfoHeaderSize == 0x24, If(this.CommonPathSuffixOffsetUnicode, CString("utf16"))),
            )
            header = ShellLinkHeader.parse(lnk_data)
            offset = header.HeaderSize

            try:
                if header.LinkFlags.HasLinkTargetIDList:
                    linktargetidlist = LinkTargetIDList.parse(lnk_data[offset:])
                    offset += linktargetidlist.IDListSize

                if header.LinkFlags.HasLinkInfo:
                    linkinfo = LinkInfo.parse(lnk_data[offset + 2:])
                    if linkinfo.VolumeID.DriveType:
                        self.event['DriveType'] = linkinfo.VolumeID.DriveType
                    if linkinfo.VolumeID.DriveSerialNumber:
                        self.event['DriveSerialNumber'] = '{0:x}'.format(linkinfo.VolumeID.DriveSerialNumber)
                    if linkinfo.VolumeID.Data:
                        self.event['VolumeLabel'] = linkinfo.VolumeID.Data
                    if linkinfo.LocalBasePath:
                        self.event['LocalBasePath'] = linkinfo.LocalBasePath
                    offset += linkinfo.LinkInfoSize

                if header.LinkFlags.HasName:
                    NAME_STRING = StringData.parse(lnk_data[offset + 2:])
                    self.event['NAME_STRING'] = NAME_STRING.String
                    offset += (NAME_STRING.CountCharacters * 2) + 2

                if header.LinkFlags.HasRelativePath:
                    RELATIVE_PATH = StringData.parse(lnk_data[offset + 2:])
                    offset += (RELATIVE_PATH.CountCharacters * 2) + 2

                if header.LinkFlags.HasWorkingDir:
                    WORKING_DIR = StringData.parse(lnk_data[offset + 2:])
                    offset += (WORKING_DIR.CountCharacters * 2) + 2

                if header.LinkFlags.HasArguments:
                    COMMAND_LINE_ARGUMENTS = StringData.parse(lnk_data[offset + 2:])
                    self.event['COMMAND_LINE_ARGUMENTS'] = COMMAND_LINE_ARGUMENTS.String
                    offset += (COMMAND_LINE_ARGUMENTS.CountCharacters * 2) + 2

                if header.LinkFlags.HasIconLocation:
                    ICON_LOCATION = StringData.parse(lnk_data[offset + 2:])
                    offset += (ICON_LOCATION.CountCharacters * 2) + 2
            except:
                self.flags.append('unable_to_parse')

            try:
                blocksize = True
                while blocksize:
                    try:
                        extradata = ExtraData.parse(lnk_data[offset + 2:])
                        blocksize = extradata.BlockSize
                    except:
                        break

                    if extradata.IconEnvironmentDataBlock:
                        self.event['IconTarget'] = extradata.IconEnvironmentDataBlock.TargetAnsi
                    if extradata.KnownFolderDataBlock:
                        self.event['KnownFolderID'] = str(uuid.UUID(bytes_le=extradata.KnownFolderDataBlock.KnownFolderID))
                    if extradata.TrackerDataBlock:
                        self.event['MachineID'] = extradata.TrackerDataBlock.MachineID.strip(b'\x00')
                        self.event['MAC'] = str(uuid.UUID(bytes_le=extradata.TrackerDataBlock.Droid[16:])).split('-')[-1]
                    if extradata.ShimDataBlock:
                        self.event['LayerName'] = extradata.ShimDataBlock.LayerName
                    if extradata.VistaAndAboveIDListDataBlock:
                        self.event['VistaAndAboveIDListDataBlock'] = extradata.VistaAndAboveIDListDataBlock
                    offset += extradata.BlockSize
            except:
                self.flags.append('unable_to_parse')
