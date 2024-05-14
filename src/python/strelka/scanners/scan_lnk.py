import uuid

from construct import Bytes, IfThenElse, Int16ul, StringEncoded, Struct, this

from strelka import strelka
from strelka.cstructs.lnk import (
    CommonNetworkRelativeLink,
    ExtraData,
    LinkInfo,
    LinkTargetIDList,
    ShellLinkHeader,
)


class ScanLnk(strelka.Scanner):
    """Collects metadata from LNK files."""

    def scan(self, data, file, options, expire_at):
        header = ShellLinkHeader.parse(data)
        offset = header.HeaderSize

        try:
            if header.LinkFlags.HasLinkTargetIDList:
                linktargetidlist = LinkTargetIDList.parse(data[offset:])
                offset += linktargetidlist.IDListSize + 2
        except strelka.ScannerTimeout:
            raise
        except Exception:
            self.flags.append("Unable to parse LinkTargetIDList")

        try:
            if header.LinkFlags.HasLinkInfo:
                linkinfo = LinkInfo.parse(data[offset:])
                if linkinfo.VolumeID.DriveType:
                    self.event["drive_type"] = linkinfo.VolumeID.DriveType
                if linkinfo.VolumeID.DriveSerialNumber:
                    self.event["drive_serial_number"] = "{0:x}".format(
                        linkinfo.VolumeID.DriveSerialNumber
                    )
                if linkinfo.VolumeID.Data:
                    self.event["volume_label"] = linkinfo.VolumeID.Data
                if linkinfo.LocalBasePath:
                    self.event["local_base_path"] = linkinfo.LocalBasePath
                if linkinfo.CommonNetworkRelativeLink:
                    commonnetworkrelativelink = CommonNetworkRelativeLink.parse(
                        data[offset + linkinfo.CommonNetworkRelativeLinkOffset :]
                    )
                    self.event["net_name"] = commonnetworkrelativelink.NetName
                offset += linkinfo.LinkInfoSize
        except strelka.ScannerTimeout:
            raise
        except Exception:
            self.flags.append("Unable to parse LinkInfo")

        StringData = "StringData" / Struct(
            "CountCharacters" / Int16ul,
            "String"
            / IfThenElse(
                header.LinkFlags.IsUnicode,
                StringEncoded(Bytes(this.CountCharacters * 2), "utf16"),
                StringEncoded(Bytes(this.CountCharacters), "utf8"),
            ),
        )

        try:
            if header.LinkFlags.HasName:
                NAME_STRING = StringData.parse(data[offset:])
                self.event["name_string"] = NAME_STRING.String
                if header.LinkFlags.IsUnicode:
                    offset += len(NAME_STRING.String) * 2 + 2
                else:
                    offset += len(NAME_STRING.String) + 2
        except strelka.ScannerTimeout:
            raise
        except Exception:
            self.flags.append("Unable to parse NAME_STRING")

        try:
            if header.LinkFlags.HasRelativePath:
                RELATIVE_PATH = StringData.parse(data[offset:])
                self.event["relative_path"] = RELATIVE_PATH.String
                if header.LinkFlags.IsUnicode:
                    offset += len(RELATIVE_PATH.String) * 2 + 2
                else:
                    offset += len(RELATIVE_PATH.String) + 2
        except strelka.ScannerTimeout:
            raise
        except Exception:
            self.flags.append("Unable to parse RELATIVE_PATH")

        try:
            if header.LinkFlags.HasWorkingDir:
                WORKING_DIR = StringData.parse(data[offset:])
                self.event["working_dir"] = WORKING_DIR.String
                if header.LinkFlags.IsUnicode:
                    offset += len(WORKING_DIR.String) * 2 + 2
                else:
                    offset += len(WORKING_DIR.String) + 2
        except strelka.ScannerTimeout:
            raise
        except Exception:
            self.flags.append("Unable to parse WORKING_DIR")

        try:
            if header.LinkFlags.HasArguments:
                COMMAND_LINE_ARGUMENTS = StringData.parse(data[offset:])
                self.event["command_line_args"] = COMMAND_LINE_ARGUMENTS.String
                if header.LinkFlags.IsUnicode:
                    offset += len(COMMAND_LINE_ARGUMENTS.String) * 2 + 2
                else:
                    offset += len(COMMAND_LINE_ARGUMENTS.String) + 2
        except strelka.ScannerTimeout:
            raise
        except Exception:
            self.flags.append("Unable to parse COMMAND_LINE_ARGUMENTS")

        try:
            if header.LinkFlags.HasIconLocation:
                ICON_LOCATION = StringData.parse(data[offset:])
                self.event["icon_location"] = ICON_LOCATION.String
                if header.LinkFlags.IsUnicode:
                    offset += len(ICON_LOCATION.String) * 2 + 2
                else:
                    offset += len(ICON_LOCATION.String) + 2
        except strelka.ScannerTimeout:
            raise
        except Exception:
            self.flags.append("Unable to parse ICON_LOCATION")

        try:
            blocksize = True
            while blocksize:
                try:
                    extradata = ExtraData.parse(data[offset:])
                    blocksize = extradata.BlockSize
                except strelka.ScannerTimeout:
                    raise
                except Exception:
                    break

                try:
                    if extradata.IconEnvironmentDataBlock:
                        self.event["icon_target"] = (
                            extradata.IconEnvironmentDataBlock.TargetAnsi
                        )
                except strelka.ScannerTimeout:
                    raise
                except Exception:
                    self.flags.append("Unable to parse IconEnvironmentDataBlock")

                if extradata.TrackerDataBlock:
                    self.event["machine_id"] = (
                        extradata.TrackerDataBlock.MachineID.strip(b"\x00")
                    )
                    self.event["mac"] = str(
                        uuid.UUID(bytes_le=extradata.TrackerDataBlock.Droid[16:])
                    ).split("-")[-1]

                offset += extradata.BlockSize

        except strelka.ScannerTimeout:
            raise
        except Exception:
            self.flags.append("Unable to parse ExtraDataBlock")
