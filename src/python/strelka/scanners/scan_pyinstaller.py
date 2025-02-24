from strelka import strelka
from strelka.auxiliary.pyinstaller.readers import (
    PKG_ITEM_BINARY,
    PKG_ITEM_DATA,
    PKG_ITEM_DEPENDENCY,
    PKG_ITEM_PYMODULE,
    PKG_ITEM_PYPACKAGE,
    PKG_ITEM_PYSOURCE,
    PKG_ITEM_PYZ,
    PKG_ITEM_RUNTIME_OPTION,
    PKG_ITEM_SPLASH,
    PKG_ITEM_ZIPFILE,
    CArchiveReader,
)


class ScanPyinstaller(strelka.Scanner):
    """
    Collects metadata and extracts pysource files from PyInstaller binaries.

    This scanner parses PyInstaller binaries to collect metadata and extract embedded pysource files.
    It is used in forensic and malware analysis to extract and analyze structured data within PyInstaller binaries.

    Scanner Type: Collection

    Attributes:
        event (dict): A dictionary to store collected metadata during the scan, structured by token types.

    Detection Use Cases:
        - **Forensic Investigation**
            - Aid in the investigation of incidents involving this specific type of Python shellcode execution by
            giving access to encapsulated code.

    Known Limitations:
        - **Other Python-based Shellcode Runners**
            - This scanner was made for a very specific format of Python shellcode runner script. It will not detect
            or extract shellcode from Python scripts which use other methods.
    """

    def scan(self, data, file, options, expire_at):
        """
        Performs the scan operation on PyInstaller samples.

        Args:
            data (bytes): The file data as a byte string.
            file (File): The file object to be scanned.
            options (dict): Options for customizing the scan.
            expire_at (datetime): Expiration timestamp for the scan result.
        """
        # read the compiled package archive
        pkg_archive = CArchiveReader(data)
        self.event["cookie"] = pkg_archive._COOKIE
        self.event["pkg_item_binary"] = []
        self.event["pkg_item_dependency"] = []
        self.event["pkg_item_pyz"] = []
        self.event["pkg_item_zipfile"] = []
        self.event["pkg_item_pypackage"] = []
        self.event["pkg_item_pymodule"] = []
        self.event["pkg_item_pysource"] = []
        self.event["pkg_item_data"] = []
        self.event["pkg_item_runtime_option"] = []
        self.event["pkg_item_splash"] = []

        # parse each item in the package archive
        for name, toc_meta in pkg_archive.toc.items():
            (
                entry_offset,
                data_length,
                uncompressed_length,
                compression_flag,
                typecode,
            ) = toc_meta

            toc_entry = {
                "name": name,
                "entry_offset": entry_offset,
                "data_length": data_length,
                "uncompressed_length": uncompressed_length,
                "compression_flag": compression_flag,
                "typecode": typecode,
            }

            if typecode == PKG_ITEM_BINARY:
                self.event["pkg_item_binary"].append(toc_entry)
            elif typecode == PKG_ITEM_DEPENDENCY:
                self.event["pkg_item_dependency"].append(toc_entry)
            elif typecode == PKG_ITEM_PYZ:
                self.event["pkg_item_pyz"].append(toc_entry)
            elif typecode == PKG_ITEM_ZIPFILE:
                self.event["pkg_item_zipfile"].append(toc_entry)
            elif typecode == PKG_ITEM_PYPACKAGE:
                self.event["pkg_item_pypackage"].append(toc_entry)
            elif typecode == PKG_ITEM_PYMODULE:
                self.event["pkg_item_pymodule"].append(toc_entry)
            elif typecode == PKG_ITEM_PYSOURCE:
                self.event["pkg_item_pysource"].append(toc_entry)
                self.emit_file(pkg_archive.extract(name), name=name)
            elif typecode == PKG_ITEM_DATA:
                self.event["pkg_item_data"].append(toc_entry)
            elif typecode == PKG_ITEM_RUNTIME_OPTION:
                self.event["pkg_item_runtime_option"].append(toc_entry)
            elif typecode == PKG_ITEM_SPLASH:
                self.event["pkg_item_splash"].append(toc_entry)
