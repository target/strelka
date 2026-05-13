import lief
from lief import ELF

from strelka import strelka

lief.logging.disable()


class ScanElf(strelka.Scanner):
    """
    Extracts and analyzes metadata from ELF (Executable and Linkable Format) files.

    This scanner uses the LIEF library to parse ELF files, extracting detailed metadata such as binary headers,
    section details, symbol tables, and other ELF-specific attributes. It is capable of identifying various
    characteristics of the ELF file, including executable and linking details.

    Scanner Type: Collection

    Attributes:
        None

    Other Parameters:
        None

    ## Detection Use Cases
    !!! info "Detection Use Cases"
        - **Symbol and Dependency Analysis**
            - Extracts symbols and library dependencies for deeper binary analysis.
        - **Security Analysis**
            - Examine ELF files for security attributes like NX and PIE.

    ## Known Limitations
    !!! warning "Known Limitations"
        - **Resource Intensive**
            - Can be resource-intensive, depending on the size and complexity of the ELF file.

    ## To Do
    !!! question "To Do"
        - **Optimization**
            - Optimize resource usage and performance for large or complex ELF files.

    ## References
    !!! quote "References"
        - [LIEF Project Documentation](https://lief.quarkslab.com/)

    ## Contributors
    !!! example "Contributors"
        - [Josh Liburdi](https://github.com/jshlbrd)
        - [Paul Hutelmyer](https://github.com/phutelmyer)
        - [Ryan O'Horo](https://github.com/ryanohoro)
        - [Sara Kalupa](https://github.com/skalupa)
    """

    def scan(
        self, data: bytes, file: strelka.File, options: dict, expire_at: int
    ) -> None:
        """
        Scans an ELF file and extracts its metadata.

        Args:
            data (bytes): Raw data of the ELF file to be scanned.
            file (strelka.File): File details and metadata.
            options (dict): Scanner options (unused in this scanner).
            expire_at (int): Expiry time of the scan.
        """
        elf = ELF.parse(data)

        self.event["total"] = {
            "libraries": len(elf.libraries),
            "relocations": len(elf.relocations),
            "sections": elf.header.numberof_sections,
            "segments": elf.header.numberof_segments,
            "symbols": len(elf.symbols),
        }

        self.event["nx"] = elf.has_nx
        self.event["pie"] = elf.is_pie

        try:
            self.event["header"] = {
                "endianness": str(elf.header.identity_data).split(".")[1],
                "entry_point": elf.header.entrypoint,
                "file": {
                    "type": str(elf.header.file_type).split(".")[1],
                    "version": str(elf.header.object_file_version).split(".")[1],
                },
                "flags": {
                    "flags_list": elf.header.flags_list,
                    "processor": elf.header.processor_flag,
                },
                "identity": {
                    "class": str(elf.header.identity_class).split(".")[1],
                    "data": str(elf.header.identity_data).split(".")[1],
                    "os_abi": str(elf.header.identity_os_abi).split(".")[1],
                    "version": str(elf.header.identity_version).split(".")[1],
                },
                "machine": str(elf.header.machine_type).split(".")[1],
                "size": elf.header.header_size,
            }
        except strelka.ScannerTimeout:
            raise
        except Exception:
            pass

        if elf.has_interpreter:
            self.event["interpreter"] = elf.interpreter

        self.event.setdefault("relocations", [])
        self.event["relocations"] = []
        for relo in elf.relocations:
            row = {
                "address": relo.address,
                "info": relo.info,
                "purpose": str(relo.purpose).split(".")[1],
                "size": relo.size,
            }

            if relo.has_section:
                row["section"] = relo.section.name
            if relo.has_symbol:
                row["symbol"] = relo.symbol.name

            row["type"] = str(relo.type)

            self.event["relocations"].append(row)

        self.event["sections"] = []

        try:
            for sec in elf.sections:
                self.event["sections"].append(
                    {
                        "alignment": sec.alignment,
                        "entropy": sec.entropy,
                        "flags": [str(f).split(".")[1] for f in sec.flags_list],
                        "name": sec.name,
                        "offset": sec.offset,
                        "size": sec.size,
                        "type": str(sec.type).split(".")[1],
                        "segments": [
                            str(seg.type).split(".")[1] for seg in sec.segments
                        ],
                    }
                )
        except strelka.ScannerTimeout:
            raise
        except Exception:
            pass

        self.event["segments"] = []

        try:
            for seg in elf.segments:
                self.event["segments"].append(
                    {
                        "alignment": seg.alignment,
                        "file_offset": seg.file_offset,
                        "physical": {
                            "address": seg.physical_address,
                            "size": seg.physical_size,
                        },
                        "sections": [
                            str(sec.name).split(".")[1] for sec in seg.sections
                        ],
                        "type": str(seg.type).split(".")[1],
                        "virtual": {
                            "address": seg.virtual_address,
                            "size": seg.virtual_size,
                        },
                    }
                )
        except strelka.ScannerTimeout:
            raise
        except Exception:
            pass

        self.event["symbols"] = {
            "exported": [sym.name for sym in elf.exported_symbols],
            "imported": [sym.name for sym in elf.imported_symbols],
            "libraries": elf.libraries,
            "table": [],
        }

        for sym in elf.symbols:
            self.event["symbols"]["table"].append(
                {
                    "binding": str(sym.binding).rsplit(".")[1],
                    "information": sym.information,
                    "function": sym.is_function,
                    "symbol": sym.name,
                    "section_index": str(sym.shndx),
                    "size": sym.size,
                    "static": sym.is_static,
                    "version": str(sym.symbol_version),
                    "type": str(sym.type).rsplit(".")[1],
                    "variable": sym.is_variable,
                    "visibility": str(sym.visibility).rsplit(".")[1],
                }
            )
