import lief
from lief import ELF

from strelka import strelka

lief.logging.disable()


class ScanElf(strelka.Scanner):
    """Collects metadata from ELF files."""

    def scan(self, data, file, options, expire_at):
        elf = ELF.parse(raw=list(data))

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
                    "arm": [str(f).split(".")[1] for f in elf.header.arm_flags_list],
                    "hexagon": [
                        str(f).split(".")[1] for f in elf.header.hexagon_flags_list
                    ],
                    "mips": [str(f).split(".")[1] for f in elf.header.mips_flags_list],
                    "ppc64": [
                        str(f).split(".")[1] for f in elf.header.ppc64_flags_list
                    ],
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

            if elf.header.machine_type == ELF.ARCH.x86_64:
                row["type"] = str(ELF.RELOCATION_X86_64(relo.type)).split(".")[1]
            elif elf.header.machine_type == ELF.ARCH.i386:
                row["type"] = str(ELF.RELOCATION_i386(relo.type)).split(".")[1]
            elif elf.header.machine_type == ELF.ARCH.ARM:
                row["type"] = str(ELF.RELOCATION_ARM(relo.type)).split(".")[1]
            elif elf.header.machine_type == ELF.ARCH.AARCH64:
                row["type"] = str(ELF.RELOCATION_AARCH64(relo.type)).split(".")[1]
            else:
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
                    "section_index": str(ELF.SYMBOL_SECTION_INDEX(sym.shndx)).rsplit(
                        "."
                    )[1],
                    "size": sym.size,
                    "static": sym.is_static,
                    "version": str(sym.symbol_version),
                    "type": str(sym.type).rsplit(".")[1],
                    "variable": sym.is_variable,
                    "visibility": str(sym.visibility).rsplit(".")[1],
                }
            )
