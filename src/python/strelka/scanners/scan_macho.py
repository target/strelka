import tempfile

from lief import MachO

from strelka import strelka

CPU_SUBTYPES = {
    "ANY": {-2: "ANY", -1: "MULTIPLE", 0: "LITTLE_ENDIAN", 1: "BIG_ENDIAN"},
    "x86": {
        -2: "x86 (I386)",
        -1: "MULITPLE",
        0: "INTEL_MODEL_ALL",
        3: "x86_ALL, x86_64_ALL, I386_ALL, or 386",
        4: "x86_ARCH1 or 486",
        5: "586 or PENT",
        8: "x86_64_H or PENTIUM_3",
        9: "PENTIUM_M",
        10: "PENTIUM_4",
        11: "ITANIUM",
        12: "XEON",
        15: "INTEL_FAMILY_MAX",
        22: "PENTPRO",
        24: "PENTIUM_3_M",
        26: "PENTIUM_4_M",
        27: "ITANIUM_2",
        28: "XEON_MP",
        40: "PENTIUM_3_XEON",
        54: "PENTII_M3",
        86: "PENTII_M5",
        103: "CELERON",
        119: "CELERON_MOBILE",
        132: "486SX",
    },
    "MC98000": {-2: "MC98000", -1: "MULTIPLE", 0: "MC98000_ALL", 1: "MC98601"},
    "ARM": {
        -2: "ARM",
        -1: "MULTIPLE",
        0: "ARM_ALL",
        1: "ARM_A500_ARCH",
        2: "ARM_A500",
        3: "ARM_A440",
        4: "ARM_M4",
        5: "ARM_V4T",
        6: "ARM_V6",
        7: "ARM_V5TEJ",
        8: "ARM_XSCALE",
        9: "ARM_V7",
        10: "ARM_V7F",
        11: "ARM_V7S",
        12: "ARM_V7K",
        13: "ARM_V8",
        14: "ARM_V6M",
        15: "ARM_V7M",
        16: "ARM_V7EM",
    },
    "SPARC": {
        -2: "SPARC",
        -1: "MULTIPLE",
        0: "SPARC_ALL or SUN4_ALL",
        1: "SUN4_260",
        2: "SUN4_110",
    },
    "POWERPC": {
        -2: "POWERPC",
        -1: "MULTIPLE",
        0: "POWERPC_ALL",
        1: "POWERPC_601",
        2: "POWERPC_602",
        3: "POWERPC_603",
        4: "POWERPC_603e",
        5: "POWERPC_603ev",
        6: "POWERPC_604",
        7: "POWERPC_604e",
        8: "POWERPC_620",
        9: "POWERPC_750",
        10: "POWERPC_7400",
        11: "POWERPC_7450",
        100: "POWERPC_970",
    },
    "x86_64": {
        -2: "x86_64",
        -1: "MULTIPLE",
        0: "INTEL_MODEL_ALL",
        3: "x86_ALL, x86_64_ALL, I386_ALL, or 386",
        4: "x86_ARCH1 or 486",
        5: "586 or PENT",
        8: "x86_64_H or PENTIUM_3",
        9: "PENTIUM_M",
        10: "PENTIUM_4",
        11: "ITANIUM",
        12: "XEON",
        15: "INTEL_FAMILY_MAX",
        22: "PENTPRO",
        24: "PENTIUM_3_M",
        26: "PENTIUM_4_M",
        27: "ITANIUM_2",
        28: "XEON_MP",
        40: "PENTIUM_3_XEON",
        54: "PENTII_M3",
        86: "PENTII_M5",
        103: "CELERON",
        119: "CELERON_MOBILE",
        132: "486SX",
        2147483648 + 0: "INTEL_MODEL_ALL",
        2147483648 + 3: "x86_ALL, x86_64_ALL, I386_ALL, or 386",
        2147483648 + 4: "x86_ARCH1 or 486",
        2147483648 + 5: "586 or PENT",
        2147483648 + 8: "x86_64_H or PENTIUM_3",
        2147483648 + 9: "PENTIUM_M",
        2147483648 + 10: "PENTIUM_4",
        2147483648 + 11: "ITANIUM",
        2147483648 + 12: "XEON",
        2147483648 + 15: "INTEL_FAMILY_MAX",
        2147483648 + 22: "PENTPRO",
        2147483648 + 24: "PENTIUM_3_M",
        2147483648 + 26: "PENTIUM_4_M",
        2147483648 + 27: "ITANIUM_2",
        2147483648 + 28: "XEON_MP",
        2147483648 + 40: "PENTIUM_3_XEON",
        2147483648 + 54: "PENTII_M3",
        2147483648 + 86: "PENTII_M5",
        2147483648 + 103: "CELERON",
        2147483648 + 119: "CELERON_MOBILE",
        2147483648 + 132: "486SX",
    },
    "ARM64": {
        -2: "ARM64",
        -1: "MULTIPLE",
        0: "ARM64_ALL",
        1: "ARM64_V8",
        2147483648 + 0: "ARM64_ALL",
        2147483648 + 1: "ARM64_V8",
    },
    "POWERPC64": {
        -2: "POWERPC64",
        -1: "MULTIPLE",
        0: "POWERPC_ALL",
        1: "POWERPC_601",
        2: "POWERPC_602",
        3: "POWERPC_603",
        4: "POWERPC_603e",
        5: "POWERPC_603ev",
        6: "POWERPC_604",
        7: "POWERPC_604e",
        8: "POWERPC_620",
        9: "POWERPC_750",
        10: "POWERPC_7400",
        11: "POWERPC_7450",
        100: "POWERPC_970",
        2147483648 + 0: "POWERPC_ALL (LIB64)",
        2147483648 + 1: "POWERPC_601 (LIB64)",
        2147483648 + 2: "POWERPC_602 (LIB64)",
        2147483648 + 3: "POWERPC_603 (LIB64)",
        2147483648 + 4: "POWERPC_603e (LIB64)",
        2147483648 + 5: "POWERPC_603ev (LIB64)",
        2147483648 + 6: "POWERPC_604 (LIB64)",
        2147483648 + 7: "POWERPC_604e (LIB64)",
        2147483648 + 8: "POWERPC_620 (LIB64)",
        2147483648 + 9: "POWERPC_750 (LIB64)",
        2147483648 + 10: "POWERPC_7400 (LIB64)",
        2147483648 + 11: "POWERPC_7450 (LIB64)",
        2147483648 + 100: "POWERPC_970 (LIB64)",
    },
}

PROTECTIONS = {
    0: "---",
    1: "r--",
    2: "-w-",
    3: "rw-",
    4: "--x",
    5: "r-x",
    6: "-wx",
    7: "rwx",
}


class ScanMacho(strelka.Scanner):
    """Collects metadata from Mach-O files."""

    def scan(self, data, file, options, expire_at):
        tmp_directory = options.get("tmp_directory", "/tmp/")

        macho = MachO.parse(raw=list(data), config=MachO.ParserConfig.deep)

        self.event["total"] = {
            "binaries": macho.size,
        }

        if macho.size > 1:
            for r in range(0, macho.size):
                b = macho.at(r)
                with tempfile.NamedTemporaryFile(dir=tmp_directory) as tmp_data:
                    b.write(tmp_data.name)
                    tmp_data.flush()

                    with open(tmp_data.name, "rb") as f:
                        # Send extracted file back to Strelka
                        self.emit_file(f.read(), name=f"binary_{r}")

            return

        binary = macho.at(0)

        self.event["total"] = {
            **self.event["total"],
            "commands": binary.header.nb_cmds,
            "libraries": len(binary.libraries),
            "relocations": len(binary.relocations),
            "sections": len(binary.sections),
            "segments": len(binary.segments),
            "symbols": len(binary.symbols),
        }

        self.event["nx"] = binary.has_nx
        self.event["pie"] = binary.is_pie

        cpu_type = str(binary.header.cpu_type).split(".")[1]
        if cpu_type != "???":
            cpu_subtype = CPU_SUBTYPES[cpu_type][binary.header.cpu_subtype]
        else:
            cpu_subtype = str(binary.header.cpu_subtype)

        self.event["header"] = {
            "cpu": {
                "primary": cpu_type,
                "sub": cpu_subtype,
            },
            "file": str(binary.header.file_type).split(".")[1],
            "flags": [str(flag).split(".")[1] for flag in binary.header.flags_list],
        }

        self.event["relocations"] = []
        for relo in binary.relocations:
            row = {
                "address": relo.address,
                "size": relo.size,
            }

            if relo.has_section:
                row["section"] = relo.section.name
            if relo.has_segment:
                row["segment"] = relo.segment.name
            if relo.has_symbol:
                row["symbol"] = relo.symbol.name

            self.event["relocations"].append(row)

        self.event["sections"] = []
        for sec in binary.sections:
            self.event["sections"].append(
                {
                    "alignment": sec.alignment,
                    "entropy": sec.entropy,
                    "name": sec.name,
                    "offset": sec.offset,
                    "size": sec.size,
                    "virtual": {
                        "address": sec.virtual_address,
                    },
                }
            )

        self.event["segments"] = []
        for seg in binary.segments:
            self.event["segments"].append(
                {
                    "command": {
                        "offset": seg.command_offset,
                        "size": seg.size,
                        "type": str(seg.command).split(".")[1],
                    },
                    "file": {
                        "offset": seg.file_offset,
                        "size": seg.file_size,
                    },
                    "flags": seg.flags,
                    "protection": {
                        "init": PROTECTIONS[seg.init_protection],
                        "max": PROTECTIONS[seg.max_protection],
                    },
                    "name": seg.name,
                    "sections": [sec.name for sec in seg.sections],
                    "virtual": {
                        "address": seg.virtual_address,
                        "size": seg.virtual_size,
                    },
                }
            )

        self.event["symbols"] = {
            "exported": [sym.name for sym in binary.exported_symbols],
            "imported": [sym.name for sym in binary.imported_symbols],
            "libraries": [lib.name for lib in binary.libraries],
            "table": [],
        }

        for sym in binary.symbols:
            row = {
                "symbol": sym.name,
                "origin": str(sym.origin).rsplit(".")[1],
            }

            if sym.has_binding_info:
                binding_address = getattr(sym.binding_info, "address", None)
                binding_class = getattr(sym.binding_info, "binding_class", None)
                binding_type = getattr(sym.binding_info, "binding_type", None)
                weak_import = getattr(sym.binding_info, "weak_import", None)

                # Convert binding_class and binding_type to string and extract the last part after "."
                if binding_class and "." in str(binding_class):
                    binding_class = str(binding_class).rsplit(".", 1)[1]

                if binding_type and "." in str(binding_type):
                    binding_type = str(binding_type).rsplit(".", 1)[1]

                row["binding"] = {
                    "address": binding_address,
                    "class": binding_class,
                    "type": binding_type,
                    "weak_import": weak_import,
                }

                if sym.binding_info.has_library:
                    lib = sym.binding_info.library
                    row["binding"]["library"] = {
                        "name": lib.name,
                        "size": lib.size,
                        "timestamp": lib.timestamp,
                        "version": {
                            "compatibility": ".".join(
                                [str(ver) for ver in lib.compatibility_version]
                            ),
                            "current": ".".join(
                                [str(ver) for ver in lib.current_version]
                            ),
                        },
                    }

                if sym.binding_info.has_segment:
                    row["binding"]["segment"] = sym.binding_info.segment.name

            elif sym.has_export_info:
                row["export"] = {
                    "address": sym.export_info.address,
                    "flags": sym.export_info.flags,
                }
            self.event["symbols"]["table"].append(row)

        self.event["commands"] = {
            "commands": [str(com.command).split(".")[1] for com in binary.commands]
        }

        if binary.has_code_signature:
            self.event["commands"]["code_signature"] = {
                "command": {
                    "offset": binary.code_signature.command_offset,
                    "size": binary.code_signature.size,
                },
                "data": {
                    "offset": binary.code_signature.data_offset,
                    "size": binary.code_signature.data_size,
                },
            }

        if binary.has_data_in_code:
            self.event["commands"]["data_in_code"] = {
                "command": {
                    "offset": binary.data_in_code.command_offset,
                    "size": binary.data_in_code.size,
                },
                "data": {
                    "offset": binary.data_in_code.data_offset,
                    "size": binary.data_in_code.data_size,
                },
            }

            entries = []
            for e in binary.data_in_code.entries:
                entries.append(
                    {
                        "length": e.length,
                        "offset": e.offset,
                        "type": str(e.type).split(".")[1],
                    }
                )
            self.event["commands"]["data_in_code"]["entries"] = entries

        if binary.has_dyld_environment:
            self.event["commands"]["dyld_environment"] = {
                "command": {
                    "offset": binary.dyld_environment.command_offset,
                    "size": binary.dyld_environment.size,
                },
                "environment_variable": binary.dyld_environment.value,
            }

        if binary.has_dyld_info:
            self.event["commands"]["dyld_info"] = {
                "bind": {
                    "offset": binary.dyld_info.bind[0],
                    "size": binary.dyld_info.bind[1],
                    "lazy": {
                        "offset": binary.dyld_info.lazy_bind[0],
                        "size": binary.dyld_info.lazy_bind[1],
                    },
                    "weak": {
                        "offset": binary.dyld_info.weak_bind[0],
                        "size": binary.dyld_info.weak_bind[1],
                    },
                },
                "command": {
                    "offset": binary.dyld_info.command_offset,
                    "size": binary.dyld_info.size,
                },
                "export": {
                    "offset": binary.dyld_info.export_info[0],
                    "size": binary.dyld_info.export_info[1],
                },
                "rebase": {
                    "offset": binary.dyld_info.rebase[0],
                    "size": binary.dyld_info.rebase[1],
                },
            }

        if binary.has_dylinker:
            self.event["commands"]["load_dylinker"] = {
                "command": {
                    "offset": binary.dylinker.command_offset,
                    "size": binary.dylinker.size,
                },
                "name": binary.dylinker.name,
            }

        if binary.has_dynamic_symbol_command:
            self.event["commands"]["dynamic_symbol"] = {
                "command": {
                    "offset": binary.dynamic_symbol_command.command_offset,
                    "size": binary.dynamic_symbol_command.size,
                },
                "offset": {
                    "symbol": {
                        "external": binary.dynamic_symbol_command.external_reference_symbol_offset,
                        "indirect": binary.dynamic_symbol_command.indirect_symbol_offset,
                    },
                    "relocation": {
                        "external": binary.dynamic_symbol_command.external_relocation_offset,
                        "local": binary.dynamic_symbol_command.local_relocation_offset,
                    },
                    "table": {
                        "module": binary.dynamic_symbol_command.module_table_offset,
                    },
                    "toc": binary.dynamic_symbol_command.toc_offset,
                },
            }

        if binary.has_encryption_info:
            self.event["commands"]["encryption_info"] = {
                "command": {
                    "offset": binary.encryption_info.command_offset,
                    "size": binary.encryption_info.size,
                },
                "crypt": {
                    "id": binary.encryption_info.crypt_id,
                    "offset": binary.encryption_info.crypt_offset,
                    "size": binary.encryption_info.crypt_size,
                },
            }

        if binary.has_function_starts:
            self.event["commands"]["function_starts"] = {
                "command": {
                    "offset": binary.function_starts.command_offset,
                    "size": binary.function_starts.size,
                },
                "data": {
                    "offset": binary.function_starts.data_offset,
                    "size": binary.function_starts.data_size,
                },
            }

        if binary.has_main_command:
            self.event["commands"]["main"] = {
                "command": {
                    "offset": binary.main_command.command_offset,
                    "size": binary.main_command.size,
                },
                "entry_point": binary.main_command.entrypoint,
                "stack_size": binary.main_command.stack_size,
            }

        if binary.has_rpath:
            self.event["commands"]["rpath"] = {
                "command": {
                    "offset": binary.rpath.command_offset,
                    "size": binary.rpath.size,
                },
                "path": binary.rpath.path,
            }

        if binary.has_segment_split_info:
            self.event["commands"]["segment_split_info"] = {
                "command": {
                    "offset": binary.segment_split_info.command_offset,
                    "size": binary.segment_split_info.size,
                },
                "data": {
                    "offset": binary.segment_split_info.data_offset,
                    "size": binary.segment_split_info.data_size,
                },
            }

        if binary.has_source_version:
            self.event["commands"]["source_version"] = {
                "command": {
                    "offset": binary.source_version.command_offset,
                    "size": binary.source_version.size,
                },
                "version": ".".join([str(v) for v in binary.source_version.version]),
            }

        if binary.has_sub_framework:
            self.event["commands"]["sub_framework"] = {
                "command": {
                    "offset": binary.sub_framework.command_offset,
                    "size": binary.sub_framework.size,
                },
            }

        if binary.has_symbol_command:
            self.event["commands"]["symbol"] = {
                "command": {
                    "offset": binary.symbol_command.command_offset,
                    "size": binary.symbol_command.size,
                },
                "strings": {
                    "offset": binary.symbol_command.strings_offset,
                    "size": binary.symbol_command.strings_size,
                },
                "symbol": {
                    "offset": binary.symbol_command.symbol_offset,
                },
            }

        if binary.has_thread_command:
            self.event["commands"]["thread"] = {
                "command": {
                    "offset": binary.thread_command.command_offset,
                    "size": binary.thread_command.size,
                },
            }

        if binary.has_uuid:
            self.event["commands"]["uuid"] = {
                "command": {
                    "offset": binary.uuid.command_offset,
                    "size": binary.uuid.size,
                },
                "uuid": "".join([str(u) for u in binary.uuid.uuid]),
            }

        if binary.has_version_min:
            self.event["commands"]["version_min"] = {
                "command": {
                    "offset": binary.version_min.command_offset,
                    "size": binary.version_min.size,
                },
                "version": ".".join([str(v) for v in binary.version_min.version]),
                "sdk": ".".join([str(s) for s in binary.version_min.sdk]),
            }
