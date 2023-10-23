from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_macho import ScanMacho as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_macho(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "total": {
            "binaries": 1,
            "commands": 16,
            "libraries": 1,
            "relocations": 0,
            "sections": 5,
            "segments": 4,
            "symbols": 3,
        },
        "nx": True,
        "pie": True,
        "header": {
            "cpu": {
                "primary": "x86_64",
                "sub": "x86_ALL, x86_64_ALL, I386_ALL, or 386",
            },
            "file": "EXECUTE",
            "flags": ["TWOLEVEL", "NOUNDEFS", "DYLDLINK", "PIE"],
        },
        "relocations": [],
        "sections": [
            {
                "alignment": 4,
                "entropy": mock.ANY,
                "name": "__text",
                "offset": 16240,
                "size": 37,
                "virtual": {"address": 4294983536},
            },
            {
                "alignment": 1,
                "entropy": mock.ANY,
                "name": "__stubs",
                "offset": 16278,
                "size": 6,
                "virtual": {"address": 4294983574},
            },
            {
                "alignment": 0,
                "entropy": mock.ANY,
                "name": "__cstring",
                "offset": 16284,
                "size": 13,
                "virtual": {"address": 4294983580},
            },
            {
                "alignment": 2,
                "entropy": mock.ANY,
                "name": "__unwind_info",
                "offset": 16300,
                "size": 72,
                "virtual": {"address": 4294983596},
            },
            {
                "alignment": 3,
                "entropy": mock.ANY,
                "name": "__got",
                "offset": 16384,
                "size": 8,
                "virtual": {"address": 4294983680},
            },
        ],
        "segments": [
            {
                "command": {"offset": 32, "size": 72, "type": "SEGMENT_64"},
                "file": {"offset": 0, "size": 0},
                "flags": 0,
                "protection": {"init": "---", "max": "---"},
                "name": "__PAGEZERO",
                "sections": [],
                "virtual": {"address": 0, "size": 4294967296},
            },
            {
                "command": {"offset": 104, "size": 392, "type": "SEGMENT_64"},
                "file": {"offset": 0, "size": 16384},
                "flags": 0,
                "protection": {"init": "r-x", "max": "r-x"},
                "name": "__TEXT",
                "sections": ["__text", "__stubs", "__cstring", "__unwind_info"],
                "virtual": {"address": 4294967296, "size": 16384},
            },
            {
                "command": {"offset": 496, "size": 152, "type": "SEGMENT_64"},
                "file": {"offset": 16384, "size": 16384},
                "flags": 16,
                "protection": {"init": "rw-", "max": "rw-"},
                "name": "__DATA_CONST",
                "sections": ["__got"],
                "virtual": {"address": 4294983680, "size": 16384},
            },
            {
                "command": {"offset": 648, "size": 72, "type": "SEGMENT_64"},
                "file": {"offset": 32768, "size": 248},
                "flags": 0,
                "protection": {"init": "r--", "max": "r--"},
                "name": "__LINKEDIT",
                "sections": [],
                "virtual": {"address": 4295000064, "size": 16384},
            },
        ],
        "symbols": {
            "exported": ["__mh_execute_header", "_main"],
            "imported": ["_printf"],
            "libraries": ["/usr/lib/libSystem.B.dylib"],
            "table": [
                {
                    "export": {"address": 0, "flags": 0},
                    "origin": "LC_SYMTAB",
                    "symbol": "__mh_execute_header",
                },
                {
                    "export": {"address": 16240, "flags": 0},
                    "origin": "LC_SYMTAB",
                    "symbol": "_main",
                },
                {
                    "binding": {
                        "address": 0,
                        "class": None,
                        "library": {
                            "name": "/usr/lib/libSystem.B.dylib",
                            "size": 56,
                            "timestamp": 2,
                            "version": {
                                "compatibility": "1.0.0",
                                "current": "1319.0.0",
                            },
                        },
                        "segment": "__DATA_CONST",
                        "type": None,
                        "weak_import": False,
                    },
                    "origin": "LC_SYMTAB",
                    "symbol": "_printf",
                },
            ],
        },
        "commands": {
            "commands": [
                "SEGMENT_64",
                "SEGMENT_64",
                "SEGMENT_64",
                "SEGMENT_64",
                "DYLD_CHAINED_FIXUPS",
                "DYLD_EXPORTS_TRIE",
                "SYMTAB",
                "DYSYMTAB",
                "LOAD_DYLINKER",
                "UUID",
                "BUILD_VERSION",
                "SOURCE_VERSION",
                "MAIN",
                "LOAD_DYLIB",
                "FUNCTION_STARTS",
                "DATA_IN_CODE",
            ],
            "data_in_code": {
                "command": {"offset": 1056, "size": 16},
                "data": {"offset": 32920, "size": 0},
                "entries": [],
            },
            "load_dylinker": {
                "command": {"offset": 856, "size": 32},
                "name": "/usr/lib/dyld",
            },
            "dynamic_symbol": {
                "command": {"offset": 776, "size": 80},
                "offset": {
                    "symbol": {"external": 0, "indirect": 32968},
                    "relocation": {"external": 0, "local": 0},
                    "table": {"module": 0},
                    "toc": 0,
                },
            },
            "function_starts": {
                "command": {"offset": 1040, "size": 16},
                "data": {"offset": 32912, "size": 8},
            },
            "main": {
                "command": {"offset": 960, "size": 24},
                "entry_point": 16240,
                "stack_size": 0,
            },
            "source_version": {
                "command": {"offset": 944, "size": 16},
                "version": "0.0.0.0.0",
            },
            "symbol": {
                "command": {"offset": 752, "size": 24},
                "strings": {"offset": 32976, "size": 40},
                "symbol": {"offset": 32920},
            },
            "uuid": {
                "command": {"offset": 888, "size": 24},
                "uuid": "3412979242375017913918719719156127234240",
            },
        },
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.macho",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
