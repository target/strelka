from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_strings import ScanStrings as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_strings(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "strings": [
            b"!This program cannot be run in DOS mode.",
            b".text",
            b"`.rsrc",
            b"*BSJB",
            b"v4.0.30319",
            b"#Strings",
            b"#GUID",
            b"#Blob",
            b"<Module>",
            b"mscorlib",
            b"HelloWorld",
            b"Console",
            b"WriteLine",
            b"GuidAttribute",
            b"DebuggableAttribute",
            b"ComVisibleAttribute",
            b"AssemblyTitleAttribute",
            b"AssemblyTrademarkAttribute",
            b"TargetFrameworkAttribute",
            b"AssemblyFileVersionAttribute",
            b"AssemblyConfigurationAttribute",
            b"AssemblyDescriptionAttribute",
            b"CompilationRelaxationsAttribute",
            b"AssemblyProductAttribute",
            b"AssemblyCopyrightAttribute",
            b"AssemblyCompanyAttribute",
            b"RuntimeCompatibilityAttribute",
            b"HelloWorld.exe",
            b"System.Runtime.Versioning",
            b"Program",
            b"System",
            b"Main",
            b"System.Reflection",
            b".ctor",
            b"System.Diagnostics",
            b"System.Runtime.InteropServices",
            b"System.Runtime.CompilerServices",
            b"DebuggingModes",
            b"args",
            b"Object",
            b"WrapNonExceptionThrows",
            b"HelloWorld",
            b"Copyright ",
            b" . 2020",
            b"$c66634a4-f119-4236-b8d2-a085d40e57c7",
            b"1.0.0.0",
            b".NETFramework,Version=v4.0",
            b"FrameworkDisplayName",
            b".NET Framework 4",
            b"RSDS",
            b"C:\\Users\\tmcguff\\source\\repos\\HelloWorld\\HelloWorld\\obj\\x64\\Release\\HelloWorld.pdb",
            b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
            b'<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">',
            b'  <assemblyIdentity version="1.0.0.0" name="MyApplication.app"/>',
            b'  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v2">',
            b"    <security>",
            b'      <requestedPrivileges xmlns="urn:schemas-microsoft-com:asm.v3">',
            b'        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>',
            b"      </requestedPrivileges>",
            b"    </security>",
            b"  </trustInfo>",
            b"</assembly>",
        ],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.exe",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
