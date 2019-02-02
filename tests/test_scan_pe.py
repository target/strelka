from pathlib import Path
import unittest
from urllib.request import urlretrieve

from server.objects import StrelkaFile
from server.scanners import scan_pe

class ScanPeTests(unittest.TestCase):
    ''' Test the ScanPE scanner '''
    @classmethod
    def setUpClass(self):
        ''' Initialize tests '''
        self.putty = Path(__file__).parent.joinpath("test_files", "putty.exe")
        self.source = "ScanPeTests"
        dl_link = "https://the.earth.li/~sgtatham/putty/0.70/w32/putty.exe"
        urlretrieve(dl_link, filename=str(self.putty))

    def setUp(self):
        ''' Each test gets a new scan '''
        self.options = {}
        self.scanner = scan_pe.ScanPe()
        self.scanner.children = []
        self.scanner.metadata = {}
        self.file_object = StrelkaFile(
            data=self.putty.read_bytes(),
            filename=self.putty.name,
            source=self.source
        )
        self.scanner.scan(self.file_object, self.options)

    @classmethod
    def tearDownClass(self):
        ''' Clean things up '''
        self.putty.unlink()

    def tearDown(self):
        ''' Clean up each test '''
        pass

    @unittest.skip("Need a PE file to test")
    def test_debug(self):
        self.assertIn("rsds", self.scanner.metadata, "Debug section not scanned")
        self.assertEqual(self.scanner.metadata["rsds"]["guid"], None, "Wrong GUID")
        self.assertEqual(self.scanner.metadata["rsds"]["age"], None, "Wrong age")
        self.assertEqual(self.scanner.metadata["rsds"]["pdb"], None, "Wrong PDB string")

    def test_debug_none(self):
        self.assertNotIn("rsds", self.scanner.metadata, "Debug section identified when one does not exist")

    @unittest.skip("Need a DLL to test")
    def test_exports(self):
        pass

    def test_exports_none(self):
        self.assertIn("exportFunctions", self.scanner.metadata, "Export functions not scanned")
        self.assertListEqual(self.scanner.metadata["exportFunctions"], [], "Export functions identified when none exist")

    def test_imphash(self):
        self.assertIn("imphash", self.scanner.metadata, "Imphash not calculated")
        self.assertEqual(self.scanner.metadata["imphash"], "63e5ceb1f07221fa9448d107ccf4ab5f", "Wrong imphash")

    def test_imports(self):
        self.assertIn("imports", self.scanner.metadata, "Import DLLs not scanned")
        import_dlls = self.scanner.metadata["imports"]
        expected = [b"GDI32.dll", b"USER32.dll", b"COMDLG32.dll", b"SHELL32.dll", b"ole32.dll", b"IMM32.dll", b"ADVAPI32.dll", b"KERNEL32.dll"]
        self.assertListEqual(sorted(expected), sorted(import_dlls), "Wrong imported DLLs identified")
        self.assertIn("importFunctions", self.scanner.metadata, "Import functions not scanned")
        self.assertEqual(len(self.scanner.metadata["importFunctions"]), 8, "Wrong number of imports identified")
        import_functions = [len(i["functions"]) for i in self.scanner.metadata["importFunctions"]]
        expected = [46, 112, 4, 1, 3, 5, 17, 127]
        self.assertListEqual(sorted(expected), sorted(import_functions), "Wrong number of imported functions identified")

    def test_file_header(self):
        self.assertEqual(self.scanner.metadata["machine"]["id"], 332, "Wrong machine id")
        self.assertEqual(self.scanner.metadata["machine"]["type"], "IMAGE_FILE_MACHINE_I386", "Wrong machine type")
        self.assertEqual(self.scanner.metadata["timestamp"], "1970-01-01T00:00:00", "Wrong timestamp")
        expected = [
            "IMAGE_FILE_EXECUTABLE_IMAGE",
            "IMAGE_FILE_32BIT_MACHINE"
        ]
        ic = self.scanner.metadata["imageCharacteristics"]
        self.assertListEqual(sorted(expected), sorted(ic), "Image characteristics were not properly extracted")
        expected = [
            "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE",
            "IMAGE_DLLCHARACTERISTICS_NO_BIND",
            "IMAGE_DLLCHARACTERISTICS_NX_COMPAT",
            "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE"
        ]
        dc = self.scanner.metadata["dllCharacteristics"]
        self.assertListEqual(sorted(expected), sorted(dc), "DLL characteristics were not properly extracted")

    def test_optional_header(self):
        self.assertIn("entryPoint", self.scanner.metadata, "entryPoint not scanned")
        self.assertEqual(self.scanner.metadata["entryPoint"], 622550, "Wrong entrypoint")
        self.assertIn("imageMagic", self.scanner.metadata, "imageMagic not scanned")
        self.assertEqual(self.scanner.metadata["imageMagic"], "32_BIT", "Wrong magic")
        self.assertIn("imageBase", self.scanner.metadata, "imageBase not scanned")
        self.assertEqual(self.scanner.metadata["imageBase"], 4194304, "Wrong image base")
        self.assertIn("subsystem", self.scanner.metadata, "subsystem not scanned")
        self.assertEqual(self.scanner.metadata["subsystem"], "IMAGE_SUBSYSTEM_WINDOWS_GUI", "Wrong subsystem")
        self.assertIn("stackReserveSize", self.scanner.metadata, "stackReserveSize not scanned")
        self.assertEqual(self.scanner.metadata["stackReserveSize"], 1048576, "Wrong stack reserve size")
        self.assertIn("stackCommitSize", self.scanner.metadata, "stackCommitSize not scanned")
        self.assertEqual(self.scanner.metadata["stackCommitSize"], 4096, "Wrong stack commit size")
        self.assertIn("heapReserveSize", self.scanner.metadata, "heapReserveSize not scanned")
        self.assertEqual(self.scanner.metadata["heapReserveSize"], 1048576, "Wrong heap reserve size")
        self.assertIn("heapCommitSize", self.scanner.metadata, "heapCommitSize not scanned")
        self.assertEqual(self.scanner.metadata["heapCommitSize"], 4096, "Wrong heap commit size")

    def test_resources(self):
        self.assertIn("resources", self.scanner.metadata, "Resources were not scanned")
        self.assertEqual(len(self.scanner.metadata["resources"]), 20, "Wrong number of resources extracted")
        # too many to check each one attribute - only do a few of them
        for resource in self.scanner.metadata["resources"]:
            self.assertEqual(resource["id"], 1033, "Wrong resource id")
            self.assertEqual(resource["name"], "IMAGE_RESOURCE_DATA_ENTRY", "Wrong resource name")
            self.assertEqual(resource["subLanguage"], "SUBLANG_ENGLISH_US", "Wrong resource language")

    @unittest.skip("Need a PE file to test")
    def test_resources_none(self):
        self.assertIn("resources", self.scanner.metadata, "Resources were not scanned")
        self.assertListEqual(self.scanner.metadata["resources"], [], "Wrong number of resources extracted")
        self.assertIn(f"{self.scanner.scanner_name}::no_resources", self.file_object.flags, "Flag not properly applied")

    def test_sections(self):
        self.assertIn("sections", self.scanner.metadata, "Sections were not scanned")
        sections = self.scanner.metadata["sections"]
        self.assertEqual(self.scanner.metadata["total"]["sections"], 10, "Wrong number of sections extracted")
        self.assertEqual(self.scanner.metadata["total"]["sections"], len(sections), "Section list length and total counted sections do not match")
        section_names = [i["name"] for i in sections]
        expected = [".00cfg", ".rdata", ".bss", ".data", ".gfids", ".rsrc", ".text", ".xdata", ".idata", ".reloc"]
        self.assertListEqual(sorted(expected), sorted(section_names), "Wrong section name")
        for section in sections:
            self.assertEqual("IMAGE_SECTION_HEADER", section["structure"], "Section structure should be of type 'IMAGE_SECTION_HEADER'")

    def test_signature(self):
        child_names = [c.filename for c in self.scanner.children]
        self.assertIn(f"{self.scanner.scanner_name}::digital_signature", child_names, "Digital signature not extracted")
        self.assertIn(f"{self.scanner.scanner_name}::signed", self.file_object.flags, "Flag not properly applied")

    @unittest.skip("Need a PE file to test")
    def test_signature_empty(self):
        self.assertIn(f"{self.scanner.scanner_name}::empty_signature", self.file_object.flags, "Flag not properly applied")

    @unittest.skip("Need a PE file to test")
    def test_signature_none(self):
        self.assertNotIn(f"{self.scanner.scanner_name}::empty_signature", self.file_object.flags, "Flag not properly applied")
        self.assertNotIn(f"{self.scanner.scanner_name}::signed", self.file_object.flags, "Flag not properly applied")

    def test_version_info(self):
        self.assertIn("versionInfo", self.scanner.metadata, "Version info was not scanned")
        # only these entries should exist
        # the test will fail if more or less entries are extracted
        expected = {
            "CompanyName": "Simon Tatham",
            "ProductName": "PuTTY suite",
            "FileDescription": "SSH, Telnet and Rlogin client",
            "InternalName": "PuTTY",
            "OriginalFilename": "PuTTY",
            "FileVersion": "Release 0.70",
            "ProductVersion": "Release 0.70",
            "LegalCopyright": "Copyright \u00a9 1997-2017 Simon Tatham."
        }
        version_info = {}
        for entry in self.scanner.metadata["versionInfo"]:
            version_info[entry["name"]] = entry["value"]
        self.assertDictEqual(expected, version_info, "Version info not properly extracted")

    @unittest.skip("Need a PE file to test")
    def test_version_info_none(self):
        self.assertIn("versionInfo", self.scanner.metadata, "Version info was not scanned")
        self.assertListEqual([], self.scanner.metadata, "Version info included when none exist")
        self.assertIn(f"{self.scanner.scanner_name}::no_version_info", self.file_object.flags, "Flag not properly applied")

    @unittest.skip("Need a PE file to test")
    def test_warnings(self):
        pass

    def test_warnings_none(self):
        self.assertIn("warnings", self.scanner.metadata, "PE warnings not scanned")
        self.assertListEqual([], self.scanner.metadata["warnings"], "PE warnings included when none exist")


if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(ScanPeTests)
    runner = unittest.TextTestRunner(verbosity=2)
    results = runner.run(suite)
    FAILED = 0
    FAILED += len(results.failures)
    FAILED += len(results.errors)
    FAILED += len(results.skipped)
    pct_coverage = (results.testsRun - FAILED) / results.testsRun
    print("ScanPe test coverage: {:.1f}%".format(pct_coverage * 100))
