from pathlib import Path
import unittest

from server.objects import StrelkaFile
from server.scanners import scan_pe

class ScanPeTests(unittest.TestCase):
    ''' Test the ScanPE scanner '''
    @classmethod
    def setUpClass(self):
        ''' Initialize tests '''
        self.test_binary = Path(__file__).parent.joinpath("test_files", "test_binary.exe")
        self.chrome = Path(__file__).parent.joinpath("test_files", "ChromeSetup.exe")
        self.source = "ScanPeTests"

    def setUp(self):
        ''' Each test gets a new scanner '''
        self.options = {}
        self.scanner = scan_pe.ScanPe()
        self.scanner.children = []
        self.scanner.metadata = {}

    @classmethod
    def tearDownClass(self):
        ''' Clean things up '''
        pass

    def tearDown(self):
        ''' Clean up each test '''
        pass

    def test_debug(self):
        file_object = StrelkaFile(
            data=self.chrome.read_bytes(),
            filename=self.chrome.name,
            source=self.source
        )
        self.scanner.scan(file_object, self.options)
        self.assertIn("rsds", self.scanner.metadata, "Debug section not scanned")
        self.assertEqual(self.scanner.metadata["rsds"]["guid"], b"185388e5-378c-f84c-918fa31a1228f84c", "Wrong GUID")
        self.assertEqual(self.scanner.metadata["rsds"]["age"], 1, "Wrong age")
        self.assertEqual(self.scanner.metadata["rsds"]["pdb"], b"mi_exe_stub.pdb", "Wrong PDB string")

    def test_no_debug(self):
        file_object = StrelkaFile(
            data=self.test_binary.read_bytes(),
            filename=self.test_binary.name,
            source=self.source
        )
        self.scanner.scan(file_object, self.options)
        self.assertNotIn("rsds", self.scanner.metadata, "Debug section identified when one does not exist")

    @unittest.skip("Need a DLL to test")
    def test_exports(self):
        pass

    def test_no_exports(self):
        file_object = StrelkaFile(
            data=self.test_binary.read_bytes(),
            filename=self.test_binary.name,
            source=self.source
        )
        self.scanner.scan(file_object, self.options)
        self.assertIn("exportFunctions", self.scanner.metadata, "Export functions not scanned")
        self.assertListEqual(self.scanner.metadata["exportFunctions"], [], "Export functions identified when none exist")

    def test_imphash(self):
        file_object = StrelkaFile(
            data=self.test_binary.read_bytes(),
            filename=self.test_binary.name,
            source=self.source
        )
        self.scanner.scan(file_object, self.options)
        self.assertIn("imphash", self.scanner.metadata, "Imphash not calculated")
        self.assertEqual(self.scanner.metadata["imphash"], "1e2002a1b2a216e0a2480e2c29f9d102", "Wrong imphash")

    def test_imports(self):
        file_object = StrelkaFile(
            data=self.test_binary.read_bytes(),
            filename=self.test_binary.name,
            source=self.source
        )
        self.scanner.scan(file_object, self.options)
        self.assertIn("imports", self.scanner.metadata, "Import DLLs not scanned")
        self.assertListEqual(self.scanner.metadata["imports"], [b"KERNEL32.dll"], "Wrong import DLL identified")
        self.assertIn("importFunctions", self.scanner.metadata, "Import functions not scanned")
        self.assertEqual(len(self.scanner.metadata["importFunctions"]), 1, "Wrong number of imports identified")
        imported = self.scanner.metadata["importFunctions"][0]
        # too many to check each one
        self.assertEqual(len(imported["functions"]), 66, "Wrong number of import functions extracted")

    def test_file_header(self):
        file_object = StrelkaFile(
            data=self.test_binary.read_bytes(),
            filename=self.test_binary.name,
            source=self.source
        )
        self.scanner.scan(file_object, self.options)
        self.assertEqual(self.scanner.metadata["machine"]["id"], 332, "Wrong machine id")
        self.assertEqual(self.scanner.metadata["machine"]["type"], "IMAGE_FILE_MACHINE_I386", "Wrong machine type")
        self.assertEqual(self.scanner.metadata["timestamp"], "2019-01-24T16:00:36", "Wrong timestamp")
        image_characteristics = [
            "IMAGE_FILE_EXECUTABLE_IMAGE",
            "IMAGE_FILE_32BIT_MACHINE"
        ]
        self.assertListEqual(self.scanner.metadata["imageCharacteristics"], image_characteristics, "Image characteristics were not properly extracted")
        dll_characteristics = [
            "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE",
            "IMAGE_DLLCHARACTERISTICS_NX_COMPAT",
            "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE"
        ]
        self.assertListEqual(self.scanner.metadata["dllCharacteristics"], dll_characteristics, "DLL characteristics were not properly extracted")

    def test_optional_header(self):
        file_object = StrelkaFile(
            data=self.test_binary.read_bytes(),
            filename=self.test_binary.name,
            source=self.source
        )
        self.scanner.scan(file_object, self.options)
        self.assertIn("entryPoint", self.scanner.metadata, "entryPoint not scanned")
        self.assertEqual(self.scanner.metadata["entryPoint"], 4833, "Wrong entrypoint")
        self.assertIn("imageMagic", self.scanner.metadata, "imageMagic not scanned")
        self.assertEqual(self.scanner.metadata["imageMagic"], "32_BIT", "Wrong magic")
        self.assertIn("imageBase", self.scanner.metadata, "imageBase not scanned")
        self.assertEqual(self.scanner.metadata["imageBase"], 4194304, "Wrong image base")
        self.assertIn("subsystem", self.scanner.metadata, "subsystem not scanned")
        self.assertEqual(self.scanner.metadata["subsystem"], "IMAGE_SUBSYSTEM_WINDOWS_CUI", "Wrong subsystem")
        self.assertIn("stackReserveSize", self.scanner.metadata, "stackReserveSize not scanned")
        self.assertEqual(self.scanner.metadata["stackReserveSize"], 1048576, "Wrong stack reserve size")
        self.assertIn("stackCommitSize", self.scanner.metadata, "stackCommitSize not scanned")
        self.assertEqual(self.scanner.metadata["stackCommitSize"], 4096, "Wrong stack commit size")
        self.assertIn("heapReserveSize", self.scanner.metadata, "heapReserveSize not scanned")
        self.assertEqual(self.scanner.metadata["heapReserveSize"], 1048576, "Wrong heap reserve size")
        self.assertIn("heapCommitSize", self.scanner.metadata, "heapCommitSize not scanned")
        self.assertEqual(self.scanner.metadata["heapCommitSize"], 4096, "Wrong heap commit size")

    def test_resources(self):
        file_object = StrelkaFile(
            data=self.chrome.read_bytes(),
            filename=self.chrome.name,
            source=self.source
        )
        self.scanner.scan(file_object, self.options)
        self.assertIn("resources", self.scanner.metadata, "Resources were not scanned")
        # too many to check each one
        self.assertEqual(len(self.scanner.metadata["resources"]), 66, "Wrong number of resources extracted")

    def test_no_resources(self):
        file_object = StrelkaFile(
            data=self.test_binary.read_bytes(),
            filename=self.test_binary.name,
            source=self.source
        )
        self.scanner.scan(file_object, self.options)
        self.assertIn("resources", self.scanner.metadata, "Resources were not scanned")
        self.assertListEqual(self.scanner.metadata["resources"], [], "Wrong number of resources extracted")
        self.assertIn(f"{self.scanner.scanner_name}::no_resources", file_object.flags, "Flag not properly applied")

    def test_sections(self):
        file_object = StrelkaFile(
            data=self.test_binary.read_bytes(),
            filename=self.test_binary.name,
            source=self.source
        )
        self.scanner.scan(file_object, self.options)
        self.assertIn("sections", self.scanner.metadata, "Sections were not scanned")
        self.assertEqual(self.scanner.metadata["total"]["sections"], 4, "Wrong number of sections extracted")
        self.assertEqual(self.scanner.metadata["total"]["sections"], len(self.scanner.metadata["sections"]), "Section list length and total counted sections do not match")
        section_names = [i["name"] for i in self.scanner.metadata["sections"]]
        self.assertListEqual(sorted([".text", ".rdata", ".data", ".reloc"]), sorted(section_names), "Wrong section name")
        for i in self.scanner.metadata["sections"]:
            self.assertEqual("IMAGE_SECTION_HEADER", i["structure"], "Section structure should be of type 'IMAGE_SECTION_HEADER'")

    def test_signature(self):
        file_object = StrelkaFile(
            data=self.chrome.read_bytes(),
            filename=self.chrome.name,
            source=self.source
        )
        self.scanner.scan(file_object, self.options)
        child_names = [c.filename for c in self.scanner.children]
        self.assertIn(f"{self.scanner.scanner_name}::digital_signature", child_names, "Digital signature not extracted")
        self.assertIn(f"{self.scanner.scanner_name}::signed", file_object.flags, "Flag not properly applied")

    @unittest.skip("Need a PE file with an empty digital signature to test")
    def test_signature(self):
        pass

    def test_no_signature(self):
        file_object = StrelkaFile(
            data=self.test_binary.read_bytes(),
            filename=self.test_binary.name,
            source=self.source
        )
        self.scanner.scan(file_object, self.options)
        self.assertNotIn(f"{self.scanner.scanner_name}::empty_signature", file_object.flags, "Flag not properly applied")
        self.assertNotIn(f"{self.scanner.scanner_name}::digital_signature", file_object.flags, "Flag not properly applied")

    def test_version_info(self):
        file_object = StrelkaFile(
            data=self.chrome.read_bytes(),
            filename=self.chrome.name,
            source=self.source
        )
        self.scanner.scan(file_object, self.options)
        self.assertIn("versionInfo", self.scanner.metadata, "Version info was not scanned")
        self.assertEqual(self.scanner.metadata["versionInfo"]["CompanyName"], "Google Inc.", "Wrong CompanyName")
        self.assertEqual(self.scanner.metadata["versionInfo"]["FileDescription"], "Google Update Setup", "Wrong FileDescription")
        self.assertEqual(self.scanner.metadata["versionInfo"]["FileVersion"], "1.3.33.23", "Wrong FileVersion")
        self.assertEqual(self.scanner.metadata["versionInfo"]["InternalName"], "Google Update Setup", "Wrong InternalName")
        self.assertEqual(self.scanner.metadata["versionInfo"]["LegalCopyright"], "Copyright 2007-2010 Google Inc.", "Wrong LegalCopyright")
        self.assertEqual(self.scanner.metadata["versionInfo"]["OriginalFilename"], "GoogleUpdateSetup.exe", "Wrong OriginalFilename")
        self.assertEqual(self.scanner.metadata["versionInfo"]["ProductName"], "Google Update", "Wrong ProductName")
        self.assertEqual(self.scanner.metadata["versionInfo"]["ProductVersion"], "1.3.33.23", "Wrong ProductVersion")
        self.assertEqual(self.scanner.metadata["versionInfo"]["LanguageId"], "en", "Wrong LanguageId")

    def test_no_version_info(self):
        file_object = StrelkaFile(
            data=self.test_binary.read_bytes(),
            filename=self.test_binary.name,
            source=self.source
        )
        self.scanner.scan(file_object, self.options)
        self.assertNotIn("versionInfo", self.scanner.metadata, "Version info identified when none exist")
        self.assertIn(f"{self.scanner.scanner_name}::no_version_info", file_object.flags, "Flag not properly applied")

    @unittest.skip("Need a PE file to test")
    def test_warnings(self):
        pass

    def test_no_warnings(self):
        file_object = StrelkaFile(
            data=self.test_binary.read_bytes(),
            filename=self.test_binary.name,
            source=self.source
        )
        self.scanner.scan(file_object, self.options)
        self.assertIn("warnings", self.scanner.metadata, "PE warnings not scanned")
        self.assertListEqual(self.scanner.metadata["warnings"], [], "PE warnings included when none exist")


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
