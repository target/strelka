from pathlib import Path
from unittest import TestCase, mock

from pytest_unordered import unordered

from strelka.scanners.scan_pe import ScanPe as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_pe(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": ["no_certs_found"],
        "total": {"libraries": 0, "resources": 2, "sections": 2, "symbols": 0},
        "summary": {
            "resource_md5": unordered(
                [
                    "f4741884351459aa7733725b88e693af",
                    "b7db84991f23a680df8e95af8946f9c9",
                ]
            ),
            "resource_sha1": unordered(
                [
                    "5371904ee7671fb0b066d9323eda553269f344f9",
                    "cac699787884fb993ced8d7dc47b7c522c7bc734",
                ]
            ),
            "resource_sha256": unordered(
                [
                    "539dc26a14b6277e87348594ab7d6e932d16aabb18612d77f29fe421a9f1d46a",
                    "d8df3d0358a91b3ef97c4d472b34a60f7cf9ee7f1a6f37058fc3d1af3a156a36",
                ]
            ),
            "section_md5": unordered(
                [
                    "c3eafa2cd34f98a226e31b8ea3fea400",
                    "cc14da7fb94ef9b27a926fe95b86b44f",
                ]
            ),
            "section_sha1": unordered(
                [
                    "3d584b265a558dc22fa6dfa9991ae7eafee5c1a4",
                    "00104b432a8e7246695843e4f2d7cf2582efa3e6",
                ]
            ),
            "section_sha256": unordered(
                [
                    "86d9755b2ba9d8ffd765621f09844dd62d0b082fdc4aafa63b3b3f3ae25d9c77",
                    "bb31a5224e9f78905909655d9c80ba7d63f03910e4f22b296d6b7865e2a477c3",
                ]
            ),
        },
        "debug": {
            "type": "rsds",
            "guid": b"a66307d0-9b84-b944-bf030bff2d7d1e4a",
            "age": 1,
            "pdb": b"C:\\Users\\tmcguff\\source\\repos\\HelloWorld\\HelloWorld\\obj\\x64\\Release\\HelloWorld.pdb",
        },
        "file_info": {
            "fixed": {
                "flags": [],
                "operating_systems": ["WINDOWS32"],
                "type": {"primary": "APP", "sub": ""},
            },
            "string": [],
            "var": {"language": None, "character_set": "Unicode"},
            "comments": "",
            "company_name": ".",
            "file_description": "HelloWorld",
            "file_version": "1.0.0.0",
            "internal_name": "HelloWorld.exe",
            "legal_copyright": "Copyright © . 2020",
            "legal_trademarks": "",
            "original_filename": "HelloWorld.exe",
            "product_name": "HelloWorld",
            "product_version": "1.0.0.0",
            "assembly_version": "1.0.0.0",
        },
        "header": {
            "machine": {"id": 34404, "type": "AMD64"},
            "magic": {"dos": "DOS", "image": "64_BIT"},
            "subsystem": "WINDOWS_CUI",
        },
        "base_of_code": 8192,
        "address_of_entry_point": 0,
        "image_base": 5368709120,
        "size_of_code": 2048,
        "size_of_initialized_data": 1536,
        "size_of_headers": 512,
        "size_of_heap_reserve": 1048576,
        "size_of_image": 24576,
        "size_of_stack_commit": 16384,
        "size_of_stack_reserve": 4194304,
        "size_of_heap_commit": 8192,
        "size_of_uninitialized_data": 0,
        "file_alignment": 512,
        "section_alignment": 8192,
        "checksum": 0,
        "major_image_version": 0,
        "minor_image_version": 0,
        "major_linker_version": 48,
        "minor_linker_version": 0,
        "major_operating_system_version": 4,
        "minor_operating_system_version": 0,
        "major_subsystem_version": 4,
        "minor_subsystem_version": 0,
        "image_version": 0.0,
        "linker_version": 48.0,
        "operating_system_version": 4.0,
        "subsystem_version": 4.0,
        "compile_time": "2104-07-18T17:22:04",
        "dll_characteristics": unordered(
            [
                "DYNAMIC_BASE",
                "NX_COMPAT",
                "NO_SEH",
                "TERMINAL_SERVER_AWARE",
            ]
        ),
        "image_characteristics": unordered(["EXECUTABLE_IMAGE", "LARGE_ADDRESS_AWARE"]),
        "resources": unordered(
            [
                {
                    "id": 1,
                    "language": {"sub": "NEUTRAL", "primary": "NEUTRAL"},
                    "type": "VERSION",
                    "md5": "f4741884351459aa7733725b88e693af",
                    "sha1": "5371904ee7671fb0b066d9323eda553269f344f9",
                    "sha256": "d8df3d0358a91b3ef97c4d472b34a60f7cf9ee7f1a6f37058fc3d1af3a156a36",
                },
                {
                    "id": 1,
                    "language": {"sub": "NEUTRAL", "primary": "NEUTRAL"},
                    "type": "MANIFEST",
                    "md5": "b7db84991f23a680df8e95af8946f9c9",
                    "sha1": "cac699787884fb993ced8d7dc47b7c522c7bc734",
                    "sha256": "539dc26a14b6277e87348594ab7d6e932d16aabb18612d77f29fe421a9f1d46a",
                },
            ]
        ),
        "sections": unordered(
            [
                {
                    "address": {"physical": 1743, "virtual": 8192},
                    "characteristics": ["CNT_CODE", "MEM_EXECUTE", "MEM_READ"],
                    "entropy": 4.621214196319175,
                    "name": ".text",
                    "size": 2048,
                    "md5": "cc14da7fb94ef9b27a926fe95b86b44f",
                    "sha1": "3d584b265a558dc22fa6dfa9991ae7eafee5c1a4",
                    "sha256": "bb31a5224e9f78905909655d9c80ba7d63f03910e4f22b296d6b7865e2a477c3",
                },
                {
                    "address": {"physical": 1472, "virtual": 16384},
                    "characteristics": ["CNT_INITIALIZED_DATA", "MEM_READ"],
                    "entropy": 4.09070377434219,
                    "name": ".rsrc",
                    "size": 1536,
                    "md5": "c3eafa2cd34f98a226e31b8ea3fea400",
                    "sha1": "00104b432a8e7246695843e4f2d7cf2582efa3e6",
                    "sha256": "86d9755b2ba9d8ffd765621f09844dd62d0b082fdc4aafa63b3b3f3ae25d9c77",
                },
            ]
        ),
        "symbols": {"exported": [], "imported": [], "libraries": [], "table": []},
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.exe",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_pe_overlay(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": ["no_certs_found", "overlay"],
        "total": {"libraries": 0, "resources": 2, "sections": 2, "symbols": 0},
        "summary": {
            "resource_md5": unordered(
                [
                    "f4741884351459aa7733725b88e693af",
                    "b7db84991f23a680df8e95af8946f9c9",
                ]
            ),
            "resource_sha1": unordered(
                [
                    "5371904ee7671fb0b066d9323eda553269f344f9",
                    "cac699787884fb993ced8d7dc47b7c522c7bc734",
                ]
            ),
            "resource_sha256": unordered(
                [
                    "539dc26a14b6277e87348594ab7d6e932d16aabb18612d77f29fe421a9f1d46a",
                    "d8df3d0358a91b3ef97c4d472b34a60f7cf9ee7f1a6f37058fc3d1af3a156a36",
                ]
            ),
            "section_md5": unordered(
                [
                    "c3eafa2cd34f98a226e31b8ea3fea400",
                    "cc14da7fb94ef9b27a926fe95b86b44f",
                ]
            ),
            "section_sha1": unordered(
                [
                    "3d584b265a558dc22fa6dfa9991ae7eafee5c1a4",
                    "00104b432a8e7246695843e4f2d7cf2582efa3e6",
                ]
            ),
            "section_sha256": unordered(
                [
                    "86d9755b2ba9d8ffd765621f09844dd62d0b082fdc4aafa63b3b3f3ae25d9c77",
                    "bb31a5224e9f78905909655d9c80ba7d63f03910e4f22b296d6b7865e2a477c3",
                ]
            ),
        },
        "debug": {
            "type": "rsds",
            "guid": b"a66307d0-9b84-b944-bf030bff2d7d1e4a",
            "age": 1,
            "pdb": b"C:\\Users\\tmcguff\\source\\repos\\HelloWorld\\HelloWorld\\obj\\x64\\Release\\HelloWorld.pdb",
        },
        "file_info": {
            "fixed": {
                "flags": [],
                "operating_systems": ["WINDOWS32"],
                "type": {"primary": "APP", "sub": ""},
            },
            "string": [],
            "var": {"language": None, "character_set": "Unicode"},
            "comments": "",
            "company_name": ".",
            "file_description": "HelloWorld",
            "file_version": "1.0.0.0",
            "internal_name": "HelloWorld.exe",
            "legal_copyright": "Copyright © . 2020",
            "legal_trademarks": "",
            "original_filename": "HelloWorld.exe",
            "product_name": "HelloWorld",
            "product_version": "1.0.0.0",
            "assembly_version": "1.0.0.0",
        },
        "header": {
            "machine": {"id": 34404, "type": "AMD64"},
            "magic": {"dos": "DOS", "image": "64_BIT"},
            "subsystem": "WINDOWS_CUI",
        },
        "base_of_code": 8192,
        "address_of_entry_point": 0,
        "image_base": 5368709120,
        "size_of_code": 2048,
        "size_of_initialized_data": 1536,
        "size_of_headers": 512,
        "size_of_heap_reserve": 1048576,
        "size_of_image": 24576,
        "size_of_stack_commit": 16384,
        "size_of_stack_reserve": 4194304,
        "size_of_heap_commit": 8192,
        "size_of_uninitialized_data": 0,
        "file_alignment": 512,
        "section_alignment": 8192,
        "checksum": 0,
        "major_image_version": 0,
        "minor_image_version": 0,
        "major_linker_version": 48,
        "minor_linker_version": 0,
        "major_operating_system_version": 4,
        "minor_operating_system_version": 0,
        "major_subsystem_version": 4,
        "minor_subsystem_version": 0,
        "image_version": 0.0,
        "linker_version": 48.0,
        "operating_system_version": 4.0,
        "overlay": {"extracted": True, "size": 6442},
        "subsystem_version": 4.0,
        "compile_time": "2104-07-18T17:22:04",
        "dll_characteristics": unordered(
            [
                "DYNAMIC_BASE",
                "NX_COMPAT",
                "NO_SEH",
                "TERMINAL_SERVER_AWARE",
            ]
        ),
        "image_characteristics": unordered(["EXECUTABLE_IMAGE", "LARGE_ADDRESS_AWARE"]),
        "resources": unordered(
            [
                {
                    "id": 1,
                    "language": {"sub": "NEUTRAL", "primary": "NEUTRAL"},
                    "type": "VERSION",
                    "md5": "f4741884351459aa7733725b88e693af",
                    "sha1": "5371904ee7671fb0b066d9323eda553269f344f9",
                    "sha256": "d8df3d0358a91b3ef97c4d472b34a60f7cf9ee7f1a6f37058fc3d1af3a156a36",
                },
                {
                    "id": 1,
                    "language": {"sub": "NEUTRAL", "primary": "NEUTRAL"},
                    "type": "MANIFEST",
                    "md5": "b7db84991f23a680df8e95af8946f9c9",
                    "sha1": "cac699787884fb993ced8d7dc47b7c522c7bc734",
                    "sha256": "539dc26a14b6277e87348594ab7d6e932d16aabb18612d77f29fe421a9f1d46a",
                },
            ]
        ),
        "sections": unordered(
            [
                {
                    "address": {"physical": 1743, "virtual": 8192},
                    "characteristics": ["CNT_CODE", "MEM_EXECUTE", "MEM_READ"],
                    "entropy": 4.621214196319175,
                    "name": ".text",
                    "size": 2048,
                    "md5": "cc14da7fb94ef9b27a926fe95b86b44f",
                    "sha1": "3d584b265a558dc22fa6dfa9991ae7eafee5c1a4",
                    "sha256": "bb31a5224e9f78905909655d9c80ba7d63f03910e4f22b296d6b7865e2a477c3",
                },
                {
                    "address": {"physical": 1472, "virtual": 16384},
                    "characteristics": ["CNT_INITIALIZED_DATA", "MEM_READ"],
                    "entropy": 4.09070377434219,
                    "name": ".rsrc",
                    "size": 1536,
                    "md5": "c3eafa2cd34f98a226e31b8ea3fea400",
                    "sha1": "00104b432a8e7246695843e4f2d7cf2582efa3e6",
                    "sha256": "86d9755b2ba9d8ffd765621f09844dd62d0b082fdc4aafa63b3b3f3ae25d9c77",
                },
            ]
        ),
        "symbols": {"exported": [], "imported": [], "libraries": [], "table": []},
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_overlay_zip.exe",
        options={
            "extract_overlay": True,
        },
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
