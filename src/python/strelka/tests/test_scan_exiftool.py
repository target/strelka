from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_exiftool import ScanExiftool as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_exiftool_doc(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "keys": [
            {"key": "SourceFile", "value": mock.ANY},
            {"key": "ExifToolVersion", "value": 12.52},
            {"key": "FileName", "value": mock.ANY},
            {"key": "Directory", "value": mock.ANY},
            {"key": "FileSize", "value": "51 kB"},
            {"key": "FileModifyDate", "value": mock.ANY},
            {"key": "FileAccessDate", "value": mock.ANY},
            {"key": "FileInodeChangeDate", "value": mock.ANY},
            {"key": "FilePermissions", "value": "-rw-------"},
            {"key": "FileType", "value": "DOC"},
            {"key": "FileTypeExtension", "value": "doc"},
            {"key": "MIMEType", "value": "application/msword"},
            {"key": "Identification", "value": "Word 8.0"},
            {"key": "LanguageCode", "value": "English (US)"},
            {"key": "DocFlags", "value": "Has picture, 1Table, ExtChar"},
            {"key": "System", "value": "Windows"},
            {"key": "Word97", "value": "No"},
            {"key": "Title", "value": ""},
            {"key": "Subject", "value": ""},
            {"key": "Author", "value": "Ryan.OHoro"},
            {"key": "Keywords", "value": ""},
            {"key": "Comments", "value": ""},
            {"key": "Template", "value": "Normal.dotm"},
            {"key": "LastModifiedBy", "value": "Ryan.OHoro"},
            {"key": "Software", "value": "Microsoft Office Word"},
            {"key": "CreateDate", "value": mock.ANY},
            {"key": "ModifyDate", "value": mock.ANY},
            {"key": "Security", "value": None},
            {"key": "CodePage", "value": "Windows Latin 1 (Western European)"},
            {"key": "Company", "value": "Target Corporation"},
            {"key": "CharCountWithSpaces", "value": 2877},
            {"key": "AppVersion", "value": 16.0},
            {"key": "ScaleCrop", "value": "No"},
            {"key": "LinksUpToDate", "value": "No"},
            {"key": "SharedDoc", "value": "No"},
            {"key": "HyperlinksChanged", "value": "No"},
            {"key": "TitleOfParts", "value": ""},
            {"key": "HeadingPairs", "value": ["Title", 1]},
            {"key": "CompObjUserTypeLen", "value": 32},
            {"key": "CompObjUserType", "value": "Microsoft Word 97-2003 Document"},
            {"key": "LastPrinted", "value": "0000:00:00 00:00:00"},
            {"key": "RevisionNumber", "value": 2},
            {"key": "TotalEditTime", "value": "1 minute"},
            {"key": "Words", "value": 430},
            {"key": "Characters", "value": 2452},
            {"key": "Pages", "value": 1},
            {"key": "Paragraphs", "value": 5},
            {"key": "Lines", "value": 20},
        ],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.doc",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_exiftool_jpg(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "keys": [
            {"key": "SourceFile", "value": mock.ANY},
            {"key": "ExifToolVersion", "value": 12.52},
            {"key": "FileName", "value": mock.ANY},
            {"key": "Directory", "value": mock.ANY},
            {"key": "FileSize", "value": "309 kB"},
            {"key": "FileModifyDate", "value": mock.ANY},
            {"key": "FileAccessDate", "value": mock.ANY},
            {"key": "FileInodeChangeDate", "value": mock.ANY},
            {"key": "FilePermissions", "value": "-rw-------"},
            {"key": "FileType", "value": "JPEG"},
            {"key": "FileTypeExtension", "value": "jpg"},
            {"key": "MIMEType", "value": "image/jpeg"},
            {"key": "ExifByteOrder", "value": "Little-endian (Intel, II)"},
            {"key": "Orientation", "value": "Horizontal (normal)"},
            {"key": "XResolution", "value": 72},
            {"key": "YResolution", "value": 72},
            {"key": "ResolutionUnit", "value": "inches"},
            {"key": "Software", "value": "ACDSee Pro 7"},
            {"key": "ModifyDate", "value": mock.ANY},
            {"key": "YCbCrPositioning", "value": "Centered"},
            {"key": "SubSecTime", "value": 903},
            {"key": "ExifImageWidth", "value": 1236},
            {"key": "ExifImageHeight", "value": 891},
            {"key": "XMPToolkit", "value": "Image::ExifTool 12.44"},
            {"key": "GPSLatitude", "value": "22 deg 54' 40.92\" S"},
            {"key": "GPSLongitude", "value": "43 deg 12' 21.30\" W"},
            {"key": "ProfileCMMType", "value": "Linotronic"},
            {"key": "ProfileVersion", "value": "2.1.0"},
            {"key": "ProfileClass", "value": "Display Device Profile"},
            {"key": "ColorSpaceData", "value": "RGB"},
            {"key": "ProfileConnectionSpace", "value": "XYZ"},
            {"key": "ProfileDateTime", "value": mock.ANY},
            {"key": "ProfileFileSignature", "value": "acsp"},
            {"key": "PrimaryPlatform", "value": "Microsoft Corporation"},
            {"key": "CMMFlags", "value": "Not Embedded, Independent"},
            {"key": "DeviceManufacturer", "value": "Hewlett-Packard"},
            {"key": "DeviceModel", "value": "sRGB"},
            {"key": "DeviceAttributes", "value": "Reflective, Glossy, Positive, Color"},
            {"key": "RenderingIntent", "value": "Perceptual"},
            {"key": "ConnectionSpaceIlluminant", "value": "0.9642 1 0.82491"},
            {"key": "ProfileCreator", "value": "Hewlett-Packard"},
            {"key": "ProfileID", "value": 0},
            {
                "key": "ProfileCopyright",
                "value": "Copyright (c) 1998 Hewlett-Packard Company",
            },
            {"key": "ProfileDescription", "value": "sRGB IEC61966-2.1"},
            {"key": "MediaWhitePoint", "value": "0.95045 1 1.08905"},
            {"key": "MediaBlackPoint", "value": "0 0 0"},
            {"key": "RedMatrixColumn", "value": "0.43607 0.22249 0.01392"},
            {"key": "GreenMatrixColumn", "value": "0.38515 0.71687 0.09708"},
            {"key": "BlueMatrixColumn", "value": "0.14307 0.06061 0.7141"},
            {"key": "DeviceMfgDesc", "value": "IEC http://www.iec.ch"},
            {
                "key": "DeviceModelDesc",
                "value": "IEC 61966-2.1 Default RGB colour space - sRGB",
            },
            {
                "key": "ViewingCondDesc",
                "value": "Reference Viewing Condition in IEC61966-2.1",
            },
            {"key": "ViewingCondIlluminant", "value": "19.6445 20.3718 16.8089"},
            {"key": "ViewingCondSurround", "value": "3.92889 4.07439 3.36179"},
            {"key": "ViewingCondIlluminantType", "value": "D50"},
            {"key": "Luminance", "value": "76.03647 80 87.12462"},
            {"key": "MeasurementObserver", "value": "CIE 1931"},
            {"key": "MeasurementBacking", "value": "0 0 0"},
            {"key": "MeasurementGeometry", "value": "Unknown"},
            {"key": "MeasurementFlare", "value": "0.999%"},
            {"key": "MeasurementIlluminant", "value": "D65"},
            {"key": "Technology", "value": "Cathode Ray Tube Display"},
            {
                "key": "RedTRC",
                "value": "(Binary data 2060 bytes, use -b option to extract)",
            },
            {
                "key": "GreenTRC",
                "value": "(Binary data 2060 bytes, use -b option to extract)",
            },
            {
                "key": "BlueTRC",
                "value": "(Binary data 2060 bytes, use -b option to extract)",
            },
            {
                "key": "Comment",
                "value": "Colégio Militar do Rio de Janeiro (J David, 1906)",
            },
            {"key": "ImageWidth", "value": 1236},
            {"key": "ImageHeight", "value": 891},
            {"key": "EncodingProcess", "value": "Baseline DCT, Huffman coding"},
            {"key": "BitsPerSample", "value": 8},
            {"key": "ColorComponents", "value": 3},
            {"key": "YCbCrSubSampling", "value": "YCbCr4:2:2 (2 1)"},
            {"key": "ImageSize", "value": "1236x891"},
            {"key": "Megapixels", "value": 1.1},
            {"key": "SubSecModifyDate", "value": mock.ANY},
            {"key": "GPSLatitudeRef", "value": "South"},
            {"key": "GPSLongitudeRef", "value": "West"},
            {
                "key": "GPSPosition",
                "value": "22 deg 54' 40.92\" S, 43 deg 12' 21.30\" W",
            },
        ],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.jpg",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
