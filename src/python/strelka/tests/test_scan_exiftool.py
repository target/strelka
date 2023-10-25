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
        "sourcefile": mock.ANY,
        "exiftoolversion": 12.6,
        "filename": mock.ANY,
        "directory": "/tmp",
        "filesize": "51 kB",
        "filemodifydate": mock.ANY,
        "fileaccessdate": mock.ANY,
        "fileinodechangedate": mock.ANY,
        "filepermissions": "-rw-------",
        "filetype": "DOC",
        "filetypeextension": "doc",
        "mimetype": "application/msword",
        "identification": "Word 8.0",
        "languagecode": "English (US)",
        "docflags": "Has picture, 1Table, ExtChar",
        "system": "Windows",
        "word97": "No",
        "title": "",
        "subject": "",
        "author": "Ryan.OHoro",
        "keywords": "",
        "comments": "",
        "template": "Normal.dotm",
        "lastmodifiedby": "Ryan.OHoro",
        "software": "Microsoft Office Word",
        "createdate": "2022:12:16 19:48:00",
        "modifydate": "2022:12:16 19:48:00",
        "security": "None",
        "codepage": "Windows Latin 1 (Western European)",
        "company": "Target Corporation",
        "charcountwithspaces": 2877,
        "appversion": 16.0,
        "scalecrop": "No",
        "linksuptodate": "No",
        "shareddoc": "No",
        "hyperlinkschanged": "No",
        "titleofparts": "",
        "headingpairs": "Title, 1",
        "compobjusertypelen": 32,
        "compobjusertype": "Microsoft Word 97-2003 Document",
        "lastprinted": "0000:00:00 00:00:00",
        "revisionnumber": 2,
        "totaledittime": "1 minute",
        "words": 430,
        "characters": 2452,
        "pages": 1,
        "paragraphs": 5,
        "lines": 20,
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
        "sourcefile": mock.ANY,
        "exiftoolversion": 12.6,
        "filename": mock.ANY,
        "directory": "/tmp",
        "filesize": "309 kB",
        "filemodifydate": mock.ANY,
        "fileaccessdate": mock.ANY,
        "fileinodechangedate": mock.ANY,
        "filepermissions": "-rw-------",
        "filetype": "JPEG",
        "filetypeextension": "jpg",
        "mimetype": "image/jpeg",
        "exifbyteorder": "Little-endian (Intel, II)",
        "orientation": "Horizontal (normal)",
        "xresolution": 72,
        "yresolution": 72,
        "resolutionunit": "inches",
        "software": "ACDSee Pro 7",
        "modifydate": "2021:02:06 19:55:44",
        "ycbcrpositioning": "Centered",
        "subsectime": 903,
        "exifimagewidth": 1236,
        "exifimageheight": 891,
        "xmptoolkit": "Image::ExifTool 12.44",
        "gpslatitude": "22 deg 54' 40.92\" S",
        "gpslongitude": "43 deg 12' 21.30\" W",
        "profilecmmtype": "Linotronic",
        "profileversion": "2.1.0",
        "profileclass": "Display Device Profile",
        "colorspacedata": "RGB ",
        "profileconnectionspace": "XYZ ",
        "profiledatetime": "1998:02:09 06:49:00",
        "profilefilesignature": "acsp",
        "primaryplatform": "Microsoft Corporation",
        "cmmflags": "Not Embedded, Independent",
        "devicemanufacturer": "Hewlett-Packard",
        "devicemodel": "sRGB",
        "deviceattributes": "Reflective, Glossy, Positive, Color",
        "renderingintent": "Perceptual",
        "connectionspaceilluminant": "0.9642 1 0.82491",
        "profilecreator": "Hewlett-Packard",
        "profileid": 0,
        "profilecopyright": "Copyright (c) 1998 Hewlett-Packard Company",
        "profiledescription": "sRGB IEC61966-2.1",
        "mediawhitepoint": "0.95045 1 1.08905",
        "mediablackpoint": "0 0 0",
        "redmatrixcolumn": "0.43607 0.22249 0.01392",
        "greenmatrixcolumn": "0.38515 0.71687 0.09708",
        "bluematrixcolumn": "0.14307 0.06061 0.7141",
        "devicemfgdesc": "IEC http://www.iec.ch",
        "devicemodeldesc": "IEC 61966-2.1 Default RGB colour space - sRGB",
        "viewingconddesc": "Reference Viewing Condition in IEC61966-2.1",
        "viewingcondilluminant": "19.6445 20.3718 16.8089",
        "viewingcondsurround": "3.92889 4.07439 3.36179",
        "viewingcondilluminanttype": "D50",
        "luminance": "76.03647 80 87.12462",
        "measurementobserver": "CIE 1931",
        "measurementbacking": "0 0 0",
        "measurementgeometry": "Unknown",
        "measurementflare": "0.999%",
        "measurementilluminant": "D65",
        "technology": "Cathode Ray Tube Display",
        "redtrc": "(Binary data 2060 bytes, use -b option to extract)",
        "greentrc": "(Binary data 2060 bytes, use -b option to extract)",
        "bluetrc": "(Binary data 2060 bytes, use -b option to extract)",
        "comment": "Colégio Militar do Rio de Janeiro (J David, 1906)",
        "imagewidth": 1236,
        "imageheight": 891,
        "encodingprocess": "Baseline DCT, Huffman coding",
        "bitspersample": 8,
        "colorcomponents": 3,
        "ycbcrsubsampling": "YCbCr4:2:2 (2 1)",
        "imagesize": "1236x891",
        "megapixels": 1.1,
        "subsecmodifydate": "2021:02:06 19:55:44.903",
        "gpslatituderef": "South",
        "gpslongituderef": "West",
        "gpsposition": "22 deg 54' 40.92\" S, 43 deg 12' 21.30\" W",
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.jpg",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
