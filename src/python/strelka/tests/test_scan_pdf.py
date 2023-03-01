from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_pdf import ScanPdf as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_pdf(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "images": 1,
        "lines": 34,
        "links": [],
        "words": 418,
        "author": "Ryan.OHoro",
        "creator": "Microsoft® Word 2016",
        "creation_date": "2022-12-16T19:48:52Z",
        "dirty": False,
        "embedded_files": {"count": 0, "names": []},
        "encrypted": False,
        "needs_pass": False,
        "format": "PDF 1.5",
        "keywords": "",
        "language": "en",
        "modify_date": "2022-12-16T19:48:52Z",
        "old_xrefs": True,
        "pages": 1,
        "producer": "Microsoft® Word 2016",
        "repaired": False,
        "subject": "",
        "title": "",
        "xrefs": 40,
        "phones": [],
        "objects": {},
        "xref_object": ['<</Type/Catalog/Pages 2 0 R/Lang(en-US)/StructTreeRoot 15 0 R/MarkInfo<</Marked true>>>>', '<</Type/Pages/Count 1/Kids[3 0 R]>>', '<</Type/Page/Parent 2 0 R/Resources<</ExtGState<</GS5 5 0 R/GS8 8 0 R>>/Font<</F1 6 0 R/F2 10 0 R/F3 12 0 R>>/XObject<</Image9 9 0 R>>/ProcSet[/PDF/Text/ImageB/ImageC/ImageI]>>/MediaBox[0 0 612 792]/Contents 4 0 R/Group<</Type/Group/S/Transparency/CS/DeviceRGB>>/Tabs/S/StructParents 0>>', '<</Filter/FlateDecode/Length 4050>>', '<</Type/ExtGState/BM/Normal/ca 1>>', '<</Type/Font/Subtype/TrueType/Name/F1/BaseFont/TimesNewRomanPSMT/Encoding/WinAnsiEncoding/FontDescriptor 7 0 R/FirstChar 32/LastChar 117/Widths 36 0 R>>', '<</Type/FontDescriptor/FontName/TimesNewRomanPSMT/Flags 32/ItalicAngle 0/Ascent 891/Descent -216/CapHeight 693/AvgWidth 401/MaxWidth 2614/FontWeight 400/XHeight 250/Leading 42/StemV 40/FontBBox[-568 -216 2046 693]>>', '<</Type/ExtGState/BM/Normal/CA 1>>', '<</Type/XObject/Subtype/Image/Width 340/Height 245/ColorSpace/DeviceRGB/BitsPerComponent 8/Filter/DCTDecode/Interpolate true/Length 21001>>', '<</Type/Font/Subtype/TrueType/Name/F2/BaseFont/ABCDEE+Calibri/Encoding/WinAnsiEncoding/FontDescriptor 11 0 R/FirstChar 32/LastChar 32/Widths 37 0 R>>', '<</Type/FontDescriptor/FontName/ABCDEE+Calibri/Flags 32/ItalicAngle 0/Ascent 750/Descent -250/CapHeight 750/AvgWidth 521/MaxWidth 1743/FontWeight 400/XHeight 250/StemV 52/FontBBox[-503 -250 1240 750]/FontFile2 38 0 R>>', '<</Type/Font/Subtype/TrueType/Name/F3/BaseFont/ArialMT/Encoding/WinAnsiEncoding/FontDescriptor 13 0 R/FirstChar 32/LastChar 120/Widths 39 0 R>>', '<</Type/FontDescriptor/FontName/ArialMT/Flags 32/ItalicAngle 0/Ascent 905/Descent -210/CapHeight 728/AvgWidth 441/MaxWidth 2665/FontWeight 400/XHeight 250/Leading 33/StemV 44/FontBBox[-665 -210 2000 728]>>', "<</Author(Ryan.OHoro)/Creator<FEFF004D006900630072006F0073006F0066007400AE00200057006F0072006400200032003000310036>/CreationDate(D:20221216134852-06'00')/ModDate(D:20221216134852-06'00')/Producer<FEFF004D006900630072006F0073006F0066007400AE00200057006F0072006400200032003000310036>>>", '<</Type/StructTreeRoot/RoleMap 16 0 R/ParentTree 17 0 R/K[18 0 R]/ParentTreeNextKey 1>>', '<</Footnote/Note/Endnote/Note/Textbox/Sect/Header/Sect/Footer/Sect/InlineShape/Sect/Annotation/Sect/Artifact/Sect/Workbook/Document/Worksheet/Part/Macrosheet/Part/Chartsheet/Part/Dialogsheet/Part/Slide/Part/Chart/Sect/Diagram/Figure>>', '<</Nums[0 21 0 R]>>', '<</P 15 0 R/S/Part/Type/StructElem/K[19 0 R 25 0 R 28 0 R 29 0 R 30 0 R 31 0 R 32 0 R 33 0 R 34 0 R 35 0 R]>>', '<</P 18 0 R/S/H1/Type/StructElem/K[20 0 R 23 0 R 24 0 R]/Pg 3 0 R>>', '<</P 19 0 R/S/Span/Type/StructElem/Pg 3 0 R/K 0>>', '[20 0 R 23 0 R 24 0 R 27 0 R 26 0 R 28 0 R 28 0 R 28 0 R 28 0 R 28 0 R 28 0 R 28 0 R 28 0 R 28 0 R 28 0 R 28 0 R 28 0 R 29 0 R 29 0 R 29 0 R 29 0 R 29 0 R 29 0 R 29 0 R 29 0 R 29 0 R 29 0 R 30 0 R 30 0 R 30 0 R 30 0 R 30 0 R 30 0 R 30 0 R 31 0 R 31 0 R 31 0 R 31 0 R 31 0 R 31 0 R 31 0 R 31 0 R 31 0 R 31 0 R 31 0 R 32 0 R 32 0 R 32 0 R 32 0 R 32 0 R 32 0 R 32 0 R 32 0 R 32 0 R 32 0 R 33 0 R 33 0 R 34 0 R 34 0 R 35 0 R]', '<</Type/ObjStm/N 20/First 142/Filter/FlateDecode/Length 601>>', '<</P 19 0 R/S/Span/Type/StructElem/ActualText(Lorem Ipsum)/K[1]/Pg 3 0 R>>', '<</P 19 0 R/S/Span/Type/StructElem/ActualText( )/K[2]/Pg 3 0 R>>', '<</P 18 0 R/S/P/Type/StructElem/K[26 0 R 27 0 R]/Pg 3 0 R>>', '<</P 25 0 R/S/Span/Type/StructElem/Pg 3 0 R/K 4>>', '<</P 25 0 R/S/InlineShape/Alt()/Type/StructElem/K[3]/Pg 3 0 R>>', '<</P 18 0 R/S/P/Type/StructElem/K[5 6 7 8 9 10 11 12 13 14 15 16]/Pg 3 0 R>>', '<</P 18 0 R/S/P/Type/StructElem/K[17 18 19 20 21 22 23 24 25 26]/Pg 3 0 R>>', '<</P 18 0 R/S/P/Type/StructElem/K[27 28 29 30 31 32 33]/Pg 3 0 R>>', '<</P 18 0 R/S/P/Type/StructElem/K[34 35 36 37 38 39 40 41 42 43 44]/Pg 3 0 R>>', '<</P 18 0 R/S/P/Type/StructElem/K[45 46 47 48 49 50 51 52 53 54]/Pg 3 0 R>>', '<</P 18 0 R/S/P/Type/StructElem/K[55 56]/Pg 3 0 R>>', '<</P 18 0 R/S/P/Type/StructElem/K[57 58]/Pg 3 0 R>>', '<</P 18 0 R/S/P/Type/StructElem/K[59]/Pg 3 0 R>>', '[250 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 333 0 0 611 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 444 0 0 0 0 0 0 0 778 0 500 500 0 333 389 0 500]', '[226]', '<</Filter/FlateDecode/Length 175850/Length1 537988>>', '[278 0 0 0 0 0 0 0 0 0 0 0 278 0 278 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 667 0 722 722 0 0 0 0 278 0 0 556 833 722 0 667 778 0 667 0 0 667 0 0 0 0 0 0 0 0 0 0 556 556 500 556 556 278 556 556 222 222 0 222 833 556 556 556 556 333 500 278 556 500 0 500]', '<</Type/XRef/Size 40/W[1 4 2]/Root 1 0 R/Info 14 0 R/ID[<996084F03FED2848AB7A00AD5BCAA8E6><996084F03FED2848AB7A00AD5BCAA8E6>]/Filter/FlateDecode/Length 132>>'],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.pdf",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
