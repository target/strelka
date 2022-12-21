from pathlib import Path
from pytest_unordered import unordered
from unittest import TestCase, mock

from strelka.scanners.scan_email import ScanEmail as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_email(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "total": {"attachments": 2, "extracted": 2},
        "body": "Lorem Ipsum\r\n\r\n[cid:image001.jpg@01D914BA.2B9507C0]\r\n\r\n\r\nLorem ipsum dolor sit amet, consectetur adi...ristique mi, quis finibus justo augue non ligula. Quisque facilisis dui in orci aliquet fermentum.\r\n",
        "domains": unordered([
            "schemas.microsoft.com",
            "www.w3.org",
            "div.msonormal",
            "span.msohyperlink",
            "span.msohyperlinkfollowed",
            "span.emailstyle17",
            "1.0in",
            "div.wordsection1",
        ]),
        "attachments": {
            "filenames": ["image001.jpg", "test.doc"],
            "hashes": unordered([
                "ee97b5bb7816b8ad3c3b4024a5d7ff06",
                "33a13c0806ec35806889a93a5f259c7a",
            ]),
            "totalsize": 72819,
        },
        "subject": "Lorem Ipsum",
        "to": unordered(["baz.quk@example.com"]),
        "from": "foo.bar@example.com",
        "date_utc": "2022-12-21T02:29:49.000Z",
        "message_id": "S7PR03MB5640AD212589DFB7CE58D90CFBEB9@DS7PR03MB5640.namprd03.prod.outlook.co",
        "received_domain": unordered([
            "ch2pr03mb5366.namprd03.prod.outlook.com",
            "mx0b-0020ab02.pphosted.com",
            "pps.filterd",
            "mx.example.com",
            "ds7pr03mb5640.namprd03.prod.outlook.com",
            "mx0a-0020ab02.pphosted.com",
        ]),
        "received_ip": unordered([
            "022.12.20.18",
            "127.0.0.1",
            "2603:10b6:610:96::16",
            "8.17.1.19",
            "2002:a05:6500:11d0:b0:17b:2a20:6c32",
            "2603:10b6:5:2c0::11",
            "205.220.177.243",
            "fe80::bd8e:df17:2c2f:2490",
        ]),
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.eml",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
