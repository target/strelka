from pathlib import Path
from unittest import TestCase, mock

from pytest_unordered import unordered

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
        "body": "Lorem Ipsum\n\n[cid:image001.jpg@01D914BA.2B9507C0]\n\n\nLorem ipsum dolor sit amet, consectetur adipisci...tristique mi, quis finibus justo augue non ligula. Quisque facilisis dui in orci aliquet fermentum.\n",
        "domains": unordered(
            [
                "schemas.microsoft.com",
                "www.w3.org",
                "div.msonormal",
                "span.msohyperlink",
                "span.msohyperlinkfollowed",
                "span.emailstyle17",
                "1.0in",
                "div.wordsection1",
            ]
        ),
        "attachments": {
            "filenames": ["image001.jpg", "test.doc"],
            "hashes": unordered(
                [
                    "ee97b5bb7816b8ad3c3b4024a5d7ff06",
                    "33a13c0806ec35806889a93a5f259c7a",
                ]
            ),
            "totalsize": 72819,
        },
        "subject": "Lorem Ipsum",
        "to": unordered(["baz.quk@example.com"]),
        "from": "foo.bar@example.com",
        "date_utc": "2022-12-21T02:29:49.000Z",
        "message_id": "DS7PR03MB5640AD212589DFB7CE58D90CFBEB9@DS7PR03MB5640.namprd03.prod.outlook.com",
        "received_domain": unordered(
            [
                "ch2pr03mb5366.namprd03.prod.outlook.com",
                "mx0b-0020ab02.pphosted.com",
                "pps.filterd",
                "mx.example.com",
                "ds7pr03mb5640.namprd03.prod.outlook.com",
                "mx0a-0020ab02.pphosted.com",
            ]
        ),
        "received_ip": unordered(
            [
                "022.12.20.18",
                "fe80::bd8e:df17:2c2f:2490",
                "8.17.1.19",
                "2603:10b6:5:2c0::11",
                "205.220.177.243",
                "2603:10b6:610:96::16",
                "127.0.0.1",
                "2002:a05:6500:11d0:b0:17b:2a20:6c32",
            ]
        ),
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.eml",
        options={
            "create_thumbnail": False,
        },
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_email_incomplete(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "total": {"attachments": 0, "extracted": 0},
        "body": "Hi Placeholder,\n\nCan I have access?\n\nThanks,\nJohn\n\n\nFrom: Placeholder Smith  "
        "<placeholder@acme.com<m...m> shared a file or folder located in Acme Share with you. Delete visitor "
        "session<https://acme.com>\n",
        "domains": ["acme.com", "share.acme.com"],
        "subject": "",
        "to": [],
        "from": "",
        "date_utc": "1970-01-01T00:00:00.000Z",
        "message_id": "",
        "received_domain": [],
        "received_ip": [],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_broken.eml",
        options={
            "create_thumbnail": True,
        },
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
