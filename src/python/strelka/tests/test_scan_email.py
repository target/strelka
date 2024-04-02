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


def test_scan_email_with_thumbnail(mocker):
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
        "base64_thumbnail": "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",
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.eml",
        options={
            "create_thumbnail": True,
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
        "flags": [
            "ScanEmail: image_thumbnail_error: Could not generate thumbnail. No HTML found."
        ],
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
