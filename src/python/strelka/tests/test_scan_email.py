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


def test_scan_email_external_connections(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "total": {"attachments": 1, "extracted": 1},
        "base64_thumbnail": "UklGRggDAABXRUJQVlA4IPwCAABQMgCdASpiAfQBPxGIvlmsKaYjoNz4AYAiCWlu6dB19Ru0PhPU8YbAZdBQDvu8O4WRlAPdTfRtQ5xlAPdTfRtQ5xlAPdMQpQJk8zx+uQDXfdEXeGsM80vZfgTLE2W+9qAe6m+jaWA1n0CvNF5rAA8HX0wEnDYR1awfk2woGUA91N9G1MZgd7upvo2oc4ygHupvo2oc4ygHupvo2oc4ygHupvo2oc4ygHupvo2oc4ygHupvo2oc4ygHupvo2oc4ygHupvo2oc4ygHupvo2oc4ygHupvo2oc4ygHupvo2oc4ygHupvo2oc4ygHupvo2oc4ygHupvo2oc4ygHupvo2oc4ygHupvo2oc4ygHupvo2oc4ygHupvo2oc4ygHupvo2oc4ygHupvo2oc4ygHupvo2oc4ygHupvo2oc4ygHupvo2oc4ygHupvo2oc4ygHupvo2oc4ygHupvo2oc4ygHupvo2oc4ygHupvo2oc4ygHupvo2oc4ygHupvo2oc4ygHupvo2oc4ygHupvo2oc4ygHupvo2oc4ygHupvoxAA/v+1iWiJB5pCNSiuEZLQ/hQ0tSwhIH8V8VOuLZZ6JU4RMO+GIxmkgPwphRCJWEGl9jO+Ypqj582f0PNYl2z8SF2yIYHVllhV7fpViEadVTEGpILt7b3EVTPkjYifOeyMMbqVcjy8CE1m5zYaLBRj9ez6fb8Wk+k+mqZGIdNG0pG54bqtVVyxOSW2y4AqrP+DVGf6EtkKpKHdThD0fDlOjdci8mq352cJHEZPrhuNmER2PZeLTkrX7XzGeQxyn7faldzML5PaqYeZdDpcagv9HIupyM/LQH47ERSIK3+WZNPGNaB0Fe7OQ3bP02hi3VTysG5vPQOB+pn+o45szcH4gT6wLq6HPbCNXU4vmSuE8kPSMubEynkUMfJD2W3gW0l+BS3u4VCQ5rYRVDHHceVYANOi6P8YMEInuKzOHHlTnNKipHt7ZT6tT2Rk00AAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
        "body": "This is a test email with plain text content.\n",
        "domains": ["example.com"],
        "attachments": {
            "filenames": ["testimage.png"],
            "hashes": ["d002d8a11baef4f66f6120b21fa2d4e3"],
            "totalsize": 68,
        },
        "subject": "Test Email with HTML Content and External Resources",
        "to": ["recipient@example.com"],
        "from": "sender@example.com",
        "date_utc": "2021-06-01T19:34:56.000Z",
        "message_id": "test@example.com",
        "received_domain": [],
        "received_ip": [],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_external_addresses.eml",
        options={
            "create_thumbnail": True,
        },
    )

    # Thumbnail generation differs between host OS for this use case.
    # Set a threshold for the acceptable length difference in base64 thumbnail generation
    length_threshold_percentage = 0.2  # Allow up to 20% difference in length

    test_length = len(test_scan_event["base64_thumbnail"])
    scanner_length = len(scanner_event["base64_thumbnail"])

    length_difference = abs(test_length - scanner_length)
    length_threshold = test_length * length_threshold_percentage

    assert (
        length_difference <= length_threshold
    ), f"Length difference {length_difference} exceeds threshold {length_threshold}"

    # Compare other event fields
    for key in test_scan_event:
        if key != "base64_thumbnail":
            TestCase().assertEqual(test_scan_event[key], scanner_event[key])
