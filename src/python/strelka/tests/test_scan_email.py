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
        "cc": [],
        "bcc": [],
        "reply_to": "",
        "return_path": "foo.bar@example.com",
        "in_reply_to": "",
        "references": [],
        "thread_topic": "Lorem Ipsum",
        "x_originating_ip": "",
        "auto_submitted": "",
        "precedence": "",
        "content_type": 'multipart/mixed; boundary="_006_DS7PR03MB5640AD212589DFB7CE58D90CFBEB9DS7PR03MB5640namp_"',
        "auth": {"spf": "pass", "dkim": "", "dmarc": "", "compauth": ""},
        "spam": {"scl": "", "bcl": ""},
        "links": unordered(
            [
                "http://schemas.microsoft.com/office/2004/12/omml",
                "http://www.w3.org/TR/REC-html40",
            ]
        ),
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.eml",
        options={
            "capture_raw_headers": False,
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
        "cc": [],
        "bcc": [],
        "reply_to": "",
        "return_path": "",
        "in_reply_to": "",
        "references": [],
        "thread_topic": "",
        "x_originating_ip": "",
        "auto_submitted": "",
        "precedence": "",
        "content_type": "",
        "auth": {"spf": "", "dkim": "", "dmarc": "", "compauth": ""},
        "spam": {"scl": "", "bcl": ""},
        "links": ["https://acme.com"],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_broken.eml",
        options={
            "capture_raw_headers": False,
        },
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_header_value_helper():
    raw = {"reply-to": ["  noreply@example.com  "], "received": ["a", "b"]}
    assert ScanUnderTest._header_value(raw, "reply-to") == "noreply@example.com"
    assert ScanUnderTest._header_value(raw, "missing") == ""


def test_extract_curated_headers():
    scanner = ScanUnderTest.__new__(ScanUnderTest)
    scanner.event = {}
    parsed_header = {"cc": ["cc1@corp.example", "cc2@corp.example"], "bcc": []}
    raw = {
        "reply-to": ["noreply@external.example"],
        "return-path": ["<sender@external.example>"],
        "in-reply-to": ["<parent@external.example>"],
        "references": ["<root@external.example> <parent@external.example>"],
        "thread-topic": ["Test Subject Thread"],
        "x-originating-ip": ["[203.0.113.10]"],
        "auto-submitted": ["auto-generated"],
        "precedence": ["bulk"],
        "content-type": ['text/plain; charset="utf-8"'],
    }
    scanner._extract_curated_headers(parsed_header, raw)
    assert scanner.event["cc"] == ["cc1@corp.example", "cc2@corp.example"]
    assert scanner.event["bcc"] == []
    assert scanner.event["reply_to"] == "noreply@external.example"
    assert scanner.event["return_path"] == "sender@external.example"
    assert scanner.event["in_reply_to"] == "parent@external.example"
    assert scanner.event["references"] == [
        "root@external.example",
        "parent@external.example",
    ]
    assert scanner.event["thread_topic"] == "Test Subject Thread"
    assert scanner.event["x_originating_ip"] == "203.0.113.10"
    assert scanner.event["auto_submitted"] == "auto-generated"
    assert scanner.event["precedence"] == "bulk"
    assert scanner.event["content_type"] == 'text/plain; charset="utf-8"'


def test_parse_auth_results():
    scanner = ScanUnderTest.__new__(ScanUnderTest)
    raw = {
        "authentication-results": [
            "mx.corp.example; spf=pass smtp.mailfrom=external.example; "
            "dkim=pass header.d=external.example; dmarc=pass action=none; "
            "compauth=pass reason=100"
        ],
        "received-spf": [
            "pass (corp.example: domain of sender@external.example "
            "designates 203.0.113.10 as permitted sender)"
        ],
    }
    assert scanner._parse_auth_results(raw) == {
        "spf": "pass",
        "dkim": "pass",
        "dmarc": "pass",
        "compauth": "pass",
    }


def test_parse_auth_results_empty():
    scanner = ScanUnderTest.__new__(ScanUnderTest)
    assert scanner._parse_auth_results({}) == {
        "spf": "",
        "dkim": "",
        "dmarc": "",
        "compauth": "",
    }


def test_decode_mime_words():
    """RFC 2047 encoded-words decode to plain text; non-encoded and malformed
    values pass through unchanged."""
    assert (
        ScanUnderTest._decode_mime_words("=?utf-8?B?4pyTIEludm9pY2U=?=") == "✓ Invoice"
    )
    assert ScanUnderTest._decode_mime_words("=?utf-8?Q?Caf=C3=A9?=") == "Café"
    assert ScanUnderTest._decode_mime_words("Plain Subject") == "Plain Subject"
    assert ScanUnderTest._decode_mime_words("") == ""
    # Malformed encoded-word is returned as-is rather than raising.
    assert ScanUnderTest._decode_mime_words("=?bogus?X?zz?=") == "=?bogus?X?zz?="


def test_extract_curated_headers_decodes_thread_topic():
    """thread_topic is RFC 2047 decoded during curated extraction."""
    scanner = ScanUnderTest.__new__(ScanUnderTest)
    scanner.event = {}
    scanner._extract_curated_headers(
        {}, {"thread-topic": ["=?utf-8?B?4pyTIEludm9pY2U=?="]}
    )
    assert scanner.event["thread_topic"] == "✓ Invoice"


def test_parse_auth_results_topmost_only():
    """Only the trusted topmost Authentication-Results is parsed; lower-hop
    headers are ignored entirely (no best-fill composite across trust domains).
    A method absent from the topmost header stays empty rather than being
    filled from an untrusted relay."""
    scanner = ScanUnderTest.__new__(ScanUnderTest)
    raw = {
        "authentication-results": [
            # Trusted topmost header from our receiving system. It omits
            # compauth on purpose.
            "mx.corp.example; spf=pass smtp.mailfrom=external.example; "
            "dkim=pass header.d=external.example; dmarc=pass action=none",
            # Untrusted upstream relay with failing verdicts AND a compauth
            # value. None of this may leak into the flat auth object.
            "relay.upstream.example; spf=fail; dkim=fail; compauth=fail reason=001",
        ],
    }
    assert scanner._parse_auth_results(raw) == {
        "spf": "pass",
        "dkim": "pass",
        "dmarc": "pass",
        "compauth": "",
    }


def test_parse_spam_scores():
    scanner = ScanUnderTest.__new__(ScanUnderTest)
    raw = {
        "x-ms-exchange-organization-scl": ["1"],
        "x-forefront-antispam-report": ["CIP:203.0.113.10;CTRY:US;SCL:1;BCL:0;"],
    }
    assert scanner._parse_spam_scores(raw) == {"scl": "1", "bcl": "0"}


def test_parse_spam_scores_empty():
    scanner = ScanUnderTest.__new__(ScanUnderTest)
    assert scanner._parse_spam_scores({}) == {"scl": "", "bcl": ""}


def test_build_raw_header_map_basic():
    scanner = ScanUnderTest.__new__(ScanUnderTest)
    raw = {"subject": ["Hello"], "received": ["a", "b"]}
    headers, flags = scanner._build_raw_header_map(raw, {})
    assert headers == {"subject": ["Hello"], "received": ["a", "b"]}
    assert flags == []


def test_build_raw_header_map_skip_list():
    scanner = ScanUnderTest.__new__(ScanUnderTest)
    raw = {"subject": ["Hello"], "x-microsoft-antispam-message-info": ["blob"]}
    headers, flags = scanner._build_raw_header_map(
        raw, {"header_skip_list": ["x-microsoft-antispam-message-info"]}
    )
    assert headers == {"subject": ["Hello"]}
    assert flags == ["skipped:x-microsoft-antispam-message-info"]


def test_build_raw_header_map_truncation():
    scanner = ScanUnderTest.__new__(ScanUnderTest)
    raw = {"x-big": ["A" * 100]}
    headers, flags = scanner._build_raw_header_map(raw, {"max_header_length": 10})
    assert headers == {"x-big": ["A" * 10]}
    assert flags == ["truncated:x-big"]


def test_build_raw_header_map_total_cap():
    scanner = ScanUnderTest.__new__(ScanUnderTest)
    raw = {"a": ["x" * 20], "b": ["y" * 20]}
    headers, flags = scanner._build_raw_header_map(raw, {"max_headers_total": 25})
    # First header fits (20 + len("a") = 21 <= 25); second pushes past the cap.
    assert headers == {"a": ["x" * 20]}
    assert flags == ["total_cap_reached:b"]


def test_scan_email_headers_fixture(mocker):
    """Synthetic Exchange email: curated fields, parsed signals, guarded raw map."""
    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_headers.eml",
        options={
            "capture_raw_headers": True,  # opt-in; default is off
            "header_skip_list": ["x-microsoft-antispam-message-info"],
        },
    )

    # Curated fields.
    assert scanner_event["cc"] == unordered(["cc1@corp.example", "cc2@corp.example"])
    assert scanner_event["reply_to"] == "noreply@external.example"
    assert scanner_event["return_path"] == "sender@external.example"
    assert scanner_event["in_reply_to"] == "parent-msgid@external.example"
    assert scanner_event["references"] == [
        "root-msgid@external.example",
        "parent-msgid@external.example",
    ]
    assert scanner_event["thread_topic"] == "Test Subject Thread"
    assert scanner_event["x_originating_ip"] == "203.0.113.10"
    assert scanner_event["auto_submitted"] == "auto-generated"
    assert scanner_event["precedence"] == "bulk"

    # Parsed signals.
    assert scanner_event["auth"] == {
        "spf": "pass",
        "dkim": "pass",
        "dmarc": "pass",
        "compauth": "pass",
    }
    assert scanner_event["spam"] == {"scl": "1", "bcl": "0"}

    # Raw map present, skip-list honored.
    assert "headers" in scanner_event
    assert "x-microsoft-antispam-message-info" not in scanner_event["headers"]
    assert scanner_event["headers_flags"] == [
        "skipped:x-microsoft-antispam-message-info"
    ]
    assert scanner_event["headers"]["subject"] == ["Test Subject"]


def test_scan_email_capture_raw_headers_disabled(mocker):
    """When disabled, no raw map is emitted but curated fields still populate."""
    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_headers.eml",
        options={
            "capture_raw_headers": False,
        },
    )
    assert "headers" not in scanner_event
    assert "headers_flags" not in scanner_event
    # Curated extraction is independent of the raw-map toggle.
    assert scanner_event["reply_to"] == "noreply@external.example"
    assert scanner_event["auth"]["dkim"] == "pass"


def test_scan_email_multihop_auth_and_optin_default(mocker):
    """Multi-hop Exchange email with NO capture_raw_headers option set.

    Verifies (a) authentication verdicts come from the trusted topmost
    Authentication-Results header (not the upstream relay's softfail/fail), and
    (b) the raw header map is opt-in: omitting the option leaves it disabled.
    """
    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_headers_multihop.eml",
        options={
            # capture_raw_headers intentionally omitted -> defaults to off.
        },
    )

    # Trusted (topmost) verdicts win over the upstream relay's failing ones.
    assert scanner_event["auth"] == {
        "spf": "pass",
        "dkim": "pass",
        "dmarc": "pass",
        "compauth": "pass",
    }
    assert scanner_event["spam"] == {"scl": "5", "bcl": "2"}
    assert scanner_event["auto_submitted"] == "auto-generated"
    assert scanner_event["precedence"] == "bulk"

    # Opt-in default: no option passed -> no raw header map emitted.
    assert "headers" not in scanner_event
    assert "headers_flags" not in scanner_event


def test_scan_email_links(mocker):
    """Links (full URLs) are extracted from the body and de-duplicated."""
    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_links.eml",
        options={"capture_raw_headers": False},
    )
    # The body repeats one URL; it appears once in the deduped output.
    assert scanner_event["links"] == unordered(
        [
            "https://one.example/a",
            "https://two.example/b",
            "https://three.example/c",
        ]
    )
    assert "ScanEmail: links_truncated" not in scanner_event["flags"]


def test_scan_email_links_capped(mocker):
    """max_links caps the emitted link list and records a truncation flag."""
    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_links.eml",
        options={"capture_raw_headers": False, "max_links": 2},
    )
    assert len(scanner_event["links"]) == 2
    assert "ScanEmail: links_truncated" in scanner_event["flags"]
