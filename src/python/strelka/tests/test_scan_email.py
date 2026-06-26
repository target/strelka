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
        "from": ["foo.bar@example.com"],
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
        "reply_to": [],
        "return_path": ["foo.bar@example.com"],
        "in_reply_to": "",
        "references": [],
        "thread_topic": "Lorem Ipsum",
        "x_originating_ip": "",
        "auto_submitted": "",
        "precedence": "",
        "content_type": 'multipart/mixed; boundary="_006_DS7PR03MB5640AD212589DFB7CE58D90CFBEB9DS7PR03MB5640namp_"',
        "x_mailer": "",
        "delivered_to": ["baz.quk@example.com"],
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
        "from": [],
        "date_utc": "1970-01-01T00:00:00.000Z",
        "message_id": "",
        "received_domain": [],
        "received_ip": [],
        "cc": [],
        "bcc": [],
        "reply_to": [],
        "return_path": [],
        "in_reply_to": "",
        "references": [],
        "thread_topic": "",
        "x_originating_ip": "",
        "auto_submitted": "",
        "precedence": "",
        "content_type": "",
        "x_mailer": "",
        "delivered_to": [],
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
    parsed_header = {
        "cc": ["cc1@corp.example", "cc2@corp.example"],
        "bcc": [],
        "delivered_to": ["recipient@corp.example"],
    }
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
        "x-mailer": ["Microsoft Office Outlook 12.0"],
    }
    scanner._extract_curated_headers(parsed_header, raw)
    assert scanner.event["cc"] == ["cc1@corp.example", "cc2@corp.example"]
    assert scanner.event["bcc"] == []
    assert scanner.event["delivered_to"] == ["recipient@corp.example"]
    assert scanner.event["reply_to"] == ["noreply@external.example"]
    assert scanner.event["return_path"] == ["sender@external.example"]
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
    assert scanner.event["x_mailer"] == "Microsoft Office Outlook 12.0"


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
    assert scanner_event["reply_to"] == ["noreply@external.example"]
    assert scanner_event["return_path"] == ["sender@external.example"]
    assert scanner_event["in_reply_to"] == "parent-msgid@external.example"
    assert scanner_event["references"] == [
        "root-msgid@external.example",
        "parent-msgid@external.example",
    ]
    assert scanner_event["thread_topic"] == "Test Subject Thread"
    assert scanner_event["x_originating_ip"] == "203.0.113.10"
    assert scanner_event["auto_submitted"] == "auto-generated"
    assert scanner_event["precedence"] == "bulk"
    assert scanner_event["x_mailer"] == "Microsoft Office Outlook 12.0"
    assert scanner_event["delivered_to"] == []

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
    assert scanner_event["reply_to"] == ["noreply@external.example"]
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


def test_scan_email_complex_recipients(mocker):
    """Complex recipient combinations: multi-address To/Cc/Bcc, tagged sender, group syntax."""
    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent
        / "fixtures/test_email_complex_recipients.eml",
        options={},
    )

    assert scanner_event["from"] == ["john.smith+sales@example.com"]
    assert scanner_event["to"] == unordered(
        ["jane.doe@corp.example", "bob@corp.example", "patrick.obrien@corp.example"]
    )
    assert scanner_event["cc"] == unordered(
        ["marketing-team@corp.example", "sales@example.com", "li.zhang@corp.example"]
    )
    assert scanner_event["bcc"] == ["secret-list@corp.example"]
    assert scanner_event["reply_to"] == unordered(
        ["no-reply@example.com", "support@example.com"]
    )
    assert scanner_event["return_path"] == ["bounce+12345@example.com"]
    assert scanner_event["in_reply_to"] == "msg-001@example.com"
    assert scanner_event["references"] == unordered(
        ["root-msg@example.com", "msg-001@example.com"]
    )
    assert scanner_event["subject"] == "Re: Q1 Sales Report [EXTERNAL]"
    assert scanner_event["message_id"] == "complex-recipients-001@example.com"
    assert scanner_event["x_mailer"] == "Microsoft Outlook 16.0"
    assert scanner_event["delivered_to"] == []


def test_scan_email_encoded_headers(mocker):
    """RFC 2047 encoded display names are decoded; addr-specs are extracted cleanly."""
    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_email_encoded_headers.eml",
        options={},
    )

    assert scanner_event["from"] == ["tokyo-office@example.jp"]
    assert scanner_event["to"] == unordered(
        [
            "francois@corp.example",
            "hans.mueller@corp.example",
            "ivan.petrov@corp.example",
        ]
    )
    assert scanner_event["cc"] == ["cafe-team@corp.example"]
    assert scanner_event["bcc"] == []
    assert scanner_event["reply_to"] == ["support@example.jp"]
    assert scanner_event["return_path"] == ["automated-system@example.com"]
    assert scanner_event["subject"] == "予業通知 - Delivery Notification"
    assert scanner_event["thread_topic"] == "重要：予業通知"
    assert scanner_event["message_id"] == "encoded-headers-001@example.jp"
    assert scanner_event["x_mailer"] == "Thunderbird 115.0"


def test_scan_email_group_syntax(mocker):
    """RFC 5322 group syntax: members are expanded into to; group label appears in cc."""
    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_email_group_syntax.eml",
        options={},
    )

    assert scanner_event["from"] == ["newsletter@example.com"]
    assert scanner_event["to"] == unordered(
        [
            "alice@corp.example",
            "bob@corp.example",
            "charlie@corp.example",
            "dave@corp.example",
            "eve@corp.example",
            "frank@corp.example",
        ]
    )
    assert scanner_event["cc"] == ["undisclosed-recipients"]
    assert scanner_event["reply_to"] == unordered(
        ["manager1@example.com", "manager2@example.com"]
    )
    assert scanner_event["return_path"] == ["system@example.com"]
    assert scanner_event["subject"] == "Company-wide Announcement"
    assert scanner_event["message_id"] == "group-syntax-001@example.com"
    assert scanner_event["x_mailer"] == "MailChimp API v3.0"


def test_scan_email_malformed_addresses(mocker):
    """Malformed address formats: missing brackets, source routing, percent-encoding."""
    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent
        / "fixtures/test_email_malformed_addresses.eml",
        options={},
    )

    assert scanner_event["from"] == ["sender@example.com"]
    assert scanner_event["to"] == unordered(
        [
            "recipient@corp.example",
            "no-brackets@corp.example",
            "extra-comma@corp.example",
            "user@final.example",
            "user%domain@example.com",
            "quoted@corp.example",
        ]
    )
    assert scanner_event["cc"] == []
    assert scanner_event["bcc"] == []
    assert scanner_event["reply_to"] == ["reply@example.com"]
    assert scanner_event["return_path"] == ["sender@example.com"]
    assert scanner_event["subject"] == "Test Malformed Addresses"
    assert scanner_event["message_id"] == "malformed-001@example.com"
    assert scanner_event["x_mailer"] == "Custom Mailer 1.0"


def test_scan_email_special_cases(mocker):
    """Bounce/DSN: null Return-Path (<>), empty Reply-To, auto-submitted signals."""
    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_email_special_cases.eml",
        options={},
    )

    assert scanner_event["from"] == ["mailer-daemon@example.com"]
    assert scanner_event["to"] == ["postmaster@corp.example"]
    assert scanner_event["cc"] == []
    assert scanner_event["bcc"] == []
    assert scanner_event["reply_to"] == []
    assert scanner_event["return_path"] == []
    assert scanner_event["subject"] == "Delivery Status Notification (Failure)"
    assert scanner_event["auto_submitted"] == "auto-replied"
    assert scanner_event["precedence"] == "bulk"
    assert scanner_event["message_id"] == "delivery-status-001@example.com"
    assert scanner_event["x_mailer"] == "Postfix 3.7.2"


def test_unwrap_links_no_rules():
    scanner = ScanUnderTest.__new__(ScanUnderTest)
    links = ["https://gateway.example/?url=https://dest.example/"]
    assert scanner._unwrap_links(links, []) == links


def test_unwrap_links_raw_url():
    # Path-based redirect: inner URL is unencoded in the path, not a querystring value
    scanner = ScanUnderTest.__new__(ScanUnderTest)
    links = ["https://gateway.example/safe/https://dest.example/page"]
    result = scanner._unwrap_links(
        links, [{"pattern": r"gateway\.example/safe/(?P<url>https?://\S+)"}]
    )
    assert result == ["https://dest.example/page"]


def test_unwrap_links_encoded_url():
    # Querystring-based redirect: inner URL is percent-encoded, auto-decoded on https?%3A prefix
    scanner = ScanUnderTest.__new__(ScanUnderTest)
    links = [
        "https://gateway.example/?url=https%3A%2F%2Fdest.example%2Fpath%3Fa%3D1&other=x"
    ]
    result = scanner._unwrap_links(
        links, [{"pattern": r"gateway\.example/\?url=(?P<url>https?%3A[^&]+)"}]
    )
    assert result == ["https://dest.example/path?a=1"]


def test_unwrap_links_urldecode_on():
    # urldecode=on forces decoding regardless of prefix
    scanner = ScanUnderTest.__new__(ScanUnderTest)
    links = ["https://gateway.example/?url=https%3A%2F%2Fdest.example%2Fpage&other=x"]
    result = scanner._unwrap_links(
        links,
        [{"pattern": r"gateway\.example/\?url=(?P<url>[^&]+)"}],
        urldecode="on",
    )
    assert result == ["https://dest.example/page"]


def test_unwrap_links_urldecode_off():
    # urldecode=off returns captured value as-is even when encoded
    scanner = ScanUnderTest.__new__(ScanUnderTest)
    links = ["https://gateway.example/?url=https%3A%2F%2Fdest.example%2Fpage&other=x"]
    result = scanner._unwrap_links(
        links,
        [{"pattern": r"gateway\.example/\?url=(?P<url>https?%3A[^&]+)"}],
        urldecode="off",
    )
    assert result == ["https%3A%2F%2Fdest.example%2Fpage"]


def test_unwrap_links_no_match_unchanged():
    scanner = ScanUnderTest.__new__(ScanUnderTest)
    links = ["https://plain.example/no-redirect"]
    result = scanner._unwrap_links(
        links, [{"pattern": r"gateway\.example/\?url=(?P<url>https?%3A[^&]+)"}]
    )
    assert result == links


def test_unwrap_links_first_rule_wins():
    scanner = ScanUnderTest.__new__(ScanUnderTest)
    links = [
        "https://gateway.example/?url=https%3A%2F%2Fdest.example%2F&redirect=https%3A%2F%2Fother.example%2F"
    ]
    rules = [
        {"pattern": r"gateway\.example/\?url=(?P<url>https?%3A[^&]+)"},
        {"pattern": r"gateway\.example/.*[?&]redirect=(?P<url>https?%3A[^&]+)"},
    ]
    assert scanner._unwrap_links(links, rules) == ["https://dest.example/"]


def test_scan_email_gateway_links_none_mode(mocker):
    """Default (none): links emitted as-is, no rewriting, no links_unwrapped."""
    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_email_gateway_links.eml",
        options={},
    )
    assert "links_unwrapped" not in scanner_event
    assert (
        "https://secure.gateway.example/redirect?url=https://actual-destination.example/path?foo=bar&other=param"
        in scanner_event["links"]
    )
    assert "https://no-gateway.example/plain" in scanner_event["links"]


def test_scan_email_gateway_links_copy_mode(mocker):
    """copy mode: originals stay in links, unwrapped encoded-redirect URL added; raw redirect unchanged."""
    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_email_gateway_links.eml",
        options={
            "link_rewrite_mode": "copy",
            "link_rewrite_rules": [
                {
                    "pattern": r"secure\.gateway\.example/redirect\?url=(?P<url>https?%3A[^&]+)"
                },
            ],
        },
    )
    assert (
        "https://secure.gateway.example/redirect?url=https://actual-destination.example/path?foo=bar&other=param"
        in scanner_event["links"]
    )
    assert (
        "https://secure.gateway.example/redirect?url=https%3A%2F%2Fencoded-destination.example%2Fpath%3Ffoo%3Dbar&other=param"
        in scanner_event["links"]
    )
    assert "https://encoded-destination.example/path?foo=bar" in scanner_event["links"]
    assert "https://no-gateway.example/plain" in scanner_event["links"]
    assert scanner_event["links_unwrapped"] == [
        "https://encoded-destination.example/path?foo=bar"
    ]


def test_scan_email_gateway_links_replace_mode(mocker):
    """replace mode: encoded-redirect URL replaced by destination; raw redirect and plain link unchanged."""
    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_email_gateway_links.eml",
        options={
            "link_rewrite_mode": "replace",
            "link_rewrite_rules": [
                {
                    "pattern": r"secure\.gateway\.example/redirect\?url=(?P<url>https?%3A[^&]+)"
                },
            ],
        },
    )
    assert (
        "https://secure.gateway.example/redirect?url=https://actual-destination.example/path?foo=bar&other=param"
        in scanner_event["links"]
    )
    assert "https://encoded-destination.example/path?foo=bar" in scanner_event["links"]
    assert "https://no-gateway.example/plain" in scanner_event["links"]
    assert "links_unwrapped" not in scanner_event


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
