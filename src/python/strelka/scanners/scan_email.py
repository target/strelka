import base64
import email
import email.header
import email.utils
import logging
import re
import urllib.parse

import eml_parser
import pytz

from strelka import strelka

# Configure logging to suppress warnings for fontTools
fonttools_logger = logging.getLogger("fontTools.subset")
fonttools_logger.setLevel(logging.WARNING)


class ScanEmail(strelka.Scanner):
    """
    Extracts and analyzes metadata and attachments from email messages.

    This scanner processes email files to extract and analyze metadata and attachments.
    It supports both plain text and HTML emails, including inline images.

    Scanner Type: Collection

    Attributes:
        None

    ## Detection Use Cases
    !!! info "Detection Use Cases"
        - **Document Extraction**
            - Extracts and analyzes documents, including attachments, from email messages for content review.
        - **Email Header Analysis**
            - Analyzes email headers for potential indicators of malicious activity, such as suspicious sender
              addresses or subject lines.
        - **Authentication Signal Extraction**
            - Parses SPF, DKIM, DMARC, and compauth verdicts from ``Authentication-Results`` /
              ``Received-SPF`` headers into a low-cardinality ``auth`` dict for reliable rule matching.
        - **Spam Score Extraction**
            - Extracts Exchange SCL/BCL spam-confidence levels from ``X-MS-Exchange-Organization-SCL``
              and ``X-Forefront-Antispam-Report`` into a ``spam`` dict.
        - **Curated Header Capture**
            - Populates named fields (``cc``, ``bcc``, ``reply_to``, ``return_path``, ``in_reply_to``,
              ``thread_topic``, ``x_originating_ip``, ``auto_submitted``, ``precedence``, ``content_type``,
              ``x_mailer``, ``references``, ``delivered_to``) for high-value header data without scanning the full header map.
        - **Link Extraction**
            - Collects full URLs found in the message body into a de-duplicated ``links`` list
              (bounded by ``max_links``, default 50) for IOC matching and triage.
        - **Display Name Surfacing (opt-in)**
            - Controlled by ``mailbox_mode``. When enabled, RFC 5322 display names are surfaced
              alongside addr-specs for ``from``, ``to``, ``cc``, ``bcc``, and ``reply_to``.
        - **Security Gateway Link Unwrapping (opt-in)**
            - When ``link_rewrite_mode`` is set, applies a user-supplied list of regex rules
              (``link_rewrite_rules``) to extract original destination URLs from security-gateway
              redirect links.
        - **Optional Raw Header Map (opt-in)**
            - Disabled by default. When ``capture_raw_headers`` is explicitly enabled, the full raw
              header map is captured under ``headers`` with a configurable skip-list (``header_skip_list``),
              per-value truncation (``max_header_length``), and a total-size cap (``max_headers_total``);
              every dropped or shortened value is recorded in ``headers_flags``. Kept opt-in because it
              emits a dynamic-keyed object (see Known Limitations).

    ## Scanner Options
    !!! note "Scanner Options"
        **``mailbox_mode``** — Display name surfacing for address fields (default: ``none``).

        Controls whether RFC 5322 display names are included alongside bare addr-specs in
        ``from``, ``to``, ``cc``, ``bcc``, and ``reply_to``. ``return_path`` and
        ``delivered_to`` are addr-spec–only headers and are never affected.

        - ``none`` — addr-specs only; no display name data emitted.
        - ``copy`` — for recipients that carry a display name, the full
          ``"Display Name <addr@spec>"`` string is appended to the same array as the
          addr-spec. Recipients without a display name appear only once.
        - ``parallel`` — addr-specs remain in the primary field unchanged; a sibling
          ``*_mailbox`` field (``from_mailbox``, ``to_mailbox``, ``cc_mailbox``,
          ``bcc_mailbox``, ``reply_to_mailbox``) is emitted containing full formatted
          address strings. When an address has no display name the formatted string
          equals the addr-spec.

        ---

        **``link_rewrite_mode``** — Security-gateway link unwrapping (default: ``none``).

        Applies ``link_rewrite_rules`` to extract original destination URLs from gateway
        redirect links. Each rule must supply a ``pattern`` with a named capture group
        ``(?P<url>...)``. Patterns should include the gateway hostname and use ``https?%3A``
        (not ``https?://``) to match the percent-encoded scheme in redirect querystring
        parameters.

        - ``none`` — links emitted as-is; no unwrapping performed.
        - ``replace`` — overwrite each gateway link with the extracted destination.
        - ``copy`` — keep original links in ``links``; merge unwrapped destinations in and
          also populate ``links_unwrapped``.
        - ``parallel`` — leave ``links`` untouched; populate only ``links_unwrapped`` with
          the extracted destinations.

        **``link_rewrite_urldecode``** — URL-decoding of captured values (default: ``auto``).

        - ``auto`` — decode only when the captured value starts with ``https?%``.
        - ``on`` — always decode.
        - ``off`` — never decode.

    ## Known Limitations
    !!! warning "Known Limitations"
        - **Email Encoding and Complex Structures**
            - Limited support for certain email encodings or complex email structures.
        - **Body Output Truncation**
            - Plain-text body content is capped at 200 characters (100-head + 100-tail) to prevent
              excessive output.
        - **Raw Header Map Index Mapping**
            - The optional ``headers`` object uses arbitrary header names as keys with list
              values; map it as ``flattened``/``flat_object`` (or disable indexing) in the
              index template to avoid mapping explosion at scale.

    ## To Do
    !!! question "To Do"
        - **Improve Error Handling**:
            - Enhance error handling for edge cases and complex email structures.
        - **Enhance Support for Additional Email Encodings and Content Types**:
            - Expand support for various email encodings and content types to improve scanning accuracy.

    ## References
    !!! quote "References"
        - [Python Email Parsing Documentation](https://docs.python.org/3/library/email.html)

    ## Contributors
    !!! example "Contributors"
        - [Josh Liburdi](https://github.com/jshlbrd)
        - [Paul Hutelmyer](https://github.com/phutelmyer)
        - [Ryan O'Horo](https://github.com/ryanohoro)

    """

    def scan(
        self,
        data: bytes,
        file: strelka.File,
        options: dict,
        expire_at: int,
    ) -> None:
        """
        Processes the email, extracts metadata, and attachments.

        Args:
            data (bytes): The raw email data.
            file (strelka.File): File details.
            options (dict): Scanner options.
            expire_at (int): Expiry time of the scan.

        Processes the email to extract metadata and attachments.
        """

        # Initialize data structures for storing scan results
        attachments = []
        self.event["total"] = {"attachments": 0, "extracted": 0}

        # Parse email contents
        try:
            # Open and parse email byte string
            ep = eml_parser.EmlParser(
                include_attachment_data=True, include_raw_body=True
            )
            parsed_eml = ep.decode_email_bytes(data)

            # Check if email was parsed properly and attempt to deconflict and reload.
            if not (parsed_eml["header"]["subject"] and parsed_eml["header"]["header"]):
                if b"\nReceived: from " in data:
                    data = (
                        data.rpartition(b"\nReceived: from ")[1]
                        + data.rpartition(b"\nReceived: from ")[2]
                    )[1:]
                elif b"Start mail input; end with <CRLF>.<CRLF>\n" in data:
                    data = data.rpartition(
                        b"Start mail input; end with <CRLF>.<CRLF>\n"
                    )[2]
                parsed_eml = ep.decode_email_bytes(data)

            # Extract body content, domains, and links
            links = []
            if "body" in parsed_eml:
                for body in parsed_eml["body"]:
                    if "content_type" in body:
                        if body["content_type"] == "text/plain":
                            if len(body["content"]) <= 200:
                                self.event["body"] = body["content"]
                            else:
                                self.event["body"] = (
                                    body["content"][:100]
                                    + "..."
                                    + body["content"][-100:]
                                )
                    else:
                        self.event["body"] = (
                            body["content"][:100] + "..." + body["content"][-100:]
                        )
                    if "domain" in body:
                        # Filter CSS dimension values (e.g. "7.5px") misidentified as domains.
                        domains = [
                            d
                            for d in body["domain"]
                            if not re.fullmatch(r"[\d.]+px", d)
                        ]
                        if "domain" in self.event:
                            self.event["domains"] += domains
                        else:
                            self.event["domains"] = domains
                    # eml_parser already extracts full URLs from each body part.
                    links.extend(body.get("uri", []))

            # Emit a deduped, order-preserved, bounded list of links.
            max_links = options.get("max_links", 50)
            deduped_links = list(dict.fromkeys(links))

            # Optional link rewriting: unwrap security-gateway redirects.
            rewrite_mode = options.get("link_rewrite_mode", "none")
            rewrite_rules = options.get("link_rewrite_rules", [])
            urldecode = options.get("link_rewrite_urldecode", "auto")
            if rewrite_mode != "none" and rewrite_rules:
                unwrapped = self._unwrap_links(deduped_links, rewrite_rules, urldecode)
                if rewrite_mode == "replace":
                    deduped_links = list(dict.fromkeys(unwrapped))
                elif rewrite_mode == "copy":
                    links_unwrapped = [
                        u for orig, u in zip(deduped_links, unwrapped) if u != orig
                    ]
                    deduped_links = list(dict.fromkeys(deduped_links + links_unwrapped))
                    self.event["links_unwrapped"] = links_unwrapped
                elif rewrite_mode == "parallel":
                    self.event["links_unwrapped"] = [
                        u for orig, u in zip(deduped_links, unwrapped) if u != orig
                    ]

            if len(deduped_links) > max_links:
                deduped_links = deduped_links[:max_links]
                self.flags.append(f"{self.__class__.__name__}: links_truncated")
            self.event["links"] = deduped_links

            # Extract attachment details and raw data
            if "attachment" in parsed_eml:
                self.event["attachments"] = {
                    "filenames": [],
                    "hashes": [],
                    "totalsize": 0,
                }
                for attachment in parsed_eml["attachment"]:
                    self.event["attachments"]["filenames"].append(
                        attachment["filename"]
                    )
                    self.event["attachments"]["hashes"].append(
                        attachment["hash"]["md5"]
                    )
                    self.event["attachments"]["totalsize"] += attachment["size"]
                    attachments.append(
                        {
                            "name": attachment["filename"],
                            "content-type": attachment["content_header"][
                                "content-type"
                            ][0],
                            "raw": base64.b64decode(attachment["raw"]),
                        }
                    )

            # Extract email header information
            self.event["subject"] = parsed_eml["header"].get("subject", "")
            date_header = parsed_eml["header"].get("date")
            if date_header:
                self.event["date_utc"] = (
                    date_header.astimezone(pytz.utc).isoformat()[:-6] + ".000Z"
                )
            header = parsed_eml.get("header", {}).get("header", {})
            message_id = header.get("message-id", [])[0] if header else None
            self.event["message_id"] = (
                str(message_id.lstrip("<").rstrip(">")) if message_id else ""
            )
            self.event["received_domain"] = parsed_eml["header"].get(
                "received_domain", []
            )
            self.event["received_ip"] = parsed_eml["header"].get("received_ip", [])

            # Expanded header extraction (curated fields, parsed signals).
            parsed_header = parsed_eml.get("header", {})
            raw_headers = parsed_header.get("header", {})
            display_name_mode = options.get("mailbox_mode", "none")
            self._extract_curated_headers(parsed_header, raw_headers, display_name_mode)
            self.event["auth"] = self._parse_auth_results(raw_headers)
            self.event["spam"] = self._parse_spam_scores(raw_headers)

            # Optional, size-guarded full raw header map ("bonus" capture).
            # Opt-in (default off): emits a dynamic-keyed object, so it stays
            # disabled unless a deployment explicitly enables it.
            if options.get("capture_raw_headers", False):
                headers, header_flags = self._build_raw_header_map(raw_headers, options)
                self.event["headers"] = headers
                self.event["headers_flags"] = header_flags

            # Process attachments
            if attachments:
                for attachment in attachments:
                    self.event["total"]["attachments"] += 1
                    name = attachment["name"]
                    try:
                        flavors = [
                            attachment["content-type"]
                            .encode("utf-8")
                            .partition(b";")[0]
                        ]
                    except Exception as e:
                        self.flags.append(
                            f"{self.__class__.__name__}: email_extract_attachment_error: {str(e)[:50]}"
                        )
                    # Send extracted file back to Strelka
                    self.emit_file(attachment["raw"], name=name, flavors=flavors)
                    self.event["total"]["extracted"] += 1

        except Exception as e:
            self.flags.append(
                f"{self.__class__.__name__}: email_parse_error: {str(e)[:50]}"
            )

    def _parse_auth_results(self, raw: dict) -> dict:
        """Parse the trusted Authentication-Results verdict into a low-cardinality dict.

        Only the topmost ``Authentication-Results`` header is parsed: the one
        stamped by our own receiving system. Lower-hop headers are relay- or
        sender-controlled, so the flat ``auth`` object reflects a single trust
        domain rather than a best-fill composite across hops. Falls back to
        ``Received-SPF`` for the spf verdict when the trusted header omits it.
        """
        auth = {"spf": "", "dkim": "", "dmarc": "", "compauth": ""}

        # _header_value returns the first (topmost) value; lower hops ignored.
        results = self._header_value(raw, "authentication-results")
        if results:
            for method in auth:
                match = re.search(rf"\b{method}=(\w+)", results)
                if match:
                    auth[method] = match.group(1).lower()

        if not auth["spf"]:
            spf_header = self._header_value(raw, "received-spf")
            if spf_header:
                auth["spf"] = spf_header.split()[0].lower()

        return auth

    def _unwrap_links(self, links: list, rules: list, urldecode: str = "auto") -> list:
        """Unwrap security-gateway redirect URLs using configured regex rules.

        Each rule must have a ``pattern`` key with a regex containing a named
        capture group ``url``. First matching rule wins per link.

        ``urldecode`` controls decoding of captured values: ``auto`` (default)
        decodes only when the value starts with ``https?%``; ``on`` always
        decodes; ``off`` never decodes.
        """
        result = []
        for link in links:
            unwrapped = link
            for rule in rules:
                m = re.search(rule.get("pattern", ""), link)
                if m and "url" in m.groupdict() and m.group("url"):
                    captured = m.group("url")
                    if urldecode == "on":
                        captured = urllib.parse.unquote(captured)
                    elif urldecode == "auto" and re.match(r"https?%", captured):
                        captured = urllib.parse.unquote(captured)
                    unwrapped = captured
                    break
            result.append(unwrapped)
        return result

    def _parse_spam_scores(self, raw: dict) -> dict:
        """Extract Exchange spam scores (SCL/BCL) as a low-cardinality dict.

        Prefers the dedicated ``X-MS-Exchange-Organization-SCL`` header, then
        falls back to SCL/BCL embedded in ``X-Forefront-Antispam-Report``.
        """
        spam = {"scl": "", "bcl": ""}

        scl = self._header_value(raw, "x-ms-exchange-organization-scl")
        if scl:
            spam["scl"] = scl

        report = self._header_value(raw, "x-forefront-antispam-report")
        if report:
            if not spam["scl"]:
                scl_match = re.search(r"SCL:(-?\d+)", report)
                if scl_match:
                    spam["scl"] = scl_match.group(1)
            bcl_match = re.search(r"BCL:(\d+)", report)
            if bcl_match:
                spam["bcl"] = bcl_match.group(1)

        return spam

    def _extract_curated_headers(
        self, parsed_header: dict, raw: dict, display_name_mode: str = "none"
    ) -> None:
        """Populate curated, high-value named header fields on ``self.event``.

        Address fields (from, to, cc, bcc, reply_to) default to emitting lists
        of bare addr-specs (user@example.com). The ``display_name_mode`` option
        controls whether display names are also surfaced:

        - ``none`` (default): addr-specs only; no display name data emitted.
        - ``copy``: for addresses that carry a display name, the full
          ``"Display Name <addr@spec>"`` string is appended to the same list as
          the addr-spec. Addresses without a display name appear only once.
        - ``parallel``: addr-specs remain in the primary field unchanged; a
          sibling ``*_mailbox`` field (e.g. ``from_mailbox``, ``to_mailbox``)
          is emitted containing the full formatted address strings for every
          recipient.  When an address has no display name the formatted string
          equals the addr-spec.

        ``return_path`` and ``delivered_to`` are addr-spec–only headers (RFC
        5321 envelope / delivery tracing) and are never affected by this option.
        """

        def emit_addr_field(field: str, pairs: list) -> None:
            """Emit one address field, applying display_name_mode."""
            specs = [addr for _, addr in pairs]
            if display_name_mode == "copy":
                extras = [
                    f"{name} <{addr}>"
                    for name, addr in pairs
                    if name  # only add formatted form when a display name exists
                ]
                self.event[field] = list(dict.fromkeys(specs + extras))
            elif display_name_mode == "parallel":
                self.event[field] = specs
                self.event[f"{field}_mailbox"] = [
                    f"{name} <{addr}>" if name else addr for name, addr in pairs
                ]
            else:
                self.event[field] = specs

        # from: single mailbox header
        raw_from = raw.get("from", [""])[0]
        from_name, from_addr = email.utils.parseaddr(raw_from)
        emit_addr_field("from", [(from_name, from_addr)] if from_addr else [])

        # to: mailbox-list
        emit_addr_field(
            "to",
            [(n, a) for n, a in email.utils.getaddresses(raw.get("to", [])) if a],
        )

        # cc: mailbox-list
        emit_addr_field(
            "cc",
            [(n, a) for n, a in email.utils.getaddresses(raw.get("cc", [])) if a],
        )

        # bcc: mailbox-list
        emit_addr_field(
            "bcc",
            [(n, a) for n, a in email.utils.getaddresses(raw.get("bcc", [])) if a],
        )

        # reply_to: address-list (may be multi-address)
        emit_addr_field(
            "reply_to",
            [(n, a) for n, a in email.utils.getaddresses(raw.get("reply-to", [])) if a],
        )

        self.event["delivered_to"] = parsed_header.get("delivered_to", [])

        # return_path: single address scalar; empty string when absent or null sender (<>).
        _, return_addr = email.utils.parseaddr(self._header_value(raw, "return-path"))
        self.event["return_path"] = return_addr
        self.event["in_reply_to"] = (
            self._header_value(raw, "in-reply-to").lstrip("<").rstrip(">")
        )
        self.event["thread_topic"] = self._decode_mime_words(
            self._header_value(raw, "thread-topic")
        )
        self.event["x_originating_ip"] = (
            self._header_value(raw, "x-originating-ip").lstrip("[").rstrip("]")
        )
        self.event["auto_submitted"] = self._header_value(raw, "auto-submitted")
        self.event["precedence"] = self._header_value(raw, "precedence")
        self.event["content_type"] = self._header_value(raw, "content-type")
        x_mailer = self._header_value(raw, "x-mailer")
        self.event["x_mailer"] = [x_mailer] if x_mailer else []

        # References is a single header of whitespace-separated message-ids.
        references_raw = self._header_value(raw, "references")
        self.event["references"] = (
            [ref.lstrip("<").rstrip(">") for ref in references_raw.split()]
            if references_raw
            else []
        )

    def _build_raw_header_map(self, raw: dict, options: dict) -> tuple:
        """Build a size-guarded map of all raw headers.

        Applies a configurable skip-list, per-value truncation, and a total
        size cap so the map stays bounded at scale. Every action that drops or
        shortens data is recorded in the returned flags list (never silent).

        Returns:
            (headers, flags): ``headers`` maps each lowercased header name to a
            LIST of its string values (always a list, for index-mapping type
            stability); ``flags`` records skip/truncate/cap actions.
        """
        max_length = options.get("max_header_length", 2048)
        max_total = options.get("max_headers_total", 32768)
        skip_list = {name.lower() for name in options.get("header_skip_list", [])}

        headers = {}
        flags = []
        running_total = 0

        for raw_name, values in raw.items():
            # Normalize to lowercase so keys and flags stay canonical even if
            # the parser ever yields mixed-case header names.
            name = str(raw_name).lower()
            if name in skip_list:
                flags.append(f"skipped:{name}")
                continue

            out_values = []
            for value in values:
                text = str(value)
                # Caps are byte limits (per the option names/docs); measure and
                # truncate on UTF-8 byte length so non-ASCII headers are bounded
                # consistently. Decode with "ignore" to drop any partial
                # multibyte char left at the truncation boundary.
                encoded = text.encode("utf-8")
                if len(encoded) > max_length:
                    text = encoded[:max_length].decode("utf-8", "ignore")
                    flags.append(f"truncated:{name}")
                out_values.append(text)

            entry_size = len(name.encode("utf-8")) + sum(
                len(v.encode("utf-8")) for v in out_values
            )
            if max_total and running_total + entry_size > max_total:
                flags.append(f"total_cap_reached:{name}")
                break
            running_total += entry_size

            headers[name] = out_values

        return headers, flags

    @staticmethod
    def _header_value(raw: dict, name: str) -> str:
        """Return the first value of a raw header, stripped.

        eml_parser stores raw headers as ``{name: [value, ...]}`` with lowercased
        names; the lookup name is lowercased here too so callers can pass any
        casing. Returns an empty string when the header is absent or empty.
        """
        values = raw.get(name.lower())
        if not values:
            return ""
        return str(values[0]).strip()

    @staticmethod
    def _decode_mime_words(value: str) -> str:
        """Decode RFC 2047 encoded-words (e.g. ``=?utf-8?B?...?=``) to plain text.

        Free-text headers like Thread-Topic arrive MIME-encoded; decoding keeps
        the logged value human-readable and matchable. Returns the input
        unchanged on any decode error.
        """
        if not value:
            return value
        try:
            return str(email.header.make_header(email.header.decode_header(value)))
        except Exception:
            return value

    @staticmethod
    def decode_and_format_header(msg: email.message.Message, header_name: str) -> str:
        """
        Decodes and safely formats a specific header field from an email message.

        Email headers can be encoded in various formats. This function decodes the header
        into a human-readable format, and also ensures that the text is safe for HTML display.

        Args:
            msg (email.message.Message): Parsed email message object.
            header_name (str): The name of the header field to decode.

        Returns:
            A string representing the decoded and formatted header field values.
            Returns a placeholder string if the header field is missing or cannot be decoded.

        """
        try:
            # Decode the specified header field
            decoded_header = email.header.decode_header(msg[header_name])[0]
            # Convert bytes to string if necessary
            field_value = decoded_header[0]
            if isinstance(field_value, bytes):
                field_value = field_value.decode(decoded_header[1] or "utf-8")
        except Exception:
            field_value = "&lt;Unknown&gt;"

        # Replace angle brackets for HTML safety
        return field_value.replace("<", "&lt;").replace(">", "&gt;")
