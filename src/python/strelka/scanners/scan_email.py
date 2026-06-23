import base64
import email
import email.header
import logging
import re

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
              ``references``) for high-value header data without scanning the full header map.
        - **Link Extraction**
            - Collects full URLs found in the message body into a de-duplicated ``links`` list
              (bounded by ``max_links``, default 50) for IOC matching and triage.
        - **Optional Raw Header Map (opt-in)**
            - Disabled by default. When ``capture_raw_headers`` is explicitly enabled, the full raw
              header map is captured under ``headers`` with a configurable skip-list (``header_skip_list``),
              per-value truncation (``max_header_length``), and a total-size cap (``max_headers_total``);
              every dropped or shortened value is recorded in ``headers_flags``. Kept opt-in because it
              emits a dynamic-keyed object (see Known Limitations).

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
                        if "domain" in self.event:
                            self.event["domains"] += body["domain"]
                        else:
                            self.event["domains"] = body["domain"]
                    # eml_parser already extracts full URLs from each body part.
                    links.extend(body.get("uri", []))

            # Emit a deduped, order-preserved, bounded list of links.
            max_links = options.get("max_links", 50)
            deduped_links = list(dict.fromkeys(links))
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
            self.event["to"] = parsed_eml["header"].get("to", "")
            self.event["from"] = parsed_eml["header"].get("from", "")
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
            self._extract_curated_headers(parsed_header, raw_headers)
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

    def _extract_curated_headers(self, parsed_header: dict, raw: dict) -> None:
        """Populate curated, high-value named header fields on ``self.event``.

        Addresses (cc/bcc) use eml_parser's normalized parsed values to match
        the existing ``to``/``from`` behavior. All other fields read from the
        raw header dict. Angle brackets are stripped from id-style values.
        """
        # Address fields - normalized by eml_parser like to/from.
        self.event["cc"] = parsed_header.get("cc", [])
        self.event["bcc"] = parsed_header.get("bcc", [])

        # Single-value text/id headers.
        self.event["reply_to"] = self._header_value(raw, "reply-to")
        self.event["return_path"] = (
            self._header_value(raw, "return-path").lstrip("<").rstrip(">")
        )
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
