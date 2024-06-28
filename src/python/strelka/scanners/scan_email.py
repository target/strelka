import base64
import email
import email.header
import logging

import eml_parser
import pytz

from strelka import strelka

# Configure logging to suppress warnings for fontTools
fonttools_logger = logging.getLogger("fontTools.subset")
fonttools_logger.setLevel(logging.WARNING)


class ScanEmail(strelka.Scanner):
    """
    Extracts and analyzes metadata, attachments, and generates thumbnails from email messages.

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
            - Analyzes email headers for potential indicators of malicious activity, such as suspicious sender addresses
            or subject lines.

    ## Known Limitations
    !!! warning "Known Limitations"
        - **Email Encoding and Complex Structures**
            - Limited support for certain email encodings or complex email structures.
        - **Limited Output**
            - Content is limited to a set amount of characters to prevent excessive output.

    ## To Do
    !!! question "To Do"
        - **Improve Error Handling**:
            - Enhance error handling for edge cases and complex email structures.
        - **Enhance Support for Additional Email Encodings and Content Types**:
            - Expand support for various email encodings and content types to improve scanning accuracy.

    ## References
    !!! quote "References"
        - [Python Email Parsing Documentation](https://docs.python.org/3/library/email.html)
        - [PyMuPDF (fitz) Documentation](https://pymupdf.readthedocs.io/en/latest/)

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

            # Extract body content and domains
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
