import base64
import email
import email.header
import hashlib
import io
import logging
import os
import tempfile
from typing import List
from urllib.parse import urlparse

import eml_parser
import fitz  # PyMuPDF
import pytz
from PIL import Image
from weasyprint import HTML, default_url_fetcher

from strelka import strelka

# Configure logging to suppress warnings for WeasyPrint and informational messages for fontTools
weasyprint_logger = logging.getLogger("weasyprint")
weasyprint_logger.setLevel(logging.CRITICAL)

fonttools_logger = logging.getLogger("fontTools.subset")
fonttools_logger.setLevel(logging.WARNING)


class ScanEmail(strelka.Scanner):
    """
    Extracts and analyzes metadata, attachments, and optionally generates thumbnails from email messages.

    This scanner processes email files to extract and analyze metadata, attachments, and optionally generates
    thumbnail images of the email content for a visual overview. It supports both plain text and HTML emails,
    including inline images.

    Scanner Type: Collection

    Attributes:
        None

    Other Parameters:
        create_thumbnail (bool): Indicates whether a thumbnail should be generated for the email content.
        thumbnail_header (bool): Indicates whether email header information should be included in the thumbnail.
        thumbnail_size (int): Specifies the dimensions for the generated thumbnail images.

    ## Detection Use Cases
    !!! info "Detection Use Cases"
        - **Document Extraction**
            - Extracts and analyzes documents, including attachments, from email messages for content review.
        - **Thumbnail Generation**
            - Optionally generates thumbnail images of email content for visual analysis, which can be useful for
            quickly identifying the content of emails.
        - **Email Header Analysis**
            - Analyzes email headers for potential indicators of malicious activity, such as suspicious sender addresses
            or subject lines.

    ## Known Limitations
    !!! warning "Known Limitations"
        - **Email Encoding and Complex Structures**
            - Limited support for certain email encodings or complex email structures.
        - **Thumbnail Accuracy**
            - Thumbnail generation may not accurately represent the email content in all cases,
            especially for emails with complex layouts or embedded content.
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
        - [WeasyPrint Documentation](https://doc.courtbouillon.org/weasyprint/stable/)
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
        Processes the email, extracts metadata, attachments, and optionally generates a thumbnail.

        Args:
            data (bytes): The raw email data.
            file (strelka.File): File details.
            options (dict): Scanner options including thumbnail creation and size.
            expire_at (int): Expiry time of the scan.

        Processes the email to extract metadata, attachments, and optionally generates a thumbnail image
        of the email content. The thumbnail generation is based on user options and can include the email
        header for context.

        """

        # Initialize data structures for storing scan results
        attachments = []
        self.event["total"] = {"attachments": 0, "extracted": 0}

        # Thumbnail creation based on user option
        create_thumbnail = options.get("create_thumbnail", False)
        thumbnail_header = options.get("thumbnail_header", False)
        thumbnail_size = options.get("thumbnail_size", (500, 500))

        # Attempt to create a thumbnail from the email
        if create_thumbnail:
            try:
                image = self.create_email_thumbnail(data, thumbnail_header)
                if image:
                    image.thumbnail(thumbnail_size, Image.Resampling.BILINEAR)
                    buffered = io.BytesIO()
                    image.save(buffered, format="WEBP", quality=30, optimize=True)
                    base64_image = base64.b64encode(buffered.getvalue()).decode("utf-8")
                    self.event["base64_thumbnail"] = base64_image
                else:
                    self.flags.append(
                        f"{self.__class__.__name__}: image_thumbnail_error: Could not generate thumbnail. No HTML found."
                    )
            except Exception as e:
                self.flags.append(
                    f"{self.__class__.__name__}: image_thumbnail_error: {str(e)[:50]}"
                )

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

    def create_email_thumbnail(self, data: bytes, show_header: bool) -> Image:
        """
        Generates a thumbnail image from the content of an email message.

        This function processes the email to extract images and text, combines them into
        a single image, and returns that image. The thumbnail can optionally include the email header
        details for context.

        Args:
            data (bytes): Raw email data.
            show_header (bool): Whether to show the header details in the output.

        Returns:
            A PIL Image object representing the combined thumbnail image of the email.
            None if no images could be created.

        """
        # Supported image types for extraction from the email
        image_types = [
            "image/gif",
            "image/jpeg",
            "image/png",
            "image/jpg",
            "image/bmp",
            "image/ico",
            "image/svg",
            "image/web",
        ]

        # Dictionary to map content IDs to images
        images_dict = {}

        # Create a temporary directory to store generated images
        with tempfile.TemporaryDirectory() as temp_dir:
            # Parse the email data
            msg = email.message_from_bytes(data)

            # List to store paths of generated images
            images_list = []

            # Extract and format header details from the email
            if show_header:
                header_fields = ["Date", "From", "To", "Subject", "Message-Id"]
                header_values = {
                    field: self.decode_and_format_header(msg, field)
                    for field in header_fields
                }

                # Generate an HTML table from the header values
                headers_html = '<table width="100%">\n'
                for field, value in header_values.items():
                    headers_html += f'  <tr><td align="right"><b>{field}:</b></td><td>{value}</td></tr>\n'
                headers_html += "</table>\n<hr></p>\n"

                # Convert HTML header details to an image
                header_image_path = self.html_to_image(headers_html, temp_dir)
                if header_image_path:
                    images_list.append(header_image_path)

            # Process the MIME parts to extract images
            for part in msg.walk():
                if part.is_multipart():
                    continue

                mime_type = part.get_content_type()
                if mime_type in image_types:
                    # Extract image data and create a base64 encoded version
                    content_id = part.get("Content-ID", "").strip("<>")
                    image_data = part.get_payload(decode=True)
                    img_data_base64 = base64.b64encode(image_data).decode("utf-8")
                    images_dict[content_id] = img_data_base64

            # Process HTML body parts and replace CID references with base64 data
            for part in msg.walk():
                if part.get_content_type() == "text/html":
                    payload = part.get_payload(decode=True).decode("utf-8")
                    for cid, img_data in images_dict.items():
                        payload = payload.replace(
                            f"cid:{cid}", f"data:image/jpeg;base64,{img_data}"
                        )

                    # Convert the modified HTML body to an image
                    body_image_path = self.html_to_image(payload, temp_dir)
                    if body_image_path:
                        images_list.append(body_image_path)

            # Combine all extracted images into a single image
            if images_list:
                images = [Image.open(path) for path in images_list]
                return self.append_images(images)

            return None

    @staticmethod
    def html_to_image(html_content: str, temp_dir: str) -> str:
        """
        Converts HTML content to an image.

        This method uses WeasyPrint to convert the HTML content to a PDF and then
        uses PyMuPDF (fitz) to render the PDF as an image. The rendered image is saved as a PNG file.

        Args:
            html_content (str): HTML content to be converted into an image.
            temp_dir (str): Temporary directory to store intermediate files.

        Returns:
            The file path to the generated image, or None if the process fails.

        """
        # Generate a unique filename for the PDF
        pdf_filename = hashlib.md5(html_content.encode()).hexdigest() + ".pdf"
        pdf_path = os.path.join(temp_dir, pdf_filename)

        # Convert HTML to a PDF using WeasyPrint
        try:
            HTML(string=html_content, url_fetcher=local_fetch_only).write_pdf(pdf_path)

            # Open the PDF with fitz and render the first page as an image
            with fitz.open(pdf_path) as doc:
                if doc.page_count > 0:
                    page = doc.load_page(0)  # first page
                    pix = page.get_pixmap()
                    image_path = os.path.join(
                        temp_dir, pdf_filename.replace(".pdf", ".png")
                    )
                    pix.save(image_path)
                    return image_path
                else:
                    return None
        except Exception:
            return None

    @staticmethod
    def append_images(images: List[Image.Image]) -> Image.Image:
        """
        Combines multiple image objects into a single image.

        This function stacks the provided images vertically to create one continuous image.
        It's particularly useful for creating a visual summary of an email's content.

        Args:
            images (list): A list of PIL Image objects to be combined.

        Returns:
            A single PIL Image object that combines all the input images.

        """
        # Define the background color for the combined image
        bg_color = (255, 255, 255)

        # Calculate the total width (max width among images) and total height (sum of heights of all images)
        widths, heights = zip(*(img.size for img in images))
        total_width = max(widths)
        total_height = sum(heights)

        # Create a new image with the calculated dimensions
        combined_image = Image.new("RGB", (total_width, total_height), color=bg_color)

        # Paste each image onto the combined image, one below the other
        y_offset = 0
        for img in images:
            combined_image.paste(img, (0, y_offset))
            y_offset += img.height

        return combined_image

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


def local_fetch_only(url, *args, **kwargs):
    """
    Custom URL fetcher for WeasyPrint that prevents any external network access.

    This function allows only local file paths and base64 encoded data. It blocks all other URLs, including
    HTTP, HTTPS, FTP, and IP addresses, ensuring that no external network access occurs during the fetching
    process.

    Args:
        url (str): The URL to fetch.
        *args: Additional positional arguments.
        **kwargs: Additional keyword arguments.

    Returns:
        dict: A dictionary containing an empty string for 'string', 'text/plain' for 'mime_type', and 'utf8' for 'encoding'
              if the URL is blocked. Otherwise, it uses the default fetcher for local resources.
    """
    try:
        parsed_url = urlparse(url)

        # Allow base64 encoded data or local file paths
        if parsed_url.scheme in ("data", "file", ""):
            return default_url_fetcher(url, *args, **kwargs)
    except:
        pass

    # Block all other URLs (http, https, ftp, IP addresses, etc.)
    return {"string": "", "mime_type": "text/plain", "encoding": "utf8"}
