import base64
import email
import email.header
import hashlib
import io
import logging
import os
import tempfile

import eml_parser
import fitz  # PyMuPDF
import pytz
from PIL import Image
from weasyprint import HTML

from strelka import strelka

# Configure logging to suppress warnings for WeasyPrint and informational messages for fontTools
weasyprint_logger = logging.getLogger("weasyprint")
weasyprint_logger.setLevel(logging.ERROR)

fonttools_logger = logging.getLogger("fontTools.subset")
fonttools_logger.setLevel(logging.WARNING)


class ScanEmail(strelka.Scanner):
    """
    Scanner that collects metadata, extracts files from email messages, and generates thumbnails.

    This scanner processes email files to extract metadata, attachments, and generates
    thumbnail images of the email content for a visual overview. It handles both plain text and HTML emails,
    including inline images.
    """

    def scan(self, data, file, options, expire_at):
        """
        Processes the email, extracts metadata and attachments, and optionally generates a thumbnail.

        Args:
            data: The raw email data.
            file: File details.
            options: Scanner options including thumbnail creation and size.
            expire_at: Expiry time of the scan.
        """
        # Initialize data structures for storing scan results
        attachments = []
        self.event["total"] = {"attachments": 0, "extracted": 0}

        # Thumbnail creation based on user option
        create_thumbnail = options.get("create_thumbnail", False)
        thumbnail_header = options.get("thumbnail_header", False)
        thumbnail_size = options.get("thumbnail_size", (500, 500))

        # ----------------
        # Thumbnail
        # ----------------
        # Create a thumbnail from the image.
        # Stores as a base64 value in the key: base64_thumbnail
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
                        f"{self.__class__.__name__}: image_thumbnail_error: Could not generate thumbnail."
                    )
            except Exception as e:
                self.flags.append(
                    f"{self.__class__.__name__}: image_thumbnail_error: {str(e)[:50]}"
                )

        # ----------------
        # Parse Email Contents
        # -------------------
        try:
            # Open and parse email byte string
            # If fail to open, return.
            try:
                ep = eml_parser.EmlParser(
                    include_attachment_data=True, include_raw_body=True
                )
                parsed_eml = ep.decode_email_bytes(data)
            except strelka.ScannerTimeout:
                raise
            except Exception as e:
                self.flags.append(
                    f"{self.__class__.__name__}: email_parse_error: {str(e)[:50]}"
                )

            # Check if email was parsed properly and attempt to deconflict and reload.
            # If fail to reparse, return.
            try:
                if not (
                    parsed_eml["header"]["subject"] and parsed_eml["header"]["header"]
                ):
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
                    if not (
                        parsed_eml["header"]["subject"]
                        and parsed_eml["header"]["header"]
                    ):
                        self.flags.append(
                            f"{self.__class__.__name__}: email_parse_error: {str(e)[:50]}"
                        )
                        return
            except strelka.ScannerTimeout:
                raise
            except Exception as e:
                self.flags.append(
                    f"{self.__class__.__name__}: email_parse_error: {str(e)[:50]}"
                )

            # Body
            # If body exists in email, collect partial message contents and domains
            try:
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
            except strelka.ScannerTimeout:
                raise
            except Exception as e:
                self.flags.append(
                    f"{self.__class__.__name__}: email_parse_body_error: {str(e)[:50]}"
                )

            # Attachments
            # If attachments exist in email, collect attachment details and raw data to be resubmitted to pipeline.
            try:
                if "attachment" in parsed_eml:
                    self.event["attachments"] = {}
                    self.event["attachments"]["filenames"] = []
                    self.event["attachments"]["hashes"] = []
                    self.event["attachments"]["totalsize"] = 0
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
            except strelka.ScannerTimeout:
                raise
            except Exception as e:
                self.flags.append(
                    f"{self.__class__.__name__}: email_parse_attachment_error: {str(e)[:50]}"
                )

            # Header
            # Collect email header information
            try:
                self.event["subject"] = parsed_eml["header"]["subject"]
                self.event["to"] = parsed_eml["header"]["to"]
                self.event["from"] = parsed_eml["header"]["from"]
                self.event["date_utc"] = (
                    parsed_eml["header"]["date"].astimezone(pytz.utc).isoformat()[:-6]
                    + ".000Z"
                )
                self.event["message_id"] = str(
                    parsed_eml["header"]["header"]["message-id"][0]
                    .lstrip("<")
                    .rstrip(">")
                )
                if "received_domain" in parsed_eml["header"]:
                    self.event["received_domain"] = parsed_eml["header"][
                        "received_domain"
                    ]
                if "received_ip" in parsed_eml["header"]:
                    self.event["received_ip"] = parsed_eml["header"]["received_ip"]
            except strelka.ScannerTimeout:
                raise
            except Exception as e:
                self.flags.append(
                    f"{self.__class__.__name__}: email_parse_header_error: {str(e)[:50]}"
                )

            # If attachments were found, submit back into pipeline
            try:
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
            except strelka.ScannerTimeout:
                raise
            except Exception as e:
                self.flags.append(
                    f"{self.__class__.__name__}: email_extract_attachment_error: {str(e)[:50]}"
                )

        except AssertionError:
            self.flags.append(f"{self.__class__.__name__}: email_assertion_error")

    def create_email_thumbnail(self, data, show_header):
        """
        Generates a thumbnail image from the content of an email message.

        This function processes the email to extract images and text, combines them into
        a single image, and returns that image.

        Args:
            show_header: Whether to show the header details in the output.
            data: Raw email data.

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

        # Options for imgkit to handle errors during image generation
        imgkit_options = {
            "load-error-handling": "skip",
            "quiet": "",
        }

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
    def html_to_image(html_content, temp_dir):
        """
        Converts HTML content to an image.

        This method uses WeasyPrint to convert the HTML content to a PDF and then
        uses PyMuPDF (fitz) to render the PDF as an image. The rendered image is saved as a PNG file.

        Args:
            html_content: HTML content to be converted into an image.
            temp_dir: Temporary directory to store intermediate files.

        Returns:
            The file path to the generated image, or None if the process fails.
        """
        # Generate a unique filename for the PDF
        pdf_filename = hashlib.md5(html_content.encode()).hexdigest() + ".pdf"
        pdf_path = os.path.join(temp_dir, pdf_filename)

        # Convert HTML to a PDF using WeasyPrint
        try:
            HTML(string=html_content).write_pdf(pdf_path)

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
        except Exception as e:
            # Log or handle the exception as needed
            return None

    @staticmethod
    def append_images(images):
        """
        Combines multiple image objects into a single image.

        This function stacks the provided images vertically to create one continuous image.
        It's particularly useful for creating a visual summary of an email's content.

        Args:
            images: A list of PIL Image objects to be combined.

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
    def decode_and_format_header(msg, header_name):
        """
        Decodes and safely formats a specific header field from an email message.

        Email headers can be encoded in various formats. This function decodes the header
        into a human-readable format, and also ensures that the text is safe for HTML display.

        Args:
            msg: Parsed email message object.
            header_name: The name of the header field to decode.

        Returns:
            A string representing the decoded and header field values.
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
