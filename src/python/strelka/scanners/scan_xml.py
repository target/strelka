from typing import Any, Dict

from lxml import etree

from strelka import strelka
from strelka.auxiliary.iocs import extract_iocs_from_string


class ScanXml(strelka.Scanner):
    """
    Collects metadata and extracts embedded files from XML files.

    This scanner parses XML files to collect metadata and extract embedded files based on specified tags.
    It is used in forensic and malware analysis to extract and analyze structured data within XML documents.

    Scanner Type: Collection

    Attributes:
        None

    Options:
        extract_tags (list[str]): Tags whose content is extracted as child files.
        metadata_tags (list[str]): Tags whose content is logged as metadata.

    ## Detection Use Cases
    !!! info "Detection Use Cases"
        - **Embedded File Extraction**
            - Extracts files embedded within specific XML tags.
        - **Metadata Extraction**:
            - Collects metadata from specific XML tags.

    ## Known Limitations
    !!! warning "Known Limitations"
        - Complex or malformed XML structures might lead to incomplete parsing or errors.
        - Excessive files may be scanned / collected if XML mimetypes are set in the `backend.yml`

    ## To Do
    !!! question "To Do"
        - Improve error handling for malformed XML structures.
        - Better extraction of tags / metadata tags

    ## References
    !!! quote "References"
        - XML File Format Specification (https://www.w3.org/XML/)

    ## Contributors
    !!! example "Contributors"
        - [Josh Liburdi](https://github.com/jshlbrd)
        - [Paul Hutelmyer](https://github.com/phutelmyer)
        - [Sara Kalupa](https://github.com/skalupa)
    """

    def scan(
        self, data: bytes, file: strelka.File, options: dict, expire_at: int
    ) -> None:
        """
        Parses XML data to extract metadata and files.

        Args:
            data: XML data as bytes.
            file: File object containing metadata about the scan.
            options: Dictionary of scanner options.
            expire_at: Time when the scan should be considered expired.

        Scans the XML file, extracting data and metadata based on the specified tags,
        and emits files as necessary.

        If given file is not a XML file, then the scanner will append a flag denoting this and exit
        """

        # Prepare options with case-insensitive tag matching
        xml_options = {
            "extract_tags": [tag.lower() for tag in options.get("extract_tags", [])],
            "metadata_tags": [tag.lower() for tag in options.get("metadata_tags", [])],
        }

        # Initialize scan event data
        self.event["tags"] = []
        self.event["tag_data"] = []
        self.event["namespaces"] = []
        self.event["total"] = {"tags": 0, "extracted": 0}
        self.emitted_files: list[str] = []

        # Parse the XML content
        try:
            xml_buffer = data
            if xml_buffer.startswith(b"<?XML"):
                xml_buffer = b"<?xml" + xml_buffer[5:]
            xml = etree.fromstring(xml_buffer)
            docinfo = xml.getroottree().docinfo
            self.event["doc_type"] = docinfo.doctype if docinfo.doctype else ""
            self.event["version"] = docinfo.xml_version if docinfo.xml_version else ""

            # Recursively process each node in the XML
            self._recurse_node(xml, xml_options)

        except Exception as e:
            # If file given is not an XML file, do not proceed with ScanXML
            if "text/xml" not in file.flavors.get("mime", []):
                self.flags.append(
                    f"{self.__class__.__name__}: xml_file_format_error: File given to ScanXML is not an XML file, "
                    f"scanner did not run."
                )
            else:
                self.flags.append(
                    f"{self.__class__.__name__}: xml_parsing_error: Unable to scan XML file with error: {e}."
                )
            return

        # Finalize the event data for reporting
        self.event["tags"] = list(set(self.event["tags"]))
        self.event["total"]["tags"] = len(self.event["tags"])
        self.event["namespaces"] = list(set(self.event["namespaces"]))
        self.event["emitted_content"] = list(set(self.emitted_files))

        # Extract and add Indicators of Compromise (IOCs)
        self.add_iocs(extract_iocs_from_string(data.decode("utf-8")))

    def _recurse_node(self, node: etree._Element, xml_options: Dict[str, Any]) -> None:
        """
        Recursively processes each XML node to extract data and metadata.

        Args:
            node: The current XML node to process.
            xml_options: Options for data extraction and metadata logging.

        Iterates through XML nodes, extracting data and collecting metadata as specified
        by the scanner options.
        """
        if node is not None and hasattr(node.tag, "__getitem__"):
            namespace, _, tag = node.tag.partition("}")
            namespace = namespace[1:] if namespace.startswith("{") else ""
            tag = tag.lower()

            if tag:
                self.event["tags"].append(tag)
            if namespace:
                self.event["namespaces"].append(namespace)

            # Handle specific content extraction and emission
            if tag in xml_options["extract_tags"]:
                content = node.text.strip() if node.text else ""
                if content:
                    self.emit_file(content, name=tag)
                    self.emitted_files.append(content)
                    self.event["total"]["extracted"] += 1

            # Always process attributes to capture any relevant metadata or data for emission
            self._process_attributes(node, xml_options, tag)

            # Continue to recurse through child nodes to extract data
            for child in node.getchildren():
                self._recurse_node(child, xml_options)

    def _process_attributes(
        self, node: etree._Element, xml_options: Dict[str, Any], tag: str
    ) -> None:
        """
        Processes XML node attributes to extract or log data.

        Args:
            node: XML node whose attributes are being processed.
            xml_options: Configuration options for the scan.
            tag: The tag of the current XML node being processed.

        Extracts data from attributes specified in the extract_tags list and logs data
        from attributes specified in the metadata_tags list.
        """
        for attr_name, attr_value in node.attrib.items():
            attr_name_lower = attr_name.lower()
            if attr_name_lower in xml_options["metadata_tags"]:
                self.event["tag_data"].append(
                    {"tag": attr_name, "content": str(node.attrib)}
                )
