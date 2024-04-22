from io import BytesIO

from lxml import etree

from strelka import strelka


class ScanJnlp(strelka.Scanner):
    """
    Analyzes Java Network Launch Protocol (JNLP) files.

    JNLP files, used by Java Web Start technology, can launch Java applications from a web browser. While facilitating
    legitimate applications, they can also be abused for malicious purposes such as distributing malware or executing
    phishing attacks.

    Scanner Type: Collection

    Attributes:
        event (dict): Stores extracted data during the scan for further analysis.

    Detection Use Cases:
        - **External Resource Reference**
            - Identify JNLP files that reference external HTTP resources, particularly those not associated with trusted
            domains.

    Known Limitations:
        - **Java Dependence**
            - Effectiveness is contingent on the presence and version of Java installed on the target system.

    Todo:
        - Improve detection of obfuscated or sophisticated threats within JNLP files.
        - Extract any other potential JNLP content / headers.

    References:
        - **File Structure**
            - https://docs.oracle.com/javase/tutorial/deployment/deploymentInDepth/jnlpFileSyntax.html
        - **Malicious Usage**
            - https://www.forcepoint.com/blog/x-labs/java-network-launch-protocol
            - https://newtonpaul.com/analysing-fileless-malware-cobalt-strike-beacon
    """

    def scan(self, data, file, options, expire_at):
        """
        Scans the given data for JNLP-related information.

        Extracts 'codebase' and 'href' attributes from JNLP and JAR tags to detect potential malicious activities.

        Args:
            data (bytes): Data of the file being scanned.
            file (File): File object being scanned.
            options (dict): Options for the scanner.
            expire_at (datetime): Expiration time of the scan result.
        """
        # Initialize variables for 'codebase' and 'href' attributes
        codebase = ""
        href = ""

        # Parse the XML to find 'jnlp' and 'jar' elements
        for elem, _ in iterate_xml_elements(data, tags=["jnlp", "jar"]):
            if elem.tag == "jnlp":
                codebase = elem.get("codebase", "").rstrip("/")
            elif elem.tag == "jar":
                href = elem.get("href", "").lstrip("/")

        # If both 'codebase' and 'href' are found, construct the full resource URL
        if codebase and href:
            self.event["resource"] = f"{codebase}/{href}"


def iterate_xml_elements(data, tags=None):
    """
    Iterates over XML data, yielding elements with specified tags.

    This method parses the XML data byte by byte and yields elements that match the specified tags. This is useful
    for extracting specific information from structured XML documents.

    Args:
        data (bytes): The XML data to parse.
        tags (list): List of XML tags to filter elements by.

    Yields:
        tuple: A tuple containing the XML element and its depth in the XML tree.
    """
    # Define the events to listen for during XML parsing
    events = ("start", "end")
    depth = 0
    inside_tags = []

    # Parse the XML data
    for event, elem in etree.iterparse(BytesIO(data), events=events):
        if event == "start":
            # If the element's tag is one we're interested in, track it and its depth
            if tags is None or elem.tag in tags:
                inside_tags.append((elem.tag, depth))
            depth += 1
        elif event == "end":
            # On end tag, reduce depth and check if the closing tag is one we're tracking
            depth -= 1
            if depth < 0:
                continue

            # Check if the current element should be yielded
            is_wanted = tags is None or elem.tag in tags
            if is_wanted and inside_tags and inside_tags[-1][0] == elem.tag:
                inside_tags.pop()
                yield elem, depth
