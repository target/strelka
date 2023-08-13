import glob
import os

import yara

from strelka import strelka


class ScanYara(strelka.Scanner):
    """Scans files with YARA.

    Attributes:
        compiled_yara: Compiled YARA file derived from YARA rule file(s)
            in location.

    Options:
        location: Location of the YARA rules file or directory.
            Defaults to '/etc/yara/'.
        meta: List of YARA rule meta identifiers
            (e.g. 'Author') that should be logged.
            Defaults to empty list.
        store_offset: To extract hexacimal offsts.
            If true, YARA metadata will be examined for
            keys. If found, extract out hexadecimal
            reference lines
        offset_meta_key: To extract hexadecimal offsets.
            A string found in a YARA's meta
            (e.g., 'StrelkaHexDump = true')
        offset_padding: Padding length before and after
            offset match for context
    """

    def init(self):
        """Initializes the ScanYara class.

        Sets up the initial state for the scanner by ensuring that
        the compiled YARA rules are not set.
        """
        self.compiled_yara = None
        self.loaded_configs = False

    def scan(self, data, file, options, expire_at):
        """Scans the provided data with YARA rules.

        Args:
            data (bytes): The data to scan.
            file (File): An object representing the file being scanned.
            options (dict): Configuration options for the scan.
            expire_at (int): Expiration time for the scan.

        Populates self.event with matches, tags, meta, and hex data
        based on YARA rule matches.
        """
        # Load YARA rules if not already loaded.
        # This prevents loading YARA rules on every execution.
        if self.compiled_yara is None:
            self.load_yara_rules(options)

        # Load YARA configuration options only once.
        # This prevents loading the configs on every execution.
        if not self.loaded_configs:
            self.store_offset = options.get("store_offset", False)
            self.offset_meta_key = options.get("offset_meta_key", "")
            self.offset_padding = options.get("offset_padding", 32)
            self.loaded_configs = True

        # Initialize the event data structure.
        self.hex_dump_cache = {}
        self.event["matches"] = []
        self.event["tags"] = set()
        self.event["meta"] = []
        self.event["hex"] = []

        # Match the data against the YARA rules.
        yara_matches = self.compiled_yara.match(data=data)
        for match in yara_matches:
            # Append rule matches and update tags.
            self.event["matches"].append(match.rule)
            self.event["tags"].update(match.tags)

            # Extract hex representation if configured to store offsets.
            if self.store_offset and self.offset_meta_key:
                if match.meta.get(self.offset_meta_key):
                    for string_data in match.strings:
                        offset, identifier, matched_string = string_data
                        self.extract_match_hex(
                            match.rule,
                            offset,
                            matched_string,
                            data,
                            self.offset_padding,
                        )

            # Append meta information if configured to do so.
            for k, v in match.meta.items():
                if not self.event["meta"] or k in self.event["meta"]:
                    self.event["meta"].append(
                        {"rule": match.rule, "identifier": k, "value": v}
                    )

        # Convert tags set to a list.
        self.event["tags"] = list(self.event["tags"])

    def load_yara_rules(self, options):
        """Loads YARA rules based on the provided path.

        Args:
            options (dict): Configuration options specifying the
            location of YARA rules.

        Compiles YARA rules either from a specified file or from
        a directory. If there's an issue with compilation, flags
        are set to indicate any compilation / loading errors.
        """
        # Retrieve location of YARA rules.
        location = options.get("location", "/etc/strelka/yara/")

        try:
            # Compile YARA rules from a directory.
            if os.path.isdir(location):
                globbed_yara_paths = glob.iglob(f"{location}/**/*.yar*", recursive=True)
                if not globbed_yara_paths:
                    self.flags.append("yara_rules_not_found")
                yara_filepaths = {
                    f"namespace_{i}": entry
                    for (i, entry) in enumerate(globbed_yara_paths)
                }
                self.compiled_yara = yara.compile(filepaths=yara_filepaths)
            # Compile YARA rules from a single file.
            elif os.path.isfile(location):
                self.compiled_yara = yara.compile(filepath=location)
            else:
                self.flags.append("yara_location_not_found")
        except yara.Error as e:
            self.flags.append(f"compiling_error_general_{e}")
        except yara.SyntaxError as e:
            self.flags.append(f"compiling_error_syntax_{e}")

    def extract_match_hex(self, rule, offset, matched_string, data, offset_padding=32):
        """
        Extracts a hex dump of a matched string in the data, with padding.

        This function retrieves a hex dump of the specified matched string within
        the data. It also provides additional context around the matched string
        by adding padding before and after the match. The total padding (i.e., the
        sum of before and after) is defined by the `offset_padding` parameter, which
        is split evenly on either side of the matched string. If the padding would
        go beyond the start or end of the data, it's adjusted to fit within the data's
        bounds.

        Args:
        - rule (str): Name of the YARA rule that triggered the match.
        - offset (int): Start offset of the matched string in the data.
        - matched_string (str): The actual string in the data that matched the YARA rule.
        - data (bytes): The file data being scanned.
        - offset_padding (int, optional): Total number of bytes to include as padding
        around the matched string in the hex dump. Defaults to 32.

        Returns:
        - Appends a dictionary containing the rule name and hex dump to self.event["hex"].
        """

        # Calculate half of the total padding to distribute evenly on either side of the match.
        # This is to add context to the match. It's recommended to keep this low (16 bytes)
        half_padding = offset_padding // 2

        # Determine the starting and ending offsets for the hex dump, ensuring we stay within data bounds.
        start_offset = max(offset - half_padding, 0)
        end_offset = min(offset + len(matched_string) + half_padding, len(data))

        # Create a list to store the hex representation lines
        hex_lines = []

        # Loop through the specified data range in 16-byte chunks to generate the hex dump
        for i in range(start_offset, end_offset, 16):
            # If this chunk hasn't been processed before, generate its hex and ASCII representations
            if i not in self.hex_dump_cache:
                chunk = data[i : i + 16]

                # Convert each byte in the chunk to its hexadecimal representation and join them with spaces.
                # E.g., a chunk [65, 66, 67] would become the string "41 42 43"
                hex_values = " ".join([f"{byte:02x}" for byte in chunk])

                # Generate an ASCII representation for each byte in the chunk:
                # - Use the character itself if it's a printable ASCII character (between 32 and 126 inclusive).
                # - Replace non-printable characters with a period ('.').
                # E.g., a chunk [65, 66, 0] would become the string "AB."
                ascii_values = "".join(
                    [chr(byte) if 32 <= byte <= 126 else "." for byte in chunk]
                )

                # Cache the generated hex and ASCII values to avoid redundant computation in the future
                self.hex_dump_cache[i] = (hex_values, ascii_values)
            else:
                hex_values, ascii_values = self.hex_dump_cache[i]

            # Generate a formatted string for this chunk and add to our hex_lines list
            hex_lines.append(f"{i:08x}  {hex_values:<47}  {ascii_values}")

        # Append the generated hex dump and rule information to the event
        self.event["hex"].append({"rule": rule, "dump": hex_lines})
