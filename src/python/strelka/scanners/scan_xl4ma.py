from strelka import strelka
from strelka.auxiliary.xl4ma import analyzer


class ScanXl4ma(strelka.Scanner):
    """
    Strelka scanner for extracting Excel 4 cell contents and IOCs.

    This scanner uses the xl4ma analyzer to extract data from Excel files.
    It attempts to decode Excel 4 cell contents and extract any potential IOCs.
    Extracted data is added to the scanner's event, and IOCs are processed
    using the scanner's IOC processing capabilities.

    Attributes inherited from strelka.Scanner:
        - name (str): Name of the scanner class.
        - key (str): Metadata key used to identify scanner metadata in scan results.
        - event (dict): Dictionary containing the result of the scan.
        - flags (list): List of flags raised during scanning.
        - iocs (list): List of IOCs extracted during scanning.
    """

    def scan(self, data, file, options, expire_at):
        """
        Overrideable scan method from strelka.Scanner.

        Processes the provided data using the xl4ma analyzer and extracts
        relevant information and IOCs.

        Args:
            data (bytes): Data associated with the file to be scanned.
            file (strelka.File): File object associated with the data.
            options (dict): Options to be applied during the scan.
            expire_at (int): Expiration timestamp for extracted files.
        """
        # Attempt to process Excel data using the xl4ma analyzer
        try:
            # Process Excel data and store the results
            results = analyzer.process_data(data=data, filename=file.name)

            # Check if decoding and IOCs are present in the results
            if "decoded" in results:
                self.event["decoded"] = results["decoded"]
            if "iocs" in results:
                self.event["iocs"] = results["iocs"]
                self.add_iocs(results["iocs"])
        except strelka.ScannerTimeout:
            # Propagate the timeout exception
            raise
        except Exception as e:
            # Append exception message to flags for diagnostic purposes
            self.flags.append(f"xl4ma_processing_exception: {str(e)}")
