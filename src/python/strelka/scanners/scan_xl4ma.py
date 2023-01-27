# Authors: Ryan Borre
from strelka.auxiliary.xl4ma import analyzer
from strelka import strelka


class ScanXl4ma(strelka.Scanner):
    """Extracts Excel 4 cell contents and attempts to extract IOCs"""

    def scan(self, data, file, options, expire_at):
        try:
            results = analyzer.process_data(data=data, filename=file.name)
        except strelka.ScannerTimeout:
            raise
        except Exception as e:
            self.flags.append(e)
            print(e)
            return

        if results:
            self.event["decoded"] = results.get("decoded", [])
            self.event["iocs"] = results.get("iocs", [])

            try:
                self.add_iocs(
                    results.get("iocs", []),
                    self.type.url,
                    description="extracted from excel4 macro",
                )
            except strelka.ScannerTimeout:
                raise
            except Exception:
                self.flags.append("xl4ma_ioc_processing_error")
