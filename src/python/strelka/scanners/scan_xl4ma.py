# Authors: Ryan Borre

from strelka.auxiliary.xl4ma import analyzer
from strelka import strelka


class ScanXl4ma(strelka.Scanner):

    def scan(self, data, file, options, expire_at):
        results = analyzer.process_data(data=data, filename=file.name)
        if results:
            self.event['decoded'] = results.get('decoded', [])
            self.event['iocs'] = results.get('iocs', [])
            self.add_iocs(results.get('iocs', []), self.type.url, description="extracted from excel4 macro")
