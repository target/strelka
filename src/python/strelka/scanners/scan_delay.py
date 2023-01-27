import time

from strelka import strelka


class ScanDelay(strelka.Scanner):
    """Delays scanner execution."""

    def scan(self, data, file, options, expire_at):
        delay = options.get("delay", 5.0)

        try:
            time.sleep(delay)
        except strelka.ScannerTimeout:
            raise
        except Exception:
            self.flags.append("non-fatal_thing_happened")
