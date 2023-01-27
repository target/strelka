from strelka import strelka


class ScanIni(strelka.Scanner):
    """Parses keys from INI files."""

    def scan(self, data, file, options, expire_at):
        self.event["comments"] = []
        self.event["keys"] = []
        self.event["sections"] = []

        section = ""
        ini = data.splitlines()
        for key in ini:
            key = key.strip()
            if not key:
                continue

            if key.startswith(b"[") and key.endswith(b"]"):
                section = key[1:-1]
                self.event["sections"].append(section)
            elif key.startswith(b"#") or key.startswith(b";"):
                self.event["comments"].append(key)
            else:
                split_key = key.split(b"=")
                if len(split_key) == 1:
                    self.event["keys"].append(
                        {
                            "section": section,
                            "value": split_key[0].strip().strip(b'"\'"'),
                        }
                    )
                elif len(split_key) == 2:
                    self.event["keys"].append(
                        {
                            "section": section,
                            "name": split_key[0].strip().strip(b'"\'"'),
                            "value": split_key[1].strip().strip(b'"\'"'),
                        }
                    )
