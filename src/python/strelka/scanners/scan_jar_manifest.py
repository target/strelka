import ast

from strelka import strelka


class ScanJarManifest(strelka.Scanner):
    """Collects metadata from JAR manifest files."""

    def scan(self, data, file, options, expire_at):
        headers = options.get("headers", [])

        manifest = b"\n".join(data.splitlines()).rstrip(b"\n")
        section_strings = manifest.split(b"\n")

        self.event["headers"] = []
        for section in section_strings:
            s = section.replace(b"\n", b"").split(b":")
            if len(s) == 2:
                h, v = s[0].strip(), s[1].strip()

                if h not in self.event["headers"]:
                    self.event["headers"].append(h)

                if headers and h not in headers:
                    continue

                try:
                    v = ast.literal_eval(v)
                except (ValueError, SyntaxError):
                    pass

                self.event["headers"].append(
                    {
                        "header": h,
                        "value": v,
                    }
                )
