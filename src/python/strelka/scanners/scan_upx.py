import os
import subprocess
import tempfile

from strelka import strelka


class ScanUpx(strelka.Scanner):
    """Decompresses UPX packed files.

    Options:
        tmp_directory: Location where tempfile writes temporary files.
            Defaults to '/tmp/'.
    """

    def scan(self, data, file, options, expire_at):
        tmp_directory = options.get("tmp_directory", "/tmp/")

        with tempfile.NamedTemporaryFile(dir=tmp_directory) as tmp_data:
            tmp_data.write(data)
            tmp_data.flush()

            upx_return = subprocess.call(
                ["upx", "-d", tmp_data.name, "-o", f"{tmp_data.name}_upx"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if upx_return == 0:
                with open(f"{tmp_data.name}_upx", "rb") as upx_fin:
                    upx_file = upx_fin.read()
                    upx_size = len(upx_file)
                    if upx_size > len(data):
                        self.flags.append("upx_packed")

                        # Send extracted file back to Strelka
                        self.emit_file(upx_file)

                os.remove(f"{tmp_data.name}_upx")

            else:
                self.flags.append(f"return_code_{upx_return}")
