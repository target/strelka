import io
import logging

import pillow_avif
from PIL import Image
from pillow_heif import register_heif_opener

from strelka import strelka

logging.getLogger("PIL").setLevel(logging.WARNING)

# Must be imported as a plugin, doesn't need to be used
_ = pillow_avif.AvifImagePlugin

register_heif_opener()


class ScanTranscode(strelka.Scanner):
    """
    Converts supported images to PNG for easier scanning

    Typical supported output options:
    gif webp jpeg bmp png tiff
    """

    def scan(self, data, file, options, expire_at):
        output_format = options.get("output_format", "jpeg")

        def convert(im):
            with io.BytesIO() as f:
                im.save(f, format=f"{output_format}", quality=90)
                return f.getvalue()

        # Send extracted file back to Strelka
        self.emit_file(convert(Image.open(io.BytesIO(data))), name=file.name)

        self.flags.append("transcoded")
