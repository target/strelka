import io
import logging

import pillow_avif
from PIL import Image, UnidentifiedImageError
from pillow_heif import register_heif_opener

from strelka import strelka

logging.getLogger("PIL").setLevel(logging.WARNING)

# Must be imported as a plugin, doesn't need to be used
_ = pillow_avif.AvifImagePlugin

register_heif_opener()


class ScanTranscode(strelka.Scanner):
    """
    Converts supported images for easier scanning

    Typical supported output options:
    gif webp jpeg bmp png tiff
    """

    def scan(self, data, file, options, expire_at):
        output_format = options.get("output_format", "jpeg")

        def convert(im):
            with io.BytesIO() as f:
                im.save(f, format=f"{output_format}", quality=90)
                return f.getvalue()

        try:
            converted_image = convert(Image.open(io.BytesIO(data)))

            # Send extracted file back to Strelka
            self.emit_file(converted_image, name=file.name)
        except UnidentifiedImageError:
            self.flags.append("unidentified_image")
            return

        self.flags.append("transcoded")
