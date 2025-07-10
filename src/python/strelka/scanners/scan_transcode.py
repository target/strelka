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

    Scanner Type: Collection

    ## Detection Use Cases
    !!! info "Detection Use Cases"
        - **Image Extraction**
            - This scanner converts image types into a version that is able to be processed by tesseract in ScanOCR.

    ## Contributors
    !!! example "Contributors"
        - [Paul Hutelmyer](https://github.com/phutelmyer)
        - [Sara Kalupa](https://github.com/skalupa)
    """

    def scan(self, data, file, options, expire_at):
        output_format = options.get("output_format", "jpeg")

        def convert(im):
            with io.BytesIO() as f:
                if "image/x-icon" in file.flavors.get(
                    "mime", []
                ) or "image/vnd.microsoft.icon" in file.flavors.get("mime", []):
                    rgba_im = im.convert("RGBA")
                    rgba_im.save(f, format=f"{output_format}", quality=90)
                    return f.getvalue()
                else:
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
