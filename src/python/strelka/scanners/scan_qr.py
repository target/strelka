import io
import re

import fitz
from PIL import Image
from pyzbar.pyzbar import decode, ZBarSymbol
from strelka import strelka

# Regex to match URL
# NOTE: this is overly simplified but will be validated elsewhere
URL_REGEX = r'^[a-zA-Z]{3,10}:\/\/.*'


class ScanQr(strelka.Scanner):
    """
    Collects QR code metadata from image files.
    """

    def scan(self, data, file, options, expire_at):
        pdf_to_png = options.get('pdf_to_png', False)

        try:
            if pdf_to_png and 'application/pdf' in file.flavors.get('mime', []):
                # TODO: Use fitz builtin OCR support which also wraps tesseract
                doc = fitz.open(stream=data, filetype='pdf')
                data = doc.get_page_pixmap(0, dpi=150).tobytes()

            img = Image.open(io.BytesIO(data))
            barcodes = decode(img, symbols=[ZBarSymbol.QRCODE])

            try:
                self.event['data'] = barcodes[0].data.decode('utf-8')
            except:
                self.flags.append('decode error')
                return

            try:
                # Type: Email
                if any(qtype in self.event['data'] for qtype in ['MATMSG', 'mailto']):
                    self.event['type'] = 'email'
                # Type: Mobile
                elif any(qtype in self.event['data'] for qtype in ['tel:', 'sms:']):
                    self.event['type'] = 'mobile'
                # Type: Geo
                elif 'geo:' in self.event['data']:
                    self.event['type'] = 'geo'
                # Type: WIFI
                elif 'WIFI' in self.event['data']:
                    self.event['type'] = 'wifi'
                # Type: URL
                elif re.match(URL_REGEX, self.event['data']):
                    self.event['type'] = 'url'
                # Type: No Defined Match
                else:
                    self.event['type'] = 'undefined'
            except:
                self.flags.append('parse error')

        except Exception:
            self.flags.append('general error')
