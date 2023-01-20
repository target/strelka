import io
import re
import logging

from pyzbar.pyzbar import decode
from PIL import Image

from strelka import strelka

logging.getLogger('PIL').setLevel(logging.WARNING)


class ScanQr(strelka.Scanner):
    """
    Collects QR code metadata from image files.
    """
    def scan(self, data, file, options, expire_at):
        try:
            URL_REGEX = r'^((https?|ftp|smtp)://)?(www\.)?[a-z0-9]+\.[a-z]+(/[a-zA-Z0-9#]+/?)*'
            barcodes = decode(Image.open(io.BytesIO(data)))

            try:
                if barcodes:
                    self.event['data'] = barcodes[0].data.decode('utf-8')
                else:
                    return
            except strelka.ScannerTimeout:
                raise
            except Exception as e:
                self.flags.append('decode error')
                return

            try:
                # Type: Email
                if any(qtype in self.event['data'] for qtype in ['MATMSG', 'mailto']):
                    self.event['type'] = 'email'
                # Type: Mobile
                elif any(qtype in self.event['data'] for qtype in ['tel:', 'sms:']):
                    self.event['type'] = 'mobile'
                # Type: App
                elif any(qtype in self.event['data'] for qtype in ['itunes.apple.com', 'market://']):
                    self.event['type'] = 'app'
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
            except strelka.ScannerTimeout:
                raise
            except Exception:
                self.flags.append('parse error')
        except strelka.ScannerTimeout:
            raise
        except Exception:
            self.flags.append('general error')
