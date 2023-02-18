import cv2
import numpy as np

from strelka import strelka


class ScanLsb(strelka.Scanner):
    """This scanner checks if there is any hidden strings at the end of each RGB value"""

    def scan(self, data, file, options, expire_at):
        try:
            image = np.frombuffer(data, np.uint8)
            image = cv2.imdecode(image, cv2.IMREAD_COLOR)
            bits = self._get_bits(image)
            bytes_ = self._get_bytes(bits)
            chars = []
            chars.append(self._convert_bytes_to_text(bytes_))
            flag = "".join(chars).encode("ascii", "ignore")
            self.event["lsb"] = len(flag) > 1
        except AttributeError:
            self.flags.append("bits_image_error")
        except cv2.error:
            self.flags.append("cv2_image_error")

    def _get_bits(self, img):
        h, w, t = img.shape
        bits = ""

        for x in range(0, h):
            for y in range(0, w):
                lst = img[x, y]
                for k in lst:
                    bits += bin(k)[-1]
            return bits

    def _convert_bytes_to_text(self, bytes_):
        asc = ""
        for byte_ in bytes_:
            asc += chr(int(byte_, 2))
        return asc

    def _get_bytes(self, bits):
        bytes_ = []
        for i in range(int(len(bits) / 8)):
            bytes_.append(bits[i * 8 : (i + 1) * 8])
            # print(bytes_)
        return bytes_
