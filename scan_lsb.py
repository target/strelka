import cv2
import numpy as np

from strelka import strelka

class ScanLsb(strelka.Scanner):
    """This scanner checks if there is any hidden strings at the end of each RGB value"""

    def scan(self,data,file,options, expire_at):
        ans=False
        image = np.fromstring(data, np.uint8)
        image = cv2.imdecode(image, cv2.IMREAD_COLOR)
        bits = self._get_bits(image)
        bytes_ = self._get_bytes(bits)
        chars = []
        chars.append(self._convert_bytes_to_text(bytes_))
        flag=(''.join(chars).encode('ascii', 'ignore'))
        if (len(flag)>1):
            ans=True
            self.event['lsb'] = ans
            #print("This Image might have something stored in")
        else:
            extract_file = strelka.File (
                source = self.name
            )
            self.event['lsb'] = ans
    
    def _get_bits(self, img):
        h, w, t = img.shape
        bits = ''

        for x in range(0, h):
            for y in range(0, w):
                l=img[x,y]
                length=len(l)
                for k in l:
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
            bytes_.append(bits[i * 8:(i + 1) * 8])
            #print(bytes_)
        return bytes_