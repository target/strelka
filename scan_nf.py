from strelka import strelka
import cv2 as cv
import numpy as np

class ScanNf(strelka.Scanner):
    """
    Converts RGB image into the HSV (Hue, Saturation, Value) Color Space
    to determine the noise floor of the image.

    This algorithm can be modified to be more/less strict by changing
    the following variables in the source code:
     p = minimum saturation percentage threshold per pixel (value between 0 and 1).
     s_thr = minimum percentage threshold for all the pixels in the image.

    Current Setting: At least 25% (s_thr) of pixels must have a saturation value of at least 5% (p)

    The higher the value for both variables, the more strict the algorithm is.
    """
    def scan(self, data, file, options, expire_at):
        # Convert image to HSV color space
        np_array = np.fromstring(data, np.uint8)
        np_image = cv.imdecode(np_array, cv.IMREAD_COLOR)
        image = cv.cvtColor(np_image, cv.COLOR_BGR2HSV)

        # Calculate histogram of saturation channel
        s = cv.calcHist([image], [1], None, [256], [0, 256])

        # Calculate percentage of pixels with saturation >= p
        p = 0.05
        s_perc = float(np.sum(s[int(p * 255.0):-1])) / float(np.prod(image.shape[0:2]))

        # Percentage threshold; above: valid image, below: noise
        s_thr = 0.25
        self.event['percentage'] = s_perc
        self.event['threshold'] = s_thr
        if s_perc < s_thr:
            self.event['noise_floor'] = True # Potentially dangerous
        else:
            self.event['noise_floor'] = False # Not dangerous