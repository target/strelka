import urllib3
import os
import requests
from requests.auth import HTTPBasicAuth
from server import objects

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ScanFalconSandbox(objects.StrelkaScanner):
    """Sends files to Falcon Sandbox.

    Attributes:

        api_key: API key used for authenticating to Falcon Sandbox. This is loaded
            from the scanner options or the environment variable
            "FS_API_KEY".
        api_secret: API secret key used for authenticating to Falcon Sandbox. This is loaded
            from the scanner options or the environment variable
            "FS_API_SECKEY".
        server: URL of the Falcon Sandbox API inteface.
        auth_check: Boolean that determines if the username and password were
            previously checked. This ensures that the username and password
            are only checked once per worker.


    Options:
        depth: Recursion depth for file submission to Falcon Sandbox.
            Defaults to 0.
        envID: List of sandbox environments to submit sample to.
            Defaults to {}
    """

    def init(self):
        self.api_key = None
        self.api_secret = None
        self.server = ''
        self.auth_check = False
        self.depth = 0
        self.envID = {}


    def submit_file(self, file_object):
        url = self.server + '/api/submit'
        files = {'file': file_object.data}

        data = {
            'nosharevt': 1,
            'environmentId': self.envID,
            'allowCommunityAccess': 1}


        try:
            response = requests.post(url,
                                     data=data,
                                     params={},
                                     verify=False,
                                     files=files,
                                     timeout=self.timeout,
                                     headers={'User-agent': 'VxApi CLI Connector'},
                                     auth=(HTTPBasicAuth(self.api_key, self.api_secret)))

            if response.status_code == 200 and response.json()["response_code"] == 0:
                sha256 = response.json()["response"]["sha256"] # Successfully submitted file
                self.metadata["sha256"] = sha256

            elif response.status_code == 200 and response.json()["response_code"] == -1:
                file_object.flags.append(f"{self.scanner_name}::duplicate_submission") # Submission Failed - duplicate

            else:
                file_object.flags.append(f"{self.scanner_name}::upload_failed") # Upload Failed

        except requests.exceptions.ConnectTimeout:
            file_object.flags.append(f"{self.scanner_name}::connect_timeout")

        return


    def scan(self, file_object, options):
        self.depth = options.get("depth", 0)

        if file_object.depth > self.depth:
            file_object.flags.append(f"{self.scanner_name}::file_depth_exceeded")
            return

        self.server = options.get("server", '')
        self.priority = options.get("priority", 3)
        self.timeout = options.get("timeout", 60)
        self.envID = options.get("envID", {})

        if not self.auth_check:
            self.api_key = options.get("api_key", None) or os.environ.get("FS_API_KEY")
            self.api_secret = options.get("api_secret", None) or os.environ.get("FS_API_SECKEY")
            self.auth_check = True

        self.submit_file(file_object)