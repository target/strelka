import os

import requests
import urllib3
from requests.auth import HTTPBasicAuth

from strelka import strelka

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ScanFalconSandbox(strelka.Scanner):
    """Sends files to Falcon Sandbox.

    Attributes:

        api_key: API key used for authenticating to Falcon Sandbox. This is loaded
            from the scanner options or the environment variable
            'FS_API_KEY'.
        api_secret: API secret key used for authenticating to Falcon Sandbox. This is loaded
            from the scanner options or the environment variable
            'FS_API_SECKEY'.
        lib: URL of the Falcon Sandbox API inteface.
        auth_check: Boolean that determines if the username and password were
            previously checked. This ensures that the username and password
            are only checked once per worker.


    Options:
        depth: Recursion depth for file submission to Falcon Sandbox.
            Defaults to 0.
        env_id: List of sandbox environments to submit sample to.
            Public Sandbox environments ID: 300: 'Linux (Ubuntu 16.04, 64 bit)',
                                            200: 'Android Static Analysis’,
                                            160: 'Windows 10 64 bit’,
                                            110: 'Windows 7 64 bit’,
                                            100: ‘Windows 7 32 bit’
            Defaults to [100]
    """

    def init(self):
        self.api_key = None
        self.api_secret = None
        self.server = ""
        self.auth_check = False
        self.depth = 0
        self.env_id = [100]

    def submit_file(self, file, env_id):
        url = self.server + "/api/submit"
        # TODO data is never referenced so this will crash
        files = {"file": None}  # data

        data = {"nosharevt": 1, "environmentId": env_id, "allowCommunityAccess": 1}

        try:
            response = requests.post(
                url,
                data=data,
                params={},
                verify=False,
                files=files,
                timeout=self.timeout,
                headers={"User-Agent": "VxApi CLI Connector"},
                auth=(HTTPBasicAuth(self.api_key, self.api_secret)),
            )

            if response.status_code == 200 and response.json()["response_code"] == 0:
                sha256 = response.json()["response"][
                    "sha256"
                ]  # Successfully submitted file
                self.event["sha256"] = sha256

            elif response.status_code == 200 and response.json()["response_code"] == -1:
                self.flags.append(
                    "duplicate_submission"
                )  # Submission Failed - duplicate

            else:
                self.flags.append("upload_failed")  # Upload Failed

        except requests.exceptions.ConnectTimeout:
            self.flags.append("connect_timeout")

        return

    def scan(self, data, file, options, expire_at):
        self.depth = options.get("depth", 0)

        if file.depth > self.depth:
            self.flags.append("file_depth_exceeded")
            return

        self.server = options.get("server", "")
        self.priority = options.get("priority", 3)
        self.timeout = options.get("timeout", 60)
        self.env_id = options.get("env_id", [100])

        if not self.auth_check:
            self.api_key = options.get("api_key", None) or os.environ.get("FS_API_KEY")
            self.api_secret = options.get("api_secret", None) or os.environ.get(
                "FS_API_SECKEY"
            )
            self.auth_check = True

        # Allow submission to multiple environments (e.g. 32-bit and 64-bit)
        for env in self.env_id:
            self.submit_file(file, env)
