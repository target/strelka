import urllib3
import os
import time
import requests
from requests.auth import HTTPBasicAuth
from server import objects
from pathlib import Path

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
        out_path: Output path for Falcon Sandbox reports and logs.
            Defaults to "".
        get_maec: Boolean that determines whether maec report should be pulled.
            Defaults to False.
        depth: Recursion depth for file submission to Falcon Sandbox.
            Defaults to 0.
        envID: List of sandbox envrionments to submit sample to.
            Defaults to {}
    """

    def init(self):
        self.api_key = None
        self.api_secret = None
        self.server = False
        self.out_path = ''
        self.basename = ''
        self.auth_check = False
        self.get_maec = False
        self.depth = 0
        self.envID = {}
        self.sha256 = 0

    def subtmit_query(self, file_object, url, data, params, files, type, stream=False, headers={'User-agent': 'VxApi CLI Connector'}):
        response = 0
        try:
            if type == "GET" :
                response = requests.get(url,
                                         data=data,
                                         params=params,
                                         verify=False,
                                         files=files,
                                         timeout=self.timeout,
                                         headers=headers,
                                         stream=stream,
                                         auth=(HTTPBasicAuth(self.api_key, self.api_secret)))
            elif type == "POST":
                response = requests.post(url,
                                         data=data,
                                         params=params,
                                         verify=False,
                                         files=files,
                                         timeout=self.timeout,
                                         headers=headers,
                                         auth=(HTTPBasicAuth(self.api_key, self.api_secret)))
        except requests.exceptions.ConnectTimeout:
            file_object.flags.append(f"{self.scanner_name}::connect_timeout")
        return response


    def submit_file(self, file_object):
        sha256 = None
        url = self.server + "/api/submit"
        params = {}
        files = {'file': file_object.data}
        data = {
            'nosharevt': 1,
            'environmentId': self.envID,
            'allowCommunityAccess': 1}

        response = self.subtmit_query(file_object, url, data, params, files, "POST")

        if response.status_code == 200 and response.json()["response_code"] == 0:
            sha256 = response.json()["response"]["sha256"] # Successfully submitted file
            self.metadata["sha256"] = sha256
        elif response.status_code == 200 and response.json()["response_code"] == -1:
            file_object.flags.append(f"{self.scanner_name}::duplicate_submission") # Submission Failed - duplicate
        else:
            file_object.flags.append(f"{self.scanner_name}::upload_failed") # Upload Failed

        return sha256


    def monitor_progress(self, file_object, env):
        url = self.server + "/api/state/" + str(self.sha256)
        params = {'environmentId': env}
        data = {}
        files = {}
        state = None

        while state != "SUCCESS" and state != "UNKNOWN" and state != "ERROR":
            response = self.subtmit_query(file_object, url, data, params, files, "GET")
            if response.status_code == 200:
                state = response.json()["response"]["state"]
                time.sleep(10)
        return state


    def get_maec_report(self, file_object, env):
        url = self.server + "/api/result/" + str(self.sha256)
        data = {}
        files = {}
        params = {'type': 'maec',
                  'environmentId': env}

        response = self.subtmit_query(file_object, url, data, params, files, "GET", True)
        if response.status_code == 200:
            if not os.path.exists(self.out_path):
                os.makedirs(self.out_path)

            maec_file = self.out_path + self.basename + ".ENV" + str(env) + ".fs.maec.xml"

            # The default umask is 0o22 which turns off write permission of group and others
            os.umask(0)
            with open(os.open(maec_file, os.O_CREAT | os.O_WRONLY, 0o777),'wb+') as f:
                for chunk in response.iter_content(chunk_size=1024):
                    if chunk:  # filter out keep-alive new chunks
                        f.write(chunk)

            self.metadata["maec_file"] = self.out_path

        else:
            file_object.flags.append(f"{self.scanner_name}::maec_download_failed")


    def scan(self, file_object, options):
        self.depth = options.get("depth", 0)

        if file_object.depth > self.depth:
            file_object.flags.append(f"{self.scanner_name}::file_depth_exceeded")
            return

        self.basename = os.path.basename(file_object.filename)
        self.out_path = options.get("out_path", '') + self.basename + "/"

        self.server = options.get("server", None)
        self.priority = options.get("priority", 3)
        self.timeout = options.get("timeout", 60)
        self.get_maec = options.get("get_maec", False)
        self.envID = options.get("envID", {})

        if not self.auth_check:
            self.api_key = options.get("api_key", None) or os.environ.get("FS_API_KEY")
            self.api_secret = options.get("api_secret", None) or os.environ.get("FS_API_SECKEY")
            self.auth_check = True

        self.sha256 = self.submit_file(file_object)

        if self.get_maec and self.sha256 is not None:
            for env in self.envID:
                if self.monitor_progress(file_object, env) == "SUCCESS":
                    self.get_maec_report(file_object, env)