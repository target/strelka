import os
import requests

from server import lib


class ScanCuckoo(lib.StrelkaScanner):
    """Sends files to Cuckoo sandbox.

    Attributes:
        username: Username used for authenticating to Cuckoo. This is loaded
            from the scanner options or the environment variable
            'CUCKOO_USERNAME'.
        password: Password used for authenticating to Cuckoo. This is loaded
            from the scanner options or the environment variable
            'CUCKOO_PASSWORD'.
        auth_check: Boolean that determines if the username and password were
            previously checked. This ensures that the username and password
            are only checked once per worker.

    Options:
        url: URL of the Cuckoo sandbox.
            Defaults to None.
        priority: Cuckoo priority assigned to the task.
            Defaults to 3.
        timeout: Amount of time (in seconds) to wait for the task to upload.
            Defaults to 10 seconds.
        unique: Boolean that tells Cuckoo to only analyze samples that have
            not been analyzed before.
            Defaults to True.
        username: See description above.
        password: See description above.
    """
    def init(self):
        self.username = None
        self.password = None
        self.auth_check = False

    def scan(self, file_object, options):
        url = options.get('url', None)
        priority = options.get('priority', 3)
        timeout = options.get('timeout', 10)
        unique = options.get('unique', True)
        if not self.auth_check:
            self.username = options.get('username', None) or os.environ.get('CUCKOO_USERNAME')
            self.password = options.get('password', None) or os.environ.get('CUCKOO_PASSWORD')
            self.auth_check = True

        if url is not None:
            url += '/tasks/create/file'
            form = {'file': (f'strelka_{file_object.uid}', file_object.data),
                    'priority': priority}
            if unique:
                form['unique'] = 'True'

            try:
                response = requests.post(url,
                                         files=form,
                                         timeout=timeout,
                                         auth=(self.username, self.password))

                if response.status_code == 200:
                    self.metadata['taskId'] = response.json()['task_id']
                elif response.status_code == 400:
                    file_object.flags.append(f'{self.scanner_name}::duplicate_upload')
                else:
                    file_object.flags.append(f'{self.scanner_name}::upload_failed')

            except requests.exceptions.ConnectTimeout:
                file_object.flags.append(f'{self.scanner_name}::connect_timeout')
