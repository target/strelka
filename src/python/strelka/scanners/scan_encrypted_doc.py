import io
import os
import zipfile
import msoffcrypto

from strelka import strelka

class ScanEncryptedDoc(strelka.Scanner):

    def init(self):
        self.passwords = []

    def scan(self, data, file, options, expire_at):
        password_file = options.get('password_file', '/etc/strelka/passwords.dat')

        if not self.passwords:
            if os.path.isfile(password_file):
                with open(password_file, 'rb') as f:
                    for line in f:
                        self.passwords.append(line.strip())

        with io.BytesIO(data) as doc_io:

            msoff_doc = msoffcrypto.OfficeFile(doc_io)
            output_doc = io.BytesIO()
            password = ''
            extract_data = b''

            if msoff_doc.is_encrypted():             
                self.flags.append('password_protected')
                
                for pw in self.passwords:
                    if not password:
                        try:
                            msoff_doc.load_key(password=pw.decode('utf-8'))
                            output_doc.seek(0)
                            msoff_doc.decrypt(output_doc)
                            output_doc.seek(0)

                            if output_doc.readable():
                                extract_data = output_doc.read()
                                password = pw.decode('utf-8')
                                break

                        except Exception:
                            pass

            if password:
                self.event['password'] = password
                
                extract_file = strelka.File(
                    source=self.name,
                )

                for c in strelka.chunk_string(extract_data):
                    self.upload_to_coordinator(
                        extract_file.pointer,
                        c,
                        expire_at,
                    )

                self.files.append(extract_file)
            else:
                self.flags.append('no_password_match_found')