import eml_parser
import base64
import pytz

from strelka import strelka


class ScanEmail(strelka.Scanner):
    """Collects metadata and extract files from email messages."""

    def scan(self, data, file, options, expire_at):
        attachments = []
        self.event['total'] = {'attachments': 0, 'extracted': 0}

        try:

            # Open and parse email byte string
            # If fail to open, return.
            try:
                ep = eml_parser.EmlParser(include_attachment_data=True, include_raw_body=True)
                parsed_eml = ep.decode_email_bytes(data)
            except strelka.ScannerTimeout:
                raise
            except Exception:
                self.flags.append('parse_load_error')
                return

            # Check if email was parsed properly and attempt to deconflict and reload.
            # If fail to reparse, return.
            try:
                if not (parsed_eml['header']['subject'] and parsed_eml['header']['header']):
                    if b'\nReceived: from ' in data:
                        data = (data.rpartition(b"\nReceived: from ")[1] + data.rpartition(b"\nReceived: from ")[
                            2])[1:]
                    elif b"Start mail input; end with <CRLF>.<CRLF>\n" in data:
                        data = data.rpartition(b"Start mail input; end with <CRLF>.<CRLF>\n")[2]
                    parsed_eml = ep.decode_email_bytes(data)
                    if not (parsed_eml['header']['subject'] and parsed_eml['header']['header']):
                        self.flags.append('parse_manual_email_error')
                        return
            except strelka.ScannerTimeout:
                raise
            except Exception as e:
                self.flags.append('parse_manual_email_error')
                return

            # Body
            # If body exists in email, collect partial message contents and domains
            try:
                if 'body' in parsed_eml:
                    for body in parsed_eml['body']:
                        if 'content_type' in body:
                            if body['content_type'] == 'text/plain':
                                if len(body['content']) <= 200:
                                    self.event['body'] = body['content']
                                else:
                                    self.event['body'] = body['content'][:100] + '...' + body['content'][-100:]
                        else:
                            self.event['body'] = body['content'][:100] + '...' + body['content'][-100:]
                        if 'domain' in body:
                            if 'domain' in self.event:
                                self.event['domains'] += body['domain']
                            else:
                                self.event['domains'] = body['domain']
            except strelka.ScannerTimeout:
                raise
            except Exception:
                self.flags.append('parse_body_error')

            # Attachments
            # If attachments exist in email, collect attachment details and raw data to be resubmitted to pipeline.
            try:
                if 'attachment' in parsed_eml:
                    self.event['attachments'] = {}
                    self.event['attachments']['filenames'] = []
                    self.event['attachments']['hashes'] = []
                    self.event['attachments']['totalsize'] = 0
                    for attachment in parsed_eml['attachment']:
                        self.event['attachments']['filenames'].append(attachment["filename"])
                        self.event['attachments']['hashes'].append(attachment['hash']['md5'])
                        self.event['attachments']['totalsize'] += attachment['size']
                        attachments.append({
                            'name': attachment['filename'],
                            'content-type': attachment['content_header']['content-type'][0],
                            'raw': base64.b64decode(attachment['raw'])
                        }
                        )
            except strelka.ScannerTimeout:
                raise
            except Exception:
                self.flags.append('parse_attachment_error')

            # Header
            # Collect email header information
            try:
                self.event['subject'] = parsed_eml['header']['subject']
                self.event['to'] = parsed_eml['header']['to']
                self.event['from'] = parsed_eml['header']['from']
                self.event['date_utc'] = parsed_eml['header']['date'].astimezone(pytz.utc).isoformat()[:-6] + '.000Z'
                self.event['message_id'] = str(parsed_eml['header']['header']['message-id'][0][1:-1])
                if 'received_domain' in parsed_eml['header']:
                    self.event['received_domain'] = parsed_eml['header']['received_domain']
                if 'received_ip' in parsed_eml['header']:
                    self.event['received_ip'] = parsed_eml['header']['received_ip']
            except strelka.ScannerTimeout:
                raise
            except Exception:
                self.flags.append('parse_header_error')

            # If attachments were found, submit back into pipeline
            try:
                if attachments:
                    for attachment in attachments:
                        self.event['total']['attachments'] += 1
                        extract_file = strelka.File(
                            name=attachment['name'],
                            source=self.name,
                        )
                        extract_file.add_flavors({'external': [attachment['content-type'].partition(";")[0]]})

                        for c in strelka.chunk_string(attachment['raw']):
                            self.upload_to_coordinator(
                                extract_file.pointer,
                                c,
                                expire_at,
                            )

                        self.files.append(extract_file)
                        self.event['total']['extracted'] += 1
            except strelka.ScannerTimeout:
                raise
            except Exception:
                self.flags.append('extract_attachment_error')

        except AssertionError:
            self.flags.append('assertion_error')
