import email

from strelka import strelka


class ScanMht(strelka.Scanner):
    """Extracts embedded files from MHT (MHTML) archives.

    This scanner processes MHTML files and extracts embedded content.
    Focuses on speed - extracts parts quickly with all headers captured.
    
    Dependencies:
        - Standard library modules (email)
    """

    def scan(self, data, file, options, expire_at):
        self.event["total"] = {"extracted": 0, "parts": 0}
        
        try:
            # Parse the MHT file as an email message (MIME format)
            message = email.message_from_string(data.decode('utf-8', errors='ignore'))
            
            # Capture all main message headers
            self.event['headers'] = dict(message.items())
            
            # Extract boundary value if present
            boundary = message.get_boundary()
            if boundary:
                self.event['boundary'] = boundary
            
            part_count = 0
            self.event['parts'] = []
            
            # Process all parts of the multipart message
            for part in message.walk():
                self.event['total']['parts'] += 1
                
                # Skip the root multipart container
                if part.get_content_maintype() == 'multipart':
                    continue
                
                # Get the payload with automatic decoding
                decoded_data = part.get_payload(decode=True)
                if not decoded_data or len(decoded_data) < 10:
                    continue
                
                # Capture all part headers
                part_headers = dict(part.items())
                self.event['parts'].append(part_headers)
                
                # Create extracted file with static naming
                extract_file = strelka.File(
                    name=f'mht_part_{part_count}',
                    source=self.name,
                )
                
                # Add content type flavor if available
                content_type = part.get_content_type()
                if content_type:
                    extract_file.add_flavors({'external': [content_type]})
                
                # Upload the decoded data
                for c in strelka.chunk_string(decoded_data):
                    self.upload_to_coordinator(
                        extract_file.pointer,
                        c,
                        expire_at,
                    )
                
                self.files.append(extract_file)
                self.event['total']['extracted'] += 1
                part_count += 1
            
            # Set flags based on extraction results
            if self.event['total']['extracted'] == 0:
                self.flags.append('no_content_extracted')

        except UnicodeDecodeError:
            self.flags.append('unicode_decode_error')
        except Exception as e:
            self.flags.append('mht_extraction_error')