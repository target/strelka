import olefile
import re
import struct
from io import BytesIO

from strelka import strelka


class ScanDocExtractImages(strelka.Scanner):
    """Extracts embedded images and objects from DOC files.

    This scanner processes Microsoft Word DOC files (OLE format) and extracts
    embedded images and other binary objects. It works directly with the OLE
    structure to find and extract content.
    
    The scanner uses signature-based detection to find embedded images within
    the binary data streams, properly identifying image boundaries.
    
    Dependencies:
        - olefile

    Options:
        tmp_directory: Location where temporary files are stored.
            Defaults to '/tmp/'.
    """

    def scan(self, data, file, options, expire_at):
        tmp_directory = options.get('tmp_directory', '/tmp/')

        self.event["total"] = {"extracted": 0, "images": 0, "ole_objects": 0}
        
        try:
            # Create a BytesIO object to open the OLE file
            ole_data = BytesIO(data)
            
            # Check if this is an OLE file
            if not olefile.isOleFile(ole_data):
                self.flags.append('not_ole_file')
                return
                
            # Open the OLE file
            ole = olefile.OleFileIO(ole_data)
            
            # Add basic OLE metadata
            self.event['ole_streams'] = ole.listdir()
            
            # Track counts
            image_count = 0
            object_count = 0
            
            # Check for the main document stream
            word_document_found = False
            if ole.exists('WordDocument'):
                word_document_found = True
                self.event['word_document_stream_found'] = True
            
            # Process the Data stream (primary location for embedded content)
            if ole.exists('Data'):
                data_stream = ole.openstream('Data')
                stream_data = data_stream.read()
                
                # --- JPEG EXTRACTION ---
                # Find JPEG signatures (FFD8FF)
                jpeg_matches = re.finditer(b'\xFF\xD8\xFF', stream_data)
                for match in jpeg_matches:
                    try:
                        start_pos = match.start()
                        # Find JPEG end marker (FFD9)
                        end_pos = stream_data.find(b'\xFF\xD9', start_pos)
                        if end_pos != -1:
                            # Extract complete JPEG data (including end marker)
                            jpeg_data = stream_data[start_pos:end_pos+2]
                            
                            # Only process if reasonable size (avoid false positives)
                            if len(jpeg_data) > 100:                                
                                # Create file for extracted image
                                extract_file = strelka.File(
                                    name=f"doc_image_{image_count}.jpg",
                                    source=self.name,
                                )
                                
                                for c in strelka.chunk_string(jpeg_data):
                                    self.upload_to_coordinator(
                                        extract_file.pointer,
                                        c,
                                        expire_at,
                                    )
                                
                                self.files.append(extract_file)
                                image_count += 1
                                self.event['total']['extracted'] += 1
                                self.event['total']['images'] += 1
                    except Exception as e:
                        self.flags.append('jpeg_extraction_error')
                
                # --- PNG EXTRACTION ---
                # Find PNG signatures (89504E470D0A1A0A)
                png_matches = re.finditer(b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A', stream_data)
                for match in png_matches:
                    try:
                        start_pos = match.start()
                        # PNG data ends with IEND chunk
                        end_marker = b'IEND\xAE\x42\x60\x82'
                        end_pos = stream_data.find(end_marker, start_pos)
                        if end_pos != -1:
                            # Extract complete PNG data (including end marker)
                            png_data = stream_data[start_pos:end_pos+len(end_marker)]
                            
                            # Create file for extracted image
                            extract_file = strelka.File(
                                name=f"doc_image_{image_count}.png",
                                source=self.name,
                            )
                            
                            for c in strelka.chunk_string(png_data):
                                self.upload_to_coordinator(
                                    extract_file.pointer,
                                    c,
                                    expire_at,
                                )
                            
                            self.files.append(extract_file)
                            image_count += 1
                            self.event['total']['extracted'] += 1
                            self.event['total']['images'] += 1
                    except Exception as e:
                        self.flags.append('png_extraction_error')
                
                # --- GIF EXTRACTION ---
                # Find GIF signatures (GIF87a or GIF89a)
                gif_matches = re.finditer(b'GIF8[79]a', stream_data)
                for match in gif_matches:
                    try:
                        start_pos = match.start()
                        # GIFs end with a trailer byte
                        end_marker = b'\x00\x3B'
                        end_pos = stream_data.find(end_marker, start_pos)
                        if end_pos != -1:
                            # Extract complete GIF data (including end marker)
                            gif_data = stream_data[start_pos:end_pos+len(end_marker)]
                            
                            # Create file for extracted image
                            extract_file = strelka.File(
                                name=f"doc_image_{image_count}.gif",
                                source=self.name,
                            )
                            
                            for c in strelka.chunk_string(gif_data):
                                self.upload_to_coordinator(
                                    extract_file.pointer,
                                    c,
                                    expire_at,
                                )
                            
                            self.files.append(extract_file)
                            image_count += 1
                            self.event['total']['extracted'] += 1
                            self.event['total']['images'] += 1
                    except Exception as e:
                        self.flags.append('gif_extraction_error')
                
                # --- BMP EXTRACTION ---
                # Find BMP signatures
                bmp_matches = re.finditer(b'BM', stream_data)
                for match in bmp_matches:
                    try:
                        start_pos = match.start()
                        # Validate BMP header and extract size information
                        if start_pos + 14 < len(stream_data):
                            # Get file size from header (at offset 2, 4 bytes, little endian)
                            size_bytes = stream_data[start_pos+2:start_pos+6]
                            if len(size_bytes) == 4:
                                file_size = struct.unpack('<I', size_bytes)[0]
                                # Extract complete BMP data
                                if start_pos + file_size <= len(stream_data):
                                    bmp_data = stream_data[start_pos:start_pos+file_size]
                                    
                                    # Create file for extracted image
                                    extract_file = strelka.File(
                                        name=f"doc_image_{image_count}.bmp",
                                        source=self.name,
                                    )
                                    
                                    for c in strelka.chunk_string(bmp_data):
                                        self.upload_to_coordinator(
                                            extract_file.pointer,
                                            c,
                                            expire_at,
                                        )
                                    
                                    self.files.append(extract_file)
                                    image_count += 1
                                    self.event['total']['extracted'] += 1
                                    self.event['total']['images'] += 1
                    except Exception as e:
                        self.flags.append('bmp_extraction_error')
            
            # --- TRADITIONAL OBJECT EXTRACTION ---
            # Get the list of all streams
            streams = ole.listdir()
            
            # Process streams likely to contain objects
            for stream in streams:
                stream_path = "/".join(stream)
                
                # Skip main streams already processed
                if stream == ['Data'] or stream == ['WordDocument']:
                    continue
                
                # Common patterns for embedded objects
                if (re.match(r'\d+/(^|\w+)/(^|\w+)Data', stream_path) or
                    'Pictures' in stream_path or
                    re.search(r'\d+/\w+Blob', stream_path) or
                    re.search(r'Data/\d+/\d+', stream_path)):
                    try:
                        obj_data = ole.openstream(stream).read()
                        
                        # Skip empty or tiny streams
                        if len(obj_data) < 16:
                            continue
                            
                        # Determine object type from header
                        obj_type = 'bin'
                        if obj_data.startswith(b'\xFF\xD8\xFF'):
                            obj_type = 'jpg'
                        elif obj_data.startswith(b'\x89PNG\r\n\x1A\n'):
                            obj_type = 'png'
                        elif obj_data.startswith(b'GIF8'):
                            obj_type = 'gif'
                        elif obj_data.startswith(b'BM'):
                            obj_type = 'bmp'
                        elif obj_data.startswith(b'\xD0\xCF\x11\xE0'):
                            obj_type = 'ole'
                        
                        stream_name = "_".join(stream)
                        
                        # Create file for extracted object
                        extract_file = strelka.File(
                            name=f"object_{object_count}_{stream_name}.{obj_type}",
                            source=self.name,
                        )
                        
                        for c in strelka.chunk_string(obj_data):
                            self.upload_to_coordinator(
                                extract_file.pointer,
                                c,
                                expire_at,
                            )
                        
                        self.files.append(extract_file)
                        object_count += 1
                        self.event['total']['extracted'] += 1
                        self.event['total']['ole_objects'] += 1
                    except Exception as e:
                        self.flags.append(f'object_extraction_error')
            
            # Close the OLE file
            ole.close()
            
            # Report status
            if not word_document_found:
                self.flags.append('no_word_document_stream')
            
            if image_count == 0 and object_count == 0:
                self.flags.append('no_objects_extracted')

        except ImportError:
            self.flags.append('olefile_import_error')
        except Exception as e:
            self.flags.append('doc_extraction_error')
            self.event['error_message'] = str(e)
