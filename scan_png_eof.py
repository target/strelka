from strelka import strelka

class  ScanPngEof(strelka.Scanner):
    """ Extract data embended in PNG files.
    
    This scanner extracts data that is inserted past the PNG file end
    """
    def scan(self, data, file, options, expire_at):
        datalen = len(data)
        if (data[datalen - 1] == b'\x82') and (data[datalen - 2] == b'\x60') and (data[len(data) - 3] == b'\x42'):
            # file DOES NOT have data after EOF, found end of file
            self.flags.append('no_trailer')
        else: # the file DOES have data after EOF, did not find end of file
            trailer_index = data.rfind(b'\x42\x60\x82')
            if trailer_index == -1 :
                self.event['end_index'] = -1 # didn't find the offical ending of the file
            else:
                trailer_index = trailer_index + 3
                self.event['trailer_index'] = trailer_index

                extract_file = strelka.File (
                    source = self.name
                )
                self.event['PNG_EOF'] = data[trailer_index:]

                self.files.append(extract_file)