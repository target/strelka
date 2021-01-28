import grpc
import uuid
# These files are located in strelka/src/python/strelka/proto
import strelka_pb2
import strelka_pb2_grpc


class StrelkaFrontend:
    """ A basic implementation of Strelka's Frontend protobuf in Python

    Attributes:
        server: URL for the strelka frontend server (default: localhost:51314)
        cert: Path to connection certificate (default: None)
        gatekeeper: Specifies if gatekeeper should be used (default: True)
        source: An optional source identifier (default: None)
        timeout: Time in seconds until operation times out (default: 60)
        chunk: Data chunk size in bytes (default: 32768)
    """

    def __init__(self, 
                 server='localhost:57314',
                 cert=None,
                 gatekeeper=True,
                 source=None,
                 timeout=60,
                 chunk=32768):
        self.server = server
        self.cert = cert
        self.gatekeeper = gatekeeper
        self.source = source
        self.timeout = timeout
        self.chunk = chunk

    def __ScanFileRequest(self, filename):
        """ Generates a ScanFileRequest message defined in Strelka's Frontend protobuf

        Args:
            filename: Path of the file to be scanned
        Returns:
            stream ScanFileRequest
        """
        request = strelka_pb2.Request(id=str(uuid.uuid4()),
                                      client='strelka-python',
                                      source=self.source,
                                      gatekeeper=self.gatekeeper)
        attributes = strelka_pb2.Attributes(filename=filename)
        with open(filename, 'rb') as f:
            while True:
                chunk = f.read(self.chunk)
                if not chunk:
                    break
                yield strelka_pb2.ScanFileRequest(data=chunk,
                                                  request=request,
                                                  attributes=attributes)

    def ScanFile(self, filename):
        """ Streams ScanFileRequest to Strelka Frontend

        Args:
            filename: Path of the file to be scanned
        Returns:
            stream ScanResponse (may be empty)
        """
        if self.cert != None:
            with open(self.cert, 'rb') as f:
                cert = f.read()
            credentials = grpc.ssl_channel_credentials(cert)
            with grpc.secure_channel(target=self.server,
                                     credentials=credentials) as chan:
                stub = strelka_pb2_grpc.FrontendStub(chan)
                response = stub.ScanFile(self.__ScanFileRequest(filename),
                                         timeout=self.timeout)
                for i in response:
                    yield i.event
        else:
            with grpc.insecure_channel(self.server) as chan:
                stub = strelka_pb2_grpc.FrontendStub(chan)
                response = stub.ScanFile(self.__ScanFileRequest(filename),
                                         timeout=self.timeout)
                for i in response:
                    yield i.event


def main():
    import argparse
    parser = argparse.ArgumentParser(description='A basic'
                                     ' Python client for Strelka.')
    parser.add_argument('-s', '--server',
                        default='localhost:51314',
                        help='url for the strelka frontend server')
    parser.add_argument('-c', '--cert',
                        default=None,
                        help='path to connection certificate')
    parser.add_argument('-l', '--log',
                        default='strelka-python.log',
                        help='path to response log file')
    parser.add_argument('-f', '--file',
                        required=True,
                        help='file to submit for scanning')
    args = parser.parse_args()
    client = StrelkaFrontend(server=args.server,
                             cert=args.cert,
                             gatekeeper=False)
    result = client.ScanFile(args.file)
    with open(args.log, 'a', encoding='utf-8') as f:
        f.write('\n.'.join(result)+'\n')


if __name__ == '__main__':
    main()
