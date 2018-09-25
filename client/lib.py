"""Defines classes and functions that are used to create client utilities."""
import io
import logging
import zlib

from server import strelka_pb2


def request_to_protobuf(file=None, location=None, filename="",
                        source="", flavors=[], metadata={}):
    """Converts file request to FileRequest protobuf.

    Args:
        file: Bytes or file-like object that represents file data.
        location: Dictionary that contains details on where to retrieve
            file from.
        filename: String that contains the name of the file.
        source: String that describes where the file originated.
        flavors: List of flavors to assign to the file when the file object
            is created.
        metadata: Dictionary of metadata related to the file.

    Returns:
        Serialized FileRequest protobuf string.
    """
    file_request = strelka_pb2.FileRequest()

    if file is not None:
        if isinstance(file, io.IOBase):
            file_request.data = zlib.compress(file.read())
        elif isinstance(file, bytes):
            file_request.data = zlib.compress(file)
    elif location is not None:
        if isinstance(location, dict):
            for (key, value) in location.items():
                file_request.location[key] = value

    if filename:
        file_request.filename = filename
    if source:
        file_request.source = source
    if flavors:
        file_request.flavors[:] = flavors
    if metadata:
        for (key, value) in metadata.items():
            file_request.metadata[key] = value

    return file_request.SerializeToString()


def parse_bro_metadata(filename, meta_separator):
    """Parses Bro metadata.

    This function parses Bro metadata that is encoded in the filename. The
    parsed metadata can include any of the following, in order:
        File source (e.g. HTTP, SMTP, SMB)
        Connection UID
        File UID
        Originator address
        Responder address
        File MIME type
        Flex metadata (e.g. for files sourced from HTTP, this is the HTTP host
            metadata, for files sourced from SMTP, this is the SMTP subject
            metadata)

    The filename must adhere to the following pattern (where <SEP> is a
    defined separator string):
        <random integers><SEP><Bro Source field OR empty><SEP><Bro Connection UID field OR empty><SEP><Bro file UID field OR empty><SEP><Bro id.orig_h field OR empty><SEP><Bro MIME type field OR empty><SEP><Bro metadata field OR empty><SEP>

    In the example below, the separator string is "S^E^P^" and all fields are
    present except the MIME type field:
        0046S^E^PHTTPS^E^PC5lS4i1kVyL9cCrMAfS^E^PFT9iQI3w7gllMdjxEhS^E^P192.168.1.1S^E^P192.168.1.2S^E^PS^E^Pexample.comS^E^P

    The example expands to this:
        '0046'
        'HTTP'
        'C5lS4i1kVyL9cCrMAf'
        'FT9iQI3w7gllMdjxEh'
        '192.168.1.1'
        '192.168.1.2'
        ''
        'example.com'
        ''

    Args:
        filename: Bro filename to parse.
        meta_separator: String used as the separator in the filename.

    Returns:
        Tuple containing parsed Bro metadata as a dictionary and Bro MIME
        type (flavors) as a list.
    """
    bro_metadata = {}
    bro_flavors = []

    split_filename = filename.split(meta_separator)
    bro_metadata["broSource"] = split_filename[1]
    bro_metadata["broUid"] = split_filename[2]
    bro_metadata["broFuid"] = split_filename[3]
    bro_metadata["broIdOrigH"] = split_filename[4]
    bro_metadata["broIdRespH"] = split_filename[5]
    if split_filename[6]:
        bro_metadata["broMimeType"] = split_filename[6]
        bro_flavors.append(split_filename[6])
    if split_filename[7]:
        bro_metadata["broMetadata"] = split_filename[7]

    return (bro_metadata, bro_flavors)


class Client:
    """Class that defines client ZMQ connections.

    Attributes:
        zmq: ZMQ connection to use.
        context: Context to use in ZMQ connection.
        poll: Poller to use in ZMQ connection.
        broker: Network address plus network port of the broker
            (e.g. "127.0.0.1:5558").
        use_green: Boolean that determines if PyZMQ green should be used. This
            can increase performance at the risk of message loss.
        broker_public_key: Location of the broker Curve public key
            certificate. If set to None, then Curve encryption is not enabled.
            Defaults to None. Must be enabled if the broker is confgured to
            use Curve encryption.
        client_secret_key: Location of the client Curve secret key
            certificate. If set to None, then Curve encryption is not enabled.
            Defaults to None. Must be enabled if the broker is confgured to
            use Curve encryption.
    """
    def __init__(self, broker, use_green=False,
                 broker_public_key=None, client_secret_key=None):
        if use_green:
            import zmq.green as zmq
        else:
            import zmq

        self._zmq = zmq
        self._context = self._zmq.Context()
        self._poll = zmq.Poller()
        self._broker = broker
        self._broker_public_key = broker_public_key
        self._client_secret_key = client_secret_key
        self._connect()

    def close(self):
        """Disconnects and terminates the connection.

        Raises:
            Exception: Unknown exception occurred.
        """
        try:
            self._disconnect()
            self._context.term()
        except Exception:
            logging.exception("client: exception while disconnecting from"
                              " broker (see traceback below)")

    def _connect(self):
        """Establishes connection to the broker.

        Connections to the broker use ZMQ PUSH sockets. The client will
        receive no return message from the broker.
        """
        self._client = self._context.socket(self._zmq.PUSH)

        if self._client_secret_key and self._broker_public_key:
            from zmq.auth import load_certificate
            (client_public,
             client_secret) = load_certificate(self._client_secret_key)
            self._client.curve_secretkey = client_secret
            self._client.curve_publickey = client_public
            (server_public, _) = load_certificate(self._broker_public_key)
            self._client.curve_serverkey = server_public

        self._client.connect(self._broker)
        self._poll.register(self._client, self._zmq.POLLIN)

    def _disconnect(self):
        """Disconnects the connection.

        When LINGER is set to 0, this is an immediate disconnection.
        """
        self._client.setsockopt(self._zmq.LINGER, 0)
        self._client.close()
        self._poll.unregister(self._client)

    def _send(self, protobuf_request, timeout):
        """Sends file requests to the broker.

        If unknown exceptions occur, then the connection to the broker is
        toggled and the file request is retried once more.

        Args:
            protobuf_request: Serialized protobuf FileRequest to be sent to
                the broker as a file request.
            timeout: Number of seconds to wait for a file request to be
                successfully sent.

        Returns:
            Boolean that describes if the file request was successfully
            or unsuccessfully sent.

        Raises:
            NotDone: If timeout is used and the file request was not sent
            within the configured time, then ZMQ raises this exception.
        """
        try:
            if timeout:
                tracker = self._client.send_multipart([protobuf_request],
                                                      copy=False,
                                                      track=True)
                tracker.wait(timeout)
            else:
                self._client.send_multipart([protobuf_request])

        except self._zmq.NotDone:
            logging.debug("client: message sending timed out")
            return False

        except:  # noqa
            try:
                self._disconnect()
                self._connect()
                if timeout:
                    tracker = self._client.send_multipart([protobuf_request],
                                                          copy=False,
                                                          track=True)
                    tracker.wait(timeout)
                else:
                    self._client.send_multipart([protobuf_request])

            except:  # noqa
                return False

        return True

    def send(self, protobuf_request, retry=0, timeout=None):
        """Sends file requests to the broker.

        Wrapper for the _send() method, this method includes the capability to
        retry file requests if they are not successfully sent.

        Args:
            protobuf_request: Serialized protobuf FileRequest to be sent to
                the broker as a file request.
            retry: Number of times to retry sending a file request if it was
                unsuccessfully sent. Defaults to 0.
            timeout: Number of seconds to wait for a file request to be
                successfully sent. Defaults to None.

        Returns:
            Boolean that describes if the file request was successfully
            or unsuccessfully sent. This does not guarantee delivery.

        Raises:
            Exception: Unknown exception occurred.
        """
        _timeout = timeout
        retries_left = retry
        try:
            result = self._send(protobuf_request, timeout=_timeout)
            while retries_left and not result:
                self._disconnect()
                self._connect()
                result = self._send(protobuf_request, timeout=_timeout)
                retries_left -= 1
            return result

        except Exception:
            logging.exception("client: exception while sending file"
                              " (see traceback below)")
