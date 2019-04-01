import pgpdump
from pgpdump.packet import PublicKeyEncryptedSessionKeyPacket
from pgpdump.packet import PublicKeyPacket
from pgpdump.packet import SignaturePacket
from pgpdump.packet import TrustPacket
from pgpdump.packet import UserAttributePacket
from pgpdump.packet import UserIDPacket

from strelka import core


class ScanPgp(core.StrelkaScanner):
    """Collects metadata from PGP files."""
    def scan(self, data, file_object, options):
        self.metadata['total'] = {
            'publicKeys': 0,
            'publicKeyEncryptedSessionKeys': 0,
            'signatures': 0,
            'trusts': 0,
            'userAttributes': 0,
            'userIds': 0,
        }

        self.metadata.setdefault('publicKeys', [])
        self.metadata.setdefault('publicKeyEncryptedSessionKeys', [])
        self.metadata.setdefault('signatures', [])
        self.metadata.setdefault('trusts', [])
        self.metadata.setdefault('userAttributes', [])
        self.metadata.setdefault('userIds', [])

        try:
            data = pgpdump.AsciiData(data)
            for packet in data.packets():
                if isinstance(packet, PublicKeyPacket):
                    self.metadata['total']['publicKeys'] += 1
                    public_key_entry = {
                        'keyId': getattr(packet, 'key_id', None),
                        'pubkeyVersion': getattr(packet, 'pubkey_version', None),
                        'fingerprint': getattr(packet, 'fingerprint', None),
                        'pubAlgorithmType': getattr(packet, 'pub_algorithm_type', None),
                        'keyValue': getattr(packet, 'key_value', None),
                    }

                    creation_time = getattr(packet, 'creation_time', None)
                    if creation_time is not None:
                        public_key_entry['creationTime'] = creation_time.isoformat(timespec='seconds')
                    expiration_time = getattr(packet, 'expiration_time', None)
                    if expiration_time is not None:
                        public_key_entry['expirationTime'] = expiration_time.isoformat(timespec='seconds')

                    if public_key_entry not in self.metadata['publicKeys']:
                        self.metadata['publicKeys'].append(public_key_entry)

                elif isinstance(packet, PublicKeyEncryptedSessionKeyPacket):
                    self.metadata['total']['publicKeyEncryptedSessionKeys'] += 1
                    public_key_encrypted_session_key_entry = {
                        'sessionKeyVersion': getattr(packet, 'session_key_version', None),
                        'keyId': getattr(packet, 'key_id', None),
                        'pubAlgorithm': getattr(packet, 'pub_algorithm', None),
                    }

                    if public_key_encrypted_session_key_entry not in self.metadata['publicKeyEncryptedSessionKeys']:
                        self.metadata['publicKeyEncryptedSessionKeys'].append(public_key_encrypted_session_key_entry)

                elif isinstance(packet, SignaturePacket):
                    self.metadata['total']['signatures'] += 1
                    signature_packet_entry = {
                        'keyId': getattr(packet, 'key_id', None),
                        'sigVersion': getattr(packet, 'sig_version', None),
                        'sigType': getattr(packet, 'sig_type', None),
                        'hashAlgorithm': getattr(packet, 'hash_algorithm', None),
                        'pubAlgorithm': getattr(packet, 'pub_algorithm', None),
                        'length': getattr(packet, 'length', None),
                    }
                    creation_time = getattr(packet, 'creation_time', None)
                    if creation_time is not None:
                        signature_packet_entry['creationTime'] = creation_time.isoformat(timespec='seconds')
                    expiration_time = getattr(packet, 'expiration_time', None)
                    if expiration_time is not None:
                        signature_packet_entry['expirationTime'] = expiration_time.isoformat(timespec='seconds')

                    if signature_packet_entry not in self.metadata['signatures']:
                        self.metadata['signatures'].append(signature_packet_entry)

                elif isinstance(packet, TrustPacket):
                    self.metadata['total']['trusts'] += 1
                    trust_entry = {
                        'trusts': getattr(packet, 'trusts', None),
                    }

                    if trust_entry not in self.metadata['trusts']:
                        self.metadata['trusts'].append(trust_entry)

                elif isinstance(packet, UserAttributePacket):
                    self.metadata['total']['userAttributes'] += 1
                    user_attribute_entry = {
                        'imageFormat': getattr(packet, 'image_format', None),
                        'imageData': getattr(packet, 'image_data', None),
                    }

                    if user_attribute_entry not in self.metadata['userAttributes']:
                        self.metadata['userAttributes'].append(user_attribute_entry)

                elif isinstance(packet, UserIDPacket):
                    self.metadata['total']['userIds'] += 1
                    user_id_entry = {
                        'user': getattr(packet, 'user', None),
                        'userName': getattr(packet, 'user_name', None),
                        'userEmail': getattr(packet, 'user_email', None),
                    }

                    if user_id_entry not in self.metadata['userIds']:
                        self.metadata['userIds'].append(user_id_entry)

        except TypeError:
            self.flags.add(f'{self.scanner_name}::type_error')
