import pgpdump
from pgpdump.packet import PublicKeyEncryptedSessionKeyPacket
from pgpdump.packet import PublicKeyPacket
from pgpdump.packet import SignaturePacket
from pgpdump.packet import TrustPacket
from pgpdump.packet import UserAttributePacket
from pgpdump.packet import UserIDPacket

from server import objects


class ScanPgp(objects.StrelkaScanner):
    """Collects metadata from PGP files."""
    def scan(self, file_object, options):
        self.metadata["total"] = {"publicKeys": 0,
                                  "publicKeyEncryptedSessionKeys": 0,
                                  "signatures": 0,
                                  "trusts": 0,
                                  "userAttributes": 0,
                                  "userIds": 0}

        self.metadata.setdefault("publicKeys", [])
        self.metadata.setdefault("publicKeyEncryptedSessionKeys", [])
        self.metadata.setdefault("signatures", [])
        self.metadata.setdefault("trusts", [])
        self.metadata.setdefault("userAttributes", [])
        self.metadata.setdefault("userIds", [])

        try:
            data = pgpdump.AsciiData(file_object.data)
            for packet in data.packets():
                if isinstance(packet, PublicKeyPacket):
                    self.metadata["total"]["publicKeys"] += 1
                    public_key_entry = {}
                    key_id = getattr(packet, "key_id", None)
                    if key_id is not None:
                        public_key_entry["keyId"] = key_id
                    pubkey_version = getattr(packet, "pubkey_version", None)
                    if pubkey_version is not None:
                        public_key_entry["pubkeyVersion"] = pubkey_version
                    fingerprint = getattr(packet, "fingerprint", None)
                    if fingerprint is not None:
                        public_key_entry["fingerprint"] = fingerprint
                    pub_algorithm_type = getattr(packet, "pub_algorithm_type", None)
                    if pub_algorithm_type is not None:
                        public_key_entry["pubAlgorithmType"] = pub_algorithm_type
                    key_value = getattr(packet, "key_value", None)
                    if key_value is not None:
                        public_key_entry["keyValue"] = key_value
                    creation_time = getattr(packet, "creation_time", None)
                    if creation_time is not None:
                        public_key_entry["creationTime"] = creation_time.isoformat(timespec="seconds")
                    expiration_time = getattr(packet, "expiration_time", None)
                    if expiration_time is not None:
                        public_key_entry["expirationTime"] = expiration_time.isoformat(timespec="seconds")

                    if (public_key_entry and
                        public_key_entry not in self.metadata["publicKeys"]):
                        self.metadata["publicKeys"].append(public_key_entry)

                elif isinstance(packet, PublicKeyEncryptedSessionKeyPacket):
                    self.metadata["total"]["publicKeyEncryptedSessionKeys"] += 1
                    public_key_encrypted_session_key_entry = {}
                    session_key_version = getattr(packet, "session_key_version", None)
                    if session_key_version is not None:
                        public_key_encrypted_session_key_entry["sessionKeyVersion"] = session_key_version
                    key_id = getattr(packet, "key_id", None)
                    if key_id is not None:
                        public_key_encrypted_session_key_entry["keyId"] = key_id
                    pub_algorithm = getattr(packet, "pub_algorithm", None)
                    if pub_algorithm is not None:
                        public_key_encrypted_session_key_entry["pubAlgorithm"] = pub_algorithm

                    if (public_key_encrypted_session_key_entry and
                        public_key_encrypted_session_key_entry not in self.metadata["publicKeyEncryptedSessionKeys"]):
                        self.metadata["publicKeyEncryptedSessionKeys"].append(public_key_encrypted_session_key_entry)

                elif isinstance(packet, SignaturePacket):
                    self.metadata["total"]["signatures"] += 1
                    signature_packet_entry = {}
                    key_id = getattr(packet, "key_id", None)
                    if key_id is not None:
                        signature_packet_entry["keyId"] = key_id
                    sig_version = getattr(packet, "sig_version", None)
                    if sig_version is not None:
                        signature_packet_entry["sigVersion"] = sig_version
                    sig_type = getattr(packet, "sig_type", None)
                    if sig_type is not None:
                        signature_packet_entry["sigType"] = sig_type
                    hash_algorithm = getattr(packet, "hash_algorithm", None)
                    if hash_algorithm is not None:
                        signature_packet_entry["hashAlgorithm"] = hash_algorithm
                    pub_algorithm = getattr(packet, "pub_algorithm", None)
                    if pub_algorithm is not None:
                        signature_packet_entry["pubAlgorithm"] = pub_algorithm
                    creation_time = getattr(packet, "creation_time", None)
                    if creation_time is not None:
                        signature_packet_entry["creationTime"] = creation_time.isoformat(timespec="seconds")
                    expiration_time = getattr(packet, "expiration_time", None)
                    if expiration_time is not None:
                        signature_packet_entry["expirationTime"] = expiration_time.isoformat(timespec="seconds")
                    length = getattr(packet, "length", None)
                    if length is not None:
                        signature_packet_entry["length"] = length

                    if (signature_packet_entry and
                        signature_packet_entry not in self.metadata["signatures"]):
                        self.metadata["signatures"].append(signature_packet_entry)

                elif isinstance(packet, TrustPacket):
                    self.metadata["total"]["trusts"] += 1
                    trust_entry = {}
                    trusts = getattr(packet, "trusts", None)
                    if trusts is not None:
                        trust_entry["trusts"] = trusts

                    if (trust_entry and
                        trust_entry not in self.metadata["trusts"]):
                        self.metadata["trusts"].append(trust_entry)

                elif isinstance(packet, UserAttributePacket):
                    self.metadata["total"]["userAttributes"] += 1
                    user_attribute_entry = {}
                    image_format = getattr(packet, "image_format", None)
                    if image_format is not None:
                        user_attribute_entry["imageFormat"] = image_format
                    image_data = getattr(packet, "image_data", None)
                    if image_data is not None:
                        user_attribute_entry["imageData"] = image_data

                    if (user_attribute_entry and
                        user_attribute_entry not in self.metadata["userAttributes"]):
                        self.metadata["userAttributes"].append(user_attribute_entry)

                elif isinstance(packet, UserIDPacket):
                    self.metadata["total"]["userIds"] += 1
                    user_id_entry = {}
                    user = getattr(packet, "user", None)
                    if user is not None:
                        user_id_entry["user"] = user
                    user_name = getattr(packet, "user_name", None)
                    if user_name is not None:
                        user_id_entry["userName"] = user_name
                    user_email = getattr(packet, "user_email", None)
                    if user_email is not None:
                        user_id_entry["userEmail"] = user_email

                    if (user_id_entry and
                        user_id_entry not in self.metadata["userIds"]):
                        self.metadata["userIds"].append(user_id_entry)

        except TypeError:
            file_object.flags.append(f"{self.scanner_name}::type_error")
