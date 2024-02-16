import pgpdump
from pgpdump.packet import (
    CompressedDataPacket,
    Packet,
    PublicKeyEncryptedSessionKeyPacket,
    PublicKeyPacket,
    SecretKeyPacket,
    SignaturePacket,
    TrustPacket,
    UserAttributePacket,
    UserIDPacket,
)

from strelka import strelka


class ScanPgp(strelka.Scanner):
    """Collects metadata from PGP files."""

    def scan(self, data, file, options, expire_at):
        self.event["total"] = {
            "public_keys": 0,
            "public_key_encrypted_session_keys": 0,
            "secret_keys": 0,
            "signatures": 0,
            "trusts": 0,
            "user_attributes": 0,
            "user_ids": 0,
        }

        self.event.setdefault("public_keys", [])
        self.event.setdefault("public_key_encrypted_session_keys", [])
        self.event.setdefault("secret_keys", [])
        self.event.setdefault("signatures", [])
        self.event.setdefault("trusts", [])
        self.event.setdefault("user_attributes", [])
        self.event.setdefault("user_ids", [])

        try:
            self.parse_pgpdump(data)
        except Exception:
            self.flags.append("pgpdump_error")

    def parse_pgpdump(self, data):
        pgpdump_data = None

        try:
            pgpdump_data = pgpdump.AsciiData(data)
        except (pgpdump.utils.PgpdumpException, AttributeError):
            try:
                pgpdump_data = pgpdump.BinaryData(data)
            except pgpdump.utils.PgpdumpException:
                self.flags.append("pgpdump_parse_error")

        if pgpdump_data:
            for packet in pgpdump_data.packets():
                if isinstance(packet, CompressedDataPacket):
                    self.parse_pgpdump(packet.decompressed_data)

                elif isinstance(packet, SecretKeyPacket):
                    self.event["total"]["secret_keys"] += 1
                    secret_key_entry = {
                        "key_id": getattr(packet, "key_id", None),
                        "pubkey_version": getattr(packet, "secretkey_version", None),
                        "fingerprint": getattr(packet, "fingerprint", None),
                        "pub_algorithm_type": getattr(
                            packet, "secret_algorithm_type", None
                        ),
                        "key_value": getattr(packet, "key_value", None),
                    }

                    creation_time = getattr(packet, "creation_time", None)
                    if creation_time is not None:
                        secret_key_entry["creation_time"] = creation_time.isoformat()
                    expiration_time = getattr(packet, "expiration_time", None)
                    if expiration_time is not None:
                        secret_key_entry["expiration_time"] = (
                            expiration_time.isoformat()
                        )

                    if secret_key_entry not in self.event["secret_keys"]:
                        self.event["secret_keys"].append(secret_key_entry)

                elif isinstance(packet, PublicKeyPacket):
                    self.event["total"]["public_keys"] += 1
                    public_key_entry = {
                        "key_id": getattr(packet, "key_id", None),
                        "pubkey_version": getattr(packet, "pubkey_version", None),
                        "fingerprint": getattr(packet, "fingerprint", None),
                        "pub_algorithm_type": getattr(
                            packet, "pub_algorithm_type", None
                        ),
                        "key_value": getattr(packet, "key_value", None),
                    }

                    creation_time = getattr(packet, "creation_time", None)
                    if creation_time is not None:
                        public_key_entry["creation_time"] = creation_time.isoformat()
                    expiration_time = getattr(packet, "expiration_time", None)
                    if expiration_time is not None:
                        public_key_entry["expiration_time"] = (
                            expiration_time.isoformat()
                        )

                    if public_key_entry not in self.event["public_keys"]:
                        self.event["public_keys"].append(public_key_entry)

                elif isinstance(packet, PublicKeyEncryptedSessionKeyPacket):
                    self.event["total"]["public_key_encrypted_session_keys"] += 1
                    public_key_encrypted_session_key_entry = {
                        "session_key_version": getattr(
                            packet, "session_key_version", None
                        ),
                        "key_id": getattr(packet, "key_id", None),
                        "pub_algorithm": getattr(packet, "pub_algorithm", None),
                    }

                    if (
                        public_key_encrypted_session_key_entry
                        not in self.event["public_key_encrypted_session_keys"]
                    ):
                        self.event["public_key_encrypted_session_keys"].append(
                            public_key_encrypted_session_key_entry
                        )

                elif isinstance(packet, SignaturePacket):
                    self.event["total"]["signatures"] += 1
                    signature_packet_entry = {
                        "key_id": getattr(packet, "key_id", None),
                        "sig_version": getattr(packet, "sig_version", None),
                        "sig_type": getattr(packet, "sig_type", None),
                        "hash_algorithm": getattr(packet, "hash_algorithm", None),
                        "pub_algorithm": getattr(packet, "pub_algorithm", None),
                        "length": getattr(packet, "length", None),
                    }
                    creation_time = getattr(packet, "creation_time", None)
                    if creation_time is not None:
                        signature_packet_entry["creation_time"] = (
                            creation_time.isoformat()
                        )
                    expiration_time = getattr(packet, "expiration_time", None)
                    if expiration_time is not None:
                        signature_packet_entry["expiration_time"] = (
                            expiration_time.isoformat()
                        )

                    if signature_packet_entry not in self.event["signatures"]:
                        self.event["signatures"].append(signature_packet_entry)

                elif isinstance(packet, TrustPacket):
                    self.event["total"]["trusts"] += 1
                    trust_entry = {
                        "trusts": getattr(packet, "trusts", None),
                    }

                    if trust_entry not in self.event["trusts"]:
                        self.event["trusts"].append(trust_entry)

                elif isinstance(packet, UserAttributePacket):
                    self.event["total"]["user_attributes"] += 1
                    user_attribute_entry = {
                        "image_format": getattr(packet, "image_format", None),
                        "image_data": getattr(packet, "image_data", None),
                    }

                    if user_attribute_entry not in self.event["user_attributes"]:
                        self.event["user_attributes"].append(user_attribute_entry)

                elif isinstance(packet, UserIDPacket):
                    self.event["total"]["user_ids"] += 1
                    user_id_entry = {
                        "user": getattr(packet, "user", None),
                        "user_name": getattr(packet, "user_name", None),
                        "user_email": getattr(packet, "user_email", None),
                    }

                    if user_id_entry not in self.event["user_ids"]:
                        self.event["user_ids"].append(user_id_entry)

                elif isinstance(packet, Packet):
                    if packet.name == "Literal Data Packet":
                        pass
                        # print(packet.data)
