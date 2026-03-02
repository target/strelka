import json
import os
import sys
from kafka import KafkaProducer

KAFKA_BROKER = os.getenv("KAFKA_BROKER", "localhost:9092")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "rules_topic")


def main(event_type, rule_file):
    with open(rule_file, "r") as f:
        rule_body = f.read()

    rule_name = None
    for line in rule_body.splitlines():
        if line.strip().startswith("rule "):
            rule_name = line.split()[1]
            break

    if not rule_name:
        print("[!] Invalid YARA rule (no rule name)")
        return

    message = {
        "event_type": event_type.upper(),
        "id": rule_name,
        "version": 1,
        "payload": {
            "rule_engine": "YARA",
            "name": rule_name,
            "raw": rule_body,
            "is_enabled": True
        }
    }

    producer = KafkaProducer(
        bootstrap_servers=[KAFKA_BROKER],
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
    )

    producer.send(KAFKA_TOPIC, message)
    producer.flush()

    print(f"[✓] Sent {event_type} for rule {rule_name}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 send_yara_rule.py <CREATE|UPDATE|UPSERT|DELETE> <rule.yar>")
        sys.exit(1)

    main(sys.argv[1], sys.argv[2])
