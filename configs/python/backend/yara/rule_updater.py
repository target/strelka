import os
import json
import yara
import tempfile
from kafka import KafkaConsumer

RULES_DIR = "/etc/strelka"
RULES_FILE = f"{RULES_DIR}/all_in_one.yar"
COMPILED_FILE = f"{RULES_DIR}/rules.compiled"

KAFKA_BROKER = os.getenv("KAFKA_BROKER", "localhost:9092")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "rules_topic")
KAFKA_GROUP = os.getenv("KAFKA_GROUP", "rule_updater")


# ================= helpers =================

def load_rules():
    if not os.path.exists(RULES_FILE):
        return ""
    with open(RULES_FILE, "r") as f:
        return f.read()


def save_rules(content):
    with open(RULES_FILE, "w") as f:
        f.write(content)


def rule_exists(all_rules, rule_name):
    return f"rule {rule_name}" in all_rules


def remove_rule(all_rules, rule_name):
    if not rule_exists(all_rules, rule_name):
        return all_rules
    before, rest = all_rules.split(f"rule {rule_name}", 1)
    rest = rest[rest.find("}") + 1 :]
    return before + rest


def upsert_rule(all_rules, rule_name, rule_body):
    if rule_exists(all_rules, rule_name):
        return remove_rule(all_rules, rule_name) + "\n\n" + rule_body
    return all_rules + "\n\n" + rule_body


def validate_rule(rule_body):
    # try compiling rule alone
    yara.compile(source=rule_body)


def compile_and_save():
    compiled = yara.compile(filepath=RULES_FILE)

    with tempfile.NamedTemporaryFile(
        dir=RULES_DIR, prefix=".rules.", delete=False
    ) as tmp:
        tmp_path = tmp.name

    compiled.save(tmp_path)
    os.replace(tmp_path, COMPILED_FILE)


# ================= main =================

def main():
    consumer = KafkaConsumer(
        KAFKA_TOPIC,
        bootstrap_servers=[KAFKA_BROKER],
        group_id=KAFKA_GROUP,
        value_deserializer=lambda m: json.loads(m.decode("utf-8")),
        auto_offset_reset="latest",
        enable_auto_commit=True,
    )

    print("[*] rule_updater started")

    for msg in consumer:
        data = msg.value

        event_type = data.get("event_type", "").upper()
        payload = data.get("payload", {})

        if payload.get("rule_engine") != "YARA":
            continue

        rule_name = payload.get("name")
        rule_body = payload.get("raw")

        if not rule_name or not rule_body:
            print("[!] Invalid payload")
            continue

        print(f"[+] {event_type} rule {rule_name}")

        try:
            # 1️⃣ validate rule alone
            validate_rule(rule_body)

            all_rules = load_rules()
            exists = rule_exists(all_rules, rule_name)

            if event_type in ("CREATE", "UPDATE", "UPSERT"):
                all_rules = upsert_rule(all_rules, rule_name, rule_body)

            elif event_type == "DELETE":
                if exists:
                    all_rules = remove_rule(all_rules, rule_name)
                else:
                    print("[!] Rule not found for delete")
                    continue

            else:
                print(f"[!] Unknown event_type: {event_type}")
                continue

            # 2️⃣ save + compile all
            save_rules(all_rules)
            compile_and_save()

            print(f"[✓] Rule {rule_name} applied successfully")

        except yara.SyntaxError as e:
            print(f"[!] YARA syntax error in rule {rule_name}: {e}")

        except yara.Error as e:
            print(f"[!] YARA compile error: {e}")

        except Exception as e:
            print(f"[!] General error: {e}")


if __name__ == "__main__":
    main()
