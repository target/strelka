import os
import sys
import yara

if len(sys.argv) != 2:
    print(f"Usage: python3 {sys.argv[0]} <yara_rules_dir>")
    sys.exit(1)

RULES_DIR = sys.argv[1]

if not os.path.isdir(RULES_DIR):
    print(f"Directory not found: {RULES_DIR}")
    sys.exit(1)

for root, _, files in os.walk(RULES_DIR):
    for name in files:
        if not name.endswith((".yar", ".yara")):
            continue

        path = os.path.join(root, name)

        try:
            yara.compile(filepath=path)
        except Exception as e:
            print(f"[DELETE] {path}")
            print(f"         {e}")
            try:
                os.remove(path)
            except Exception as rm_err:
                print(f"[ERROR] Could not delete {path}: {rm_err}")

