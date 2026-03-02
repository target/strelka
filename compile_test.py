import yara

RULES_FILE = "/root/discover/strelka/all_in_one.yar"

try:
    rules = yara.compile(filepath=RULES_FILE)
    print("[✓] YARA rules compiled successfully")

except yara.SyntaxError as e:
    print(f"[!] YARA syntax error: {e}")

except yara.Error as e:
    print(f"[!] YARA general error: {e}")
