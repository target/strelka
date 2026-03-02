import os
import glob
import argparse
import yara
import re


def is_index_file(path):
    return path.endswith("_index.yar")


def extract_rules(file_content):
    """
    Extract individual YARA rules from file content.
    Very simple rule splitter based on 'rule' keyword.
    """
    pattern = re.compile(r'(rule\s+[^{]+\{.*?\})', re.DOTALL)
    return pattern.findall(file_content)


def is_rule_valid(rule_text):
    """
    Try to compile a single rule.
    Return True if valid, False otherwise.
    """
    try:
        yara.compile(source=rule_text)
        return True
    except Exception as e:
        print(f"    [-] Invalid rule skipped: {e}")
        return False


def merge_yara_rules(input_dir, output_file):
    yara_files = glob.glob(
        os.path.join(input_dir, "**", "*.yar"),
        recursive=True
    )

    merged = []

    for yara_file in yara_files:

        if is_index_file(yara_file):
            continue

        try:
            with open(yara_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            # Remove include statements
            content = "\n".join(
                line for line in content.splitlines()
                if not line.strip().startswith("include")
            )

            rules = extract_rules(content)

            valid_rules = []

            for rule in rules:
                if is_rule_valid(rule):
                    valid_rules.append(rule)
                else:
                    print(f"    [!] Skipped bad rule in {yara_file}")

            if valid_rules:
                merged.append(
                    f"\n\n// ===== Source: {yara_file} =====\n"
                    + "\n\n".join(valid_rules)
                )
                print(f"[+] Processed: {yara_file} ({len(valid_rules)} valid rules)")
            else:
                print(f"[!] No valid rules in: {yara_file}")

        except Exception as e:
            print(f"[ERROR] Failed to process {yara_file}: {e}")

    if not merged:
        print("[!] No YARA rules merged")
        return

    with open(output_file, "w", encoding="utf-8") as out:
        out.write("\n".join(merged))

    print(f"\n[✓] Clean merged rules saved to: {output_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Merge YARA rules (compile each rule individually)")
    parser.add_argument("input_dir", help="Root YARA rules directory")
    parser.add_argument("-o", "--output", default="all_in_one.yar")

    args = parser.parse_args()
    merge_yara_rules(args.input_dir, args.output)
