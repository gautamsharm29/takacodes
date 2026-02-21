import os
import re
import sys

KEYWORDS = [
    b"pay", b"purchase", b"billing", b"coin", b"bean", b"coupon", b"vip",
    b"money", b"bypass", b"free", b"verify", b"receipt", b"google_play",
    b"debug", b"test", b"mock", b"sandbox", b"hack", b"cheat"
]

def get_strings(filepath, min_len=4):
    with open(filepath, "rb") as f:
        content = f.read()

    # Regex to find printable strings
    regex = rb"[ -~]{" + str(min_len).encode() + rb",}"
    matches = re.finditer(regex, content)

    for match in matches:
        yield match.group().decode("utf-8", errors="ignore"), match.start()

def analyze_file(filepath):
    print(f"Analyzing {filepath}...")
    try:
        strings = list(get_strings(filepath))
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
        return

    findings = []

    # heuristic: check for payment classes in DEX
    if filepath.endswith(".dex"):
        for s, offset in strings:
            if "com/pay/lwchat_pay" in s or "LWChat_PayServiceImp" in s:
                findings.append(f"Found Payment Class/Method: {s}")
            if "Bypass" in s or "bypass" in s:
                 findings.append(f"Found Bypass keyword: {s}")
            if "verify" in s.lower() and "receipt" in s.lower():
                 findings.append(f"Found Receipt Verification logic: {s}")

    # heuristic: check for payment strings in SO
    elif filepath.endswith(".so"):
        for s, offset in strings:
            if any(k.decode() in s.lower() for k in KEYWORDS):
                # Filter out common noise
                if "free" in s.lower() and ("mem" in s.lower() or "context" in s.lower()):
                    continue
                findings.append(f"Found Keyword '{s}' at offset {hex(offset)}")

    if findings:
        print(f"  Found {len(findings)} potential issues:")
        for f in findings[:20]: # Limit output
            print(f"    - {f}")
        if len(findings) > 20:
            print(f"    - ... and {len(findings)-20} more.")
    else:
        print("  No significant findings.")
    print("-" * 40)

def main():
    # Find all .dex and .so files
    files_to_analyze = []

    # Walk base directory for dex
    for root, dirs, files in os.walk("base"):
        for file in files:
            if file.endswith(".dex"):
                files_to_analyze.append(os.path.join(root, file))

    # Walk split_config for so
    for root, dirs, files in os.walk("split_config.arm64_v8a"):
        for file in files:
            if file.endswith(".so"):
                files_to_analyze.append(os.path.join(root, file))

    print(f"Found {len(files_to_analyze)} files to analyze.")
    for filepath in files_to_analyze:
        analyze_file(filepath)

if __name__ == "__main__":
    main()
