import requests
import base64
from urllib.parse import unquote
import sys

def clean_link(raw_link):
    if "#" not in raw_link:
        return raw_link
    base, remark_enc = raw_link.rsplit("#", 1)
    try:
        clean_remark = unquote(remark_enc).strip()
        clean_remark = " ".join(clean_remark.split())
        clean_remark = clean_remark.replace("\u200b", "").replace("\u00a0", " ")
        if len(clean_remark) > 80:
            clean_remark = clean_remark[:77] + "..."
    except:
        clean_remark = remark_enc
    return f"{base}#{clean_remark}"

def process_entry(entry):
    entry = entry.strip()
    if not entry:
        return []
    if entry.startswith(("http://", "https://")):
        try:
            r = requests.get(entry, timeout=20)
            r.raise_for_status()
            content = r.text.strip()
        except:
            return []
    else:
        content = entry
    lines = content.splitlines()
    if len(lines) == 1 and not lines[0].startswith(("vless://", "vmess://", "trojan://", "ss://")):
        try:
            padding = "=" * (-len(lines[0]) % 4)
            decoded = base64.urlsafe_b64decode(lines[0] + padding).decode("utf-8")
            lines = decoded.splitlines()
        except:
            pass
    cleaned = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if not line.startswith(("vless://", "vmess://", "trojan://", "ss://")):
            try:
                padding = "=" * (-len(line) % 4)
                decoded = base64.urlsafe_b64decode(line + padding).decode("utf-8").strip()
                if decoded.startswith(("vless://", "vmess://", "trojan://", "ss://")):
                    line = decoded
            except:
                pass
        if line.startswith(("vless://", "vmess://", "trojan://", "ss://")):
            cleaned.append(clean_link(line))
        else:
            cleaned.append(line)
    return cleaned

def main():
    cleaned_all = []
    try:
        with open("subs.txt", encoding="utf-8") as f:
            entries = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        sys.exit(1)
    for entry in entries:
        configs = process_entry(entry)
        if configs:
            cleaned_all.extend(configs)
    unique = []
    seen = set()
    for link in cleaned_all:
        if link not in seen:
            seen.add(link)
            unique.append(link)
    with open("result.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(unique) + "\n")

if __name__ == "__main__":
    main()
