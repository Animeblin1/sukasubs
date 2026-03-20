#!/usr/bin/env python3
# @la_cringe

import base64
import gzip
import json
import re
import sys
import zlib
from urllib.parse import unquote, urlparse, parse_qs, quote

import requests
import yaml

PROXY_SCHEMES = (
    "vless://", "vmess://", "trojan://", "ss://",
    "hy2://", "hysteria2://", "hysteria://",
    "tuic://", "wireguard://", "wg://",
)

LINK_RE = re.compile(
    r'(?:vless|vmess|trojan|ss|hy2|hysteria2?|tuic|wireguard|wg)://[^\s\'"<>\]\[,}{`\\]+',
    re.IGNORECASE,
)

B64_RE = re.compile(r'[A-Za-z0-9+/\-_]{40,}={0,3}')

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
})

PROTO_LABELS = {
    "vless": "", "vmess": "VMess", "trojan": "Trojan",
    "ss": "SS", "hy2": "HY2", "hysteria2": "HY2",
    "hysteria": "HY1", "tuic": "TUIC", "wireguard": "WG", "wg": "WG",
}

_FLAG_RE = re.compile(r"[\U0001F1E6-\U0001F1FF]{2}")
_JUNK_RE = re.compile(
    r"[\|｜]\s*(?:тгк|tg|telegram|канал|channel|bot|бот|sub|подписка)\s*:?\s*@\S+",
    re.IGNORECASE,
)
_HANDLE_RE = re.compile(r"@\w+")
_TRAIL_RE = re.compile(r"\s*[\|｜\-–—]\s*$")


def _sanitize_remark(remark: str, scheme: str = "") -> str:
    remark = unquote(remark).strip()
    for ch in "\u200b\u200c\u200d\u00ad\ufeff":
        remark = remark.replace(ch, "")
    remark = remark.replace("\u00a0", " ")
    remark = re.sub(r"\s+", " ", remark).strip()
    remark = _JUNK_RE.sub("", remark)
    remark = re.sub(
        r"[\|｜]\s*(?:тгк|tg|telegram|канал|channel|подписка|sub|bot|бот).*$",
        "", remark, flags=re.IGNORECASE,
    )
    remark = _HANDLE_RE.sub("", remark)
    remark = _TRAIL_RE.sub("", remark).strip()

    flags = _FLAG_RE.findall(remark)
    flag = flags[0] if flags else ""
    clean = _FLAG_RE.sub("", remark).strip()
    clean = re.sub(r"^[\s|｜\-–—]+", "", clean).strip()
    parts = [p.strip() for p in re.split(r"[\|｜\-–—]", clean) if p.strip()]
    label = parts[0][:40].strip() if parts else ""
    proto = PROTO_LABELS.get(scheme.lower(), "")
    suffix_parts = [s for s in [label, proto] if s]
    result = ((flag + " ") if flag else "") + " ".join(suffix_parts)
    result = re.sub(r"\s+", " ", result).strip()
    return result or remark[:40]


def clean_link(raw_link, scheme: str = ""):
    if not scheme:
        m = re.match(r"^([a-zA-Z0-9+\-]+)://", raw_link)
        scheme = m.group(1) if m else ""
    if "#" not in raw_link:
        return raw_link
    base, remark_enc = raw_link.rsplit("#", 1)
    try:
        remark = _sanitize_remark(remark_enc, scheme)
    except Exception:
        remark = unquote(remark_enc)[:40]
    return f"{base}#{remark}"


def _h3_to_tcp_link(link):
    if "alpn=" not in link:
        return None
    try:
        base_part = link.split("#")[0]
        remark = link.split("#")[1] if "#" in link else ""
        scheme_host, _, qs = base_part.partition("?")
        params = {}
        for kv in qs.split("&"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                params[k] = v
        alpn_raw = unquote(params.get("alpn", ""))
        alpn_list = [a.strip() for a in re.split(r"[,\s]+", alpn_raw) if a.strip()]
        if "h3" not in alpn_list:
            return None
        tcp_alpn = [a for a in alpn_list if a != "h3"] or ["h2"]
        params["alpn"] = quote(",".join(tcp_alpn), safe="")
        new_qs = "&".join(f"{k}={v}" for k, v in params.items())
        new_remark = (unquote(remark) + " [TCP]").strip() if remark else "[TCP]"
        return f"{scheme_host}?{new_qs}#{new_remark}"
    except Exception:
        return None


def _qs(params):
    return "&".join(f"{k}={quote(str(v), safe='')}" for k, v in params.items() if v not in (None, ""))


def try_decode_base64(data: str):
    data = data.strip()
    for s in (data, data.replace("-", "+").replace("_", "/")):
        for pad in ("", "=" * (-len(s) % 4)):
            try:
                decoded = base64.b64decode(s + pad).decode("utf-8", errors="ignore")
                if decoded.strip():
                    return decoded
            except Exception:
                pass
    return None


def try_decompress(data: bytes):
    for fn in (gzip.decompress, zlib.decompress, lambda b: zlib.decompress(b, -15)):
        try:
            return fn(data).decode("utf-8", errors="ignore")
        except Exception:
            pass
    return None


def extract_links_raw(text: str) -> list[str]:
    results = []
    for m in LINK_RE.finditer(text):
        raw = m.group(0).rstrip(".,;:)'\"")
        scheme = raw.split("://")[0].lower()
        results.append(clean_link(raw, scheme))
    return results


def _try_all_b64_blobs(text: str) -> list[str]:
    links = []
    for m in B64_RE.finditer(text):
        blob = m.group(0)
        if len(blob) < 40:
            continue
        decoded = try_decode_base64(blob)
        if decoded:
            found = extract_links_raw(decoded)
            if found:
                links.extend(found)
    return links


def extract_from_html(html: str) -> list[str]:
    links = []

    # 1. strip tags → plain text scan
    text_content = re.sub(r"<[^>]+>", " ", html)
    text_content = re.sub(r"&amp;", "&", text_content)
    text_content = re.sub(r"&#(\d+);", lambda m: chr(int(m.group(1))), text_content)
    links.extend(extract_links_raw(text_content))

    # 2. HTML comments
    for comment in re.findall(r"<!--(.*?)-->", html, re.DOTALL):
        links.extend(extract_links_raw(comment))
        links.extend(_try_all_b64_blobs(comment))

    # 3. meta content attributes
    for val in re.findall(r'<meta[^>]+content=["\']([^"\']+)["\']', html, re.IGNORECASE):
        links.extend(extract_links_raw(unquote(val)))
        decoded = try_decode_base64(val)
        if decoded:
            links.extend(extract_links_raw(decoded))

    # 4. href / src / data-* / value attributes
    for val in re.findall(r'(?:href|src|data-[a-z\-]+|value)\s*=\s*["\']([^"\']{20,})["\']', html, re.IGNORECASE):
        val_dec = unquote(val)
        links.extend(extract_links_raw(val_dec))
        decoded = try_decode_base64(val)
        if decoded:
            links.extend(extract_links_raw(decoded))

    # 5. JS string literals (single, double, backtick)
    for val in re.findall(r'["\`]([^"\`\n]{30,})["\`]', html):
        links.extend(extract_links_raw(val))
        decoded = try_decode_base64(val)
        if decoded:
            links.extend(extract_links_raw(decoded))

    # 6. atob("...") calls
    for b64 in re.findall(r'atob\s*\(\s*["\']([A-Za-z0-9+/=\-_]+)["\']', html):
        decoded = try_decode_base64(b64)
        if decoded:
            links.extend(extract_links_raw(decoded))
            # decoded might itself be b64
            d2 = try_decode_base64(decoded)
            if d2:
                links.extend(extract_links_raw(d2))

    # 7. JSON blobs inside <script> tags
    for script in re.findall(r"<script[^>]*>(.*?)</script>", html, re.DOTALL | re.IGNORECASE):
        links.extend(extract_links_raw(script))
        # JSON.parse("...") or window.__NUXT__ = {...}
        for json_candidate in re.findall(r"[\[{].*?[\]}]", script, re.DOTALL):
            try:
                data = json.loads(json_candidate)
                links.extend(_walk_json(data))
            except Exception:
                pass
        links.extend(_try_all_b64_blobs(script))

    # 8. <script type="application/json">
    for json_block in re.findall(r'<script[^>]+type=["\']application/json["\'][^>]*>(.*?)</script>', html, re.DOTALL | re.IGNORECASE):
        try:
            data = json.loads(json_block)
            links.extend(_walk_json(data))
        except Exception:
            links.extend(extract_links_raw(json_block))

    # 9. Telegram channel HTML
    if "tgme_widget_message" in html:
        links.extend(parse_telegram_channel(html))

    # 10. XOR/ROT13 - scan for rot13'd proxy schemes
    rot13_text = html.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
    ))
    links.extend(extract_links_raw(rot13_text))

    return _dedup(links)


def _walk_json(obj, depth=0) -> list[str]:
    if depth > 8:
        return []
    links = []
    if isinstance(obj, str):
        links.extend(extract_links_raw(obj))
        decoded = try_decode_base64(obj)
        if decoded:
            links.extend(extract_links_raw(decoded))
    elif isinstance(obj, list):
        for item in obj:
            links.extend(_walk_json(item, depth + 1))
    elif isinstance(obj, dict):
        for v in obj.values():
            links.extend(_walk_json(v, depth + 1))
    return links


def parse_telegram_channel(html: str) -> list[str]:
    links = []
    html_unescape = {"&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": '"', "&#39;": "'"}
    blocks = re.findall(r'<div class="tgme_widget_message_text[^"]*"[^>]*>(.*?)</div>', html, re.DOTALL)
    for block in blocks:
        clean = re.sub(r"<[^>]+>", " ", block)
        for ent, repl in html_unescape.items():
            clean = clean.replace(ent, repl)
        links.extend(extract_links_raw(clean))
        links.extend(_try_all_b64_blobs(clean))
    if not links:
        links.extend(extract_from_html(html))
    return _dedup(links)


def fetch_telegram_all_pages(channel_url: str) -> list[str]:
    parsed = urlparse(channel_url)
    base = f"https://t.me/s/{parsed.path.lstrip('/').split('/')[0].split('?')[0]}"
    links = []
    url = base
    seen_ids = set()
    for _ in range(20):
        r = SESSION.get(url, timeout=30, allow_redirects=True)
        if r.status_code != 200:
            break
        html = r.text
        page_links = parse_telegram_channel(html)
        if not page_links:
            break
        new = [l for l in page_links if l not in seen_ids]
        if not new:
            break
        links.extend(new)
        seen_ids.update(new)
        before_m = re.search(r'href="[^"]+\?before=(\d+)"', html)
        if not before_m:
            break
        url = f"{base}?before={before_m.group(1)}"
    return links


def detect_and_parse(content: str | bytes, url: str = "") -> list[str]:
    if isinstance(content, bytes):
        decompressed = try_decompress(content)
        if decompressed:
            content = decompressed
        else:
            try:
                content = content.decode("utf-8", errors="ignore")
            except Exception:
                return []

    content = content.strip()
    if not content:
        return []

    # 1. Direct links in plain text
    links = extract_links_raw(content)
    if links:
        return _dedup(links)

    # 2. Whole body base64
    decoded = try_decode_base64(content)
    if decoded:
        links = extract_links_raw(decoded)
        if links:
            return _dedup(links)

    # 3. Per-line (plain or base64 per line)
    per_line = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        d = try_decode_base64(line)
        if d:
            per_line.extend(extract_links_raw(d))
        else:
            per_line.extend(extract_links_raw(line))
    if per_line:
        return _dedup(per_line)

    # 4. Clash YAML
    if re.search(r"^\s*(proxies|Proxies)\s*:", content, re.MULTILINE):
        links = parse_clash_yaml(content)
        if links:
            return _dedup(links)

    # 5. Sing-box / JSON
    stripped = content.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            data = json.loads(content)
            links = _walk_json(data)
            if not links and isinstance(data, dict) and "outbounds" in data:
                links = parse_singbox_json(content)
            if links:
                return _dedup(links)
        except Exception:
            pass

    # 6. HTML / JS
    if "<html" in content.lower() or "<div" in content.lower() or "<script" in content.lower():
        links = extract_from_html(content)
        if links:
            return _dedup(links)

    # 7. Any b64 blobs anywhere
    links = _try_all_b64_blobs(content)
    if links:
        return _dedup(links)

    # 8. Try YAML anyway
    if ":" in content:
        try:
            links = parse_clash_yaml(content)
            if links:
                return _dedup(links)
        except Exception:
            pass

    return []


def _dedup(links: list[str]) -> list[str]:
    seen = set()
    out = []
    for l in links:
        key = l.split("#")[0]
        if key not in seen:
            seen.add(key)
            out.append(l)
    return out


def fetch_url(url: str):
    try:
        parsed = urlparse(url)

        if parsed.netloc == "t.me":
            return None, url, "telegram"

        r = SESSION.get(url, timeout=30, allow_redirects=True)
        print(f"[FETCH] {url} -> {r.status_code} ct={r.headers.get('Content-Type','?')!r} len={len(r.content)}", file=sys.stderr)
        r.raise_for_status()

        ct = r.headers.get("Content-Type", "").lower()

        # Try decompress even if server forgot Content-Encoding
        decompressed = try_decompress(r.content)
        if decompressed and extract_links_raw(decompressed):
            return decompressed, r.url, ct

        if "octet-stream" in ct:
            decoded = try_decode_base64(r.content.decode("latin-1", errors="ignore"))
            if decoded:
                return decoded, r.url, ct

        try:
            return r.content.decode("utf-8"), r.url, ct
        except Exception:
            return r.content.decode("latin-1", errors="ignore"), r.url, ct

    except Exception as e:
        print(f"[WARN] fetch failed for {url}: {e}", file=sys.stderr)
        return None, url, ""


def process_entry(entry: str) -> list[str]:
    entry = entry.strip()
    if not entry or entry.startswith("#"):
        return []

    if entry.startswith(("http://", "https://")):
        parsed = urlparse(entry)

        # Telegram: paginate all posts
        if parsed.netloc == "t.me":
            links = fetch_telegram_all_pages(entry)
            print(f"[TG] {entry} -> {len(links)} links", file=sys.stderr)
            return links

        # Check if URL itself has base64/encoded sub in params
        qs = parse_qs(parsed.query)
        for key in ("sub", "url", "link", "config"):
            if key in qs:
                val = qs[key][0]
                decoded = try_decode_base64(val) or unquote(val)
                sub_links = detect_and_parse(decoded)
                if sub_links:
                    print(f"[QPARAM:{key}] {entry} -> {len(sub_links)} links", file=sys.stderr)
                    return sub_links

        content, final_url, ct = fetch_url(entry)
        if content is None:
            return []

        links = detect_and_parse(content, final_url)
        print(f"[OK] {entry} -> {len(links)} links", file=sys.stderr)
        return links

    # Direct link or raw content
    return detect_and_parse(entry)


def parse_clash_yaml(text):
    links = []
    try:
        data = yaml.safe_load(text)
    except Exception:
        return links
    if not isinstance(data, dict):
        return links
    proxies = data.get("proxies") or data.get("Proxies") or []
    for p in proxies:
        if not isinstance(p, dict):
            continue
        ptype = str(p.get("type", "")).lower()
        name = unquote(str(p.get("name", "proxy")))
        server = p.get("server", "")
        port = p.get("port", 443)
        if not server:
            continue

        try:
            if ptype == "vless":
                uuid = p.get("uuid", "")
                flow = p.get("flow", "")
                network = p.get("network", "tcp")
                tls = p.get("tls", False)
                reality_opts = p.get("reality-opts", {}) or {}
                ws_opts = p.get("ws-opts", {}) or {}
                grpc_opts = p.get("grpc-opts", {}) or {}
                h2_opts = p.get("h2-opts", {}) or {}
                xhttp_opts = p.get("xhttp-opts", {}) or {}
                servername = p.get("servername", "") or p.get("sni", "")
                fingerprint = p.get("client-fingerprint", "")
                alpn_raw = p.get("alpn", [])
                if isinstance(alpn_raw, str):
                    alpn_list = [a.strip() for a in alpn_raw.split(",") if a.strip()]
                else:
                    alpn_list = list(alpn_raw) if alpn_raw else []

                params = {"type": network, "encryption": "none"}
                if flow: params["flow"] = flow
                if tls:
                    if reality_opts:
                        params["security"] = "reality"
                        params["pbk"] = reality_opts.get("public-key", "")
                        params["sid"] = reality_opts.get("short-id", "")
                    else:
                        params["security"] = "tls"
                    if servername: params["sni"] = servername
                    if fingerprint: params["fp"] = fingerprint
                if alpn_list: params["alpn"] = ",".join(alpn_list)
                if network == "ws":
                    params["path"] = ws_opts.get("path", "/")
                    host = (ws_opts.get("headers") or {}).get("Host", "")
                    if host: params["host"] = host
                elif network == "grpc":
                    params["serviceName"] = grpc_opts.get("grpc-service-name", "")
                elif network in ("h2", "http"):
                    paths = h2_opts.get("path") or []
                    params["path"] = paths[0] if paths else "/"
                    hosts = h2_opts.get("host") or []
                    if hosts: params["host"] = hosts[0]
                elif network == "xhttp":
                    params["path"] = xhttp_opts.get("path", "/")
                    if xhttp_opts.get("host"): params["host"] = xhttp_opts["host"]
                    if xhttp_opts.get("mode"): params["mode"] = xhttp_opts["mode"]

                link = clean_link(f"vless://{uuid}@{server}:{port}?{_qs(params)}#{name}", "vless")
                links.append(link)
                tcp = _h3_to_tcp_link(link)
                if tcp: links.append(tcp)

            elif ptype == "vmess":
                uuid = p.get("uuid", "")
                aid = p.get("alterId", 0)
                security = p.get("cipher", "auto")
                network = p.get("network", "tcp")
                tls = p.get("tls", False)
                ws_opts = p.get("ws-opts", {}) or {}
                grpc_opts = p.get("grpc-opts", {}) or {}
                xhttp_opts = p.get("xhttp-opts", {}) or {}
                servername = p.get("servername", "") or p.get("sni", "")
                alpn_raw = p.get("alpn", [])
                alpn_str = ",".join(alpn_raw if isinstance(alpn_raw, list) else [alpn_raw]) if alpn_raw else ""

                vmess_obj = {
                    "v": "2", "ps": name, "add": server, "port": str(port),
                    "id": uuid, "aid": str(aid), "scy": security,
                    "net": network, "type": "none",
                    "tls": "tls" if tls else "",
                    "sni": servername, "alpn": alpn_str,
                }
                if network == "ws":
                    vmess_obj["path"] = ws_opts.get("path", "/")
                    vmess_obj["host"] = (ws_opts.get("headers") or {}).get("Host", "")
                elif network == "grpc":
                    vmess_obj["path"] = grpc_opts.get("grpc-service-name", "")
                elif network == "xhttp":
                    vmess_obj["path"] = xhttp_opts.get("path", "/")
                    vmess_obj["host"] = xhttp_opts.get("host", "")

                encoded = base64.b64encode(json.dumps(vmess_obj, ensure_ascii=False).encode()).decode()
                link = f"vmess://{encoded}"
                links.append(link)
                tcp = _h3_to_tcp_link(link)
                if tcp: links.append(tcp)

            elif ptype == "trojan":
                password = p.get("password", "")
                sni = p.get("sni", "") or p.get("servername", "")
                network = p.get("network", "tcp")
                ws_opts = p.get("ws-opts", {}) or {}
                grpc_opts = p.get("grpc-opts", {}) or {}
                xhttp_opts = p.get("xhttp-opts", {}) or {}
                fp = p.get("client-fingerprint", "")
                alpn_raw = p.get("alpn", [])
                alpn_str = ",".join(alpn_raw if isinstance(alpn_raw, list) else [alpn_raw]) if alpn_raw else ""

                params = {}
                if sni: params["sni"] = sni
                if fp: params["fp"] = fp
                if alpn_str: params["alpn"] = alpn_str
                if network == "ws":
                    params["type"] = "ws"
                    params["path"] = ws_opts.get("path", "/")
                    host = (ws_opts.get("headers") or {}).get("Host", "")
                    if host: params["host"] = host
                elif network == "grpc":
                    params["type"] = "grpc"
                    params["serviceName"] = grpc_opts.get("grpc-service-name", "")
                elif network == "xhttp":
                    params["type"] = "xhttp"
                    params["path"] = xhttp_opts.get("path", "/")
                    if xhttp_opts.get("host"): params["host"] = xhttp_opts["host"]

                link = clean_link(f"trojan://{password}@{server}:{port}?{_qs(params)}#{name}", "trojan")
                links.append(link)
                tcp = _h3_to_tcp_link(link)
                if tcp: links.append(tcp)

            elif ptype in ("ss", "shadowsocks"):
                method = p.get("cipher", "")
                password = p.get("password", "")
                plugin = p.get("plugin", "")
                plugin_opts = p.get("plugin-opts", {}) or {}
                userinfo = base64.b64encode(f"{method}:{password}".encode()).decode()
                params = {}
                if plugin:
                    params["plugin"] = plugin
                    if plugin_opts:
                        params["plugin-opts"] = ";".join(f"{k}={v}" for k, v in plugin_opts.items())
                links.append(clean_link(f"ss://{userinfo}@{server}:{port}?{_qs(params)}#{name}", "ss"))

            elif ptype in ("hysteria2", "hy2"):
                password = p.get("password", "")
                sni = p.get("sni", "") or p.get("servername", "")
                obfs = p.get("obfs", "")
                obfs_password = p.get("obfs-password", "")
                params = {}
                if sni: params["sni"] = sni
                if obfs: params["obfs"] = obfs
                if obfs_password: params["obfs-password"] = obfs_password
                base_link = clean_link(f"hy2://{password}@{server}:{port}?{_qs(params)}#{name}", "hy2")
                links.append(base_link.rstrip() + " [UDP]" if "#" in base_link else base_link)
                links.append(base_link.rstrip() + " [TCP]" if "#" in base_link else base_link)

            elif ptype == "hysteria":
                auth = p.get("auth-str", "") or p.get("auth_str", "")
                up = p.get("up", "") or p.get("up-speed", "")
                down = p.get("down", "") or p.get("down-speed", "")
                sni = p.get("sni", "")
                obfs = p.get("obfs", "")
                protocol = p.get("protocol", "udp")
                params = {}
                if auth: params["auth"] = auth
                if up: params["upmbps"] = up
                if down: params["downmbps"] = down
                if sni: params["peer"] = sni
                if obfs: params["obfs"] = obfs
                if protocol and protocol != "udp": params["protocol"] = protocol
                links.append(clean_link(f"hysteria://{server}:{port}?{_qs(params)}#{name}", "hysteria"))
                if protocol in ("udp", ""):
                    params_tcp = dict(params)
                    params_tcp["protocol"] = "faketcp"
                    links.append(clean_link(f"hysteria://{server}:{port}?{_qs(params_tcp)}#{name} [TCP]", "hysteria"))

            elif ptype == "tuic":
                uuid = p.get("uuid", "")
                password = p.get("password", "")
                sni = p.get("sni", "") or p.get("servername", "")
                congestion = p.get("congestion-controller", "")
                params = {}
                if sni: params["sni"] = sni
                if congestion: params["congestion_control"] = congestion
                links.append(clean_link(f"tuic://{uuid}:{password}@{server}:{port}?{_qs(params)}#{name} [UDP]", "tuic"))

            elif ptype in ("wireguard", "wg"):
                private_key = p.get("private-key", "")
                public_key = p.get("public-key", "")
                preshared = p.get("preshared-key", "")
                ip = p.get("ip", "")
                dns = p.get("dns", "")
                mtu = p.get("mtu", "")
                params = {}
                if public_key: params["publickey"] = public_key
                if preshared: params["presharedkey"] = preshared
                if ip: params["address"] = ip
                if dns: params["dns"] = dns if isinstance(dns, str) else ",".join(str(d) for d in dns)
                if mtu: params["mtu"] = mtu
                links.append(clean_link(f"wireguard://{private_key}@{server}:{port}?{_qs(params)}#{name}", "wireguard"))

        except Exception as e:
            print(f"[WARN] proxy parse error ({ptype} {name}): {e}", file=sys.stderr)
            continue

    return links


def parse_singbox_json(text):
    links = []
    try:
        data = json.loads(text)
    except Exception:
        return links
    if not isinstance(data, dict):
        return links
    outbounds = data.get("outbounds", [])
    for ob in outbounds:
        if not isinstance(ob, dict):
            continue
        obtype = str(ob.get("type", "")).lower()
        tag = unquote(str(ob.get("tag", "proxy")))
        server = ob.get("server", "")
        port = ob.get("server_port", 443)
        if not server:
            continue
        try:
            if obtype == "vless":
                uuid = ob.get("uuid", "")
                flow = ob.get("flow", "")
                tls_obj = ob.get("tls", {}) or {}
                transport = ob.get("transport", {}) or {}
                network = transport.get("type", "tcp")
                params = {"type": network, "encryption": "none"}
                if flow: params["flow"] = flow
                if tls_obj:
                    reality = tls_obj.get("reality", {}) or {}
                    if reality.get("enabled"):
                        params["security"] = "reality"
                        params["pbk"] = reality.get("public_key", "")
                        params["sid"] = reality.get("short_id", "")
                    else:
                        params["security"] = "tls"
                    sni = tls_obj.get("server_name", "")
                    if sni: params["sni"] = sni
                    utls = tls_obj.get("utls", {}) or {}
                    fp = utls.get("fingerprint", "")
                    if fp: params["fp"] = fp
                    alpn_list = tls_obj.get("alpn", [])
                    if alpn_list: params["alpn"] = ",".join(alpn_list)
                if network == "ws":
                    params["path"] = transport.get("path", "/")
                    headers = transport.get("headers", {}) or {}
                    if headers.get("Host"): params["host"] = headers["Host"]
                elif network == "grpc":
                    params["serviceName"] = transport.get("service_name", "")
                elif network == "xhttp":
                    params["path"] = transport.get("path", "/")
                    if transport.get("host"): params["host"] = transport["host"]
                    if transport.get("mode"): params["mode"] = transport["mode"]
                link = clean_link(f"vless://{uuid}@{server}:{port}?{_qs(params)}#{tag}", "vless")
                links.append(link)
                tcp = _h3_to_tcp_link(link)
                if tcp: links.append(tcp)

            elif obtype == "vmess":
                uuid = ob.get("uuid", "")
                security = ob.get("security", "auto")
                alter_id = ob.get("alter_id", 0)
                tls_obj = ob.get("tls", {}) or {}
                transport = ob.get("transport", {}) or {}
                network = transport.get("type", "tcp")
                vmess_obj = {
                    "v": "2", "ps": tag, "add": server, "port": str(port),
                    "id": uuid, "aid": str(alter_id), "scy": security,
                    "net": network, "type": "none",
                    "tls": "tls" if tls_obj else "",
                    "sni": tls_obj.get("server_name", ""),
                    "alpn": ",".join(tls_obj.get("alpn", [])) if tls_obj else "",
                    "path": transport.get("path", "") if network in ("ws", "h2", "xhttp") else "",
                }
                encoded = base64.b64encode(json.dumps(vmess_obj, ensure_ascii=False).encode()).decode()
                link = f"vmess://{encoded}"
                links.append(link)
                tcp = _h3_to_tcp_link(link)
                if tcp: links.append(tcp)

            elif obtype == "trojan":
                password = ob.get("password", "")
                tls_obj = ob.get("tls", {}) or {}
                sni = tls_obj.get("server_name", "")
                params = {}
                if sni: params["sni"] = sni
                link = clean_link(f"trojan://{password}@{server}:{port}?{_qs(params)}#{tag}", "trojan")
                links.append(link)
                tcp = _h3_to_tcp_link(link)
                if tcp: links.append(tcp)

            elif obtype == "shadowsocks":
                method = ob.get("method", "")
                password = ob.get("password", "")
                userinfo = base64.b64encode(f"{method}:{password}".encode()).decode()
                links.append(clean_link(f"ss://{userinfo}@{server}:{port}#{tag}", "ss"))

            elif obtype == "hysteria2":
                password = ob.get("password", "")
                tls_obj = ob.get("tls", {}) or {}
                sni = tls_obj.get("server_name", "")
                obfs_obj = ob.get("obfs", {}) or {}
                params = {}
                if sni: params["sni"] = sni
                if obfs_obj.get("type"):
                    params["obfs"] = obfs_obj["type"]
                    params["obfs-password"] = obfs_obj.get("password", "")
                base_link = clean_link(f"hy2://{password}@{server}:{port}?{_qs(params)}#{tag}", "hy2")
                remark = base_link.split("#")[1] if "#" in base_link else ""
                b = base_link.split("#")[0]
                links.append(f"{b}#{remark} [UDP]")
                links.append(f"{b}#{remark} [TCP]")

            elif obtype == "tuic":
                uuid = ob.get("uuid", "")
                password = ob.get("password", "")
                tls_obj = ob.get("tls", {}) or {}
                sni = tls_obj.get("server_name", "")
                congestion = ob.get("congestion_control", "")
                params = {}
                if sni: params["sni"] = sni
                if congestion: params["congestion_control"] = congestion
                links.append(clean_link(f"tuic://{uuid}:{password}@{server}:{port}?{_qs(params)}#{tag} [UDP]", "tuic"))

            elif obtype == "wireguard":
                private_key = ob.get("private_key", "")
                peers = ob.get("peers") or []
                peer = peers[0] if peers else {}
                public_key = peer.get("public_key", "")
                preshared = peer.get("pre_shared_key", "")
                local_addr = ob.get("local_address", [])
                dns_servers = ob.get("dns", [])
                mtu = ob.get("mtu", "")
                params = {}
                if public_key: params["publickey"] = public_key
                if preshared: params["presharedkey"] = preshared
                if local_addr:
                    params["address"] = local_addr if isinstance(local_addr, str) else ",".join(local_addr)
                if dns_servers:
                    params["dns"] = dns_servers if isinstance(dns_servers, str) else ",".join(str(d) for d in dns_servers)
                if mtu: params["mtu"] = mtu
                links.append(clean_link(f"wireguard://{private_key}@{server}:{port}?{_qs(params)}#{tag}", "wireguard"))

        except Exception as e:
            print(f"[WARN] singbox parse error ({obtype} {tag}): {e}", file=sys.stderr)
            continue
    return links


def main():
    sources_file = "subs.txt"
    output_file = "result.txt"

    try:
        with open(sources_file, encoding="utf-8") as f:
            entries = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[ERROR] {sources_file} not found", file=sys.stderr)
        sys.exit(1)

    all_links = []
    for entry in entries:
        parsed = process_entry(entry)
        if parsed:
            all_links.extend(parsed)
        else:
            print(f"[EMPTY] {entry[:80]!r}", file=sys.stderr)

    seen = set()
    unique = []
    for link in all_links:
        key = link.split("#")[0]
        if key not in seen:
            seen.add(key)
            unique.append(link)

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(unique) + "\n")

    print(f"[DONE] {len(unique)} unique links -> {output_file}", file=sys.stderr)


if __name__ == "__main__":
    main()
