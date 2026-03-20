#!/usr/bin/env python3
# @la_cringe

import requests
import base64
import json
import re
import sys
import yaml
from urllib.parse import unquote, urlparse, quote

PROXY_SCHEMES = (
    "vless://", "vmess://", "trojan://", "ss://",
    "hy2://", "hysteria2://", "hysteria://",
    "tuic://", "wireguard://", "wg://",
)

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (compatible; subscription-parser/2.0)",
    "Accept": "*/*",
})


PROTO_LABELS = {
    "vless": "", "vmess": "VMess", "trojan": "Trojan",
    "ss": "SS", "hy2": "HY2", "hysteria2": "HY2",
    "hysteria": "HY1", "tuic": "TUIC", "wireguard": "WG", "wg": "WG",
}

_FLAG_RE = re.compile(r"[\U0001F1E6-\U0001F1FF]{2}")
_JUNK_RE = re.compile(
    r"(?:\|\s*\|\s*|\s*[-–—]\s*)"       # pipe / dash separators
    r"(?:тгк|tg|telegram|канал|channel|bot|бот|sub|подписка)\s*:?\s*@\S+",
    re.IGNORECASE,
)
_HANDLE_RE = re.compile(r"@\S+")
_TGK_RE = re.compile(
    r"(?:\||\s)(?:тгк|tg|telegram|канал|channel)\s*:?\s*.*$",
    re.IGNORECASE,
)
_NOISE_RE = re.compile(
    r"(?:\||:)\s*(?:тгк|tg|telegram|канал|подписка|sub|bot|бот).*$",
    re.IGNORECASE,
)


def _sanitize_remark(remark: str, scheme: str = "") -> str:
    remark = unquote(remark).strip()
    for ch in "\u200b\u200c\u200d\u00ad\ufeff":
        remark = remark.replace(ch, "")
    remark = remark.replace("\u00a0", " ")
    remark = re.sub(r"\s+", " ", remark).strip()

    remark = _JUNK_RE.sub("", remark)
    remark = _TGK_RE.sub("", remark)
    remark = _NOISE_RE.sub("", remark)
    remark = _HANDLE_RE.sub("", remark)
    remark = re.sub(r"\s*\|\s*$", "", remark)
    remark = re.sub(r"\s+", " ", remark).strip()

    flags = _FLAG_RE.findall(remark)
    flag = flags[0] if flags else ""

    clean = _FLAG_RE.sub("", remark).strip()
    clean = re.sub(r"^\s*[|\-–—]\s*", "", clean).strip()
    clean = re.sub(r"\s*[|\-–—]\s*$", "", clean).strip()

    parts = [p.strip() for p in re.split(r"[|\-–—]", clean) if p.strip()]
    label = parts[0] if parts else ""
    label = label[:30].strip()

    proto = PROTO_LABELS.get(scheme.lower(), "")

    suffix_parts = [s for s in [label, proto] if s]
    suffix = " ".join(suffix_parts)

    result = (flag + " " + suffix).strip() if flag else suffix
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


def try_decode_base64(data):
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


def extract_links_from_text(text):
    pattern = re.compile(
        r'(?:vless|vmess|trojan|ss|hy2|hysteria2?|tuic|wireguard|wg)://[^\s\'"<>\]\[,}{]+',
        re.IGNORECASE
    )
    results = []
    for m in pattern.finditer(text):
        raw = m.group(0).rstrip(".,;:)")
        scheme = raw.split("://")[0].lower()
        results.append(clean_link(raw, scheme))
    return results


def _qs(params):
    return "&".join(f"{k}={quote(str(v), safe='')}" for k, v in params.items() if v not in (None, ""))


def _h3_to_tcp_link(link, suffix=" [TCP]"):
    """If link has alpn containing h3, return a copy with alpn=h2 (TCP). Else None."""
    from urllib.parse import urlparse, parse_qs, urlencode
    try:
        if "alpn=" not in link:
            return None
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
        new_remark = (unquote(remark) + suffix).strip() if remark else suffix.strip()
        return f"{scheme_host}?{new_qs}#{new_remark}"
    except Exception:
        return None



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
                if flow:
                    params["flow"] = flow
                if tls:
                    if reality_opts:
                        params["security"] = "reality"
                        params["pbk"] = reality_opts.get("public-key", "")
                        params["sid"] = reality_opts.get("short-id", "")
                    else:
                        params["security"] = "tls"
                    if servername:
                        params["sni"] = servername
                    if fingerprint:
                        params["fp"] = fingerprint
                if alpn_list:
                    params["alpn"] = ",".join(alpn_list)
                if network == "ws":
                    params["path"] = ws_opts.get("path", "/")
                    host = (ws_opts.get("headers") or {}).get("Host", "")
                    if host:
                        params["host"] = host
                elif network == "grpc":
                    params["serviceName"] = grpc_opts.get("grpc-service-name", "")
                elif network in ("h2", "http"):
                    paths = h2_opts.get("path") or []
                    params["path"] = paths[0] if paths else "/"
                    hosts = h2_opts.get("host") or []
                    if hosts:
                        params["host"] = hosts[0]
                elif network == "xhttp":
                    params["path"] = xhttp_opts.get("path", "/")
                    if xhttp_opts.get("host"):
                        params["host"] = xhttp_opts["host"]
                    if xhttp_opts.get("mode"):
                        params["mode"] = xhttp_opts["mode"]

                links.append(clean_link(f"vless://{uuid}@{server}:{port}?{_qs(params)}#{name}", "vless"))
                tcp_link = _h3_to_tcp_link(links[-1])
                if tcp_link:
                    links.append(tcp_link)

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
                    "sni": servername,
                    "alpn": alpn_str,
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
                links.append(f"vmess://{encoded}")
                tcp_link = _h3_to_tcp_link(links[-1])
                if tcp_link:
                    links.append(tcp_link)

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
                if sni:
                    params["sni"] = sni
                if fp:
                    params["fp"] = fp
                if alpn_str:
                    params["alpn"] = alpn_str
                if network == "ws":
                    params["type"] = "ws"
                    params["path"] = ws_opts.get("path", "/")
                    host = (ws_opts.get("headers") or {}).get("Host", "")
                    if host:
                        params["host"] = host
                elif network == "grpc":
                    params["type"] = "grpc"
                    params["serviceName"] = grpc_opts.get("grpc-service-name", "")
                elif network == "xhttp":
                    params["type"] = "xhttp"
                    params["path"] = xhttp_opts.get("path", "/")
                    if xhttp_opts.get("host"):
                        params["host"] = xhttp_opts["host"]

                links.append(clean_link(f"trojan://{password}@{server}:{port}?{_qs(params)}#{name}", "trojan"))
                tcp_link = _h3_to_tcp_link(links[-1])
                if tcp_link:
                    links.append(tcp_link)

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
                        opts_str = ";".join(f"{k}={v}" for k, v in plugin_opts.items())
                        params["plugin-opts"] = opts_str
                links.append(clean_link(f"ss://{userinfo}@{server}:{port}?{_qs(params)}#{name}", "ss"))

            elif ptype in ("hysteria2", "hy2"):
                password = p.get("password", "")
                sni = p.get("sni", "") or p.get("servername", "")
                obfs = p.get("obfs", "")
                obfs_password = p.get("obfs-password", "")
                params = {}
                if sni:
                    params["sni"] = sni
                if obfs:
                    params["obfs"] = obfs
                if obfs_password:
                    params["obfs-password"] = obfs_password
                links.append(clean_link(f"hy2://{password}@{server}:{port}?{_qs(params)}#{name} [UDP]", "hy2"))
                links.append(clean_link(f"hy2://{password}@{server}:{port}?{_qs(params)}#{name} [TCP]", "hy2"))

            elif ptype == "hysteria":
                auth = p.get("auth-str", "") or p.get("auth_str", "")
                up = p.get("up", "") or p.get("up-speed", "")
                down = p.get("down", "") or p.get("down-speed", "")
                sni = p.get("sni", "")
                obfs = p.get("obfs", "")
                protocol = p.get("protocol", "udp")
                params = {}
                if auth:
                    params["auth"] = auth
                if up:
                    params["upmbps"] = up
                if down:
                    params["downmbps"] = down
                if sni:
                    params["peer"] = sni
                if obfs:
                    params["obfs"] = obfs
                if protocol and protocol != "udp":
                    params["protocol"] = protocol
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
                if sni:
                    params["sni"] = sni
                if congestion:
                    params["congestion_control"] = congestion
                links.append(clean_link(f"tuic://{uuid}:{password}@{server}:{port}?{_qs(params)}#{name} [UDP]", "tuic"))

            elif ptype in ("wireguard", "wg"):
                private_key = p.get("private-key", "")
                public_key = p.get("public-key", "")
                preshared = p.get("preshared-key", "")
                ip = p.get("ip", "")
                dns = p.get("dns", "")
                mtu = p.get("mtu", "")
                params = {}
                if public_key:
                    params["publickey"] = public_key
                if preshared:
                    params["presharedkey"] = preshared
                if ip:
                    params["address"] = ip
                if dns:
                    params["dns"] = dns if isinstance(dns, str) else ",".join(str(d) for d in dns)
                if mtu:
                    params["mtu"] = mtu
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
                if flow:
                    params["flow"] = flow
                if tls_obj:
                    reality = tls_obj.get("reality", {}) or {}
                    if reality.get("enabled"):
                        params["security"] = "reality"
                        params["pbk"] = reality.get("public_key", "")
                        params["sid"] = reality.get("short_id", "")
                    else:
                        params["security"] = "tls"
                    sni = tls_obj.get("server_name", "")
                    if sni:
                        params["sni"] = sni
                    utls = tls_obj.get("utls", {}) or {}
                    fp = utls.get("fingerprint", "")
                    if fp:
                        params["fp"] = fp
                alpn_list = tls_obj.get("alpn", []) if tls_obj else []
                if alpn_list:
                    params["alpn"] = ",".join(alpn_list)
                if network == "ws":
                    params["path"] = transport.get("path", "/")
                    headers = transport.get("headers", {}) or {}
                    if headers.get("Host"):
                        params["host"] = headers["Host"]
                elif network == "grpc":
                    params["serviceName"] = transport.get("service_name", "")
                elif network == "xhttp":
                    params["path"] = transport.get("path", "/")
                    if transport.get("host"):
                        params["host"] = transport["host"]
                    if transport.get("mode"):
                        params["mode"] = transport["mode"]
                links.append(clean_link(f"vless://{uuid}@{server}:{port}?{_qs(params)}#{tag}", "vless"))
                tcp_link = _h3_to_tcp_link(links[-1])
                if tcp_link:
                    links.append(tcp_link)

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
                    "path": transport.get("path", "") if network in ("ws", "h2") else "",
                }
                encoded = base64.b64encode(json.dumps(vmess_obj, ensure_ascii=False).encode()).decode()
                links.append(f"vmess://{encoded}")

            elif obtype == "trojan":
                password = ob.get("password", "")
                tls_obj = ob.get("tls", {}) or {}
                sni = tls_obj.get("server_name", "")
                params = {}
                if sni:
                    params["sni"] = sni
                links.append(clean_link(f"trojan://{password}@{server}:{port}?{_qs(params)}#{tag}", "trojan"))
                tcp_link = _h3_to_tcp_link(links[-1])
                if tcp_link:
                    links.append(tcp_link)

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
                if sni:
                    params["sni"] = sni
                if obfs_obj.get("type"):
                    params["obfs"] = obfs_obj["type"]
                    params["obfs-password"] = obfs_obj.get("password", "")
                links.append(clean_link(f"hy2://{password}@{server}:{port}?{_qs(params)}#{tag} [UDP]", "hy2"))
                links.append(clean_link(f"hy2://{password}@{server}:{port}?{_qs(params)}#{tag} [TCP]", "hy2"))

            elif obtype == "tuic":
                uuid = ob.get("uuid", "")
                password = ob.get("password", "")
                tls_obj = ob.get("tls", {}) or {}
                sni = tls_obj.get("server_name", "")
                congestion = ob.get("congestion_control", "")
                params = {}
                if sni:
                    params["sni"] = sni
                if congestion:
                    params["congestion_control"] = congestion
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
                if public_key:
                    params["publickey"] = public_key
                if preshared:
                    params["presharedkey"] = preshared
                if local_addr:
                    addr = local_addr if isinstance(local_addr, str) else ",".join(local_addr)
                    params["address"] = addr
                if dns_servers:
                    dns = dns_servers if isinstance(dns_servers, str) else ",".join(str(d) for d in dns_servers)
                    params["dns"] = dns
                if mtu:
                    params["mtu"] = mtu
                links.append(clean_link(f"wireguard://{private_key}@{server}:{port}?{_qs(params)}#{tag}", "wireguard"))

        except Exception as e:
            print(f"[WARN] singbox parse error ({obtype} {tag}): {e}", file=sys.stderr)
            continue

    return links


def parse_telegram_channel(text):
    links = []
    html_unescape = {"&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": '"', "&#39;": "'"}
    post_blocks = re.findall(r'<div class="tgme_widget_message_text[^"]*"[^>]*>(.*?)</div>', text, re.DOTALL)
    for block in post_blocks:
        clean = re.sub(r'<[^>]+>', ' ', block)
        for ent, repl in html_unescape.items():
            clean = clean.replace(ent, repl)
        links.extend(extract_links_from_text(clean))
    if not links:
        links.extend(extract_links_from_text(re.sub(r'<[^>]+>', ' ', text)))
    return links


def detect_and_parse(content):
    content = content.strip()
    if not content:
        return []

    links = extract_links_from_text(content)
    if links:
        return links

    decoded = try_decode_base64(content)
    if decoded:
        links = extract_links_from_text(decoded)
        if links:
            return links

    per_line = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        decoded_line = try_decode_base64(line)
        if decoded_line:
            per_line.extend(extract_links_from_text(decoded_line))
        else:
            per_line.extend(extract_links_from_text(line))
    if per_line:
        return per_line

    if re.search(r'^\s*(proxies|Proxies)\s*:', content, re.MULTILINE):
        yaml_links = parse_clash_yaml(content)
        if yaml_links:
            return yaml_links

    if content.lstrip().startswith("{"):
        json_links = parse_singbox_json(content)
        if json_links:
            return json_links

    if "tgme_widget_message" in content:
        tg_links = parse_telegram_channel(content)
        if tg_links:
            return tg_links

    return []


def fetch_url(url):
    try:
        parsed = urlparse(url)
        if parsed.netloc == "t.me" and "/s/" not in parsed.path:
            path = parsed.path.lstrip("/")
            url = f"https://t.me/s/{path}"
        r = SESSION.get(url, timeout=25, allow_redirects=True)
        r.raise_for_status()
        return r.text
    except Exception as e:
        print(f"[WARN] fetch failed for {url}: {e}", file=sys.stderr)
        return None


def process_entry(entry):
    entry = entry.strip()
    if not entry or entry.startswith("#"):
        return []
    if entry.startswith(("http://", "https://")):
        content = fetch_url(entry)
        if content is None:
            return []
        return detect_and_parse(content)
    return detect_and_parse(entry)


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
            print(f"[OK] {entry[:80]!r} -> {len(parsed)} links", file=sys.stderr)
            all_links.extend(parsed)
        else:
            print(f"[EMPTY] {entry[:80]!r}", file=sys.stderr)

    seen = set()
    unique = []
    for link in all_links:
        base = link.split("#")[0] if "#" in link else link
        if base not in seen:
            seen.add(base)
            unique.append(link)

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(unique) + "\n")

    print(f"[DONE] {len(unique)} unique links -> {output_file}", file=sys.stderr)


if __name__ == "__main__":
    main()
