import base64
import concurrent.futures
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from urllib.parse import parse_qs, quote, unquote, urlparse

import requests

TARGET_COUNTRIES = {"US", "JP", "KR", "CA", "AU", "IN"}
PROTOCOLS = ("vless://", "vmess://", "trojan://", "ss://")
MAX_GITHUB_REPOS = 20
MAX_CANDIDATE_NODES = 300
TCP_WORKERS = 50
XRAY_WORKERS = 20
REQUEST_TIMEOUT = 10

_port_lock = threading.Lock()
_next_port = 20000


def get_free_port() -> int:
    global _next_port
    with _port_lock:
        port = _next_port
        _next_port += 1
        return port


def b64_decode_safe(data: str) -> str:
    s = data.strip().replace("-", "+").replace("_", "/")
    pad = (-len(s)) % 4
    if pad:
        s += "=" * pad
    try:
        return base64.b64decode(s).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def discover_github_sources() -> list[str]:
    urls: list[str] = []
    if os.path.exists("sources.txt"):
        with open("sources.txt", "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    urls.append(line)

    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"

    queries = [
        "v2ray sub free nodes",
        "vless vmess subscription",
    ]
    repos_seen: set[str] = set()
    repo_items: list[dict] = []

    for q in queries:
        try:
            resp = requests.get(
                "https://api.github.com/search/repositories",
                params={"q": q, "sort": "updated", "order": "desc", "per_page": MAX_GITHUB_REPOS},
                headers=headers,
                timeout=15,
            )
            if resp.status_code == 200:
                for item in resp.json().get("items", []):
                    full_name = item.get("full_name")
                    if full_name and full_name not in repos_seen:
                        repos_seen.add(full_name)
                        repo_items.append(item)
        except Exception:
            continue
        if len(repo_items) >= MAX_GITHUB_REPOS:
            break

    repo_items = repo_items[:MAX_GITHUB_REPOS]
    raw_pattern = re.compile(r"https?://raw\.githubusercontent\.com/[^\s\"'<>`)\]]+")

    for item in repo_items:
        full_name = item.get("full_name")
        default_branch = item.get("default_branch", "main")
        for readme_name in ("README.md", "readme.md"):
            raw_readme = f"https://raw.githubusercontent.com/{full_name}/{default_branch}/{readme_name}"
            try:
                r = requests.get(raw_readme, timeout=10)
                if r.status_code == 200:
                    found = raw_pattern.findall(r.text)
                    for u in found:
                        if any(u.lower().endswith(ext) for ext in (".png", ".jpg", ".jpeg", ".gif", ".svg")):
                            continue
                        if u not in urls:
                            urls.append(u)
                    break
            except Exception:
                continue

    return urls


def extract_nodes_from_text(text: str) -> list[str]:
    nodes: list[str] = []
    if not any(p in text for p in PROTOCOLS):
        decoded = b64_decode_safe(text)
        if any(p in decoded for p in PROTOCOLS):
            text = decoded

    for line in text.splitlines():
        line = line.strip()
        if line.startswith(PROTOCOLS):
            nodes.append(line)
    return nodes


def fetch_all_nodes(source_urls: list[str]) -> list[str]:
    raw_nodes: list[str] = []

    def _fetch(url: str) -> list[str]:
        try:
            r = requests.get(url, timeout=12)
            if r.status_code == 200 and r.text:
                return extract_nodes_from_text(r.text)
        except Exception:
            pass
        return []

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        for res in ex.map(_fetch, source_urls):
            raw_nodes.extend(res)

    seen_core: set[str] = set()
    unique_nodes: list[str] = []
    for node in raw_nodes:
        core = node.split("#", 1)[0].strip()
        if core and core not in seen_core:
            seen_core.add(core)
            unique_nodes.append(core)
    return unique_nodes


def parse_host_port(node_uri: str) -> tuple[str, int] | None:
    try:
        if node_uri.startswith("vmess://"):
            raw = b64_decode_safe(node_uri[len("vmess://"):])
            if not raw:
                return None
            cfg = json.loads(raw)
            host = cfg.get("add", "")
            port = int(cfg.get("port", 0))
            return (host, port) if host and port > 0 else None
        parsed = urlparse(node_uri)
        if parsed.hostname and parsed.port:
            return parsed.hostname, int(parsed.port)
    except Exception:
        return None
    return None


def tcp_precheck(nodes: list[str]) -> list[str]:
    def _check(node: str) -> str | None:
        hp = parse_host_port(node)
        if not hp:
            return None
        host, port = hp
        try:
            with socket.create_connection((host, port), timeout=3):
                return node
        except Exception:
            return None

    alive: list[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=TCP_WORKERS) as ex:
        for res in ex.map(_check, nodes):
            if res:
                alive.append(res)
                if len(alive) >= MAX_CANDIDATE_NODES:
                    break
    return alive


def build_outbound(node_uri: str) -> dict | None:
    try:
        if node_uri.startswith("vmess://"):
            cfg = json.loads(b64_decode_safe(node_uri[len("vmess://"):]))
            net = cfg.get("net", "tcp")
            tls = cfg.get("tls", "")
            stream = {"network": net}
            if tls == "tls":
                stream["security"] = "tls"
                stream["tlsSettings"] = {"serverName": cfg.get("sni") or cfg.get("host") or cfg.get("add"), "allowInsecure": True}
            if net == "ws":
                stream["wsSettings"] = {"path": cfg.get("path", "/"), "headers": {"Host": cfg.get("host", "")}}
            elif net == "grpc":
                stream["grpcSettings"] = {"serviceName": cfg.get("path", "")}
            return {
                "protocol": "vmess",
                "settings": {
                    "vnext": [{
                        "address": cfg["add"],
                        "port": int(cfg["port"]),
                        "users": [{"id": cfg["id"], "alterId": int(cfg.get("aid", 0)), "security": cfg.get("scy", "auto")}],
                    }]
                },
                "streamSettings": stream,
            }

        if node_uri.startswith("vless://"):
            u = urlparse(node_uri)
            qs = parse_qs(u.query)
            net = qs.get("type", ["tcp"])[0]
            sec = qs.get("security", ["none"])[0]
            stream: dict = {"network": net}
            if sec == "tls":
                stream["security"] = "tls"
                stream["tlsSettings"] = {"serverName": qs.get("sni", [u.hostname])[0], "allowInsecure": True}
            elif sec == "reality":
                stream["security"] = "reality"
                stream["realitySettings"] = {
                    "serverName": qs.get("sni", [u.hostname])[0],
                    "fingerprint": qs.get("fp", ["chrome"])[0],
                    "publicKey": qs.get("pbk", [""])[0],
                    "shortId": qs.get("sid", [""])[0],
                    "spiderX": qs.get("spx", [""])[0],
                }
            if net == "ws":
                stream["wsSettings"] = {"path": qs.get("path", ["/"])[0], "headers": {"Host": qs.get("host", [u.hostname])[0]}}
            elif net == "grpc":
                stream["grpcSettings"] = {"serviceName": qs.get("serviceName", [""])[0]}
            user = {"id": u.username, "encryption": qs.get("encryption", ["none"])[0]}
            flow = qs.get("flow", [""])[0]
            if flow:
                user["flow"] = flow
            return {
                "protocol": "vless",
                "settings": {"vnext": [{"address": u.hostname, "port": int(u.port), "users": [user]}]},
                "streamSettings": stream,
            }

        if node_uri.startswith("trojan://"):
            u = urlparse(node_uri)
            qs = parse_qs(u.query)
            net = qs.get("type", ["tcp"])[0]
            stream = {
                "network": net,
                "security": "tls",
                "tlsSettings": {"serverName": qs.get("sni", [u.hostname])[0], "allowInsecure": True},
            }
            if net == "ws":
                stream["wsSettings"] = {"path": qs.get("path", ["/"])[0], "headers": {"Host": qs.get("host", [u.hostname])[0]}}
            elif net == "grpc":
                stream["grpcSettings"] = {"serviceName": qs.get("serviceName", [""])[0]}
            return {
                "protocol": "trojan",
                "settings": {"servers": [{"address": u.hostname, "port": int(u.port), "password": unquote(u.username or "")}]},
                "streamSettings": stream,
            }

        if node_uri.startswith("ss://"):
            body = node_uri[len("ss://"):].split("#", 1)[0]
            if "@" in body:
                userinfo, hostport = body.rsplit("@", 1)
                if ":" not in userinfo:
                    userinfo = b64_decode_safe(userinfo)
                method, password = userinfo.split(":", 1)
                host, port_str = hostport.rsplit(":", 1)
            else:
                decoded = b64_decode_safe(body)
                userinfo, hostport = decoded.rsplit("@", 1)
                method, password = userinfo.split(":", 1)
                host, port_str = hostport.rsplit(":", 1)
            return {
                "protocol": "shadowsocks",
                "settings": {"servers": [{"address": host, "port": int(port_str), "method": method, "password": password}]},
            }
    except Exception:
        return None
    return None


def test_node_with_xray(node_uri: str, xray_bin: str) -> tuple[str, int] | None:
    outbound = build_outbound(node_uri)
    if not outbound:
        return None

    port = get_free_port()
    config = {
        "log": {"loglevel": "none"},
        "inbounds": [{"port": port, "listen": "127.0.0.1", "protocol": "socks", "settings": {"udp": True}}],
        "outbounds": [outbound],
    }

    tmp_dir = tempfile.mkdtemp(prefix="xray_")
    cfg_path = os.path.join(tmp_dir, "config.json")
    proc = None
    try:
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(config, f)

        proc = subprocess.Popen(
            [xray_bin, "run", "-c", cfg_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(0.8)
        if proc.poll() is not None:
            return None

        proxies = {
            "http": f"socks5h://127.0.0.1:{port}",
            "https": f"socks5h://127.0.0.1:{port}",
        }

        t0 = time.monotonic()
        trace_resp = requests.get("https://cloudflare.com/cdn-cgi/trace", proxies=proxies, timeout=REQUEST_TIMEOUT)
        latency_ms = int((time.monotonic() - t0) * 1000)
        if trace_resp.status_code != 200:
            return None

        loc = ""
        for line in trace_resp.text.splitlines():
            if line.startswith("loc="):
                loc = line.split("=", 1)[1].strip().upper()
                break
        if loc not in TARGET_COUNTRIES:
            return None

        gem_resp = requests.get(
            "https://gemini.google.com/app",
            proxies=proxies,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36"},
        )
        if gem_resp.status_code != 200:
            return None
        final_url = gem_resp.url.lower()
        if "google.com/sorry" in final_url or "unsupported" in final_url:
            return None

        api_key = os.environ.get("GEMINI_API_KEY", "").strip()
        tag_prefix = "Gemini-OK"
        if api_key:
            api_resp = requests.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={api_key}",
                json={"contents": [{"parts": [{"text": "ping"}]}]},
                proxies=proxies,
                timeout=REQUEST_TIMEOUT,
            )
            if api_resp.status_code == 200:
                tag_prefix = "Gemini-API-OK"
            else:
                return None
        else:
            api_probe = requests.get(
                "https://generativelanguage.googleapis.com/v1beta/models",
                proxies=proxies,
                timeout=REQUEST_TIMEOUT,
            )
            if api_probe.status_code not in (200, 400, 403):
                return None

        remark = quote(f"[{tag_prefix} | {loc} | {latency_ms}ms]")
        tagged_uri = f"{node_uri}#{remark}"
        return tagged_uri, latency_ms
    except Exception:
        return None
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
        shutil.rmtree(tmp_dir, ignore_errors=True)


def main() -> None:
    xray_bin = shutil.which("xray") or "./xray"
    if not os.path.exists(xray_bin) and not shutil.which("xray"):
        raise RuntimeError("xray binary not found")

    sources = discover_github_sources()
    print(f"Discovered {len(sources)} subscription sources.")

    unique_nodes = fetch_all_nodes(sources)
    print(f"Extracted {len(unique_nodes)} unique nodes.")

    alive_nodes = tcp_precheck(unique_nodes)
    print(f"TCP pre-check passed: {len(alive_nodes)} nodes.")

    passed: list[tuple[str, int]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=XRAY_WORKERS) as ex:
        futures = [ex.submit(test_node_with_xray, n, xray_bin) for n in alive_nodes]
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            if res:
                passed.append(res)

    passed.sort(key=lambda x: x[1])
    print(f"Gemini check passed: {len(passed)} nodes.")

    os.makedirs("sub", exist_ok=True)
    plain_content = "\n".join(item[0] for item in passed)
    encoded_content = base64.b64encode(plain_content.encode("utf-8")).decode("utf-8")

    with open("sub/gemini_v2rayn.txt", "w", encoding="utf-8") as f:
        f.write(encoded_content + "\n")


if __name__ == "__main__":
    main()
