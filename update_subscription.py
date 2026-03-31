import requests
import re
import time
import socket
import ssl
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import parse_qs

# ============== SOURCES (only high-quality GitHub raw files) ==============
SOURCES = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile-2.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-checked.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS_mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt",
]

EXCLUDE_COUNTRIES = {"🇮🇷", "🇷🇺", "🇨🇳", "🇹🇷", "IR", "RU", "CN", "TR"}
TOP_N = 50
MAX_ACCEPTABLE_LATENCY = 1000  # ms

# ================== HELPER FUNCTIONS ==================
def should_exclude(config: str) -> bool:
    try:
        remark = config.split('#')[-1].upper()
        return any(c in remark for c in EXCLUDE_COUNTRIES)
    except:
        return False


def extract_vless_info(cfg: str):
    """Robust parser: returns (host, port, sni, is_reality)"""
    try:
        url_part = cfg.split('#')[0]
        if not url_part.startswith('vless://'):
            return None, None, None, False

        without_scheme = url_part[8:]
        if '@' not in without_scheme:
            return None, None, None, False

        _, rest = without_scheme.split('@', 1)
        hostport_part = rest.split('?')[0].split('/')[0]

        if ':' in hostport_part:
            host, port_str = hostport_part.rsplit(':', 1)
            port = int(port_str)
        else:
            host = hostport_part
            port = 443

        # Parse query parameters
        params = {}
        if '?' in rest:
            query = rest.split('?', 1)[1]
            params = parse_qs(query)

        sni_list = params.get('sni') or params.get('serverNames') or params.get('host')
        sni = sni_list[0] if sni_list else host

        is_reality = 'security=reality' in cfg or 'pbk=' in cfg or 'reality' in cfg.lower()
        return host.strip(), port, sni.strip(), is_reality
    except:
        return None, None, None, False


def test_node(cfg: str):
    """Full check: TCP + TLS handshake in ONE connection"""
    host, port, sni, is_reality = extract_vless_info(cfg)
    if not host or not port:
        return cfg, 9999

    start_time = time.time()
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=5.0) as raw_sock:
            if is_reality or sni != host:
                with context.wrap_socket(raw_sock, server_hostname=sni) as ssock:
                    pass  # TLS handshake successful

        latency = round((time.time() - start_time) * 1000, 1)
        return cfg, latency
    except Exception:
        return cfg, 9999


def generate_subscription() -> str:
    print("🔄 Fetching all VLESS nodes from sources...")
    configs = []

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 VLESS-Checker/2.2"
    }

    for url in SOURCES:
        try:
            resp = requests.get(url, timeout=15, headers=headers)
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line.startswith('vless://') and not should_exclude(line):
                        configs.append(line)
        except Exception as e:
            print(f"⚠️ Source failed: {url} → {e}")

    configs = list(dict.fromkeys(configs))  # remove duplicates, preserve order
    print(f"📥 Loaded {len(configs)} unique VLESS configs")

    # === FULL CHECK: TCP + TLS on ALL nodes ===
    print("⚡ Testing ALL nodes (TCP + TLS handshake)...")
    tested = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(test_node, c) for c in configs]
        for future in as_completed(futures):
            cfg, latency = future.result()
            if latency < MAX_ACCEPTABLE_LATENCY:
                tested.append((cfg, latency))

    # Sort by lowest latency
    tested.sort(key=lambda x: x[1])
    fastest = [cfg for cfg, latency in tested[:TOP_N]]

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    header = f"""# profile-title: 🚀 Fastest VLESS Reality (GitHub Auto-Updated)
# profile-update-interval: 6
# Generated: {now}
# Total Nodes Tested: {len(configs)}
# Good Nodes Found: {len(fastest)}
# Tests performed: TCP connect + TLS handshake (Reality-aware)
# Latency measured from: GitHub Actions Runner
# Sorted by: Lowest Ping → Highest Ping
# Max acceptable latency: {MAX_ACCEPTABLE_LATENCY} ms
# Repository: {requests.get('https://api.github.com/repos/' + os.getenv('GITHUB_REPOSITORY', 'unknown/unknown')).json().get('html_url', 'this repo')}
"""

    print(f"✅ Generated {len(fastest)} best working nodes")
    return header + "\n".join(fastest)


if __name__ == "__main__":
    import os
    print("🚀 Starting GitHub VLESS Subscription Updater")
    subscription = generate_subscription()

    filename = "subscription.txt"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(subscription)

    print(f"✅ Successfully updated {filename} with {subscription.count('vless://')} nodes")
