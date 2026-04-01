import requests
import time
import socket
import ssl
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import parse_qs
import base64

# ============== SOURCES ==============
SOURCES = [
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/8.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile-2.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-checked.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS_mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt",
]

EXCLUDE_COUNTRIES = {"🇮🇷", "🇷🇺", "🇨🇳", "🇹🇷", "IR", "RU", "CN", "TR"}
TOP_N = 500
MAX_TEST_LATENCY = 10000

# ================== HELPER FUNCTIONS ==================
def should_exclude(config: str) -> bool:
    try:
        remark = config.split('#')[-1].upper()
        return any(c in remark for c in EXCLUDE_COUNTRIES)
    except:
        return False

def detect_protocol(cfg: str) -> str:
    cfg = cfg.strip().lower()
    if cfg.startswith('vless://'): return 'vless'
    elif cfg.startswith('trojan://'): return 'trojan'
    elif cfg.startswith('ss://'): return 'ss'
    return 'unknown'

def extract_vless_info(cfg: str):
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

def extract_trojan_info(cfg: str):
    try:
        url_part = cfg.split('#')[0]
        if not url_part.startswith('trojan://'):
            return None, None, None
        without_scheme = url_part[9:]
        if '@' in without_scheme:
            _, rest = without_scheme.split('@', 1)
        else:
            rest = without_scheme
        hostport_part = rest.split('?')[0].split('/')[0]
        if ':' in hostport_part:
            host, port_str = hostport_part.rsplit(':', 1)
            port = int(port_str)
        else:
            host = hostport_part
            port = 443
        sni = host
        if '?' in rest:
            params = parse_qs(rest.split('?', 1)[1])
            sni_list = params.get('sni') or params.get('peer')
            if sni_list:
                sni = sni_list[0]
        return host.strip(), port, sni.strip()
    except:
        return None, None, None

def extract_ss_info(cfg: str):
    try:
        if not cfg.startswith('ss://'):
            return None, None
        part = cfg[5:].split('#')[0].split('/')[0]
        if '@' in part:
            _, hostport = part.split('@', 1)
        else:
            try:
                decoded = base64.urlsafe_b64decode(part + '===').decode('utf-8')
                _, hostport = decoded.split('@', 1)
            except:
                return None, None
        if ':' in hostport:
            host, port_str = hostport.rsplit(':', 1)
            return host.strip(), int(port_str)
        return None, None
    except:
        return None, None

def test_node(cfg: str):
    proto = detect_protocol(cfg)
    try:
        if proto == 'vless':
            host, port, sni, is_reality = extract_vless_info(cfg)
            if not host or not port:
                return cfg, 99999
            start_time = time.time()
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=6.0) as raw_sock:
                if is_reality or sni != host:
                    with context.wrap_socket(raw_sock, server_hostname=sni) as ssock:
                        pass
            latency = round((time.time() - start_time) * 1000, 1)
            return cfg, latency

        elif proto == 'trojan':
            host, port, sni = extract_trojan_info(cfg)
            if not host or not port:
                return cfg, 99999
            start_time = time.time()
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=6.0) as raw_sock:
                with context.wrap_socket(raw_sock, server_hostname=sni) as ssock:
                    pass
            latency = round((time.time() - start_time) * 1000, 1)
            return cfg, latency

        elif proto == 'ss':
            host, port = extract_ss_info(cfg)
            if not host or not port:
                return cfg, 99999
            start_time = time.time()
            with socket.create_connection((host, port), timeout=6.0) as raw_sock:
                pass
            latency = round((time.time() - start_time) * 1000, 1)
            return cfg, latency
    except:
        return cfg, 99999

def generate_subscription() -> str:
    print("🔄 Fetching VLESS, Trojan and Shadowsocks nodes from all sources...")
    configs = []
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 VLESS-Checker/2.3"}
    for url in SOURCES:
        try:
            resp = requests.get(url, timeout=20, headers=headers)
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line and any(line.startswith(p) for p in ['vless://', 'trojan://', 'ss://']):
                        if not should_exclude(line):
                            configs.append(line)
        except Exception as e:
            print(f"⚠️ Failed to load {url}: {e}")

    configs = list(dict.fromkeys(configs))
    print(f"📥 Loaded {len(configs)} unique configs (VLESS + Trojan + SS)")

    # Test all nodes
    print(f"⚡ Testing {len(configs)} nodes with TCP + TLS handshake...")
    tested = []
    with ThreadPoolExecutor(max_workers=60) as executor:
        futures = [executor.submit(test_node, c) for c in configs]
        for future in as_completed(futures):
            cfg, latency = future.result()
            if latency < MAX_TEST_LATENCY:
                tested.append((cfg, latency))

    # Sort by latency (lowest first) - All protocols mixed together
    tested.sort(key=lambda x: x[1])
    good_nodes = [cfg for cfg, lat in tested]
    print(f"✅ Found {len(good_nodes)} active nodes (TCP+TLS responded)")

    # Fallback
    if not good_nodes:
        print("⚠️ No nodes responded to test. Using all loaded configs as fallback.")
        good_nodes = configs[:TOP_N]

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    header = f"""# profile-title: 🚀 Mixed VLESS + Trojan + Shadowsocks Active Nodes (Ping Tested)
# profile-update-interval: 6
# Generated: {now}
# Total Nodes Tested: {len(configs)}
# Active Nodes Found: {len(good_nodes)}
# Test: TCP connect + TLS handshake (Reality-aware)
# Sorted by: Lowest latency first
# All protocols mixed & sorted by speed
# GitHub Auto-Updated
"""

    print(f"📤 Preparing final subscription with {len(good_nodes[:TOP_N])} fastest nodes")
    return header + "\n".join(good_nodes[:TOP_N])

if __name__ == "__main__":
    print("🚀 Starting Mixed Subscription Updater")
    subscription = generate_subscription()
    filename = "subscription.txt"          # ← Same file as your original request
    with open(filename, "w", encoding="utf-8") as f:
        f.write(subscription)

    vless_count = subscription.count('vless://')
    trojan_count = subscription.count('trojan://')
    ss_count = subscription.count('ss://')
    print(f"✅ File 'subscription.txt' created successfully!")
    print(f"   Total nodes: {vless_count + trojan_count + ss_count} ({vless_count} VLESS + {trojan_count} Trojan + {ss_count} Shadowsocks)")
