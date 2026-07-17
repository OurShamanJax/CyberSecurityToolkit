"""WireGuard config generator — real X25519 keys, standard .conf output.

R.O.D.E does NOT implement VPN crypto; it hands you correct WireGuard configs to
use with WireGuard's audited implementation. Free, self-hosted, no accounts.
"""
import base64, os
try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
    _HAVE = True
except Exception:
    _HAVE = False


def _keypair():
    priv = X25519PrivateKey.generate()
    raw = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw).decode(), base64.b64encode(pub).decode()


def generate(o: dict) -> dict:
    if not _HAVE:
        return {"ok": False, "error": "The 'cryptography' package is required (it's in requirements.txt). Restart start.bat after install."}
    endpoint = o.get("endpoint", "vpn.example.com").strip() or "vpn.example.com"
    port = int(o.get("port", 51820))
    subnet = (o.get("subnet", "10.8.0") or "10.8.0").rstrip(".")
    dns = o.get("dns", "1.1.1.1")
    peers = max(1, min(int(o.get("peers", 1)), 30))
    s_priv, s_pub = _keypair()
    server_ip = f"{subnet}.1"
    peer_confs, peer_blocks = [], []
    for i in range(peers):
        p_priv, p_pub = _keypair()
        psk = base64.b64encode(os.urandom(32)).decode()
        ip = f"{subnet}.{i + 2}"
        peer_confs.append({"name": f"peer{i + 1}", "ip": ip, "conf":
f"""[Interface]
PrivateKey = {p_priv}
Address = {ip}/24
DNS = {dns}

[Peer]
PublicKey = {s_pub}
PresharedKey = {psk}
Endpoint = {endpoint}:{port}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""})
        peer_blocks.append(f"[Peer]\n# peer{i + 1}\nPublicKey = {p_pub}\nPresharedKey = {psk}\nAllowedIPs = {ip}/32\n")
    server_conf = (
f"""[Interface]
Address = {server_ip}/24
ListenPort = {port}
PrivateKey = {s_priv}
# Full-tunnel NAT (Linux server): uncomment and set your WAN iface (e.g. eth0)
# PostUp   = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
# PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

""" + "\n".join(peer_blocks))
    return {"ok": True,
            "server": {"conf": server_conf, "public_key": s_pub, "endpoint": f"{endpoint}:{port}", "address": server_ip},
            "peers": peer_confs}
