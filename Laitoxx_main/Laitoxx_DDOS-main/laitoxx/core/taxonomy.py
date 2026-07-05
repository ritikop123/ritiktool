"""Attack taxonomy: all method codes, categories, descriptions."""

# ── Attack categories ─────────────────────────────────────────────────────
# Structure: { category_name: { display_name: (code, description) } }
ATTACK_CATEGORIES: dict[str, dict[str, tuple[str, str]]] = {
    "L2 Data Link": {
        "ARP Flood":    ("ARP-FLOOD", "Flood ARP requests to poison caches"),
        "VLAN Hopping": ("VLAN-HOP",  "Escape VLAN isolation via 802.1Q tagging"),
    },
    "L3 Network": {
        "Smurf Attack":   ("SMURF",      "ICMP broadcast amplification"),
        "Fraggle Attack": ("FRAGGLE",    "UDP broadcast amplification"),
        "Ping of Death":  ("POD",        "Oversized ICMP packets"),
        "IPv6 NDP Flood": ("NDP",        "Flood Neighbor Discovery Protocol"),
        "BGP Hijacking":  ("BGP-HIJACK", "Route announcement manipulation"),
    },
    "L4 Transport": {
        "TCP SYN Flood":         ("TCP-SYN",    "Half-open connection flood"),
        "TCP ACK Flood":         ("TCP-ACK",    "ACK packet flood"),
        "TCP RST Flood":         ("RST",        "Reset packet flood"),
        "UDP Flood":             ("UDP",        "Volumetric UDP flood"),
        "ICMP Flood":            ("ICMP",       "Ping flood"),
        "CPS Flood":             ("CPS",        "Connections-per-second optimized"),
        "CONNECTION Flood":      ("CONNECTION", "Full TCP connection flood"),
        "SNMP Amplification":    ("SNMP",       "~6x amplification via SNMP"),
        "Chargen Amplification": ("CHARGEN",    "High amplification via chargen"),
        "CLDAP Amplification":   ("CLDAP",      "~56x amplification via CLDAP"),
        "RDP Amplification":     ("RDP-AMP",    "~86x amplification via RDP"),
        "NetBIOS Amplification": ("NETBIOS",    "~4x amplification via NetBIOS"),
    },
    "L7 HTTP Basic": {
        "HTTP GET Flood":    ("GET",        "Standard GET request flood"),
        "HTTP POST Flood":   ("POST",       "POST request flood with payload"),
        "HTTP HEAD Flood":   ("HEAD",       "HEAD request flood"),
        "OVH Bypass":        ("OVH",        "Mimic OVH anti-DDoS fingerprint"),
        "RHEX Attack":       ("RHEX",       "Random hex string payloads"),
        "STOMP Attack":      ("STOMP",      "Slow malformed requests"),
        "STRESS Attack":     ("STRESS",     "Huge body payloads"),
        "DYN Attack":        ("DYN",        "Random subdomain generation"),
        "NULL Attack":       ("NULL",       "Minimal/null requests"),
        "COOKIE Attack":     ("COOKIE",     "Large/many cookies"),
        "PPS Attack":        ("PPS",        "Packet-per-second optimized"),
        "EVEN Attack":       ("EVEN",       "Randomized headers"),
        "DOWNLOADER Attack": ("DOWNLOADER", "Slow response reading"),
    },
    "L7 Protection Bypass": {
        "Cloudflare Bypass":    ("CFB",    "Direct origin IP targeting"),
        "Cloudflare UAM":       ("CFBUAM", "JS challenge solving bypass"),
        "DDoS-Guard Bypass":    ("DGB",    "DDoS-Guard evasion"),
        "ArvanCloud Bypass":    ("AVB",    "ArvanCloud protection bypass"),
        "Google Bot Attack":    ("BOT",    "Googlebot impersonation"),
        "Google Shield Bypass": ("GSB",    "Google Shield evasion"),
        "Combined Bypass":      ("BYPASS", "Multi-technique rotation"),
        "KILLER Attack":        ("KILLER", "Multi-vector combined"),
    },
    "L7 Specialized": {
        "WebSocket Flood":       ("WS",         "WebSocket connection flood"),
        "HTTP/2 Stream Flood":   ("H2STREAM",   "HTTP/2 stream multiplexing attack"),
        "HTTP/2 HPACK Bomb":     ("H2HPACK",    "HPACK compression bomb"),
        "HTTP/2 RST Flood":      ("H2RST",       "HTTP/2 RST_STREAM flood"),
        "HTTP/2 SETTINGS Flood": ("H2SETTINGS",  "HTTP/2 SETTINGS frame flood"),
        "HTTP/3 QUIC Flood":     ("QUIC",        "QUIC protocol flood"),
        "GraphQL Flood":         ("GRAPHQL",     "GraphQL query complexity attack"),
        "SMTP Flood":            ("SMTP",        "Email server flood"),
        "IMAP Flood":            ("IMAP",        "IMAP protocol flood"),
        "POP3 Flood":            ("POP3",        "POP3 protocol flood"),
        "SIP Flood":             ("SIP",         "VoIP signaling flood"),
        "RTP Flood":             ("RTP",         "Media stream flood"),
        "RTCP Flood":            ("RTCP",        "Media control flood"),
        "WebDAV Flood":          ("WEBDAV",      "WebDAV method flood"),
    },
}

# ── Flat look-ups (built once at import) ─────────────────────────────────
# name → code,  name → category
ATTACK_NAME_MAP: dict[str, str] = {}
ATTACK_TO_CATEGORY: dict[str, str] = {}

for _cat, _attacks in ATTACK_CATEGORIES.items():
    for _name, (_code, _desc) in _attacks.items():
        ATTACK_NAME_MAP[_name] = _code
        ATTACK_TO_CATEGORY[_name] = _cat

# Methods that require raw sockets (Administrator / root)
RAW_SOCKET_ATTACKS: frozenset[str] = frozenset({
    "ARP-FLOOD", "VLAN-HOP",
    "SMURF", "FRAGGLE", "POD", "NDP", "BGP-HIJACK",
    "TCP-ACK", "RST", "ICMP",
    "SNMP", "CHARGEN", "CLDAP", "RDP-AMP", "NETBIOS",
})

# Categories considered "L7" (HTTP application layer)
L7_CATEGORIES: frozenset[str] = frozenset({
    "L7 HTTP Basic",
    "L7 Protection Bypass",
    "L7 Specialized",
})
