namespace LaitoxxGui.Models;

/// <summary>One JSON line emitted by console_app.py --json</summary>
public record AttackStat(
    double T,
    double Pps,
    long Packets,
    double Remaining,
    string Status
);

public record AttackMethod(string Code, string DisplayName, string Category, string Description);

public static class AttackMethods
{
    // All method codes available cross-platform (L2/L3 only on Linux)
    // Mirrors ATTACK_CATEGORIES in console_app.py
    private static readonly List<AttackMethod> _all = new()
    {
        // L4 Transport
        new("TCP-SYN",    "TCP SYN Flood",         "L4",      "Half-open connection flood"),
        new("TCP-ACK",    "TCP ACK Flood",          "L4",      "ACK packet flood"),
        new("RST",        "TCP RST Flood",          "L4",      "Reset packet flood"),
        new("UDP",        "UDP Flood",              "L4",      "Volumetric UDP flood"),
        new("ICMP",       "ICMP Flood",             "L4",      "Ping flood"),
        new("CPS",        "CPS Flood",              "L4",      "Connections-per-second"),
        new("CONNECTION", "CONNECTION Flood",       "L4",      "Full TCP connection flood"),
        new("SNMP",       "SNMP Amplification",     "L4",      "~6x amplification"),
        new("CHARGEN",    "Chargen Amplification",  "L4",      "High amplification"),
        new("CLDAP",      "CLDAP Amplification",    "L4",      "~56x amplification"),
        new("RDP-AMP",    "RDP Amplification",      "L4",      "~86x amplification"),
        new("NETBIOS",    "NetBIOS Amplification",  "L4",      "~4x amplification"),
        // L7 HTTP Basic
        new("GET",        "HTTP GET Flood",         "L7 Basic", "Standard GET flood"),
        new("POST",       "HTTP POST Flood",        "L7 Basic", "POST with payload"),
        new("HEAD",       "HTTP HEAD Flood",        "L7 Basic", "HEAD request flood"),
        new("OVH",        "OVH Bypass",             "L7 Basic", "OVH fingerprint mimic"),
        new("RHEX",       "RHEX Attack",            "L7 Basic", "Random hex payloads"),
        new("STOMP",      "STOMP Attack",           "L7 Basic", "Slow malformed requests"),
        new("STRESS",     "STRESS Attack",          "L7 Basic", "Huge body payloads"),
        new("DYN",        "DYN Attack",             "L7 Basic", "Random subdomain generation"),
        new("NULL",       "NULL Attack",            "L7 Basic", "Minimal/null requests"),
        new("COOKIE",     "COOKIE Attack",          "L7 Basic", "Large/many cookies"),
        new("PPS",        "PPS Attack",             "L7 Basic", "Packet-per-second optimized"),
        new("EVEN",       "EVEN Attack",            "L7 Basic", "Randomized headers"),
        new("DOWNLOADER", "DOWNLOADER Attack",      "L7 Basic", "Slow response reading"),
        // L7 Bypass
        new("CFB",        "Cloudflare Bypass",      "L7 Bypass", "Direct origin targeting"),
        new("CFBUAM",     "Cloudflare UAM",         "L7 Bypass", "JS challenge bypass"),
        new("DGB",        "DDoS-Guard Bypass",      "L7 Bypass", "DDoS-Guard evasion"),
        new("AVB",        "ArvanCloud Bypass",      "L7 Bypass", "ArvanCloud bypass"),
        new("BOT",        "Google Bot Attack",      "L7 Bypass", "Googlebot impersonation"),
        new("GSB",        "Google Shield Bypass",   "L7 Bypass", "Google Shield evasion"),
        new("BYPASS",     "Combined Bypass",        "L7 Bypass", "Multi-technique rotation"),
        new("KILLER",     "KILLER Attack",          "L7 Bypass", "Multi-vector combined"),
        // L7 Specialized
        new("WS",         "WebSocket Flood",        "L7 Special", "WebSocket flood"),
        new("H2STREAM",   "HTTP/2 Stream",          "L7 Special", "HTTP/2 multiplexing"),
        new("H2HPACK",    "HTTP/2 HPACK Bomb",      "L7 Special", "HPACK compression bomb"),
        new("H2RST",      "HTTP/2 RST Flood",       "L7 Special", "RST_STREAM flood"),
        new("H2SETTINGS", "HTTP/2 SETTINGS",        "L7 Special", "SETTINGS frame flood"),
        new("QUIC",       "HTTP/3 QUIC Flood",      "L7 Special", "QUIC protocol flood"),
        new("GRAPHQL",    "GraphQL Flood",          "L7 Special", "GraphQL complexity"),
        new("SMTP",       "SMTP Flood",             "L7 Special", "Email server flood"),
        new("IMAP",       "IMAP Flood",             "L7 Special", "IMAP flood"),
        new("POP3",       "POP3 Flood",             "L7 Special", "POP3 flood"),
        new("SIP",        "SIP Flood",              "L7 Special", "VoIP signaling flood"),
        new("RTP",        "RTP Flood",              "L7 Special", "Media stream flood"),
        new("RTCP",       "RTCP Flood",             "L7 Special", "Media control flood"),
        new("WEBDAV",     "WebDAV Flood",           "L7 Special", "WebDAV method flood"),
        // L2/L3 — Linux only, included but hidden on Windows at runtime
        new("ARP-FLOOD",  "ARP Flood",              "L2/L3",     "Flood ARP requests"),
        new("VLAN-HOP",   "VLAN Hopping",           "L2/L3",     "VLAN isolation escape"),
        new("SMURF",      "Smurf Attack",           "L2/L3",     "ICMP broadcast amplification"),
        new("FRAGGLE",    "Fraggle Attack",         "L2/L3",     "UDP broadcast amplification"),
        new("POD",        "Ping of Death",          "L2/L3",     "Oversized ICMP packets"),
        new("NDP",        "IPv6 NDP Flood",         "L2/L3",     "Neighbor Discovery flood"),
        new("BGP-HIJACK", "BGP Hijacking",          "L2/L3",     "Route announcement"),
    };

    public static IEnumerable<AttackMethod> GetAvailable()
    {
        bool isLinux = System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(
            System.Runtime.InteropServices.OSPlatform.Linux);
        return _all.Where(m => isLinux || m.Category != "L2/L3");
    }

    public static IEnumerable<string> Categories =>
        GetAvailable().Select(m => m.Category).Distinct();
}
