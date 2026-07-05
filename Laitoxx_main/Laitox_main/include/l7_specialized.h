#pragma once

#include "attack_engine.h"
#include <vector>
#include <map>
#include <queue>

#ifdef _WIN32
    #include <winsock2.h>
#else
    #define SOCKET int
#endif

namespace laitoxx {

// ============================================================================
// L7 Specialized Protocol Attacks (Phase 2)
// ============================================================================

// WebSocket Flood - WebSocket connection/frame flood
class WebSocketFlood : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    std::string generate_websocket_handshake();
    std::string create_websocket_frame(const std::string& payload);
};

// HTTP/2 Stream Flood - Overwhelm with parallel streams
class HTTP2StreamFlood : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    std::vector<char> build_http2_headers_frame(uint32_t stream_id);
    std::vector<char> build_http2_data_frame(uint32_t stream_id, const std::string& data);
};

// HTTP/2 HPACK Bomb - Exploit header compression
class HTTP2HPACKBomb : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    std::vector<char> build_hpack_bomb();
};

// HTTP/2 RST_STREAM Flood - Reset stream flood
class HTTP2RSTFlood : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    std::vector<char> build_rst_stream_frame(uint32_t stream_id);
};

// HTTP/2 SETTINGS Flood - Settings frame flood
class HTTP2SettingsFlood : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    std::vector<char> build_settings_frame();
};

// HTTP/3 QUIC Flood - QUIC protocol flood
class HTTP3QUICFlood : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    std::vector<char> build_quic_initial_packet();
    std::vector<char> build_quic_handshake();
};

// GraphQL Complexity Flood - Complex query flood
class GraphQLFlood : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    std::string generate_complex_query(int depth);
    std::string generate_nested_query(int depth);
};

// SMTP Session Flood - SMTP connection flood
class SMTPFlood : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    void smtp_handshake(SOCKET sock);
};

// IMAP/POP3 Flood - Mail protocol flood
class IMAPFlood : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    void imap_commands(SOCKET sock);
};

class POP3Flood : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    void pop3_commands(SOCKET sock);
};

// SIP INVITE Flood - VoIP SIP flood
class SIPFlood : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    std::string generate_sip_invite();
    std::string random_call_id();
};

// RTP/RTCP Flood - Media protocol flood
class RTPFlood : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    std::vector<char> build_rtp_packet();
};

class RTCPFlood : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    std::vector<char> build_rtcp_packet();
};

// WebDAV PROPFIND - WebDAV exploit
class WebDAVFlood : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    std::string generate_propfind_request();
};

} // namespace laitoxx
