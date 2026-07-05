#pragma once

#include "attack_engine.h"
#include <vector>
#include <string>

namespace laitoxx {

// ============================================================================
// L7 Database Protocol Attacks (Phase 3)
// ============================================================================

// Redis RESP Protocol Flood
class RedisFlood : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    std::string build_redis_command(const std::string& cmd);
    std::vector<std::string> generate_complex_commands();
};

// MongoDB Wire Protocol Flood
class MongoDBFlood : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    std::vector<char> build_mongodb_query();
    std::vector<char> build_mongodb_aggregate();
    std::vector<char> encode_bson(const std::string& json);
};

// ElasticSearch REST API Flood
class ElasticSearchFlood : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    std::string generate_complex_query();
    std::string generate_aggregation_query();
    std::string generate_search_request(int depth);
};

} // namespace laitoxx
