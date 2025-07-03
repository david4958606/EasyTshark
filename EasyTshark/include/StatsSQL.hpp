#pragma once
#include <sstream>
#include <string>

#include "loguru.hpp"
#include "PageAndOrder.hpp"

class QueryCondition;

namespace StatsSql
{
    inline std::string BuildIpStatsQuerySql(const QueryCondition& condition)
    {
        std::string        sql;
        std::ostringstream oss;
        oss << R"(
        SELECT
            ip,
            location,
            MIN(start_time) AS earliest_time,
            MAX(end_time) AS latest_time,
            GROUP_CONCAT(DISTINCT port) AS ports,
            GROUP_CONCAT(DISTINCT trans_proto) AS trans_protos,
            GROUP_CONCAT(DISTINCT app_proto) AS app_protos,
            SUM(sent_packets) AS total_sent_packets,
            SUM(sent_bytes) AS total_sent_bytes,
            SUM(recv_packets) AS total_recv_packets,
            SUM(recv_bytes) AS total_recv_bytes,
            SUM(tcp_sessions) AS tcp_session_count,
            SUM(udp_sessions) AS udp_session_count
        FROM (
            SELECT
                ip1 AS ip,
                ip1_location AS location,
                start_time,
                end_time,
                ip1_port AS port,
                trans_proto,
                app_proto,
                ip1_send_packets_count AS sent_packets,
                ip1_send_bytes_count AS sent_bytes,
                ip2_send_packets_count AS recv_packets,
                ip2_send_bytes_count AS recv_bytes,
                CASE WHEN trans_proto LIKE '%TCP%' THEN 1 ELSE 0 END AS tcp_sessions,
                CASE WHEN trans_proto LIKE '%UDP%' THEN 1 ELSE 0 END AS udp_sessions
            FROM t_sessions
            UNION ALL
            SELECT
                ip2 AS ip,
                ip2_location AS location,
                start_time,
                end_time,
                ip2_port AS port,
                trans_proto,
                app_proto,
                ip2_send_packets_count AS sent_packets,
                ip2_send_bytes_count AS sent_bytes,
                ip1_send_packets_count AS recv_packets,
                ip1_send_bytes_count AS recv_bytes,
                CASE WHEN trans_proto LIKE '%TCP%' THEN 1 ELSE 0 END AS tcp_sessions,
                CASE WHEN trans_proto LIKE '%UDP%' THEN 1 ELSE 0 END AS udp_sessions
            FROM t_sessions
        ) t
        GROUP BY ip;)";
        oss << PageHelper::GetPageSql;
        sql = oss.str();
        LOG_F(INFO, "[BUILD SQL]: %s", sql.c_str());
        return sql;
    }

    inline std::string BuildIpStatsQuerySql_Count(const QueryCondition& condition)
    {
        std::string sql = BuildIpStatsQuerySql(condition);
        auto        pos = sql.find("LIMIT");
        if (pos != std::string::npos)
        {
            sql = sql.substr(0, pos);
        }
        std::string countSql = "SELECT COUNT(0) FROM (" + sql + ") t_temp;";
        LOG_F(INFO, "[BUILD SQL]: %s", countSql.c_str());
        return countSql;
    }
}
