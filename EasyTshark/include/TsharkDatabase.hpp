#pragma once
#include <memory>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

#include "loguru.hpp"
#include "PacketSQL.hpp"
#include "sqlite3.h"
#include "TsharkDataType.h"
#include "QueryCondition.h"
#include "SessionSQL.hpp"

class QueryCondition;

class TsharkDatabase
{
public:
    explicit TsharkDatabase(const std::string& dbName)
    {
        // 删除之前的旧文件（如果有的话）
        remove(dbName.c_str());

        // 打开数据库连接
        if (sqlite3_open(dbName.c_str(), &Db) != SQLITE_OK)
        {
            throw std::runtime_error("Failed to open database: " + dbName);
        }

        if (!CreatePacketTable())
        {
            const std::string err = "Failed to create packet table in database: " + dbName;
            LOG_F(ERROR, err.c_str());
        }
        CreateSessionTable();
    }

    // 析构函数，关闭数据库连接
    ~TsharkDatabase()
    {
        if (Db)
        {
            sqlite3_close(Db);
        }
    }

    bool StorePackets(const std::vector<std::shared_ptr<Packet>>& packets) const
    {
        sqlite3_exec(Db, "BEGIN TRANSACTION;", nullptr, nullptr, nullptr);
        std::string insertSql = R"(
            INSERT INTO t_packets (
                frame_number, time, cap_len, len, src_mac, dst_mac, src_ip, src_location, src_port,
                dst_ip, dst_location, dst_port, protocol, info, file_offset
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        )";

        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(Db, insertSql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        {
            throw std::runtime_error("Failed to prepare insert statement");
        }

        // 遍历列表并插入数据
        bool hasError = false;
        for (const auto& packet : packets)
        {
            sqlite3_bind_int(stmt, 1, packet->FrameNumber);
            sqlite3_bind_double(stmt, 2, packet->Time);
            sqlite3_bind_int(stmt, 3, packet->CapLen);
            sqlite3_bind_int(stmt, 4, packet->Len);
            sqlite3_bind_text(stmt, 5, packet->SourceMac.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 6, packet->DestinationMac.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 7, packet->SourceIp.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 8, packet->SourceLocation.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_int(stmt, 9, packet->SourcePort);
            sqlite3_bind_text(stmt, 10, packet->DestinationIp.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 11, packet->DestinationLocation.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_int(stmt, 12, packet->DestinationPort);
            sqlite3_bind_text(stmt, 13, packet->Protocol.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 14, packet->Info.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_int(stmt, 15, packet->FileOffset);

            if (sqlite3_step(stmt) != SQLITE_DONE)
            {
                LOG_F(ERROR, "Failed to execute insert statement");
                hasError = true;
                break;
            }

            sqlite3_reset(stmt);
        }

        if (!hasError)
        {
            if (sqlite3_exec(Db, "COMMIT;", nullptr, nullptr, nullptr) != SQLITE_OK)
            {
                hasError = true;
            }

            // 释放语句
            sqlite3_finalize(stmt);
        }

        return !hasError;
    }

    bool QueryPackets(const QueryCondition&                 queryCondition,
                      std::vector<std::shared_ptr<Packet>>& packetList) const
    {
        sqlite3_stmt *    stmt = nullptr, *countStmt = nullptr;
        const std::string sql  = PacketSql::BuildPacketQuerySql(queryCondition);


        if (sqlite3_prepare_v2(Db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        {
            LOG_F(ERROR, "Failed to prepare statement: ");
            return false;
        }

        sqlite3_bind_text(stmt, 1, queryCondition.Ip.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, queryCondition.Ip.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 3, queryCondition.Port);
        sqlite3_bind_int(stmt, 4, queryCondition.Port);

        while (sqlite3_step(stmt) == SQLITE_ROW)
        {
            auto packet         = std::make_shared<Packet>();
            packet->FrameNumber = sqlite3_column_int(stmt, 0);
            packet->Time        = sqlite3_column_double(stmt, 1);
            packet->CapLen      = sqlite3_column_int(stmt, 2);
            packet->Len         = sqlite3_column_int(stmt, 3);
            packet->SourceMac   = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4))
                                      ? reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4))
                                      : "";
            packet->DestinationMac = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5))
                                         ? reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5))
                                         : "";
            packet->SourceIp = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6))
                                   ? reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6))
                                   : "";
            packet->SourceLocation = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7))
                                         ? reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7))
                                         : "";
            packet->SourcePort    = sqlite3_column_int(stmt, 8);
            packet->DestinationIp = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 9))
                                        ? reinterpret_cast<const char*>(sqlite3_column_text(stmt, 9))
                                        : "";
            packet->DestinationLocation = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 10))
                                              ? reinterpret_cast<const char*>(sqlite3_column_text(stmt, 10))
                                              : "";
            packet->DestinationPort = sqlite3_column_int(stmt, 11);
            packet->Protocol        = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 12))
                                          ? reinterpret_cast<const char*>(sqlite3_column_text(stmt, 12))
                                          : "";
            packet->Info = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 13))
                               ? reinterpret_cast<const char*>(sqlite3_column_text(stmt, 13))
                               : "";
            packet->FileOffset = sqlite3_column_int(stmt, 14);
            packetList.push_back(packet);
        }
        sqlite3_finalize(stmt);
        return true;
    }

    void StoreAndUpdateSessions(const std::unordered_set<std::shared_ptr<Session>>& sessions) const
    {
        sqlite3_exec(Db, "BEGIN TRANSACTION;", nullptr, nullptr, nullptr);


        std::string   upsertSql = R"(
            INSERT INTO t_sessions (
                session_id, ip1, ip1_location, ip1_port, ip2, ip2_location, ip2_port,
                trans_proto, app_proto, start_time, end_time,
                ip1_send_packets_count, ip1_send_bytes_count, ip2_send_packets_count, ip2_send_bytes_count,
                packet_count, total_bytes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(session_id) DO UPDATE SET
                trans_proto = excluded.trans_proto,
                app_proto = excluded.app_proto,
                start_time = excluded.start_time,
                end_time = excluded.end_time,
                ip1_send_packets_count = excluded.ip1_send_packets_count,
                ip1_send_bytes_count = excluded.ip1_send_bytes_count,
                ip2_send_packets_count = excluded.ip2_send_packets_count,
                ip2_send_bytes_count = excluded.ip2_send_bytes_count,
                packet_count = excluded.packet_count,
                total_bytes = excluded.total_bytes
        )";
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(Db, upsertSql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        {
            LOG_F(ERROR, "Failed to prepare upsert statement");
            throw std::runtime_error("Failed to prepare upsert statement");
        }
        // 遍历列表并插入或更新数据
        for (const auto& session : sessions)
        {
            sqlite3_bind_int(stmt, 1, session->SessionId);
            sqlite3_bind_text(stmt, 2, session->Ip1.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 3, session->Ip1Location.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_int(stmt, 4, session->Ip1Port);
            sqlite3_bind_text(stmt, 5, session->Ip2.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 6, session->Ip2Location.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_int(stmt, 7, session->Ip2Port);
            sqlite3_bind_text(stmt, 8, session->TransProtocol.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 9, session->AppProtocol.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_double(stmt, 10, session->StartTime);
            sqlite3_bind_double(stmt, 11, session->EndTime);
            sqlite3_bind_int(stmt, 12, session->Ip1SendPacketCount);
            sqlite3_bind_int(stmt, 13, session->Ip1SendBytesCount);
            sqlite3_bind_int(stmt, 14, session->Ip2SendPacketCount);
            sqlite3_bind_int(stmt, 15, session->Ip2SendBytesCount);
            sqlite3_bind_int(stmt, 16, session->PacketCount);
            sqlite3_bind_int(stmt, 17, session->TotalBytes);
            if (sqlite3_step(stmt) != SQLITE_DONE)
            {
                LOG_F(ERROR, "Failed to execute upsert statement");
                throw std::runtime_error("Failed to execute upsert statement");
            }
            sqlite3_reset(stmt); // 重置语句以便下一次绑定
        }
        if (sqlite3_exec(Db, "COMMIT;", nullptr, nullptr, nullptr) != SQLITE_OK)
        {
            LOG_F(ERROR, "Failed to commit transaction");
            throw std::runtime_error("Failed to commit transaction");
        }
        // 释放语句
        sqlite3_finalize(stmt);
    }

    bool QuerySessions(QueryCondition& condition, std::vector<std::shared_ptr<Session>>& sessionList)
    {
        sqlite3_stmt* stmt = nullptr;
        std::string   sql  = SessionSql::BuildSessionQuerySql(condition);
        if (sqlite3_prepare_v2(Db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        {
            LOG_F(ERROR, "Failed to prepare statement: ");
            return false;
        }
        while (sqlite3_step(stmt) == SQLITE_ROW)
        {
            auto session                = std::make_shared<Session>();
            session->SessionId          = sqlite3_column_int(stmt, 0);
            session->Ip1                = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            session->Ip1Port            = sqlite3_column_int(stmt, 2);
            session->Ip1Location        = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
            session->Ip2                = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
            session->Ip2Port            = sqlite3_column_int(stmt, 5);
            session->Ip2Location        = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
            session->TransProtocol      = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
            session->AppProtocol        = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
            session->StartTime          = sqlite3_column_double(stmt, 9);
            session->EndTime            = sqlite3_column_double(stmt, 10);
            session->Ip1SendPacketCount = sqlite3_column_int(stmt, 11);
            session->Ip1SendBytesCount  = sqlite3_column_int(stmt, 12);
            session->Ip2SendPacketCount = sqlite3_column_int(stmt, 13);
            session->Ip2SendBytesCount  = sqlite3_column_int(stmt, 14);
            session->PacketCount        = sqlite3_column_int(stmt, 15);
            session->TotalBytes         = sqlite3_column_int(stmt, 16);
            sessionList.push_back(session);
        }
        sqlite3_finalize(stmt);
        return true;
    }

private:
    sqlite3* Db = nullptr;

    bool CreatePacketTable() const
    {
        // 检查表是否存在，若不存在则创建
        /*
        * struct Packet {
            int frame_number;
            double time;
            uint32_t cap_len;
            uint32_t len;
            std::string src_mac;
            std::string dst_mac;
            std::string src_ip;
            std::string src_location;
            uint16_t src_port;
            std::string dst_ip;
            std::string dst_location;
            uint16_t dst_port;
            std::string protocol;
            std::string info;
            uint32_t file_offset;
        };
        */
        const std::string createTableSql = R"(
            CREATE TABLE IF NOT EXISTS t_packets (
                frame_number INTEGER PRIMARY KEY,
                time REAL,
                cap_len INTEGER,
                len INTEGER,
                src_mac TEXT,
                dst_mac TEXT,
                src_ip TEXT,
                src_location TEXT,
                src_port INTEGER,
                dst_ip TEXT,
                dst_location TEXT,
                dst_port INTEGER,
                protocol TEXT,
                info TEXT,
                file_offset INTEGER
            );
        )";

        if (sqlite3_exec(Db, createTableSql.c_str(), nullptr, nullptr, nullptr) != SQLITE_OK)
        {
            LOG_F(ERROR, "Failed to create table t_packets");
            return false;
        }

        return true;
    }

    void CreateSessionTable() const
    {
        std::string createTableSql = R"(
            CREATE TABLE IF NOT EXISTS t_sessions (
                session_id INTEGER PRIMARY KEY,
                ip1 TEXT,
                ip1_port INTEGER,
                ip1_location TEXT,
                ip2 TEXT,
                ip2_port INTEGER,
                ip2_location TEXT,
                trans_proto TEXT,
                app_proto TEXT,
                start_time REAL,
                end_time REAL,
                ip1_send_packets_count INTEGER,
                ip1_send_bytes_count INTEGER,
                ip2_send_packets_count INTEGER,
                ip2_send_bytes_count INTEGER,
                packet_count INTEGER,
                total_bytes INTEGER
            );
        )";

        if (sqlite3_exec(Db, createTableSql.c_str(), nullptr, nullptr, nullptr) != SQLITE_OK)
        {
            LOG_F(ERROR, "Failed to create table t_sessions");
            throw std::runtime_error("Failed to create table t_sessions");
        }
        const std::string clearTableSql = "DELETE FROM t_sessions;";
        if (sqlite3_exec(Db, clearTableSql.c_str(), nullptr, nullptr, nullptr) != SQLITE_OK)
        {
            LOG_F(ERROR, "Failed to clear table t_sessions");
            throw std::runtime_error("Failed to clear table t_sessions");
        }
    }
};
