#pragma once
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "loguru.hpp"
#include "sqlite3.h"
#include "TsharkDataType.h"
#include "QueryCondition.h"

class QueryCondition;

class TsharkDatabase
{
public:
    explicit TsharkDatabase(const std::string& dbName)
    {
        // 删除之前的旧文件（如果有的话）
        remove(dbName.c_str());

        // 打开数据库连接
        if (sqlite3_open(dbName.c_str(), &db) != SQLITE_OK)
        {
            throw std::runtime_error("Failed to open database: " + dbName);
        }

        CreatePacketTable();
    }

    // 析构函数，关闭数据库连接
    ~TsharkDatabase()
    {
        if (db)
        {
            sqlite3_close(db);
        }
    }

    bool StorePackets(const std::vector<std::shared_ptr<Packet>>& packets) const
    {
        sqlite3_exec(db, "BEGIN TRANSACTION;", nullptr, nullptr, nullptr);
        std::string insertSql = R"(
            INSERT INTO t_packets (
                frame_number, time, cap_len, len, src_mac, dst_mac, src_ip, src_location, src_port,
                dst_ip, dst_location, dst_port, protocol, info, file_offset
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        )";

        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, insertSql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        {
            throw std::runtime_error("Failed to prepare insert statement");
        }

        // 遍历列表并插入数据
        bool hasError = false;
        for (const auto& packet : packets)
        {
            sqlite3_bind_int(stmt, 1, packet->FrameNumber);
            sqlite3_bind_double(stmt, 2, std::stod(packet->Time));
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
            if (sqlite3_exec(db, "COMMIT;", nullptr, nullptr, nullptr) != SQLITE_OK)
            {
                hasError = true;
            }

            // 释放语句
            sqlite3_finalize(stmt);
        }

        return !hasError;
    }

    bool QueryPackets(QueryCondition&                       queryCondition,
                      std::vector<std::shared_ptr<Packet>>& packetList) const
    {
        sqlite3_stmt *    stmt = nullptr, *countStmt = nullptr;
        const std::string sql  =
            "select * from t_packets where (src_ip==? or dst_ip==?) and (src_port==? or dst_port==?)";

        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
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
            packet->Time        = std::to_string(sqlite3_column_double(stmt, 1));
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
            packet->FileOffset = sqlite3_column_int64(stmt, 14);
            packetList.push_back(packet);
        }
        sqlite3_finalize(stmt);
        return true;
    }

private:
    sqlite3* db = nullptr;

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

        if (sqlite3_exec(db, createTableSql.c_str(), nullptr, nullptr, nullptr) != SQLITE_OK)
        {
            LOG_F(ERROR, "Failed to create table t_packets");
            return false;
        }

        return true;
    }
};
