#pragma once
#include <string>
#include <sstream>
#include <vector>

#include "loguru.hpp"
#include "QueryCondition.h"

namespace PacketSql
{
    inline std::string BuildPacketQuerySql(QueryCondition& condition)
    {
        std::string       sql;
        std::stringstream ss;

        ss << "SELECT * FROM t_packets";

        std::vector<std::string> conditionList;

        if (!condition.Ip.empty())
        {
            char buf[100] = { 0 };
            snprintf(buf,
                     sizeof(buf),
                     "src_ip='%s' or dst_ip='%s'",
                     condition.Ip.c_str(), condition.Ip.c_str());
        }

        if (condition.Port != 0)
        {
            char buf[100] = { 0 };
            snprintf(buf,
                     sizeof(buf),
                     "src_port=%d or dst_port=%d",
                     condition.Port, condition.Port);
            conditionList.push_back(buf);
        }

        if (!condition.Proto.empty())
        {
            char buf[100] = { 0 };
            snprintf(buf,
                     sizeof(buf),
                     "protocol='%s'",
                     condition.Proto.c_str());
            conditionList.push_back(buf);
        }

        if (!conditionList.empty())
        {
            ss << " WHERE ";
            for (size_t i = 0; i < conditionList.size(); ++i)
            {
                if (i > 0)
                {
                    ss << " AND ";
                }
                ss << conditionList[i];
            }
        }

        sql = ss.str();
        LOG_F(INFO, "[BUILD SQL]: %s", sql.c_str());
        return sql;
    }
}
