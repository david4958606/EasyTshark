#pragma once
#include <algorithm>
#include <sstream>
#include <string>
#include <vector>

#include "loguru.hpp"
#include "QueryCondition.h"

namespace SessionSql
{
    inline std::string BuildSessionQuerySql(const QueryCondition& condition)
    {
        std::string       sql;
        std::stringstream ss;
        ss << "SELECT * FROM t_sessions";

        std::vector<std::string> conditionList;
        if (!condition.Proto.empty())
        {
            char buf[100] = { 0 };
            snprintf(buf,
                     sizeof(buf),
                     "(app_proto like '%%%s%%' or trans_proto like '%%%s%%')",
                     condition.Proto.c_str(), condition.Proto.c_str());
            conditionList.push_back(buf);
        }
        if (!condition.Ip.empty())
        {
            char buf[100] = { 0 };
            snprintf(buf,
                     sizeof(buf),
                     "(ip1='%s' or ip2='%s')", condition.Ip.c_str(),
                     condition.Ip.c_str());
            conditionList.push_back(buf);
        }
        if (condition.Port != 0)
        {
            char buf[100] = { 0 };
            snprintf(buf,
                     sizeof(buf),
                     "(ip1_port=%d or ip2_port=%d)",
                     condition.Port, condition.Port);
            conditionList.push_back(buf);
        }
        if (condition.SessionId != 0)
        {
            char buf[100] = { 0 };
            snprintf(buf,
                     sizeof(buf),
                     "(session_id=%d)",
                     condition.SessionId);
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

        ss << PageHelper::GetPageSql();

        sql = ss.str();
        LOG_F(INFO, "[BUILD SQL]: %s", sql.c_str());
        return sql;
    }
}
