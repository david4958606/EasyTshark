#pragma once
#include "BaseController.hpp"

class StatsController : public BaseController
{
public:
    StatsController(httplib::Server& server, const std::shared_ptr<TsharkManager>& tsharkManager)
        : BaseController(server, tsharkManager)
    {}

    void RegisterRoute() override
    {
        __Server.Post("/api/getIPStatsList", [this](const httplib::Request& req, httplib::Response& res)
        {
            GetIpStatsList(req, res);
        });
        __Server.Post("/api/getProtoStatsList", [this](const httplib::Request& req, httplib::Response& res)
        {
            GetProtocolStatsList(req, res);
        });
        __Server.Post("/api/getRegionStatsList", [this](const httplib::Request& req, httplib::Response& res)
        {
            GetRegionStatsList(req, res);
        });
    }

    void GetIpStatsList(const httplib::Request& req, httplib::Response& res)
    {
        try
        {
            QueryCondition queryCondition;
            if (!ParseQueryCondition(req, queryCondition))
            {
                SendErrorResponse(res, ERROR_PARAMETER_WRONG);
                return;
            }
            std::vector<std::shared_ptr<IpStatsInfo>> ipStatsList;
            int                                       total = 0;
            __TsharkManager->QueryIpStats(queryCondition, ipStatsList, total);
            SendDataList(res, ipStatsList, total);
        }
        catch (const std::exception&)
        {
            SendErrorResponse(res, ERROR_INTERNAL_WRONG);
        }
    }

    void GetProtocolStatsList(const httplib::Request& req, httplib::Response& res)
    {
        try
        {
            QueryCondition queryCondition;
            if (!ParseQueryCondition(req, queryCondition))
            {
                SendErrorResponse(res, ERROR_PARAMETER_WRONG);
                return;
            }
            std::vector<std::shared_ptr<ProtoStatsInfo>> protoStatsList;
            int                                          total = 0;
            __TsharkManager->QueryProtocolStats(queryCondition, protoStatsList, total);
            SendDataList(res, protoStatsList, total);
        }
        catch (const std::exception&)
        {
            SendErrorResponse(res, ERROR_INTERNAL_WRONG);
        }
    }

    void GetRegionStatsList(const httplib::Request& req, httplib::Response& res)
    {
        try
        {
            QueryCondition queryCondition;
            if (!ParseQueryCondition(req, queryCondition))
            {
                SendErrorResponse(res, ERROR_PARAMETER_WRONG);
                return;
            }
            std::vector<std::shared_ptr<RegionStatsInfo>> regionStatsList;
            int                                           total = 0;
            __TsharkManager->QueryRegionStats(queryCondition, regionStatsList, total);
            SendDataList(res, regionStatsList, total);
        }
        catch (const std::exception&)
        {
            SendErrorResponse(res, ERROR_INTERNAL_WRONG);
        }
    }
};
