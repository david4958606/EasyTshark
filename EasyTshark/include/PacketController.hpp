#pragma once
#include "BaseController.hpp"
#include "httplib.h"
#include "main.h"
#include "prettywriter.h"
#include "TsharkManager.h"

class PacketController : public BaseController
{
public:
    PacketController(httplib::Server&                      server,
                     const std::shared_ptr<TsharkManager>& tsharkManager)
        : BaseController(server, tsharkManager)
    {}

    void RegisterRoute() override
    {
        __Server.Post("/api/getPacketList",
                      [this](const httplib::Request& req, httplib::Response& res)
                      {
                          GetPacketList(req, res);
                      });
    }

    void GetPacketList(const httplib::Request& req, httplib::Response& res)
    {
        try
        {
            QueryCondition queryCondition;
            if (!ParseQueryCondition(req, queryCondition))
            {
                SendErrorResponse(res, ERROR_PARAMETER_WRONG);
                return;
            }
            std::vector<std::shared_ptr<Packet>> packetList;
            __TsharkManager->QueryPackets(queryCondition, packetList);
            SendDataList(res, packetList);
        }
        catch (const std::exception& e)
        {
            SendErrorResponse(res, ERROR_INTERNAL_WRONG);
        }
    }
};
