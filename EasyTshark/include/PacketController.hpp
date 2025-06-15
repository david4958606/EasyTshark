#pragma once
#include "BaseController.hpp"
#include "httplib.h"
#include "main.h"
#include "prettywriter.h"
#include "TsharkManager.h"
#include "MiscUtil.h"

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

        __Server.Post("/api/analysisFile",
                      [this](const httplib::Request& req, httplib::Response& res)
                      {
                          AnalysisFile(req, res);
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

    void AnalysisFile(const httplib::Request& req, httplib::Response& res) const
    {
        try
        {
            if (req.body.empty())
            {
                return SendErrorResponse(res, ERROR_PARAMETER_WRONG);
            }

            rapidjson::Document doc;
            if (doc.Parse(req.body.c_str()).HasParseError())
            {
                return SendErrorResponse(res, ERROR_PARAMETER_WRONG);
            }

            std::string filePath = doc["filePath"].GetString();
            if (!MiscUtil::FileExists(filePath.c_str()))
            {
                return SendErrorResponse(res, ERROR_FILE_NOT_FOUND);
            }

            if (__TsharkManager->AnalysisFile(filePath))
            {
                SendSuccessResponse(res);
            }
            else
            {
                SendErrorResponse(res, ERROR_TSHARK_WRONG);
            }
        }
        catch (const std::exception& e)
        {
            SendErrorResponse(res, ERROR_INTERNAL_WRONG);
        }
    }
};
