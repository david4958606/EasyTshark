#pragma once
#include "BaseController.hpp"

class AdaptorController : public BaseController
{
public:
    AdaptorController(httplib::Server&                      server,
                      const std::shared_ptr<TsharkManager>& tsharkManager)
        : BaseController(server, tsharkManager)
    {}

    void GetWorkStatus(const httplib::Request& req, httplib::Response& res) const
    {
        try
        {
            const WorkStatus                    workStatus = __TsharkManager->GetWorkStatus();
            rapidjson::Document                 resDoc;
            rapidjson::Document::AllocatorType& allocator = resDoc.GetAllocator();
            resDoc.SetObject();
            resDoc.AddMember("workStatus", workStatus, allocator);
            SendJsonResponse(res, resDoc);
        }
        catch (const std::exception e)
        {
            SendErrorResponse(res, ERROR_INTERNAL_ERROR);
        }
    }

    void StartCapture(const httplib::Request& req, httplib::Response& res) const
    {
        try
        {
            if (req.body.empty())
            {
                return SendErrorResponse(res, ERROR_PARAMETER_WRONG);
            }

            if (__TsharkManager->GetWorkStatus() != STATUS_IDLE)
            {
                return SendErrorResponse(res, ERROR_STATUS_WRONG);
            }

            rapidjson::Document doc;
            if (doc.Parse(req.body.c_str()).HasParseError())
            {
                return SendErrorResponse(res, ERROR_PARAMETER_WRONG);
            }

            if (!doc.HasMember("adapterName"))
            {
                return SendErrorResponse(res, ERROR_PARAMETER_WRONG);
            }

            std::string adapterName = doc["adapterName"].GetString();
            if (adapterName.empty())
            {
                return SendErrorResponse(res, ERROR_PARAMETER_WRONG);
            }

            if (__TsharkManager->StartCapture(adapterName))
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

    void StopCapture(const httplib::Request& req, httplib::Response& res) const
    {
        try
        {
            if (__TsharkManager->GetWorkStatus() == STATUS_CAPTURING)
            {
                __TsharkManager->StopCapture();
                SendSuccessResponse(res);
            }
            else
            {
                SendErrorResponse(res, ERROR_STATUS_WRONG);
            }
        }
        catch (const std::exception& e)
        {
            // 如果发生异常，返回错误响应
            SendErrorResponse(res, ERROR_INTERNAL_WRONG);
        }
    }

    void StartMonitorAdaptersFlowTrend(const httplib::Request& req, httplib::Response& res) const
    {
        try
        {
            if (__TsharkManager->GetWorkStatus() == STATUS_IDLE)
            {
                __TsharkManager->StartMonitorAdaptersFlowTrend();
                SendSuccessResponse(res);
            }
            else if (__TsharkManager->GetWorkStatus() == STATUS_MONITORING)
            {
                SendSuccessResponse(res);
            }
            else
            {
                SendErrorResponse(res, ERROR_STATUS_WRONG);
            }
        }
        catch (std::exception& e)
        {
            SendErrorResponse(res, ERROR_INTERNAL_WRONG);
        }
    }

    void StopMonitorAdaptersFlowTrend(const httplib::Request& req, httplib::Response& res) const
    {
        try
        {
            if (__TsharkManager->GetWorkStatus() == STATUS_MONITORING)
            {
                __TsharkManager->StopMonitorAdaptersFlowTrend();
                SendSuccessResponse(res);
            }
            else
            {
                SendErrorResponse(res, ERROR_SUCCESS);
            }
        }
        catch (std::exception& e)
        {
            SendErrorResponse(res, ERROR_INTERNAL_WRONG);
        }
    }

    void GetAdaptersFlowTrendData(const httplib::Request& req, httplib::Response& res) const
    {
        try
        {
            std::map<std::string, std::map<long, long>> flowTrendData;
            __TsharkManager->GetAdaptersFlowTrendData(flowTrendData);

            rapidjson::Document                 resDoc;
            rapidjson::Document::AllocatorType& allocator = resDoc.GetAllocator();
            resDoc.SetObject();

            resDoc.AddMember("code", ERROR_SUCCESS, allocator);
            resDoc.AddMember("msg", rapidjson::Value(TsharkError::GetErrorMsg(ERROR_SUCCESS).c_str(), allocator),
                             allocator);
            rapidjson::Value dataObject(rapidjson::kObjectType);
            for (const auto& adaptorItem : flowTrendData)
            {
                rapidjson::Value adaptorDataList(rapidjson::kArrayType);
                for (const auto& timeItem : adaptorItem.second)
                {
                    rapidjson::Value timeObj(rapidjson::kObjectType);
                    timeObj.AddMember("time", static_cast<unsigned int>(timeItem.first), allocator);
                    timeObj.AddMember("bytes", static_cast<unsigned int>(timeItem.second), allocator);
                    adaptorDataList.PushBack(timeObj, allocator);
                }

                dataObject.AddMember(rapidjson::StringRef(adaptorItem.first.c_str()), adaptorDataList, allocator);
            }
            resDoc.AddMember("data", dataObject, allocator);
            rapidjson::StringBuffer                    buffer;
            rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
            resDoc.Accept(writer);

            res.set_content(buffer.GetString(), "application/json");
        }
        catch (std::exception& e)
        {
            SendErrorResponse(res, ERROR_INTERNAL_WRONG);
        }
    }

    void GetNetworkAdapters(const httplib::Request& req, httplib::Response& res) const
    {
        try
        {
            std::vector<AdapterInfo>            adapterList = __TsharkManager->GetNetworkAdapters();
            rapidjson::Document                 resDoc;
            rapidjson::Document::AllocatorType& allocator = resDoc.GetAllocator();
            resDoc.SetObject();
            for (const auto& adapter : adapterList)
            {
                std::string displayName = adapter.Name;
                if (!adapter.Remark.empty())
                {
                    displayName += " (" + adapter.Remark + ")";
                }
                std::string idStr = std::to_string(adapter.Id);
                resDoc.AddMember(rapidjson::Value(idStr.c_str(), allocator),
                                 rapidjson::Value(displayName.c_str(), allocator), allocator);
            }
            SendJsonResponse(res, resDoc);
        }
        catch (const std::exception& e)
        {
            SendErrorResponse(res, ERROR_INTERNAL_WRONG);
        }
    }

    void RegisterRoute() override
    {
        __Server.Get("/api/getWorkStatus",
                     [this](const httplib::Request& req, httplib::Response& res)
                     {
                         GetWorkStatus(req, res);
                     });

        __Server.Post("/api/startCapture",
                      [this](const httplib::Request& req, httplib::Response& res)
                      {
                          StartCapture(req, res);
                      });

        __Server.Post("/api/stopCapture",
                      [this](const httplib::Request& req, httplib::Response& res)
                      {
                          StopCapture(req, res);
                      });

        __Server.Get("/api/startMonitorAdaptersFlowTrend",
                     [this](const httplib::Request& req, httplib::Response& res)
                     {
                         StartMonitorAdaptersFlowTrend(req, res);
                     });

        __Server.Get("/api/stopMonitorAdaptersFlowTrend",
                     [this](const httplib::Request& req, httplib::Response& res)
                     {
                         StopMonitorAdaptersFlowTrend(req, res);
                     });

        __Server.Get("/api/getAdaptersFlowTrendData",
                     [this](const httplib::Request& req, httplib::Response& res)
                     {
                         GetAdaptersFlowTrendData(req, res);
                     });

        __Server.Get("/api/getNetworkAdapters",
                     [this](const httplib::Request& req, httplib::Response& res)
                     {
                         GetNetworkAdapters(req, res);
                     });
    }
};
