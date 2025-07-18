#pragma once
#include "BaseController.hpp"

class SessionController : public BaseController
{
public:
    SessionController(httplib::Server& server, const std::shared_ptr<TsharkManager>& tsharkManager)
        : BaseController(server, tsharkManager)
    {}

    void GetSessionList(const httplib::Request& req, httplib::Response& res)
    {
        try
        {
            QueryCondition queryCondition;
            if (!ParseQueryCondition(req, queryCondition))
            {
                SendErrorResponse(res, ERROR_PARAMETER_WRONG);
                return;
            }
            int                                   total = 0;
            std::vector<std::shared_ptr<Session>> sessionList;
            __TsharkManager->QuerySessions(queryCondition, sessionList, total);
            SendDataList(res, sessionList, total);
        }
        catch (const std::exception&)
        {
            SendErrorResponse(res, ERROR_INTERNAL_WRONG);
        }
    }

    void GetSessionDataStream(const httplib::Request& req, httplib::Response& res) const
    {
        try
        {
            uint32_t sessionId = 0;

            // 检查是否有 body 数据
            if (req.body.empty())
            {
                return SendErrorResponse(res, ERROR_PARAMETER_WRONG);
            }
            // 解析 JSON 数据
            rapidjson::Document doc;
            if (doc.Parse(req.body.c_str()).HasParseError())
            {
                return SendErrorResponse(res, ERROR_PARAMETER_WRONG);
            }

            // 验证是否是 JSON 对象
            if (!doc.IsObject())
            {
                return SendErrorResponse(res, ERROR_PARAMETER_WRONG);
            }
            // 提取参数字段
            if (doc.HasMember("session_id") && doc["session_id"].IsNumber())
            {
                sessionId = doc["session_id"].GetInt();
            }
            std::vector<DataStreamItem> dataStreamList;
            DataStreamCountInfo countInfo = __TsharkManager->GetSessionDataStream(sessionId, dataStreamList);
            rapidjson::Document resDoc;
            rapidjson::Document::AllocatorType& allocator = resDoc.GetAllocator();
            resDoc.SetObject();
            resDoc.AddMember("code", ERROR_SUCCESS, allocator);
            resDoc.AddMember("msg", rapidjson::Value(TsharkError::GetErrorMsg(ERROR_SUCCESS).c_str(), allocator),
                             allocator);
            rapidjson::Value countObj(rapidjson::kObjectType);
            countInfo.ToJsonObj(countObj, allocator);
            resDoc.AddMember("count", countObj, allocator);
            rapidjson::Value dataArray(rapidjson::kArrayType);
            for (const auto& item : dataStreamList)
            {
                rapidjson::Value itemObj(rapidjson::kObjectType);
                item.ToJsonObj(itemObj, allocator);
                assert(itemObj.IsObject());
                dataArray.PushBack(itemObj, allocator);
            }
            resDoc.AddMember("data", dataArray, allocator);
            rapidjson::StringBuffer                    buffer;
            rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
            resDoc.Accept(writer);
            res.set_content(buffer.GetString(), "application/json");
        }
        catch (const std::exception&)
        {
            SendErrorResponse(res, ERROR_INTERNAL_WRONG);
        }
    }

    void RegisterRoute() override
    {
        __Server.Post("/api/getSessionList", [this](const httplib::Request& req, httplib::Response& res)
        {
            GetSessionList(req, res);
        });
        __Server.Post("/api/getSessionDataStream", [this](const httplib::Request& req, httplib::Response& res)
        {
            GetSessionDataStream(req, res);
        });
    }
};
