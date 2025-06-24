#pragma once
#include "httplib.h"
#include "TsharkManager.h"
#include "document.h"
#include "stringbuffer.h"
#include "writer.h"
#include "TsharkError.hpp"

class BaseController
{
public:
    BaseController(httplib::Server&                      server,
                   const std::shared_ptr<TsharkManager>& tsharkManager)
        : __Server(server),
          __TsharkManager(tsharkManager)
    {}

    virtual void RegisterRoute() = 0;

protected:
    httplib::Server&               __Server;
    std::shared_ptr<TsharkManager> __TsharkManager;

public:
    static int GetIntParam(const httplib::Request& req,
                           const std::string&      paramName,
                           const int               defaultValue = 0)
    {
        int value = defaultValue;
        if (const auto it = req.params.find(paramName); it != req.params.end())
        {
            value = std::stoi(it->second);
        }
        return value;
    }

    static std::string GetStringParam(const httplib::Request& req,
                                      const std::string&      paramName,
                                      const std::string&      defaultValue = "")
    {
        std::string value = defaultValue;
        if (const auto it = req.params.find(paramName); it != req.params.end())
        {
            value = it->second;
        }
        return value;
    }

protected:
    template <typename Data=Packet>
    void SendDataList(httplib::Response&                  res,
                      std::vector<std::shared_ptr<Data>>& dataList)
    {
        /**
         * {
         *     "code": 0,
         *     "msg": "操作成功",
         *     "data" [] / {}
         * }
         */
        rapidjson::Document                 resDoc;
        rapidjson::Document::AllocatorType& allocator = resDoc.GetAllocator();
        resDoc.SetObject();

        // Set code and message
        resDoc.AddMember("code", ERROR_SUCCESS, allocator);
        resDoc.AddMember("msg",
                         rapidjson::Value(TsharkError::GetErrorMsg(ERROR_SUCCESS).c_str(), allocator),
                         allocator);
        // Set data
        rapidjson::Value dataArray(rapidjson::kArrayType);
        for (const auto& data : dataList)
        {
            rapidjson::Value obj(rapidjson::kObjectType);
            data->ToJsonObj(obj, allocator);
            assert(obj.IsObject());
            dataArray.PushBack(obj, allocator);
        }

        resDoc.AddMember("data", dataArray, allocator);

        rapidjson::StringBuffer                    buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        resDoc.Accept(writer);

        res.set_content(buffer.GetString(), "application/json");
    }

    static void SendSuccessResponse(httplib::Response& res)
    {
        rapidjson::Document                 resDoc;
        rapidjson::Document::AllocatorType& allocator = resDoc.GetAllocator();
        resDoc.SetObject();
        resDoc.AddMember("code", 0, allocator);
        resDoc.AddMember("msg",
                         rapidjson::Value(TsharkError::GetErrorMsg(ERROR_SUCCESS).c_str(), allocator),
                         allocator);

        rapidjson::StringBuffer                    buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        resDoc.Accept(writer);

        res.set_content(buffer.GetString(), "application/json");
    }

    static void SendJsonResponse(httplib::Response& res, rapidjson::Document& dataDoc)
    {
        /**
         * 返回数据格式：
         * {
         *     "code": 0,
         *     "msg": "操作成功",
         *     "data" [] / {}
         * }
         */
        rapidjson::Document                 resDoc;
        rapidjson::Document::AllocatorType& allocator = resDoc.GetAllocator();
        resDoc.SetObject();
        resDoc.AddMember("code", ERROR_SUCCESS, allocator);
        resDoc.AddMember("msg",
                         rapidjson::Value(TsharkError::GetErrorMsg(ERROR_SUCCESS).c_str(), allocator),
                         allocator);
        resDoc.AddMember("data", dataDoc, allocator);

        rapidjson::StringBuffer                    buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        resDoc.Accept(writer);

        res.set_content(buffer.GetString(), "application/json");
    }

    static void SendErrorResponse(httplib::Response& res, const int errorCode)
    {
        rapidjson::Document                 resDoc;
        rapidjson::Document::AllocatorType& allocator = resDoc.GetAllocator();
        resDoc.SetObject();
        resDoc.AddMember("code", errorCode, allocator);
        resDoc.AddMember("msg", rapidjson::Value(TsharkError::GetErrorMsg(errorCode).c_str(), allocator), allocator);

        rapidjson::StringBuffer                    buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        resDoc.Accept(writer);

        res.set_content(buffer.GetString(), "application/json");
    }

    static bool ParseQueryCondition(const httplib::Request& req, QueryCondition& queryCondition)
    {
        try
        {
            if (req.body.empty())
            {
                throw std::runtime_error("Request body is empty");
            }

            rapidjson::Document doc;
            if (doc.Parse(req.body.c_str()).HasParseError())
            {
                throw std::runtime_error("Failed to parse JSON");
            }

            if (!doc.IsObject())
            {
                throw std::runtime_error("Invalid JSON format, expected an object");
            }

            if (doc.HasMember("ip") && doc["ip"].IsString())
            {
                queryCondition.Ip = doc["ip"].GetString();
            }

            if (doc.HasMember("port") && doc["port"].IsUint())
            {
                queryCondition.Port = static_cast<uint16_t>(doc["port"].GetUint());
            }

            if (doc.HasMember("proto") && doc["proto"].IsString())
            {
                queryCondition.Proto = doc["proto"].GetString();
            }

            if (doc.HasMember("mac") && doc["mac"].IsString())
            {
                queryCondition.Mac = doc["mac"].GetString();
            }

            if (doc.HasMember("location") && doc["location"].IsString())
            {
                queryCondition.Location = doc["location"].GetString();
            }
        }
        catch (std::exception&)
        {
            std::cout << "parse parameter error" << std::endl;
            return false;
        }
        return true;
    }
};
