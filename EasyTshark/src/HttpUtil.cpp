#include "HttpUtil.h"

#include "document.h"
#include "main.h"
#include "TsharkDataType.h"
#include "stringbuffer.h"
#include "prettywriter.h"

void HttpUtil::QueryPacket(const httplib::Request& req, httplib::Response& res)
{
    rapidjson::Document doc;
    if (doc.Parse(req.body.c_str()).HasParseError())
    {
        res.status = 400;
        res.set_content("Invalid JSON format", "text/plain");
        return;
    }

    do
    {
        std::string ip;
        uint16_t    port;
        // 提取IP字段
        if (doc.HasMember("ip") && doc["ip"].IsString())
        {
            ip = doc["ip"].GetString();
        }
        else
        {
            res.status = 400;
            res.set_content("Missing 'ip' field in JSON", "text/plain");
            break;
        }

        if (doc.HasMember("port") && doc["port"].IsNumber())
        {
            port = doc["port"].GetInt();
        }
        else
        {
            res.status = 400;
            res.set_content("Missing 'port' field in JSON", "text/plain");
            break;
        }

        std::vector<std::shared_ptr<Packet>> allPackets;
        QueryCondition                       queryCondition;
        queryCondition.Ip   = ip;
        queryCondition.Port = port;
        gPtrTsharkManager->QueryPackets(queryCondition, allPackets);

        rapidjson::Document responseDoc(rapidjson::kObjectType);
        auto                allocator = responseDoc.GetAllocator();
        responseDoc.AddMember("code", 0, allocator);
        responseDoc.AddMember("msg", "success", allocator);

        rapidjson::Value dataArray(rapidjson::kArrayType);
        for (auto packet : allPackets)
        {
            rapidjson::Value pktObj(rapidjson::kObjectType);
            pktObj.AddMember("frame_number", packet->FrameNumber, allocator);
            pktObj.AddMember("timestamp", packet->Time, allocator);
            pktObj.AddMember("src_mac", rapidjson::Value(packet->SourceMac.c_str(), allocator), allocator);
            pktObj.AddMember("dst_mac", rapidjson::Value(packet->DestinationMac.c_str(), allocator), allocator);
            pktObj.AddMember("src_ip", rapidjson::Value(packet->SourceIp.c_str(), allocator), allocator);
            pktObj.AddMember("src_location", rapidjson::Value(packet->SourceLocation.c_str(), allocator), allocator);
            pktObj.AddMember("src_port", packet->SourcePort, allocator);
            pktObj.AddMember("dst_ip", rapidjson::Value(packet->DestinationIp.c_str(), allocator), allocator);
            pktObj.AddMember("dst_location", rapidjson::Value(packet->DestinationLocation.c_str(), allocator),
                             allocator);
            pktObj.AddMember("dst_port", packet->DestinationPort, allocator);
            pktObj.AddMember("cap_len", packet->CapLen, allocator);
            pktObj.AddMember("len", packet->Len, allocator);
            pktObj.AddMember("protocol", rapidjson::Value(packet->Protocol.c_str(), allocator), allocator);
            pktObj.AddMember("info", rapidjson::Value(packet->Info.c_str(), allocator), allocator);
            pktObj.AddMember("file_offset", packet->FileOffset, allocator);
            dataArray.PushBack(pktObj, allocator);
        }
        responseDoc.AddMember("data", dataArray, allocator);
        rapidjson::StringBuffer                          buffer;
        rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(buffer);
        responseDoc.Accept(writer);
        res.set_content(buffer.GetString(), "application/json");
    }
    while (false);
}
