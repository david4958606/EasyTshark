#include <filesystem>
#include <iostream>


#include "main.h"

#include "stringbuffer.h"
#include "writer.h"
#include "TsharkManager.h"
#include "Ip2RegionUtil.h"
#include "loguru.hpp"


int main(int argc, char* argv[])
{
    InitLog(argc, argv);

    InitIp2RegionUtil();
    std::filesystem::path cwd = std::filesystem::current_path();
    TsharkManager         tsharkManager(cwd.string());

    tsharkManager.StartMonitorAdaptersFlowTrend();
    std::this_thread::sleep_for(std::chrono::seconds(10));
    std::map<std::string, std::map<long, long>> trendData;
    tsharkManager.GetAdaptersFlowTrendData(trendData);
    tsharkManager.StopMonitorAdaptersFlowTrend();

    // 把获取到的数据打印输出
    rapidjson::Document                 resDoc;
    rapidjson::Document::AllocatorType& allocator = resDoc.GetAllocator();
    resDoc.SetObject();
    rapidjson::Value dataObject(rapidjson::kObjectType);
    for (const auto& adaptorItem : trendData)
    {
        rapidjson::Value adaptorDataList(rapidjson::kArrayType);
        for (const auto& timeItem : adaptorItem.second)
        {
            rapidjson::Value timeObj(rapidjson::kObjectType);
            timeObj.AddMember("time", (unsigned int)timeItem.first, allocator);
            timeObj.AddMember("bytes", (unsigned int)timeItem.second, allocator);
            adaptorDataList.PushBack(timeObj, allocator);
        }

        dataObject.AddMember(rapidjson::StringRef(adaptorItem.first.c_str()), adaptorDataList, allocator);
    }

    resDoc.AddMember("data", dataObject, allocator);

    // 序列化为 JSON 字符串
    rapidjson::StringBuffer                    buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    resDoc.Accept(writer);

    LOG_F(INFO, "Network Adaptor Flow: %s", buffer.GetString());

    // tsharkManager.StartCapture("WLAN");
    //
    // std::string input;
    // while (true)
    // {
    //     std::cout << "请输入q退出抓包: ";
    //     std::cin >> input;
    //     if (input == "q")
    //     {
    //         tsharkManager.StopCapture();
    //         break;
    //     }
    // }
    // tsharkManager.PrintAllPackets();
}

void InitIp2RegionUtil()
{
    Ip2RegionUtil::Instance().Init("resource\\ip2region.xdb");
}

void InitLog(int argc, char* argv[])
{
    loguru::init(argc, argv);
    loguru::add_file("logs.log", loguru::Append, loguru::Verbosity_MAX);
}
