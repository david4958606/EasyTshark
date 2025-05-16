import <filesystem>;
import <iostream>;
import <format>;


#include "main.h"
#include "TsharkManager.h"
#include "Ip2RegionUtil.h"
#include "loguru.hpp"


int main(int argc, char* argv[])
{
    InitLog(argc, argv);

    InitIp2RegionUtil();
    std::filesystem::path cwd = std::filesystem::current_path();
    TsharkManager         tsharkManager(cwd.string());
    tsharkManager.ReadPcap("resource\\capture.pcap");
    tsharkManager.PrintAllPackets();

    std::cout << "\n\n";
    std::vector<AdapterInfo> adaptors = tsharkManager.GetNetworkAdapters();
    for (auto& item : adaptors)
    {
        LOG_F(INFO, "网卡[%d]: name[%s] remark[%s]", item.Id, item.Name.c_str(), item.Remark.c_str());
    }
    return 0;
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
