#include <filesystem>
#include <iostream>


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

    std::string pcapPath;
    std::cout << "Please enter PCAP file path: ";
    std::cin >> pcapPath;
    tsharkManager.ReadPcap(pcapPath);
    tsharkManager.PrintAllPackets();

    uint32_t    frameNumber;
    std::string result;
    std::cout << "Please enter frame number: ";
    std::cin >> frameNumber;
    tsharkManager.GetPackageDetailInfo(frameNumber, result);
    std::cout << result << std::endl;
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
