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
    tsharkManager.StartCapture("WLAN");

    std::string input;
    while (true)
    {
        std::cout << "请输入q退出抓包: ";
        std::cin >> input;
        if (input == "q")
        {
            tsharkManager.StopCapture();
            break;
        }
    }
    tsharkManager.PrintAllPackets();
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
