#include <filesystem>
#include <iostream>


#include "main.h"

#include "AdaptorController.hpp"
#include "httplib.h"
#include "HttpUtil.h"
#include "TsharkManager.h"
#include "Ip2RegionUtil.h"
#include "loguru.hpp"
#include "PacketController.hpp"
#include "SessionController.hpp"
#include "StatsController.hpp"


int main(int argc, char* argv[])
{
    InitLog(argc, argv);

    InitIp2RegionUtil();
    const std::filesystem::path cwd = std::filesystem::current_path();
    gPtrTsharkManager               = std::make_shared<TsharkManager>(cwd.string());

    // OnlineCapture(gPtrTsharkManager, "WLAN", 5);
    // OfflineAnalysis(gPtrTsharkManager);
    // gPtrTsharkManager->PrintAllSessions();

    SetUpServer();
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

void GetDetailedJson(TsharkManager& tsharkManager)
{
    std::string pcapPath;
    std::cout << "Please enter PCAP file path: ";
    std::cin >> pcapPath;
    tsharkManager.AnalysisFile(pcapPath);
    tsharkManager.PrintAllPackets();

    uint32_t    frameNumber;
    std::string result;
    std::cout << "Please enter frame number: ";
    std::cin >> frameNumber;
    tsharkManager.GetPackageDetailInfo(frameNumber, result);
    std::cout << result << std::endl;
}

void OnlineCapture(const std::shared_ptr<TsharkManager>& gPtrTsharkManager,
                   const std::string&                    adapterName,
                   const int                             duration)
{
    gPtrTsharkManager->StartCapture(adapterName);

    std::string input;
    if (duration > 0)
    {
        LOG_F(INFO, "Capture will stop after %d seconds.", duration);
        std::this_thread::sleep_for(std::chrono::seconds(duration));
        gPtrTsharkManager->StopCapture();
        return;
    }

    while (true)
    {
        std::cout << "Press Q to Stop: ";
        std::cin >> input;
        if (input == "q" or input == "Q")
        {
            gPtrTsharkManager->StopCapture();
            break;
        }
    }
    // gPtrTsharkManager->PrintAllPackets();
}

void OfflineAnalysis(const std::shared_ptr<TsharkManager>& gPtrTsharkManager)
{
    gPtrTsharkManager->AnalysisFile("resource\\capture.pcap");
    // gPtrTsharkManager->PrintAllPackets();
}

void SetUpServer()
{
    httplib::Server svr;
    svr.set_pre_routing_handler(HttpUtil::BeforeRequest);

    svr.set_post_routing_handler(HttpUtil::AfterRequest);

    std::vector<std::shared_ptr<BaseController>> controllerList;
    controllerList.push_back(std::make_shared<PacketController>(svr, gPtrTsharkManager));
    controllerList.push_back(std::make_shared<AdaptorController>(svr, gPtrTsharkManager));
    controllerList.push_back(std::make_shared<SessionController>(svr, gPtrTsharkManager));
    controllerList.push_back(std::make_shared<StatsController>(svr, gPtrTsharkManager));
    for (const auto& controller : controllerList)
    {
        controller->RegisterRoute();
    }

    svr.listen("127.0.0.1", 8080);
    LOG_F(INFO, "Server is listening on http://127.0.0.1:8080");
}
