#include <filesystem>
#include <iostream>


#include "main.h"

#include "httplib.h"
#include "TsharkManager.h"
#include "Ip2RegionUtil.h"
#include "loguru.hpp"
#include "PacketController.hpp"


int main(int argc, char* argv[])
{
    InitLog(argc, argv);

    InitIp2RegionUtil();
    std::filesystem::path cwd = std::filesystem::current_path();
    // TsharkManager         tsharkManager(cwd.string());
    gPtrTsharkManager = std::make_shared<TsharkManager>(cwd.string());

    // OnlineCapture(gPtrTsharkManager, "WLAN");
    OfflineAnalysis(gPtrTsharkManager);


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

void OnlineCapture(const std::shared_ptr<TsharkManager>& gPtrTsharkManager, const std::string& adapterName)
{
    gPtrTsharkManager->StartCapture(adapterName);

    std::string input;
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
    gPtrTsharkManager->PrintAllPackets();
}

void SetUpServer()
{
    httplib::Server svr;
    svr.set_pre_routing_handler([](const httplib::Request& req, httplib::Response& /*res*/)
    {
        BeforeRequest(req);
        return httplib::Server::HandlerResponse::Unhandled;
    });

    svr.set_post_routing_handler([](const httplib::Request& req, const httplib::Response& res)
    {
        AfterRequest(req, res);
    });


    PacketController packetController(svr, gPtrTsharkManager);
    packetController.RegisterRoute();

    svr.listen("127.0.0.1", 8080);
}

void BeforeRequest(const httplib::Request& req)
{
    LOG_F(INFO, "[Before] URL: %s | IP: %s", req.path.c_str(), req.remote_addr.c_str());
}

void AfterRequest(const httplib::Request& req, const httplib::Response& res)
{
    LOG_F(INFO, "[After]  Status Code: %d", res.status);
}
