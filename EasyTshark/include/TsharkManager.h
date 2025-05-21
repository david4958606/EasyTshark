#pragma once
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>


#include "AdapterMonitorInfo.h"
#include "document.h"
#include "Ip2RegionUtil.h"
#include "TsharkDataType.h"
#include "ProcessUtil.h"

#ifdef _WIN32
#define POPEN _popen
#define PCLOSE _pclose
#endif

class TsharkManager
{
public:
    explicit TsharkManager(const std::string& workDir);
    ~TsharkManager();

    // analyze pcap file
    bool ReadPcap(const std::string& path);

    void PrintAllPackets() const;

    bool ReadPacketHex(uint32_t frameNumber, std::vector<unsigned char>& data);

    std::vector<AdapterInfo> GetNetworkAdapters() const;

    bool StartCapture(const std::string& adapterName);

    bool StopCapture();

    void StartMonitorAdaptersFlowTrend();
    void StopMonitorAdaptersFlowTrend();
    void GetAdaptersFlowTrendData(std::map<std::string, std::map<long, long>>& flowTrendData);

private:
    static bool ParseLine(std::string line, const std::shared_ptr<Packet>& packet);

    static std::string ConvertTimeStamp(const std::string& timestampStr);

    std::string TsharkPath;
    std::string CurrentFilePath;

    Ip2RegionUtil& IpUtil = Ip2RegionUtil::Instance();

    std::unordered_map<uint32_t, std::shared_ptr<Packet>> AllPackets;

    void CaptureWorkThreadEntry(const std::string& adapterName);

    std::shared_ptr<std::thread> CaptureWorkThread;

    bool StopFlag;

    PidT CaptureTsharkPid = 0;

    std::map<std::string, AdapterMonitorInfo> AdapterFlowTrendMonitorMap;
    std::recursive_mutex                      AdapterFlowTrendMapLock;
    time_t                                    AdapterFlowTrendMonitorStartTime = 0;

    void AdapterFlowTrendMonitorThreadEntry(std::string adapterName);
};

typedef rapidjson::Document::AllocatorType& AllocatorType;
